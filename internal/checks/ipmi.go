// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checks

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// ipmiGetChannelAuthCap is a strictly read-only 23-byte RMCP + IPMI v1.5/v2.0
// "Get Channel Authentication Capabilities" request (NetFn=App 0x06, Cmd=0x38,
// Channel=0x8e current channel with IPMI v2.0 bit set, Priv=Admin 0x04).
var ipmiGetChannelAuthCap = []byte{
	// RMCP Header: v1.0, reserved=0, seq=0xff (no RMCP ACK), class=0x07 (IPMI)
	0x06, 0x00, 0xff, 0x07,
	// IPMI Session Header: authType=none, seq=0, sessionID=0, msgLen=9
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09,
	// IPMI Message: rsAddr=0x20, netFn/rsLUN=0x18, cksum1=0xc8,
	// rqAddr=0x81, rqSeq=0x00, cmd=0x38, channel=0x8e, priv=0x04, cksum2=0xb5
	0x20, 0x18, 0xc8, 0x81, 0x00, 0x38, 0x8e, 0x04, 0xb5,
}

// ipmiRMCPPlusOpenSessionCipher0 is a strictly read-only 48-byte RMCP+ Open
// Session Request proposing Cipher Suite 0 (auth=NONE, integrity=NONE,
// confidentiality=NONE) to detect the classic IPMI v2.0 Cipher 0 authentication
// bypass (CVE-2013-4786) without sending any credentials or mutating BMC state.
var ipmiRMCPPlusOpenSessionCipher0 = []byte{
	// RMCP Header: v1.0, reserved=0, seq=0xff, class=0x07 (IPMI)
	0x06, 0x00, 0xff, 0x07,
	// RMCP+ Session Header: authType=0x06 (RMCP+), payloadType=0x10 (Open Session Req),
	// sessionID=0, seq=0, payloadLen=32 (0x0020 LE)
	0x06, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00,
	// Open Session Request Payload (32 bytes):
	// msgTag=0x00, maxPriv=0x04 (Admin), reserved=0x0000, consoleSessionID=0x41424344
	0x00, 0x04, 0x00, 0x00, 0x44, 0x43, 0x42, 0x41,
	// Auth Payload: type=0x00, reserved=0x0000, len=0x08, algo=0x00 (RAKP-none), reserved=0x000000
	0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
	// Integrity Payload: type=0x01, reserved=0x0000, len=0x08, algo=0x00 (none), reserved=0x000000
	0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
	// Confidentiality Payload: type=0x02, reserved=0x0000, len=0x08, algo=0x00 (none), reserved=0x000000
	0x02, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
}

// ipmiEnterpriseVendors maps common IANA Private Enterprise Numbers reported in
// IPMI Get Channel Authentication Capabilities responses to readable BMC vendors.
var ipmiEnterpriseVendors = map[uint32]string{
	2:     "IBM",
	11:    "HP",
	232:   "HPE iLO",
	343:   "Intel",
	674:   "Dell iDRAC",
	2623:  "ASUS ASMB",
	3157:  "ASRock Rack",
	7154:  "AMI / IPMI",
	10876: "Supermicro",
	19046: "Lenovo",
	20974: "AMI MegaRAC",
	39773: "ASPEED",
	45995: "Gigabyte",
	49871: "OpenBMC",
}

// probeIPMI performs a strictly read-only RMCP/IPMI Get Channel Authentication
// Capabilities query on UDP 623 (and, when IPMI v2.0 RMCP+ is advertised, a
// read-only RMCP+ Open Session Cipher 0 probe) to detect exposed out-of-band
// server management controllers and authentication weaknesses.
func probeIPMI(ctx context.Context, ip string, port int, obs *Observation) (string, bool) {
	if port <= 0 {
		port = 623
	}
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", addr)
	if err != nil {
		return "", false
	}
	defer conn.Close()

	// Keep per-packet wait snappy so non-BMC hosts fail fast without stalling scans.
	deadline := time.Now().Add(600 * time.Millisecond)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write(ipmiGetChannelAuthCap); err != nil {
		return "", false
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 24 {
		return "", false
	}
	resp := buf[:n]

	// Validate RMCP v1.0 (0x06), class IPMI (0x07), NetFn App Response (0x1c),
	// Cmd GetChannelAuthCap (0x38), and completion code OK (0x00).
	if resp[0] != 0x06 || resp[3] != 0x07 || resp[15] != 0x1c || resp[19] != 0x38 || resp[20] != 0x00 {
		return "", false
	}

	// IPMI v2.0 Table 22-15 response bytes:
	//   resp[22] authTypes:  bit 7 (0x80) = IPMI v2.0 extended capabilities available
	//                        (RMCP+ channel support is indicated separately),
	//                        bit 4 = cleartext password, bit 2 = MD5,
	//                        bit 1 = MD2, bit 0 = None
	//   resp[23] authStatus: bit 2 = non-null users enabled, bit 1 = null users enabled,
	//                        bit 0 = anonymous login enabled
	authTypes := resp[22]
	authStatus := resp[23]

	ipmiV2 := (authTypes & 0x80) != 0
	var modes []string
	if (authTypes & 0x01) != 0 {
		modes = append(modes, "None")
	}
	if (authTypes & 0x02) != 0 {
		modes = append(modes, "MD2")
	}
	if (authTypes & 0x04) != 0 {
		modes = append(modes, "MD5")
	}
	if (authTypes & 0x10) != 0 {
		modes = append(modes, "Cleartext")
	}
	if ipmiV2 {
		modes = append(modes, "RMCP+")
	}

	anonLogin := (authStatus & 0x01) != 0
	nullUser := (authStatus & 0x02) != 0
	nonNullUser := (authStatus & 0x04) != 0

	vendor := ""
	if n >= 28 {
		// Bytes 25..27 carry the 24-bit little-endian IANA Enterprise ID.
		iana := uint32(resp[25]) | uint32(resp[26])<<8 | uint32(resp[27])<<16
		if name, ok := ipmiEnterpriseVendors[iana]; ok {
			vendor = name
		} else if iana != 0 && iana != 0xffffff {
			vendor = fmt.Sprintf("IANA:%d", iana)
		}
	}

	// If IPMI v2.0 RMCP+ is supported, test whether Cipher Suite 0 (unauthenticated
	// bypass) is accepted via a single read-only Open Session Request.
	cipher0Accepted := false
	if ipmiV2 {
		c0Deadline := time.Now().Add(500 * time.Millisecond)
		if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(c0Deadline) {
			c0Deadline = ctxDeadline
		}
		_ = conn.SetDeadline(c0Deadline)
		if _, err := conn.Write(ipmiRMCPPlusOpenSessionCipher0); err == nil {
			c0Buf := make([]byte, 128)
			if cn, err := conn.Read(c0Buf); err == nil && cn >= 20 {
				// RMCP v1.0 (0x06), class IPMI (0x07), authType RMCP+ (0x06),
				// payloadType Open Session Response (0x11), status code byte[17] == 0x00.
				if c0Buf[0] == 0x06 && c0Buf[3] == 0x07 && c0Buf[4] == 0x06 && c0Buf[5] == 0x11 {
					payloadLen := binary.LittleEndian.Uint16(c0Buf[14:16])
					if payloadLen >= 8 && c0Buf[17] == 0x00 {
						cipher0Accepted = true
					}
				}
			}
		}
	}

	ver := "IPMI v1.5"
	if ipmiV2 {
		ver = "IPMI v2.0 (RMCP+)"
	}

	var risks []string
	if cipher0Accepted {
		risks = append(risks, "CIPHER 0 AUTH BYPASS ACCEPTED (CVE-2013-4786)")
	}
	if anonLogin || nullUser {
		risks = append(risks, "anonymous/null-user login enabled")
	}
	if ipmiV2 && nonNullUser {
		risks = append(risks, "RAKP-HMAC-SHA1 offline password hash exposure (CVE-2013-4786)")
	}
	if (authTypes & 0x10) != 0 {
		risks = append(risks, "cleartext password auth supported")
	}

	var parts []string
	parts = append(parts, fmt.Sprintf("%s exposed on UDP:%d", ver, port))
	if vendor != "" {
		parts = append(parts, fmt.Sprintf("vendor=%s", vendor))
	}
	if len(modes) > 0 {
		parts = append(parts, fmt.Sprintf("auth=[%s]", strings.Join(modes, ",")))
	}
	if len(risks) > 0 {
		parts = append(parts, strings.Join(risks, "; "))
	}
	fields := make(map[string]string)
	if anonLogin {
		fields["anonymous_login"] = "true"
	}
	if nullUser {
		fields["null_user"] = "true"
	}
	if cipher0Accepted {
		fields["cipher_zero"] = "true"
	}
	if len(fields) > 0 {
		obs.Fields = fields
	}
	return strings.Join(parts, " · "), true
}
