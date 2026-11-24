// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checks

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestProbeIPMIRMCPAndCipher0(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 256)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n >= 20 && buf[0] == 0x06 && buf[3] == 0x07 && buf[19] == 0x38 {
				// Reply with valid IPMI v2.0 GetChannelAuthCap (vendor=20974 AMI MegaRAC: 0xee, 0x51, 0x00)
				resp := make([]byte, 30)
				resp[0] = 0x06
				resp[3] = 0x07
				resp[15] = 0x1c // App response
				resp[19] = 0x38 // GetChannelAuthCap
				resp[20] = 0x00 // OK
				resp[21] = 0x01 // channel 1
				resp[22] = 0x84 // IPMI v2.0 + MD5
				resp[23] = 0x04 // non-null usernames enabled
				resp[25] = 0xee
				resp[26] = 0x51
				resp[27] = 0x00
				_, _ = pc.WriteTo(resp, addr)
			} else if n >= 16 && buf[0] == 0x06 && buf[4] == 0x06 && buf[5] == 0x10 {
				// Reply accepting RMCP+ Open Session Cipher 0 (status code 0x00)
				resp := make([]byte, 24)
				resp[0] = 0x06
				resp[3] = 0x07
				resp[4] = 0x06
				resp[5] = 0x11 // Open Session Response
				resp[14] = 0x08
				resp[15] = 0x00
				resp[17] = 0x00 // No error -> Cipher 0 accepted!
				_, _ = pc.WriteTo(resp, addr)
			}
		}
	}()

	udpAddr := pc.LocalAddr().(*net.UDPAddr)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ev, ok := probeIPMI(ctx, "127.0.0.1", udpAddr.Port)
	if !ok {
		t.Fatalf("expected IPMI probe to match mock BMC")
	}
	for _, want := range []string{"IPMI v2.0", "AMI MegaRAC", "CIPHER 0 AUTH BYPASS"} {
		if !strings.Contains(ev, want) {
			t.Errorf("evidence %q missing %q", ev, want)
		}
	}
}
