// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checks

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/karalabe/uniblue/internal/probe"
)

// probeObserve evaluates purely against cached passive/discovery facts already
// collected in HostProfile without sending a single network packet.
func probeObserve(chk *Check, hp probe.HostProfile, port int) (string, bool) {
	if chk.Probe.Match.EvidenceSummary != "" {
		return chk.Probe.Match.EvidenceSummary, true
	}
	var parts []string
	if len(chk.Preconditions.MDNSTypeAny) > 0 {
		for _, s := range hp.MDNSServices {
			if !matchesMDNSService(chk, s) {
				continue
			}
			detail := fmt.Sprintf("mDNS %s", s.Type)
			if s.Port > 0 {
				detail += fmt.Sprintf(" (port %d)", s.Port)
			}
			if len(s.TXT) > 0 {
				detail += " [" + strings.Join(s.TXT, ", ") + "]"
			}
			parts = append(parts, detail)
		}
	}
	if chk.compiled.upnpDevice != nil || chk.compiled.upnpService != nil {
		for _, d := range hp.UPnPDevices {
			if !matchesUPnPDevice(chk, d) {
				continue
			}
			label := strings.TrimSpace(strings.Join([]string{d.Manufacturer, d.ModelName, d.DeviceType}, " "))
			if label == "" {
				label = d.ST
			}
			if label != "" {
				parts = append(parts, "UPnP/SSDP "+compactASCII(label, 96))
			}
		}
	}
	if chk.compiled.wsType != nil {
		for _, w := range hp.WSDiscovery {
			if !matchesWSRecord(chk, w) {
				continue
			}
			if len(w.Types) > 0 {
				parts = append(parts, "WS-Discovery "+strings.Join(w.Types, ", "))
			}
		}
	}
	if len(parts) > 0 {
		return "observed " + strings.Join(parts, "; "), true
	}
	if port > 0 {
		return fmt.Sprintf("observed matching service on port %d", port), true
	}
	return "observed matching passive host fingerprint", true
}

// probeSNMPReadOnly sends a single bounded SNMPv2c GetRequest for sysDescr.0
// (1.3.6.1.2.1.1.1.0) using the single explicitly configured community string.
// It never cycles communities, never emits SET requests, and never walks MIB tables.
func probeSNMPReadOnly(ctx context.Context, ip string, port int, community string, obs *Observation) (string, bool) {
	if community == "" {
		community = "public"
	}
	if port <= 0 {
		port = 161
	}

	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return "", false
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	reqID := randomUint32() & 0x7fffffff
	pkt := buildSNMPv2GetSysDescr(community, reqID)
	if _, err := conn.Write(pkt); err != nil {
		return "", false
	}

	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil || n < 16 {
		return "", false
	}
	sysDescr, ok := parseSNMPGetResponse(buf[:n], reqID)
	if !ok {
		return "", false
	}
	// A valid GetResponse proves the community matched an active SNMP agent
	// (ObsService), while a non-empty sysDescr value upgrades the observation to
	// ObsPrivilegeVerified so read grants gated on sys_descr can fire.
	obs.Level = ObsService
	if sysDescr != "" {
		obs.Level = ObsPrivilegeVerified
		obs.Fields = map[string]string{"sys_descr": sysDescr}
		return fmt.Sprintf("SNMPv2c GET sysDescr.0 succeeded with community %q (%q)", community, compactASCII(sysDescr, 90)), true
	}
	return fmt.Sprintf("SNMPv2c GET sysDescr.0 succeeded with community %q", community), true
}

// buildSNMPv2GetSysDescr constructs a minimal valid ASN.1 BER SNMPv2c
// GetRequest for sysDescr.0 (1.3.6.1.2.1.1.1.0).
func buildSNMPv2GetSysDescr(community string, reqID uint32) []byte {
	// OID 1.3.6.1.2.1.1.1.0 BER encoding: 06 08 2b 06 01 02 01 01 01 00
	varbind := asn1Seq([]byte{0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00})
	varbindList := asn1Seq(varbind)

	var pduBody bytes.Buffer
	pduBody.Write(asn1Int(int(reqID)))
	pduBody.Write(asn1Int(0)) // error-status = noError
	pduBody.Write(asn1Int(0)) // error-index = 0
	pduBody.Write(varbindList)
	pdu := asn1Wrap(0xa0, pduBody.Bytes()) // GetRequest-PDU

	var msg bytes.Buffer
	msg.Write(asn1Int(1)) // version = 1 (SNMPv2c)
	msg.Write(asn1Wrap(0x04, []byte(community)))
	msg.Write(pdu)
	return asn1Seq(msg.Bytes())
}

// parseSNMPGetResponse validates an SNMP GetResponse-PDU (0xA2), verifies the
// matching request-id and error-status == 0, and extracts the first OCTET STRING
// varbind value (sysDescr.0).
func parseSNMPGetResponse(raw []byte, wantReqID uint32) (string, bool) {
	// Outer SEQUENCE
	msg, ok := asn1Unwrap(raw, 0x30)
	if !ok {
		return "", false
	}
	// Skip version INTEGER and community OCTET STRING.
	_, rest, ok := asn1Next(msg, 0x02)
	if !ok {
		return "", false
	}
	_, rest, ok = asn1Next(rest, 0x04)
	if !ok {
		return "", false
	}
	// Expect GetResponse-PDU (0xA2).
	pdu, _, ok := asn1Next(rest, 0xa2)
	if !ok {
		return "", false
	}
	reqBytes, rest, ok := asn1Next(pdu, 0x02)
	if !ok || decodeASN1Int(reqBytes) != int(wantReqID) {
		return "", false
	}
	errBytes, rest, ok := asn1Next(rest, 0x02)
	if !ok || decodeASN1Int(errBytes) != 0 {
		return "", false
	}
	// Skip error-index.
	_, rest, ok = asn1Next(rest, 0x02)
	if !ok {
		return "", false
	}
	vbList, _, ok := asn1Next(rest, 0x30)
	if !ok {
		return "", false
	}
	vb, _, ok := asn1Next(vbList, 0x30)
	if !ok {
		return "", false
	}
	// Skip OID, read value.
	_, valRest, ok := asn1Next(vb, 0x06)
	if !ok || len(valRest) < 2 {
		return "", false
	}
	// Extract OCTET STRING (0x04) when present; non-string varbinds (such as
	// SNMPv2c noSuchObject/noSuchInstance exceptions) still confirm a live agent
	// accepted the community string, so return true with an empty sysDescr.
	if valBytes, _, ok := asn1Next(valRest, 0x04); ok {
		return string(valBytes), true
	}
	return "", true
}

// asn1Seq wraps body in an ASN.1 BER SEQUENCE (tag 0x30).
func asn1Seq(body []byte) []byte { return asn1Wrap(0x30, body) }

// asn1Wrap encodes a tag-length-value BER element using definite short or
// 1- to 2-byte long-form length encoding.
func asn1Wrap(tag byte, body []byte) []byte {
	var out bytes.Buffer
	out.WriteByte(tag)
	l := len(body)
	switch {
	case l < 128:
		out.WriteByte(byte(l))
	case l < 256:
		out.Write([]byte{0x81, byte(l)})
	default:
		out.Write([]byte{0x82, byte(l >> 8), byte(l)})
	}
	out.Write(body)
	return out.Bytes()
}

// asn1Int encodes a non-negative 32-bit integer (cast to uint32) as a minimal
// ASN.1 BER INTEGER, prepending a 0x00 sign byte whenever the high bit would
// otherwise be set.
func asn1Int(v int) []byte {
	if v == 0 {
		return []byte{0x02, 0x01, 0x00}
	}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(v))
	i := 0
	for i < 3 && b[i] == 0 {
		i++
	}
	if b[i]&0x80 != 0 {
		return asn1Wrap(0x02, append([]byte{0x00}, b[i:]...))
	}
	return asn1Wrap(0x02, b[i:])
}

// asn1Unwrap returns the value bytes of a BER element matching wantTag.
func asn1Unwrap(data []byte, wantTag byte) ([]byte, bool) {
	v, _, ok := asn1Next(data, wantTag)
	return v, ok
}

// asn1Next parses one BER element with tag wantTag from data and returns its
// value slice along with the unparsed trailing bytes.
func asn1Next(data []byte, wantTag byte) (val, rest []byte, ok bool) {
	if len(data) < 2 || data[0] != wantTag {
		return nil, nil, false
	}
	l := int(data[1])
	off := 2
	if l&0x80 != 0 {
		nBytes := l & 0x7f
		if nBytes == 0 || nBytes > 2 || off+nBytes > len(data) {
			return nil, nil, false
		}
		l = 0
		for range nBytes {
			l = (l << 8) | int(data[off])
			off++
		}
	}
	if off+l > len(data) {
		return nil, nil, false
	}
	return data[off : off+l], data[off+l:], true
}

// decodeASN1Int decodes big-endian unsigned BER INTEGER content bytes.
func decodeASN1Int(b []byte) int {
	v := 0
	for _, x := range b {
		v = (v << 8) | int(x)
	}
	return v
}

// probeTLSLegacy performs a single read-only TLS handshake pinned to TLS 1.0-1.1
// to prove whether an HTTPS endpoint still accepts deprecated legacy TLS
// protocols (RFC 8996). It explicitly offers both standard and legacy/insecure
// cipher suites (including RSA key exchange and 3DES) so old embedded appliances
// (iLO, iDRAC, printers, NAS) that lack ECDHE are still detected.
func probeTLSLegacy(ctx context.Context, ip string, port int, obs *Observation) (string, bool) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{},
		Config: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // read-only LAN protocol negotiation check
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS11,
			CipherSuites:       allLegacyTLSCipherSuites(),
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return "", false
	}
	defer conn.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return "", false
	}
	ver := tlsConn.ConnectionState().Version
	switch ver {
	case tls.VersionTLS10:
		obs.Fields = map[string]string{"tls_version": "1.0"}
		return "endpoint negotiated deprecated TLS 1.0 (RFC 8996)", true
	case tls.VersionTLS11:
		obs.Fields = map[string]string{"tls_version": "1.1"}
		return "endpoint negotiated deprecated TLS 1.1 (RFC 8996)", true
	default:
		return "", false
	}
}

// allLegacyTLSCipherSuites returns the combined list of standard and insecure
// cipher suite IDs supported by crypto/tls so legacy TLS 1.0/1.1 servers
// offering only RSA key exchange or 3DES can still complete the probe handshake.
func allLegacyTLSCipherSuites() []uint16 {
	safe := tls.CipherSuites()
	insecure := tls.InsecureCipherSuites()
	suites := make([]uint16, 0, len(safe)+len(insecure))
	for _, cs := range safe {
		suites = append(suites, cs.ID)
	}
	for _, cs := range insecure {
		suites = append(suites, cs.ID)
	}
	return suites
}

// probeMemcached sends a single read-only "version\r\n" command to TCP 11211.
func probeMemcached(ctx context.Context, ip string, port int, obs *Observation) (string, bool) {
	conn, err := dialWithContextDeadline(ctx, ip, port)
	if err != nil {
		return "", false
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "version\r\n"); err != nil {
		return "", false
	}
	buf := make([]byte, 128)
	n, _ := conn.Read(buf)
	line := compactASCII(string(buf[:n]), 80)
	if strings.HasPrefix(line, "VERSION ") {
		obs.Fields = map[string]string{"version": strings.TrimPrefix(line, "VERSION ")}
		return fmt.Sprintf("Memcached responded to unauthenticated version query (%q)", line), true
	}
	return "", false
}

// probeRsync passively reads the initial "@RSYNCD: " greeting banner on TCP 873.
func probeRsync(ctx context.Context, ip string, port int, obs *Observation) (string, bool) {
	conn, err := dialWithContextDeadline(ctx, ip, port)
	if err != nil {
		return "", false
	}
	defer conn.Close()
	buf := make([]byte, 128)
	n, _ := conn.Read(buf)
	line := compactASCII(string(buf[:n]), 80)
	if strings.HasPrefix(line, "@RSYNCD:") {
		obs.Fields = map[string]string{"version": strings.TrimSpace(strings.TrimPrefix(line, "@RSYNCD:"))}
		return fmt.Sprintf("rsync daemon greeting observed (%q)", line), true
	}
	return "", false
}

// probeMPD reads the initial "OK MPD " greeting on TCP 6600 and sends a
// strictly read-only "status\n" command to verify whether the daemon actually
// allows unauthenticated queries (password-protected MPD servers still emit
// "OK MPD " on connect but reject "status" with an ACK permission error).
func probeMPD(ctx context.Context, ip string, port int, obs *Observation) (string, bool) {
	conn, err := dialWithContextDeadline(ctx, ip, port)
	if err != nil {
		return "", false
	}
	defer conn.Close()

	br := bufio.NewReader(io.LimitReader(conn, 8192))
	greetingRaw, err := br.ReadString('\n')
	if err != nil && len(greetingRaw) == 0 {
		return "", false
	}
	greeting := compactASCII(greetingRaw, 80)
	if !strings.HasPrefix(greeting, "OK MPD ") {
		return "", false
	}

	if _, err := io.WriteString(conn, "status\n"); err != nil {
		return "", false
	}

	sawState := false
	for range 64 {
		line, err := br.ReadString('\n')
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "ACK ") {
			return "", false
		}
		if strings.HasPrefix(trimmed, "state:") {
			sawState = true
		}
		if trimmed == "OK" {
			_, _ = io.WriteString(conn, "close\n")
			if sawState {
				obs.Fields = map[string]string{"version": strings.TrimPrefix(greeting, "OK MPD ")}
				return fmt.Sprintf("Music Player Daemon allowed unauthenticated status query (%q)", greeting), true
			}
			return "", false
		}
		if err != nil {
			break
		}
	}
	return "", false
}

// probeKasa sends a single read-only TP-Link Kasa legacy XOR-framed
// {"system":{"get_sysinfo":{}}} query on TCP port 9999 without toggling relays.
func probeKasa(ctx context.Context, ip string, port int, obs *Observation) (string, bool) {
	conn, err := dialWithContextDeadline(ctx, ip, port)
	if err != nil {
		return "", false
	}
	defer conn.Close()

	plain := []byte(`{"system":{"get_sysinfo":{}}}`)
	enc := kasaXOREncode(plain)
	pkt := make([]byte, 4+len(enc))
	binary.BigEndian.PutUint32(pkt[0:4], uint32(len(enc)))
	copy(pkt[4:], enc)

	if _, err := conn.Write(pkt); err != nil {
		return "", false
	}

	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return "", false
	}
	respLen := binary.BigEndian.Uint32(hdr)
	if respLen < 10 || respLen > 8192 {
		return "", false
	}
	body := make([]byte, respLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return "", false
	}
	dec := kasaXORDecode(body)
	var parsed struct {
		System struct {
			GetSysinfo struct {
				Model string `json:"model"`
				SWVer string `json:"sw_ver"`
			} `json:"get_sysinfo"`
		} `json:"system"`
	}
	if err := json.Unmarshal(dec, &parsed); err != nil || parsed.System.GetSysinfo.Model == "" {
		return "", false
	}
	obs.Fields = map[string]string{"model": parsed.System.GetSysinfo.Model}
	return fmt.Sprintf("TP-Link Kasa legacy XOR API responded to get_sysinfo (model=%q)", compactASCII(parsed.System.GetSysinfo.Model, 48)), true
}

// kasaXOREncode obfuscates a TP-Link Kasa JSON payload using the legacy
// autokey XOR cipher seeded with 0xAB (each output byte becomes the next key).
func kasaXOREncode(in []byte) []byte {
	out := make([]byte, len(in))
	key := byte(0xAB)
	for i, b := range in {
		key ^= b
		out[i] = key
	}
	return out
}

// kasaXORDecode reverses TP-Link Kasa's 0xAB-seeded autokey XOR framing.
func kasaXORDecode(in []byte) []byte {
	out := make([]byte, len(in))
	key := byte(0xAB)
	for i, b := range in {
		out[i] = key ^ b
		key = b
	}
	return out
}

// probeCoAP sends a single read-only CoAP CON GET /.well-known/core packet
// (RFC 7252) on UDP 5683 and verifies a 2.05 Content (0x45) reply.
func probeCoAP(ctx context.Context, ip string, port int, obs *Observation) (string, bool) {
	if port <= 0 {
		port = 5683
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return "", false
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	msgID := uint16(randomUint32())
	// Header: ver=1, type=CON(0), TKL=0 => 0x40; Code=GET(0x01); MsgID
	// Options: Uri-Path (11) ".well-known" (len 11), Uri-Path (0) "core" (len 4)
	var pkt bytes.Buffer
	pkt.Write([]byte{0x40, 0x01, byte(msgID >> 8), byte(msgID)})
	pkt.WriteByte(0xBB) // delta 11 (Uri-Path), len 11
	pkt.WriteString(".well-known")
	pkt.WriteByte(0x04) // delta 0 (Uri-Path), len 4
	pkt.WriteString("core")

	if _, err := conn.Write(pkt.Bytes()); err != nil {
		return "", false
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return "", false
	}
	// Verify CoAP version 1, matching Message ID, and response code 2.05 (0x45).
	if (buf[0]>>6) != 1 || buf[1] != 0x45 || binary.BigEndian.Uint16(buf[2:4]) != msgID {
		return "", false
	}
	obs.Fields = map[string]string{"response_code": "2.05"}
	return "CoAP server returned 2.05 Content for /.well-known/core resource discovery", true
}

// probeNATPMP sends a strictly read-only 2-byte NAT-PMP v0 External Address
// Request (RFC 6886: version=0, opcode=0) on UDP 5351. It never creates or
// modifies any port mappings.
func probeNATPMP(ctx context.Context, ip string, port int, obs *Observation) (string, bool) {
	if port <= 0 {
		port = 5351
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return "", false
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if _, err := conn.Write([]byte{0x00, 0x00}); err != nil {
		return "", false
	}
	resp := make([]byte, 16)
	n, err := conn.Read(resp)
	if err != nil || n < 12 {
		return "", false
	}
	// RFC 6886 section 3.2: ver=0, opcode=128, result=0 (2-byte big-endian).
	if resp[0] != 0x00 || resp[1] != 0x80 || binary.BigEndian.Uint16(resp[2:4]) != 0 {
		return "", false
	}
	obs.Fields = map[string]string{"result_code": "0"}
	return "NAT-PMP gateway responded to v0 external-address query on UDP 5351", true
}

// probeIPP sends a minimal read-only IPP 1.1 Get-Printer-Attributes (0x000B)
// request asking ONLY for printer-make-and-model and ipp-versions-supported.
func (r *Runner) probeIPP(ctx context.Context, ip string, port int, obs *Observation) (string, bool) {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	printerURI := fmt.Sprintf("ipp://%s/ipp/print", net.JoinHostPort(ip, strconv.Itoa(port)))
	var body bytes.Buffer
	// IPP v1.1 (0x01 0x01), Op=Get-Printer-Attributes (0x000B), ReqID=1
	body.Write([]byte{0x01, 0x01, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x01})
	body.WriteByte(0x01) // operation-attributes-tag
	writeIPPAttr(&body, 0x47, "attributes-charset", "utf-8")
	writeIPPAttr(&body, 0x48, "attributes-natural-language", "en")
	writeIPPAttr(&body, 0x45, "printer-uri", printerURI)
	writeIPPAttr(&body, 0x44, "requested-attributes", "printer-make-and-model")
	writeIPPAttr(&body, 0x44, "", "ipp-versions-supported")
	body.WriteByte(0x03) // end-of-attributes-tag

	targetURL := fmt.Sprintf("%s://%s/ipp/print", scheme, net.JoinHostPort(ip, strconv.Itoa(port)))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body.Bytes()))
	if err != nil {
		return "", false
	}
	req.Header.Set("Content-Type", "application/ipp")
	req.Header.Set("User-Agent", "UniBlue-Checker/0.1")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	// Valid IPP reply: major version 1 or 2, status code 0x0000..0x0002 (successful-*), reqID=1.
	if len(raw) < 8 || (raw[0] != 1 && raw[0] != 2) {
		return "", false
	}
	status := binary.BigEndian.Uint16(raw[2:4])
	reqID := binary.BigEndian.Uint32(raw[4:8])
	if reqID != 1 || status > 0x0002 {
		return "", false
	}
	obs.Fields = map[string]string{"status": strconv.Itoa(int(status))}
	return fmt.Sprintf("IPP Get-Printer-Attributes returned status 0x%04x on port %d", status, port), true
}

// writeIPPAttr appends a single RFC 8010 IPP attribute (value-tag, big-endian
// name-length + name, big-endian value-length + value) to w.
func writeIPPAttr(w *bytes.Buffer, tag byte, name, val string) {
	w.WriteByte(tag)
	_ = binary.Write(w, binary.BigEndian, uint16(len(name)))
	w.WriteString(name)
	_ = binary.Write(w, binary.BigEndian, uint16(len(val)))
	w.WriteString(val)
}

// matchJSONPredicates evaluates bounded dot/index JSONPath predicates against
// a decoded JSON response body.
func matchJSONPredicates(body []byte, preds []JSONPredicate, fields map[string]string) bool {
	if len(preds) == 0 {
		return true
	}
	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		return false
	}
	for _, p := range preds {
		val, found := evalJSONPath(root, p.Path)
		if p.Exists != nil {
			if found != *p.Exists {
				return false
			}
		}
		if !found {
			if p.Equals != "" || p.NotEquals != "" || p.compiled != nil {
				return false
			}
			continue
		}
		strVal := stringifyJSONScalar(val)
		if p.Equals != "" && strVal != p.Equals {
			return false
		}
		if p.NotEquals != "" && strVal == p.NotEquals {
			return false
		}
		if p.compiled != nil && !p.compiled.MatchString(strVal) {
			return false
		}
		// Object and array predicates expose presence without retaining nested
		// settings or credentials from an otherwise redacted response.
		if fields != nil {
			switch val.(type) {
			case map[string]any, []any:
				fields[p.Path] = ""
			default:
				fields[p.Path] = strVal
			}
		}
	}
	return true
}

// evalJSONPath resolves a bounded subset of JSONPath ("$.a.b" or "$.items[0].k").
func evalJSONPath(root any, path string) (any, bool) {
	p := strings.TrimPrefix(strings.TrimSpace(path), "$")
	p = strings.TrimPrefix(p, ".")
	if p == "" {
		return root, true
	}
	cur := root
	for _, seg := range strings.Split(p, ".") {
		if seg == "" {
			continue
		}
		key := seg
		idx := -1
		if br := strings.IndexByte(seg, '['); br >= 0 && strings.HasSuffix(seg, "]") {
			key = seg[:br]
			parsedIdx, err := strconv.Atoi(seg[br+1 : len(seg)-1])
			if err != nil || parsedIdx < 0 {
				return nil, false
			}
			idx = parsedIdx
		}
		if key != "" {
			m, ok := cur.(map[string]any)
			if !ok {
				return nil, false
			}
			next, exists := m[key]
			if !exists {
				return nil, false
			}
			cur = next
		}
		if idx >= 0 {
			arr, ok := cur.([]any)
			if !ok || idx >= len(arr) {
				return nil, false
			}
			cur = arr[idx]
		}
	}
	return cur, true
}

// stringifyJSONScalar formats a decoded JSON value as a string for equality
// and regex matching in JSONPredicate.
func stringifyJSONScalar(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case bool:
		return strconv.FormatBool(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case nil:
		return "null"
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}

// randomUint32 returns a random 32-bit unsigned integer for UDP request/message IDs.
func randomUint32() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}

// randomShortHex returns 4 random lowercase hex characters for ephemeral client IDs.
func randomShortHex() string {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
