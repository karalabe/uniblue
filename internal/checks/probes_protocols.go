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
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// probeBitcoinP2P performs a strictly read-only Bitcoin P2P `version` handshake
// (relay=false) on TCP (default 8333) to confirm a live Bitcoin node and extract
// its protocol version and user-agent string without requesting blocks or mempool.
func probeBitcoinP2P(ctx context.Context, ip string, port int, obs *Observation) (string, bool) {
	if port <= 0 {
		port = 8333
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return "", false
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	}

	// Build minimal 99-byte Bitcoin P2P version payload (version 70016, relay=false).
	var payload bytes.Buffer
	_ = binary.Write(&payload, binary.LittleEndian, int32(70016))            // protocol version
	_ = binary.Write(&payload, binary.LittleEndian, uint64(0))               // services
	_ = binary.Write(&payload, binary.LittleEndian, time.Now().UTC().Unix()) // timestamp
	payload.Write(make([]byte, 26))                                          // addr_recv
	payload.Write(make([]byte, 26))                                          // addr_from
	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	payload.Write(nonce[:])
	ua := "/UniBlue:0.1/"
	payload.WriteByte(byte(len(ua)))
	payload.WriteString(ua)
	_ = binary.Write(&payload, binary.LittleEndian, int32(0)) // start_height
	payload.WriteByte(0x00)                                   // relay=false

	pBytes := payload.Bytes()
	sum1 := sha256.Sum256(pBytes)
	sum2 := sha256.Sum256(sum1[:])

	var msg bytes.Buffer
	if port == 18333 {
		msg.Write([]byte{0x0b, 0x11, 0x09, 0x07}) // Bitcoin testnet3 magic
	} else {
		msg.Write([]byte{0xf9, 0xbe, 0xb4, 0xd9}) // Bitcoin mainnet magic
	}
	cmd := [12]byte{'v', 'e', 'r', 's', 'i', 'o', 'n'}
	msg.Write(cmd[:])
	_ = binary.Write(&msg, binary.LittleEndian, uint32(len(pBytes)))
	msg.Write(sum2[:4])
	msg.Write(pBytes)

	if _, err := conn.Write(msg.Bytes()); err != nil {
		return "", false
	}

	hdr := make([]byte, 24)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return "", false
	}
	network := bitcoinNetworkFromMagic(hdr[:4])
	if network == "" {
		return "", false
	}
	respCmd := strings.TrimRight(string(hdr[4:16]), "\x00")
	if respCmd != "version" {
		return "", false
	}
	respLen := binary.LittleEndian.Uint32(hdr[16:20])
	if respLen < 80 || respLen > 4096 {
		return "", false
	}
	respPayload := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respPayload); err != nil {
		return "", false
	}
	rSum1 := sha256.Sum256(respPayload)
	rSum2 := sha256.Sum256(rSum1[:])
	if !bytes.Equal(rSum2[:4], hdr[20:24]) {
		return "", false
	}

	protoVer := int32(binary.LittleEndian.Uint32(respPayload[0:4]))
	agent := parseBitcoinUserAgent(respPayload)
	obs.Fields = map[string]string{"network": network, "version": strconv.Itoa(int(protoVer))}
	if agent != "" {
		return fmt.Sprintf("Bitcoin P2P (%s) version=%d agent=%s", network, protoVer, agent), true
	}
	return fmt.Sprintf("Bitcoin P2P (%s) version=%d", network, protoVer), true
}

// bitcoinNetworkFromMagic maps the 4-byte Bitcoin P2P message framing magic to
// its network name (mainnet, testnet3, signet, or regtest).
func bitcoinNetworkFromMagic(m []byte) string {
	switch {
	case bytes.Equal(m, []byte{0xf9, 0xbe, 0xb4, 0xd9}):
		return "mainnet"
	case bytes.Equal(m, []byte{0x0b, 0x11, 0x09, 0x07}):
		return "testnet3"
	case bytes.Equal(m, []byte{0x0a, 0x03, 0xcf, 0x40}):
		return "signet"
	case bytes.Equal(m, []byte{0xfa, 0xbf, 0xb5, 0xda}):
		return "regtest"
	default:
		return ""
	}
}

// parseBitcoinUserAgent extracts the length-prefixed user-agent string from a
// Bitcoin P2P version payload after its fixed 80-byte prefix.
func parseBitcoinUserAgent(payload []byte) string {
	// Version(4) + Services(8) + Time(8) + AddrRecv(26) + AddrFrom(26) + Nonce(8) = 80
	if len(payload) <= 80 {
		return ""
	}
	uaLen := int(payload[80])
	if uaLen == 0 || uaLen > 128 || 81+uaLen > len(payload) {
		return ""
	}
	return strings.TrimSpace(string(payload[81 : 81+uaLen]))
}

// probeBitcoinRPC issues a strictly read-only JSON-RPC `getnetworkinfo` call
// with no credentials to verify whether Bitcoin Core RPC enforces HTTP auth.
func (r *Runner) probeBitcoinRPC(ctx context.Context, ip string, port int, obs *Observation) (string, bool) {
	if port <= 0 {
		port = 8332
	}
	body := `{"jsonrpc":"1.0","id":"uniblue","method":"getnetworkinfo","params":[]}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("http://%s/", net.JoinHostPort(ip, strconv.Itoa(port))), strings.NewReader(body))
	if err != nil {
		return "", false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	var parsed struct {
		ID     any `json:"id"`
		Error  any `json:"error"`
		Result *struct {
			Version         int    `json:"version"`
			Subversion      string `json:"subversion"`
			ProtocolVersion int    `json:"protocolversion"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil || parsed.Error != nil || parsed.Result == nil {
		return "", false
	}
	if idStr, ok := parsed.ID.(string); !ok || idStr != "uniblue" {
		return "", false
	}
	if parsed.Result.Subversion == "" || parsed.Result.ProtocolVersion <= 0 {
		return "", false
	}
	obs.Fields = map[string]string{"subversion": parsed.Result.Subversion}
	return fmt.Sprintf("Unauthenticated Bitcoin JSON-RPC getnetworkinfo succeeded (subversion=%q, version=%d)", parsed.Result.Subversion, parsed.Result.Version), true
}

// probeEthEngineAPI issues a strictly read-only `engine_exchangeCapabilities`
// request without a JWT Authorization header on TCP 8551 to verify whether an
// Ethereum Execution Client Engine API enforces JWT authentication.
func (r *Runner) probeEthEngineAPI(ctx context.Context, ip string, port int, obs *Observation) (string, bool) {
	if port <= 0 {
		port = 8551
	}
	body := `{"jsonrpc":"2.0","id":1,"method":"engine_exchangeCapabilities","params":[[]]}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("http://%s/", net.JoinHostPort(ip, strconv.Itoa(port))), strings.NewReader(body))
	if err != nil {
		return "", false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	var parsed struct {
		ID     float64  `json:"id"`
		Error  any      `json:"error"`
		Result []string `json:"result"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil || parsed.Error != nil || parsed.ID != 1 || len(parsed.Result) == 0 {
		return "", false
	}
	hasEngineMethod := false
	for _, capName := range parsed.Result {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(capName)), "engine_") {
			hasEngineMethod = true
			break
		}
	}
	if !hasEngineMethod {
		return "", false
	}
	obs.Fields = map[string]string{"capability_count": strconv.Itoa(len(parsed.Result))}
	return fmt.Sprintf("Ethereum Engine API responded to engine_exchangeCapabilities without JWT auth (%d capabilities)", len(parsed.Result)), true
}

// probeNUT performs a strictly read-only `VER` + `LIST UPS` query against a
// Network UPS Tools (NUT) upsd daemon (TCP 3493) without issuing control commands.
func probeNUT(ctx context.Context, ip string, port int, obs *Observation) (string, bool) {
	if port <= 0 {
		port = 3493
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return "", false
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	}

	if _, err := conn.Write([]byte("VER\n")); err != nil {
		return "", false
	}
	br := bufio.NewReader(io.LimitReader(conn, 8192))
	verLine, err := br.ReadString('\n')
	if err != nil {
		return "", false
	}
	verLine = strings.TrimSpace(verLine)
	if !strings.Contains(strings.ToLower(verLine), "ups") && !strings.Contains(strings.ToLower(verLine), "nut") {
		return "", false
	}

	upsCount := 0
	if _, err := conn.Write([]byte("LIST UPS\n")); err == nil {
		for range 32 {
			line, err := br.ReadString('\n')
			if err != nil {
				break
			}
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "UPS ") {
				upsCount++
			}
			if line == "END LIST UPS" {
				obs.Fields = map[string]string{"listed_ups": strconv.Itoa(upsCount)}
				break
			}
			if strings.HasPrefix(line, "ERR ") {
				break
			}
		}
	}
	return fmt.Sprintf("NUT upsd responded (%s, %d UPS unit(s) listed)", verLine, upsCount), true
}

// probeLIFX sends a single read-only LIFX LAN GetVersion (type 32) UDP packet
// to port 56700 and decodes the StateVersion (type 33) vendor/product IDs.
func probeLIFX(ctx context.Context, ip string, port int, obs *Observation) (string, bool) {
	if port <= 0 {
		port = 56700
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return "", false
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	}

	// 36-byte LIFX LAN header: size=36, protocol=1024 + addressable(0x1000) -> 0x1400, source=0x55424c55, type=32 (GetVersion).
	pkt := make([]byte, 36)
	binary.LittleEndian.PutUint16(pkt[0:2], 36)
	binary.LittleEndian.PutUint16(pkt[2:4], 0x1400)
	binary.LittleEndian.PutUint32(pkt[4:8], 0x55424c55)
	pkt[22] = 0x01 // res_required=1
	binary.LittleEndian.PutUint16(pkt[32:34], 32)

	if _, err := conn.Write(pkt); err != nil {
		return "", false
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 48 {
		return "", false
	}
	protoFlags := binary.LittleEndian.Uint16(buf[2:4])
	msgType := binary.LittleEndian.Uint16(buf[32:34])
	if (protoFlags&0x0fff) != 1024 || msgType != 33 {
		return "", false
	}
	vendor := binary.LittleEndian.Uint32(buf[36:40])
	product := binary.LittleEndian.Uint32(buf[40:44])
	obs.Fields = map[string]string{"vendor_id": strconv.FormatUint(uint64(vendor), 10), "product_id": strconv.FormatUint(uint64(product), 10)}
	return fmt.Sprintf("LIFX LAN StateVersion vendor=%d product=%d", vendor, product), true
}

// probePJLink passively reads the initial PJLink greeting on TCP 4352 without
// sending any commands. Matches ONLY `PJLINK 0` (no authentication required);
// `PJLINK 1 <salt>` indicates password protection and returns false.
func probePJLink(ctx context.Context, ip string, port int, obs *Observation) (string, bool) {
	if port <= 0 {
		port = 4352
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return "", false
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	}
	br := bufio.NewReader(io.LimitReader(conn, 128))
	line, err := br.ReadString('\r')
	if err != nil && len(line) == 0 {
		return "", false
	}
	greeting := strings.TrimSpace(line)
	if greeting == "PJLINK 0" {
		obs.Fields = map[string]string{"auth_required": "false"}
		return "PJLink display advertised 'PJLINK 0' (unauthenticated projector/signage control)", true
	}
	return "", false
}

// probeNBNS sends one unicast RFC 1002 NBSTAT query (QTYPE=0x0021) to UDP 137,
// validates the transaction ID, and reports NetBIOS service role flags without
// broadcasting or persisting raw workstation/user strings.
func probeNBNS(ctx context.Context, ip string, port int, obs *Observation) (string, bool) {
	if port <= 0 {
		port = 137
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return "", false
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	}

	var tx [2]byte
	_, _ = rand.Read(tx[:])
	// 50-byte NBSTAT wildcard query ("*" padded with 15 zero bytes -> CK + 30 'A's).
	pkt := make([]byte, 50)
	pkt[0], pkt[1] = tx[0], tx[1]
	pkt[5] = 1 // QDCOUNT = 1
	pkt[12] = 32
	pkt[13], pkt[14] = 'C', 'K'
	for i := 15; i < 45; i++ {
		pkt[i] = 'A'
	}
	pkt[45] = 0x00
	binary.BigEndian.PutUint16(pkt[46:48], 0x0021) // NBSTAT
	binary.BigEndian.PutUint16(pkt[48:50], 0x0001) // IN

	if _, err := conn.Write(pkt); err != nil {
		return "", false
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 57 {
		return "", false
	}
	// RFC 1002 NBSTAT reply: matching tx ID, QR response bit (0x80) in byte 2,
	// NUMBER_OF_NAMES at byte 56, then 18-byte entries (15B name, 1B suffix, 2B flags).
	if buf[0] != tx[0] || buf[1] != tx[1] || (buf[2]&0x80) == 0 {
		return "", false
	}
	numNames := int(buf[56])
	if numNames <= 0 || numNames > 64 || 57+numNames*18 > n {
		return "", false
	}
	hasFileServer := false
	for i := range numNames {
		off := 57 + i*18
		// Suffix 0x20 advertises the NetBIOS File Server Service.
		suffix := buf[off+15]
		if suffix == 0x20 {
			hasFileServer = true
		}
	}
	role := "workstation"
	if hasFileServer {
		role = "file-server (0x20)"
	}
	obs.Fields = map[string]string{"name_count": strconv.Itoa(int(numNames))}
	return fmt.Sprintf("NetBIOS NBSTAT responded (%d name entries, role=%s)", numNames, role), true
}

// probePCP sends a strictly read-only RFC 6887 PCP v2 ANNOUNCE request (opcode 0)
// to UDP 5351 without creating or modifying any port mapping.
func probePCP(ctx context.Context, ip string, port int, obs *Observation) (string, bool) {
	if port <= 0 {
		port = 5351
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return "", false
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	}

	pkt := make([]byte, 24)
	pkt[0] = 2 // PCP version 2
	pkt[1] = 0 // ANNOUNCE request (R=0, Opcode=0)
	// RFC 6887 section 7.1 encodes the client IP at bytes 8..24 as a 16-byte
	// IPv6 or IPv4-mapped IPv6 address (falling back to ::ffff:127.0.0.1).
	if laddr, ok := conn.LocalAddr().(*net.UDPAddr); ok && laddr.IP != nil {
		copy(pkt[8:24], laddr.IP.To16())
	} else {
		pkt[18], pkt[19] = 0xff, 0xff
		pkt[20], pkt[23] = 127, 1
	}
	if _, err := conn.Write(pkt); err != nil {
		return "", false
	}
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil || n < 24 {
		return "", false
	}
	// Expect PCP v2, R=1 + ANNOUNCE opcode (0x80), and Result Code 0 (SUCCESS).
	if buf[0] != 2 || buf[1] != 0x80 || buf[3] != 0 {
		return "", false
	}
	epoch := binary.BigEndian.Uint32(buf[8:12])
	obs.Fields = map[string]string{"epoch": strconv.FormatUint(uint64(epoch), 10)}
	return fmt.Sprintf("PCP v2 ANNOUNCE succeeded (epoch=%d)", epoch), true
}

// probeDNSRecursion sends one read-only RFC 1035 standard query (RD=1) to UDP 53
// and checks whether the server sets Recursion Available (RA=1) without REFUSED.
func probeDNSRecursion(ctx context.Context, ip string, port int, obs *Observation) (string, bool) {
	if port <= 0 {
		port = 53
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return "", false
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	}

	var tx [2]byte
	_, _ = rand.Read(tx[:])
	// Standard query for example.com A IN with RD=1 (0x0100).
	pkt := []byte{
		tx[0], tx[1], 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		0x00, 0x01, 0x00, 0x01,
	}
	if _, err := conn.Write(pkt); err != nil {
		return "", false
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return "", false
	}
	if buf[0] != tx[0] || buf[1] != tx[1] {
		return "", false
	}
	flags := binary.BigEndian.Uint16(buf[2:4])
	isResp := (flags & 0x8000) != 0
	ra := (flags & 0x0080) != 0
	rcode := flags & 0x000f
	ancount := binary.BigEndian.Uint16(buf[6:8])
	if !isResp || !ra || rcode != 0 || ancount == 0 {
		return "", false
	}
	obs.Fields = map[string]string{"answers": strconv.Itoa(int(ancount))}
	return fmt.Sprintf("DNS server resolved recursive query (RA=1, NOERROR, answers=%d)", ancount), true
}

// probeNTP sends a single read-only 48-byte NTPv4 client request (Mode 3) to
// UDP 123 and validates a Mode 4 server response with stratum 1..15.
func probeNTP(ctx context.Context, ip string, port int, obs *Observation) (string, bool) {
	if port <= 0 {
		port = 123
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return "", false
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	}

	pkt := make([]byte, 48)
	pkt[0] = 0x23 // LI=0, VN=4, Mode=3 (client)
	if _, err := conn.Write(pkt); err != nil {
		return "", false
	}
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil || n < 48 {
		return "", false
	}
	mode := buf[0] & 0x07
	stratum := buf[1]
	if mode != 4 || stratum == 0 || stratum > 15 {
		return "", false
	}
	obs.Fields = map[string]string{"stratum": strconv.Itoa(int(stratum))}
	return fmt.Sprintf("NTPv%d server responded (stratum=%d)", (buf[0]>>3)&0x07, stratum), true
}

// probeSTUN sends a read-only RFC 5389 STUN Binding Request to UDP 3478 and
// validates a Binding Success Response with matching magic cookie & transaction ID.
func probeSTUN(ctx context.Context, ip string, port int, obs *Observation) (string, bool) {
	if port <= 0 {
		port = 3478
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return "", false
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	}

	pkt := make([]byte, 20)
	binary.BigEndian.PutUint16(pkt[0:2], 0x0001)     // Binding Request
	binary.BigEndian.PutUint16(pkt[2:4], 0x0000)     // Length 0
	binary.BigEndian.PutUint32(pkt[4:8], 0x2112A442) // RFC 5389 magic cookie
	_, _ = rand.Read(pkt[8:20])

	if _, err := conn.Write(pkt); err != nil {
		return "", false
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 20 {
		return "", false
	}
	// Validate RFC 5389 Binding Success Response (0x0101), magic cookie, and 96-bit transaction ID.
	if binary.BigEndian.Uint16(buf[0:2]) != 0x0101 ||
		binary.BigEndian.Uint32(buf[4:8]) != 0x2112A442 ||
		!bytes.Equal(buf[8:20], pkt[8:20]) {
		return "", false
	}
	obs.Fields = map[string]string{"binding_success": "true"}
	return "STUN Binding Success Response (RFC 5389) verified", true
}
