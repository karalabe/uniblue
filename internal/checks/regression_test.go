// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checks

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	builtinchecks "github.com/karalabe/uniblue/checks"
	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/unifi"
)

func loadBuiltinMap(t *testing.T) map[string]*Check {
	t.Helper()
	list, err := LoadFromFS(builtinchecks.BuiltinFS)
	if err != nil {
		t.Fatalf("LoadFromFS(BuiltinFS): %v", err)
	}
	byID := make(map[string]*Check, len(list))
	for _, c := range list {
		byID[c.ID] = c
	}
	return byID
}

// TestFindingKeyIncludesPropertyAndTransport verifies that Finding.Key()
// distinguishes synthetic findings sharing a host and port via Property, keeps
// legacy keys unchanged when Property is empty, and preserves non-TCP transport.
func TestFindingKeyIncludesPropertyAndTransport(t *testing.T) {
	cl := unifi.Client{MAC: "aa:00:00:00:00:10", IP: "192.168.1.10"}

	fPlain := Finding{CheckID: "UB-0003", Client: cl, Port: 3389}
	if got := fPlain.Key(); got != "UB-0003|aa:00:00:00:00:10|3389" {
		t.Fatalf("plain key = %q, want UB-0003|aa:00:00:00:00:10|3389", got)
	}

	fFwd1 := Finding{CheckID: "UB-UNIFI-PORTFWD", Client: cl, Port: 0, Property: "fwd-443"}
	fFwd2 := Finding{CheckID: "UB-UNIFI-PORTFWD", Client: cl, Port: 0, Property: "fwd-22"}
	if fFwd1.Key() == fFwd2.Key() {
		t.Fatalf("distinct port-forward properties must not collide: %q", fFwd1.Key())
	}
	if fFwd1.Key() != "UB-UNIFI-PORTFWD|aa:00:00:00:00:10|0|fwd-443" {
		t.Fatalf("unexpected port-forward key: %q", fFwd1.Key())
	}

	fUDP := Finding{CheckID: "UB-0017", Client: cl, Port: 3478, Property: "stun-server", Transport: "udp"}
	if got := fUDP.Key(); got != "UB-0017|aa:00:00:00:00:10|3478|stun-server|udp" {
		t.Fatalf("udp key with property = %q", got)
	}
}

// TestJupyterSpacingAndValetudoMatches verifies UB-0034 matches Python
// json.dumps default spacing as well as compact JSON, and UB-2026-0043 matches
// real Valetudo /api/v2/robot responses without requiring a capabilities key.
func TestJupyterSpacingAndValetudoMatches(t *testing.T) {
	byID := loadBuiltinMap(t)

	t.Run("jupyter spaced and compact json", func(t *testing.T) {
		chk := byID["UB-0034"]
		var body string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/contents" {
				http.NotFound(w, r)
				return
			}
			_, _ = io.WriteString(w, body)
		}))
		defer srv.Close()
		_, pStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
		port, _ := strconv.Atoi(pStr)
		r := NewRunner(nil, 1)

		body = `{"name": "", "path": "", "type": "directory", "content": []}`
		if _, ok := r.executeProbe(context.Background(), chk, "127.0.0.1", port); !ok {
			t.Fatal("UB-0034 must match standard Python json.dumps spaced JSON")
		}
		body = `{"name":"","type":"directory","content":[]}`
		if _, ok := r.executeProbe(context.Background(), chk, "127.0.0.1", port); !ok {
			t.Fatal("UB-0034 must still match compact JSON")
		}
		body = `<html><body>Login</body></html>`
		if _, ok := r.executeProbe(context.Background(), chk, "127.0.0.1", port); ok {
			t.Fatal("UB-0034 must reject non-JSON login page")
		}
	})

	t.Run("valetudo robot response without capabilities", func(t *testing.T) {
		chk := byID["UB-2026-0043"]
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v2/robot" {
				http.NotFound(w, r)
				return
			}
			_, _ = io.WriteString(w, `{"manufacturer": "Roborock", "modelName": "S5 Max", "modelDetails": {}, "implementation": "RoborockS5MaxValetudoRobot"}`)
		}))
		defer srv.Close()
		_, pStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
		port, _ := strconv.Atoi(pStr)
		r := NewRunner(nil, 1)

		if _, ok := r.executeProbe(context.Background(), chk, "127.0.0.1", port); !ok {
			t.Fatal("UB-2026-0043 must match real Valetudo /api/v2/robot response")
		}
	})
}

// TestNervaTLSCipherPropertySeverityDedupAndUnauthMapping verifies that Nerva
// TLS cipher findings use a distinct tls-cipher property, higher-severity Nerva
// findings win deduplication per key, and unauth Nerva IDs map to auth-anon.
func TestNervaTLSCipherPropertySeverityDedupAndUnauthMapping(t *testing.T) {
	cl := unifi.Client{IP: "192.0.2.40", MAC: "aa:bb:cc:dd:00:40"}
	profiles := []probe.HostProfile{
		{
			Client: cl,
			Services: []probe.Service{
				{
					Port:            443,
					Protocol:        "https",
					TLS:             true,
					AnonymousAccess: true, // simulates legacy substring mis-set on tls-anon-cipher
					Findings: []probe.ServiceFinding{
						{ID: "tls-weak-version-10", Severity: "low", Evidence: "TLS 1.0"},
						{ID: "tls-weak-cipher", Severity: "low", Evidence: "3DES"},
						{ID: "tls-anon-cipher", Severity: "high", Title: "Anonymous TLS Cipher", Evidence: "ADH cipher"},
					},
				},
				{
					Port:     2375,
					Protocol: "docker",
					Findings: []probe.ServiceFinding{
						{ID: "docker-unauth-api", Severity: "critical", Evidence: "Docker API exposed"},
					},
				},
				{
					Port:     554,
					Protocol: "rtsp",
					Findings: []probe.ServiceFinding{
						{ID: "rtsp-unauthenticated-stream", Severity: "high", Evidence: "RTSP stream open"},
					},
				},
			},
		},
	}

	// UB-0009 covers tls-protocol on 443 and UB-0029 covers auth-anon on 2375.
	existing := []Finding{
		{CheckID: "UB-0009", Client: cl, Port: 443},
		{CheckID: "UB-0029", Client: cl, Port: 2375},
	}

	got := FindingsFromProfiles(profiles, existing)
	if len(got) != 2 {
		t.Fatalf("expected 2 findings (tls-cipher on 443 + rtsp-unauth on 554), got %d: %+v", len(got), got)
	}

	byCheck := make(map[string]Finding, len(got))
	for _, f := range got {
		byCheck[f.CheckID] = f
	}

	cipher, ok := byCheck["NERVA-TLS-ANON-CIPHER"]
	if !ok {
		t.Fatalf("expected high-severity NERVA-TLS-ANON-CIPHER to survive UB-0009 and beat low tls-weak-cipher, got %+v", got)
	}
	if cipher.Property != "tls-cipher" || cipher.Category != "misconfig" || cipher.ClaimKind != ClaimServiceObserved {
		t.Fatalf("tls-anon-cipher misclassified: prop=%q cat=%q claim=%q", cipher.Property, cipher.Category, cipher.ClaimKind)
	}
	if strings.Contains(cipher.Title, "Unauthenticated / Anonymous") {
		t.Fatalf("tls-anon-cipher must not be retitled as unauthenticated service access: %q", cipher.Title)
	}

	rtsp, ok := byCheck["NERVA-RTSP-UNAUTHENTICATED-STREAM"]
	if !ok {
		t.Fatalf("expected NERVA-RTSP-UNAUTHENTICATED-STREAM on port 554, got %+v", got)
	}
	if rtsp.Property != "auth-anon" || rtsp.Category != "unauth-control" || rtsp.ClaimKind != ClaimConfirmedPermission {
		t.Fatalf("rtsp unauth finding metadata wrong: prop=%q cat=%q claim=%q", rtsp.Property, rtsp.Category, rtsp.ClaimKind)
	}
}

// TestRTSPDescribeAuthEnforcement verifies probeRTSP reconnect fallback and
// rejects 403 challenges or non-SDP 200 responses.
func TestRTSPDescribeAuthEnforcement(t *testing.T) {
	t.Run("reconnect after options close", func(t *testing.T) {
		port, closeFn := startMockTCP(t, func(conn net.Conn) {
			br := bufio.NewReader(conn)
			reqLine, err := br.ReadString('\n')
			if err != nil {
				return
			}
			for {
				line, err := br.ReadString('\n')
				if err != nil || strings.TrimSpace(line) == "" {
					break
				}
			}
			if strings.HasPrefix(reqLine, "OPTIONS ") {
				_, _ = io.WriteString(conn, "RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: OPTIONS, DESCRIBE\r\n\r\n")
				return // closes TCP connection immediately
			}
			if strings.HasPrefix(reqLine, "DESCRIBE ") {
				sdp := "v=0\r\nm=video 0 RTP/AVP 96\r\n"
				_, _ = io.WriteString(conn, "RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Type: application/sdp\r\nContent-Length: "+strconv.Itoa(len(sdp))+"\r\n\r\n"+sdp)
			}
		})
		defer closeFn()

		if _, ok := probeRTSP(context.Background(), "127.0.0.1", port); !ok {
			t.Fatal("expected RTSP DESCRIBE reconnect after OPTIONS close to match")
		}
	})

	t.Run("rejects describe 403", func(t *testing.T) {
		port, closeFn := startMockTCP(t, func(conn net.Conn) {
			br := bufio.NewReader(conn)
			for range 2 {
				reqLine, err := br.ReadString('\n')
				if err != nil {
					return
				}
				for {
					line, err := br.ReadString('\n')
					if err != nil || strings.TrimSpace(line) == "" {
						break
					}
				}
				if strings.HasPrefix(reqLine, "OPTIONS ") {
					_, _ = io.WriteString(conn, "RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n")
				} else {
					_, _ = io.WriteString(conn, "RTSP/1.0 403 Forbidden\r\nCSeq: 2\r\n\r\n")
				}
			}
		})
		defer closeFn()

		if _, ok := probeRTSP(context.Background(), "127.0.0.1", port); ok {
			t.Fatal("expected DESCRIBE 403 NOT to match")
		}
	})
}

// TestESPHomeUnencryptedMDNSPrecondition verifies UB-2026-0036 fires on
// unencrypted ESPHome nodes (missing api_encryption or api_encryption_supported
// only) and does not fire on Noise-encrypted ESPHome nodes.
func TestESPHomeUnencryptedMDNSPrecondition(t *testing.T) {
	byID := loadBuiltinMap(t)
	chk := byID["UB-2026-0036"]
	r := NewRunner([]*Check{chk}, 1)

	unencryptedOmitted := probe.HostProfile{
		Client:       unifi.Client{IP: "192.0.2.60"},
		MDNSServices: []probe.MDNSService{{Type: "_esphomelib._tcp", Port: 6053, TXT: []string{"version=2024.12.0", "platform=ESP32"}}},
	}
	unencryptedSupportedOnly := probe.HostProfile{
		Client:       unifi.Client{IP: "192.0.2.61"},
		MDNSServices: []probe.MDNSService{{Type: "_esphomelib._tcp", Port: 6053, TXT: []string{"api_encryption_supported=Noise_NNpsk0_25519_ChaChaPoly_SHA256"}}},
	}
	encrypted := probe.HostProfile{
		Client:       unifi.Client{IP: "192.0.2.62"},
		MDNSServices: []probe.MDNSService{{Type: "_esphomelib._tcp", Port: 6053, TXT: []string{"version=2024.12.0", "api_encryption=Noise_NNpsk0_25519_ChaChaPoly_SHA256"}}},
	}

	if got := r.RunHost(context.Background(), unencryptedOmitted); len(got) != 1 || got[0].CheckID != "UB-2026-0036" {
		t.Fatalf("unencrypted ESPHome (omitted key) must match UB-2026-0036, got %+v", got)
	}
	if got := r.RunHost(context.Background(), unencryptedSupportedOnly); len(got) != 1 || got[0].CheckID != "UB-2026-0036" {
		t.Fatalf("unencrypted ESPHome (api_encryption_supported only) must match UB-2026-0036, got %+v", got)
	}
	if got := r.RunHost(context.Background(), encrypted); len(got) != 0 {
		t.Fatalf("Noise-encrypted ESPHome must NOT match UB-2026-0036, got %+v", got)
	}
}

// TestEmbeddedPanelAndCUPSAuthGuards verifies UB-0040 rejects login forms with
// password inputs and overly broad generic controller titles, and UB-0041
// probes auth-gated /admin/conf/cupsd.conf rather than public /admin.
func TestEmbeddedPanelAndCUPSAuthGuards(t *testing.T) {
	byID := loadBuiltinMap(t)

	t.Run("ub-0040 rejects password login page and broad controller title", func(t *testing.T) {
		chk := byID["UB-0040"]
		var page string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, page)
		}))
		defer srv.Close()
		_, pStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
		port, _ := strconv.Atoi(pStr)
		r := NewRunner(nil, 1)

		// Generic "Controller" title should not pass preconditions.
		genericHP := probe.HostProfile{
			OpenPorts: []int{80},
			HTTP:      map[int]probe.HTTPBanner{80: {Scheme: "http", StatusCode: 200, Title: "My Network Controller"}},
		}
		if _, ok := matchPreconditions(chk, genericHP); ok {
			t.Fatal("UB-0040 must not match generic 'Controller' title")
		}

		// Password form on Smart Meter page must be rejected by body_not_contains.
		page = `<html><title>Smart Meter</title><body><form><input type="password" name="pw"></form></body></html>`
		if _, ok := r.executeProbe(context.Background(), chk, "127.0.0.1", port); ok {
			t.Fatal("UB-0040 must reject page containing a password input")
		}

		// True unauthenticated panel without password input still matches.
		page = `<html><title>Smart Meter</title><body><button>Toggle Relay</button></body></html>`
		if _, ok := r.executeProbe(context.Background(), chk, "127.0.0.1", port); !ok {
			t.Fatal("UB-0040 must match unauthenticated panel without password input")
		}
	})

	t.Run("ub-0041 checks cupsd.conf auth", func(t *testing.T) {
		chk := byID["UB-0041"]
		authEnabled := true
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/admin":
				_, _ = io.WriteString(w, "<html><title>CUPS</title><body>Add Printer</body></html>")
			case "/admin/conf/cupsd.conf":
				if authEnabled {
					w.Header().Set("WWW-Authenticate", `Basic realm="CUPS"`)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				_, _ = io.WriteString(w, "LogLevel warn\nListen 0.0.0.0:631\n<Location /admin>\n  Order allow,deny\n</Location>\n")
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()
		_, pStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
		port, _ := strconv.Atoi(pStr)
		r := NewRunner(nil, 1)

		if _, ok := r.executeProbe(context.Background(), chk, "127.0.0.1", port); ok {
			t.Fatal("UB-0041 must NOT flag CUPS when /admin/conf/cupsd.conf returns 401")
		}
		authEnabled = false
		if _, ok := r.executeProbe(context.Background(), chk, "127.0.0.1", port); !ok {
			t.Fatal("UB-0041 must flag CUPS when /admin/conf/cupsd.conf is served unauthenticated")
		}
	})
}

// TestTLSLegacyDetectsRSAKeyExchangeCipher verifies probeTLSLegacy detects a
// TLS 1.0 server offering only legacy RSA key exchange (removed from Go defaults).
func TestTLSLegacyDetectsRSAKeyExchangeCipher(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS10,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA},
	})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				if tc, ok := conn.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
			}(c)
		}
	}()

	_, pStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(pStr)
	ev, ok := probeTLSLegacy(context.Background(), "127.0.0.1", port)
	if !ok || !strings.Contains(ev, "TLS 1.0") {
		t.Fatalf("expected probeTLSLegacy to detect RSA-kex TLS 1.0 server, got ok=%v ev=%q", ok, ev)
	}
}

// TestRunnerHTTPTransportDisablesKeepAlives verifies Runner's HTTP transport
// disables keep-alives and sets an IdleConnTimeout so repeated scans do not
// leak connections or goroutines.
func TestRunnerHTTPTransportDisablesKeepAlives(t *testing.T) {
	r := NewRunner(nil, 1)
	tr, ok := r.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", r.httpClient.Transport)
	}
	if !tr.DisableKeepAlives {
		t.Fatal("expected Runner http.Transport.DisableKeepAlives to be true")
	}
	if tr.IdleConnTimeout <= 0 {
		t.Fatalf("expected positive IdleConnTimeout, got %v", tr.IdleConnTimeout)
	}
}

// TestRDPNoNLATLSRequiredAndLegacyFallback verifies probeRDPNoNLA flags both
// TLS-required SecurityLayer=2 servers without NLA and legacy RDP servers that
// refuse SSL, while staying silent when NLA is enforced.
func TestRDPNoNLATLSRequiredAndLegacyFallback(t *testing.T) {
	// Server with NLA off and SecurityLayer=2 (requires PROTOCOL_SSL = 0x01).
	portTLSOnly, closeTLSOnly := startMockTCP(t, func(conn net.Conn) {
		req := make([]byte, 19)
		if _, err := io.ReadFull(conn, req); err != nil {
			return
		}
		requested := binary.LittleEndian.Uint32(req[15:19])
		if requested&0x01 != 0 {
			// Accept PROTOCOL_SSL (0x01) without NLA.
			_, _ = conn.Write([]byte{
				0x03, 0x00, 0x00, 0x13,
				0x0e, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00,
			})
			return
		}
		// Reject PROTOCOL_RDP with SSL_REQUIRED_BY_SERVER (0x01).
		_, _ = conn.Write([]byte{
			0x03, 0x00, 0x00, 0x13,
			0x0e, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x03, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00,
		})
	})
	defer closeTLSOnly()

	ev, ok := probeRDPNoNLA(context.Background(), "127.0.0.1", portTLSOnly)
	if !ok || !strings.Contains(ev, "PROTOCOL_SSL") {
		t.Fatalf("expected TLS-required RDP without NLA to match, got ok=%v ev=%q", ok, ev)
	}

	// Legacy server refusing SSL with SSL_NOT_ALLOWED_BY_SERVER (0x02), accepting PROTOCOL_RDP (0x00).
	portLegacy, closeLegacy := startMockTCP(t, func(conn net.Conn) {
		req := make([]byte, 19)
		if _, err := io.ReadFull(conn, req); err != nil {
			return
		}
		requested := binary.LittleEndian.Uint32(req[15:19])
		if requested&0x01 != 0 {
			_, _ = conn.Write([]byte{
				0x03, 0x00, 0x00, 0x13,
				0x0e, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x03, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
			})
			return
		}
		_, _ = conn.Write([]byte{
			0x03, 0x00, 0x00, 0x13,
			0x0e, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
		})
	})
	defer closeLegacy()

	ev, ok = probeRDPNoNLA(context.Background(), "127.0.0.1", portLegacy)
	if !ok || !strings.Contains(ev, "PROTOCOL_RDP") {
		t.Fatalf("expected legacy RDP fallback to match, got ok=%v ev=%q", ok, ev)
	}
}

// TestStrictYAMLKnownFieldsAndNonEmptyHTTPMatch verifies Parse rejects unknown
// YAML keys (such as misspelled matcher fields) and HTTP checks with an empty MatchSpec.
func TestStrictYAMLKnownFieldsAndNonEmptyHTTPMatch(t *testing.T) {
	misspelled := `
id: UB-TEST-TYPO
title: Typo Matcher
severity: high
safety: read-only
preconditions:
  ports_any: [80]
probe:
  type: http
  method: GET
  path: /api/secret
  match:
    stauts: [200]
    body_contain_all: ["secret"]
`
	if _, err := Parse([]byte(misspelled), "typo.yaml"); err == nil {
		t.Fatal("expected Parse with KnownFields(true) to reject misspelled YAML keys")
	}

	emptyMatch := `
id: UB-TEST-EMPTY-MATCH
title: Empty HTTP Match
severity: high
safety: read-only
preconditions:
  ports_any: [80]
probe:
  type: http
  method: GET
  path: /api/secret
  match:
    redact_body: true
`
	if _, err := Parse([]byte(emptyMatch), "empty.yaml"); err == nil {
		t.Fatal("expected Validate to reject http probe with empty MatchSpec")
	}
}

// TestMPDStatusAuthCheck verifies probeMPD sends a read-only status command
// and does not flag password-protected MPD daemons that return an ACK error.
func TestMPDStatusAuthCheck(t *testing.T) {
	portAuth, closeAuth := startMockTCP(t, func(conn net.Conn) {
		_, _ = io.WriteString(conn, "OK MPD 0.23.5\n")
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		if strings.HasPrefix(string(buf[:n]), "status") {
			_, _ = io.WriteString(conn, "ACK [4@0] {status} you don't have permission\n")
		}
	})
	defer closeAuth()

	if ev, ok := probeMPD(context.Background(), "127.0.0.1", portAuth); ok {
		t.Fatalf("expected password-protected MPD NOT to match, got ev=%q", ev)
	}
}

// TestHTTPProbeInfersHTTPSForTLSPortsAndFingerprintedTLS verifies probeHTTP
// selects https for well-known TLS management ports (such as Intel AMT 16993)
// and honors fingerprinted TLS flags from HostProfile.Services and HTTP banners.
func TestHTTPProbeInfersHTTPSForTLSPortsAndFingerprintedTLS(t *testing.T) {
	for _, p := range []int{443, 636, 993, 995, 5986, 8006, 8007, 8443, 9443, 10443, 16993, 16995} {
		if got := inferHTTPScheme(probe.HostProfile{}, p, nil); got != "https" {
			t.Fatalf("inferHTTPScheme(port=%d) = %q, want https", p, got)
		}
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/logon.htm" {
			_, _ = io.WriteString(w, "<html><title>Intel(R) AMT</title><body>Intel Active Management Technology</body></html>")
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	_, pStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(pStr)

	byID := loadBuiltinMap(t)
	amtChk := *byID["UB-2026-0003"]
	amtChk.Preconditions.PortsAny = []int{port}
	if err := amtChk.Validate(); err != nil {
		t.Fatalf("validate cloned AMT check: %v", err)
	}

	hp := probe.HostProfile{
		Client:    unifi.Client{IP: "127.0.0.1", Hostname: "workstation-amt"},
		OpenPorts: []int{port},
		Services:  []probe.Service{{Port: port, Protocol: "http", TLS: true}},
	}
	got := NewRunner([]*Check{&amtChk}, 1).RunHost(context.Background(), hp)
	if len(got) != 1 || got[0].CheckID != "UB-2026-0003" {
		t.Fatalf("expected Intel AMT over TLS to match via Services TLS flag, got %+v", got)
	}
}

// TestBuiltinCheckFixes_HomeKit_deCONZ_VNC_STUN_OT_ActiveMQ verifies the
// updated preconditions and matchers across UB-2026-0022, UB-2026-0024,
// UB-0002, UB-0017, UB-0049, and UB-0028.
func TestBuiltinCheckFixes_HomeKit_deCONZ_VNC_STUN_OT_ActiveMQ(t *testing.T) {
	byID := loadBuiltinMap(t)

	// #118 HomeKit HAP odd sf bitmask (bit 0 set).
	hk := byID["UB-2026-0022"]
	for _, sf := range []string{"sf=1", "sf=3", "sf=5", "sf=7", "sf=11"} {
		hp := probe.HostProfile{MDNSServices: []probe.MDNSService{{Type: "_hap._tcp", Port: 51826, TXT: []string{sf}}}}
		if _, ok := matchPreconditions(hk, hp); !ok {
			t.Fatalf("UB-2026-0022 must match unpaired %s", sf)
		}
	}
	for _, sf := range []string{"sf=0", "sf=2", "sf=4", "sf=10"} {
		hp := probe.HostProfile{MDNSServices: []probe.MDNSService{{Type: "_hap._tcp", Port: 51826, TXT: []string{sf}}}}
		if _, ok := matchPreconditions(hk, hp); ok {
			t.Fatalf("UB-2026-0022 must NOT match paired %s", sf)
		}
	}

	// #119 deCONZ matches captured UPnP fields + modelid=deCONZ and rejects Philips Hue.
	deconz := byID["UB-2026-0024"]
	var apiBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/config" {
			_, _ = io.WriteString(w, apiBody)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	_, pStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(pStr)
	hpDeconz := probe.HostProfile{
		Client: unifi.Client{IP: "127.0.0.1"},
		UPnPDevices: []probe.UPnPDevice{{
			Port:         port,
			Server:       "Linux/3.14.0 UPnP/1.0 IpBridge/1.26.0",
			Manufacturer: "Royal Philips Electronics",
			ModelName:    "Philips hue bridge 2012",
		}},
	}
	apiBody = `{"bridgeid":"00212EFFFF012345","swversion":"2.27.4","modelid":"deCONZ"}`
	if got := NewRunner([]*Check{deconz}, 1).RunHost(context.Background(), hpDeconz); len(got) != 1 {
		t.Fatalf("UB-2026-0024 must match deCONZ gateway, got %+v", got)
	}
	apiBody = `{"bridgeid":"001788FFFE012345","swversion":"1965111030","modelid":"BSB002"}`
	if got := NewRunner([]*Check{deconz}, 1).RunHost(context.Background(), hpDeconz); len(got) != 0 {
		t.Fatalf("UB-2026-0024 must NOT match genuine Philips Hue bridge, got %+v", got)
	}

	// #120 VNC UB-0002 only schedules [5900, 5901] globally, yet still probes walked displays.
	vnc := byID["UB-0002"]
	global := PlanGlobalPorts([]int{80}, []*Check{vnc})
	if len(global) != 3 || global[1] != 5900 || global[2] != 5901 {
		t.Fatalf("UB-0002 must only add 5900 and 5901 globally, got %v", global)
	}
	walkedHP := probe.HostProfile{OpenPorts: []int{5900, 5905}}
	ports, ok := matchPreconditions(vnc, walkedHP)
	if !ok || len(ports) != 2 || ports[0] != 5900 || ports[1] != 5905 {
		t.Fatalf("UB-0002 must probe walked VNC displays alongside 5900, got ok=%v ports=%v", ok, ports)
	}

	// #121 STUN UB-0017 uses TCP ports 3478/5349 + discovery_only; UB-0049 drops dead UDP protos.
	stun := byID["UB-0017"]
	if !stun.Preconditions.DiscoveryOnly || len(stun.Preconditions.PortsAny) != 2 {
		t.Fatalf("UB-0017 preconditions unexpected: %+v", stun.Preconditions)
	}
	ot := byID["UB-0049"]
	for _, p := range ot.Preconditions.ServiceProtoAny {
		if p == "bacnet" || p == "knxip" {
			t.Fatalf("UB-0049 must not include dead UDP-only Nerva protocol %q", p)
		}
	}

	// #122 ActiveMQ matches Nerva's activemq-openwire protocol name.
	broker := byID["UB-0028"]
	hpAMQ := probe.HostProfile{Services: []probe.Service{{Port: 61616, Protocol: "activemq-openwire"}}}
	if _, ok := matchPreconditions(broker, hpAMQ); !ok {
		t.Fatal("UB-0028 must match Nerva activemq-openwire protocol")
	}
}

// TestProbeObserveRecordsOnlyMatchingDiscoveryEntries verifies probeObserve
// includes only matching UPnP, WS-Discovery, and mDNS records in Evidence.
func TestProbeObserveRecordsOnlyMatchingDiscoveryEntries(t *testing.T) {
	upnpChk, err := Parse([]byte(`
id: UB-TEST-OBS-UPNP
title: Test Observe UPnP
severity: info
safety: read-only
preconditions:
  upnp_device_regex: "(?i)Sonos"
probe:
  type: observe
`), "obs-upnp.yaml")
	if err != nil {
		t.Fatalf("Parse upnp observe: %v", err)
	}

	wsChk, err := Parse([]byte(`
id: UB-TEST-OBS-WS
title: Test Observe WS
severity: info
safety: read-only
preconditions:
  ws_type_regex: "(?i)NetworkVideoTransmitter"
probe:
  type: observe
`), "obs-ws.yaml")
	if err != nil {
		t.Fatalf("Parse ws observe: %v", err)
	}

	hp := probe.HostProfile{
		Client: unifi.Client{IP: "192.0.2.88"},
		UPnPDevices: []probe.UPnPDevice{
			{Manufacturer: "Sonos", ModelName: "Beam", DeviceType: "urn:schemas-upnp-org:device:ZonePlayer:1"},
			{Manufacturer: "UnrelatedVendor", ModelName: "Toaster", DeviceType: "urn:schemas-upnp-org:device:Basic:1"},
		},
		WSDiscovery: []probe.WSDiscoveryRecord{
			{Types: []string{"dn:NetworkVideoTransmitter"}},
			{Types: []string{"wsdp:Device", "wprt:PrintDeviceType"}},
		},
	}

	evUPnP, ok := probeObserve(upnpChk, hp, 0)
	if !ok || !strings.Contains(evUPnP, "Sonos") || strings.Contains(evUPnP, "UnrelatedVendor") {
		t.Fatalf("UPnP observe evidence must include only matching devices, got %q", evUPnP)
	}
	evWS, ok := probeObserve(wsChk, hp, 0)
	if !ok || !strings.Contains(evWS, "NetworkVideoTransmitter") || strings.Contains(evWS, "PrintDeviceType") {
		t.Fatalf("WS-Discovery observe evidence must include only matching records, got %q", evWS)
	}
}
