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
		// Large (>64 KiB) Jupyter root listing truncated before the trailing top-level "type": "directory".
		var large strings.Builder
		large.WriteString(`{"name": "", "path": "", "last_modified": "2026-11-25T12:00:00Z", "content": [`)
		for i := range 350 {
			if i > 0 {
				large.WriteString(", ")
			}
			large.WriteString(`{"name": "notebook-` + strconv.Itoa(i) + `.ipynb", "path": "notebook-` + strconv.Itoa(i) + `.ipynb", "last_modified": "2026-11-25T12:00:00.000000Z", "created": "2026-11-25T12:00:00.000000Z", "content": null, "format": null, "mimetype": null, "size": 1024, "writable": true, "type": "notebook"}`)
		}
		large.WriteString(`], "format": "json", "writable": true, "type": "directory"}`)
		if large.Len() <= maxProbeBodyBytes {
			t.Fatalf("expected large Jupyter body > %d bytes, got %d", maxProbeBodyBytes, large.Len())
		}
		body = large.String()
		if _, ok := r.executeProbe(context.Background(), chk, "127.0.0.1", port); !ok {
			t.Fatal("UB-0034 must match large (>64 KiB) truncated Jupyter root listing")
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

// TestNervaTLSCipherPropertySeverityDedupAndUnauthMapping verifies that distinct
// Nerva TLS cipher classes (anon, null, export) receive distinct properties and
// all survive alongside UB-0009, unrelated findings on AnonymousAccess services
// keep their real titles, and unauth Nerva IDs map to auth-anon.
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
					AnonymousAccess: true, // simulates service-level flag alongside unrelated findings
					Findings: []probe.ServiceFinding{
						{ID: "tls-weak-version-10", Severity: "low", Evidence: "TLS 1.0"},
						{ID: "tls-anon-cipher", Severity: "high", Title: "Anonymous TLS Cipher", Evidence: "ADH cipher"},
						{ID: "tls-null-cipher", Severity: "high", Title: "NULL TLS Cipher", Evidence: "NULL cipher"},
						{ID: "tls-export-cipher", Severity: "high", Title: "EXPORT TLS Cipher", Evidence: "EXPORT cipher"},
						{ID: "os-eol", Severity: "medium", Title: "End-of-Life OS", Description: "Ubuntu 18.04 reached EOL", Evidence: "Ubuntu 18.04"},
						{ID: "php-vulnerable-php2shell", Severity: "high", Title: "Vulnerable PHP Version", Description: "PHP 8.1 CGI exposure", Evidence: "PHP/8.1"},
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
	if len(got) != 6 {
		t.Fatalf("expected 6 findings (anon/null/export ciphers + os-eol + php + rtsp-unauth), got %d: %+v", len(got), got)
	}

	byCheck := make(map[string]Finding, len(got))
	for _, f := range got {
		byCheck[f.CheckID] = f
	}

	wantCiphers := map[string]string{
		"NERVA-TLS-ANON-CIPHER":   "tls-cipher-anon",
		"NERVA-TLS-NULL-CIPHER":   "tls-cipher-null",
		"NERVA-TLS-EXPORT-CIPHER": "tls-cipher-export",
	}
	for id, wantProp := range wantCiphers {
		cipher, ok := byCheck[id]
		if !ok {
			t.Fatalf("expected %s to survive alongside other TLS cipher findings and UB-0009, got %+v", id, got)
		}
		if cipher.Property != wantProp || cipher.Category != "misconfig" || cipher.ClaimKind != ClaimServiceObserved {
			t.Fatalf("%s misclassified: prop=%q (want %q) cat=%q claim=%q", id, cipher.Property, wantProp, cipher.Category, cipher.ClaimKind)
		}
		if strings.Contains(cipher.Title, "Unauthenticated / Anonymous") {
			t.Fatalf("%s must not be retitled as unauthenticated service access: %q", id, cipher.Title)
		}
	}

	for _, id := range []string{"NERVA-OS-EOL", "NERVA-PHP-VULNERABLE-PHP2SHELL"} {
		f, ok := byCheck[id]
		if !ok {
			t.Fatalf("expected unrelated finding %s to survive", id)
		}
		if strings.Contains(f.Title, "Unauthenticated / Anonymous") {
			t.Fatalf("unrelated finding %s must not be retitled as anonymous access: %q", id, f.Title)
		}
		for _, act := range f.Remediation.UniFiActions {
			if act == "disable_anonymous_access" {
				t.Fatalf("unrelated finding %s must not receive disable_anonymous_access remediation: %v", id, f.Remediation.UniFiActions)
			}
		}
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

		// Password form variants and JS/SPA login shells must all be rejected.
		rejectPages := []struct {
			name string
			html string
		}{
			{"lowercase password input", `<html><title>Smart Meter</title><body><form><input type="password" name="pw"></form></body></html>`},
			{"uppercase PASSWORD input", `<html><title>Smart Meter Controller</title><body><form><input type="PASSWORD" name="pw"></form></body></html>`},
			{"spaced type attribute", `<html><title>Smart Meter</title><body><form><input type = "password" name="pw"></form></body></html>`},
			{"unquoted mixed-case type", `<html><title>Smart Meter</title><body><form><input type=Password name="pw"></form></body></html>`},
			{"SPA empty root shell", `<html><head><title>Shelly</title><script type="module" src="/assets/index.js"></script></head><body><div id="app"></div></body></html>`},
			{"JS-only shell without controls", `<html><head><title>Shelly</title></head><body><script>window.bootLogin();</script></body></html>`},
			{"auth bundle script", `<html><head><title>Shelly</title></head><body><a href="/login">Sign in</a><script src="/static/auth-bundle.js"></script></body></html>`},
		}
		for _, tc := range rejectPages {
			page = tc.html
			if _, ok := r.executeProbe(context.Background(), chk, "127.0.0.1", port); ok {
				t.Fatalf("UB-0040 must reject %s", tc.name)
			}
		}

		// True unauthenticated static control panel still matches.
		page = `<html><title>Smart Meter</title><body><button>Toggle Relay</button></body></html>`
		if _, ok := r.executeProbe(context.Background(), chk, "127.0.0.1", port); !ok {
			t.Fatal("UB-0040 must match unauthenticated panel without password input")
		}

		// Stock open Tasmota page includes a noscript banner alongside server-rendered
		// control buttons and must match both preconditions and HTTP probe.
		tasmotaHP := probe.HostProfile{
			OpenPorts: []int{80},
			HTTP:      map[int]probe.HTTPBanner{80: {Scheme: "http", StatusCode: 200, Title: "Tasmota - Main Menu"}},
		}
		if _, ok := matchPreconditions(chk, tasmotaHP); !ok {
			t.Fatal("UB-0040 preconditions must match stock Tasmota title")
		}
		page = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Tasmota - Main Menu</title>` +
			`<script>function la(p){var x=new XMLHttpRequest();x.open("GET",".?m=1"+p,true);x.send();}</script></head>` +
			`<body><div><noscript>To use Tasmota, please enable JavaScript<br></noscript>` +
			`<h3>Tasmota</h3><h2>Living Room Plug</h2></div>` +
			`<table><tr><td><button onclick='la("&o=1");'>Toggle</button></td></tr></table>` +
			`<form action='cn' method='get'><button>Configuration</button></form>` +
			`<form action='cs' method='get'><button>Console</button></form></body></html>`
		if _, ok := r.executeProbe(context.Background(), chk, "127.0.0.1", port); !ok {
			t.Fatal("UB-0040 must match stock open Tasmota panel with noscript banner")
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

	// Negative-only HTTP matchers must be rejected because they would match 404/500 responses.
	negativeOnlyCases := []struct {
		name  string
		match string
	}{
		{"headers_absent only", "    headers_absent: [\"WWW-Authenticate\"]"},
		{"body_not_contains only", "    body_not_contains: [\"login\"]"},
		{"body_not_regex only", "    body_not_regex: \"(?i)login\""},
		{"negative combination only", "    headers_absent: [\"WWW-Authenticate\"]\n    body_not_contains: [\"password\"]"},
	}
	for _, tc := range negativeOnlyCases {
		raw := "id: UB-TEST-NEG-ONLY\ntitle: Negative Only\nseverity: high\nsafety: read-only\npreconditions:\n  ports_any: [80]\nprobe:\n  type: http\n  method: GET\n  path: /api/secret\n  match:\n" + tc.match + "\n"
		if _, err := Parse([]byte(raw), "neg.yaml"); err == nil {
			t.Fatalf("expected Validate to reject negative-only HTTP matcher (%s)", tc.name)
		}
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

	// Verify legacy TLS 1.2 RSA-kex-only and TLS 1.1 RSA-CBC servers (typical of
	// older Intel AMT firmware) are also detected by probeHTTP.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
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
	rsaCert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}

	legacyCases := []struct {
		name   string
		minVer uint16
		maxVer uint16
		cipher uint16
	}{
		{"TLS 1.2 RSA-AES128-GCM", tls.VersionTLS12, tls.VersionTLS12, tls.TLS_RSA_WITH_AES_128_GCM_SHA256},
		{"TLS 1.1 RSA-AES128-CBC", tls.VersionTLS11, tls.VersionTLS11, tls.TLS_RSA_WITH_AES_128_CBC_SHA},
	}
	for _, tc := range legacyCases {
		t.Run(tc.name, func(t *testing.T) {
			legacySrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/logon.htm" {
					_, _ = io.WriteString(w, "<html><title>Intel(R) AMT</title><body>Intel Active Management Technology</body></html>")
					return
				}
				http.NotFound(w, r)
			}))
			legacySrv.TLS = &tls.Config{
				Certificates: []tls.Certificate{rsaCert},
				MinVersion:   tc.minVer,
				MaxVersion:   tc.maxVer,
				CipherSuites: []uint16{tc.cipher},
			}
			legacySrv.StartTLS()
			defer legacySrv.Close()

			_, lpStr, _ := net.SplitHostPort(legacySrv.Listener.Addr().String())
			lPort, _ := strconv.Atoi(lpStr)

			chkCopy := *byID["UB-2026-0003"]
			chkCopy.Preconditions.PortsAny = []int{lPort}
			if err := chkCopy.Validate(); err != nil {
				t.Fatalf("validate: %v", err)
			}
			lhp := probe.HostProfile{
				Client:    unifi.Client{IP: "127.0.0.1", Hostname: "workstation-amt"},
				OpenPorts: []int{lPort},
				Services:  []probe.Service{{Port: lPort, Protocol: "http", TLS: true}},
			}
			res := NewRunner([]*Check{&chkCopy}, 1).RunHost(context.Background(), lhp)
			if len(res) != 1 || res[0].CheckID != "UB-2026-0003" {
				t.Fatalf("%s: expected UB-2026-0003 match, got %+v", tc.name, res)
			}
		})
	}
}

// TestBuiltinCheckFixes_HomeKit_deCONZ_VNC_STUN_OT_ActiveMQ verifies the
// updated preconditions and matchers across UB-2026-0022, UB-2026-0024,
// UB-0002, UB-0017, UB-0049, and UB-0028.
func TestBuiltinCheckFixes_HomeKit_deCONZ_VNC_STUN_OT_ActiveMQ(t *testing.T) {
	byID := loadBuiltinMap(t)

	// HomeKit HAP odd sf bitmask (bit 0 set).
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

	// deCONZ matches captured UPnP fields + modelid=deCONZ and rejects Philips Hue.
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

	// VNC UB-0002 only schedules [5900, 5901] globally, yet still probes walked displays.
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

	// Passive-flow UDP STUN/TURN and BACnet/KNXip match UB-0017 and UB-0049
	// without requiring TCP open ports or expanding the global TCP sweep.
	stun := byID["UB-0017"]
	if !stun.Preconditions.DiscoveryOnly || len(stun.Preconditions.PortsAny) != 2 || len(stun.Preconditions.ServiceProtoAny) != 2 {
		t.Fatalf("UB-0017 preconditions unexpected: %+v", stun.Preconditions)
	}
	// Start a local UDP STUN responder and verify UDP-only passive flow triggers UB-0017.
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer pc.Close()
	_, stunPortStr, _ := net.SplitHostPort(pc.LocalAddr().String())
	stunPort, _ := strconv.Atoi(stunPortStr)
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, rerr := pc.ReadFrom(buf)
			if rerr != nil {
				return
			}
			if n >= 20 {
				rep := make([]byte, 20)
				binary.BigEndian.PutUint16(rep[0:2], 0x0101)
				copy(rep[4:20], buf[4:20])
				_, _ = pc.WriteTo(rep, addr)
			}
		}
	}()
	stunTestChk := *stun
	stunTestChk.Probe.Port = stunPort
	if err := stunTestChk.Validate(); err != nil {
		t.Fatalf("validate stun clone: %v", err)
	}
	udpOnlySTUN := probe.HostProfile{
		Client:   unifi.Client{IP: "127.0.0.1", Name: "coturn-udp"},
		Services: []probe.Service{{Port: 3478, Transport: "udp", Protocol: "stun"}},
	}
	if got := NewRunner([]*Check{&stunTestChk}, 1).RunHost(context.Background(), udpOnlySTUN); len(got) != 1 || got[0].CheckID != "UB-0017" || got[0].Transport != "udp" {
		t.Fatalf("UDP-only passive-flow STUN server must trigger UB-0017, got %+v", got)
	}
	udpPortOnlySTUN := probe.HostProfile{
		Client:   unifi.Client{IP: "127.0.0.1", Name: "stun-port-only"},
		Services: []probe.Service{{Port: 3478, Transport: "udp", Protocol: "unknown"}},
	}
	if got := NewRunner([]*Check{&stunTestChk}, 1).RunHost(context.Background(), udpPortOnlySTUN); len(got) != 1 || got[0].CheckID != "UB-0017" {
		t.Fatalf("UDP-only port 3478 observation must trigger UB-0017, got %+v", got)
	}
	unrelatedSTUN := probe.HostProfile{
		Client:    unifi.Client{IP: "127.0.0.1", Name: "regular-host"},
		OpenPorts: []int{80, 443},
	}
	if got := NewRunner([]*Check{&stunTestChk}, 1).RunHost(context.Background(), unrelatedSTUN); len(got) != 0 {
		t.Fatalf("unrelated host must NOT trigger UB-0017, got %+v", got)
	}

	ot := byID["UB-0049"]
	bacnetHP := probe.HostProfile{
		Client:   unifi.Client{IP: "192.0.2.91", Name: "bms-plc"},
		Services: []probe.Service{{Port: 47808, Transport: "udp", Protocol: "bacnet"}},
	}
	if got := NewRunner([]*Check{ot}, 1).RunHost(context.Background(), bacnetHP); len(got) != 1 || got[0].CheckID != "UB-0049" || got[0].Transport != "udp" {
		t.Fatalf("passive UDP bacnet service must match UB-0049 with udp transport, got %+v", got)
	}
	knxHP := probe.HostProfile{
		Client:   unifi.Client{IP: "192.0.2.92", Name: "knx-gw"},
		Services: []probe.Service{{Port: 3671, Transport: "udp", Protocol: "knxip"}},
	}
	if got := NewRunner([]*Check{ot}, 1).RunHost(context.Background(), knxHP); len(got) != 1 || got[0].CheckID != "UB-0049" || got[0].Transport != "udp" {
		t.Fatalf("passive UDP knxip service must match UB-0049 with udp transport, got %+v", got)
	}

	// ActiveMQ matches Nerva's activemq-openwire protocol name.
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

// TestHTTPMatchersAndPassiveUDPPreconditionsInMemory exercises UB-0034 large
// truncated JSON matching, UB-0040 body_not_regex / SPA filtering, and UB-0017
// / UB-0049 passive UDP preconditions without requiring loopback sockets.
func TestHTTPMatchersAndPassiveUDPPreconditionsInMemory(t *testing.T) {
	byID := loadBuiltinMap(t)

	// 1. UB-0034 Jupyter matching including >64 KiB truncated listings.
	jup := byID["UB-0034"]
	okResp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	var large strings.Builder
	large.WriteString(`{"name": "", "path": "", "content": [`)
	for i := range 350 {
		if i > 0 {
			large.WriteString(", ")
		}
		large.WriteString(`{"name": "nb-` + strconv.Itoa(i) + `.ipynb", "path": "nb-` + strconv.Itoa(i) + `.ipynb", "last_modified": "2026-11-25T12:00:00.000000Z", "created": "2026-11-25T12:00:00.000000Z", "content": null, "writable": true, "type": "notebook"}`)
	}
	large.WriteString(`], "type": "directory"}`)
	truncLarge := []byte(large.String()[:maxProbeBodyBytes])

	for _, body := range [][]byte{
		[]byte(`{"name": "", "path": "", "type": "directory", "content": []}`),
		[]byte(`{"name":"","type":"directory","content":[]}`),
		truncLarge,
	} {
		if !jup.Probe.Match.matchesHTTP(okResp, body) {
			t.Fatalf("UB-0034 must match valid/truncated Jupyter listing (len=%d)", len(body))
		}
	}
	for _, body := range [][]byte{
		[]byte(`<html><body>Login</body></html>`),
		[]byte(`{"message": "Forbidden", "reason": null}`),
	} {
		if jup.Probe.Match.matchesHTTP(okResp, body) {
			t.Fatalf("UB-0034 must reject non-Jupyter response %q", string(body))
		}
	}

	// 2. UB-0040 Embedded panel rejects password markup variants and SPA/JS shells.
	panel := byID["UB-0040"]
	for _, html := range []string{
		`<html><title>Smart Meter</title><body><form><input type="password" name="pw"></form></body></html>`,
		`<html><title>Smart Meter Controller</title><body><form><input type="PASSWORD" name="pw"></form></body></html>`,
		`<html><title>Smart Meter</title><body><form><input type = "password" name="pw"></form></body></html>`,
		`<html><title>Smart Meter</title><body><form><input type=Password name="pw"></form></body></html>`,
		`<html><head><title>Shelly</title><script type="module" src="/assets/index.js"></script></head><body><div id="app"></div></body></html>`,
		`<html><head><title>Shelly</title></head><body><script>window.bootLogin();</script></body></html>`,
		`<html><head><title>Shelly</title></head><body><a href="/login">Sign in</a><script src="/static/auth-bundle.js"></script></body></html>`,
	} {
		if panel.Probe.Match.matchesHTTP(okResp, []byte(html)) {
			t.Fatalf("UB-0040 must reject login/SPA page %q", html)
		}
	}
	for _, html := range []string{
		`<html><title>Smart Meter</title><body><button>Toggle Relay</button></body></html>`,
		`<html><title>Tasmota</title><body><table><tr><td>OFF</td></tr></table><button>Toggle</button></body></html>`,
	} {
		if !panel.Probe.Match.matchesHTTP(okResp, []byte(html)) {
			t.Fatalf("UB-0040 must match unauthenticated static control panel %q", html)
		}
	}

	// 3. UB-0017 STUN/TURN preconditions match UDP-only passive flows and TCP hints, not unrelated hosts.
	stun := byID["UB-0017"]
	if ports, ok := matchPreconditions(stun, probe.HostProfile{
		Services: []probe.Service{{Port: 3478, Transport: "udp", Protocol: "stun"}},
	}); !ok || len(ports) != 1 || ports[0] != 3478 {
		t.Fatalf("UB-0017 must match UDP-only passive stun flow, got ok=%v ports=%v", ok, ports)
	}
	if ports, ok := matchPreconditions(stun, probe.HostProfile{
		Services: []probe.Service{{Port: 3478, Transport: "udp", Protocol: "unknown"}},
	}); !ok || len(ports) != 1 || ports[0] != 3478 {
		t.Fatalf("UB-0017 must match UDP-only port 3478 observation, got ok=%v ports=%v", ok, ports)
	}
	if ports, ok := matchPreconditions(stun, probe.HostProfile{
		OpenPorts: []int{5349},
	}); !ok || len(ports) != 1 || ports[0] != 3478 {
		t.Fatalf("UB-0017 must match TCP 5349 hint and target UDP 3478, got ok=%v ports=%v", ok, ports)
	}
	if _, ok := matchPreconditions(stun, probe.HostProfile{OpenPorts: []int{80, 443}}); ok {
		t.Fatal("UB-0017 must NOT match unrelated host without STUN/TURN ports or services")
	}

	// 4. UB-0049 OT observe check matches passive UDP bacnet and knxip with udp transport.
	ot := byID["UB-0049"]
	r := NewRunner([]*Check{ot}, 1)
	for _, tc := range []struct {
		proto string
		port  int
	}{
		{"bacnet", 47808},
		{"knxip", 3671},
	} {
		hp := probe.HostProfile{
			Client:   unifi.Client{IP: "192.0.2.95"},
			Services: []probe.Service{{Port: tc.port, Transport: "udp", Protocol: tc.proto}},
		}
		got := r.RunHost(context.Background(), hp)
		if len(got) != 1 || got[0].CheckID != "UB-0049" || got[0].Transport != "udp" || got[0].Port != tc.port {
			t.Fatalf("UB-0049 failed for passive UDP %s: got %+v", tc.proto, got)
		}
	}
}
