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
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	builtinchecks "github.com/karalabe/uniblue/checks"
	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/unifi"
)

var updateGolden = flag.Bool("update-golden", false, "update the embedded check grant table")

// TestCheckGrantsGolden pins the capabilities of every embedded check after merge validation.
func TestCheckGrantsGolden(t *testing.T) {
	checks, err := LoadFromFS(builtinchecks.BuiltinFS)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := Merge(checks)
	if err != nil {
		t.Fatal(err)
	}
	var table strings.Builder
	for _, chk := range merged {
		var grants []string
		for _, g := range chk.Grants {
			desc := fmt.Sprintf("%s/%s", g.Effect, g.Basis)
			if g.WhenField != "" {
				desc += " when " + g.WhenField
			}
			if g.Requires != "" {
				desc += " requires " + g.Requires
			}
			if g.Note != "" {
				desc += " (" + g.Note + ")"
			}
			grants = append(grants, desc)
		}
		slices.Sort(grants)
		fmt.Fprintf(&table, "%s -> [%s]\n", chk.ID, strings.Join(grants, " | "))
	}
	const path = "testdata/check_grants.golden"
	if *updateGolden {
		if err := os.WriteFile(path, []byte(table.String()), 0644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if table.String() != string(want) {
		t.Errorf("check grants changed, review the table and regenerate with -update-golden:\n%s", table.String())
	}
}

// TestGrantValidation checks the evidence ceiling and field vocabulary used for each grant.
func TestGrantValidation(t *testing.T) {
	for _, tc := range []struct {
		name, probe string
		grants      []GrantSpec
		want        string
	}{
		{"missing grants", "tcp", nil, "grants required"},
		{"unknown effect", "tcp", []GrantSpec{{Effect: "admin", Basis: BasisImplied}}, "effect"},
		{"unknown basis", "tcp", []GrantSpec{{Effect: GrantControl, Basis: "likely"}}, "basis"},
		{"missing prerequisite", "tcp", []GrantSpec{{Effect: GrantControl, Basis: BasisConditional, Requires: " "}}, "requires"},
		{"tcp proof", "tcp", []GrantSpec{{Effect: GrantPivot, Basis: BasisProven}}, "at most implied"},
		{"passive proof", "observe", []GrantSpec{{Effect: GrantSecrets, Basis: BasisProven}}, "at most implied"},
		{"foreign field", "redis", []GrantSpec{{Effect: GrantRead, Basis: BasisImplied, WhenField: "connack"}}, "when_field"},
		{"compound predicate", "mqtt", []GrantSpec{{Effect: GrantRead, Basis: BasisImplied, WhenField: "connack == 0 || true"}}, "when_field"},
		{"unmatched JSON path", "http", []GrantSpec{{Effect: GrantRead, Basis: BasisImplied, WhenField: "$.unmatched"}}, "when_field"},
		{"HTTP header alone", "http", []GrantSpec{{Effect: GrantRead, Basis: BasisProven}}, "cannot prove read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			chk := Check{
				ID: "UB-TEST", Title: "Grant test", Severity: SeverityHigh, Safety: "read-only",
				Preconditions: Preconditions{PortsAny: []int{80}},
				Probe:         ProbeSpec{Type: tc.probe, Path: "/", Match: MatchSpec{Status: []int{200}}},
				Grants:        tc.grants,
			}
			if err := chk.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Validate() = %v, want %q", err, tc.want)
			}
		})
	}
	// Risk-bearing advertised checks (severity > info) are not inventory-only and require grants.
	highAdv := Check{
		ID: "UB-ADV", Title: "Advertised control", Claim: ClaimServiceAdvertised, Severity: SeverityHigh, Safety: "read-only",
		Preconditions: Preconditions{MDNSTypeAny: []string{"_hap._tcp"}},
		Probe:         ProbeSpec{Type: "observe"},
	}
	if err := highAdv.Validate(); err == nil || !strings.Contains(err.Error(), "grants required") {
		t.Errorf("high-severity advertised check without grants: %v", err)
	}
	// Normalized TLS version and IPMI cipher_zero predicates validate cleanly.
	for _, chk := range []Check{
		{ID: "UB-TLS", Title: "TLS 1.0", Severity: SeverityMedium, Safety: "read-only", Preconditions: Preconditions{PortsAny: []int{443}}, Probe: ProbeSpec{Type: "tls-legacy"}, Grants: []GrantSpec{{Effect: GrantSecrets, Basis: BasisImplied, WhenField: "tls_version == 1.0"}}},
		{ID: "UB-IPMI", Title: "IPMI", Severity: SeverityHigh, Safety: "read-only", Preconditions: Preconditions{PortsAny: []int{623}}, Probe: ProbeSpec{Type: "ipmi"}, Grants: []GrantSpec{{Effect: GrantControl, Basis: BasisImplied, WhenField: "cipher_zero"}}},
	} {
		if err := chk.Validate(); err != nil {
			t.Errorf("%s Validate() = %v", chk.ID, err)
		}
	}
}

// TestSupersededGrants checks that suppression rejects cycles and preserves unconditional effects across check sources.
func TestSupersededGrants(t *testing.T) {
	generic := &Check{ID: "UB-GENERIC", Grants: []GrantSpec{{Effect: GrantRead, Basis: BasisImplied}, {Effect: GrantSecrets, Basis: BasisImplied}}}
	specific := &Check{ID: "UB-SPECIFIC", Supersedes: []string{generic.ID}, Grants: []GrantSpec{{Effect: GrantRead, Basis: BasisImplied}}}
	_, err := Merge([]*Check{specific}, []*Check{generic})
	if err == nil || !strings.Contains(err.Error(), specific.ID) || !strings.Contains(err.Error(), generic.ID) || !strings.Contains(err.Error(), "secrets") {
		t.Fatalf("missing superseded grant: %v", err)
	}
	// Self-supersession and mutual cycles must fail so RunHost never suppresses every finding.
	selfSup := &Check{ID: "UB-SELF", Supersedes: []string{"UB-SELF"}, Grants: []GrantSpec{{Effect: GrantRead, Basis: BasisImplied}}}
	if _, err := Merge([]*Check{selfSup}); err == nil || !strings.Contains(err.Error(), "itself") {
		t.Fatalf("self-supersession should fail: %v", err)
	}
	cycA := &Check{ID: "UB-CYC-A", Supersedes: []string{"UB-CYC-B"}, Grants: []GrantSpec{{Effect: GrantRead, Basis: BasisImplied}}}
	cycB := &Check{ID: "UB-CYC-B", Supersedes: []string{"UB-CYC-A"}, Grants: []GrantSpec{{Effect: GrantRead, Basis: BasisImplied}}}
	if _, err := Merge([]*Check{cycA, cycB}); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("supersedes cycle should fail: %v", err)
	}
	// A conditional when_field grant cannot cover an unconditional superseded grant.
	narrow := &Check{ID: "UB-NARROW", Supersedes: []string{"UB-GENERIC"}, Grants: []GrantSpec{
		{Effect: GrantRead, Basis: BasisImplied},
		{Effect: GrantSecrets, Basis: BasisImplied, WhenField: "$.x == 1"},
	}}
	if _, err := Merge([]*Check{narrow, generic}); err == nil || !strings.Contains(err.Error(), "unconditional") {
		t.Fatalf("conditional grant should not cover unconditional superseded grant: %v", err)
	}
}

// TestGrantObservations exercises multi-step data collection, filtering and transient serialization.
func TestGrantObservations(t *testing.T) {
	chk, err := Parse([]byte(`id: UB-OBS
title: Feature settings
safety: read-only
preconditions: {ports_any: [80]}
probe:
  type: http
  steps:
    - paths: [/old, /settings]
      match:
        status: [200]
        json_match: [{path: $.feature, exists: true}, {path: $.ready, equals: "true"}]
    - path: /mode
      match: {status: [200], json_match: [{path: $.admin, exists: true}]}
grants:
  - {effect: read, basis: proven}
  - {effect: configure, basis: proven, when_field: $.admin == true}
  - {effect: control, basis: implied, when_field: $.feature}
`), "obs.yaml")
	if err != nil {
		t.Fatal(err)
	}
	got := runBuiltinHTTP(t, 80, func(w http.ResponseWriter, r *http.Request) {
		body := map[string]string{
			"/old":      `{"feature":"discard","ready":false}`,
			"/settings": `{"feature":{"private":"value"},"ready":true}`,
			"/mode":     `{"admin":false,"unmatched":"private"}`,
		}
		fmt.Fprint(w, body[r.URL.Path])
	}, chk)
	if len(got) != 1 {
		t.Fatalf("findings = %v", got)
	}
	obs := got[0].Observation
	if obs.Level != ObsPrivilegeVerified || len(obs.Fields) != 4 || obs.Fields["$.ready"] != "true" || obs.Fields["$.admin"] != "false" || obs.Fields["status"] != "200" {
		t.Fatalf("observation = %+v", obs)
	}
	if v, ok := obs.Fields["$.feature"]; !ok || v != "" {
		t.Fatalf("object presence retained contents or failed to match: %q, %t", v, ok)
	}
	if grants := EffectiveGrants(chk, obs); !slices.Equal(grants, []GrantSpec{chk.Grants[0], chk.Grants[2]}) {
		t.Errorf("effective grants = %v", grants)
	}
	if grants := EffectiveGrants(chk, Observation{Level: ObsService}); len(grants) != 0 {
		t.Errorf("service observation yielded proven grants: %v", grants)
	}
	if grants := EffectiveGrants(chk, Observation{}); !slices.Equal(grants, chk.Grants[:1]) {
		t.Errorf("grants without fields = %v", grants)
	}
	with, err := json.Marshal(got[0])
	if err != nil {
		t.Fatal(err)
	}
	got[0].Observation = Observation{}
	without, err := json.Marshal(got[0])
	if err != nil || !bytes.Equal(with, without) || bytes.Contains(bytes.ToLower(with), []byte("observation")) {
		t.Fatalf("observation changed finding JSON: %s (%v)", with, err)
	}
}

// TestValidationSafetyGuardrails verifies that Validate rejects non-read-only
// checks, mutating HTTP methods, external URLs, missing preconditions, and
// oversized probe timeouts.
func TestValidationSafetyGuardrails(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{
			name: "rejects non-read-only safety",
			yaml: `
id: UB-TEST-01
title: Bad Safety
severity: high
safety: intrusive
preconditions:
  ports_any: [80]
probe:
  type: http
  method: GET
  path: /
`,
		},
		{
			name: "rejects POST http method",
			yaml: `
id: UB-TEST-02
title: Forbidden Method
severity: high
safety: read-only
preconditions:
  ports_any: [80]
probe:
  type: http
  method: POST
  path: /reboot
`,
		},
		{
			name: "rejects external url in path",
			yaml: `
id: UB-TEST-03
title: SSRF Attempt
severity: high
safety: read-only
preconditions:
  ports_any: [80]
probe:
  type: http
  method: GET
  path: https://evil.example/exfil
`,
		},
		{
			name: "requires precondition ports",
			yaml: `
id: UB-TEST-04
title: Missing Ports
severity: low
safety: read-only
probe:
  type: tcp
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.yaml), tc.name); err == nil {
				t.Fatalf("expected Parse to reject %s", tc.name)
			}
		})
	}
}

// TestHTTPCheckExecution verifies end-to-end precondition matching and HTTP
// probe evaluation against a local mock web server.
func TestHTTPCheckExecution(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/system/status" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"fan_speed":3,"bypass_state":"open"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	chk, err := Parse([]byte(`
id: UB-HVAC-001
title: Unauthenticated Ventilation API
grants: [{effect: read, basis: proven}]
category: unauth-control
severity: high
safety: read-only
preconditions:
  ports_any: [`+portStr+`]
  http_title_regex: "(?i)ventilation"
probe:
  type: http
  method: GET
  path: /api/v1/system/status
  match:
    status: [200]
    body_contains_all: ["fan_speed", "bypass_state"]
    headers_absent: ["WWW-Authenticate"]
    redact_body: true
`), "hvac.yaml")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	hp := probe.HostProfile{
		Client:    unifi.Client{IP: "127.0.0.1", MAC: "aa:bb:cc:dd:ee:01", Hostname: "ventilation"},
		OpenPorts: []int{port},
		HTTP: map[int]probe.HTTPBanner{
			port: {Scheme: "http", StatusCode: 200, Title: "AirFlow Ventilation"},
		},
	}

	findings := NewRunner([]*Check{chk}, 2).RunAll(context.Background(), []probe.HostProfile{hp})
	if len(findings) != 1 || findings[0].CheckID != "UB-HVAC-001" {
		t.Fatalf("expected 1 finding for UB-HVAC-001, got %+v", findings)
	}
}

// TestProtocolProbes verifies read-only TCP/UDP protocol probes (MQTT, Modbus,
// VNC, Telnet, Denon/Marantz AVR, ComfoConnect, Ethereum RPC, ADB, RDP NLA,
// anonymous FTP, ES File Explorer, and Redis) against local mock servers.
func TestProtocolProbes(t *testing.T) {
	t.Run("mqtt anonymous accepted", func(t *testing.T) {
		port, closeFn := startMockTCP(t, func(conn net.Conn) {
			buf := make([]byte, 64)
			_, _ = conn.Read(buf)
			// Reply with MQTT CONNACK accepted (0x20 0x02 0x00 0x00).
			_, _ = conn.Write([]byte{0x20, 0x02, 0x00, 0x00})
		})
		defer closeFn()

		var obs Observation
		if _, ok := probeMQTT(context.Background(), "127.0.0.1", port, &obs); !ok || obs.Fields["connack"] != "0" {
			t.Fatal("expected anonymous MQTT probe to match")
		}
	})

	t.Run("modbus slave responds", func(t *testing.T) {
		port, closeFn := startMockTCP(t, func(conn net.Conn) {
			req := make([]byte, 11)
			if _, err := io.ReadFull(conn, req); err != nil {
				return
			}
			// Echo transaction ID + protocol ID 0x0000 + valid Modbus exception response.
			_, _ = conn.Write([]byte{req[0], req[1], 0x00, 0x00, 0x00, 0x03, 0x01, 0xAB, 0x01})
		})
		defer closeFn()

		if _, ok := probeModbus(context.Background(), "127.0.0.1", port, &Observation{}); !ok {
			t.Fatal("expected Modbus probe to match")
		}
	})

	t.Run("rtsp unauthenticated describe vs auth challenge", func(t *testing.T) {
		portOpen, closeOpen := startMockTCP(t, func(conn net.Conn) {
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
					_, _ = io.WriteString(conn, "RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: OPTIONS, DESCRIBE, PLAY\r\n\r\n")
				} else if strings.HasPrefix(reqLine, "DESCRIBE ") {
					sdp := "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=Cam\r\nm=video 0 RTP/AVP 96\r\n"
					_, _ = io.WriteString(conn, "RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Type: application/sdp\r\nContent-Length: "+strconv.Itoa(len(sdp))+"\r\n\r\n"+sdp)
				}
			}
		})
		defer closeOpen()

		if _, ok := probeRTSP(context.Background(), "127.0.0.1", portOpen, &Observation{}); !ok {
			t.Fatal("expected unauthenticated RTSP DESCRIBE probe to match")
		}

		portAuth, closeAuth := startMockTCP(t, func(conn net.Conn) {
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
					_, _ = io.WriteString(conn, "RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: OPTIONS, DESCRIBE, PLAY\r\n\r\n")
				} else if strings.HasPrefix(reqLine, "DESCRIBE ") {
					_, _ = io.WriteString(conn, "RTSP/1.0 401 Unauthorized\r\nCSeq: 2\r\nWWW-Authenticate: Digest realm=\"cam\"\r\n\r\n")
				}
			}
		})
		defer closeAuth()

		if ev, ok := probeRTSP(context.Background(), "127.0.0.1", portAuth, &Observation{}); ok {
			t.Fatalf("expected password-protected RTSP camera (DESCRIBE 401) NOT to match, got ev=%q", ev)
		}
	})

	t.Run("vnc confirmed serverinit", func(t *testing.T) {
		port, closeFn := startMockTCP(t, func(conn net.Conn) {
			_, _ = io.WriteString(conn, "RFB 003.008\n")
			ver := make([]byte, 12)
			if _, err := io.ReadFull(conn, ver); err != nil {
				return
			}
			// 2 security types: VNC Auth (2) and None (1).
			_, _ = conn.Write([]byte{0x02, 0x02, 0x01})
			sel := make([]byte, 1)
			if _, err := io.ReadFull(conn, sel); err != nil || sel[0] != 0x01 {
				return
			}
			// SecurityResult = 0 (OK).
			_, _ = conn.Write([]byte{0x00, 0x00, 0x00, 0x00})
			// Read ClientInit (shared=1).
			ci := make([]byte, 1)
			if _, err := io.ReadFull(conn, ci); err != nil || ci[0] != 0x01 {
				return
			}
			// Send ServerInit with 1024x768 and desktop name "QEMU (Ubuntu)".
			name := "QEMU (Ubuntu)"
			hdr := make([]byte, 24)
			binary.BigEndian.PutUint16(hdr[0:2], 1024)
			binary.BigEndian.PutUint16(hdr[2:4], 768)
			binary.BigEndian.PutUint32(hdr[20:24], uint32(len(name)))
			_, _ = conn.Write(append(hdr, []byte(name)...))
		})
		defer closeFn()

		ev, ok := probeVNC(context.Background(), "127.0.0.1", port, &Observation{})
		if !ok {
			t.Fatal("expected VNC ServerInit probe to match")
		}
		if !strings.Contains(ev, "QEMU (Ubuntu)") || !strings.Contains(ev, "1024x768") {
			t.Fatalf("unexpected VNC evidence: %q", ev)
		}
	})

	t.Run("vnc securityresult rejected", func(t *testing.T) {
		port, closeFn := startMockTCP(t, func(conn net.Conn) {
			_, _ = io.WriteString(conn, "RFB 003.008\n")
			ver := make([]byte, 12)
			_, _ = io.ReadFull(conn, ver)
			_, _ = conn.Write([]byte{0x01, 0x01})
			sel := make([]byte, 1)
			_, _ = io.ReadFull(conn, sel)
			// SecurityResult = 1 (Failed) -> must not report false positive.
			_, _ = conn.Write([]byte{0x00, 0x00, 0x00, 0x01})
		})
		defer closeFn()

		if _, ok := probeVNC(context.Background(), "127.0.0.1", port, &Observation{}); ok {
			t.Fatal("expected failed SecurityResult to reject VNC match")
		}
	})

	t.Run("avr read-only power query", func(t *testing.T) {
		port, closeFn := startMockTCP(t, func(conn net.Conn) {
			buf := make([]byte, 16)
			n, _ := conn.Read(buf)
			if strings.HasPrefix(string(buf[:n]), "PW?") {
				_, _ = io.WriteString(conn, "PWSTANDBY\r")
			}
		})
		defer closeFn()

		ev, ok := probeDenonMarantzAVR(context.Background(), "127.0.0.1", port, &Observation{})
		if !ok || !strings.Contains(ev, "PWSTANDBY") {
			t.Fatalf("expected AVR probe match with PWSTANDBY, got ok=%v ev=%q", ok, ev)
		}
	})

	t.Run("telnet iac negotiation and banner", func(t *testing.T) {
		port, closeFn := startMockTCP(t, func(conn net.Conn) {
			// Send IAC DO ECHO followed by a standard login prompt.
			_, _ = conn.Write([]byte{255, 253, 1})
			reply := make([]byte, 3)
			_, _ = io.ReadFull(conn, reply)
			_, _ = io.WriteString(conn, "RouterOS login: ")
		})
		defer closeFn()

		var obs Observation
		ev, ok := probeTelnet(context.Background(), "127.0.0.1", port, &obs)
		if !ok || obs.Fields["prompt"] != "login" || !strings.Contains(ev, "RouterOS login:") {
			t.Fatalf("expected telnet login banner evidence, got ok=%v ev=%q", ok, ev)
		}
	})

	t.Run("ethereum json-rpc exposed", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":"Geth/v1.15.0-stable/linux-amd64/go1.24.0"}`)
		}))
		defer srv.Close()

		_, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
		port, _ := strconv.Atoi(portStr)

		r := NewRunner(nil, 1)
		ev, ok := r.probeEthereumRPC(context.Background(), "127.0.0.1", port, &Observation{})
		if !ok || !strings.Contains(ev, "Geth/v1.15.0") {
			t.Fatalf("expected eth-rpc probe match with Geth version, got ok=%v ev=%q", ok, ev)
		}
	})

	t.Run("adb unauthenticated cnxn accepted", func(t *testing.T) {
		port, closeFn := startMockTCP(t, func(conn net.Conn) {
			hdr := make([]byte, 24)
			if _, err := io.ReadFull(conn, hdr); err != nil {
				return
			}
			// Consume client payload.
			pLen := binary.LittleEndian.Uint32(hdr[12:16])
			if pLen > 0 && pLen < 1024 {
				_, _ = io.ReadFull(conn, make([]byte, pLen))
			}
			banner := []byte("device::ro.product.model=SHIELD Android TV\x00")
			var sum uint32
			for _, b := range banner {
				sum += uint32(b)
			}
			const cmdCNXN uint32 = 0x4E584E43
			resp := make([]byte, 24+len(banner))
			binary.LittleEndian.PutUint32(resp[0:4], cmdCNXN)
			binary.LittleEndian.PutUint32(resp[4:8], 0x01000000)
			binary.LittleEndian.PutUint32(resp[8:12], 0x00004000)
			binary.LittleEndian.PutUint32(resp[12:16], uint32(len(banner)))
			binary.LittleEndian.PutUint32(resp[16:20], sum)
			binary.LittleEndian.PutUint32(resp[20:24], cmdCNXN^0xffffffff)
			copy(resp[24:], banner)
			_, _ = conn.Write(resp)
		})
		defer closeFn()

		ev, ok := probeADB(context.Background(), "127.0.0.1", port, &Observation{})
		if !ok || !strings.Contains(ev, "SHIELD Android TV") {
			t.Fatalf("expected ADB CNXN match with device model, got ok=%v ev=%q", ok, ev)
		}
	})

	t.Run("adb auth challenge rejected cleanly", func(t *testing.T) {
		port, closeFn := startMockTCP(t, func(conn net.Conn) {
			hdr := make([]byte, 24)
			if _, err := io.ReadFull(conn, hdr); err != nil {
				return
			}
			pLen := binary.LittleEndian.Uint32(hdr[12:16])
			if pLen > 0 && pLen < 1024 {
				_, _ = io.ReadFull(conn, make([]byte, pLen))
			}
			const cmdAUTH uint32 = 0x48545541 // "AUTH"
			resp := make([]byte, 24)
			binary.LittleEndian.PutUint32(resp[0:4], cmdAUTH)
			binary.LittleEndian.PutUint32(resp[4:8], 1) // AUTH_TOKEN
			binary.LittleEndian.PutUint32(resp[20:24], cmdAUTH^0xffffffff)
			_, _ = conn.Write(resp)
		})
		defer closeFn()

		if ev, ok := probeADB(context.Background(), "127.0.0.1", port, &Observation{}); ok {
			t.Fatalf("expected ADB AUTH challenge to NOT match unauth check, got ev=%q", ev)
		}
	})

	t.Run("rdp without nla accepted vs nla enforced", func(t *testing.T) {
		// Mock RDP server with NLA disabled (TYPE_RDP_NEG_RSP = 0x02, PROTOCOL_RDP = 0x00).
		portOpen, closeOpen := startMockTCP(t, func(conn net.Conn) {
			req := make([]byte, 19)
			if _, err := io.ReadFull(conn, req); err != nil {
				return
			}
			resp := []byte{
				0x03, 0x00, 0x00, 0x13,
				0x0e, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
			}
			_, _ = conn.Write(resp)
		})
		defer closeOpen()

		if _, ok := probeRDPNoNLA(context.Background(), "127.0.0.1", portOpen, &Observation{}); !ok {
			t.Fatal("expected RDP server with NLA disabled to match")
		}

		// Mock RDP server enforcing NLA (TYPE_RDP_NEG_FAILURE = 0x03, HYBRID_REQUIRED_BY_SERVER = 0x05).
		portNLA, closeNLA := startMockTCP(t, func(conn net.Conn) {
			req := make([]byte, 19)
			if _, err := io.ReadFull(conn, req); err != nil {
				return
			}
			resp := []byte{
				0x03, 0x00, 0x00, 0x13,
				0x0e, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x03, 0x00, 0x08, 0x00, 0x05, 0x00, 0x00, 0x00,
			}
			_, _ = conn.Write(resp)
		})
		defer closeNLA()

		if ev, ok := probeRDPNoNLA(context.Background(), "127.0.0.1", portNLA, &Observation{}); ok {
			t.Fatalf("expected NLA-enforced RDP server NOT to match, got ev=%q", ev)
		}
	})

	t.Run("ftp anonymous login vs auth required", func(t *testing.T) {
		portAnon, closeAnon := startMockTCP(t, func(conn net.Conn) {
			br := bufio.NewReader(conn)
			_, _ = io.WriteString(conn, "220 WiFi FTP Server Ready\r\n")
			_, _ = br.ReadString('\n')
			_, _ = io.WriteString(conn, "331 Anonymous login ok\r\n")
			_, _ = br.ReadString('\n')
			_, _ = io.WriteString(conn, "230 Login successful\r\n")
		})
		defer closeAnon()

		if _, ok := probeFTPAnonymous(context.Background(), "127.0.0.1", portAnon, &Observation{}); !ok {
			t.Fatal("expected anonymous FTP to match")
		}

		portAuth, closeAuth := startMockTCP(t, func(conn net.Conn) {
			br := bufio.NewReader(conn)
			_, _ = io.WriteString(conn, "220 Secure FTP\r\n")
			_, _ = br.ReadString('\n')
			_, _ = io.WriteString(conn, "530 Anonymous access denied\r\n")
		})
		defer closeAuth()

		if ev, ok := probeFTPAnonymous(context.Background(), "127.0.0.1", portAuth, &Observation{}); ok {
			t.Fatalf("expected auth-only FTP NOT to match, got ev=%q", ev)
		}
	})

	t.Run("redis pong vs noauth", func(t *testing.T) {
		portOpen, closeOpen := startMockTCP(t, func(conn net.Conn) {
			buf := make([]byte, 16)
			_, _ = conn.Read(buf)
			_, _ = io.WriteString(conn, "+PONG\r\n")
		})
		defer closeOpen()

		if _, ok := probeRedisUnauth(context.Background(), "127.0.0.1", portOpen, &Observation{}); !ok {
			t.Fatal("expected unauth Redis +PONG to match")
		}

		portAuth, closeAuth := startMockTCP(t, func(conn net.Conn) {
			buf := make([]byte, 16)
			_, _ = conn.Read(buf)
			_, _ = io.WriteString(conn, "-NOAUTH Authentication required.\r\n")
		})
		defer closeAuth()

		if ev, ok := probeRedisUnauth(context.Background(), "127.0.0.1", portAuth, &Observation{}); ok {
			t.Fatalf("expected auth-protected Redis NOT to match, got ev=%q", ev)
		}
	})

	t.Run("es file explorer cve-2019-6447", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"name":"Old Android","version":"9","model":"SM-G950F","sdk":"28"}`)
		}))
		defer srv.Close()
		_, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
		port, _ := strconv.Atoi(portStr)

		r := NewRunner(nil, 1)
		ev, ok := r.probeESFileExplorer(context.Background(), "127.0.0.1", port, &Observation{})
		if !ok || !strings.Contains(ev, "SM-G950F") {
			t.Fatalf("expected ES File Explorer match with SM-G950F, got ok=%v ev=%q", ok, ev)
		}
	})
}

// TestIoTBuiltinHTTPChecksAuthVsUnauth verifies built-in HTTP appliance checks
// (Shelly Gen2, Transmission, Brother CVE-2024-51977, iOS SSH ports_all, and
// Python SimpleHTTP) match unauthenticated endpoints and reject auth challenges.
func TestIoTBuiltinHTTPChecksAuthVsUnauth(t *testing.T) {
	allChecks, err := LoadFromFS(builtinchecks.BuiltinFS)
	if err != nil {
		t.Fatalf("LoadFromFS: %v", err)
	}
	byID := make(map[string]*Check, len(allChecks))
	for _, c := range allChecks {
		byID[c.ID] = c
	}

	// Verify Shelly Gen2 (UB-2026-0032): matches 200 JSON, rejects 401 Digest.
	t.Run("shelly_gen2_unauth_vs_digest", func(t *testing.T) {
		chk := byID["UB-2026-0032"]
		authEnabled := false
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/rpc/Shelly.GetConfig" {
				http.NotFound(w, r)
				return
			}
			if authEnabled {
				w.Header().Set("WWW-Authenticate", `Digest realm="shellyplus1"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = io.WriteString(w, `{"sys":{"device":{"fw_id":"1.4.4"}},"wifi":{"sta":{"ssid":"lab"}}}`)
		}))
		defer srv.Close()
		_, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
		port, _ := strconv.Atoi(portStr)
		r := NewRunner(nil, 1)

		if _, ok := r.executeProbe(context.Background(), chk, "127.0.0.1", port); !ok {
			t.Fatal("expected unauth Shelly Gen2 to match UB-2026-0032")
		}
		authEnabled = true
		if _, ok := r.executeProbe(context.Background(), chk, "127.0.0.1", port); ok {
			t.Fatal("expected Digest-protected Shelly Gen2 NOT to match UB-2026-0032")
		}
	})

	// Verify Transmission RPC (UB-2026-0069): matches 409+Session-Id, rejects 401.
	t.Run("transmission_409_vs_401", func(t *testing.T) {
		chk := byID["UB-2026-0069"]
		authEnabled := false
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/transmission/rpc" {
				http.NotFound(w, r)
				return
			}
			if authEnabled {
				w.Header().Set("WWW-Authenticate", `Basic realm="Transmission"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("X-Transmission-Session-Id", "abc123session")
			w.WriteHeader(http.StatusConflict)
		}))
		defer srv.Close()
		_, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
		port, _ := strconv.Atoi(portStr)
		r := NewRunner(nil, 1)

		if _, ok := r.executeProbe(context.Background(), chk, "127.0.0.1", port); !ok {
			t.Fatal("expected unauth Transmission 409 to match UB-2026-0069")
		}
		authEnabled = true
		if _, ok := r.executeProbe(context.Background(), chk, "127.0.0.1", port); ok {
			t.Fatal("expected auth-protected Transmission 401 NOT to match UB-2026-0069")
		}
	})

	// Verify Brother CVE-2024-51977 (UB-2026-0053) CSV disclosure.
	t.Run("brother_cve_2024_51977", func(t *testing.T) {
		chk := byID["UB-2026-0053"]
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/etc/mnt_info.csv" {
				_, _ = io.WriteString(w, "\"Node Name\",\"Model Name\",\"Serial No.\"\n\"BRN001122\",\"MFC-L2750DW\",\"E12345678\"\n")
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()
		_, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
		port, _ := strconv.Atoi(portStr)
		r := NewRunner(nil, 1)

		if _, ok := r.executeProbe(context.Background(), chk, "127.0.0.1", port); !ok {
			t.Fatal("expected vulnerable Brother /etc/mnt_info.csv to match UB-2026-0053")
		}
	})

	// Verify ports_all precondition (UB-2026-0073 Jailbroken iOS SSH):
	// requires BOTH 62078 and 22, so neither stock iOS (62078 only) nor Mac/Linux (22 only) triggers.
	t.Run("ports_all_jailbroken_ios", func(t *testing.T) {
		chk := byID["UB-2026-0073"]
		stockIOS := probe.HostProfile{OpenPorts: []int{62078}}
		normalMac := probe.HostProfile{OpenPorts: []int{22}}
		jailbrokenIOS := probe.HostProfile{OpenPorts: []int{22, 62078}}

		if _, ok := matchPreconditions(chk, stockIOS); ok {
			t.Fatal("stock iOS (62078 only) must NOT match jailbreak SSH check")
		}
		if _, ok := matchPreconditions(chk, normalMac); ok {
			t.Fatal("normal Mac/Linux (22 only) must NOT match jailbreak SSH check")
		}
		ports, ok := matchPreconditions(chk, jailbrokenIOS)
		if !ok || len(ports) != 1 || ports[0] != 22 {
			t.Fatalf("jailbroken iOS (22+62078) expected probe port [22], got ok=%v ports=%v", ok, ports)
		}
	})

	// Verify header_contains matcher (UB-0038 Python SimpleHTTP).
	t.Run("python_simplehttp_header_contains", func(t *testing.T) {
		chk := byID["UB-0038"]
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "SimpleHTTP/0.6 Python/3.12.2")
			_, _ = io.WriteString(w, "<html><title>Directory listing for /</title><body><h1>Directory listing for /</h1></body></html>")
		}))
		defer srv.Close()
		_, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
		port, _ := strconv.Atoi(portStr)
		r := NewRunner(nil, 1)

		if _, ok := r.executeProbe(context.Background(), chk, "127.0.0.1", port); !ok {
			t.Fatal("expected Python SimpleHTTP to match UB-0038")
		}
	})
}

// TestFindingsFromProfilesDeduplicationAndNormalization verifies that Nerva
// finding IDs normalize cleanly and skip properties already covered by YAML checks.
func TestFindingsFromProfilesDeduplicationAndNormalization(t *testing.T) {
	profiles := []probe.HostProfile{
		{
			Client: unifi.Client{IP: "10.0.255.0", MAC: "aa:01", Name: "Home Assistant", NetworkName: "Default"},
			Services: []probe.Service{
				{
					Port:            3000,
					Protocol:        "http",
					AnonymousAccess: true,
					Findings: []probe.ServiceFinding{
						{ID: "grafana:10.0.0-anon-access", Severity: "medium", Evidence: "unauth query succeeded"},
					},
				},
				{
					Port:     5900,
					Protocol: "vnc",
					Findings: []probe.ServiceFinding{
						{ID: "vnc-none", Severity: "high", Evidence: "duplicate on port 5900"},
					},
				},
			},
		},
	}

	// Simulate UB-0002 already covering port 5900 on 10.0.255.0.
	existing := []Finding{
		{CheckID: "UB-0002", Client: profiles[0].Client, Port: 5900},
	}

	got := FindingsFromProfiles(profiles, existing)
	if len(got) != 1 {
		t.Fatalf("expected 1 non-duplicate Nerva finding, got %d: %+v", len(got), got)
	}
	if got[0].CheckID != "NERVA-GRAFANA-ANON-ACCESS" {
		t.Fatalf("expected version-stripped check ID NERVA-GRAFANA-ANON-ACCESS, got %q", got[0].CheckID)
	}
	if got[0].BaseSeverity != SeverityMedium {
		t.Fatalf("expected medium severity, got %v", got[0].BaseSeverity)
	}
}

// startMockTCP starts a localhost TCP server that handles connections with fn
// and returns its listening port plus a cleanup function.
func startMockTCP(t *testing.T, fn func(net.Conn)) (int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				fn(c)
			}(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, func() { _ = ln.Close() }
}

type stepTransport func(*http.Request) (*http.Response, error)

func (f stepTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestHTTPStepValidation verifies read-only and schema guardrails for probe.steps.
func TestHTTPStepValidation(t *testing.T) {
	const header = "id: UB-TEST-HTTP\ntitle: HTTP step test\ngrants: [{effect: read, basis: implied}]\nsafety: read-only\npreconditions: {ports_any: [80]}\nprobe: "
	const valid = "{path: /info, match: {status: [200]}}"
	inSteps := func(step string) string { return "{type: http, steps: [" + valid + ", " + step + "]}" }

	for _, tc := range []struct{ name, spec, wantErr string }{
		{"forbidden method", inSteps("{method: POST, path: /, match: {status: [200]}}"), "method"},
		{"absolute path", inSteps("{path: 'https://example.org/', match: {status: [200]}}"), "relative path"},
		{"scheme-relative path", inSteps("{paths: [/ok, //example.org], match: {status: [200]}}"), "relative path"},
		{"forbidden header", inSteps("{path: /, request_headers: {Cookie: session}, match: {status: [200]}}"), "allowlist"},
		{"negative matcher only", inSteps("{path: /, match: {headers_absent: [Server]}}"), "positive"},
		{"bare root JSON exists only", inSteps("{path: /, match: {json_match: [{path: '$', exists: true}]}}"), "positive"},
		{"empty steps", "{type: http, steps: []}", "between"},
		{"too many steps", "{type: http, steps: [" + strings.Repeat(valid+", ", maxProbeSteps) + valid + "]}", "between"},
		{"mixed top-level path", "{type: http, path: /, steps: [" + valid + "]}", "combined"},
		{"mixed top-level match", "{type: http, match: {status: [200]}, steps: [" + valid + "]}", "combined"},
		{"non-HTTP probe", "{type: tcp, steps: [" + valid + "]}", "requires probe.type http"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(header+tc.spec), "test.yaml"); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
	// Preserve compatibility for single-request paths with interior "//".
	if _, err := Parse([]byte(header+"{type: http, path: /api//status, match: {status: [200]}}"), "test.yaml"); err != nil {
		t.Fatalf("interior // path should remain valid: %v", err)
	}
}

// TestHTTPStepExecutionAndLegacyFraming checks multi-step matching, body read errors,
// and legacy single-request resilience against truncated embedded HTTP responses.
func TestHTTPStepExecutionAndLegacyFraming(t *testing.T) {
	const header = "id: UB-TEST-HTTP\ntitle: HTTP test\ngrants: [{effect: read, basis: implied}]\nsafety: read-only\npreconditions: {ports_any: [80]}\nprobe: "
	multi, err := Parse([]byte(header+`{type: http, timeout: 100ms, steps: [
		{paths: [/first, /alt], match: {status: [200], body_regex: '^ready', evidence_summary: ready}},
		{method: HEAD, path: /second, match: {status: [200]}}
	]}`), "test.yaml")
	if err != nil {
		t.Fatal(err)
	}

	// Happy path via fallback /alt + shared deadline.
	r := NewRunner(nil, 1)
	var seen []string
	var deadline time.Time
	r.httpClient.Transport = stepTransport(func(req *http.Request) (*http.Response, error) {
		seen = append(seen, req.URL.Path)
		dl, ok := req.Context().Deadline()
		if !ok || (!deadline.IsZero() && !deadline.Equal(dl)) {
			t.Fatalf("missing or mismatched deadline on %s", req.URL.Path)
		}
		deadline = dl
		if req.URL.Path == "/first" {
			return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ready"))}, nil
	})
	if ev, ok := r.executeProbe(t.Context(), multi, "127.0.0.1", 80); !ok || !slices.Equal(seen, []string{"/first", "/alt", "/second"}) || !strings.Contains(ev, "ready") {
		t.Fatalf("multi-step match failed: ok=%t seen=%v ev=%q", ok, seen, ev)
	}

	// Multi-step sequences reject responses whose body read fails mid-stream.
	r.httpClient.Transport = stepTransport(func(req *http.Request) (*http.Response, error) {
		pr, pw := io.Pipe()
		go func() {
			_, _ = io.WriteString(pw, "ready")
			_ = pw.CloseWithError(io.ErrUnexpectedEOF)
		}()
		return &http.Response{StatusCode: 200, Body: io.NopCloser(pr)}, nil
	})
	if _, ok := r.executeProbe(t.Context(), multi, "127.0.0.1", 80); ok {
		t.Fatal("multi-step check must reject truncated body read error")
	}

	// Legacy single-request HTTP check must still match sloppy embedded/BMC responses.
	legacy, err := Parse([]byte(header+`{type: http, path: /, match: {status: [200], body_contains_all: ["MegaRAC"]}}`), "test.yaml")
	if err != nil {
		t.Fatal(err)
	}
	r.httpClient.Transport = stepTransport(func(req *http.Request) (*http.Response, error) {
		pr, pw := io.Pipe()
		go func() {
			_, _ = io.WriteString(pw, "<title>MegaRAC SPx</title>")
			_ = pw.CloseWithError(io.ErrUnexpectedEOF)
		}()
		return &http.Response{StatusCode: 200, Body: io.NopCloser(pr)}, nil
	})
	if _, ok := r.executeProbe(t.Context(), legacy, "127.0.0.1", 80); !ok {
		t.Fatal("legacy single-request HTTP check must still match partial body before EOF error")
	}
}

// runBuiltinHTTP redirects connections for port to an ephemeral httptest.Server.
func runBuiltinHTTP(t *testing.T, port int, handler http.HandlerFunc, checks ...*Check) []Finding {
	t.Helper()
	srv := httptest.NewServer(handler)
	defer srv.Close()
	r := NewRunner(checks, 1)
	r.httpClient.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	return r.RunHost(t.Context(), probe.HostProfile{
		Client:    unifi.Client{IP: "127.0.0.1"},
		OpenPorts: []int{port},
	})
}

// TestCommunityCheckPrecision verifies Node-RED auth modes, Shelly Gen1 json_match,
// and honest service-observed evidence on MegaRAC and ComfoConnect.
func TestCommunityCheckPrecision(t *testing.T) {
	all := loadBuiltinMap(t)

	t.Run("Node-RED", func(t *testing.T) {
		chks := []*Check{all["UB-2026-0026"], all["UB-2026-0074"], all["UB-2026-0075"]}
		tabFlow := `[{"type":"tab","label":"secret-flow","info":"` + strings.Repeat("x", maxProbeBodyBytes) + `"}]`
		for _, tc := range []struct {
			name         string
			flowsStatus  int
			flowsBody    string
			loginBody    string
			settingsBody string
			wantID       string
			wantSev      Severity
		}{
			{"auth required", 401, "", "", "", "", SeverityInfo},
			{"anon read only", 200, tabFlow, `{"type":"credentials"}`, `{"httpNodeRoot":"/","user":{"anonymous":true,"permissions":"read"}}`, "UB-2026-0074", SeverityHigh},
			{"token-only anon read", 200, tabFlow, `{}`, `{"httpNodeRoot":"/","user":{"anonymous":true,"permissions":"read"}}`, "UB-2026-0074", SeverityHigh},
			{"anon wildcard admin", 200, tabFlow, `{"type":"credentials"}`, `{"httpNodeRoot":"/","user":{"anonymous":true,"permissions":"*"}}`, "UB-2026-0075", SeverityCritical},
			{"anon wildcard admin array", 200, tabFlow, `{"type":"credentials"}`, `{"httpNodeRoot":"/","user":{"anonymous":true,"permissions":["*"]}}`, "UB-2026-0075", SeverityCritical},
			{"no adminAuth", 200, tabFlow, " {}\n", `{"httpNodeRoot":"/","version":"4.0.0"}`, "UB-2026-0026", SeverityCritical},
			{"no adminAuth empty flows", 200, `[]`, `{}`, `{"httpNodeRoot":"/","version":"4.0.0"}`, "UB-2026-0026", SeverityCritical},
		} {
			t.Run(tc.name, func(t *testing.T) {
				got := runBuiltinHTTP(t, 1880, func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/flows":
						w.WriteHeader(tc.flowsStatus)
						_, _ = io.WriteString(w, tc.flowsBody)
					case "/auth/login":
						_, _ = io.WriteString(w, tc.loginBody)
					case "/settings":
						_, _ = io.WriteString(w, tc.settingsBody)
					}
				}, chks...)
				if tc.wantID == "" {
					if len(got) != 0 {
						t.Fatalf("expected 0 findings, got %+v", got)
					}
					return
				}
				if len(got) != 1 || got[0].CheckID != tc.wantID || got[0].BaseSeverity != tc.wantSev || strings.Contains(got[0].Evidence, "secret-flow") {
					t.Fatalf("want single %s (%v), got %+v", tc.wantID, tc.wantSev, got)
				}
			})
		}
	})

	t.Run("Shelly Gen1", func(t *testing.T) {
		chk := all["UB-2026-0031"]
		for _, tc := range []struct {
			name   string
			status int
			body   string
			want   bool
		}{
			{"wifi_ap disabled but login enabled", 200, `{"wifi_ap":{"enabled":false},"login":{"enabled":true},"wifi_sta":{}}`, false},
			{"login disabled", 200, `{"wifi_sta":{"ssid":"secret-ssid"},"login":{"enabled":false}}`, true},
			{"auth challenge", 401, `{"wifi_sta":{},"login":{"enabled":false}}`, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				got := runBuiltinHTTP(t, 80, func(w http.ResponseWriter, r *http.Request) {
					if tc.status == 401 {
						w.Header().Set("WWW-Authenticate", `Basic realm="Shelly"`)
					}
					w.WriteHeader(tc.status)
					_, _ = io.WriteString(w, tc.body)
				}, chk)
				if (len(got) == 1) != tc.want {
					t.Fatalf("want match=%t, got %+v", tc.want, got)
				}
				if tc.want && strings.Contains(got[0].Evidence, "secret-ssid") {
					t.Fatalf("evidence leaked body: %q", got[0].Evidence)
				}
			})
		}
	})

	t.Run("MegaRAC and ComfoConnect stay actionable service-observed", func(t *testing.T) {
		got := runBuiltinHTTP(t, 80, func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "<title>MegaRAC SPx Login</title>")
		}, all["UB-2026-0001"])
		if len(got) != 1 || got[0].ClaimKind != ClaimServiceObserved || got[0].BaseSeverity != SeverityHigh || got[0].IsInventoryOnly() || got[0].CVE != "" {
			t.Fatalf("unexpected MegaRAC finding: %+v", got)
		}

		port, closeTCP := startMockTCP(t, func(net.Conn) {})
		defer closeTCP()
		udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err != nil {
			t.Fatal(err)
		}
		defer udp.Close()
		go func() {
			var req [64]byte
			if n, addr, err := udp.ReadFromUDP(req[:]); err == nil && bytes.Equal(req[:n], []byte{0x0a, 0}) {
				_, _ = udp.WriteToUDP([]byte{0x12, 6, 0x0a, 4, 127, 0, 0, 1}, addr)
			}
		}()
		chk := *all["UB-2026-0039"]
		chk.Preconditions.PortsAny = []int{port}
		chk.Probe.Port = port
		chk.Probe.Timeout = 500 * time.Millisecond
		got = NewRunner([]*Check{&chk}, 1).RunHost(t.Context(), probe.HostProfile{
			Client:    unifi.Client{IP: "127.0.0.1", Hostname: "comfoconnect"},
			OpenPorts: []int{port},
		})
		if len(got) != 1 || got[0].ClaimKind != ClaimServiceObserved || got[0].BaseSeverity != SeverityHigh ||
			got[0].IsInventoryOnly() || !strings.Contains(got[0].Evidence, "PIN and control authorization untested") {
			t.Fatalf("unexpected ComfoConnect finding: %+v", got)
		}
	})
}
