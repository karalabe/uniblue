package checks

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	builtinchecks "github.com/karalabe/uniblue/checks"
	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/unifi"
)

func TestBuiltinChecksAreValid(t *testing.T) {
	list, err := LoadFromFS(builtinchecks.BuiltinFS)
	if err != nil {
		t.Fatalf("LoadFromFS(BuiltinFS): %v", err)
	}
	if len(list) < 6 {
		t.Fatalf("expected at least 6 built-in checks, got %d", len(list))
	}
	if _, err := Merge(list); err != nil {
		t.Fatalf("Merge(builtins): %v", err)
	}
}

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

func TestProtocolProbes(t *testing.T) {
	t.Run("mqtt anonymous accepted", func(t *testing.T) {
		port, closeFn := startMockTCP(t, func(conn net.Conn) {
			buf := make([]byte, 64)
			_, _ = conn.Read(buf)
			// Reply with MQTT CONNACK accepted (0x20 0x02 0x00 0x00).
			_, _ = conn.Write([]byte{0x20, 0x02, 0x00, 0x00})
		})
		defer closeFn()

		if _, ok := probeMQTT(context.Background(), "127.0.0.1", port); !ok {
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

		if _, ok := probeModbus(context.Background(), "127.0.0.1", port); !ok {
			t.Fatal("expected Modbus probe to match")
		}
	})

	t.Run("rtsp unauthenticated options", func(t *testing.T) {
		port, closeFn := startMockTCP(t, func(conn net.Conn) {
			buf := make([]byte, 256)
			_, _ = conn.Read(buf)
			_, _ = io.WriteString(conn, "RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: OPTIONS, DESCRIBE, PLAY\r\n\r\n")
		})
		defer closeFn()

		if _, ok := probeRTSP(context.Background(), "127.0.0.1", port); !ok {
			t.Fatal("expected unauthenticated RTSP probe to match")
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

		ev, ok := probeVNC(context.Background(), "127.0.0.1", port)
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

		if _, ok := probeVNC(context.Background(), "127.0.0.1", port); ok {
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

		ev, ok := probeDenonMarantzAVR(context.Background(), "127.0.0.1", port)
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

		ev, ok := probeTelnet(context.Background(), "127.0.0.1", port)
		if !ok || !strings.Contains(ev, "RouterOS login:") {
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
		ev, ok := r.probeEthereumRPC(context.Background(), "127.0.0.1", port)
		if !ok || !strings.Contains(ev, "Geth/v1.15.0") {
			t.Fatalf("expected eth-rpc probe match with Geth version, got ok=%v ev=%q", ok, ev)
		}
	})
}

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

	// Simulate UB-0005 already covering port 5900 on 10.0.255.0.
	existing := []Finding{
		{CheckID: "UB-0005", Client: profiles[0].Client, Port: 5900},
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
