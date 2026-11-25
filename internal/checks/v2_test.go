// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checks

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/unifi"
)

// TestPerHostPortPlannerZeroBloatAt1000Rules verifies that scaling to 1,000
// identity-gated device rules adds zero global TCP ports and targets only matching hosts.
func TestPerHostPortPlannerZeroBloatAt1000Rules(t *testing.T) {
	base := []int{80, 443}
	var rules []*Check
	for i := range 1000 {
		port := 10000 + i
		raw := fmt.Sprintf(`
id: UB-SCALE-%04d
title: Synthetic Specialty Device %d
severity: low
safety: read-only
preconditions:
  ports_any: [%d]
  mac_prefix: ["aa:bb:%02x"]
probe:
  type: tcp
`, i, i, port, i%256)
		chk, err := Parse([]byte(raw), "scale.yaml")
		if err != nil {
			t.Fatalf("Parse synthetic rule %d: %v", i, err)
		}
		rules = append(rules, chk)
	}

	// Adding 1,000 device-specific rules must add zero ports
	// to the global TCP sweep.
	global := PlanGlobalPorts(base, rules)
	if len(global) != 2 || global[0] != 80 || global[1] != 443 {
		t.Fatalf("expected global ports [80 443], got %v", global)
	}

	// An unrelated host gets zero extra ports; a matching MAC gets only its rule's ports.
	clients := []unifi.Client{
		{IP: "192.0.2.10", MAC: "11:22:33:44:55:66"},
		{IP: "192.0.2.20", MAC: "aa:bb:05:11:22:33"},
	}
	hints := PlanHostPorts(clients, rules, nil)
	if len(hints["192.0.2.10"]) != 0 {
		t.Fatalf("unrelated host received unexpected ports: %v", hints["192.0.2.10"])
	}
	if len(hints["192.0.2.20"]) == 0 || hints["192.0.2.20"][0] != 10005 {
		t.Fatalf("matching host did not receive expected port 10005: %v", hints["192.0.2.20"])
	}
}

// TestRuleEngineObserveJSONAndMultiPath verifies passive observe checks,
// multi-path HTTP fallback with JSONPath predicates, and forbidden header rejection.
func TestRuleEngineObserveJSONAndMultiPath(t *testing.T) {
	// 1. Passive mDNS observe check (unpaired HomeKit sf=1 vs paired sf=0).
	chk, err := Parse([]byte(`
id: UB-TEST-HAP
title: Unpaired HomeKit
severity: high
safety: read-only
preconditions:
  mdns_type_any: ["_hap._tcp"]
  mdns_txt_regex: "(?i)^sf=1$"
probe:
  type: observe
`), "hap.yaml")
	if err != nil {
		t.Fatalf("Parse observe check: %v", err)
	}
	r := NewRunner([]*Check{chk}, 1)

	paired := probe.HostProfile{
		Client:       unifi.Client{IP: "192.0.2.11"},
		MDNSServices: []probe.MDNSService{{Type: "_hap._tcp", Port: 51826, TXT: []string{"sf=0"}}},
	}
	unpaired := probe.HostProfile{
		Client:       unifi.Client{IP: "192.0.2.12"},
		MDNSServices: []probe.MDNSService{{Type: "_hap._tcp", Port: 51826, TXT: []string{"sf=1"}}},
	}
	if got := r.RunHost(context.Background(), paired); len(got) != 0 {
		t.Fatalf("paired HAP device must not match, got %+v", got)
	}
	if got := r.RunHost(context.Background(), unpaired); len(got) != 1 || got[0].Port != 51826 {
		t.Fatalf("unpaired HAP device expected 1 finding on port 51826, got %+v", got)
	}

	// 2. Multi-path HTTP fallback + JSONPath + body_not_contains.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/missing":
			http.NotFound(w, r)
		case "/v2/info":
			_, _ = io.WriteString(w, `{"api":{"version":"2","auth_en":false}}`)
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer srv.Close()
	_, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	httpChk, err := Parse([]byte(`
id: UB-TEST-JSON
title: Multi-Path JSON Check
severity: medium
safety: read-only
preconditions:
  ports_any: [`+portStr+`]
probe:
  type: http
  method: GET
  paths: ["/v1/missing", "/v2/info"]
  request_headers:
    Accept: application/json
  match:
    status: [200]
    body_not_contains: ["Login Required"]
    json_match:
      - path: "$.api.version"
        equals: "2"
      - path: "$.api.auth_en"
        equals: "false"
    evidence_summary: "confirmed auth_en=false via JSONPath"
`), "json.yaml")
	if err != nil {
		t.Fatalf("Parse http json check: %v", err)
	}
	ev, ok := r.executeProbe(context.Background(), httpChk, "127.0.0.1", port)
	if !ok || !strings.Contains(ev, "confirmed auth_en=false") {
		t.Fatalf("expected multi-path JSON match, got ok=%v ev=%q", ok, ev)
	}

	// 3. Reject forbidden HTTP request headers (Authorization / Cookie / Host).
	if _, err := Parse([]byte(`
id: UB-TEST-BADHDR
title: Bad Header
severity: low
safety: read-only
preconditions:
  ports_any: [80]
probe:
  type: http
  method: GET
  path: /
  request_headers:
    Authorization: Bearer leaked
`), "badhdr.yaml"); err == nil {
		t.Fatal("expected Parse to reject Authorization request header")
	}
}

// TestExtendedReadOnlyProtocolProbes verifies read-only probes for TP-Link Kasa,
// Memcached, rsync, MPD, SNMPv2c, CoAP, and NAT-PMP against local mocks.
func TestExtendedReadOnlyProtocolProbes(t *testing.T) {
	t.Run("kasa xor get_sysinfo", func(t *testing.T) {
		port, closeFn := startMockTCP(t, func(conn net.Conn) {
			hdr := make([]byte, 4)
			if _, err := io.ReadFull(conn, hdr); err != nil {
				return
			}
			n := binary.BigEndian.Uint32(hdr)
			_, _ = io.ReadFull(conn, make([]byte, n))
			reply := kasaXOREncode([]byte(`{"system":{"get_sysinfo":{"model":"HS110(EU)","sw_ver":"1.2.6"}}}`))
			out := make([]byte, 4+len(reply))
			binary.BigEndian.PutUint32(out[0:4], uint32(len(reply)))
			copy(out[4:], reply)
			_, _ = conn.Write(out)
		})
		defer closeFn()
		ev, ok := probeKasa(context.Background(), "127.0.0.1", port)
		if !ok || !strings.Contains(ev, "HS110(EU)") {
			t.Fatalf("expected Kasa match, got ok=%v ev=%q", ok, ev)
		}
	})

	t.Run("memcached rsync and mpd", func(t *testing.T) {
		mcPort, closeMC := startMockTCP(t, func(conn net.Conn) {
			_, _ = conn.Read(make([]byte, 32))
			_, _ = io.WriteString(conn, "VERSION 1.6.22\r\n")
		})
		defer closeMC()
		if _, ok := probeMemcached(context.Background(), "127.0.0.1", mcPort); !ok {
			t.Fatal("expected Memcached match")
		}

		rsPort, closeRS := startMockTCP(t, func(conn net.Conn) {
			_, _ = io.WriteString(conn, "@RSYNCD: 31.0\n")
		})
		defer closeRS()
		if _, ok := probeRsync(context.Background(), "127.0.0.1", rsPort); !ok {
			t.Fatal("expected rsync match")
		}

		mpdPort, closeMPD := startMockTCP(t, func(conn net.Conn) {
			_, _ = io.WriteString(conn, "OK MPD 0.23.5\n")
		})
		defer closeMPD()
		if _, ok := probeMPD(context.Background(), "127.0.0.1", mpdPort); !ok {
			t.Fatal("expected MPD match")
		}
	})

	t.Run("snmp v2c get response", func(t *testing.T) {
		pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			t.Fatalf("listen udp: %v", err)
		}
		defer pc.Close()
		go func() {
			buf := make([]byte, 1024)
			n, addr, err := pc.ReadFromUDP(buf)
			if err != nil || n < 16 {
				return
			}
			// Extract incoming request-id from the SNMPv2c GetRequest.
			msg, ok := asn1Unwrap(buf[:n], 0x30)
			if !ok {
				return
			}
			_, rest, _ := asn1Next(msg, 0x02)
			_, rest, _ = asn1Next(rest, 0x04)
			pdu, _, _ := asn1Next(rest, 0xa0)
			reqBytes, _, _ := asn1Next(pdu, 0x02)
			reqID := decodeASN1Int(reqBytes)

			vb := asn1Seq(append([]byte{0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}, asn1Wrap(0x04, []byte("ExampleOS Switch 2.4"))...))
			var pduBody bytes.Buffer
			pduBody.Write(asn1Int(reqID))
			pduBody.Write(asn1Int(0))
			pduBody.Write(asn1Int(0))
			pduBody.Write(asn1Seq(vb))
			var resp bytes.Buffer
			resp.Write(asn1Int(1))
			resp.Write(asn1Wrap(0x04, []byte("public")))
			resp.Write(asn1Wrap(0xa2, pduBody.Bytes()))
			_, _ = pc.WriteToUDP(asn1Seq(resp.Bytes()), addr)
		}()

		ev, ok := probeSNMPReadOnly(context.Background(), "127.0.0.1", pc.LocalAddr().(*net.UDPAddr).Port, "public")
		if !ok || !strings.Contains(ev, "ExampleOS Switch 2.4") {
			t.Fatalf("expected SNMP match with sysDescr, got ok=%v ev=%q", ok, ev)
		}
	})

	t.Run("coap and natpmp udp", func(t *testing.T) {
		coapConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			t.Fatalf("listen coap udp: %v", err)
		}
		defer coapConn.Close()
		go func() {
			buf := make([]byte, 256)
			n, addr, err := coapConn.ReadFromUDP(buf)
			if err != nil || n < 4 {
				return
			}
			// ACK 2.05 Content echoing Message ID.
			_, _ = coapConn.WriteToUDP([]byte{0x60, 0x45, buf[2], buf[3], 0xff, '<', '/', 't', 'e', 'm', 'p', '>'}, addr)
		}()
		if _, ok := probeCoAP(context.Background(), "127.0.0.1", coapConn.LocalAddr().(*net.UDPAddr).Port); !ok {
			t.Fatal("expected CoAP 2.05 match")
		}

		pmpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			t.Fatalf("listen natpmp udp: %v", err)
		}
		defer pmpConn.Close()
		go func() {
			buf := make([]byte, 32)
			_, addr, err := pmpConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			// RFC 6886 external address response: ver=0, op=128, result=0, epoch=1, ip=198.51.100.1
			_, _ = pmpConn.WriteToUDP([]byte{0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 198, 51, 100, 1}, addr)
		}()
		if _, ok := probeNATPMP(context.Background(), "127.0.0.1", pmpConn.LocalAddr().(*net.UDPAddr).Port); !ok {
			t.Fatal("expected NAT-PMP match")
		}
	})
}

// TestNervaDedupPreservesIndependentTLSFinding verifies that a generic TLS
// protocol finding on port 443 does not suppress an expired-certificate finding.
func TestNervaDedupPreservesIndependentTLSFinding(t *testing.T) {
	profiles := []probe.HostProfile{
		{
			Client: unifi.Client{IP: "192.0.2.30", MAC: "aa:bb:cc:00:00:01"},
			Services: []probe.Service{
				{
					Port:     443,
					Protocol: "https",
					TLS:      true,
					Findings: []probe.ServiceFinding{
						{ID: "tls-certificate-expired", Severity: "medium", Evidence: "expired"},
					},
				},
			},
		},
	}
	existing := []Finding{
		{CheckID: "UB-2026-0053", Category: "info-disclosure", Client: profiles[0].Client, Port: 443},
	}
	got := FindingsFromProfiles(profiles, existing)
	if len(got) != 1 || got[0].CheckID != "NERVA-TLS-CERTIFICATE-EXPIRED" {
		t.Fatalf("independent TLS finding on port 443 must be preserved, got %+v", got)
	}
}
