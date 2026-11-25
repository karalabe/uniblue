// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/unifi"
)

func TestRunnerUsesEffectiveProbeIPAndNeverContactsPublicIPv4(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("vulnerable-marker"))
	}))
	defer srv.Close()

	addrPort := netip.MustParseAddrPort(strings.TrimPrefix(srv.URL, "http://"))
	port := int(addrPort.Port())

	rawCheck := `
id: UB-TEST-PROBEIP
title: Test EffectiveProbeIP Selection
category: test
severity: high
safety: read-only
preconditions:
  ports_any: [` + strconv.Itoa(port) + `]
probe:
  type: http
  method: GET
  path: /
  match:
    status: [200]
    body_contains_all: ["vulnerable-marker"]
`
	chk, err := Parse([]byte(rawCheck), "test")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	runner := NewRunner([]*Check{chk}, 1)

	// Host has a disallowed public IPv4 as Client.IP, plus an allowed loopback
	// address selected as ProbeIP. Active check must hit ProbeIP (127.0.0.1),
	// never 8.8.8.8.
	hp := probe.HostProfile{
		Client: unifi.Client{
			MAC:   "aa:bb:cc:dd:ee:10",
			IP:    "198.51.100.25",
			IPv6:  []string{"127.0.0.1"},
			Name:  "DualStackPublicV4",
		},
		ProbeIP:   addrPort.Addr().String(),
		OpenPorts: []int{port},
	}
	findings := runner.RunHost(context.Background(), hp)
	if hits.Load() == 0 || len(findings) != 1 {
		t.Fatalf("expected active check to hit authorized ProbeIP and produce 1 finding, hits=%d findings=%+v", hits.Load(), findings)
	}

	// Host with ONLY a disallowed public IPv4 and no ProbeIP must be skipped completely.
	hpPublicOnly := probe.HostProfile{
		Client: unifi.Client{
			MAC:  "aa:bb:cc:dd:ee:11",
			IP:   "198.51.100.26",
			Name: "PublicOnly",
		},
		OpenPorts: []int{port},
	}
	if got := hpPublicOnly.EffectiveProbeIP(); got != "" {
		t.Fatalf("EffectiveProbeIP for public-only host = %q, want empty", got)
	}
	if findings := runner.RunHost(context.Background(), hpPublicOnly); len(findings) != 0 {
		t.Fatalf("expected 0 findings for public-only host, got %+v", findings)
	}
}

func TestMatchesMDNSServiceIgnoresUntrustedReflectedAdverts(t *testing.T) {
	rawCheck := `
id: UB-TEST-MDNS-AUTH
title: Test mDNS Attribution Guard
category: iot
severity: high
safety: read-only
preconditions:
  mdns_type_any: ["_slzb-06._tcp"]
probe:
  type: observe
`
	chk, err := Parse([]byte(rawCheck), "test")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	untrusted := probe.MDNSService{
		Type:             "_slzb-06._tcp",
		Instance:         "forged-coord",
		Port:             6638,
		ResponderIP:      "192.168.1.66",
		Reflected:        true,
		TrustedReflector: false,
	}
	if matchesMDNSService(chk, untrusted) {
		t.Fatal("untrusted reflected mDNS service must not match mDNS-gated check")
	}

	trusted := untrusted
	trusted.ResponderIP = "192.168.1.1"
	trusted.TrustedReflector = true
	if !matchesMDNSService(chk, trusted) {
		t.Fatal("trusted gateway-reflected mDNS service should match mDNS-gated check")
	}

	authoritative := probe.MDNSService{
		Type:        "_slzb-06._tcp",
		Instance:    "real-coord",
		Port:        6638,
		ResponderIP: "192.168.1.30",
		Reflected:   false,
	}
	if !matchesMDNSService(chk, authoritative) {
		t.Fatal("authoritative mDNS service should match mDNS-gated check")
	}
}
