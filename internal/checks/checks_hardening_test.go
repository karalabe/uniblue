// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checks

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/unifi"
	"golang.org/x/net/dns/dnsmessage"
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
grants: [{effect: read, basis: proven}]
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
			MAC:  "aa:bb:cc:dd:ee:10",
			IP:   "198.51.100.25",
			IPv6: []string{"127.0.0.1"},
			Name: "DualStackPublicV4",
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
grants:
  - {effect: control, basis: conditional, requires: the bridge accepts TCP connections without authentication}
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

func TestActiveFindingDeduplicatesExpandedIPv6(t *testing.T) {
	const port = 443
	chk := loadBuiltinMap(t)["UB-0009"]
	hp := probe.HostProfile{
		ProbeIP: "0:0:0:0:0:0:0:1",
		Client:  unifi.Client{IPv6: []string{"::1"}},
		Services: []probe.Service{{
			Port: port, AddressFamily: "ipv6",
			Findings: []probe.ServiceFinding{{ID: "tls-weak-version-10"}},
		}},
	}
	ep := findingEndpoints(chk, hp, port)[0]
	if !slices.Equal(ep.ips, []string{"::1"}) {
		t.Fatalf("active check observed IPs = %v", ep.ips)
	}
	existing := []Finding{{CheckID: chk.ID, Client: hp.Client, Port: port, ObservedIPs: ep.ips, Transport: ep.transport}}
	if extra := FindingsFromProfiles([]probe.HostProfile{hp}, existing); len(extra) != 0 {
		t.Fatalf("duplicate IPv6 finding: %+v", extra)
	}
}

func ingestTestRecord(t *testing.T, cache *probe.DiscoveryCache, now time.Time, responder, name string, ttl uint32, body dnsmessage.ResourceBody) {
	t.Helper()
	msg := dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Answers: []dnsmessage.Resource{{
		Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), TTL: ttl, Class: dnsmessage.ClassINET},
		Body:   body,
	}}}
	packet, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	cache.IngestMDNSPacket(packet, responder, "eth0", "LAN", now)
}

func TestMDNSFindingsUseOnlyServiceRespondersTXT(t *testing.T) {
	checks := loadBuiltinMap(t)
	const device, gateway, other = "192.168.1.20", "192.168.1.1", "192.168.1.66"
	for _, tc := range []struct {
		service, check, realTXT, otherTXT string
		port                              uint16
		findings                          int
	}{
		{"_esphomelib._tcp", "UB-2026-0036", "version=2026.1", "api_encryption=Noise_NNpsk0", 6053, 1},
		{"_hap._tcp", "UB-2026-0022", "sf=0", "sf=1", 51826, 0},
	} {
		for _, owner := range []string{device, gateway} {
			for _, otherFirst := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/from_%s/other_first_%t", tc.service, owner, otherFirst), func(t *testing.T) {
					cache := probe.NewDiscoveryCache()
					cache.SetTrustedReflectors([]string{gateway})
					now := time.Now()
					instance := "device." + tc.service + ".local."
					txt := func(sender, value string) {
						ingestTestRecord(t, cache, now, sender, instance, 60, &dnsmessage.TXTResource{TXT: []string{value}})
					}
					if otherFirst {
						txt(other, tc.otherTXT)
					}
					ingestTestRecord(t, cache, now, owner, "device.local.", 60, &dnsmessage.AResource{A: netip.MustParseAddr(device).As4()})
					ingestTestRecord(t, cache, now, owner, instance, 60, &dnsmessage.SRVResource{Port: tc.port, Target: dnsmessage.MustNewName("device.local.")})
					txt(owner, tc.realTXT)
					if !otherFirst {
						txt(other, tc.otherTXT)
					}
					snap := cache.Snapshot(now)
					if len(snap.MDNS[other]) != 0 {
						t.Fatalf("standalone TXT attributed a service to %s: %+v", other, snap.MDNS[other])
					}
					hp := probe.HostProfile{Client: unifi.Client{IP: device}, MDNSServices: snap.MDNS[device]}
					if len(hp.MDNSServices) != 1 || !slices.Equal(hp.MDNSServices[0].TXT, []string{tc.realTXT}) {
						t.Fatalf("unexpected TXT on %s: %+v", device, hp.MDNSServices)
					}
					r := NewRunner([]*Check{checks[tc.check]}, 1)
					if findings := r.RunHost(context.Background(), hp); len(findings) != tc.findings {
						t.Fatalf("got %+v, want %d findings", findings, tc.findings)
					}
				})
			}
		}
	}
}

func TestRelayedCoordinatorUsesLiveAddressSources(t *testing.T) {
	const gateway, coordinator, other = "192.168.1.1", "192.168.20.44", "192.168.1.66"
	const nas4, nas6 = "192.168.1.10", "fd00::10"
	const host = "coordinator.local."
	cache := probe.NewDiscoveryCache()
	cache.SetTrustedReflectors([]string{gateway})
	now := time.Now()
	address := func(sender, ip string, ttl uint32) {
		addr := netip.MustParseAddr(ip)
		if addr.Is4() {
			ingestTestRecord(t, cache, now, sender, host, ttl, &dnsmessage.AResource{A: addr.As4()})
		} else {
			ingestTestRecord(t, cache, now, sender, host, ttl, &dnsmessage.AAAAResource{AAAA: addr.As16()})
		}
	}
	address(other, nas4, 120)
	ingestTestRecord(t, cache, now, gateway, "bridge._slzb-06._tcp.local.", 120, &dnsmessage.SRVResource{
		Port: 6638, Target: dnsmessage.MustNewName(host),
	})
	address(gateway, coordinator, 120)
	address(other, nas6, 120)
	r := NewRunner([]*Check{loadBuiltinMap(t)["UB-2026-0023"]}, 1)
	assertVisible := func(ip string, want bool) {
		t.Helper()
		snap := cache.Snapshot(now)
		svcs := snap.MDNS[ip]
		_, protected := snap.RawPrintIPs[ip][6638]
		hp := probe.HostProfile{Client: unifi.Client{IP: ip}, MDNSServices: svcs}
		got := r.RunHost(context.Background(), hp)
		if (len(got) == 1) != want || (len(svcs) == 1) != want || protected != want {
			t.Fatalf("%s: services=%+v findings=%+v protected=%t, want visibility %t", ip, svcs, got, protected, want)
		}
	}
	assertVisible(nas4, false)
	assertVisible(nas6, false)
	assertVisible(coordinator, true)
	if svcs := cache.Snapshot(now).MDNS[coordinator]; !slices.Equal(svcs[0].TargetIPs, []string{coordinator}) {
		t.Fatalf("unrelated addresses in relayed service: %v", svcs[0].TargetIPs)
	}

	// A self-announcement and a separate gateway announcement may both
	// establish the mapping, each for its own lifetime.
	address(nas4, nas4, 1)
	address(gateway, nas6, 2)
	address(other, nas6, 0)
	assertVisible(nas4, true)
	assertVisible(nas6, true)
	now = now.Add(3 * time.Second)
	assertVisible(nas4, false)
	assertVisible(nas6, false)
	cache.PruneExpired(now)
	assertVisible(nas4, false)
	assertVisible(coordinator, true)
}
