// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/karalabe/uniblue/internal/unifi"
	"github.com/praetorian-inc/nerva/pkg/plugins"
	"gopkg.in/yaml.v3"
)

// TestForgedMDNSRawPrintCannotHideVictimPort verifies that a forged or
// reflected mDNS raw-print advertisement from another host cannot mark an
// arbitrary port (such as SMB 445 or Telnet 23) as a zero-byte raw print sink
// on a victim host, while self-announced sinks and well-known ports 9100/515
// remain protected.
func TestForgedMDNSRawPrintCannotHideVictimPort(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	cache := NewDiscoveryCache()

	// Attacker 192.168.1.66 forges a _pdl-datastream._tcp reply pointing to victim 192.168.1.10:445.
	forged := buildMDNSTestPacket("_pdl-datastream._tcp", "fake-printer", "nas.local", 445, 120, []byte{192, 168, 1, 10}, nil, nil)
	cache.IngestMDNSPacket(forged, "192.168.1.66", "eth0", "LAN", now)

	// Attacker also tries adding its own A record alongside the victim's A record.
	forgedMultiA := buildMDNSTestPacket("_pdl-datastream._tcp", "fake-printer-2", "nas2.local", 23, 120, []byte{192, 168, 1, 10}, nil, nil)
	cache.IngestMDNSPacket(forgedMultiA, "192.168.1.66", "eth0", "LAN", now)
	attackerOwnA := buildMDNSTestPacket("_pdl-datastream._tcp", "fake-printer-2", "nas2.local", 23, 120, []byte{192, 168, 1, 66}, nil, nil)
	cache.IngestMDNSPacket(attackerOwnA, "192.168.1.66", "eth0", "LAN", now)

	// Genuine printer 192.168.1.50 advertises its own raw print port 9101.
	genuine := buildMDNSTestPacket("_pdl-datastream._tcp", "real-printer", "printer.local", 9101, 120, []byte{192, 168, 1, 50}, nil, nil)
	cache.IngestMDNSPacket(genuine, "192.168.1.50", "eth0", "LAN", now)

	// Reflected well-known JetDirect port 9100 should still be protected.
	reflected9100 := buildMDNSTestPacket("_pdl-datastream._tcp", "remote-printer", "remote.local", 9100, 120, []byte{192, 168, 1, 70}, nil, nil)
	cache.IngestMDNSPacket(reflected9100, "192.168.1.1", "eth0", "LAN", now)

	snap := cache.Snapshot(now)

	if _, poisoned := snap.RawPrintIPs["192.168.1.10"][445]; poisoned {
		t.Fatalf("forged mDNS reply must not hide victim port 445: RawPrintIPs=%+v", snap.RawPrintIPs["192.168.1.10"])
	}
	if _, poisoned := snap.RawPrintIPs["192.168.1.10"][23]; poisoned {
		t.Fatalf("multi-A forged mDNS reply must not hide victim port 23: RawPrintIPs=%+v", snap.RawPrintIPs["192.168.1.10"])
	}
	if _, ok := snap.RawPrintIPs["192.168.1.50"][9101]; !ok {
		t.Fatalf("self-announced raw print port 9101 must be protected: RawPrintIPs=%+v", snap.RawPrintIPs)
	}
	if _, ok := snap.RawPrintIPs["192.168.1.70"][9100]; !ok {
		t.Fatalf("well-known raw print port 9100 must stay protected even when reflected")
	}

	victimProfile := HostProfile{
		Client:       unifi.Client{IP: "192.168.1.10"},
		MDNSServices: snap.MDNS["192.168.1.10"],
	}
	if victimProfile.IsRawPrintPort(445) {
		t.Fatal("HostProfile.IsRawPrintPort(445) must reject reflected/forged mDNS advertisement")
	}
	if victimProfile.IsRawPrintPort(23) {
		t.Fatal("HostProfile.IsRawPrintPort(23) must reject third-party mDNS responder")
	}

	printerProfile := HostProfile{
		Client:       unifi.Client{IP: "192.168.1.50"},
		MDNSServices: snap.MDNS["192.168.1.50"],
	}
	if !printerProfile.IsRawPrintPort(9101) {
		t.Fatal("HostProfile.IsRawPrintPort(9101) must accept self-announced printer port")
	}
}

// TestFetchSSDPDescriptionsSkipsExcludedIPs verifies that excluded IPs never
// receive unicast UPnP XML description HTTP GETs or appear in discovery output.
func TestFetchSSDPDescriptionsSkipsExcludedIPs(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<root><device><modelName>ExcludedDevice</modelName></device></root>`))
	}))
	defer srv.Close()

	excluded := map[string]struct{}{"127.0.0.1": {}}
	ssdpHits := []ssdpHit{{
		ip:       "127.0.0.1",
		st:       "upnp:rootdevice",
		location: srv.URL + "/desc.xml",
	}}
	noLoc := map[string][]ssdpHit{
		"127.0.0.1": {{ip: "127.0.0.1", st: "ssdp:all", server: "Test/1.0"}},
	}

	res := fetchSSDPDescriptions(context.Background(), srv.Client(), ssdpHits, noLoc, nil, excluded)
	if got := hits.Load(); got != 0 {
		t.Fatalf("excluded IP received %d unicast UPnP HTTP GETs, want 0", got)
	}
	if len(res["127.0.0.1"]) != 0 {
		t.Fatalf("excluded IP must not produce UPnP entries, got %+v", res["127.0.0.1"])
	}

	// Non-excluded fetch against the same server succeeds.
	resAllowed := fetchSSDPDescriptions(context.Background(), srv.Client(), ssdpHits, nil, nil, nil)
	if got := hits.Load(); got != 1 || len(resAllowed["127.0.0.1"]) != 1 || resAllowed["127.0.0.1"][0].ModelName != "ExcludedDevice" {
		t.Fatalf("expected non-excluded UPnP fetch to succeed, hits=%d res=%+v", hits.Load(), resAllowed)
	}
}

// TestMDNSNameLengthLimitAndCacheCaps verifies that readDNSName enforces the
// RFC 1035 255-byte wire length cap and DiscoveryCache bounds records per
// responder and globally against memory exhaustion floods.
func TestMDNSNameLengthLimitAndCacheCaps(t *testing.T) {
	// Build a compression-pointer chain that expands past 255 wire bytes.
	var bomb bytes.Buffer
	// Offset 0: 63-byte label + pointer back to offset 0.
	bomb.WriteByte(63)
	bomb.Write(bytes.Repeat([]byte("a"), 63))
	bomb.Write([]byte{0xc0, 0x00})
	if name, _, ok := readDNSName(bomb.Bytes(), 0); ok {
		t.Fatalf("expected oversized compressed DNS name to be rejected, got len=%d", len(name))
	}

	// Build a valid name near the 255-byte boundary (3*64 + 62 + 1 = 255 wire bytes).
	var maxValid bytes.Buffer
	for range 3 {
		maxValid.WriteByte(63)
		maxValid.Write(bytes.Repeat([]byte("b"), 63))
	}
	maxValid.WriteByte(61)
	maxValid.Write(bytes.Repeat([]byte("c"), 61))
	maxValid.WriteByte(0)
	if _, _, ok := readDNSName(maxValid.Bytes(), 0); !ok {
		t.Fatal("expected valid 255-wire-byte RFC 1035 domain name to parse")
	}

	// Build a 256-wire-byte uncompressed name (invalid per RFC 1035).
	var overByOne bytes.Buffer
	for range 3 {
		overByOne.WriteByte(63)
		overByOne.Write(bytes.Repeat([]byte("b"), 63))
	}
	overByOne.WriteByte(62)
	overByOne.Write(bytes.Repeat([]byte("c"), 62))
	overByOne.WriteByte(0)
	if _, _, ok := readDNSName(overByOne.Bytes(), 0); ok {
		t.Fatal("expected 256-wire-byte domain name to be rejected")
	}

	// Single responder flood must be capped at maxMDNSServicesPerHost.
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	cache := NewDiscoveryCache()
	for i := range 200 {
		pkt := buildMDNSTestPacket("_http._tcp", fmt.Sprintf("flood-%d", i), fmt.Sprintf("host-%d.local", i), uint16(1000+i), 120, []byte{192, 168, 1, 66}, nil, nil)
		cache.IngestMDNSPacket(pkt, "192.168.1.66", "eth0", "LAN", now)
	}
	if len(cache.mdnsInst) > maxMDNSServicesPerHost {
		t.Fatalf("per-responder mDNS instance cap exceeded: got %d, max %d", len(cache.mdnsInst), maxMDNSServicesPerHost)
	}
	if len(cache.hostIPs) > maxMDNSServicesPerHost {
		t.Fatalf("per-responder mDNS host cap exceeded: got %d, max %d", len(cache.hostIPs), maxMDNSServicesPerHost)
	}

	// Global flood across many distinct responders must be capped at maxMDNSServicesTotal.
	globalCache := NewDiscoveryCache()
	for hostIdx := range 40 {
		respIP := fmt.Sprintf("10.1.%d.%d", hostIdx/250, (hostIdx%250)+1)
		for svcIdx := range 64 {
			pkt := buildMDNSTestPacket("_http._tcp", fmt.Sprintf("h%d-s%d", hostIdx, svcIdx), fmt.Sprintf("h%d.local", hostIdx), uint16(8000+svcIdx), 120, []byte{10, 1, byte(hostIdx / 250), byte((hostIdx % 250) + 1)}, nil, nil)
			globalCache.IngestMDNSPacket(pkt, respIP, "eth0", "LAN", now)
		}
	}
	if len(globalCache.mdnsInst) > maxMDNSServicesTotal {
		t.Fatalf("global mDNS instance cap exceeded: got %d, max %d", len(globalCache.mdnsInst), maxMDNSServicesTotal)
	}
}

// TestDualStackMDNSPreservesAllResponderIPs verifies that an Avahi or
// dual-stack host replying from both its IPv4 and link-local IPv6 addresses
// never flips Reflected=true or drops its advertised port regardless of arrival order.
func TestDualStackMDNSPreservesAllResponderIPs(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	pkt := buildMDNSTestPacket("_home-assistant._tcp", "Home", "ha.local", 8123, 120, []byte{192, 168, 1, 50}, nil, nil)

	for _, order := range [][]string{
		{"192.168.1.50", "fe80::50"},
		{"fe80::50", "192.168.1.50"},
	} {
		cache := NewDiscoveryCache()
		for _, resp := range order {
			cache.IngestMDNSPacket(pkt, resp, "eth0", "LAN", now)
		}
		snap := cache.Snapshot(now)
		svcs := snap.MDNS["192.168.1.50"]
		if len(svcs) != 1 || svcs[0].Reflected {
			t.Fatalf("order %v: expected non-reflected service, got %+v", order, svcs)
		}
		ports := snap.PortsByIP["192.168.1.50"]
		if len(ports) != 1 || ports[0] != 8123 {
			t.Fatalf("order %v: expected advertised port [8123], got %v", order, ports)
		}
	}
}

// TestPassiveFlowHostnameOnlyInferredOutbound verifies that a passive flow
// record with empty Direction and empty RemoteIP but non-empty RemoteHost is
// classified as outbound rather than a locally hosted listener.
func TestPassiveFlowHostnameOnlyInferredOutbound(t *testing.T) {
	profiles := []HostProfile{{
		Client: unifi.Client{IP: "192.168.1.20", Name: "smart-plug"},
	}}
	ApplyPassiveFlows(profiles, []PassiveFlowRecord{
		{LocalIP: "192.168.1.20", RemoteHost: "api.tuya.com", Port: 443, Transport: "tcp", Protocol: "tls"},
		{LocalIP: "192.168.1.20", Port: 8080, Transport: "tcp", Protocol: "http"},
	})

	hp := profiles[0]
	if len(hp.OutboundDependencies) != 1 || hp.OutboundDependencies[0].DestinationHost != "api.tuya.com" || hp.OutboundDependencies[0].Port != 443 {
		t.Fatalf("expected hostname-only flow to become outbound dependency, got %+v", hp.OutboundDependencies)
	}
	if len(hp.Services) != 1 || hp.Services[0].Port != 8080 {
		t.Fatalf("expected only empty-remote record to be hosted (port 8080), got %+v", hp.Services)
	}
}

// TestBridgeInventoryUniqueChildIDs verifies that NVR/bridge inventory parsers
// assign distinct deterministic IDs to non-Latin names and unnamed same-model
// devices so AttachBridgeChildren never drops them on ID collision.
func TestBridgeInventoryUniqueChildIDs(t *testing.T) {
	raw := `
parent_ip: 192.168.1.40
devices:
  - name: "前门"
    model: "Cam-A"
  - name: "后院"
    model: "Cam-B"
  - model: "Model-X"
  - model: "Model-X"
`
	children, err := ParseBridgeInventory([]byte(raw), BridgeInventorySpec{Format: "nvr"})
	if err != nil {
		t.Fatalf("ParseBridgeInventory: %v", err)
	}
	if len(children) != 4 {
		t.Fatalf("expected 4 parsed children, got %d", len(children))
	}

	profiles := []HostProfile{{
		Client: unifi.Client{IP: "192.168.1.40", Name: "NVR"},
	}}
	AttachBridgeChildren(profiles, children)
	if len(profiles[0].Children) != 4 {
		t.Fatalf("expected all 4 cameras attached without ID collision, got %d: %+v", len(profiles[0].Children), profiles[0].Children)
	}
}

// TestMDNSQueryTypesCoverAllChecks walks all YAML check definitions under
// checks/ and verifies that every preconditions.mdns_type_any entry is present
// in mdnsQueryTypes.
func TestMDNSQueryTypesCoverAllChecks(t *testing.T) {
	browsed := make(map[string]struct{}, len(mdnsQueryTypes))
	for _, qt := range mdnsQueryTypes {
		norm := strings.ToLower(normalizeMDNSType(qt))
		if norm != "" {
			browsed[norm] = struct{}{}
		}
	}

	checksDir := filepath.Join("..", "..", "checks")
	var missing []string
	var filesChecked int
	err := filepath.WalkDir(checksDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var doc struct {
			ID            string `yaml:"id"`
			Preconditions struct {
				MDNSTypeAny []string `yaml:"mdns_type_any"`
			} `yaml:"preconditions"`
		}
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		filesChecked++
		for _, mt := range doc.Preconditions.MDNSTypeAny {
			norm := strings.ToLower(normalizeMDNSType(mt))
			if _, ok := browsed[norm]; !ok {
				missing = append(missing, fmt.Sprintf("%s (%s)", mt, doc.ID))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk checks: %v", err)
	}
	if filesChecked == 0 {
		t.Fatal("expected to inspect check YAML files")
	}
	if len(missing) > 0 {
		t.Fatalf("mdnsQueryTypes is missing check precondition types: %v", missing)
	}
}

// TestRawSerialCoordinatorPortsAreConnectOnly verifies that Ethernet Zigbee
// and UART bridge mDNS types (_slzb-06._tcp, _uzg-01._tcp, _smlight._tcp,
// _esphome-uart._tcp, _zigbee-coordinator._tcp) are excluded from active
// probing and receive zero application bytes at the TCP socket boundary.
func TestRawSerialCoordinatorPortsAreConnectOnly(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	for _, svcType := range []string{
		"_slzb-06._tcp",
		"_uzg-01._tcp",
		"_smlight._tcp",
		"_esphome-uart._tcp",
		"_zigbee-coordinator._tcp",
	} {
		cache := NewDiscoveryCache()
		pkt := buildMDNSTestPacket(svcType, "coord", "slzb.local", 6638, 120, []byte{192, 168, 1, 88}, nil, nil)
		cache.IngestMDNSPacket(pkt, "192.168.1.88", "eth0", "IoT", now)
		snap := cache.Snapshot(now)

		if len(snap.PortsByIP["192.168.1.88"]) != 0 {
			t.Fatalf("%s must not enter PortsByIP: got %v", svcType, snap.PortsByIP["192.168.1.88"])
		}
		if _, ok := snap.RawPrintIPs["192.168.1.88"][6638]; !ok {
			t.Fatalf("%s port 6638 must be recorded in zero-byte sink guard", svcType)
		}
	}

	// Verify at the TCP socket boundary that zero bytes are sent to a raw serial port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	var bytesRead atomic.Int64
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
				buf := make([]byte, 512)
				n, _ := conn.Read(buf)
				if n > 0 {
					bytesRead.Add(int64(n))
				}
			}(c)
		}
	}()

	fp := NewFingerprinter([]int{port}, 1, 500*time.Millisecond, nil)
	fp.SetCachedDiscovery(&LANDiscovery{
		MDNS: map[string][]MDNSService{
			"127.0.0.1": {{Type: "_slzb-06._tcp", Port: port, ResponderIP: "127.0.0.1"}},
		},
		RawPrintIPs: map[string]map[int]struct{}{
			"127.0.0.1": {port: {}},
		},
	})

	profiles := fp.FingerprintAll(context.Background(), []unifi.Client{{IP: "127.0.0.1", Name: "SLZB-06"}})
	time.Sleep(100 * time.Millisecond)

	if len(profiles) != 1 || !profiles[0].HasPort(port) {
		t.Fatalf("expected connect-only detection on raw serial port %d, got %+v", port, profiles)
	}
	if got := bytesRead.Load(); got != 0 {
		t.Fatalf("SAFETY VIOLATION: raw serial coordinator received %d bytes (must be 0)", got)
	}
}

// TestSSDPCollectorCapsDedupAndMergeSTs verifies per-responder LOCATION caps,
// no-LOCATION deduplication and caps, header string truncation, and merging
// multiple ST headers observed for the same LOCATION.
func TestSSDPCollectorCapsDedupAndMergeSTs(t *testing.T) {
	c := newSSDPCollector()

	// Flooder 192.168.1.66 sends 150 distinct LOCATION replies; per-IP cap must
	// keep it from exhausting the 128-entry global cap.
	for i := range 150 {
		raw := fmt.Sprintf("HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.66:%d/desc.xml\r\nST: upnp:rootdevice\r\nSERVER: Flood/1.0\r\n\r\n", 10000+i)
		c.ingest("192.168.1.66", raw)
	}
	// Real router 192.168.1.1 sends 3 distinct STs for the same LOCATION.
	for _, st := range []string{
		"upnp:rootdevice",
		"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
		"urn:schemas-upnp-org:service:WANIPConnection:1",
	} {
		raw := fmt.Sprintf("HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1:49000/igd.xml\r\nST: %s\r\nSERVER: MiniUPnPd/2.3\r\n\r\n", st)
		c.ingest("192.168.1.1", raw)
	}

	// Duplicate and flooded no-LOCATION replies with oversized header values.
	longServer := strings.Repeat("S", 1000)
	for i := range 20 {
		// Repeat same (ST, SERVER) twice each to check dedupe too.
		raw := fmt.Sprintf("HTTP/1.1 200 OK\r\nST: urn:test:%d\r\nSERVER: %s\r\n\r\n", i%10, longServer)
		c.ingest("192.168.1.77", raw)
		c.ingest("192.168.1.77", raw)
	}

	hits, noLoc := c.result()
	var floodCount int
	var routerHit *ssdpHit
	for i := range hits {
		switch hits[i].ip {
		case "192.168.1.66":
			floodCount++
		case "192.168.1.1":
			routerHit = &hits[i]
		}
	}
	if floodCount != maxSSDPLocHitsPerIP {
		t.Fatalf("expected flooder LOCATION hits capped at %d, got %d", maxSSDPLocHitsPerIP, floodCount)
	}
	if routerHit == nil {
		t.Fatal("real router LOCATION hit was starved by flooder")
	}
	if len(routerHit.sts) != 3 {
		t.Fatalf("expected all 3 STs merged on router LOCATION, got %v", routerHit.sts)
	}
	mergedST, extraSvcs := mergedSSDPSTs(*routerHit)
	if !strings.Contains(mergedST, "InternetGatewayDevice:1") || !strings.Contains(mergedST, "WANIPConnection:1") {
		t.Fatalf("merged ST missing device/service URNs: %q", mergedST)
	}
	if len(extraSvcs) != 1 || extraSvcs[0] != "urn:schemas-upnp-org:service:WANIPConnection:1" {
		t.Fatalf("expected service URN extracted into ServiceTypes, got %v", extraSvcs)
	}

	if len(noLoc["192.168.1.77"]) != maxSSDPNoLocHitsPerIP {
		t.Fatalf("expected noLocHits capped at %d, got %d", maxSSDPNoLocHitsPerIP, len(noLoc["192.168.1.77"]))
	}
	if len(noLoc["192.168.1.77"][0].server) > maxSSDPHeaderLen {
		t.Fatalf("expected SSDP SERVER header truncated to <= %d bytes, got %d", maxSSDPHeaderLen, len(noLoc["192.168.1.77"][0].server))
	}
}

// TestNervaAnonymousAccessIgnoresTLSAnonCipher verifies that tls-anon-cipher
// does not set Service.AnonymousAccess while Nerva's canonical AnonymousAccess
// flag and genuine unauth/anon finding IDs are preserved.
func TestNervaAnonymousAccessIgnoresTLSAnonCipher(t *testing.T) {
	now := time.Now().UTC()

	tlsSvc, _, _ := convertNervaService(plugins.Service{
		IP:              "192.168.1.10",
		Port:            443,
		Protocol:        "https",
		TLS:             true,
		AnonymousAccess: false,
		SecurityFindings: []plugins.SecurityFinding{
			{ID: "tls-anon-cipher", Severity: plugins.SeverityHigh, Evidence: "TLS_DH_anon_WITH_AES_128_CBC_SHA"},
		},
	}, now)
	if tlsSvc.AnonymousAccess {
		t.Fatal("tls-anon-cipher must NOT set AnonymousAccess=true")
	}

	// Canonical Nerva AnonymousAccess flag passes through cleanly.
	redisSvc, _, _ := convertNervaService(plugins.Service{
		IP:              "192.168.1.10",
		Port:            6379,
		Protocol:        "redis",
		AnonymousAccess: true,
	}, now)
	if !redisSvc.AnonymousAccess {
		t.Fatal("Nerva top-level AnonymousAccess=true must pass through")
	}

	// Explicit unauth finding ID sets AnonymousAccess=true.
	dockerSvc, _, _ := convertNervaService(plugins.Service{
		IP:       "192.168.1.10",
		Port:     2375,
		Protocol: "docker",
		SecurityFindings: []plugins.SecurityFinding{
			{ID: "docker-unauth-api", Severity: plugins.SeverityCritical, Evidence: "GET /version 200 OK"},
		},
	}, now)
	if !dockerSvc.AnonymousAccess {
		t.Fatal("docker-unauth-api finding should set AnonymousAccess=true")
	}
}

// TestFingerprinterRefusesPublicIPsUnlessAllowed verifies that FingerprintAll
// refuses to probe public internet IP addresses unless explicitly allowed via
// SetAllowedSubnets, while permitting RFC1918, IPv6 ULA, CGNAT, link-local,
// and loopback addresses.
func TestFingerprinterRefusesPublicIPsUnlessAllowed(t *testing.T) {
	fp := NewFingerprinter([]int{80}, 2, 200*time.Millisecond, nil)
	fp.skipDiscovery = true

	for _, allowed := range []string{"192.168.1.10", "10.0.0.5", "172.16.0.1", "100.64.1.2", "169.254.1.1", "127.0.0.1", "fd00::1", "fe80::1", "::1"} {
		if !fp.isAllowedProbeIP(allowed) {
			t.Fatalf("expected private/local IP %s to be allowed", allowed)
		}
	}
	for _, blocked := range []string{"203.0.113.10", "8.8.8.8", "1.1.1.1", "2001:db8::1", "2606:4700:4700::1111"} {
		if fp.isAllowedProbeIP(blocked) {
			t.Fatalf("expected public IP %s to be refused by default", blocked)
		}
	}

	profiles := fp.FingerprintAll(context.Background(), []unifi.Client{
		{IP: "203.0.113.10", MAC: "aa:bb:cc:dd:ee:10", Name: "public-host"},
		{IP: "8.8.8.8", MAC: "aa:bb:cc:dd:ee:11", Name: "dns-public"},
	})
	if len(profiles) != 0 {
		t.Fatalf("expected public IPs to produce 0 profiles, got %+v", profiles)
	}

	fp.SetAllowedSubnets([]netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")})
	if !fp.isAllowedProbeIP("203.0.113.10") {
		t.Fatal("expected IP inside explicitly allowed subnet to be permitted")
	}
	if fp.isAllowedProbeIP("8.8.8.8") {
		t.Fatal("expected IP outside explicitly allowed subnet to remain refused")
	}
}

// TestPriorityPortsDialedBeforeBaselineAndExemptFromCutoff verifies that
// hinted and discovered ports are ordered before baseline ports so silent
// firewalls dropping baseline SYNs never prevent priority ports from being probed.
func TestPriorityPortsDialedBeforeBaselineAndExemptFromCutoff(t *testing.T) {
	fp := NewFingerprinter([]int{21, 22, 23, 80, 135, 139, 443, 445, 3389}, 1, 200*time.Millisecond, nil)
	fp.SetHostPortHints(map[string][]int{"192.168.1.30": {3389, 8443}})
	fp.SetCachedDiscovery(&LANDiscovery{
		PortsByIP: map[string][]int{"192.168.1.30": {8123}},
	})

	priority, baseline := fp.splitPortsForHost("192.168.1.30")
	wantPriority := []int{3389, 8123, 8443}
	if len(priority) != len(wantPriority) {
		t.Fatalf("priority ports=%v, want %v", priority, wantPriority)
	}
	for i, p := range wantPriority {
		if priority[i] != p {
			t.Fatalf("priority[%d]=%d, want %d (full=%v)", i, priority[i], p, priority)
		}
	}
	for _, p := range baseline {
		if p == 3389 {
			t.Fatalf("priority port 3389 should not be duplicated in baseline: %v", baseline)
		}
	}

	ordered := fp.portsForHost("192.168.1.30")
	if len(ordered) < 3 || ordered[0] != 3389 || ordered[1] != 8123 || ordered[2] != 8443 {
		t.Fatalf("expected priority ports first in portsForHost, got %v", ordered)
	}
}

// TestAlternatePortFallbackBoundsBannerRead verifies that a hostile TCP
// listener streaming unbounded bytes without a newline cannot cause
// probeAlternatePortFallback to allocate or store more than 256 bytes.
func TestAlternatePortFallbackBoundsBannerRead(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer c.Close()
		chunk := append([]byte("SSH-2.0-flood-"), bytes.Repeat([]byte("A"), 64*1024)...)
		_, _ = c.Write(chunk)
	}()

	svc, ok := probeAlternatePortFallback(context.Background(), "127.0.0.1", port, 500*time.Millisecond)
	if !ok || svc.Protocol != "ssh" {
		t.Fatalf("expected bounded ssh fallback detection, got ok=%v svc=%+v", ok, svc)
	}
	if len(svc.Banner) == 0 || len(svc.Banner) > maxFallbackBannerBytes {
		t.Fatalf("expected banner length in (0, %d], got %d", maxFallbackBannerBytes, len(svc.Banner))
	}
}

// TestServiceCoverageDualStackMDNSNoDoubleCount verifies that ComputeServiceCoverage
// records mDNS endpoints under the host's probed address family rather than
// "dual" so dual-stack hosts do not double-count the same port.
func TestServiceCoverageDualStackMDNSNoDoubleCount(t *testing.T) {
	profiles := []HostProfile{{
		Client: unifi.Client{
			IP:   "192.168.1.50",
			IPv6: []string{"fd00::50"},
		},
		OpenPorts: []int{8123},
		Services: []Service{{
			Port:          8123,
			Transport:     "tcp",
			Protocol:      "http",
			State:         ServiceStateObservedProtocol,
			AddressFamily: "ipv4",
		}},
		MDNSServices: []MDNSService{{
			Type:          "_home-assistant._tcp",
			Port:          8123,
			Transport:     "tcp",
			AddressFamily: "dual",
		}},
	}}

	cov := ComputeServiceCoverage(profiles)
	if cov.TotalObservedEndpoints != 1 {
		t.Fatalf("expected 1 deduplicated endpoint for dual-stack port 8123, got %d (report=%+v)", cov.TotalObservedEndpoints, cov)
	}
	if cov.ByAddressFamily["dual"] != 0 {
		t.Fatalf("expected no 'dual' address-family bucket, got %+v", cov.ByAddressFamily)
	}
}

// TestTLSSelfSignedRecognizesLeafCertWithoutCA verifies that self-signed leaf
// certificates lacking CA basicConstraints are reported as TLSSelfSigned=true,
// while CA-signed leaf certificates report TLSSelfSigned=false.
func TestTLSSelfSignedRecognizesLeafCertWithoutCA(t *testing.T) {
	leafCert := generateTestSelfSignedCert(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><title>SelfSigned</title></html>"))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{leafCert}}
	srv.StartTLS()
	defer srv.Close()

	_, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	fp := NewFingerprinter([]int{port}, 1, time.Second, nil)
	banner, ok := fp.fetchHTTPBanner(context.Background(), "https", "127.0.0.1", port)
	if !ok {
		t.Fatal("expected HTTPS banner fetch to succeed")
	}
	if !banner.TLSSelfSigned {
		t.Fatal("expected self-signed leaf cert without CA basicConstraints to report TLSSelfSigned=true")
	}

	// Verify a CA-signed leaf cert returns false.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen ca key: %v", err)
	}
	caTmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen leaf key: %v", err)
	}
	leafTmpl := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "device.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &leafTmpl, &caTmpl, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create ca-signed leaf: %v", err)
	}
	parsedLeaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if isSelfSignedCert(parsedLeaf) {
		t.Fatal("CA-signed leaf cert must not be reported as self-signed")
	}
}

// TestWSDProbeGeneratesUniqueRandomMessageID verifies that buildWSDProbeXML
// emits a fresh RFC 4122 UUID MessageID on every probe instead of a constant.
func TestWSDProbeGeneratesUniqueRandomMessageID(t *testing.T) {
	re := regexp.MustCompile(`<w:MessageID>uuid:([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})</w:MessageID>`)
	p1 := buildWSDProbeXML()
	p2 := buildWSDProbeXML()
	m1 := re.FindStringSubmatch(p1)
	m2 := re.FindStringSubmatch(p2)
	if len(m1) != 2 || len(m2) != 2 {
		t.Fatalf("expected valid UUIDv4 MessageIDs, got p1=%q p2=%q", p1, p2)
	}
	if m1[1] == m2[1] {
		t.Fatalf("expected fresh random UUID per WSD probe, got duplicate %q", m1[1])
	}
}

// TestFingerprinterTransportDisablesKeepAlivesAndSupportsCachedDiscovery
// verifies that NewFingerprinter disables HTTP keep-alives to avoid socket
// leaks across scans and that SetCachedDiscovery injects cached LAN discovery.
func TestFingerprinterTransportDisablesKeepAlivesAndSupportsCachedDiscovery(t *testing.T) {
	fp := NewFingerprinter([]int{80}, 2, time.Second, nil)
	tr, ok := fp.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", fp.httpClient.Transport)
	}
	if !tr.DisableKeepAlives {
		t.Fatal("expected DisableKeepAlives=true on Fingerprinter transport")
	}
	if tr.IdleConnTimeout <= 0 {
		t.Fatalf("expected positive IdleConnTimeout on Fingerprinter transport, got %v", tr.IdleConnTimeout)
	}

	cached := &LANDiscovery{
		MDNS: map[string][]MDNSService{
			"192.168.1.90": {{Type: "_http._tcp", Port: 8080}},
		},
	}
	fp.SetCachedDiscovery(cached)
	if !fp.skipDiscovery || fp.Discovery() != cached {
		t.Fatalf("expected SetCachedDiscovery to inject cached snapshot and skip multicast discovery")
	}
}
