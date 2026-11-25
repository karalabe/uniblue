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
	"encoding/binary"
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
	cache.SetTrustedReflectors([]string{"192.168.1.1"})

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
	for hostIdx := range 70 {
		respIP := fmt.Sprintf("10.1.%d.%d", hostIdx/250, (hostIdx%250)+1)
		for svcIdx := range 64 {
			pkt := buildMDNSTestPacket("_http._tcp", fmt.Sprintf("h%d-s%d", hostIdx, svcIdx), fmt.Sprintf("h%d.local", hostIdx), uint16(8000+svcIdx), 120, []byte{10, 1, byte(hostIdx / 250), byte((hostIdx % 250) + 1)}, nil, nil)
			globalCache.IngestMDNSPacket(pkt, respIP, "eth0", "LAN", now)
		}
	}
	if len(globalCache.mdnsInst) > maxMDNSServicesTotal {
		t.Fatalf("global mDNS instance cap exceeded: got %d, max %d", len(globalCache.mdnsInst), maxMDNSServicesTotal)
	}
	if len(globalCache.mdnsInst) != maxMDNSServicesTotal {
		t.Fatalf("expected global mDNS cap to saturate at %d, got %d", maxMDNSServicesTotal, len(globalCache.mdnsInst))
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

func buildMDNSRawPTRPacket(ownerName, targetName string, ttl uint32) []byte {
	var pkt bytes.Buffer
	pkt.Write([]byte{0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00})
	writeName := func(buf *bytes.Buffer, name string) {
		for _, lbl := range bytes.Split([]byte(name), []byte(".")) {
			if len(lbl) == 0 {
				continue
			}
			buf.WriteByte(byte(len(lbl)))
			buf.Write(lbl)
		}
		buf.WriteByte(0)
	}
	writeName(&pkt, ownerName)
	var rdata bytes.Buffer
	writeName(&rdata, targetName)
	_ = binary.Write(&pkt, binary.BigEndian, uint16(12)) // PTR
	_ = binary.Write(&pkt, binary.BigEndian, uint16(1))
	_ = binary.Write(&pkt, binary.BigEndian, ttl)
	_ = binary.Write(&pkt, binary.BigEndian, uint16(rdata.Len()))
	pkt.Write(rdata.Bytes())
	return pkt.Bytes()
}

// TestMDNSPTRTypeConfusionCannotHideVictimPort verifies that a forged PTR
// pointing from a raw-print service type to a victim's non-print instance name
// is ignored and cannot suppress probing of the victim's own advertised port.
func TestMDNSPTRTypeConfusionCannotHideVictimPort(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	cache := NewDiscoveryCache()

	// Attacker injects a mismatched PTR before the victim responds.
	forgedPTR := buildMDNSRawPTRPacket("_pdl-datastream._tcp.local", "NAS._smb._tcp.local", 120)
	cache.IngestMDNSPacket(forgedPTR, "192.168.1.66", "eth0", "LAN", now)

	// Victim announces its own legitimate SMB service.
	victimPkt := buildMDNSTestPacket("_smb._tcp", "NAS", "nas.local", 445, 120, []byte{192, 168, 1, 10}, nil, nil)
	cache.IngestMDNSPacket(victimPkt, "192.168.1.10", "eth0", "LAN", now)

	snap := cache.Snapshot(now)
	if _, hidden := snap.RawPrintIPs["192.168.1.10"][445]; hidden {
		t.Fatalf("forged PTR type confusion must not mark victim port 445 as raw print: %+v", snap.RawPrintIPs)
	}
	foundPort := false
	for _, p := range snap.PortsByIP["192.168.1.10"] {
		if p == 445 {
			foundPort = true
		}
	}
	if !foundPort {
		t.Fatalf("victim SMB port 445 must remain in PortsByIP, got %v", snap.PortsByIP["192.168.1.10"])
	}
	hp := HostProfile{
		Client:       unifi.Client{IP: "192.168.1.10"},
		MDNSServices: snap.MDNS["192.168.1.10"],
	}
	if hp.IsRawPrintPort(445) {
		t.Fatal("HostProfile.IsRawPrintPort(445) must remain false after PTR type-confusion attempt")
	}
}

// TestMDNSPerTargetAuthorityBlocksMultiAForgedPortHint verifies that a forged
// SRV whose target hostname resolves to both a victim IP and the attacker's own
// IP is treated as reflected for the victim and never injects ports into PortsByIP.
func TestMDNSPerTargetAuthorityBlocksMultiAForgedPortHint(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	cache := NewDiscoveryCache()

	// Attacker 192.168.1.66 advertises evil.local pointing to both victim and itself.
	pktVictimA := buildMDNSTestPacket("_http._tcp", "bait", "evil.local", 6638, 120, []byte{192, 168, 1, 10}, nil, nil)
	pktAttackerA := buildMDNSTestPacket("_http._tcp", "bait", "evil.local", 6638, 120, []byte{192, 168, 1, 66}, nil, nil)
	cache.IngestMDNSPacket(pktVictimA, "192.168.1.66", "eth0", "LAN", now)
	cache.IngestMDNSPacket(pktAttackerA, "192.168.1.66", "eth0", "LAN", now)

	snap := cache.Snapshot(now)
	if len(snap.PortsByIP["192.168.1.10"]) != 0 {
		t.Fatalf("forged multi-A SRV must not inject ports into victim PortsByIP, got %v", snap.PortsByIP["192.168.1.10"])
	}
	svcs := snap.MDNS["192.168.1.10"]
	if len(svcs) != 1 || !svcs[0].Reflected {
		t.Fatalf("victim service from multi-A forged SRV must be marked Reflected=true, got %+v", svcs)
	}
	// Attacker's own IP matches the responder and may remain non-reflected.
	attackerSvcs := snap.MDNS["192.168.1.66"]
	if len(attackerSvcs) != 1 || attackerSvcs[0].Reflected {
		t.Fatalf("attacker's own target IP should remain authoritative, got %+v", attackerSvcs)
	}
}

// TestReflectedSerialBridgeProtectedZeroBytesAndSpoofedAdminPortNotHidden
// verifies that a Zigbee UART coordinator advertised through an mDNS reflector
// on known coordinator ports (6638, 6639, 20108) receives zero payload bytes
// even when hinted, while spoofed relayed serial-bridge or raw-print adverts
// cannot hide arbitrary ports (6379, 3389, 5900, 2375, 8080, 9101-9107, 445, 22).
func TestReflectedSerialBridgeProtectedZeroBytesAndSpoofedAdminPortNotHidden(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	cache := NewDiscoveryCache()
	cache.SetTrustedReflectors([]string{"192.168.1.1"})

	// Gateway reflector 192.168.1.1 relays SLZB-06 coordinator on known port 6638.
	reflectedSerial := buildMDNSTestPacket("_slzb-06._tcp", "slzb-coord", "slzb.local", 6638, 120, []byte{192, 168, 20, 40}, nil, nil)
	cache.IngestMDNSPacket(reflectedSerial, "192.168.1.1", "eth0", "IoT", now)

	// Gateway reflector relays a raw printer on JetDirect ports 9100-9107 (all protected).
	reflectedPrint9100 := buildMDNSTestPacket("_pdl-datastream._tcp", "office-prn-9100", "prn9100.local", 9100, 120, []byte{192, 168, 20, 50}, nil, nil)
	cache.IngestMDNSPacket(reflectedPrint9100, "192.168.1.1", "eth0", "IoT", now)
	for p := uint16(9101); p <= 9107; p++ {
		pkt := buildMDNSTestPacket("_pdl-datastream._tcp", fmt.Sprintf("office-prn-%d", p), fmt.Sprintf("prn-%d.local", p), p, 120, []byte{192, 168, 20, 51}, nil, nil)
		cache.IngestMDNSPacket(pkt, "192.168.1.1", "eth0", "IoT", now)
	}

	// Attacker tries to hide Redis (6379), RDP (3389), VNC (5900), Docker (2375),
	// HTTP (8080), SMB (445), and SSH (22) via forged relayed adverts.
	for _, p := range []uint16{22, 2375, 3389, 5900, 6379, 8080} {
		pkt := buildMDNSTestPacket("_slzb-06._tcp", fmt.Sprintf("fake-zigbee-%d", p), "nas.local", p, 120, []byte{192, 168, 1, 10}, nil, nil)
		cache.IngestMDNSPacket(pkt, "192.168.1.66", "eth0", "LAN", now)
	}
	spoofedSMB := buildMDNSTestPacket("_pdl-datastream._tcp", "fake-prn", "nas.local", 445, 120, []byte{192, 168, 1, 10}, nil, nil)
	cache.IngestMDNSPacket(spoofedSMB, "192.168.1.66", "eth0", "LAN", now)

	// Authoritative self-announced custom serial port 7777 and print port 9102 stay protected.
	selfSerial := buildMDNSTestPacket("_slzb-06._tcp", "own-coord", "own-coord.local", 7777, 120, []byte{192, 168, 1, 88}, nil, nil)
	cache.IngestMDNSPacket(selfSerial, "192.168.1.88", "eth0", "LAN", now)
	selfPrint := buildMDNSTestPacket("_pdl-datastream._tcp", "own-prn", "own-prn.local", 9102, 120, []byte{192, 168, 1, 89}, nil, nil)
	cache.IngestMDNSPacket(selfPrint, "192.168.1.89", "eth0", "LAN", now)

	snap := cache.Snapshot(now)
	if _, ok := snap.RawPrintIPs["192.168.20.40"][6638]; !ok {
		t.Fatalf("reflected SLZB-06 known coordinator port 6638 must be protected: %+v", snap.RawPrintIPs)
	}
	if _, ok := snap.RawPrintIPs["192.168.20.50"][9100]; !ok {
		t.Fatalf("reflected raw print port 9100 must be protected: %+v", snap.RawPrintIPs)
	}
	for p := 9101; p <= 9107; p++ {
		if _, protected := snap.RawPrintIPs["192.168.20.51"][p]; !protected {
			t.Fatalf("relayed _pdl-datastream must protect JetDirect port %d", p)
		}
	}
	victimHP := HostProfile{
		Client:       unifi.Client{IP: "192.168.1.10"},
		MDNSServices: snap.MDNS["192.168.1.10"],
	}
	for _, p := range []int{22, 445, 2375, 3389, 5900, 6379, 8080} {
		if _, poisoned := snap.RawPrintIPs["192.168.1.10"][p]; poisoned {
			t.Fatalf("forged relayed advert must NOT hide victim port %d", p)
		}
		if victimHP.IsRawPrintPort(p) {
			t.Fatalf("HostProfile.IsRawPrintPort(%d) must NOT be true for forged relayed advert", p)
		}
	}
	if _, ok := snap.RawPrintIPs["192.168.1.88"][7777]; !ok {
		t.Fatalf("authoritative self-announced serial port 7777 must stay protected")
	}
	if _, ok := snap.RawPrintIPs["192.168.1.89"][9102]; !ok {
		t.Fatalf("authoritative self-announced print port 9102 must stay protected")
	}

	// End-to-end socket verification on a known reflected coordinator port.
	var ln net.Listener
	var port int
	for _, cand := range []int{6638, 6639, 20108} {
		l, lerr := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", cand))
		if lerr == nil {
			ln = l
			port = cand
			break
		}
	}
	if ln != nil {
		defer ln.Close()
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

		loopCache := NewDiscoveryCache()
		loopCache.SetTrustedReflectors([]string{"192.168.1.1"})
		pkt := buildMDNSTestPacket("_slzb-06._tcp", "slzb-coord", "slzb.local", uint16(port), 120, []byte{127, 0, 0, 1}, nil, nil)
		loopCache.IngestMDNSPacket(pkt, "192.168.1.1", "eth0", "IoT", now)
		loopSnap := loopCache.Snapshot(now)

		fp := NewFingerprinter([]int{80}, 1, 500*time.Millisecond, nil)
		fp.SetCachedDiscovery(loopSnap)
		fp.SetHostPortHints(map[string][]int{"127.0.0.1": {port}})

		profiles := fp.FingerprintAll(context.Background(), []unifi.Client{{IP: "127.0.0.1", Name: "SLZB-06"}})
		time.Sleep(100 * time.Millisecond)

		if len(profiles) != 1 || !profiles[0].HasPort(port) {
			t.Fatalf("expected connect-only detection on reflected serial port %d, got %+v", port, profiles)
		}
		if got := bytesRead.Load(); got != 0 {
			t.Fatalf("SAFETY VIOLATION: reflected serial coordinator received %d bytes (must be 0)", got)
		}
	}
}

// TestMDNSReflectorLargeDeviceCountAndPerTargetCap verifies that a single mDNS
// reflector relaying 100+ distinct devices is not truncated at 64, while a
// multi-source flood targeting a single victim is capped at maxMDNSServicesPerHost.
func TestMDNSReflectorLargeDeviceCountAndPerTargetCap(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

	// 1. Gateway reflector 192.168.1.1 relays 100 distinct IoT devices.
	refCache := NewDiscoveryCache()
	refCache.SetTrustedReflectors([]string{"192.168.1.1"})
	for i := range 100 {
		ip := []byte{192, 168, 20, byte(i + 1)}
		pkt := buildMDNSTestPacket("_esphomelib._tcp", fmt.Sprintf("plug-%d", i), fmt.Sprintf("plug-%d.local", i), 6053, 120, ip, nil, []string{"platform=ESP32"})
		refCache.IngestMDNSPacket(pkt, "192.168.1.1", "eth0", "IoT", now)
	}
	refSnap := refCache.Snapshot(now)
	if len(refSnap.MDNS) != 100 {
		t.Fatalf("expected all 100 reflected devices to remain visible, got %d", len(refSnap.MDNS))
	}

	// 2. Multi-source attacker (40 source IPs x 64 services = 2560) targets one victim.
	floodCache := NewDiscoveryCache()
	victimOwn := buildMDNSTestPacket("_smb._tcp", "RealNAS", "realnas.local", 445, 120, []byte{192, 168, 1, 10}, nil, nil)
	floodCache.IngestMDNSPacket(victimOwn, "192.168.1.10", "eth0", "LAN", now)
	for src := range 40 {
		respIP := fmt.Sprintf("fd00:dead::%x", src+1)
		for svc := range 64 {
			pkt := buildMDNSTestPacket("_http._tcp", fmt.Sprintf("f-%d-%d", src, svc), fmt.Sprintf("fh-%d-%d.local", src, svc), uint16(10000+svc), 120, []byte{192, 168, 1, 10}, nil, nil)
			floodCache.IngestMDNSPacket(pkt, respIP, "eth0", "LAN", now)
		}
	}
	floodSnap := floodCache.Snapshot(now)
	if got := len(floodSnap.MDNS["192.168.1.10"]); got > maxMDNSServicesPerHost {
		t.Fatalf("per-target mDNS service cap exceeded under multi-source flood: got %d, max %d", got, maxMDNSServicesPerHost)
	}
	foundReal := false
	for _, s := range floodSnap.MDNS["192.168.1.10"] {
		if s.Type == "_smb._tcp" && s.Instance == "RealNAS" && !s.Reflected {
			foundReal = true
			break
		}
	}
	if !foundReal {
		t.Fatalf("victim's own authoritative service was evicted by multi-source flood")
	}
}

type recordingRoundTripper struct {
	reqs []string
}

func (rt *recordingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.reqs = append(rt.reqs, req.URL.String())
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       http.NoBody,
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// TestSSDPFetchRefusesPublicRespondersUnlessAllowed verifies that a spoofed
// SSDP reply from a public internet address never triggers an outbound HTTP GET
// unless that prefix is explicitly permitted via allowedSubnets.
func TestSSDPFetchRefusesPublicRespondersUnlessAllowed(t *testing.T) {
	rt := &recordingRoundTripper{}
	client := &http.Client{Transport: rt}
	hits := []ssdpHit{{
		ip:       "203.0.113.7",
		st:       "upnp:rootdevice",
		location: "http://203.0.113.7:8080/desc.xml",
	}}
	noLoc := map[string][]ssdpHit{
		"203.0.113.7": {{ip: "203.0.113.7", st: "ssdp:all", server: "Spoof/1.0"}},
	}

	res := fetchSSDPDescriptions(context.Background(), client, hits, noLoc, nil, nil)
	if len(rt.reqs) != 0 {
		t.Fatalf("public SSDP responder must never trigger HTTP GET, got %v", rt.reqs)
	}
	if len(res["203.0.113.7"]) != 0 {
		t.Fatalf("public SSDP responder must not be recorded, got %+v", res["203.0.113.7"])
	}

	// Explicit site subnet allows the fetch.
	allowed := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	_ = fetchSSDPDescriptionsWithSubnets(context.Background(), client, hits, nil, nil, nil, allowed)
	if len(rt.reqs) != 1 || rt.reqs[0] != "http://203.0.113.7:8080/desc.xml" {
		t.Fatalf("expected explicitly allowed subnet SSDP fetch to proceed, got %v", rt.reqs)
	}
}

// TestSSDPMultiSourceFloodDoesNotStarveGatewayIGD verifies that multi-source
// SSDP LOCATION floods cannot evict or starve the gateway's IGD LOCATION.
func TestSSDPMultiSourceFloodDoesNotStarveGatewayIGD(t *testing.T) {
	t.Run("many multi-location sources", func(t *testing.T) {
		c := newSSDPCollector()
		// 40 distinct flooder IPs x 8 LOCATIONs each = 320 > maxSSDPLocHitsTotal.
		for src := range 40 {
			ip := fmt.Sprintf("192.168.10.%d", src+10)
			for i := range maxSSDPLocHitsPerIP {
				raw := fmt.Sprintf("HTTP/1.1 200 OK\r\nLOCATION: http://%s:%d/d.xml\r\nST: upnp:rootdevice\r\nSERVER: Flood/1.0\r\n\r\n", ip, 10000+i)
				c.ingest(ip, raw)
			}
		}
		routerRaw := "HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1:49000/igd.xml\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nSERVER: MiniUPnPd/2.3\r\n\r\n"
		c.ingest("192.168.1.1", routerRaw)

		hits, _ := c.result()
		if len(hits) > maxSSDPLocHitsTotal {
			t.Fatalf("global SSDP cap exceeded: %d > %d", len(hits), maxSSDPLocHitsTotal)
		}
		if len(hits) == 0 || hits[0].ip != "192.168.1.1" {
			t.Fatalf("expected gateway IGD hit to survive multi-source flood and sort first, got first=%+v", hits[:min(3, len(hits))])
		}
	})

	t.Run("single-location flood exceeding global cap", func(t *testing.T) {
		c := newSSDPCollector()
		for src := range maxSSDPLocHitsTotal + 50 {
			ip := fmt.Sprintf("10.50.%d.%d", src/250, (src%250)+1)
			raw := fmt.Sprintf("HTTP/1.1 200 OK\r\nLOCATION: http://%s:8080/d.xml\r\nST: upnp:rootdevice\r\nSERVER: Flood/1.0\r\n\r\n", ip)
			c.ingest(ip, raw)
		}
		routerRaw := "HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1:49000/igd.xml\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nSERVER: MiniUPnPd/2.3\r\n\r\n"
		c.ingest("192.168.1.1", routerRaw)

		hits, _ := c.result()
		if len(hits) == 0 || hits[0].ip != "192.168.1.1" {
			t.Fatalf("expected gateway IGD hit to survive full single-slot flood via reserved IGD priority, got first=%+v", hits[:min(3, len(hits))])
		}
	})

	t.Run("32 sources forged IGD flood does not starve router", func(t *testing.T) {
		c := newSSDPCollector()
		for src := range 32 {
			ip := fmt.Sprintf("192.168.30.%d", src+10)
			for i := range maxSSDPLocHitsPerIP {
				raw := fmt.Sprintf("HTTP/1.1 200 OK\r\nLOCATION: http://%s:%d/igd.xml\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nSERVER: SpoofIGD/1.0\r\n\r\n", ip, 20000+i)
				c.ingest(ip, raw)
			}
		}
		routerRaw := "HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1:49000/igd.xml\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nSERVER: MiniUPnPd/2.3\r\n\r\n"
		c.ingest("192.168.1.1", routerRaw)

		hits, _ := c.result()
		foundRouter := false
		for _, h := range hits {
			if h.ip == "192.168.1.1" && h.location == "http://192.168.1.1:49000/igd.xml" {
				foundRouter = true
			}
		}
		if !foundRouter {
			t.Fatalf("real router IGD was starved by 32-source forged IGD flood (total hits=%d)", len(hits))
		}
		if got := c.igdLocCountByIP["192.168.30.10"]; got > maxSSDPIGDLocHitsPerIP {
			t.Fatalf("expected per-source IGD locations capped at %d, got %d", maxSSDPIGDLocHitsPerIP, got)
		}
	})

	t.Run("128 sources saturating table with forged IGDs evicts excess for router", func(t *testing.T) {
		c := newSSDPCollector()
		for src := range 128 {
			ip := fmt.Sprintf("10.60.%d.%d", src/250, (src%250)+1)
			for i := range maxSSDPIGDLocHitsPerIP {
				raw := fmt.Sprintf("HTTP/1.1 200 OK\r\nLOCATION: http://%s:%d/igd.xml\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nSERVER: SpoofIGD/1.0\r\n\r\n", ip, 21000+i)
				c.ingest(ip, raw)
			}
		}
		routerRaw := "HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1:49000/igd.xml\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nSERVER: MiniUPnPd/2.3\r\n\r\n"
		c.ingest("192.168.1.1", routerRaw)

		hits, _ := c.result()
		if len(hits) > maxSSDPLocHitsTotal {
			t.Fatalf("global SSDP cap exceeded: %d > %d", len(hits), maxSSDPLocHitsTotal)
		}
		foundRouter := false
		for _, h := range hits {
			if h.ip == "192.168.1.1" {
				foundRouter = true
				break
			}
		}
		if !foundRouter {
			t.Fatalf("real router IGD was starved when 128 sources saturated table with 2 forged IGDs each")
		}
	})
}

// TestDualStackFingerprintHostDeduplicatesDiscoveryEntries verifies that a
// dual-stack client with matching mDNS, UPnP, and WS-Discovery observations
// across IPv4 and IPv6 does not receive duplicate discovery records in HostProfile.
func TestDualStackFingerprintHostDeduplicatesDiscoveryEntries(t *testing.T) {
	fp := NewFingerprinter(nil, 1, 200*time.Millisecond, nil)
	fp.SetCachedDiscovery(&LANDiscovery{
		MDNS: map[string][]MDNSService{
			"127.0.0.1": {{Type: "_home-assistant._tcp", Instance: "Home", Port: 8123, Transport: "tcp", ObserverVLAN: "LAN", Reflected: true}},
			"::1":       {{Type: "_home-assistant._tcp", Instance: "Home", Port: 8123, Transport: "tcp", ObserverVLAN: "LAN", Reflected: false}},
		},
		UPnP: map[string][]UPnPDevice{
			"127.0.0.1": {{ST: "upnp:rootdevice", Port: 1900, Manufacturer: "Sonos", ModelName: "Beam"}},
			"::1":       {{ST: "upnp:rootdevice", Port: 1900, Manufacturer: "Sonos", ModelName: "Beam"}},
		},
		WSDiscovery: map[string][]WSDiscoveryRecord{
			"127.0.0.1": {{Types: []string{"NetworkVideoTransmitter"}, Ports: []int{8000}}},
			"::1":       {{Types: []string{"NetworkVideoTransmitter"}, Ports: []int{8000}}},
		},
	})

	hp := fp.FingerprintHost(context.Background(), unifi.Client{
		IP:   "127.0.0.1",
		IPv6: []string{"::1"},
		Name: "ha-dual-stack",
	})
	if len(hp.MDNSServices) != 1 {
		t.Fatalf("expected 1 deduplicated mDNS service on dual-stack host, got %d: %+v", len(hp.MDNSServices), hp.MDNSServices)
	}
	if hp.MDNSServices[0].Reflected {
		t.Fatalf("expected authoritative non-reflected mDNS record to win dual-stack dedupe, got %+v", hp.MDNSServices[0])
	}
	if len(hp.UPnPDevices) != 1 {
		t.Fatalf("expected 1 deduplicated UPnP device on dual-stack host, got %d: %+v", len(hp.UPnPDevices), hp.UPnPDevices)
	}
	if len(hp.WSDiscovery) != 1 {
		t.Fatalf("expected 1 deduplicated WS-Discovery record on dual-stack host, got %d: %+v", len(hp.WSDiscovery), hp.WSDiscovery)
	}
}

// TestConvertNervaServiceClearsHTTPAnonymousFlagForUnrelatedFindings verifies
// that Nerva's HTTP AnonymousAccess flag is cleared when the only anonymous
// finding was a dropped synthetic placeholder or when only non-auth findings
// (such as os-eol or php version checks) are present.
func TestConvertNervaServiceClearsHTTPAnonymousFlagForUnrelatedFindings(t *testing.T) {
	now := time.Now().UTC()

	// Synthetic grafana-anon-access dropped + unrelated os-eol kept.
	svc1, _, _ := convertNervaService(plugins.Service{
		IP:              "192.168.1.20",
		Port:            3000,
		Protocol:        "http",
		AnonymousAccess: true,
		SecurityFindings: []plugins.SecurityFinding{
			{ID: "grafana-anon-access", Severity: plugins.SeverityMedium, Evidence: "Successfully queried endpoint without credentials"},
			{ID: "os-eol", Severity: plugins.SeverityMedium, Title: "End-of-Life OS", Evidence: "Ubuntu 18.04"},
		},
	}, now)
	if svc1.AnonymousAccess {
		t.Fatal("AnonymousAccess must be cleared when synthetic HTTP anon finding was dropped and only os-eol remains")
	}
	if len(svc1.Findings) != 1 || svc1.Findings[0].ID != "os-eol" {
		t.Fatalf("expected os-eol finding to remain, got %+v", svc1.Findings)
	}

	// HTTP fingerprinter sets AnonymousAccess=true with only a non-auth custom finding.
	svc2, _, _ := convertNervaService(plugins.Service{
		IP:              "192.168.1.21",
		Port:            80,
		Protocol:        "http",
		AnonymousAccess: true,
		SecurityFindings: []plugins.SecurityFinding{
			{ID: "php-vulnerable-php2shell", Severity: plugins.SeverityHigh, Title: "PHP CGI Vulnerable", Evidence: "X-Powered-By: PHP/8.1"},
		},
	}, now)
	if svc2.AnonymousAccess {
		t.Fatal("AnonymousAccess must be cleared for HTTP services with only non-auth findings")
	}
	if len(svc2.Findings) != 1 || svc2.Findings[0].ID != "php-vulnerable-php2shell" {
		t.Fatalf("expected php-vulnerable-php2shell to remain, got %+v", svc2.Findings)
	}

	// Real unauthenticated HTTP finding still preserves AnonymousAccess=true.
	svc3, _, _ := convertNervaService(plugins.Service{
		IP:              "192.168.1.22",
		Port:            8080,
		Protocol:        "http",
		AnonymousAccess: true,
		SecurityFindings: []plugins.SecurityFinding{
			{ID: "jenkins-unauth-console", Severity: plugins.SeverityCritical, Evidence: "GET /script 200 OK"},
		},
	}, now)
	if !svc3.AnonymousAccess {
		t.Fatal("real unauth HTTP finding must preserve AnonymousAccess=true")
	}
}

func buildMDNSBulkSRVPacket(host string, ipv4 []byte, svcType string, count int, basePort uint16, ttl uint32) []byte {
	var pkt bytes.Buffer
	anCount := uint16(1 + count)
	pkt.Write([]byte{0x00, 0x00, 0x84, 0x00, 0x00, 0x00})
	_ = binary.Write(&pkt, binary.BigEndian, anCount)
	pkt.Write([]byte{0x00, 0x00, 0x00, 0x00})

	writeName := func(buf *bytes.Buffer, name string) {
		for _, lbl := range bytes.Split([]byte(name), []byte(".")) {
			if len(lbl) == 0 {
				continue
			}
			buf.WriteByte(byte(len(lbl)))
			buf.Write(lbl)
		}
		buf.WriteByte(0)
	}

	// A record first.
	writeName(&pkt, host)
	_ = binary.Write(&pkt, binary.BigEndian, uint16(1))
	_ = binary.Write(&pkt, binary.BigEndian, uint16(1))
	_ = binary.Write(&pkt, binary.BigEndian, ttl)
	_ = binary.Write(&pkt, binary.BigEndian, uint16(4))
	pkt.Write(ipv4)

	// count SRV records pointing to host.
	for i := range count {
		full := fmt.Sprintf("flood-%d.%s.local", i, svcType)
		writeName(&pkt, full)
		var rdata bytes.Buffer
		_ = binary.Write(&rdata, binary.BigEndian, uint16(0))
		_ = binary.Write(&rdata, binary.BigEndian, uint16(0))
		_ = binary.Write(&rdata, binary.BigEndian, basePort+uint16(i))
		writeName(&rdata, host)
		_ = binary.Write(&pkt, binary.BigEndian, uint16(33))
		_ = binary.Write(&pkt, binary.BigEndian, uint16(1))
		_ = binary.Write(&pkt, binary.BigEndian, ttl)
		_ = binary.Write(&pkt, binary.BigEndian, uint16(rdata.Len()))
		pkt.Write(rdata.Bytes())
	}
	return pkt.Bytes()
}

// TestMDNSAttackerArrivesFirstAndGlobalFloodFairness verifies that:
//  1. A forged packet filling a victim's 64-entry per-target quota cannot drop
//     the victim's subsequent authoritative adverts or sink guards.
//  2. Multi-source forged floods (both 4 sources attempting 4096 entries and
//     32 sources saturating the 4096 global table) cannot blind genuine devices
//     answering later.
func TestMDNSAttackerArrivesFirstAndGlobalFloodFairness(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

	t.Run("attacker arrives first fills victim 64 SRVs and 64 hostnames", func(t *testing.T) {
		cache := NewDiscoveryCache()

		// 1 packet with 1 A record + 64 SRVs filling victim's instance quota.
		bulk := buildMDNSBulkSRVPacket("spoof.local", []byte{192, 168, 1, 10}, "_http._tcp", maxMDNSServicesPerHost, 10000, 120)
		cache.IngestMDNSPacket(bulk, "192.168.1.66", "eth0", "LAN", now)
		// Also fill victim's 64-hostname quota from attacker.
		for i := range maxMDNSServicesPerHost {
			pkt := buildMDNSTestPacket("_http._tcp", fmt.Sprintf("hflood-%d", i), fmt.Sprintf("spoof-h-%d.local", i), uint16(11000+i), 120, []byte{192, 168, 1, 10}, nil, nil)
			cache.IngestMDNSPacket(pkt, "192.168.1.67", "eth0", "LAN", now)
		}

		// Victim arrives afterwards with its own authoritative ESPHome + SLZB-06 adverts.
		esphome := buildMDNSTestPacket("_esphomelib._tcp", "hallway-node", "hallway.local", 6053, 120, []byte{192, 168, 1, 10}, nil, []string{"platform=ESP32"})
		slzb := buildMDNSTestPacket("_slzb-06._tcp", "zigbee-coord", "hallway.local", 6638, 120, []byte{192, 168, 1, 10}, nil, nil)
		cache.IngestMDNSPacket(esphome, "192.168.1.10", "eth0", "LAN", now)
		cache.IngestMDNSPacket(slzb, "192.168.1.10", "eth0", "LAN", now)

		snap := cache.Snapshot(now)
		foundESP, foundSLZB := false, false
		for _, s := range snap.MDNS["192.168.1.10"] {
			if s.Type == "_esphomelib._tcp" && s.Instance == "hallway-node" && !s.Reflected {
				foundESP = true
			}
			if s.Type == "_slzb-06._tcp" && s.Instance == "zigbee-coord" && !s.Reflected {
				foundSLZB = true
			}
		}
		if !foundESP || !foundSLZB {
			t.Fatalf("victim authoritative adverts suppressed by earlier forged packet: esphome=%v slzb=%v", foundESP, foundSLZB)
		}
		if _, protected := snap.RawPrintIPs["192.168.1.10"][6638]; !protected {
			t.Fatalf("victim authoritative SLZB-06 sink guard on 6638 was lost: %+v", snap.RawPrintIPs["192.168.1.10"])
		}
	})

	t.Run("4-source 4096 flood and 32-source full table flood", func(t *testing.T) {
		// 4 spoofed sources attempting 1024 forged entries each (4096 total).
		cache4 := NewDiscoveryCache()
		for src := range 4 {
			respIP := fmt.Sprintf("192.168.99.%d", src+1)
			for i := range 1024 {
				targetOctet3 := byte((src*1024+i)/200 + 1)
				targetOctet4 := byte((src*1024+i)%200 + 1)
				pkt := buildMDNSTestPacket("_http._tcp", fmt.Sprintf("f4-%d-%d", src, i), fmt.Sprintf("f4-%d-%d.local", src, i), uint16(12000+(i%1000)), 120, []byte{10, 20, targetOctet3, targetOctet4}, nil, nil)
				cache4.IngestMDNSPacket(pkt, respIP, "eth0", "LAN", now)
			}
		}
		genuine := buildMDNSTestPacket("_home-assistant._tcp", "Home", "home.local", 8123, 120, []byte{192, 168, 1, 50}, nil, nil)
		cache4.IngestMDNSPacket(genuine, "192.168.1.50", "eth0", "LAN", now)
		snap4 := cache4.Snapshot(now)
		if len(snap4.MDNS["192.168.1.50"]) != 1 || snap4.MDNS["192.168.1.50"][0].Type != "_home-assistant._tcp" {
			t.Fatalf("4-source flood blinded genuine device: %+v", snap4.MDNS["192.168.1.50"])
		}

		// 32 spoofed sources x 128 forged reflected entries = 4096, saturating global tables.
		cache32 := NewDiscoveryCache()
		for src := range 32 {
			respIP := fmt.Sprintf("192.168.98.%d", src+1)
			for i := range maxMDNSServicesPerResponder {
				idx := src*maxMDNSServicesPerResponder + i
				pkt := buildMDNSTestPacket("_http._tcp", fmt.Sprintf("f32-%d-%d", src, i), fmt.Sprintf("f32-%d-%d.local", src, i), uint16(13000+(i%1000)), 120, []byte{10, 30, byte(idx/200 + 1), byte(idx%200 + 1)}, nil, nil)
				cache32.IngestMDNSPacket(pkt, respIP, "eth0", "LAN", now)
			}
		}
		if len(cache32.mdnsInst) != maxMDNSServicesTotal || len(cache32.hostIPs) != maxMDNSHostsTotal {
			t.Fatalf("expected saturated global tables (%d/%d), got inst=%d hosts=%d", maxMDNSServicesTotal, maxMDNSHostsTotal, len(cache32.mdnsInst), len(cache32.hostIPs))
		}
		cache32.IngestMDNSPacket(genuine, "192.168.1.50", "eth0", "LAN", now)
		snap32 := cache32.Snapshot(now)
		if len(snap32.MDNS["192.168.1.50"]) != 1 || snap32.MDNS["192.168.1.50"][0].Type != "_home-assistant._tcp" {
			t.Fatalf("32-source global flood blinded genuine device: %+v", snap32.MDNS["192.168.1.50"])
		}
	})
}

// TestIPv6OnlyClientSelectsAllowedULAOverOutOfSubnetGUA verifies that an
// IPv6-only client whose PrimaryIP is an out-of-subnet GUA still probes its
// allowed ULA (or loopback) address instead of being skipped.
func TestIPv6OnlyClientSelectsAllowedULAOverOutOfSubnetGUA(t *testing.T) {
	clULA := unifi.Client{
		MAC:  "aa:bb:cc:dd:ee:25",
		Name: "v6-ula-sensor",
		IPv6: []string{"fe80::25", "2a02:1234:5678:10::25", "fd12:3456::25"},
	}
	if got := SelectProbeIP(clULA, nil); got != "fd12:3456::25" {
		t.Fatalf("SelectProbeIP(ULA fallback) = %q, want fd12:3456::25", got)
	}

	// FingerprintAll must retain this host rather than skipping it on PrimaryIP().
	fpNoPorts := NewFingerprinter(nil, 1, 100*time.Millisecond, nil)
	fpNoPorts.skipDiscovery = true
	profilesULA := fpNoPorts.FingerprintAll(context.Background(), []unifi.Client{clULA})
	if len(profilesULA) != 1 || profilesULA[0].Client.MAC != clULA.MAC {
		t.Fatalf("expected IPv6-only host with allowed ULA not to be skipped, got %+v", profilesULA)
	}

	// End-to-end dial verification when ::1 follows an out-of-subnet GUA.
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			_ = c.Close()
		}
	}()
	_, pStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(pStr)

	clLoop := unifi.Client{
		MAC:  "aa:bb:cc:dd:ee:26",
		Name: "v6-loop-host",
		IPv6: []string{"fe80::25", "2a02:1234:5678:10::25", "::1"},
	}
	if clLoop.PrimaryIP() != "2a02:1234:5678:10::25" {
		t.Fatalf("expected PrimaryIP to be out-of-subnet GUA, got %q", clLoop.PrimaryIP())
	}
	fp := NewFingerprinter([]int{port}, 1, 500*time.Millisecond, nil)
	fp.skipDiscovery = true
	profiles := fp.FingerprintAll(context.Background(), []unifi.Client{clLoop})
	if len(profiles) != 1 || !profiles[0].HasPort(port) {
		t.Fatalf("expected FingerprintAll to probe allowed IPv6 ::1 on port %d, got %+v", port, profiles)
	}
}
