// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/karalabe/uniblue/internal/unifi"
)

func TestMDNSForgedSRVCannotRewriteAuthoritativeSinkOrInheritAuthority(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	cache := NewDiscoveryCache()

	// Genuine printer 192.168.1.20 announces its own raw print port 9100.
	genuine := buildMDNSTestPacket("_pdl-datastream._tcp", "OfficePrinter", "printer.local", 9100, 120, []byte{192, 168, 1, 20}, nil, nil)
	cache.IngestMDNSPacket(genuine, "192.168.1.20", "eth0", "LAN", now)

	// Attacker 192.168.1.66 attempts to overwrite the printer's SRV port to 23 (Telnet).
	forged := buildMDNSTestPacket("_pdl-datastream._tcp", "OfficePrinter", "printer.local", 23, 120, []byte{192, 168, 1, 20}, nil, nil)
	cache.IngestMDNSPacket(forged, "192.168.1.66", "eth0", "LAN", now)

	snap := cache.Snapshot(now)
	if _, ok := snap.RawPrintIPs["192.168.1.20"][9100]; !ok {
		t.Fatalf("expected genuine printer port 9100 to remain protected: %+v", snap.RawPrintIPs)
	}
	if _, poisoned := snap.RawPrintIPs["192.168.1.20"][23]; poisoned {
		t.Fatalf("forged SRV must not overwrite authoritative printer port to 23: %+v", snap.RawPrintIPs)
	}

	// Genuine Zigbee coordinator 192.168.1.30 announces its own bridge port 6638.
	coord := buildMDNSTestPacket("_slzb-06._tcp", "SLZB-06", "slzb.local", 6638, 120, []byte{192, 168, 1, 30}, nil, nil)
	cache.IngestMDNSPacket(coord, "192.168.1.30", "eth0", "LAN", now)

	// Attacker tries to move the coordinator's SRV to port 80 so 6638 loses protection.
	forgedCoord := buildMDNSTestPacket("_slzb-06._tcp", "SLZB-06", "slzb.local", 80, 120, []byte{192, 168, 1, 30}, nil, nil)
	cache.IngestMDNSPacket(forgedCoord, "192.168.1.66", "eth0", "LAN", now)

	snap = cache.Snapshot(now)
	if _, ok := snap.RawPrintIPs["192.168.1.30"][6638]; !ok {
		t.Fatalf("expected genuine coordinator bridge port 6638 to stay protected: %+v", snap.RawPrintIPs)
	}
	if _, poisoned := snap.RawPrintIPs["192.168.1.30"][80]; poisoned {
		t.Fatalf("forged SRV must not move coordinator guard to port 80: %+v", snap.RawPrintIPs)
	}
}

func TestMDNSReflectedCustomSerialBridgeZeroByteAndRiskyPortsNotHidden(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	cache := NewDiscoveryCache()
	cache.SetTrustedReflectors([]string{"192.168.1.1"})

	// Gateway reflects a Zigbee coordinator on a user-configured custom bridge port 7777.
	customCoord := buildMDNSTestPacket("_slzb-06._tcp", "slzb-custom", "slzb-custom.local", 7777, 120, []byte{192, 168, 20, 44}, nil, nil)
	cache.IngestMDNSPacket(customCoord, "192.168.1.1", "eth0", "IoT", now)

	// Forged reflected serial adverts must still NOT hide well-known risky service ports.
	for _, p := range []uint16{22, 445, 2375, 3389, 5900, 6379, 8080} {
		pkt := buildMDNSTestPacket("_slzb-06._tcp", fmt.Sprintf("spoof-%d", p), "nas.local", p, 120, []byte{192, 168, 1, 10}, nil, nil)
		cache.IngestMDNSPacket(pkt, "192.168.1.66", "eth0", "LAN", now)
	}

	snap := cache.Snapshot(now)
	if _, ok := snap.RawPrintIPs["192.168.20.44"][7777]; !ok {
		t.Fatalf("reflected coordinator on custom port 7777 must stay zero-byte protected: %+v", snap.RawPrintIPs)
	}
	for _, svc := range snap.MDNS["192.168.20.44"] {
		if !svc.Reflected || !svc.TrustedReflector {
			t.Fatalf("expected gateway-reflected service to carry Reflected=true and TrustedReflector=true, got %+v", svc)
		}
	}
	for _, svc := range snap.MDNS["192.168.1.10"] {
		if svc.TrustedReflector {
			t.Fatalf("non-gateway responder must not set TrustedReflector=true: %+v", svc)
		}
	}
	victimHP := HostProfile{
		Client:       unifi.Client{IP: "192.168.1.10"},
		MDNSServices: snap.MDNS["192.168.1.10"],
	}
	for _, p := range []int{22, 445, 2375, 3389, 5900, 6379, 8080} {
		if _, poisoned := snap.RawPrintIPs["192.168.1.10"][p]; poisoned {
			t.Fatalf("forged reflected serial advert hid risky port %d", p)
		}
		if victimHP.IsRawPrintPort(p) {
			t.Fatalf("IsRawPrintPort(%d) must be false for forged reflected advert", p)
		}
	}
}

func TestMDNSGatewayReflectorPreservesTwoHundredServices(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	cache := NewDiscoveryCache()
	cache.SetTrustedReflectors([]string{"192.168.1.1"})

	for i := 1; i <= 100; i++ {
		ip := []byte{192, 168, 20, byte(i)}
		host := fmt.Sprintf("iot-%03d.local", i)
		p1 := buildMDNSTestPacket("_http._tcp", fmt.Sprintf("iot-http-%03d", i), host, 80, 120, ip, nil, nil)
		p2 := buildMDNSTestPacket("_esphomelib._tcp", fmt.Sprintf("iot-esp-%03d", i), host, 6053, 120, ip, nil, nil)
		cache.IngestMDNSPacket(p1, "192.168.1.1", "eth0", "IoT", now)
		cache.IngestMDNSPacket(p2, "192.168.1.1", "eth0", "IoT", now)
	}

	snap := cache.Snapshot(now)
	total := 0
	for i := 1; i <= 100; i++ {
		total += len(snap.MDNS[fmt.Sprintf("192.168.20.%d", i)])
	}
	if total != 200 {
		t.Fatalf("expected gateway reflector to preserve all 200 services across 100 devices, got %d", total)
	}
}

func TestMDNSAttackerFirstDoesNotSuppressReflectedVictimOrCoordinator(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	cache := NewDiscoveryCache()
	cache.SetTrustedReflectors([]string{"192.168.1.1"})

	// Single attacker tries to fill victim 192.168.20.40's per-target quota first.
	for i := 0; i < 80; i++ {
		pkt := buildMDNSTestPacket("_http._tcp", fmt.Sprintf("junk-%02d", i), fmt.Sprintf("junk-%02d.local", i), uint16(10000+i), 120, []byte{192, 168, 20, 40}, nil, nil)
		cache.IngestMDNSPacket(pkt, "192.168.1.66", "eth0", "IoT", now)
	}
	// Multiple spoofed attackers also try to exhaust all 64 slots on 192.168.20.40.
	for s := 1; s <= 10; s++ {
		src := fmt.Sprintf("192.168.1.%d", 100+s)
		for i := 0; i < 16; i++ {
			pkt := buildMDNSTestPacket("_http._tcp", fmt.Sprintf("flood-%d-%d", s, i), fmt.Sprintf("f-%d-%d.local", s, i), uint16(12000+i), 120, []byte{192, 168, 20, 40}, nil, nil)
			cache.IngestMDNSPacket(pkt, src, "eth0", "IoT", now)
		}
	}

	// Genuine gateway reflector arrives AFTER the flood with the real SLZB-06 coordinator.
	coord := buildMDNSTestPacket("_slzb-06._tcp", "real-slzb", "real-slzb.local", 6638, 120, []byte{192, 168, 20, 40}, nil, nil)
	cache.IngestMDNSPacket(coord, "192.168.1.1", "eth0", "IoT", now)

	snap := cache.Snapshot(now)
	if _, ok := snap.RawPrintIPs["192.168.20.40"][6638]; !ok {
		t.Fatalf("reflected coordinator guard on 6638 was suppressed by attacker-first flood: %+v", snap.RawPrintIPs["192.168.20.40"])
	}
}

func TestMDNS150SourceFloodEvictionCompletesQuickly(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	cache := NewDiscoveryCache()

	// Pre-build 150 distinct spoofed sources sending 64 records each (9,600 inserts,
	// well past the 4096 global cap so eviction runs continuously).
	start := time.Now()
	for s := 1; s <= 150; s++ {
		src := net.IPv4(10, 99, byte(s/250), byte(s%250+1)).String()
		for i := 0; i < 64; i++ {
			target := []byte{10, 88, byte(s % 250), byte(i + 1)}
			pkt := buildMDNSTestPacket("_http._tcp", fmt.Sprintf("s%d-i%d", s, i), fmt.Sprintf("h%d-%d.local", s, i), uint16(20000+i), 120, target, nil, nil)
			cache.IngestMDNSPacket(pkt, src, "eth0", "LAN", now)
		}
	}
	// Genuine device answers after the flood.
	realPkt := buildMDNSTestPacket("_smb._tcp", "GenuineNAS", "nas.local", 445, 120, []byte{192, 168, 1, 25}, nil, nil)
	cache.IngestMDNSPacket(realPkt, "192.168.1.25", "eth0", "LAN", now)
	elapsed := time.Since(start)

	// Indexed O(1) eviction should process 9,600 packets in well under 1s (even under -race).
	if elapsed > 2*time.Second {
		t.Fatalf("150-source flood took %v (expected indexed O(1) eviction well below 2s)", elapsed)
	}
	snap := cache.Snapshot(now)
	found := false
	for _, svc := range snap.MDNS["192.168.1.25"] {
		if svc.Type == "_smb._tcp" && svc.Instance == "GenuineNAS" && !svc.Reflected {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("genuine host after 150-source flood was lost: %+v", snap.MDNS["192.168.1.25"])
	}
}

func TestSinkPortTrustByResponder(t *testing.T) {
	const target, gateway, neighbor = "192.168.20.10", "192.168.1.1", "192.168.1.66"
	for _, tc := range []struct {
		service    string
		ports      []int
		trustRelay bool
	}{
		{"_slzb-06._tcp", []int{1880, 5555, 8545, 8551, 8888, 9222, 9229, 16992, 59777}, false},
		{"_slzb-06._tcp", []int{6638, 6639, 20108, 7777}, true},
		{"_printer._tcp", []int{9101, 9107}, true},
		{"_pdl-datastream._tcp", []int{8888}, false},
	} {
		for _, port := range tc.ports {
			for _, sender := range []string{target, gateway, neighbor} {
				cache := NewDiscoveryCache()
				cache.SetTrustedReflectors([]string{gateway})
				now := time.Now()
				packet := buildMDNSTestPacket(tc.service, "device", "device.local", uint16(port), 60, net.ParseIP(target).To4(), nil, nil)
				cache.IngestMDNSPacket(packet, sender, "eth0", "LAN", now)
				snap := cache.Snapshot(now)
				hp := HostProfile{Client: unifi.Client{IP: target}, MDNSServices: snap.MDNS[target]}
				want := sender == target || (sender == gateway && tc.trustRelay)
				_, protected := snap.RawPrintIPs[target][port]
				if protected != want || hp.IsRawPrintPort(port) != want {
					t.Fatalf("%s port %d from %s: snapshot=%t profile=%t, want %t", tc.service, port, sender, protected, hp.IsRawPrintPort(port), want)
				}
			}
		}
	}
}
