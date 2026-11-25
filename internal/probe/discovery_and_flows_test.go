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
	"math/big"
	"net"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/karalabe/uniblue/internal/unifi"
)

func buildMDNSTestPacket(svcType, instance, targetHost string, port uint16, ttl uint32, ipv4 []byte, ipv6 []byte, txt []string) []byte {
	var pkt bytes.Buffer
	anCount := uint16(3)
	if len(ipv4) == 4 {
		anCount++
	}
	if len(ipv6) == 16 {
		anCount++
	}
	// Header: response flags 0x8400
	hdr := []byte{0x00, 0x00, 0x84, 0x00, 0x00, 0x00, byte(anCount >> 8), byte(anCount), 0x00, 0x00, 0x00, 0x00}
	pkt.Write(hdr)

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

	fullInst := instance + "." + svcType + ".local"

	// 1. PTR
	writeName(&pkt, svcType+".local")
	var ptrTarget bytes.Buffer
	writeName(&ptrTarget, fullInst)
	_ = binary.Write(&pkt, binary.BigEndian, uint16(12))
	_ = binary.Write(&pkt, binary.BigEndian, uint16(1))
	_ = binary.Write(&pkt, binary.BigEndian, ttl)
	_ = binary.Write(&pkt, binary.BigEndian, uint16(ptrTarget.Len()))
	pkt.Write(ptrTarget.Bytes())

	// 2. SRV
	writeName(&pkt, fullInst)
	var srvData bytes.Buffer
	_ = binary.Write(&srvData, binary.BigEndian, uint16(0))
	_ = binary.Write(&srvData, binary.BigEndian, uint16(0))
	_ = binary.Write(&srvData, binary.BigEndian, port)
	writeName(&srvData, targetHost)
	_ = binary.Write(&pkt, binary.BigEndian, uint16(33))
	_ = binary.Write(&pkt, binary.BigEndian, uint16(1))
	_ = binary.Write(&pkt, binary.BigEndian, ttl)
	_ = binary.Write(&pkt, binary.BigEndian, uint16(srvData.Len()))
	pkt.Write(srvData.Bytes())

	// 3. TXT
	writeName(&pkt, fullInst)
	var txtData bytes.Buffer
	for _, s := range txt {
		txtData.WriteByte(byte(len(s)))
		txtData.WriteString(s)
	}
	_ = binary.Write(&pkt, binary.BigEndian, uint16(16))
	_ = binary.Write(&pkt, binary.BigEndian, uint16(1))
	_ = binary.Write(&pkt, binary.BigEndian, ttl)
	_ = binary.Write(&pkt, binary.BigEndian, uint16(txtData.Len()))
	pkt.Write(txtData.Bytes())

	// 4. A
	if len(ipv4) == 4 {
		writeName(&pkt, targetHost)
		_ = binary.Write(&pkt, binary.BigEndian, uint16(1))
		_ = binary.Write(&pkt, binary.BigEndian, uint16(1))
		_ = binary.Write(&pkt, binary.BigEndian, ttl)
		_ = binary.Write(&pkt, binary.BigEndian, uint16(4))
		pkt.Write(ipv4)
	}
	// 5. AAAA
	if len(ipv6) == 16 {
		writeName(&pkt, targetHost)
		_ = binary.Write(&pkt, binary.BigEndian, uint16(28))
		_ = binary.Write(&pkt, binary.BigEndian, uint16(1))
		_ = binary.Write(&pkt, binary.BigEndian, ttl)
		_ = binary.Write(&pkt, binary.BigEndian, uint16(16))
		pkt.Write(ipv6)
	}
	return pkt.Bytes()
}

// TestDiscoveryCache_MatterUDPException_IPv6_Reflection_TTLWithdrawal verifies
// Matter _matter._tcp UDP transport handling, IPv6 AAAA assembly, mDNS reflector
// attribution, RFC 6762 TTL=0 withdrawal, TXT key replacement, and TTL expiry.
func TestDiscoveryCache_MatterUDPException_IPv6_Reflection_TTLWithdrawal(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	cache := NewDiscoveryCache()

	// 1. Matter operational (_matter._tcp) with IPv6 AAAA only must stay UDP and never enter TCP PortsByIP.
	ipv6Bytes := net.ParseIP("fd00:1::10").To16()
	matterPkt := buildMDNSTestPacket("_matter._tcp", "ABCDEF0123456789-0000000000000001", "matter-lamp.local", 5540, 120, nil, ipv6Bytes, []string{"sii=500", "sai=300"})
	cache.IngestMDNSPacket(matterPkt, "fd00:1::10", "eth0.20", "IoT", now)

	// 2. Reflected IPPS printer announced by gateway reflector 10.0.50.1 on Guest VLAN for printer 10.0.1.30.
	printerPkt := buildMDNSTestPacket("_ipps._tcp", "OfficePrinter", "printer.local", 631, 60, []byte{10, 0, 1, 30}, nil, []string{"ty=LaserJet", "tls=1.2"})
	cache.IngestMDNSPacket(printerPkt, "10.0.50.1", "eth0.50", "Guest", now)

	// 3. Thread Border Router (_meshcop._udp)
	tbrPkt := buildMDNSTestPacket("_meshcop._udp", "OpenThread-BR", "otbr.local", 49155, 120, []byte{10, 0, 20, 5}, ipv6Bytes, []string{"vn=OpenThread", "tv=1.3.0"})
	cache.IngestMDNSPacket(tbrPkt, "10.0.20.5", "eth0.20", "IoT", now)

	snap := cache.Snapshot(now)

	// Verify Matter operational IPv6 record has Transport=="udp", AddressFamily=="ipv6", and zero TCP ports planned.
	matterSvcs := snap.MDNS["fd00:1::10"]
	foundMatter := false
	for _, s := range matterSvcs {
		if s.Type == "_matter._tcp" {
			foundMatter = true
			if s.Transport != "udp" || s.AddressFamily != "ipv6" || s.ObserverVLAN != "IoT" {
				t.Fatalf("unexpected Matter operational service metadata: %+v", s)
			}
		}
	}
	if !foundMatter {
		t.Fatalf("expected Matter operational service on IPv6 address, got %+v", snap.MDNS)
	}
	if len(snap.PortsByIP["fd00:1::10"]) != 0 {
		t.Fatalf("Matter _matter._tcp MUST NOT schedule TCP dials, got PortsByIP=%v", snap.PortsByIP["fd00:1::10"])
	}

	// Verify reflected printer is attributed to 10.0.1.30 (NOT reflector 10.0.50.1) with Reflected=true.
	if len(snap.MDNS["10.0.50.1"]) != 0 {
		t.Fatalf("reflected service must not be assigned to reflector IP 10.0.50.1")
	}
	prnSvcs := snap.MDNS["10.0.1.30"]
	if len(prnSvcs) != 1 || !prnSvcs[0].Reflected || prnSvcs[0].ObserverVLAN != "Guest" {
		t.Fatalf("expected reflected printer service on 10.0.1.30 with ObserverVLAN=Guest, got %+v", prnSvcs)
	}

	// Verify RFC 6762 TTL=0 goodbye packet immediately withdraws the printer service.
	byePkt := buildMDNSTestPacket("_ipps._tcp", "OfficePrinter", "printer.local", 631, 0, []byte{10, 0, 1, 30}, nil, nil)
	cache.IngestMDNSPacket(byePkt, "10.0.50.1", "eth0.50", "Guest", now.Add(5*time.Second))
	snapAfterBye := cache.Snapshot(now.Add(5 * time.Second))
	if len(snapAfterBye.MDNS["10.0.1.30"]) != 0 {
		t.Fatalf("expected TTL=0 goodbye packet to withdraw service, still got %+v", snapAfterBye.MDNS["10.0.1.30"])
	}

	// Verify TXT replacement: cm=0 refresh replaces cm=1 without leaving stale values.
	commOpen := buildMDNSTestPacket("_matterc._udp", "LAMP01", "lamp01.local", 5540, 120, []byte{10, 0, 20, 44}, nil, []string{"cm=1", "d=1234"})
	cache.IngestMDNSPacket(commOpen, "10.0.20.44", "eth0.20", "IoT", now)
	commClosed := buildMDNSTestPacket("_matterc._udp", "LAMP01", "lamp01.local", 5540, 120, []byte{10, 0, 20, 44}, nil, []string{"cm=0", "d=1234"})
	cache.IngestMDNSPacket(commClosed, "10.0.20.44", "eth0.20", "IoT", now.Add(2*time.Second))
	snapTXT := cache.Snapshot(now.Add(2 * time.Second))
	for _, s := range snapTXT.MDNS["10.0.20.44"] {
		for _, kv := range s.TXT {
			if kv == "cm=1" {
				t.Fatalf("stale TXT cm=1 survived refresh to cm=0: %+v", s.TXT)
			}
		}
	}

	// Verify unresolved SRV target host is never falsely attributed to reflector IP.
	unresolvedPkt := buildMDNSTestPacket("_ipp._tcp", "GhostPrinter", "unknown-printer.local", 631, 60, nil, nil, []string{"ty=Ghost"})
	cache.IngestMDNSPacket(unresolvedPkt, "10.0.50.1", "eth0.50", "Guest", now)
	snapUnres := cache.Snapshot(now)
	if len(snapUnres.MDNS["10.0.50.1"]) != 0 {
		t.Fatalf("unresolved SRV target must not be assigned to reflector 10.0.50.1, got %+v", snapUnres.MDNS["10.0.50.1"])
	}

	// Verify TTL expiry removes Matter after 121 seconds.
	snapExpired := cache.Snapshot(now.Add(125 * time.Second))
	if len(snapExpired.MDNS["fd00:1::10"]) != 0 {
		t.Fatalf("expected expired mDNS records to drop after TTL, got %+v", snapExpired.MDNS["fd00:1::10"])
	}
}

// TestRawPrinterReceivesZeroApplicationBytesAtSocketBoundary verifies at the
// TCP socket boundary that Fingerprinter writes zero application bytes to raw print sinks.
func TestRawPrinterReceivesZeroApplicationBytesAtSocketBoundary(t *testing.T) {
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
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
				buf := make([]byte, 512)
				n, _ := c.Read(buf)
				if n > 0 {
					bytesRead.Add(int64(n))
				}
			}(conn)
		}
	}()

	// Simulate an advertised _pdl-datastream._tcp raw printer on a non-standard port.
	fp := NewFingerprinter([]int{port}, 1, 500*time.Millisecond, nil)
	fp.skipDiscovery = true
	fp.discovery = &LANDiscovery{
		RawPrintIPs: map[string]map[int]struct{}{
			"127.0.0.1": {port: {}},
		},
	}

	profiles := fp.FingerprintAll(context.Background(), []unifi.Client{{IP: "127.0.0.1", Name: "Raw-Printer"}})
	time.Sleep(100 * time.Millisecond)

	if len(profiles) != 1 || !profiles[0].HasPort(port) {
		t.Fatalf("expected connect-only detection of raw printer port %d, got %+v", port, profiles)
	}
	if !slices.Equal(profiles[0].RawPrintPorts, []int{port}) || !slices.Equal(profiles[0].ConnectOnlyPorts, []int{port}) {
		t.Fatalf("raw print ports %v, connect-only ports %v, want [%d]", profiles[0].RawPrintPorts, profiles[0].ConnectOnlyPorts, port)
	}
	if got := bytesRead.Load(); got != 0 {
		t.Fatalf("SAFETY VIOLATION: fake raw printer received %d application bytes (must be strictly 0)", got)
	}
}

// TestNervaMatrixAudit_AlternatePorts_AndTLSUnknownApp verifies Nerva registry
// introspection, alternate-port SSH detection, raw TLS unknown-app preservation,
// and separation of hosted passive services from outbound CDN dependencies.
func TestNervaMatrixAudit_AlternatePorts_AndTLSUnknownApp(t *testing.T) {
	// 1. Audit pinned Nerva registry counts (must report TCP/TLS + UDP/SCTP recognizers).
	entries := AuditPinnedNervaPlugins()
	if len(entries) < 100 {
		t.Fatalf("expected >= 100 pinned Nerva plugins, got %d", len(entries))
	}

	// 2. Start local mock SSH on an alternate port (not 22) and a raw TLS-only server
	// speaking an unknown custom application protocol.
	sshLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen ssh: %v", err)
	}
	defer sshLn.Close()
	_, sshPortStr, _ := net.SplitHostPort(sshLn.Addr().String())
	sshPort, _ := strconv.Atoi(sshPortStr)
	go func() {
		for {
			c, err := sshLn.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3\r\n"))
			_ = c.Close()
		}
	}()

	// Self-signed TLS listener that completes TLS handshake then closes (unknown app behind TLS).
	tlsCert := generateTestSelfSignedCert(t)
	tlsLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{tlsCert}})
	if err != nil {
		t.Fatalf("listen tls: %v", err)
	}
	defer tlsLn.Close()
	_, tlsPortStr, _ := net.SplitHostPort(tlsLn.Addr().String())
	tlsPort, _ := strconv.Atoi(tlsPortStr)
	go func() {
		for {
			c, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(400 * time.Millisecond))
				buf := make([]byte, 64)
				_, _ = conn.Read(buf)
			}(c)
		}
	}()

	fp := NewFingerprinter([]int{sshPort, tlsPort}, 1, 1500*time.Millisecond, nil)
	fp.skipDiscovery = true
	profiles := fp.FingerprintAll(context.Background(), []unifi.Client{{IP: "127.0.0.1", Name: "sim-host"}})
	if len(profiles) != 1 {
		t.Fatalf("expected 1 profile, got %d", len(profiles))
	}

	// Verify passive flows separate hosted UDP services from outbound CDN/encrypted dependencies.
	now := time.Now().UTC()
	ApplyPassiveFlows(profiles, []PassiveFlowRecord{
		{Direction: "hosted", LocalIP: "127.0.0.1", Port: 53, Transport: "udp", Protocol: "dns", Source: "zeek", Observer: "Core", ObservedAt: &now},
		{Direction: "hosted", LocalIP: "127.0.0.1", Port: 8443, Transport: "udp", Protocol: "quic", Source: "zeek", Observer: "Core", ObservedAt: &now},
		{Direction: "outbound", LocalIP: "127.0.0.1", RemoteIP: "13.32.10.5", Port: 443, Transport: "tcp", Protocol: "tls", SharedCDN: true, Source: "unifi-flows", Observer: "Gateway", ObservedAt: &now},
		{Direction: "outbound", LocalIP: "127.0.0.1", RemoteIP: "198.51.100.44", Port: 443, Transport: "udp", Protocol: "quic", ECHPresent: true, Source: "ipfix", Observer: "Gateway", ObservedAt: &now},
	})

	hp := profiles[0]
	foundAltSSH := false
	foundAltTLS := false
	foundHostedUDP := false
	foundQUICUnknown := false
	for _, svc := range hp.Services {
		if svc.Port == sshPort && svc.Transport == "tcp" && svc.Protocol == "ssh" && svc.State == ServiceStateObservedProtocol {
			foundAltSSH = true
		}
		if svc.Port == tlsPort && svc.Transport == "tcp" && svc.Protocol == "tls" && svc.State == ServiceStateTLSUnknownApp {
			foundAltTLS = true
		}
		if svc.Transport == "udp" && svc.Port == 53 && svc.Protocol == "dns" && svc.State == ServiceStateObservedProtocol {
			foundHostedUDP = true
		}
		if svc.Transport == "udp" && svc.Port == 8443 && svc.State == ServiceStateTLSUnknownApp {
			foundQUICUnknown = true
		}
		if svc.Port == 443 {
			t.Fatalf("outbound connection to port 443 must NEVER create a locally hosted 443 service: %+v", svc)
		}
	}
	if !foundAltSSH {
		t.Fatalf("expected alternate-port SSH listener on :%d to resolve as observed-protocol ssh, got services=%+v", sshPort, hp.Services)
	}
	if !foundAltTLS {
		t.Fatalf("expected alternate-port raw TLS listener on :%d to resolve as tls-unknown-app, got services=%+v", tlsPort, hp.Services)
	}
	if !foundHostedUDP || !foundQUICUnknown {
		t.Fatalf("expected hosted UDP DNS (%v) and QUIC tls-unknown-app (%v), got services=%+v", foundHostedUDP, foundQUICUnknown, hp.Services)
	}
	if len(hp.OutboundDependencies) != 2 {
		t.Fatalf("expected 2 outbound dependencies, got %+v", hp.OutboundDependencies)
	}
	if hp.OutboundDependencies[0].AttributionLevel != AttributionHostingRangeOnly ||
		hp.OutboundDependencies[1].AttributionLevel != AttributionOpaqueEncrypted {
		t.Fatalf("unexpected outbound attribution levels: %+v", hp.OutboundDependencies)
	}

	cov := ComputeServiceCoverage(profiles)
	if cov.TotalObservedEndpoints < 4 || cov.OutboundDependencies != 2 || cov.PinnedNervaTCPCapable < 100 || cov.PinnedNervaUDPOnly < 20 {
		t.Fatalf("unexpected service coverage metrics: %+v", cov)
	}
}

// TestBridgeInventoryParsers_Zigbee2MQTT_And_ZWaveJS verifies parsing of
// Zigbee2MQTT and Z-Wave JS exports into normalized non-IP child device records.
func TestBridgeInventoryParsers_Zigbee2MQTT_And_ZWaveJS(t *testing.T) {
	z2m := `[
		{"ieee_address":"0x00124b0001","type":"Coordinator","friendly_name":"Coordinator"},
		{"ieee_address":"0x00158d0002","type":"EndDevice","friendly_name":"Hallway Motion","power_source":"Battery","interview_completed":true,"software_build_id":"20230501","definition":{"model":"RTCGQ11LM","vendor":"Aqara","description":"Aqara motion sensor"}}
	]`
	zChildren, err := ParseBridgeInventory([]byte(z2m), BridgeInventorySpec{Format: "zigbee2mqtt", ParentIP: "10.0.20.2"})
	if err != nil || len(zChildren) != 1 {
		t.Fatalf("ParseBridgeInventory(zigbee2mqtt): err=%v children=%+v", err, zChildren)
	}
	if zChildren[0].Vendor != "Aqara" || zChildren[0].Model != "RTCGQ11LM" || !zChildren[0].Sleeping || zChildren[0].DirectLANReachability != "non-ip-radio" {
		t.Fatalf("unexpected Zigbee child: %+v", zChildren[0])
	}

	zwave := `[
		{"nodeId":1,"name":"Controller","ready":true,"isListening":true},
		{"nodeId":7,"name":"Front Door Lock","ready":false,"isListening":false,"firmwareVersion":"1.4.2","deviceConfig":{"manufacturer":"Schlage","label":"BE469ZP","description":"Smart Deadbolt"}}
	]`
	zwChildren, err := ParseBridgeInventory([]byte(zwave), BridgeInventorySpec{Format: "zwave-js", ParentIP: "10.0.20.2"})
	if err != nil || len(zwChildren) != 1 {
		t.Fatalf("ParseBridgeInventory(zwave-js): err=%v children=%+v", err, zwChildren)
	}
	if zwChildren[0].Vendor != "Schlage" || zwChildren[0].InterviewComplete == nil || *zwChildren[0].InterviewComplete != false || !zwChildren[0].Sleeping {
		t.Fatalf("unexpected Z-Wave child: %+v", zwChildren[0])
	}
}

func generateTestSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// TestIPv6OnlyProbingDualStackFlowsAndDeviceBridgeChildren verifies that
// IPv6-only clients produce active profiles, dual-stack IPv6 passive flows
// match their parent host profile, and bridge children owned by a UniFi
// infrastructure device (such as a gateway running Protect) are matched.
func TestIPv6OnlyProbingDualStackFlowsAndDeviceBridgeChildren(t *testing.T) {
	// 1. IPv6-only client with a listening TCP port on [::1].
	ln6, err := net.Listen("tcp6", "[::1]:0")
	if err == nil {
		defer ln6.Close()
		port6 := ln6.Addr().(*net.TCPAddr).Port
		go func() {
			for {
				c, aerr := ln6.Accept()
				if aerr != nil {
					return
				}
				_ = c.Close()
			}
		}()

		fp := NewFingerprinter([]int{port6}, 1, 500*time.Millisecond, nil)
		fp.skipDiscovery = true
		profiles := fp.FingerprintAll(context.Background(), []unifi.Client{
			{MAC: "02:aa:bb:00:00:60", Name: "matter-v6-only", IPv6: []string{"::1"}},
		})
		if len(profiles) != 1 || !profiles[0].HasPort(port6) {
			t.Fatalf("expected IPv6-only client to produce profile with open port %d, got %+v", port6, profiles)
		}
	}

	// 2. Dual-stack client matches an imported passive flow using its IPv6 address
	// AND preserves both IPv4 and IPv6 services on the same (transport, port).
	dualProfiles := []HostProfile{
		{
			Client: unifi.Client{
				MAC:  "02:aa:bb:00:00:61",
				IP:   "192.0.2.61",
				IPv6: []string{"2001:db8:0:0::61"},
				Name: "dual-stack-host",
			},
		},
	}
	ApplyPassiveFlows(dualProfiles, []PassiveFlowRecord{
		{Direction: "hosted", LocalIP: "192.0.2.61", Port: 5540, Transport: "udp", Protocol: "matter", Source: "zeek"},
		{Direction: "hosted", LocalIP: "2001:db8::61", Port: 5540, Transport: "udp", Protocol: "matter", Source: "zeek"},
	})
	if len(dualProfiles[0].Services) != 2 {
		t.Fatalf("expected dual-stack host to retain BOTH ipv4 and ipv6 services on udp/5540, got %+v", dualProfiles[0].Services)
	}
	if dualProfiles[0].Services[0].AddressFamily != "ipv4" || dualProfiles[0].Services[1].AddressFamily != "ipv6" {
		t.Fatalf("expected [ipv4, ipv6] address families, got %+v", dualProfiles[0].Services)
	}

	// 3. Bridge children owned by a UniFi infrastructure device (e.g. UDM Pro Protect).
	devs := []unifi.Device{
		{MAC: "aa:00:00:00:00:01", IP: "192.0.2.1", Name: "Home Gateway", Model: "UDM-Pro", Type: "udm"},
	}
	matched := MatchDeviceBridgeChildren(devs, []ChildDevice{
		{ID: "protect-cam-1", Name: "Porch Doorbell", ParentMAC: "aa:00:00:00:00:01", Category: "camera"},
	})
	if len(matched["aa:00:00:00:00:01"]) != 1 || matched["aa:00:00:00:00:01"][0].Name != "Porch Doorbell" {
		t.Fatalf("expected Protect child to match gateway device, got %+v", matched)
	}
}
