// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checks

import (
	"context"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	builtinchecks "github.com/karalabe/uniblue/checks"
	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/unifi"
)

// TestNewChecksAddZeroGlobalPortsAndZeroConnectionsToUnrelatedHosts verifies
// that discovery-only, passive, and UDP checks never expand the global TCP sweep
// and make zero connections to unrelated hosts.
func TestNewChecksAddZeroGlobalPortsAndZeroConnectionsToUnrelatedHosts(t *testing.T) {
	all, err := LoadFromFS(builtinchecks.BuiltinFS)
	if err != nil {
		t.Fatalf("LoadFromFS: %v", err)
	}

	var scopedChecks []*Check
	for _, c := range all {
		if c.Preconditions.DiscoveryOnly || c.Probe.Type == "observe" || isNonTCPProbe(c.Probe.Type) {
			scopedChecks = append(scopedChecks, c)
		}
	}
	if len(scopedChecks) == 0 {
		t.Fatal("expected discovery-only / passive checks")
	}

	// 1. Planner invariant: discovery-only, passive, and UDP-only checks must add
	// ZERO ports to the global TCP baseline sweep.
	base := []int{80, 443}
	planned := PlanGlobalPorts(base, scopedChecks)
	if len(planned) != 2 || planned[0] != 80 || planned[1] != 443 {
		t.Fatalf("scoped checks must add ZERO global TCP ports, got %v", planned)
	}

	// 2. Socket-level invariant: running all scoped checks against an unrelated host
	// with a listening TCP socket must make ZERO connections to that host.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	var connCount atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			connCount.Add(1)
			_ = c.Close()
		}
	}()

	unrelated := probe.HostProfile{
		Client:    unifi.Client{IP: "127.0.0.1", Name: "regular-laptop"},
		OpenPorts: []int{port},
	}
	r := NewRunner(scopedChecks, 1)
	if got := r.RunHost(context.Background(), unrelated); len(got) != 0 {
		t.Fatalf("expected 0 findings on unrelated host, got %+v", got)
	}
	time.Sleep(30 * time.Millisecond)
	if n := connCount.Load(); n != 0 {
		t.Fatalf("scoped checks made %d unexpected TCP connection(s) to unrelated host", n)
	}
}

// TestFalsePositiveGuards_MatterCommissioning_DoorBirdVsAxis_RawPrinter verifies
// that Matter cm=0 extended discovery does not fire commissioning alerts, DoorBird
// OUI prevents Axis misattribution, and raw print sinks receive zero probe bytes.
func TestFalsePositiveGuards_MatterCommissioning_DoorBirdVsAxis_RawPrinter(t *testing.T) {
	all, err := LoadFromFS(builtinchecks.BuiltinFS)
	if err != nil {
		t.Fatalf("LoadFromFS: %v", err)
	}
	r := NewRunner(all, 1)

	// 1. Matter cm=1 (active commissioning) fires UB-2026-0020 at Info severity;
	// cm=0 (extended discovery outside commissioning window) must not fire.
	matterActive := probe.HostProfile{
		Client:       unifi.Client{IP: "192.0.2.10"},
		MDNSServices: []probe.MDNSService{{Type: "_matterc._udp", Port: 5540, TXT: []string{"cm=1", "d=3840"}}},
	}
	matterExtended := probe.HostProfile{
		Client:       unifi.Client{IP: "192.0.2.11"},
		MDNSServices: []probe.MDNSService{{Type: "_matterc._udp", Port: 5540, TXT: []string{"cm=0", "d=3840"}}},
	}
	gotActive := r.RunHost(context.Background(), matterActive)
	if len(gotActive) != 1 || gotActive[0].CheckID != "UB-2026-0020" || gotActive[0].BaseSeverity != SeverityInfo {
		t.Fatalf("expected Info UB-2026-0020 on cm=1 Matter device, got %+v", gotActive)
	}
	if got := r.RunHost(context.Background(), matterExtended); len(got) != 0 {
		t.Fatalf("Matter cm=0 extended discovery must NOT fire commissioning check, got %+v", got)
	}

	// 2. DoorBird (_axis-video._tcp + real wire key macaddress=1c:ca:e3...) vs Axis camera.
	doorbird := probe.HostProfile{
		Client:       unifi.Client{IP: "192.0.2.12"},
		MDNSServices: []probe.MDNSService{{Type: "_axis-video._tcp", Port: 80, TXT: []string{"macaddress=1ccae3010203"}}},
	}
	axisCam := probe.HostProfile{
		Client:       unifi.Client{IP: "192.0.2.13"},
		MDNSServices: []probe.MDNSService{{Type: "_axis-video._tcp", Port: 80, TXT: []string{"macaddress=accc8e010203"}}},
	}
	if got := r.RunHost(context.Background(), doorbird); len(got) != 1 || got[0].CheckID != "UB-2026-0012" {
		t.Fatalf("expected DoorBird match UB-2026-0012 on macaddress=1ccae3..., got %+v", got)
	}
	if got := r.RunHost(context.Background(), axisCam); len(got) != 0 {
		t.Fatalf("Axis camera must NOT match DoorBird UB-2026-0012, got %+v", got)
	}

	// 3. Raw printer zero-byte guard in Runner: even if a raw print sink overlaps
	// an HTTP check port, Runner must not write any bytes to that socket.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	_, pStr, _ := net.SplitHostPort(ln.Addr().String())
	rawPort, _ := strconv.Atoi(pStr)
	var bytesWritten atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
				buf := make([]byte, 256)
				n, _ := conn.Read(buf)
				bytesWritten.Add(int64(n))
			}(c)
		}
	}()
	httpChk := &Check{
		ID:       "UB-2026-9999",
		Title:    "Test HTTP Probe",
		Safety:   "read-only",
		Severity: SeverityLow,
		Preconditions: Preconditions{
			PortsAny:      []int{rawPort},
			DiscoveryOnly: true,
		},
		Probe: ProbeSpec{Type: "http", Method: "GET", Path: "/", Scheme: "http"},
	}
	if err := httpChk.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	rawPrinter := probe.HostProfile{
		Client:        unifi.Client{IP: "127.0.0.1", Name: "Raw-Printer"},
		OpenPorts:     []int{rawPort},
		RawPrintPorts: []int{rawPort},
	}
	NewRunner([]*Check{httpChk}, 1).RunHost(context.Background(), rawPrinter)
	time.Sleep(50 * time.Millisecond)
	if n := bytesWritten.Load(); n != 0 {
		t.Fatalf("SAFETY VIOLATION: Runner sent %d bytes to raw print port %d", n, rawPort)
	}
}

// TestPropertyKeyedNervaDeduplicationPreservesIndependentFindings verifies that
// Nerva deduplication keys on security property so distinct findings on the same
// port (such as SMBv1 vs. SMB signing, or HTTP vs. expired TLS cert) both survive.
func TestPropertyKeyedNervaDeduplicationPreservesIndependentFindings(t *testing.T) {
	hp := probe.HostProfile{
		Client: unifi.Client{IP: "192.0.2.50", MAC: "aa:bb:cc:dd:ee:50"},
		Services: []probe.Service{
			{
				Port:      445,
				Transport: "tcp",
				Protocol:  "smb",
				Findings: []probe.ServiceFinding{
					{ID: "smb-v1-enabled", Severity: "high", Evidence: "SMBv1 negotiated"},
					{ID: "smb-signing-not-required", Severity: "medium", Evidence: "signing optional"},
				},
			},
			{
				Port:      443,
				Transport: "tcp",
				Protocol:  "https",
				Findings: []probe.ServiceFinding{
					{ID: "tls-weak-version-10", Severity: "medium", Evidence: "TLS 1.0"},
					{ID: "tls-weak-key", Severity: "medium", Evidence: "1024-bit RSA"},
				},
			},
		},
	}
	existing := []Finding{
		{CheckID: "UB-CUSTOM-SMBV1", Property: "smb-v1", Transport: "tcp", Client: hp.Client, Port: 445},
		{CheckID: "UB-0009", Property: "tls-protocol", Transport: "tcp", Client: hp.Client, Port: 443},
	}
	got := FindingsFromProfiles([]probe.HostProfile{hp}, existing)
	gotIDs := make(map[string]bool)
	for _, f := range got {
		gotIDs[f.CheckID] = true
	}
	if !gotIDs["NERVA-SMB-SIGNING-NOT-REQUIRED"] || !gotIDs["NERVA-TLS-WEAK-KEY"] || len(got) != 2 {
		t.Fatalf("expected smb-signing and tls-weak-key to survive dedup while suppressing smb-v1 and tls-10, got %+v", got)
	}
}
