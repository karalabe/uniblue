// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package classify

import (
	"testing"

	classifydata "github.com/karalabe/uniblue/classify"
	"github.com/karalabe/uniblue/internal/oui"
	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/unifi"
)

// TestClassifyDeterministicSignals verifies deterministic device classification
// across protocol/port proof, virtual MAC prefixes, IEEE OUIs, hostnames, and
// locally-administered randomized MAC addresses.
func TestClassifyDeterministicSignals(t *testing.T) {
	c, err := Load(classifydata.BuiltinFS, oui.New(t.TempDir()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	cases := []struct {
		name     string
		client   unifi.Client
		profile  *probe.HostProfile
		isWANWeb bool
		wantCat  Category
	}{
		{
			name:    "ipmi bmc",
			client:  unifi.Client{IP: "192.168.1.5", MAC: "d4:5d:64:00:00:01", OUI: "ASUSTek COMPUTER INC.", IsWired: true},
			profile: &probe.HostProfile{OpenPorts: []int{22, 443, 623}, HTTP: map[int]probe.HTTPBanner{443: {Title: "ASMB9-iKVM"}}},
			wantCat: CategoryBMC,
		},
		{
			name:    "nas server",
			client:  unifi.Client{IP: "192.168.1.2", MAC: "38:d5:47:00:00:01", OUI: "ASUSTek COMPUTER INC.", IsWired: true},
			profile: &probe.HostProfile{OpenPorts: []int{80, 443, 445, 2049}},
			wantCat: CategoryServer,
		},
		{
			name:    "qemu virtual machine",
			client:  unifi.Client{IP: "192.168.1.20", MAC: "52:54:00:aa:bb:cc", IsWired: true},
			wantCat: CategoryVM,
		},
		{
			name:     "wan reverse proxy",
			client:   unifi.Client{IP: "192.168.1.30", MAC: "02:44:55:11:22:33", IsWired: true},
			isWANWeb: true,
			wantCat:  CategoryNetService,
		},
		{
			name:    "dns appliance",
			client:  unifi.Client{IP: "192.168.1.31", MAC: "02:55:66:11:22:33", IsWired: true},
			profile: &probe.HostProfile{OpenPorts: []int{53, 80, 443}, HTTP: map[int]probe.HTTPBanner{80: {Title: "Pi-hole"}}},
			wantCat: CategoryNetService,
		},
		{
			name:    "esp32 3d printer beats generic silicon rule",
			client:  unifi.Client{IP: "192.168.1.40", MAC: "ec:64:c9:00:00:01", Hostname: "prusa-mk4", OUI: "Espressif Inc.", IsWired: false},
			wantCat: CategoryPrinter,
		},
		{
			name:    "unnamed esp32 falls back to iot",
			client:  unifi.Client{IP: "192.168.1.41", MAC: "ec:64:c9:00:00:02", OUI: "Espressif Inc.", IsWired: false},
			wantCat: CategoryIoT,
		},
		{
			name:    "irobot vacuum via vendor",
			client:  unifi.Client{IP: "192.168.1.42", MAC: "50:14:79:00:00:01", OUI: "iRobot Corporation", IsWired: false},
			wantCat: CategoryIoT,
		},
		{
			name:    "av receiver via vendor",
			client:  unifi.Client{IP: "192.168.1.43", MAC: "00:05:cd:00:00:01", OUI: "D&M Holdings Inc.", IsWired: true},
			wantCat: CategoryMedia,
		},
		{
			name:    "private wifi mac personal device",
			client:  unifi.Client{IP: "192.168.1.50", MAC: "02:aa:bb:00:00:01", IsWired: false},
			wantCat: CategoryPersonal,
		},
		{
			name:    "wired synthetic mac container",
			client:  unifi.Client{IP: "192.168.1.51", MAC: "a2:11:22:33:44:55", IsWired: true},
			wantCat: CategoryVM,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := c.ClassifyClient(tc.client, tc.profile, tc.isWANWeb)
			if got.Category != tc.wantCat {
				t.Fatalf("got category %q (role=%q, signals=%v), want %q", got.Category, got.Role, got.Signals, tc.wantCat)
			}
		})
	}
}

// TestClassifyPreservesHardwareIdentityOverServicesAndWAN verifies that specific
// hardware roles (printers with SMB, WAN-forwarded cameras, Hue/AirPlay mDNS
// receivers, SIP endpoints, hypervisors, and backup servers) are not overwritten
// by generic file-sharing ports or WAN web exposure flags.
func TestClassifyPreservesHardwareIdentityOverServicesAndWAN(t *testing.T) {
	c, err := Load(classifydata.BuiltinFS, oui.New(t.TempDir()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// 1. Multifunction IPPS printer with Scan-to-SMB (445) stays CategoryPrinter.
	prn := c.ClassifyClient(
		unifi.Client{IP: "192.0.2.20", MAC: "00:11:22:00:00:20", IsWired: true},
		&probe.HostProfile{
			OpenPorts:    []int{445, 631},
			MDNSServices: []probe.MDNSService{{Type: "_ipps._tcp", Port: 631}},
		},
		false,
	)
	if prn.Category != CategoryPrinter {
		t.Fatalf("IPPS+SMB printer classified as %q (%q), want %q", prn.Category, prn.Role, CategoryPrinter)
	}

	// 2. RTSP camera with a forwarded web port stays CategoryCamera (not Reverse Proxy).
	cam := c.ClassifyClient(
		unifi.Client{IP: "192.0.2.21", MAC: "00:11:22:00:00:21", IsWired: true},
		&probe.HostProfile{OpenPorts: []int{80, 554}},
		true,
	)
	if cam.Category != CategoryCamera {
		t.Fatalf("WAN-forwarded RTSP camera classified as %q (%q), want %q", cam.Category, cam.Role, CategoryCamera)
	}

	// 3. Hue Bridge mDNS and AirPlay-only receiver classify cleanly instead of Unclassified.
	hue := c.ClassifyClient(
		unifi.Client{IP: "192.0.2.22", MAC: "00:11:22:00:00:22", IsWired: true},
		&probe.HostProfile{MDNSServices: []probe.MDNSService{{Type: "_hue._tcp", Port: 443}}},
		false,
	)
	if hue.Category != CategoryIoT || hue.Role != "Philips Hue Bridge" {
		t.Fatalf("Hue mDNS classified as %+v, want Philips Hue Bridge", hue)
	}
	ap := c.ClassifyClient(
		unifi.Client{IP: "192.0.2.23", MAC: "00:11:22:00:00:23", IsWired: false},
		&probe.HostProfile{MDNSServices: []probe.MDNSService{{Type: "_airplay._tcp", Port: 7000}}},
		false,
	)
	if ap.Category != CategoryMedia || ap.Role != "AirPlay Media Receiver" {
		t.Fatalf("AirPlay-only device classified as %+v, want AirPlay Media Receiver", ap)
	}

	// 4. Recognized SIP service classifies as VoIP / SIP Endpoint (not Unclassified).
	sip := c.ClassifyClient(
		unifi.Client{IP: "192.0.2.24", MAC: "00:11:22:00:00:24", IsWired: true},
		&probe.HostProfile{Services: []probe.Service{{Port: 5060, Transport: "udp", Protocol: "sip"}}},
		false,
	)
	if sip.Category != CategoryNetService || sip.Role != "VoIP / SIP Endpoint" {
		t.Fatalf("SIP device classified as %+v, want VoIP / SIP Endpoint", sip)
	}

	// 5. Hypervisor and Backup Server receive distinct roles within CategoryServer.
	pve := c.ClassifyClient(
		unifi.Client{IP: "192.0.2.25", MAC: "00:11:22:00:00:25", IsWired: true},
		&probe.HostProfile{OpenPorts: []int{22, 8006}},
		false,
	)
	if pve.Category != CategoryServer || pve.Role != "Hypervisor" {
		t.Fatalf("Proxmox host classified as %+v, want Hypervisor", pve)
	}
	pbs := c.ClassifyClient(
		unifi.Client{IP: "192.0.2.26", MAC: "00:11:22:00:00:26", IsWired: true},
		&probe.HostProfile{OpenPorts: []int{22, 8007}},
		false,
	)
	if pbs.Category != CategoryServer || pbs.Role != "Backup Server" {
		t.Fatalf("Backup host classified as %+v, want Backup Server", pbs)
	}
}
