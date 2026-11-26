// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package classify

import (
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	classifydata "github.com/karalabe/uniblue/classify"
	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/config"
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

	// 6. Axis camera identified by vendor with only HTTPS visible stays CategoryCamera
	// even when forwarded from WAN (does not become WAN Web Entrypoint / Reverse Proxy).
	axis := c.ClassifyClient(
		unifi.Client{IP: "192.0.2.27", MAC: "ac:cc:8e:00:00:27", OUI: "Axis Communications AB", IsWired: true},
		&probe.HostProfile{OpenPorts: []int{443}},
		true,
	)
	if axis.Category != CategoryCamera {
		t.Fatalf("WAN-forwarded HTTPS-only Axis camera classified as %q (%q), want %q", axis.Category, axis.Role, CategoryCamera)
	}

	// 7. IPv6-only Hue Bridge classifies cleanly via batch ClassifyAll under its PrimaryIP key.
	v6Hue := unifi.Client{MAC: "00:17:88:00:00:28", IPv6: []string{"fd00:10::28"}, IsWired: true}
	batch := c.ClassifyAll(
		&unifi.Snapshot{Clients: []unifi.Client{v6Hue}},
		[]probe.HostProfile{{
			Client:       v6Hue,
			MDNSServices: []probe.MDNSService{{Type: "_hue._tcp", Port: 443, AddressFamily: "ipv6"}},
		}},
	)
	gotHue, ok := batch["fd00:10::28"]
	if !ok || gotHue.Category != CategoryIoT || gotHue.Role != "Philips Hue Bridge" {
		t.Fatalf("IPv6-only Hue batch ClassifyAll got %+v (map=%+v), want Philips Hue Bridge under fd00:10::28", gotHue, batch)
	}
}

// TestClassifyHostnameBoundariesAndPersonalPrecedence verifies that whole-token
// hostname matching and personal-device rule precedence prevent names like
// "Camerons-iPhone", "Campbell-Laptop", "Jonass-iPhone", and "Panasonic-TV"
// from being misclassified as cameras or NAS servers while preserving true
// camera, NAS, and Proxmox hostname matches.
func TestClassifyHostnameBoundariesAndPersonalPrecedence(t *testing.T) {
	c, err := Load(classifydata.BuiltinFS, oui.New(t.TempDir()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	cases := []struct {
		name      string
		client    unifi.Client
		wantCat   Category
		forbidCat Category
	}{
		{
			name:    "Camerons-iPhone with private MAC is personal not camera",
			client:  unifi.Client{IP: "192.0.2.10", MAC: "02:aa:bb:00:00:10", Hostname: "Camerons-iPhone", IsWired: false},
			wantCat: CategoryPersonal,
		},
		{
			name:    "Campbell-Laptop is personal not camera",
			client:  unifi.Client{IP: "192.0.2.11", MAC: "00:11:22:00:00:11", Hostname: "Campbell-Laptop", IsWired: false},
			wantCat: CategoryPersonal,
		},
		{
			name:    "Jonass-iPhone is personal not NAS",
			client:  unifi.Client{IP: "192.0.2.12", MAC: "02:aa:bb:00:00:12", Hostname: "Jonass-iPhone", IsWired: false},
			wantCat: CategoryPersonal,
		},
		{
			name:      "Panasonic-TV is media not NAS",
			client:    unifi.Client{IP: "192.0.2.13", MAC: "00:11:22:00:00:13", Hostname: "Panasonic-TV", IsWired: true},
			wantCat:   CategoryMedia,
			forbidCat: CategoryServer,
		},
		{
			name:      "Cameron-Host does not match cam token",
			client:    unifi.Client{IP: "192.0.2.14", MAC: "00:11:22:00:00:14", Hostname: "Cameron-Host", IsWired: true},
			wantCat:   CategoryUnknown,
			forbidCat: CategoryCamera,
		},
		{
			name:      "Jonas-Box does not match nas token",
			client:    unifi.Client{IP: "192.0.2.15", MAC: "00:11:22:00:00:15", Hostname: "Jonas-Box", IsWired: true},
			wantCat:   CategoryUnknown,
			forbidCat: CategoryServer,
		},
		{
			name:      "appvendor-box does not match pve token",
			client:    unifi.Client{IP: "192.0.2.16", MAC: "00:11:22:00:00:16", Hostname: "appvendor-box", IsWired: true},
			wantCat:   CategoryUnknown,
			forbidCat: CategoryServer,
		},
		{
			name:    "front-cam01 matches camera",
			client:  unifi.Client{IP: "192.0.2.20", MAC: "00:11:22:00:00:20", Hostname: "front-cam01", IsWired: true},
			wantCat: CategoryCamera,
		},
		{
			name:    "g4-doorbell matches camera",
			client:  unifi.Client{IP: "192.0.2.21", MAC: "00:11:22:00:00:21", Hostname: "g4-doorbell", IsWired: true},
			wantCat: CategoryCamera,
		},
		{
			name:    "home-nas01 matches server",
			client:  unifi.Client{IP: "192.0.2.22", MAC: "00:11:22:00:00:22", Hostname: "home-nas01", IsWired: true},
			wantCat: CategoryServer,
		},
		{
			name:    "pve01 matches server",
			client:  unifi.Client{IP: "192.0.2.23", MAC: "00:11:22:00:00:23", Hostname: "pve01", IsWired: true},
			wantCat: CategoryServer,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := c.ClassifyClient(tc.client, nil, false)
			if tc.forbidCat != "" && got.Category == tc.forbidCat {
				t.Fatalf("got forbidden category %q (role=%q, signals=%v)", got.Category, got.Role, got.Signals)
			}
			if got.Category != tc.wantCat {
				t.Fatalf("got category %q (role=%q, signals=%v), want %q", got.Category, got.Role, got.Signals, tc.wantCat)
			}
		})
	}
}

// TestProtocolTraits checks the embedded catalog and the names used by service fingerprints.
func TestProtocolTraits(t *testing.T) {
	catalog, err := LoadProtocols(classifydata.BuiltinFS)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range strings.Fields("ssh http https smb rdp vnc telnet ftp snmp mqtt modbus rtsp ipp redis memcached mongodb postgres mysql mssql docker kubernetes etcd rsync nfs afp ldap ldaps kerberos dns ntp smtp imap pop3 upnp mdns ssdp esphome hap matter wireguard openvpn ipmi winrm adb coap home-assistant") {
		if _, ok := catalog[name]; !ok {
			t.Errorf("missing %s protocol traits", name)
		}
	}
	if trait, ok := LookupProtocol(" MQTT "); !ok || !trait.Hub || trait.AuthModel != "optional" {
		t.Errorf("MQTT traits = %+v, %t", trait, ok)
	}
	if trait, ok := LookupProtocol("postgresql"); !ok || trait.AuthModel != catalog["postgres"].AuthModel {
		t.Errorf("PostgreSQL lookup = %+v, %t", trait, ok)
	}
	if trait, ok := LookupProtocol("mdns"); !ok || trait.TransportClass != "cleartext-noauth" || !slices.Equal(trait.AnonGrants, []checks.GrantEffect{checks.GrantRead}) {
		t.Errorf("mDNS lookup = %+v, %t", trait, ok)
	}
	if _, ok := LookupProtocol("unrecognized"); ok {
		t.Error("unknown protocol matched")
	}
	for _, fields := range []string{
		"hub: false, transport_class: insecure, auth_model: none",
		"hub: false, transport_class: tls, auth_model: password",
		"hub: false, transport_class: tls, auth_model: none, anon_grants: [admin]",
		"transport_class: tls, auth_model: required",
	} {
		fsys := fstest.MapFS{"protocols.yaml": {Data: []byte("test: {" + fields + "}")}}
		if _, err := LoadProtocols(fsys); err == nil {
			t.Errorf("accepted invalid protocol traits %q", fields)
		}
	}
}

// TestInferDeviceAsset distinguishes network-wide control from individual access links.
func TestInferDeviceAsset(t *testing.T) {
	for _, tc := range []struct {
		dev  unifi.Device
		tier AssetTier
	}{
		{unifi.Device{Type: "udm"}, TierCrown},
		{unifi.Device{Type: "UCG"}, TierCrown},
		{unifi.Device{Type: "uxg"}, TierCrown},
		{unifi.Device{Type: "usg"}, TierCrown},
		{unifi.Device{Type: "uck"}, TierCrown},
		{unifi.Device{Type: "usw", Name: "Core Switch"}, TierCrown},
		{unifi.Device{Type: "usw", Model: "USW-Pro-Aggregation"}, TierCrown},
		{unifi.Device{Type: "usw", Name: "Office Switch"}, TierHigh},
		{unifi.Device{Type: "uap"}, TierHigh},
	} {
		got := InferDeviceAsset(tc.dev)
		if got.Tier != tc.tier || !slices.Equal(got.Consequences, []Consequence{ConsequenceControlPlane, ConsequenceContinuity}) || got.Reason == "" {
			t.Errorf("InferDeviceAsset(%+v) = %+v, want %s with network control and continuity", tc.dev, got, tc.tier)
		}
	}
}

// TestInferClientAsset exercises real taxonomy roles, including broad product
// families where the hostname is needed to identify a higher-impact device.
func TestInferClientAsset(t *testing.T) {
	c, err := Load(classifydata.BuiltinFS, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		host, vendor string
		tier         AssetTier
		dims         []Consequence
	}{
		{"rack-bmc", "", TierCrown, []Consequence{ConsequenceControlPlane, ConsequenceContinuity}},
		{"switch", "Mikrotik", TierHigh, []Consequence{ConsequenceControlPlane, ConsequenceContinuity}},
		{"pi-hole", "", TierHigh, []Consequence{ConsequenceControlPlane, ConsequenceContinuity}},
		{"nas01", "", TierHigh, []Consequence{ConsequenceData, ConsequenceContinuity}},
		{"pve01", "", TierCrown, []Consequence{ConsequenceData, ConsequenceContinuity, ConsequenceControlPlane}},
		{"proxmox-backup", "", TierCrown, []Consequence{ConsequenceData, ConsequenceContinuity}},
		{"work-laptop", "", TierHigh, []Consequence{ConsequenceData, ConsequenceIdentity, ConsequencePrivacy}},
		{"porch-camera", "Axis Communications", TierMedium, []Consequence{ConsequencePrivacy}},
		{"unvr01", "Axis Communications", TierHigh, []Consequence{ConsequencePrivacy, ConsequenceData}},
		{"shelly-plug", "", TierLow, []Consequence{ConsequencePhysical}},
		{"hall-thermostat", "", TierMedium, []Consequence{ConsequencePhysical}},
		{"node-red", "", TierHigh, []Consequence{ConsequenceControlPlane, ConsequencePhysical, ConsequencePrivacy}},
		{"zigbee-bridge", "Signify", TierHigh, []Consequence{ConsequenceControlPlane, ConsequencePhysical, ConsequencePrivacy}},
		{"roomba", "", TierLow, []Consequence{ConsequencePhysical, ConsequencePrivacy}},
		{"laserjet", "", TierLow, []Consequence{ConsequenceData}},
		{"prusa", "", TierLow, []Consequence{ConsequencePhysical}},
		{"sonos", "", TierLow, []Consequence{ConsequencePrivacy}},
	} {
		t.Run(tc.host, func(t *testing.T) {
			cl := unifi.Client{Hostname: tc.host, OUI: tc.vendor}
			got := InferClientAsset(cl, c.ClassifyClient(cl, nil, false))
			if got.Tier != tc.tier || !slices.Equal(got.Consequences, tc.dims) || got.Unclassified || got.Reason == "" {
				t.Errorf("got %+v, want %s %v", got, tc.tier, tc.dims)
			}
		})
	}
	for _, category := range []Category{"", CategoryUnknown} {
		got := InferClientAsset(unifi.Client{}, DeviceInfo{Category: category})
		if got.Tier != TierMedium || !got.Unclassified || got.Reason != "Unclassified device (defaulting to medium until identified)" {
			t.Errorf("fallback for %q = %+v", category, got)
		}
	}
}

// TestResolveAssets checks exact matching even when clients share an IP and
// verifies that relation targets use the same profile keys as their owners.
func TestResolveAssets(t *testing.T) {
	const gateway = "00:00:5e:00:53:01"
	const client = "02:00:00:00:00:02"
	vm := unifi.Client{ID: "Guest-A", IP: "192.0.2.1"}
	snap := &unifi.Snapshot{
		Devices: []unifi.Device{{ID: "Gateway", MAC: gateway, Type: "udm"}},
		Clients: []unifi.Client{vm, {MAC: client, ID: "Phone", IP: vm.IP}, {ID: "Spare"}},
	}
	profiles := []probe.HostProfile{{Client: vm, OpenPorts: []int{8006}}, {Client: snap.Clients[1]}}
	assets, warnings := ResolveAssets(snap, profiles, []config.AssetOverride{
		{ID: "Gateway", Manages: []string{"Phone"}, Hosts: []string{"Guest-A", "Offline"}},
		{MAC: "02-00-00-00-00-02", Tier: "low", Consequences: []string{"privacy"}},
		{ID: "Spare", Label: "Spare client", Tier: "disposable"},
		{ID: "guest-a"},
		{MAC: "DA0000000003", Manages: []string{"Missing"}},
	})
	gw := assets[gateway]
	if len(assets) != 4 || !gw.Override || gw.Tier != TierCrown || !slices.Equal(gw.Manages, []string{client}) || !slices.Equal(gw.Hosts, []string{"Guest-A", "Offline"}) ||
		!slices.Equal(gw.Consequences, []Consequence{ConsequenceControlPlane, ConsequenceContinuity}) {
		t.Errorf("gateway and relations = %+v (in %d profiles)", gw, len(assets))
	}
	phone := assets[client]
	if !phone.Override || phone.Tier != TierLow || !slices.Equal(phone.Consequences, []Consequence{ConsequencePrivacy}) {
		t.Errorf("phone override = %+v", phone)
	}
	if got := assets["Guest-A"]; got.Override || got.Tier != TierCrown || !slices.Contains(got.Consequences, ConsequenceControlPlane) {
		t.Errorf("probed hypervisor = %+v", got)
	}
	if got := assets["Spare"]; got.Tier != TierDisposable || got.Unclassified || !got.Override || !strings.Contains(got.Reason, "Spare client") {
		t.Errorf("owner-identified client = %+v", got)
	}
	want := []string{
		"Asset override for Gateway lists Offline under hosts, but that target did not match any device or client in the current scan",
		"Asset override for " + client + " uses a randomized (locally administered) MAC address and may stop matching after a reconnect",
		"Asset override for guest-a did not match any device or client in the current scan",
		"Asset override for da:00:00:00:00:03 uses a randomized (locally administered) MAC address and may stop matching after a reconnect",
		"Asset override for da:00:00:00:00:03 did not match any device or client in the current scan",
	}
	if !slices.Equal(warnings, want) {
		t.Errorf("warnings = %q, want %q", warnings, want)
	}
}

// TestResolveAssetAliases checks MAC/ID conflicts (including offline MACs),
// duplicate overrides across MAC and ID, self-references, and session-mode
// compact core-switch model codes.
func TestResolveAssetAliases(t *testing.T) {
	const mac = "00:00:5e:00:53:02"
	snap := &unifi.Snapshot{Devices: []unifi.Device{
		{ID: "AP", MAC: mac, Type: "uap"},
		{ID: "Switch", Type: "usw", Model: "USAGGPRO"},
		{ID: "Agg8", MAC: "00:00:5e:00:53:03", Type: "usw", Model: "USL8A"},
	}}
	assets, warnings := ResolveAssets(snap, nil, []config.AssetOverride{
		{MAC: mac, ID: "Switch", Tier: "disposable"},
		{MAC: "00:00:5e:00:53:99", ID: "AP", Tier: "disposable"},
		{ID: "AP", Hosts: []string{mac}, Consequences: []string{}},
		{MAC: mac, Tier: "low"},
	})
	ap := assets[mac]
	if !ap.Override || ap.Tier != TierHigh || len(ap.Hosts) != 0 || len(ap.Consequences) != 0 || assets["Switch"].Override {
		t.Errorf("conflicting selectors, duplicate override, or self-host relation applied: %+v", assets)
	}
	if assets["Switch"].Tier != TierCrown || assets["00:00:5e:00:53:03"].Tier != TierCrown {
		t.Errorf("compact session-mode aggregation switch codes must infer TierCrown: %+v", assets)
	}
	if len(warnings) != 4 ||
		!strings.Contains(warnings[0], "different device") ||
		!strings.Contains(warnings[1], "different device") ||
		!strings.Contains(warnings[2], "itself") ||
		!strings.Contains(warnings[3], "already matched") {
		t.Errorf("warnings = %q", warnings)
	}
}
