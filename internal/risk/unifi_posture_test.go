// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package risk

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/unifi"
)

// TestAnalyzeUniFiPostureAndPhysicalTamper verifies Wi-Fi encryption/isolation,
// Evil-Twin vs. owned virtual BSSID filtering, unauthorized wired AP correlation,
// gateway security controls, and shared-VLAN BMC detection.
func TestAnalyzeUniFiPostureAndPhysicalTamper(t *testing.T) {
	snap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{
				Name:  "Gateway",
				MAC:   "aa:bb:cc:11:22:01",
				IP:    "192.168.1.1",
				Model: "UDMPRO",
				Type:  "udm",
			},
			{
				Name:  "Core Switch",
				MAC:   "aa:bb:cc:11:22:02",
				IP:    "192.168.1.2",
				Model: "USW-24-PoE",
				Type:  "usw",
				Ports: []unifi.SwitchPort{
					{
						PortIdx:             1,
						Name:                "Driveway Camera",
						Enabled:             true,
						Up:                  true,
						Speed:               1000,
						NativeNetworkName:   "IoT",
						Forward:             "native",
						TaggedVLANMgmt:      "block_all",
						PortSecurityEnabled: true,
						MACTableCount:       3, // inline rogue hub / tap!
					},
					{
						PortIdx:           2,
						Name:              "Office Wall",
						Enabled:           true,
						Up:                true,
						Speed:             1000,
						NativeNetworkName: "Default",
						Forward:           "native",
						TaggedVLANMgmt:    "block_all",
						STPState:          "discarding",
						STPStateChanges:   4,
					},
				},
			},
		},
		Clients: []unifi.Client{
			{
				Name:        "Mystery Wired Box",
				MAC:         "de:ad:be:ef:01:10",
				IP:          "192.168.1.88",
				IsWired:     true,
				NetworkName: "Default",
			},
			{
				Name:        "Compute Server Management Console",
				MAC:         "aa:bb:cc:dd:ee:99",
				IP:          "192.168.2.5",
				IsWired:     true,
				NetworkName: "Servers",
			},
		},
		WLANs: []unifi.WLANConfig{
			{
				Name:        "HomeWiFi",
				Enabled:     true,
				Security:    "wpapsk",
				WPAMode:     "wpa2",
				WPA3Support: false,
				PMFMode:     "disabled",
				NetworkName: "Default",
			},
			{
				Name:        "GuestWiFi",
				Enabled:     true,
				Security:    "open",
				IsGuest:     true,
				L2Isolation: false,
				NetworkName: "Default",
			},
		},
		RogueAPs: []unifi.RogueAP{
			// Near-cloned BSSID broadcasting our SSID with is_rogue=false must still alert as Evil-Twin.
			{
				BSSID:   "ae:bb:cc:11:22:05",
				ESSID:   "HomeWiFi",
				Channel: 36,
				RSSI:    -45,
			},
			// Neighboring AP broadcasting a different SSID must not alert.
			{
				BSSID:   "cc:dd:ee:00:11:22",
				ESSID:   "NeighborWiFi",
				OUI:     "Netgear",
				Channel: 1,
				RSSI:    -78,
			},
			// True Evil-Twin broadcasting our SSID must alert Critical.
			{
				BSSID:    "66:77:88:99:aa:bb",
				ESSID:    "HomeWiFi",
				OUI:      "Espressif",
				Channel:  6,
				RSSI:     -52,
				Security: "wpapsk",
			},
			// Foreign BSSID sharing a MAC stem with wired client de:ad:be:ef:01:10 must alert High.
			{
				BSSID:   "de:ad:be:ef:01:12",
				ESSID:   "HiddenRouter",
				Channel: 11,
				RSSI:    -40,
			},
		},
		SecuritySettings: &unifi.SiteSecuritySettings{
			SSHEnabled:           true,
			SSHPasswordAuth:      true,
			SSHPasswordAuthKnown: true,
			SSHKeyCount:          0,
			UPnPEnabled:          true,
			IPSMode:              "disabled",
			HoneypotEnabled:      false,
			DoHState:             "off",
		},
		RecentLogs: []unifi.ControllerLogEvent{
			{Category: "SECURITY", SubCategory: "FIREWALL"},
			{Category: "SECURITY", Event: "THREAT_BLOCKED"},
			{Category: "SECURITY", Event: "OTHER"},
			{
				ID:        "hp-1",
				Timestamp: time.Now().UTC(),
				Category:  "SECURITY",
				Event:     "HONEYPOT_TRIGGERED",
				Severity:  "critical",
				Message:   "Honeypot hit from 192.168.1.99",
			},
		},
	}

	trusted := map[string]struct{}{"default": {}}
	isolated := map[string]struct{}{"iot": {}}

	_, portFindings, _ := AnalyzeSwitchPorts(snap, config.NetworkConfig{}, trusted, isolated)
	summary, postureFindings, notes := AnalyzeUniFiPosture(snap, trusted, isolated)
	if !slices.ContainsFunc(notes, func(n PostureNote) bool {
		return n.Title == "Gateway IDS/IPS blocked 1 intrusion attempt(s) in the last 24h"
	}) {
		t.Errorf("expected exactly one intrusion in posture notes: %v", notes)
	}

	if summary == nil || summary.EvilTwinCount != 2 {
		t.Fatalf("expected EvilTwinCount=2 (foreign + near-cloned BSSID), got %+v", summary)
	}

	all := append(portFindings, postureFindings...)
	got := make(map[string]checks.Severity, len(all))
	for _, f := range all {
		got[f.CheckID] = f.EffectiveSeverity
	}

	want := map[string]checks.Severity{
		"UB-UNIFI-PORT-EXT-MULTI-MAC":   checks.SeverityCritical,
		"UB-UNIFI-PORT-STP-BLOCKED":     checks.SeverityHigh,
		"UB-UNIFI-WIFI-OPEN":            checks.SeverityHigh,
		"UB-UNIFI-WIFI-IOT-ON-TRUSTED":  checks.SeverityHigh,
		"UB-UNIFI-WIFI-NO-L2-ISOLATION": checks.SeverityMedium,
		"UB-UNIFI-WIFI-EVIL-TWIN":       checks.SeverityCritical,
		"UB-UNIFI-WIFI-ROGUE-WIRED-AP":  checks.SeverityHigh,
		"UB-UNIFI-SSH-PASSWORD":         checks.SeverityHigh,
		"UB-UNIFI-UPNP-ENABLED":         checks.SeverityHigh,
		"UB-UNIFI-HONEYPOT-HIT":         checks.SeverityCritical,
		"UB-UNIFI-BMC-SHARED-VLAN":      checks.SeverityHigh,
	}
	for id, wantSev := range want {
		sev, ok := got[id]
		if !ok {
			t.Errorf("missing expected finding %s", id)
		} else if sev != wantSev {
			t.Errorf("finding %s severity = %v, want %v", id, sev, wantSev)
		}
	}
	if len(notes) < 3 {
		t.Errorf("expected posture notes for WPA2-only, IPS disabled, Honeypot disabled, DoH off; got %d", len(notes))
	}
}

// TestDeviceSSHAuthMode distinguishes missing telemetry from an explicit key-only setting.
func TestDeviceSSHAuthMode(t *testing.T) {
	for _, tc := range []struct {
		known bool
		want  string
	}{{false, "auth mode unknown"}, {true, "key-only"}} {
		snap := &unifi.Snapshot{SecuritySettings: &unifi.SiteSecuritySettings{SSHEnabled: true, SSHPasswordAuthKnown: tc.known, SSHKeyCount: 1}}
		_, _, notes := AnalyzeUniFiPosture(snap, nil, nil)
		if !slices.ContainsFunc(notes, func(n PostureNote) bool {
			return strings.Contains(n.Title, "Device SSH is enabled ("+tc.want+",")
		}) {
			t.Errorf("password setting known = %t: %v", tc.known, notes)
		}
	}
}

// TestEvilTwinClonedAndNearClonedBSSIDsDetected verifies that exact clones,
// locally-administered octet-0 flips, and last-octet near-clones carrying a
// Ubiquiti OUI with is_rogue=false are never silently suppressed as owned radios.
func TestEvilTwinClonedAndNearClonedBSSIDsDetected(t *testing.T) {
	snap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{Name: "Hallway AP", MAC: "24:5a:4c:11:22:33", IP: "192.168.1.5", Model: "U6-Pro", Type: "uap"},
		},
		WLANs: []unifi.WLANConfig{
			{ID: "w1", Name: "HomeWiFi", Enabled: true, Security: "wpapsk", WPAMode: "wpa2", WPA3Support: true, PMFMode: "optional", NetworkName: "Default"},
		},
		RogueAPs: []unifi.RogueAP{
			// Exact BSSID clone with Ubiquiti OUI and is_rogue=false.
			{BSSID: "24:5a:4c:11:22:33", ESSID: "HomeWiFi", OUI: "Ubiquiti", Channel: 6, RSSI: -48, IsRogue: false},
			// Locally-administered octet-0 flip clone (24 -> 26).
			{BSSID: "26:5a:4c:11:22:33", ESSID: "HomeWiFi", OUI: "Ubiquiti", Channel: 11, RSSI: -50, IsRogue: false},
			// Last-octet near-clone (33 -> 34).
			{BSSID: "24:5a:4c:11:22:34", ESSID: "HomeWiFi", OUI: "Ubiquiti", Channel: 36, RSSI: -52, IsRogue: false},
			// Unrelated neighbor SSID must not trigger an evil-twin alert.
			{BSSID: "24:5a:4c:11:22:35", ESSID: "OtherNet", OUI: "Ubiquiti", Channel: 1, RSSI: -75, IsRogue: false},
		},
	}

	summary, findings, _ := AnalyzeUniFiPosture(snap, map[string]struct{}{"default": {}}, nil)
	if summary == nil || summary.EvilTwinCount != 3 {
		t.Fatalf("expected EvilTwinCount=3 for exact, LAA, and last-octet clones, got %+v", summary)
	}
	flagged := make(map[string]bool)
	for _, f := range findings {
		if f.CheckID == "UB-UNIFI-WIFI-EVIL-TWIN" {
			flagged[f.Client.MAC] = true
		}
	}
	for _, want := range []string{"24:5a:4c:11:22:33", "26:5a:4c:11:22:33", "24:5a:4c:11:22:34"} {
		if !flagged[want] {
			t.Fatalf("expected cloned BSSID %s to raise UB-UNIFI-WIFI-EVIL-TWIN, got %+v", want, flagged)
		}
	}

	// Verify explicit known VAP BSSID matching only suppresses non-rogue exact matches.
	knownVAPs := []string{"26:5a:4c:11:22:33"}
	if !isOwnedUniFiRadio(unifi.RogueAP{BSSID: "26:5a:4c:11:22:33", IsRogue: false}, knownVAPs) {
		t.Fatal("expected exact match in authoritative known VAP BSSID list to be recognized as owned")
	}
	if isOwnedUniFiRadio(unifi.RogueAP{BSSID: "26:5a:4c:11:22:33", IsRogue: true}, knownVAPs) {
		t.Fatal("expected is_rogue=true never to be suppressed even if BSSID matches known VAP")
	}
	if isOwnedUniFiRadio(unifi.RogueAP{BSSID: "24:5a:4c:11:22:34", IsRogue: false}, knownVAPs) {
		t.Fatal("expected near-clone not in authoritative known VAP list never to be suppressed")
	}
}
