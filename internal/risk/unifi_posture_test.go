// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package risk

import (
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
			// Owned AP virtual BSSID (middle 4 octets match aa:bb:cc:11:22:01) must not alert.
			{
				BSSID:   "ae:bb:cc:11:22:05",
				ESSID:   "HomeWiFi",
				Channel: 36,
				RSSI:    -45,
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
			SSHEnabled:      true,
			SSHPasswordAuth: true,
			SSHKeyCount:     0,
			UPnPEnabled:     true,
			IPSMode:         "disabled",
			HoneypotEnabled: false,
			DoHState:        "off",
		},
		RecentLogs: []unifi.ControllerLogEvent{
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

	if summary == nil || summary.EvilTwinCount != 1 {
		t.Fatalf("expected EvilTwinCount=1, got %+v", summary)
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
