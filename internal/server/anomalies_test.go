// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package server

import (
	"testing"
	"time"

	"github.com/karalabe/uniblue/internal/classify"
	"github.com/karalabe/uniblue/internal/unifi"
)

func TestAnomalyTrackerPortTamperAndBehavioralSignals(t *testing.T) {
	now := time.Now().UTC()
	tr := newAnomalyTracker()

	initialPorts := map[string]portLiveState{
		"sw1|1": {
			DeviceName:    "Core Switch",
			DeviceIP:      "192.168.1.2",
			PortIdx:       1,
			PortName:      "Port 1",
			Zone:          "external",
			Up:            true,
			Enabled:       true,
			PoEPowerWatts: 9.2,
			MACTableCount: 1,
			STPState:      "forwarding",
		},
		"sw1|2": {
			DeviceName:    "Core Switch",
			DeviceIP:      "192.168.1.2",
			PortIdx:       2,
			PortName:      "Port 2",
			Zone:          "internal",
			Up:            true,
			Enabled:       true,
			MACTableCount: 1,
			STPState:      "forwarding",
		},
	}

	initSnap := &unifi.Snapshot{
		Devices: []unifi.Device{{Name: "AP1", MAC: "aa:bb:cc:11:22:33"}},
		WLANs:   []unifi.WLANConfig{{Name: "HomeWiFi", Enabled: true, Security: "wpapsk"}},
		KnownClients: []unifi.HistoricalClient{
			{
				MAC:      "11:22:33:44:55:66",
				Name:     "Old Tablet",
				IsWired:  false,
				LastSeen: now.Add(-45 * 24 * time.Hour).Unix(),
			},
		},
		Clients: []unifi.Client{
			{
				MAC:     "aa:aa:aa:aa:aa:aa",
				IP:      "192.168.1.50",
				Name:    "HVAC Bridge",
				TxBytes: 1 << 20,
			},
		},
		Health: &unifi.SystemHealth{
			WANStatus:      "ok",
			WANIP:          "203.0.113.10",
			ActiveVPNUsers: 0,
		},
		SecuritySettings: &unifi.SiteSecuritySettings{
			SSHEnabled: false,
			IPSMode:    "ips",
		},
		RecentLogs: []unifi.ControllerLogEvent{
			{ID: "old-1", Category: "SECURITY", Event: "THREAT_BLOCKED", Severity: "high", Message: "old"},
		},
	}

	tr.Seed(initSnap, initialPorts, now)

	// 1. Test PoE cable-swap tamper + inline hub MAC surge + STP blocking.
	nextPorts := map[string]portLiveState{
		"sw1|1": {
			DeviceName:    "Core Switch",
			DeviceIP:      "192.168.1.2",
			PortIdx:       1,
			PortName:      "Port 1",
			Zone:          "external",
			Up:            true,
			Enabled:       true,
			PoEPowerWatts: 0.0, // PoE camera replaced by battery laptop!
			MACTableCount: 2,   // and an inline hub!
			STPState:      "forwarding",
		},
		"sw1|2": {
			DeviceName:    "Core Switch",
			DeviceIP:      "192.168.1.2",
			PortIdx:       2,
			PortName:      "Port 2",
			Zone:          "internal",
			Up:            true,
			Enabled:       true,
			MACTableCount: 1,
			STPState:      "discarding",
		},
	}
	portEvs := tr.EvaluatePortAnomalies(initialPorts, nextPorts)
	seenTypes := map[string]string{}
	for _, ev := range portEvs {
		seenTypes[ev.Type] = ev.Severity
	}
	if seenTypes["port_poe_tamper"] != "critical" {
		t.Errorf("expected critical port_poe_tamper, got %v", portEvs)
	}
	if seenTypes["port_mac_surge"] != "critical" {
		t.Errorf("expected critical port_mac_surge, got %v", portEvs)
	}
	if seenTypes["port_stp_blocked"] != "high" {
		t.Errorf("expected high port_stp_blocked, got %v", portEvs)
	}

	// 2. Test dormant wakeup (>30d) + Wi-Fi->Wired medium swap.
	joinEvs := tr.EvaluateClientJoinAnomalies(unifi.Client{
		MAC:         "11:22:33:44:55:66",
		IP:          "192.168.1.77",
		Name:        "Old Tablet",
		IsWired:     true,
		NetworkName: "Default",
	}, now)
	joinTypes := map[string]bool{}
	for _, ev := range joinEvs {
		joinTypes[ev.Type] = true
	}
	if !joinTypes["client_dormant_wakeup"] || !joinTypes["client_medium_swap"] {
		t.Errorf("expected both dormant wakeup and medium swap, got %+v", joinEvs)
	}

	// 3. Test IoT upload spike (>= 50 MB in <= 5m).
	spikeEvs := tr.EvaluateIoTUploadSpikes(
		[]unifi.Client{{
			MAC:     "aa:aa:aa:aa:aa:aa",
			IP:      "192.168.1.50",
			Name:    "HVAC Bridge",
			TxBytes: 70 << 20, // +69 MB in 1 minute
		}},
		map[string]classify.Result{"192.168.1.50": {Category: "iot"}},
		now.Add(1*time.Minute),
	)
	if len(spikeEvs) != 1 || spikeEvs[0].Type != "iot_upload_spike" {
		t.Fatalf("expected iot_upload_spike, got %+v", spikeEvs)
	}

	// 4. Test Evil-Twin AP, WAN IP change, VPN connect, config drift, and new IDS/Admin logs.
	nextSnap := &unifi.Snapshot{
		Devices: initSnap.Devices,
		WLANs:   initSnap.WLANs,
		RogueAPs: []unifi.RogueAP{
			{BSSID: "77:88:99:aa:bb:cc", ESSID: "HomeWiFi", OUI: "Rogue", Channel: 1, RSSI: -50},
		},
		Health: &unifi.SystemHealth{
			WANStatus:      "ok",
			WANIP:          "198.51.100.42",
			ActiveVPNUsers: 1,
			VPNConnections: []unifi.VPNConnection{
				{ID: "wg-1", User: "alice", Type: "wireguard", RemoteIP: "192.0.2.5", LocalIP: "10.9.0.2"},
			},
		},
		SecuritySettings: &unifi.SiteSecuritySettings{
			SSHEnabled:      true, // drifted!
			SSHPasswordAuth: true,
			IPSMode:         "ips",
		},
	}
	freshLogs := []unifi.ControllerLogEvent{
		{ID: "old-1", Category: "SECURITY", Event: "THREAT_BLOCKED", Severity: "high", Message: "old"},
		{ID: "new-ids-2", Category: "SECURITY", Event: "THREAT_BLOCKED", Severity: "high", Message: "IDS blocked 198.51.100.99"},
		{ID: "admin:new-3", Category: "ADMIN", Event: "ADMIN_ACCESS", Severity: "medium", Admin: "ops", Message: "ops accessed UniFi"},
	}
	siteEvs := tr.EvaluateSiteTelemetry(nextSnap, freshLogs)
	siteTypes := map[string]bool{}
	for _, ev := range siteEvs {
		siteTypes[ev.Type] = true
	}
	for _, wantType := range []string{"ids_threat", "admin_activity", "wifi_evil_twin", "wan_ip_changed", "vpn_connected", "config_drift"} {
		if !siteTypes[wantType] {
			t.Errorf("missing expected live event %q; got %+v", wantType, siteEvs)
		}
	}
}
