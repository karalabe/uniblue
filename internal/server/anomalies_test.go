// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package server

import (
	"strings"
	"testing"
	"time"

	classifydata "github.com/karalabe/uniblue/classify"
	"github.com/karalabe/uniblue/internal/classify"
	"github.com/karalabe/uniblue/internal/oui"
	"github.com/karalabe/uniblue/internal/unifi"
)

// TestAnomalyTrackerPortTamperAndBehavioralSignals verifies detection of PoE
// cable swaps, inline hub MAC surges, STP blocking, dormant wakeups, wired/Wi-Fi
// swaps, IoT upload spikes, Evil-Twin APs, WAN/VPN transitions, and config drift.
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
		{ID: "block", Category: "SECURITY", SubCategory: "FIREWALL", Policy: "Guest rules", Severity: "high"},
		{ID: "other", Category: "SECURITY", Event: "OTHER", Severity: "low"},
		{ID: "admin:new-3", Category: "ADMIN", Event: "ADMIN_ACCESS", Severity: "medium", Admin: "ops", Message: "ops accessed UniFi"},
	}
	siteEvs := tr.EvaluateSiteTelemetry(nextSnap, freshLogs)
	siteTypes := map[string]bool{}
	for _, ev := range siteEvs {
		siteTypes[ev.Type] = true
		if ev.Type == "firewall_block" && (ev.Severity != "info" || ev.Policy != "Guest rules") {
			t.Errorf("unexpected firewall event: %+v", ev)
		}
		if ev.Type == "controller_log" && ev.Severity != "low" {
			t.Errorf("unexpected controller log severity: %+v", ev)
		}
	}
	for _, wantType := range []string{"ids_threat", "firewall_block", "controller_log", "admin_activity", "wifi_evil_twin", "wan_ip_changed", "vpn_connected", "config_drift"} {
		if !siteTypes[wantType] {
			t.Errorf("missing expected live event %q; got %+v", wantType, siteEvs)
		}
	}
}

// TestEvaluateIoTUploadSpikesIPv6OnlyClient verifies that an IPv6-only IoT
// device classified via classify.ClassifyAll triggers iot_upload_spike when it
// uploads 200 MiB within the anomaly window.
func TestEvaluateIoTUploadSpikesIPv6OnlyClient(t *testing.T) {
	ouiDB := oui.New("")
	_ = ouiDB.Load()
	classifier, err := classify.Load(classifydata.BuiltinFS, ouiDB)
	if err != nil {
		t.Fatalf("classify.Load: %v", err)
	}

	now := time.Now().UTC()
	v6IoT := unifi.Client{
		MAC:         "02:aa:bb:cc:dd:66",
		IPv6:        []string{"fd00:20::42"},
		Name:        "shelly-plug-kitchen",
		Hostname:    "shellyplug-s-123456",
		OUI:         "Espressif Inc.",
		NetworkName: "IoT",
		TxBytes:     1 << 20,
	}
	snap := &unifi.Snapshot{
		Site:    "default",
		Clients: []unifi.Client{v6IoT},
	}
	classes := classifier.ClassifyAll(snap, nil)
	if got := lookupClientClass(classes, v6IoT); got.Category != classify.CategoryIoT {
		t.Fatalf("expected ClassifyAll to classify IPv6-only client as iot, got %+v (map=%+v)", got, classes)
	}

	tr := newAnomalyTracker()
	tr.Seed(snap, nil, now)

	v6IoTSpiked := v6IoT
	v6IoTSpiked.TxBytes = (1 << 20) + (200 << 20)
	evs := tr.EvaluateIoTUploadSpikes([]unifi.Client{v6IoTSpiked}, classes, now.Add(2*time.Minute))
	if len(evs) != 1 {
		t.Fatalf("expected 1 iot_upload_spike event for IPv6-only IoT client, got %+v", evs)
	}
	if evs[0].Type != "iot_upload_spike" || evs[0].Severity != "high" || evs[0].IP != "fd00:20::42" {
		t.Fatalf("unexpected IPv6-only iot_upload_spike event: %+v", evs[0])
	}
	if !strings.Contains(evs[0].Summary, "fd00:20::42") {
		t.Fatalf("expected IPv6 address in spike summary, got %q", evs[0].Summary)
	}
}
