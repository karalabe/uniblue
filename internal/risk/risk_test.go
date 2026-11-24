package risk

import (
	"path/filepath"
	"testing"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/unifi"
)

func TestEvaluateBlastRadiusScoring(t *testing.T) {
	netCfg := config.NetworkConfig{
		TrustedVLANs:  []string{"Default"},
		IsolatedVLANs: []string{"IoT"},
	}

	snap := &unifi.Snapshot{
		Site: "default",
		Clients: []unifi.Client{
			{IP: "192.168.1.10", MAC: "aa:01", Name: "hvac-trusted", NetworkName: "Default"},
			{IP: "192.168.20.10", MAC: "aa:02", Name: "hvac-iot", NetworkName: "IoT"},
			{IP: "192.168.20.20", MAC: "aa:03", Name: "cam-exposed", NetworkName: "IoT"},
		},
		PortForwards: []unifi.PortForward{
			{Name: "Cam-WAN", Enabled: true, Proto: "tcp", DstPort: "554", FwdIP: "192.168.20.20", FwdPort: "554", Src: "any"},
		},
	}

	raw := []checks.Finding{
		{CheckID: "UB-0003", BaseSeverity: checks.SeverityHigh, Client: snap.Clients[0], Port: 502},
		{CheckID: "UB-0003", BaseSeverity: checks.SeverityHigh, Client: snap.Clients[1], Port: 502},
		{CheckID: "UB-0004", BaseSeverity: checks.SeverityMedium, Client: snap.Clients[2], Port: 554},
	}

	report := Evaluate(snap, raw, netCfg)
	got := make(map[string]checks.Severity)
	for _, f := range report.Findings {
		got[f.Key()] = f.EffectiveSeverity
	}

	// Trusted VLAN bumps high -> critical.
	if got["UB-0003|aa:01|502"] != checks.SeverityCritical {
		t.Fatalf("trusted VLAN finding = %v, want critical", got["UB-0003|aa:01|502"])
	}
	// Isolated VLAN lowers high -> medium.
	if got["UB-0003|aa:02|502"] != checks.SeverityMedium {
		t.Fatalf("isolated VLAN finding = %v, want medium", got["UB-0003|aa:02|502"])
	}
	// WAN port forward forces medium -> critical even on IoT VLAN.
	if got["UB-0004|aa:03|554"] != checks.SeverityCritical {
		t.Fatalf("WAN-exposed finding = %v, want critical", got["UB-0004|aa:03|554"])
	}
}

func TestStatePersistenceAndDiffing(t *testing.T) {
	netCfg := config.NetworkConfig{
		TrustedVLANs:  []string{"Default"},
		IsolatedVLANs: []string{"IoT"},
	}

	// First scan: device sits safely on IoT VLAN.
	snap1 := &unifi.Snapshot{
		Site: "default",
		Clients: []unifi.Client{
			{IP: "192.168.20.10", MAC: "aa:02", Name: "hvac", NetworkName: "IoT"},
		},
	}
	raw1 := []checks.Finding{
		{CheckID: "UB-0003", BaseSeverity: checks.SeverityHigh, Client: snap1.Clients[0], Port: 502},
	}
	rep1 := Evaluate(snap1, raw1, netCfg)
	st1 := BuildState(snap1, rep1, netCfg)

	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := SaveState(statePath, st1); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	loaded, err := LoadState(statePath)
	if err != nil || loaded == nil {
		t.Fatalf("LoadState: %v (loaded=%v)", err, loaded)
	}

	// Second scan: same device moved onto Trusted VLAN + a brand new device joins Trusted VLAN.
	snap2 := &unifi.Snapshot{
		Site: "default",
		Clients: []unifi.Client{
			{IP: "192.168.1.10", MAC: "aa:02", Name: "hvac", NetworkName: "Default"},
			{IP: "192.168.1.99", MAC: "bb:99", Name: "rogue-laptop", NetworkName: "Default"},
		},
	}
	raw2 := []checks.Finding{
		{CheckID: "UB-0003", BaseSeverity: checks.SeverityHigh, Client: snap2.Clients[0], Port: 502},
	}
	rep2 := Evaluate(snap2, raw2, netCfg)

	diff := ComputeDiff(loaded, snap2, rep2, netCfg)
	if len(diff.EscalatedFindings) != 1 {
		t.Fatalf("expected 1 escalated finding, got %d", len(diff.EscalatedFindings))
	}
	if len(diff.NewTrustedClients) != 2 {
		t.Fatalf("expected 2 newly seen trusted clients (moved hvac + rogue-laptop), got %d", len(diff.NewTrustedClients))
	}
	if !diff.HasAlerts(checks.SeverityHigh) {
		t.Fatal("expected diff to trigger high-severity alert")
	}
}

func TestExposureClassificationAndPostureNotes(t *testing.T) {
	netCfg := config.NetworkConfig{
		TrustedVLANs:  []string{"Default"},
		IsolatedVLANs: []string{"IoT"},
	}

	snap := &unifi.Snapshot{
		Site: "default",
		Networks: []unifi.Network{
			{ID: "n1", Name: "Default", VLAN: "1"},
			{ID: "n2", Name: "IoT", VLAN: "30"},
			{ID: "n3", Name: "Servers", VLAN: "2"},
		},
		Clients: []unifi.Client{
			{IP: "10.0.1.50", MAC: "aa:01", Name: "Ventilation", NetworkName: "Default"},
			{IP: "192.168.10.3", MAC: "aa:02", Name: "p2p-node", NetworkName: "Servers"},
		},
		PortForwards: []unifi.PortForward{
			{Name: "Ethereum DevP2P", Enabled: true, Proto: "tcp_udp", DstPort: "30303", FwdIP: "192.168.10.3", FwdPort: "30303", Src: "any"},
			{Name: "Accidental Eth RPC", Enabled: true, Proto: "tcp", DstPort: "8545", FwdIP: "192.168.10.3", FwdPort: "8545", Src: "any"},
		},
	}

	raw := []checks.Finding{
		{CheckID: "UB-2026-0001", BaseSeverity: checks.SeverityHigh, Client: snap.Clients[0], Port: 56747},
	}

	report := Evaluate(snap, raw, netCfg)

	// Expect 2 WAN surface entries: DevP2P classified INFO (expected-p2p), RPC classified CRITICAL (dangerous-rpc).
	if len(report.WANSurface) != 2 {
		t.Fatalf("expected 2 WAN surface items, got %d", len(report.WANSurface))
	}
	if report.WANSurface[0].Class != "dangerous-rpc" || report.WANSurface[0].Severity != checks.SeverityCritical {
		t.Fatalf("expected RPC forward to be CRITICAL dangerous-rpc, got %+v", report.WANSurface[0])
	}
	if report.WANSurface[1].Class != "expected-p2p" || report.WANSurface[1].Severity != checks.SeverityInfo {
		t.Fatalf("expected DevP2P forward to be INFO expected-p2p, got %+v", report.WANSurface[1])
	}

	// Only the CRITICAL RPC forward (not expected DevP2P) should appear as a Finding.
	portFwdFindings := 0
	for _, f := range report.Findings {
		if f.CheckID == "UB-UNIFI-PORTFWD" {
			portFwdFindings++
		}
	}
	if portFwdFindings != 1 {
		t.Fatalf("expected exactly 1 actionable port-forward finding (RPC only), got %d", portFwdFindings)
	}

	// Unused "IoT" VLAN posture note should fire automatically.
	if len(report.PostureNotes) == 0 {
		t.Fatal("expected posture note flagging unused IoT VLAN")
	}
}
