// Package risk correlates raw device findings with UniFi network topology
// (VLAN trust tiers and WAN port forwards), computes effective blast-radius
// severity, and tracks state across scans to alert only on meaningful changes.
package risk

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/unifi"
	"github.com/karalabe/uniblue/rules"
)

// Report holds the complete risk-scored output of a single UniBlue scan.
type Report struct {
	// GeneratedAt records when the report was evaluated.
	GeneratedAt time.Time `json:"generated_at"`

	// Site is the UniFi site evaluated.
	Site string `json:"site"`

	// ClientCount is the number of active LAN clients observed in UniFi.
	ClientCount int `json:"client_count"`

	// CleanClients is the number of active clients with zero confirmed check findings.
	CleanClients int `json:"clean_clients"`

	// UniFiDeviceCount is the total number of UniFi infrastructure devices.
	UniFiDeviceCount int `json:"unifi_device_count"`

	// CleanUniFiDevices counts UniFi devices running up-to-date firmware.
	CleanUniFiDevices int `json:"clean_unifi_devices"`

	// Findings holds all actionable check and posture findings sorted from
	// highest to lowest effective severity.
	Findings []checks.Finding `json:"findings"`

	// WANSurface classifies every enabled WAN port forward into expected P2P/VPN,
	// public web entrypoints, or dangerous admin/RPC exposures.
	WANSurface []ExposureAssessment `json:"wan_surface,omitempty"`

	// PostureNotes captures network-wide architectural observations (such as an
	// unused isolated IoT VLAN or unnamed WAN-exposed hosts).
	PostureNotes []PostureNote `json:"posture_notes,omitempty"`
}

// State captures the minimal baseline persisted to disk between consecutive
// scans so `uniblue watch` only alerts on new issues or posture regressions.
type State struct {
	// UpdatedAt records when the baseline was last saved.
	UpdatedAt time.Time `json:"updated_at"`

	// Findings maps finding keys ("checkID|mac|port") to their last known
	// effective severity.
	Findings map[string]checks.Severity `json:"findings"`

	// TrustedClients maps normalized MAC addresses previously seen on a trusted
	// VLAN to their display names.
	TrustedClients map[string]string `json:"trusted_clients"`

	// PortForwards maps enabled port-forward keys to a human-readable summary.
	PortForwards map[string]string `json:"port_forwards"`
}

// Diff summarizes security-relevant changes between the previous persisted
// State and the current scan.
type Diff struct {
	// NewFindings lists findings that did not exist in the previous state.
	NewFindings []checks.Finding `json:"new_findings,omitempty"`

	// EscalatedFindings lists existing findings whose effective severity increased
	// (for example, a vulnerable IoT device was moved to a trusted VLAN or port-forwarded).
	EscalatedFindings []checks.Finding `json:"escalated_findings,omitempty"`

	// ResolvedKeys lists finding keys that were previously active and are now gone.
	ResolvedKeys []string `json:"resolved_keys,omitempty"`

	// NewTrustedClients lists previously unseen devices that appeared on a trusted VLAN.
	NewTrustedClients []unifi.Client `json:"new_trusted_clients,omitempty"`

	// NewPortForwards lists newly enabled WAN port-forwarding rules.
	NewPortForwards []unifi.PortForward `json:"new_port_forwards,omitempty"`
}

// HasAlerts reports whether Diff contains any notable event matching or
// exceeding minSeverity.
func (d Diff) HasAlerts(minSeverity checks.Severity) bool {
	for _, f := range d.NewFindings {
		if f.EffectiveSeverity >= minSeverity {
			return true
		}
	}
	for _, f := range d.EscalatedFindings {
		if f.EffectiveSeverity >= minSeverity {
			return true
		}
	}
	return len(d.NewTrustedClients) > 0 || len(d.NewPortForwards) > 0
}

// Evaluate applies UniFi blast-radius scoring to raw check findings and appends
// built-in UniFi posture findings (such as active WAN port forwards or
// upgradable UniFi infrastructure firmware).
func Evaluate(snap *unifi.Snapshot, rawFindings []checks.Finding, netCfg config.NetworkConfig) Report {
	trustedSet := toLowerSet(netCfg.TrustedVLANs)
	isolatedSet := toLowerSet(netCfg.IsolatedVLANs)

	// Index active clients by IP so port-forward rules can link back to client
	// metadata when generating posture findings.
	clientsByIP := make(map[string]unifi.Client, len(snap.Clients))
	for _, cl := range snap.Clients {
		if cl.IP != "" {
			clientsByIP[cl.IP] = cl
		}
	}

	// Index enabled port forwards by destination IP for O(1) exposure lookups.
	forwardsByIP := make(map[string][]unifi.PortForward)
	for _, pf := range snap.PortForwards {
		if pf.Enabled && pf.FwdIP != "" {
			forwardsByIP[pf.FwdIP] = append(forwardsByIP[pf.FwdIP], pf)
		}
	}

	classifier, _ := LoadExposureClassifier(rules.BuiltinFS)

	scored := make([]checks.Finding, 0, len(rawFindings)+len(snap.PortForwards))
	affectedClientIPs := make(map[string]struct{})
	for _, f := range rawFindings {
		f = scoreFinding(f, forwardsByIP[f.Client.IP], trustedSet, isolatedSet)
		scored = append(scored, f)
		if f.Client.IP != "" {
			affectedClientIPs[f.Client.IP] = struct{}{}
		}
	}

	// Classify every enabled WAN port forward using declarative exposure rules
	// (distinguishing expected Ethereum P2P / WireGuard listeners from risky web
	// proxies or critical RPC/RDP/database exposures).
	var wanSurface []ExposureAssessment
	for _, pf := range snap.PortForwards {
		if !pf.Enabled {
			continue
		}
		cl, known := clientsByIP[pf.FwdIP]
		if !known {
			cl = unifi.Client{IP: pf.FwdIP, Name: pf.Name}
		}

		assessment := classifier.Classify(pf, cl)
		var reasons []string
		if pf.Src == "" || strings.EqualFold(pf.Src, "any") {
			reasons = append(reasons, "open to any source IP on WAN")
		}
		// Only escalate non-P2P/VPN forwards that punch directly into a trusted VLAN.
		if assessment.Severity >= checks.SeverityMedium && matchesVLAN(cl, trustedSet) {
			assessment.Severity = assessment.Severity.Bump(1)
			reasons = append(reasons, fmt.Sprintf("forwards into trusted VLAN %q", vlanLabel(cl)))
		}
		wanSurface = append(wanSurface, assessment)

		// Expected P2P/VPN listeners stay in WANSurface (INFO) without cluttering
		// actionable Findings or waking up watch alerts.
		if assessment.Severity < checks.SeverityMedium {
			continue
		}

		scored = append(scored, checks.Finding{
			CheckID:           "UB-UNIFI-PORTFWD",
			Title:             fmt.Sprintf("%s (%s -> %s:%s)", assessment.RuleName, pf.DstPort, pf.FwdIP, pf.FwdPort),
			Category:          assessment.Class,
			BaseSeverity:      assessment.Severity,
			EffectiveSeverity: assessment.Severity,
			RiskReasons:       reasons,
			Client:            cl,
			Evidence:          fmt.Sprintf("rule %q forwards %s WAN:%s to %s:%s (src=%s)", pf.Name, pf.Proto, pf.DstPort, pf.FwdIP, pf.FwdPort, fallbackAny(pf.Src)),
			Remediation: checks.Remediation{
				Summary:      assessment.Summary,
				UniFiActions: assessment.Actions,
			},
		})
	}

	sort.Slice(wanSurface, func(i, j int) bool {
		if wanSurface[i].Severity != wanSurface[j].Severity {
			return wanSurface[i].Severity > wanSurface[j].Severity
		}
		return wanSurface[i].Forward.Name < wanSurface[j].Forward.Name
	})

	// Emit a low-severity posture finding for UniFi infrastructure gear running
	// outdated firmware reported as upgradable by the controller.
	cleanUniFi := 0
	for _, dev := range snap.Devices {
		if !dev.Upgradable {
			cleanUniFi++
			continue
		}
		scored = append(scored, checks.Finding{
			CheckID:           "UB-UNIFI-FIRMWARE",
			Title:             fmt.Sprintf("UniFi Device Firmware Update Available (%s)", dev.Model),
			Category:          "firmware",
			BaseSeverity:      checks.SeverityLow,
			EffectiveSeverity: checks.SeverityLow,
			Client: unifi.Client{
				MAC:  dev.MAC,
				IP:   dev.IP,
				Name: dev.Name,
				OUI:  "Ubiquiti",
			},
			Evidence: fmt.Sprintf("%s (%s) is running firmware %s with a newer release available", dev.Name, dev.Model, dev.Version),
			Remediation: checks.Remediation{
				Summary:      "Review Ubiquiti release notes and update device firmware to ensure security patches are applied.",
				UniFiActions: []string{"update_unifi_firmware"},
			},
		})
	}

	sort.Slice(scored, func(i, j int) bool {
		if scored[i].EffectiveSeverity != scored[j].EffectiveSeverity {
			return scored[i].EffectiveSeverity > scored[j].EffectiveSeverity
		}
		if scored[i].Client.IP != scored[j].Client.IP {
			return scored[i].Client.IP < scored[j].Client.IP
		}
		return scored[i].CheckID < scored[j].CheckID
	})

	cleanClients := 0
	for _, cl := range snap.Clients {
		if _, bad := affectedClientIPs[cl.IP]; !bad {
			cleanClients++
		}
	}

	postureNotes := AnalyzePosture(snap, scored, netCfg)

	return Report{
		GeneratedAt:       time.Now().UTC(),
		Site:              snap.Site,
		ClientCount:       len(snap.Clients),
		CleanClients:      cleanClients,
		UniFiDeviceCount:  len(snap.Devices),
		CleanUniFiDevices: cleanUniFi,
		Findings:          scored,
		WANSurface:        wanSurface,
		PostureNotes:      postureNotes,
	}
}

// scoreFinding adjusts a finding's EffectiveSeverity based on whether the
// vulnerable port is WAN-exposed or placed on a trusted vs. isolated VLAN.
func scoreFinding(f checks.Finding, forwards []unifi.PortForward, trustedSet, isolatedSet map[string]struct{}) checks.Finding {
	f.EffectiveSeverity = f.BaseSeverity
	f.RiskReasons = nil

	// Check WAN exposure first: a vulnerable service reachable directly from the
	// internet is always treated as Critical regardless of internal VLAN.
	for _, pf := range forwards {
		if pf.ExposesPort(f.Port) {
			f.EffectiveSeverity = checks.SeverityCritical
			f.RiskReasons = append(f.RiskReasons, fmt.Sprintf("exposed to WAN via port forward %q (WAN:%s)", pf.Name, pf.DstPort))
			return f
		}
	}

	if matchesVLAN(f.Client, trustedSet) {
		f.EffectiveSeverity = f.EffectiveSeverity.Bump(1)
		f.RiskReasons = append(f.RiskReasons, fmt.Sprintf("hosted on trusted VLAN %q", vlanLabel(f.Client)))
	} else if matchesVLAN(f.Client, isolatedSet) {
		f.EffectiveSeverity = f.EffectiveSeverity.Bump(-1)
		f.RiskReasons = append(f.RiskReasons, fmt.Sprintf("mitigated on isolated VLAN %q", vlanLabel(f.Client)))
	}
	return f
}

// BuildState extracts a compact State baseline from a UniFi snapshot and its
// evaluated Report.
func BuildState(snap *unifi.Snapshot, report Report, netCfg config.NetworkConfig) *State {
	trustedSet := toLowerSet(netCfg.TrustedVLANs)

	st := &State{
		UpdatedAt:      time.Now().UTC(),
		Findings:       make(map[string]checks.Severity, len(report.Findings)),
		TrustedClients: make(map[string]string),
		PortForwards:   make(map[string]string),
	}
	for _, f := range report.Findings {
		st.Findings[f.Key()] = f.EffectiveSeverity
	}
	for _, cl := range snap.Clients {
		if cl.MAC != "" && matchesVLAN(cl, trustedSet) {
			st.TrustedClients[cl.MAC] = cl.DisplayName()
		}
	}
	for _, pf := range snap.PortForwards {
		if pf.Enabled {
			st.PortForwards[portForwardKey(pf)] = fmt.Sprintf("%s (%s:%s -> %s:%s)", pf.Name, pf.Proto, pf.DstPort, pf.FwdIP, pf.FwdPort)
		}
	}
	return st
}

// ComputeDiff compares a previous baseline against the current scan and returns
// only newly introduced, escalated, or newly appearing high-trust items. When
// prev is nil (first run), all active findings are treated as new while device
// and port-forward baselines are initialized quietly.
func ComputeDiff(prev *State, snap *unifi.Snapshot, report Report, netCfg config.NetworkConfig) Diff {
	var diff Diff
	trustedSet := toLowerSet(netCfg.TrustedVLANs)

	if prev == nil {
		diff.NewFindings = append(diff.NewFindings, report.Findings...)
		return diff
	}

	currentKeys := make(map[string]struct{}, len(report.Findings))
	for _, f := range report.Findings {
		key := f.Key()
		currentKeys[key] = struct{}{}
		oldSev, existed := prev.Findings[key]
		if !existed {
			diff.NewFindings = append(diff.NewFindings, f)
		} else if f.EffectiveSeverity > oldSev {
			diff.EscalatedFindings = append(diff.EscalatedFindings, f)
		}
	}

	for oldKey := range prev.Findings {
		if _, stillActive := currentKeys[oldKey]; !stillActive {
			diff.ResolvedKeys = append(diff.ResolvedKeys, oldKey)
		}
	}
	sort.Strings(diff.ResolvedKeys)

	for _, cl := range snap.Clients {
		if cl.MAC == "" || !matchesVLAN(cl, trustedSet) {
			continue
		}
		if _, known := prev.TrustedClients[cl.MAC]; !known {
			diff.NewTrustedClients = append(diff.NewTrustedClients, cl)
		}
	}

	for _, pf := range snap.PortForwards {
		if !pf.Enabled {
			continue
		}
		if _, known := prev.PortForwards[portForwardKey(pf)]; !known {
			diff.NewPortForwards = append(diff.NewPortForwards, pf)
		}
	}

	return diff
}

// LoadState reads a previously saved State from path. If the file does not
// exist yet, it returns (nil, nil) so callers treat the run as a first baseline.
func LoadState(path string) (*State, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read state %q: %w", path, err)
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("parse state %q: %w", path, err)
	}
	return &st, nil
}

// SaveState writes st atomically to path using a temp file + rename so an
// interrupted watch loop never leaves a half-written state file behind.
func SaveState(path string, st *State) error {
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create state dir %q: %w", dir, err)
		}
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("write temp state %q: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("commit state %q: %w", path, err)
	}
	return nil
}

// matchesVLAN reports whether a client's resolved network name or numeric VLAN
// tag appears in the configured lowercase set.
func matchesVLAN(cl unifi.Client, set map[string]struct{}) bool {
	if len(set) == 0 {
		return false
	}
	if cl.NetworkName != "" {
		if _, ok := set[strings.ToLower(cl.NetworkName)]; ok {
			return true
		}
	}
	if cl.VLAN != "" {
		if _, ok := set[strings.ToLower(cl.VLAN)]; ok {
			return true
		}
	}
	return false
}

// vlanLabel returns a readable VLAN identifier for risk reason messages.
func vlanLabel(cl unifi.Client) string {
	if cl.NetworkName != "" {
		return cl.NetworkName
	}
	if cl.VLAN != "" {
		return "VLAN " + cl.VLAN
	}
	return "unknown"
}

// portForwardKey creates a stable key for tracking enabled port-forward rules.
func portForwardKey(pf unifi.PortForward) string {
	return fmt.Sprintf("%s|%s|%s|%s", pf.Proto, pf.DstPort, pf.FwdIP, pf.FwdPort)
}

// toLowerSet normalizes a string slice into a trimmed, lowercase lookup map.
func toLowerSet(items []string) map[string]struct{} {
	set := make(map[string]struct{}, len(items))
	for _, s := range items {
		if norm := strings.ToLower(strings.TrimSpace(s)); norm != "" {
			set[norm] = struct{}{}
		}
	}
	return set
}

// fallbackAny returns "any" when a UniFi port-forward source restriction is empty.
func fallbackAny(src string) string {
	if strings.TrimSpace(src) == "" {
		return "any"
	}
	return src
}
