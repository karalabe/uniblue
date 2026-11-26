// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package risk correlates raw device findings with UniFi network topology
// (VLAN trust tiers and WAN port forwards), computes effective blast-radius
// severity, and tracks state across scans to alert only on meaningful changes.
package risk

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/unifi"
	"github.com/karalabe/uniblue/rules"
)

// offlineFindingTTL bounds how long findings for an offline client host are
// carried forward in persisted state before aging out as resolved.
const offlineFindingTTL = 7 * 24 * time.Hour

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

	// SwitchPorts holds physical Ethernet/SFP port allocation, perimeter zoning,
	// connected peers, and port-security status for every UniFi switch, gateway,
	// and In-Wall AP.
	SwitchPorts []SwitchDeviceView `json:"switch_ports,omitempty"`

	// UniFiPosture summarizes gateway security controls, Wi-Fi SSID posture,
	// neighboring AP/evil-twin counts, WAN/VPN health, and recent controller logs.
	UniFiPosture *UniFiPostureSummary `json:"unifi_posture,omitempty"`

	// Isolation holds the effective boundary evaluation matrix across zones,
	// IPv4/IPv6 families, gateway vs. L3-switch routing, and L2 Wi-Fi/wired paths.
	Isolation *IsolationMatrix `json:"isolation,omitempty"`
}

// State captures the minimal baseline persisted to disk between consecutive
// scans so `uniblue watch` only alerts on new issues or posture regressions.
type State struct {
	// UpdatedAt records when the baseline was last saved.
	UpdatedAt time.Time `json:"updated_at"`

	// Findings maps finding keys ("checkID|mac|port") to their last known
	// effective severity.
	Findings map[string]checks.Severity `json:"findings"`

	// FindingLastSeen records when each finding key was last actively observed
	// (UTC). Carried-forward findings for offline or unprobed hosts age out
	// after offlineFindingTTL so permanently departed or excluded hosts do not
	// stay forever.
	FindingLastSeen map[string]time.Time `json:"finding_last_seen,omitempty"`

	// CarriedFindings marks finding keys retained only via online-unprobed
	// carry-forward so ComputeDiff does not re-emit them in ResolvedKeys on
	// every cycle while they remain within offlineFindingTTL.
	CarriedFindings map[string]bool `json:"carried_findings,omitempty"`

	// TrustedClients maps normalized MAC addresses previously seen on a trusted
	// VLAN to their display names.
	TrustedClients map[string]string `json:"trusted_clients"`

	// PortForwards maps enabled port-forward keys to a human-readable summary.
	PortForwards map[string]string `json:"port_forwards"`

	// ExactCVEs maps exact-version CVE alert keys ("host|product|version|cveID")
	// to their last known status ("high", "critical", "high|kev", etc.) so only
	// newly matched or newly KEV-promoted exact CVEs trigger outbound webhooks.
	// A nil map indicates the CVE baseline has not been seeded yet.
	ExactCVEs map[string]string `json:"exact_cves,omitempty"`

	// ExactCVELastSeen records when each exact-version CVE key was last actively
	// observed (UTC) so transient banner misses or offline hosts do not cause
	// flapping alerts while genuinely patched CVEs age out cleanly.
	ExactCVELastSeen map[string]time.Time `json:"exact_cve_last_seen,omitempty"`
}

// AlertEvent represents a high-signal live security event (admin activity,
// firewall or config drift, honeypot hit, edge physical tamper, evil-twin AP,
// or trusted-VLAN medium swap) forwarded via webhook alongside diff changes.
type AlertEvent struct {
	Type     string          `json:"type"`
	Severity checks.Severity `json:"severity"`
	Time     time.Time       `json:"time,omitempty"`
	Host     string          `json:"host,omitempty"`
	IP       string          `json:"ip,omitempty"`
	Summary  string          `json:"summary"`
}

// CVEAlert represents a newly matched or newly KEV-promoted exact-version CVE
// on a LAN host or UniFi infrastructure appliance.
type CVEAlert struct {
	CVEID           string          `json:"cve_id"`
	HostName        string          `json:"host_name"`
	HostIP          string          `json:"host_ip"`
	VLAN            string          `json:"vlan,omitempty"`
	Product         string          `json:"product"`
	Version         string          `json:"version,omitempty"`
	Severity        checks.Severity `json:"severity"`
	CVSS            float64         `json:"cvss,omitempty"`
	KEV             bool            `json:"kev,omitempty"`
	WANExposed      bool            `json:"wan_exposed,omitempty"`
	MinFixedVersion string          `json:"min_fixed_version,omitempty"`
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

	// NewCVEs lists newly matched (or newly KEV-listed) exact-version CVEs.
	NewCVEs []CVEAlert `json:"new_cves,omitempty"`

	// Events lists high-signal live security events warranting operator or agent review.
	Events []AlertEvent `json:"events,omitempty"`
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
	for _, c := range d.NewCVEs {
		if c.KEV || c.Severity >= minSeverity {
			return true
		}
	}
	for _, ev := range d.Events {
		if ev.Severity >= minSeverity {
			return true
		}
	}
	return len(d.NewTrustedClients) > 0 || len(d.NewPortForwards) > 0
}

// IsClientOnTrustedVLAN reports whether cl sits on a VLAN classified as trusted
// by UniBlue's VLAN tier resolution.
func IsClientOnTrustedVLAN(snap *unifi.Snapshot, cl unifi.Client, netCfg config.NetworkConfig) bool {
	trustedSet, _ := resolveVLANTiers(snap, netCfg)
	return matchesVLAN(cl, trustedSet)
}

// Evaluate applies UniFi blast-radius scoring to raw check findings and appends
// built-in UniFi posture findings (such as active WAN port forwards or
// upgradable UniFi infrastructure firmware).
func Evaluate(snap *unifi.Snapshot, rawFindings []checks.Finding, netCfg config.NetworkConfig) Report {
	trustedSet, isolatedSet := resolveVLANTiers(snap, netCfg)

	// Index active clients by IP so port-forward rules can link back to client
	// metadata when generating posture findings.
	clientsByIP := make(map[string]unifi.Client, len(snap.Clients))
	for _, cl := range snap.Clients {
		for _, ip := range cl.AllIPs() {
			clientsByIP[canonicalIsolationIP(ip)] = cl
		}
	}

	// Index enabled port forwards by destination IP for O(1) exposure lookups.
	forwardsByIP := make(map[string][]unifi.PortForward)
	for _, pf := range snap.PortForwards {
		if pf.Enabled && pf.FwdIP != "" {
			ip := canonicalIsolationIP(pf.FwdIP)
			forwardsByIP[ip] = append(forwardsByIP[ip], pf)
		}
	}

	classifier, _ := LoadExposureClassifier(rules.BuiltinFS)

	scored := make([]checks.Finding, 0, len(rawFindings)+len(snap.PortForwards))
	for _, f := range rawFindings {
		var forwards []unifi.PortForward
		for _, ip := range f.EndpointIPs() {
			forwards = append(forwards, forwardsByIP[canonicalIsolationIP(ip)]...)
		}
		f = scoreFinding(f, forwards, trustedSet, isolatedSet)
		scored = append(scored, f)
	}

	// Classify every enabled WAN port forward using declarative exposure rules
	// (distinguishing expected Ethereum P2P / WireGuard listeners from risky web
	// proxies or critical RPC/RDP/database exposures).
	var wanSurface []ExposureAssessment
	for _, pf := range snap.PortForwards {
		if !pf.Enabled {
			continue
		}
		cl, known := clientsByIP[canonicalIsolationIP(pf.FwdIP)]
		if !known {
			cl = unifi.Client{IP: pf.FwdIP, Name: pf.Name}
			if net, ok := lookupNetworkByIP(snap, pf.FwdIP); ok {
				cl.NetworkID = net.ID
				cl.NetworkName = net.Name
				cl.VLAN = net.VLAN
			}
		}

		assessment := classifier.Classify(pf, cl)
		var reasons []string
		if pf.SourceUnknown {
			reasons = append(reasons, "WAN source filter unresolved")
		} else if !pf.IsSourceRestricted() {
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

		fwdProp := "portfwd:" + firstNonEmptyStr(pf.ID, fmt.Sprintf("%s-%s-%s-%s", pf.Proto, pf.DstPort, pf.FwdIP, pf.FwdPort))
		fwdPort := 0
		if expanded := pf.ExpandFwdPorts(1); len(expanded) > 0 {
			fwdPort = expanded[0]
		}
		scored = append(scored, checks.Finding{
			CheckID:           "UB-UNIFI-PORTFWD",
			Title:             fmt.Sprintf("%s (%s -> %s:%s)", assessment.RuleName, pf.DstPort, pf.FwdIP, pf.FwdPort),
			Category:          assessment.Class,
			Property:          fwdProp,
			Port:              fwdPort,
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

	// Audit Zone-Based Firewall policies generically for overly permissive
	// WAN-to-Gateway, WAN-to-LAN, or isolated-zone-to-Internal ALLOW rules.
	scored = append(scored, auditFirewallPolicies(snap)...)

	// Analyze physical switch/gateway/In-Wall AP port allocations and external
	// cable perimeter security (including LLDP parent feeder ports).
	switchPorts, portFindings, portNotes := AnalyzeSwitchPorts(snap, netCfg, trustedSet, isolatedSet)
	scored = append(scored, portFindings...)

	// Audit Wi-Fi SSIDs, Evil-Twin/Rogue APs, UniFi device SSH, UPnP, IDS/IPS,
	// Honeypot, DNS Shield, and recent controller security logs.
	unifiPosture, postureFindings, unifiNotes := AnalyzeUniFiPosture(snap, trustedSet, isolatedSet, netCfg.IsolationPolicy.ManagementVLANs...)
	scored = append(scored, postureFindings...)

	// Evaluate effective inter-zone, IPv4/IPv6, gateway/switch-routed, and L2
	// isolation boundaries, plus extended infrastructure and health checks.
	isoMatrix, isoFindings, isoNotes := EvaluateIsolation(snap, rawFindings, netCfg)
	scored = append(scored, isoFindings...)
	extFindings, extNotes := AnalyzeExtendedNetworkChecks(snap, netCfg)
	scored = append(scored, extFindings...)

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
		if scored[i].CheckID != scored[j].CheckID {
			return scored[i].CheckID < scored[j].CheckID
		}
		return scored[i].Port < scored[j].Port
	})

	affectedClientIPs := make(map[string]struct{})
	affectedClientMACs := make(map[string]struct{})
	for _, f := range scored {
		if f.IsInventoryOnly() {
			continue
		}
		if f.Client.IP != "" {
			affectedClientIPs[f.Client.IP] = struct{}{}
		}
		if m := strings.ToLower(strings.TrimSpace(f.Client.MAC)); m != "" && !strings.HasPrefix(m, "fw:") && !strings.HasPrefix(m, "gw:") {
			affectedClientMACs[m] = struct{}{}
		}
	}

	cleanClients := 0
	for _, cl := range snap.Clients {
		_, badIP := affectedClientIPs[cl.IP]
		_, badMAC := affectedClientMACs[strings.ToLower(strings.TrimSpace(cl.MAC))]
		if !badIP && !badMAC {
			cleanClients++
		}
	}

	postureNotes := AnalyzePosture(snap, scored, netCfg)
	postureNotes = append(postureNotes, portNotes...)
	postureNotes = append(postureNotes, unifiNotes...)
	postureNotes = append(postureNotes, isoNotes...)
	postureNotes = append(postureNotes, extNotes...)

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
		SwitchPorts:       switchPorts,
		UniFiPosture:      unifiPosture,
		Isolation:         isoMatrix,
	}
}

// scoreFinding adjusts a finding's EffectiveSeverity based on whether the
// vulnerable port is WAN-exposed (matching L4 transport, translated destination
// port, and WAN source restrictions) or placed on a trusted vs. isolated VLAN.
// Pure inventory observations (asset-identity / service-advertised /
// service-observed at Info severity) are preserved as Info without escalation.
func scoreFinding(f checks.Finding, forwards []unifi.PortForward, trustedSet, isolatedSet map[string]struct{}) checks.Finding {
	f.EffectiveSeverity = f.BaseSeverity
	f.RiskReasons = nil

	if f.IsInventoryOnly() {
		return f
	}

	transport := f.EffectiveTransport()
	// Check WAN exposure across ALL matching forwards (worst severity wins so an
	// earlier source-restricted forward never hides a later open src=any forward).
	matchedWAN := false
	bestSev := f.BaseSeverity
	for _, pf := range forwards {
		if !pf.ExposesEndpoint(f.Port, transport) {
			continue
		}
		matchedWAN = true
		if pf.SourceUnknown {
			// Treat an unresolved WAN source filter at least as severely as a
			// source-restricted WAN forward so exposure is never scored below
			// an unforwarded trusted-VLAN host.
			cand := f.BaseSeverity.Bump(1)
			if cand > bestSev {
				bestSev = cand
			}
			f.RiskReasons = append(f.RiskReasons, fmt.Sprintf(
				"exposed via %s WAN forward %q with unresolved source filter (WAN:%s -> %s:%s)",
				strings.ToUpper(transport), pf.Name, pf.DstPort, pf.FwdIP, pf.FwdPort,
			))
			continue
		}
		if pf.IsSourceRestricted() {
			cand := f.BaseSeverity.Bump(1)
			if cand > bestSev {
				bestSev = cand
			}
			f.RiskReasons = append(f.RiskReasons, fmt.Sprintf(
				"exposed via source-restricted %s WAN forward %q (WAN:%s -> %s:%s, src=%s)",
				strings.ToUpper(transport), pf.Name, pf.DstPort, pf.FwdIP, pf.FwdPort, pf.Src,
			))
		} else {
			bestSev = checks.SeverityCritical
			f.RiskReasons = append(f.RiskReasons, fmt.Sprintf(
				"exposed to WAN via %s port forward %q (WAN:%s -> %s:%s, src=any)",
				strings.ToUpper(transport), pf.Name, pf.DstPort, pf.FwdIP, pf.FwdPort,
			))
		}
	}
	if matchedWAN {
		f.EffectiveSeverity = bestSev
		return f
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
// evaluated Report, retaining the highest EffectiveSeverity whenever two
// findings share a key.
func BuildState(snap *unifi.Snapshot, report Report, netCfg config.NetworkConfig) *State {
	return BuildStateWithPrev(nil, snap, report, netCfg, nil)
}

// BuildStateWithPrev constructs the next persisted baseline while carrying
// forward known TrustedClients and findings belonging to hosts that are
// temporarily offline or not yet rescanned, preventing false "[NEW TRUSTED
// DEVICE]" and "[NEW ...]" alert storms across brief reconnects or restarts.
//
// When probedHostKeys is non-nil, only hosts present in probedHostKeys have
// their previous host-scoped findings eligible to expire/resolve; hosts absent
// from snap.Clients always retain their previous host-scoped findings until
// they return and are rescanned.
func BuildStateWithPrev(prev *State, snap *unifi.Snapshot, report Report, netCfg config.NetworkConfig, probedHostKeys map[string]struct{}) *State {
	trustedSet, _ := resolveVLANTiers(snap, netCfg)
	now := time.Now().UTC()

	st := &State{
		UpdatedAt:       now,
		Findings:        make(map[string]checks.Severity, len(report.Findings)),
		FindingLastSeen: make(map[string]time.Time, len(report.Findings)),
		TrustedClients:  make(map[string]string),
		PortForwards:    make(map[string]string),
	}

	// Carry forward previously known trusted clients so a household phone or
	// rebooting NAS is never re-alerted as a brand-new trusted device.
	if prev != nil {
		for mac, name := range prev.TrustedClients {
			st.TrustedClients[mac] = name
		}
	}

	activeHosts := activeClientHostSet(snap)

	migratedLegacyKeys := make(map[string]struct{})
	for _, f := range report.Findings {
		if f.IsInventoryOnly() {
			continue
		}
		k := stateFindingKey(f)
		for _, legacyKey := range legacyBaseFindingKeys(k) {
			migratedLegacyKeys[legacyKey] = struct{}{}
		}
		sev := f.EffectiveSeverity
		// If a port-forward target host is temporarily offline and its VLAN could
		// not be resolved from configured subnets, retain the previous severity
		// so a host reboot never causes a false downgrade followed by escalation.
		if f.CheckID == "UB-UNIFI-PORTFWD" && prev != nil {
			ipLow := strings.ToLower(strings.TrimSpace(f.Client.IP))
			_, targetOnline := activeHosts[ipLow]
			if !targetOnline {
				if prevSev, ok := prev.Findings[k]; ok && prevSev > sev {
					sev = prevSev
				}
			}
		}
		if existing, ok := st.Findings[k]; !ok || sev > existing {
			st.Findings[k] = sev
		}
		st.FindingLastSeen[k] = now
	}

	// Carry forward previous host-scoped findings for offline or not-yet-probed
	// hosts so transient disconnects never drop and re-alert unchanged findings,
	// while expiring findings for permanently gone or unprobed hosts after
	// offlineFindingTTL.
	if prev != nil && snap != nil {
		for k, sev := range prev.Findings {
			if _, exists := st.Findings[k]; exists {
				continue
			}
			if _, migrated := migratedLegacyKeys[k]; migrated {
				continue
			}
			checkID, hostID := splitFindingKey(k)
			if !isClientScopedFinding(checkID, hostID) {
				continue
			}
			hostLow := strings.ToLower(strings.TrimSpace(hostID))
			_, isActive := activeHosts[hostLow]
			if !isActive {
				lastSeen := findingLastSeen(prev, k, now)
				if now.Sub(lastSeen) <= offlineFindingTTL {
					st.Findings[k] = sev
					st.FindingLastSeen[k] = lastSeen
				}
				continue
			}
			if probedHostKeys != nil {
				if _, wasProbed := probedHostKeys[hostLow]; !wasProbed {
					lastSeen := findingLastSeen(prev, k, now)
					if now.Sub(lastSeen) <= offlineFindingTTL {
						st.Findings[k] = sev
						st.FindingLastSeen[k] = lastSeen
						if st.CarriedFindings == nil {
							st.CarriedFindings = make(map[string]bool)
						}
						st.CarriedFindings[k] = true
					}
				}
			}
		}
	}

	if snap != nil {
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
	}
	if prev != nil && prev.ExactCVEs != nil {
		st.ExactCVEs = make(map[string]string, len(prev.ExactCVEs))
		for k, v := range prev.ExactCVEs {
			st.ExactCVEs[k] = v
		}
	}
	if prev != nil && prev.ExactCVELastSeen != nil {
		st.ExactCVELastSeen = make(map[string]time.Time, len(prev.ExactCVELastSeen))
		for k, v := range prev.ExactCVELastSeen {
			st.ExactCVELastSeen[k] = v
		}
	}
	return st
}

// activeClientHostSet builds a normalized lookup set of all MACs and IPs for
// currently online clients in snap.
func activeClientHostSet(snap *unifi.Snapshot) map[string]struct{} {
	if snap == nil {
		return nil
	}
	activeHosts := make(map[string]struct{}, len(snap.Clients)*2)
	for _, cl := range snap.Clients {
		if m := strings.ToLower(strings.TrimSpace(cl.MAC)); m != "" {
			activeHosts[m] = struct{}{}
		}
		for _, ip := range cl.AllIPs() {
			activeHosts[strings.ToLower(strings.TrimSpace(ip))] = struct{}{}
		}
	}
	return activeHosts
}

// stateFindingKey returns the persisted state key for f. For WAN port forwards,
// the key is anchored to the stable port-forward identifier rather than the
// target client's MAC/IP so an offline host never flips the key and re-alerts.
func stateFindingKey(f checks.Finding) string {
	if f.CheckID == "UB-UNIFI-PORTFWD" && strings.HasPrefix(f.Property, "portfwd:") {
		return fmt.Sprintf("%s|%s|%d", f.CheckID, f.Property, f.Port)
	}
	return f.Key()
}

// isClientScopedFinding reports whether a state finding key belongs to an
// individual LAN client host (as opposed to site-wide, gateway, switch, VLAN,
// WLAN, or firewall-policy posture) and should be carried forward across brief
// host offline windows.
func isClientScopedFinding(checkID, hostID string) bool {
	if hostID == "" {
		return false
	}
	hostLow := strings.ToLower(strings.TrimSpace(hostID))
	for _, pfx := range []string{"fw:", "gw:", "iso:", "vlan:", "wlan:", "portfwd:"} {
		if strings.HasPrefix(hostLow, pfx) {
			return false
		}
	}
	if !strings.HasPrefix(checkID, "UB-UNIFI-") {
		return true
	}
	switch checkID {
	case "UB-UNIFI-ISO-BMC-PATH",
		"UB-UNIFI-ISO-BMC-IPV6",
		"UB-UNIFI-BMC-SHARED-VLAN",
		"UB-UNIFI-ISO-PRINTER-ADMIN",
		"UB-UNIFI-WIFI-ROGUE-WIRED-AP":
		return true
	default:
		return false
	}
}

// findingLastSeen resolves the last actively observed timestamp for a finding
// key in prev, falling back to prev.UpdatedAt and then fallback for legacy
// state files that predate FindingLastSeen.
func findingLastSeen(prev *State, key string, fallback time.Time) time.Time {
	if prev != nil {
		if ts, ok := prev.FindingLastSeen[key]; ok && !ts.IsZero() {
			return ts
		}
		if !prev.UpdatedAt.IsZero() {
			return prev.UpdatedAt
		}
	}
	return fallback
}

// shouldCarryForward reports whether oldKey belongs to an offline or
// online-but-unprobed client host whose finding is still within
// offlineFindingTTL and should be retained silently rather than emitted as
// resolved.
func shouldCarryForward(prev *State, oldKey string, activeHosts, probedHostKeys map[string]struct{}, now time.Time) bool {
	checkID, hostID := splitFindingKey(oldKey)
	if !isClientScopedFinding(checkID, hostID) {
		return false
	}
	lastSeen := findingLastSeen(prev, oldKey, now)
	if now.Sub(lastSeen) > offlineFindingTTL {
		return false
	}
	hostLow := strings.ToLower(strings.TrimSpace(hostID))
	if _, isActive := activeHosts[hostLow]; !isActive {
		return true
	}
	if probedHostKeys != nil {
		_, wasProbed := probedHostKeys[hostLow]
		return !wasProbed
	}
	return prev != nil && prev.CarriedFindings[oldKey]
}

// legacyBaseFindingKeys returns legacy finding key formats from older state
// files (the 3-part "<CheckID>|<host>|<port>" key and, for non-TCP transports,
// the 4-part "<CheckID>|<host>|<port>|<transport>" key without property).
func legacyBaseFindingKeys(key string) []string {
	parts := strings.Split(key, "|")
	if len(parts) <= 3 {
		return nil
	}
	base3 := parts[0] + "|" + parts[1] + "|" + parts[2]
	if len(parts) == 5 && parts[4] != "" && parts[4] != "tcp" {
		return []string{base3 + "|" + parts[4], base3}
	}
	return []string{base3}
}

// splitFindingKey extracts the CheckID and host identifier from a Finding.Key()
// formatted as "<CheckID>|<host>|<port>[|<property>]".
func splitFindingKey(key string) (checkID, host string) {
	parts := strings.Split(key, "|")
	if len(parts) < 2 {
		return key, ""
	}
	return parts[0], parts[1]
}

// ComputeDiff compares a previous baseline against the current scan and returns
// only newly introduced, escalated, or newly appearing high-trust items. When
// prev is nil (first run), all active findings are treated as new while device
// and port-forward baselines are initialized quietly.
func ComputeDiff(prev *State, snap *unifi.Snapshot, report Report, netCfg config.NetworkConfig) Diff {
	return ComputeDiffWithProbed(prev, snap, report, netCfg, nil)
}

// ComputeDiffWithProbed compares a previous baseline against the current scan
// while honoring probedHostKeys so findings on online-but-unprobed hosts are
// silently carried forward within offlineFindingTTL rather than emitted as
// resolved.
func ComputeDiffWithProbed(prev *State, snap *unifi.Snapshot, report Report, netCfg config.NetworkConfig, probedHostKeys map[string]struct{}) Diff {
	var diff Diff
	trustedSet, _ := resolveVLANTiers(snap, netCfg)

	if prev == nil {
		for _, f := range report.Findings {
			if !f.IsInventoryOnly() {
				diff.NewFindings = append(diff.NewFindings, f)
			}
		}
		return diff
	}

	now := time.Now().UTC()
	activeHosts := activeClientHostSet(snap)

	currentKeys := make(map[string]struct{}, len(report.Findings))
	matchedPrevKeys := make(map[string]struct{}, len(report.Findings))
	for _, f := range report.Findings {
		if f.IsInventoryOnly() {
			continue
		}
		key := stateFindingKey(f)
		currentKeys[key] = struct{}{}
		oldSev, existed := prev.Findings[key]
		if existed {
			matchedPrevKeys[key] = struct{}{}
		} else {
			for _, legacyKey := range legacyBaseFindingKeys(key) {
				if legacySev, legacyExisted := prev.Findings[legacyKey]; legacyExisted {
					oldSev = legacySev
					existed = true
					matchedPrevKeys[legacyKey] = struct{}{}
					break
				}
			}
		}
		if !existed {
			diff.NewFindings = append(diff.NewFindings, f)
		} else if f.EffectiveSeverity > oldSev {
			diff.EscalatedFindings = append(diff.EscalatedFindings, f)
		}
	}

	for oldKey := range prev.Findings {
		if _, stillActive := currentKeys[oldKey]; stillActive {
			continue
		}
		if _, migrated := matchedPrevKeys[oldKey]; migrated {
			continue
		}
		if snap != nil && shouldCarryForward(prev, oldKey, activeHosts, probedHostKeys, now) {
			continue
		}
		diff.ResolvedKeys = append(diff.ResolvedKeys, oldKey)
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
	if dir == "" {
		dir = "."
	}
	if dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create state dir %q: %w", dir, err)
		}
	}

	tmpFile, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temp state in %q: %w", dir, err)
	}
	tmp := tmpFile.Name()
	if err := tmpFile.Chmod(0o600); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("chmod temp state %q: %w", tmp, err)
	}
	if _, err := tmpFile.Write(raw); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("write temp state %q: %w", tmp, err)
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close temp state %q: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("commit state %q: %w", path, err)
	}
	return nil
}

// resolveVLANTiers merges any explicit user-configured trusted/isolated VLANs
// with factual topology metadata from UniFi itself: Firewall Zones (Internal vs
// Hotspot/Dmz or any user zone blocked from Internal), explicit Network
// Isolation flags, and UniFi's structural network purpose ("corporate" vs "guest").
// It never guesses trust tiers from user-chosen VLAN names.
func resolveVLANTiers(snap *unifi.Snapshot, netCfg config.NetworkConfig) (trusted, isolated map[string]struct{}) {
	trusted = toLowerSet(netCfg.TrustedVLANs)
	isolated = toLowerSet(netCfg.IsolatedVLANs)
	if snap == nil {
		return trusted, isolated
	}

	isoZones := isolatedZoneSet(snap)
	intendedIsoZones := intendedIsolatedZoneSet(snap)

	for _, n := range snap.Networks {
		nameLower := strings.ToLower(strings.TrimSpace(n.Name))
		vlanLower := strings.ToLower(strings.TrimSpace(n.VLAN))
		if nameLower == "" && vlanLower == "" {
			continue
		}

		// Skip non-LAN entries (WAN uplinks and remote-user VPN pools).
		purposeLower := strings.ToLower(strings.TrimSpace(n.Purpose))
		zoneLower := strings.ToLower(strings.TrimSpace(n.ZoneName))
		if purposeLower == "wan" || purposeLower == "remote-user-vpn" ||
			zoneLower == "external" || zoneLower == "vpn" || zoneLower == "gateway" {
			continue
		}

		// Respect explicit user placement before applying UniFi structural metadata.
		if _, ok := trusted[nameLower]; ok {
			continue
		}
		if _, ok := isolated[nameLower]; ok {
			continue
		}
		if vlanLower != "" {
			if _, ok := trusted[vlanLower]; ok {
				continue
			}
			if _, ok := isolated[vlanLower]; ok {
				continue
			}
		}

		switch {
		case n.IsolationEnabled || purposeLower == "guest" || isoZones[zoneLower]:
			if nameLower != "" {
				isolated[nameLower] = struct{}{}
			}
			if vlanLower != "" {
				isolated[vlanLower] = struct{}{}
			}
		case intendedIsoZones[zoneLower]:
			// Custom zones with isolation intent (e.g., a shadowed, narrow, or
			// leaking BLOCK toward Internal) do NOT earn the isolated-VLAN
			// mitigation downgrade, but must also never fall through into
			// trustedSet (which would suppress leak auditing and trigger false
			// new-trusted-device alerts).
		case zoneLower == "internal" || purposeLower == "corporate" || vlanLower == "1":
			if nameLower != "" {
				trusted[nameLower] = struct{}{}
			}
			if vlanLower != "" {
				trusted[vlanLower] = struct{}{}
			}
		}
	}
	return trusted, isolated
}

// IsolatedZones returns the lowercase set of UniFi firewall zone names that
// effectively enforce isolation from Internal LANs. Shared by topology and risk
// so both packages agree on zone isolation semantics.
func IsolatedZones(snap *unifi.Snapshot) map[string]bool {
	return isolatedZoneSet(snap)
}

func zoneLANNetworks(snap *unifi.Snapshot, zone string) []unifi.Network {
	var nets []unifi.Network
	for _, n := range snap.Networks {
		switch strings.ToLower(strings.TrimSpace(n.Purpose)) {
		case "wan", "wan2", "remote-user-vpn":
			continue
		}
		if strings.EqualFold(strings.TrimSpace(n.ZoneName), zone) {
			nets = append(nets, n)
		}
	}
	if len(nets) == 0 {
		// With no inventory, only a zone-wide target proves coverage.
		return []unifi.Network{{ZoneName: zone}}
	}
	return nets
}

func endpointCoversNetwork(ep unifi.PolicyEndpoint, n unifi.Network) bool {
	return !ep.NegatePort && ep.CoversAllPorts() && !ep.NegateTarget &&
		endpointUnconditionallyMatchesNetwork(ep, n.ZoneName, n, false)
}

func blocksCoverNetworkPairs(blocks []unifi.FirewallPolicy, srcNets, dstNets []unifi.Network) bool {
	for _, src := range srcNets {
		for _, dst := range dstNets {
			if !slices.ContainsFunc(blocks, func(block unifi.FirewallPolicy) bool {
				return endpointCoversNetwork(block.Source, src) && endpointCoversNetwork(block.Destination, dst)
			}) {
				return false
			}
		}
	}
	return true
}

// blanketBlockZones checks the union of unconditional blocks for every pair of
// source and Internal networks. A single broad but conditional policy can
// still express isolation intent for leak reporting.
func blanketBlockZones(snap *unifi.Snapshot, intent bool) map[string]string {
	zones := make(map[string]string)
	blocks := make(map[string][]unifi.FirewallPolicy)
	dstNets := zoneLANNetworks(snap, "Internal")
	for _, pol := range snap.FirewallPolicies {
		if !pol.Enabled || pol.UnsupportedReason != "" || !strings.EqualFold(strings.TrimSpace(pol.Destination.ZoneName), "Internal") {
			continue
		}
		switch strings.ToUpper(strings.TrimSpace(pol.Action)) {
		case "BLOCK", "REJECT", "DROP":
		default:
			continue
		}
		src := strings.ToLower(strings.TrimSpace(pol.Source.ZoneName))
		switch src {
		case "", "internal", "external", "gateway", "vpn":
			continue
		}
		if pol.Schedule == "" && matchesIPFamily(pol.IPVersion, "ipv4") && matchesConnState(pol.ConnectionStates, "new") &&
			matchesPolicyProtocol(pol.Protocol, pol.ProtocolNegated, "tcp") && matchesPolicyProtocol(pol.Protocol, pol.ProtocolNegated, "udp") {
			blocks[src] = append(blocks[src], pol)
		} else if intent && !pol.ProtocolNegated && matchesProtocol(pol.Protocol, "tcp") &&
			blocksCoverNetworkPairs([]unifi.FirewallPolicy{pol}, zoneLANNetworks(snap, src), dstNets) {
			zones[src] = strings.TrimSpace(pol.Source.ZoneName)
		}
	}
	for src, rules := range blocks {
		if blocksCoverNetworkPairs(rules, zoneLANNetworks(snap, src), dstNets) {
			zones[src] = strings.TrimSpace(rules[0].Source.ZoneName)
		}
	}
	return zones
}

// intendedIsolatedZoneSet includes built-in isolated zones and custom zones
// with blanket block intent, even if earlier allows defeat enforcement.
func intendedIsolatedZoneSet(snap *unifi.Snapshot) map[string]bool {
	zones := map[string]bool{"hotspot": true, "dmz": true}
	if snap != nil {
		for zone := range blanketBlockZones(snap, true) {
			zones[zone] = true
		}
	}
	return zones
}

// isolatedZoneSet returns the lowercase set of UniFi firewall zone names that
// genuinely enforce isolation from internal LANs: UniFi's built-in Hotspot and
// DMZ zones, plus any custom zone where enabled firewall policies actually block
// general new TCP and UDP transit into every Internal network across IPv4 and
// IPv6 (respecting policy ordering, protocol, source/destination selectors,
// connection states, and schedules while tolerating only single-host /32 or
// /128 narrow-port pinholes such as DNS 53 or NTP 123).
func isolatedZoneSet(snap *unifi.Snapshot) map[string]bool {
	zones := map[string]bool{
		"hotspot": true,
		"dmz":     true,
	}
	if snap == nil || len(snap.FirewallPolicies) == 0 {
		return zones
	}
	if snap.Visibility != nil && !snap.Visibility.GatewayPoliciesAvailable {
		return zones
	}
	sorted := make([]unifi.FirewallPolicy, len(snap.FirewallPolicies))
	copy(sorted, snap.FirewallPolicies)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Index != sorted[j].Index {
			return sorted[i].Index < sorted[j].Index
		}
		return i < j
	})

	candidates := blanketBlockZones(snap, false)
	intNets := zoneLANNetworks(snap, "Internal")

	gwName, _ := findGatewayIdentity(snap)
	switchACLStatus := "unavailable"
	switchACLReason := "controller snapshot omits switch ACLs"
	if snap.SwitchACLCoverage != nil && snap.SwitchACLCoverage.Status != "" {
		switchACLStatus = strings.ToLower(snap.SwitchACLCoverage.Status)
		if snap.SwitchACLCoverage.Reason != "" {
			switchACLReason = snap.SwitchACLCoverage.Reason
		}
	} else if len(snap.SwitchACLs) > 0 {
		switchACLStatus = "complete"
		switchACLReason = ""
	}

	for srcLow, srcRaw := range candidates {
		srcNets := zoneLANNetworks(snap, srcRaw)
		pinholeIntent := config.IsolationIntent{
			ApprovedPaths: narrowPinholePathsForZone(sorted, srcRaw),
		}
		var pinholeIPsV4, pinholeIPsV6 []string
		for _, ap := range pinholeIntent.ApprovedPaths {
			switch selectorFamilyTri(ap.DestIP) {
			case "ipv4":
				pinholeIPsV4 = append(pinholeIPsV4, ap.DestIP)
			case "ipv6":
				pinholeIPsV6 = append(pinholeIPsV6, ap.DestIP)
			}
		}

		hasV6Ctx := zoneHasIPv6Context(snap, srcLow)
		fullyIsolated := true

		for _, srcNet := range srcNets {
			for _, dstNet := range intNets {
				for _, fam := range []string{"ipv4", "ipv6"} {
					cell := evaluateTransitBoundary(
						snap, nil, sorted, pinholeIntent, true, "",
						switchACLStatus, switchACLReason, gwName,
						srcNet, dstNet, srcRaw, "Internal", fam,
					)
					if cell.Verdict != IsolationBlockedOK {
						fullyIsolated = false
						break
					}
					// Require explicit BLOCK/REJECT backing (not implicit zone
					// default alone) on IPv4, and on IPv6 whenever the zone or
					// Internal has IPv6 context.
					if fam == "ipv4" || hasV6Ctx {
						if cell.DecisiveRuleID == "" {
							fullyIsolated = false
							break
						}
						if srcNet.RouterDeviceMAC == "" && dstNet.RouterDeviceMAC == "" {
							avoid := pinholeIPsV4
							if fam == "ipv6" {
								avoid = pinholeIPsV6
							}
							dstIP := sampleNetworkIPForFamily(dstNet, snap, fam)
							if len(avoid) > 0 {
								if out := sampleIPOutsideSelectors(dstNet, snap, fam, avoid); out != "" {
									dstIP = out
								}
							}
							srcIP := sampleNetworkIPForFamily(srcNet, snap, fam)
							udpDec := evaluateGatewayPolicies(sorted, pathQuery{
								srcZone:    srcRaw,
								srcNetID:   srcNet.ID,
								srcNetName: srcNet.Name,
								srcIP:      srcIP,
								dstZone:    "Internal",
								dstNetID:   dstNet.ID,
								dstNetName: dstNet.Name,
								dstIP:      dstIP,
								proto:      "udp",
								port:       53,
								ipFamily:   fam,
								state:      "new",
							})
							if udpDec.action != "deny" || udpDec.ruleID == "" {
								fullyIsolated = false
								break
							}
						}
					}
				}
				if !fullyIsolated {
					break
				}
			}
			if !fullyIsolated {
				break
			}
		}
		if fullyIsolated {
			zones[srcLow] = true
		}
	}
	return zones
}

// lookupNetworkByIP resolves an IPv4/IPv6 address to its most specific
// configured UniFi LAN network using longest-prefix matching.
func lookupNetworkByIP(snap *unifi.Snapshot, rawIP string) (unifi.Network, bool) {
	if snap == nil {
		return unifi.Network{}, false
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(rawIP))
	if err != nil {
		return unifi.Network{}, false
	}
	addr = addr.Unmap()
	var best unifi.Network
	bestBits := -1
	for _, n := range snap.Networks {
		p := strings.ToLower(strings.TrimSpace(n.Purpose))
		if p == "wan" || p == "wan2" {
			continue
		}
		for _, cidr := range []string{n.Subnet, n.IPv6Subnet} {
			if cidr == "" {
				continue
			}
			pfx, err := netip.ParsePrefix(strings.TrimSpace(cidr))
			if err != nil {
				continue
			}
			if pfx.Contains(addr) && pfx.Bits() > bestBits {
				best = n
				bestBits = pfx.Bits()
			}
		}
	}
	return best, bestBits >= 0
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
