// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package risk correlates raw device findings with UniFi network topology
// and WAN exposure, and tracks changes to findings and remediation priorities
// across scans.
package risk

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/unifi"
	"github.com/karalabe/uniblue/rules"
)

// offlineFindingTTL bounds how long findings for an offline client host are
// carried forward in persisted state before aging out as resolved.
const offlineFindingTTL = 7 * 24 * time.Hour

// transientPatchActionGrace keeps a single missed service version banner from
// immediately resolving a known patch action while genuinely patched hosts age
// out promptly once the grace window passes.
const transientPatchActionGrace = 2 * time.Hour

// CurrentScoringVersion identifies the baseline for finding scores and ranked action identities.
const CurrentScoringVersion = 3

// Report holds the complete risk-scored output of a single UniBlue scan.
type Report struct {
	// SSHHostKeys holds the next pinned SSH host-key fingerprint baseline keyed
	// by host-and-port so callers can persist it into State.SSHHostKeys,
	// retaining prior fingerprints for missing observations and for hosts that
	// presented a changed key (excluded from serialized JSON reports).
	SSHHostKeys map[string]string `json:"-"`

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
	// ScoringVersion identifies the scoring rules used to build this baseline.
	ScoringVersion int `json:"scoring_version,omitempty"`

	// Actions maps stable action IDs to their retained priority. An empty map records a seeded site.
	Actions map[string]string `json:"actions"`

	// ActionLastSeen records the most recent observation at any priority.
	ActionLastSeen map[string]time.Time `json:"action_last_seen,omitempty"`

	// ActionPeakAt records the last observation at the retained priority.
	ActionPeakAt map[string]time.Time `json:"action_peak_at,omitempty"`

	// CarriedActions marks actions retained for online hosts awaiting a new probe.
	CarriedActions map[string]bool `json:"carried_actions,omitempty"`

	// ActionAssets maps each asset-tracked action ID to its per-host
	// last-observed UTC timestamps (keyed by normalized client MAC or IP) so
	// absent clients age out independently.
	ActionAssets map[string]map[string]time.Time `json:"action_assets,omitempty"`

	// UpgradeCarriedHosts records clients awaiting their first probe after a scoring upgrade.
	UpgradeCarriedHosts map[string]time.Time `json:"upgrade_carried_hosts,omitempty"`

	// KnownClientIPs maps canonical WAN backend IP addresses to the last
	// unambiguously observed client MAC so offline WAN backends retain stable
	// MAC-anchored action IDs across disconnects.
	KnownClientIPs map[string]string `json:"known_client_ips,omitempty"`

	// SSHHostKeys holds the last observed public host-key fingerprint for each device and port.
	SSHHostKeys map[string]string `json:"ssh_host_keys,omitempty"`

	// UpdatedAt records when the baseline was last saved.
	UpdatedAt time.Time `json:"updated_at"`

	// Findings maps persisted finding keys (Finding.Key() formatted as
	// "checkID|host|port[|property][|transport]", or
	// "UB-UNIFI-PORTFWD|portfwd:<id>|<port>" for port forwards) to their last
	// known effective severity.
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

// NeedsScoringRebaseline reports whether a saved baseline must be upgraded silently.
func (s *State) NeedsScoringRebaseline() bool {
	return s != nil && s.ScoringVersion < CurrentScoringVersion
}

// ActionAlert describes a remediation whose priority is new or has increased.
type ActionAlert struct {
	// ID identifies the remediation independently of its wording or queue position.
	ID string `json:"id"`
	// Title describes the change the operator can make.
	Title string `json:"title"`
	// Reason explains why the change matters.
	Reason string `json:"reason,omitempty"`
	// Lane names the work queue that contains the action.
	Lane string `json:"lane"`
	// Priority is the highest exposure tier reduced by the action.
	Priority string `json:"priority"`
	// Severity sets the notification threshold for the action.
	Severity checks.Severity `json:"severity"`
	// Previous is the prior priority when an action escalates.
	Previous string `json:"previous_priority,omitempty"`
	// Benefits names the devices that benefit most from the change.
	Benefits []string `json:"benefits,omitempty"`
	// AffectedAssets identifies the devices protected by the change.
	AffectedAssets []string `json:"affected_assets,omitempty"`
	// HighProfile indicates that the action protects a frequently targeted software stack.
	HighProfile bool `json:"high_profile,omitempty"`
}

type actionPriority struct {
	rank     int
	severity checks.Severity
	label    string
}

// lookupActionPriority keeps ordering, notification severity and display text in sync.
func lookupActionPriority(p string) actionPriority {
	switch strings.ToUpper(strings.TrimSpace(p)) {
	case "P1":
		return actionPriority{5, checks.SeverityCritical, "Urgent"}
	case "P2":
		return actionPriority{4, checks.SeverityHigh, "High"}
	case "P3":
		return actionPriority{3, checks.SeverityMedium, "Medium"}
	case "P4":
		return actionPriority{2, checks.SeverityLow, "Low"}
	case "P5":
		return actionPriority{1, checks.SeverityLow, "Low"}
	default:
		return actionPriority{0, checks.SeverityInfo, "Verify"}
	}
}

// ActionPriorityRank orders recognized priorities from P5 (1) to P1 (5).
func ActionPriorityRank(p string) int {
	return lookupActionPriority(p).rank
}

// ActionPrioritySeverity maps a remediation priority to its webhook severity.
func ActionPrioritySeverity(p string) checks.Severity {
	return lookupActionPriority(p).severity
}

// ActionPriorityLabel returns the plain-English urgency displayed to operators.
func ActionPriorityLabel(p string) string {
	return lookupActionPriority(p).label
}

// AlertEvent represents a high-signal live security event (admin activity,
// firewall or config drift, honeypot hit, edge physical tamper, evil-twin AP,
// or trusted-VLAN medium swap) forwarded via webhook alongside diff changes.
type AlertEvent struct {
	// Type classifies the security event category (e.g., "admin_access", "honeypot_hit").
	Type string `json:"type"`

	// Severity ranks the operational urgency of the event.
	Severity checks.Severity `json:"severity"`

	// Time records when the event occurred, if known.
	Time time.Time `json:"time,omitempty"`

	// Host is the display name of the affected client or infrastructure device, if applicable.
	Host string `json:"host,omitempty"`

	// IP is the relevant source or device IP address associated with the event, if any.
	IP string `json:"ip,omitempty"`

	// Summary is a concise human-readable description of the event.
	Summary string `json:"summary"`
}

// CVEAlert represents a newly matched or newly KEV-promoted exact-version CVE
// on a LAN host or UniFi infrastructure appliance.
type CVEAlert struct {
	// CVEID is the canonical CVE identifier (e.g., "CVE-2024-12345").
	CVEID string `json:"cve_id"`

	// HostName is the display name of the affected host or UniFi device.
	HostName string `json:"host_name"`

	// HostIP is the IP address of the affected host or device.
	HostIP string `json:"host_ip"`

	// VLAN is the resolved network/VLAN name where the affected host resides.
	VLAN string `json:"vlan,omitempty"`

	// Product is the normalized software or firmware product name matched by the CVE.
	Product string `json:"product"`

	// Version is the exact observed software or firmware version string, if known.
	Version string `json:"version,omitempty"`

	// Severity is the effective vulnerability severity for alerting.
	Severity checks.Severity `json:"severity"`

	// CVSS is the base score from the selected NVD CVSS metric for this CVE, when available.
	CVSS float64 `json:"cvss,omitempty"`

	// KEV reports whether the CVE appears in CISA's Known Exploited Vulnerabilities catalog.
	KEV bool `json:"kev,omitempty"`

	// WANExposed reports whether a matching enabled port forward exposes the affected host.
	WANExposed bool `json:"wan_exposed,omitempty"`

	// MinFixedVersion is the minimum fixed version from the product/version rollup
	// across exact CVE matches, which can exceed the fix boundary for this
	// individual CVE, if published.
	MinFixedVersion string `json:"min_fixed_version,omitempty"`
}

// Diff summarizes security-relevant changes between the previous persisted
// State and the current scan.
type Diff struct {
	// NewActions lists remediations newly available in the action queue.
	NewActions []ActionAlert `json:"new_actions,omitempty"`

	// EscalatedActions lists existing remediations that now reduce a higher exposure tier.
	EscalatedActions []ActionAlert `json:"escalated_actions,omitempty"`

	// ResolvedActionIDs identifies actions that are no longer needed.
	ResolvedActionIDs []string `json:"resolved_action_ids,omitempty"`

	// NewFindings lists findings that did not exist in the previous state.
	NewFindings []checks.Finding `json:"new_findings,omitempty"`

	// EscalatedFindings lists existing findings whose effective severity increased
	// (for example, when a vulnerable service becomes reachable from the internet).
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
	meetsThreshold := func(a ActionAlert) bool { return a.Severity >= minSeverity }
	if slices.ContainsFunc(d.NewActions, meetsThreshold) || slices.ContainsFunc(d.EscalatedActions, meetsThreshold) {
		return true
	}
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
func Evaluate(snap *unifi.Snapshot, rawFindings []checks.Finding, netCfg config.NetworkConfig, profiles ...probe.HostProfile) Report {
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

	oracle := NewOracle(snap, netCfg)
	isoMatrix, isoFindings, isoNotes := oracle.evaluateIsolation(rawFindings, netCfg)
	scored := make([]checks.Finding, 0, len(rawFindings)+len(snap.PortForwards))
	for _, f := range rawFindings {
		var forwards []unifi.PortForward
		for _, ip := range f.EndpointIPs() {
			forwards = append(forwards, forwardsByIP[canonicalIsolationIP(ip)]...)
		}
		scored = append(scored, scoreFinding(f, forwards, oracle))
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

		assessment := classifier.Classify(pf, cl, profiles...)
		var reasons []string
		if pf.SourceUnknown {
			reasons = append(reasons, "WAN source filter unresolved")
		} else if !pf.IsSourceRestricted() {
			reasons = append(reasons, "open to any source IP on WAN")
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
// port, and WAN source restrictions).
// Pure inventory observations (asset-identity / service-advertised /
// service-observed at Info severity) are preserved as Info without escalation.
func scoreFinding(f checks.Finding, forwards []unifi.PortForward, oracle *Oracle) checks.Finding {
	f.EffectiveSeverity = f.BaseSeverity
	f.RiskReasons = nil

	if f.IsInventoryOnly() {
		return f
	}

	if f.CheckID == "UB-0010" && f.Port == 53 && len(f.EndpointIPs()) > 0 {
		local := PrivateResolver(f)
		unknown := false
		for _, ip := range f.EndpointIPs() {
			switch oracle.ListenerWAN(f.Client, ip, f.EffectiveTransport(), f.Port) {
			case "allow":
				f.EffectiveSeverity = checks.SeverityCritical
				f.RiskReasons = append(f.RiskReasons, "WAN traffic can reach the recursive DNS listener at "+ip)
				local = false
			case "unknown":
				f.RiskReasons = append(f.RiskReasons, "WAN reachability is unknown for the DNS listener at "+ip)
				local = false
				unknown = true
			}
		}
		if local {
			f.EffectiveSeverity, f.ClaimKind = checks.SeverityInfo, checks.ClaimServiceObserved
		}
		// Return immediately once WAN reachability is settled (either confirmed
		// critical allow or confirmed non-WAN). When ListenerWAN returned
		// "unknown" without already reaching Critical (for instance, due to a
		// port forward with an unresolved source filter), fall through to the
		// port-forward loop below so the standard severity bump and forward
		// evidence are still applied.
		if !unknown || f.EffectiveSeverity == checks.SeverityCritical {
			return f
		}
	}

	transport := f.EffectiveTransport()
	// Check WAN exposure across ALL matching forwards (worst severity wins so an
	// earlier source-restricted forward never hides a later open src=any forward).
	for _, pf := range forwards {
		if pf.FwdPort == "" {
			pf.FwdPort = pf.DstPort
		}
		if !pf.ExposesEndpoint(f.Port, transport) {
			continue
		}
		if pf.SourceUnknown {
			// An unresolved filter provides no evidence of stronger protection
			// than a known source restriction.
			f.EffectiveSeverity = max(f.EffectiveSeverity, f.BaseSeverity.Bump(1))
			f.RiskReasons = append(f.RiskReasons, fmt.Sprintf(
				"exposed via %s WAN forward %q with unresolved source filter (WAN:%s -> %s:%s)",
				strings.ToUpper(transport), pf.Name, pf.DstPort, pf.FwdIP, pf.FwdPort,
			))
			continue
		}
		if pf.IsSourceRestricted() {
			f.EffectiveSeverity = max(f.EffectiveSeverity, f.BaseSeverity.Bump(1))
			f.RiskReasons = append(f.RiskReasons, fmt.Sprintf(
				"exposed via source-restricted %s WAN forward %q (WAN:%s -> %s:%s, src=%s)",
				strings.ToUpper(transport), pf.Name, pf.DstPort, pf.FwdIP, pf.FwdPort, pf.Src,
			))
		} else {
			f.EffectiveSeverity = checks.SeverityCritical
			f.RiskReasons = append(f.RiskReasons, fmt.Sprintf(
				"exposed to WAN via %s port forward %q (WAN:%s -> %s:%s, src=any)",
				strings.ToUpper(transport), pf.Name, pf.DstPort, pf.FwdIP, pf.FwdPort,
			))
		}
	}
	return f
}

// PrivateResolver reports whether recursion was observed exclusively on private LAN addresses.
func PrivateResolver(f checks.Finding) bool {
	ips := f.EndpointIPs()
	if f.CheckID != "UB-0010" || f.Port != 53 || len(ips) == 0 {
		return false
	}
	for _, raw := range ips {
		ip, err := netip.ParseAddr(raw)
		if err != nil || !ip.Unmap().IsPrivate() {
			return false
		}
	}
	return true
}

// CompareSSHHostKeys compares current observations with the last saved scan, if any.
func (s *State) CompareSSHHostKeys(profiles []probe.HostProfile) map[string]string {
	if s == nil {
		return probe.CompareSSHHostKeys(profiles, nil)
	}
	return probe.CompareSSHHostKeys(profiles, s.SSHHostKeys)
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
// Offline hosts retain findings for up to offlineFindingTTL. When probe
// coverage is available, online hosts also retain them until their next probe
// or the same deadline.
func BuildStateWithPrev(prev *State, snap *unifi.Snapshot, report Report, netCfg config.NetworkConfig, probedHostKeys map[string]struct{}) *State {
	trustedSet, _ := resolveVLANTiers(snap, netCfg)
	now := time.Now().UTC()

	st := &State{
		ScoringVersion:  CurrentScoringVersion,
		SSHHostKeys:     report.SSHHostKeys,
		UpdatedAt:       now,
		Findings:        make(map[string]checks.Severity, len(report.Findings)),
		FindingLastSeen: make(map[string]time.Time, len(report.Findings)),
		TrustedClients:  make(map[string]string),
		PortForwards:    make(map[string]string),
	}
	activeHosts := activeClientHostSet(snap)

	// Carry forward previously known trusted clients so a household phone or
	// rebooting NAS is never re-alerted as a brand-new trusted device.
	if prev != nil {
		st.Actions = maps.Clone(prev.Actions)
		st.ActionLastSeen = maps.Clone(prev.ActionLastSeen)
		st.ActionPeakAt = maps.Clone(prev.ActionPeakAt)
		st.CarriedActions = maps.Clone(prev.CarriedActions)
		st.ActionAssets = maps.Clone(prev.ActionAssets)
		for id, assets := range prev.ActionAssets {
			st.ActionAssets[id] = maps.Clone(assets)
		}
		st.UpgradeCarriedHosts = maps.Clone(prev.UpgradeCarriedHosts)
		for host, seen := range st.UpgradeCarriedHosts {
			_, online := activeHosts[host]
			_, probed := probedHostKeys[host]
			if now.Sub(seen) > offlineFindingTTL || (online && probed) {
				delete(st.UpgradeCarriedHosts, host)
			}
		}
		if st.SSHHostKeys == nil {
			st.SSHHostKeys = prev.SSHHostKeys
		}
		for mac, name := range prev.TrustedClients {
			st.TrustedClients[mac] = name
		}
	}

	// Retain IP-to-MAC mappings only for configured WAN backends and addresses
	// backing active or carried WAN service actions so stale DHCP leases do not
	// accumulate in state.
	onlineOwners := onlineIPOwners(snap)
	st.KnownClientIPs = wanBackendOwners(snap, knownClientIPs(prev, onlineOwners), onlineOwners, st.Actions)

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
			hostLow := observationHostKey(hostID)
			lastSeen := observationLastSeen(prev.FindingLastSeen[k], prev.UpdatedAt, now)
			if !carryHostObservation(hostLow, lastSeen, now, activeHosts, probedHostKeys, false) {
				continue
			}
			_, isActive := activeHosts[hostLow]
			if isActive {
				if st.CarriedFindings == nil {
					st.CarriedFindings = make(map[string]bool)
				}
				st.CarriedFindings[k] = true
			}
			// Baselines saved under scoring version < 2 applied a one-tier
			// severity discount to isolated-VLAN findings; bump carried-forward
			// severities by one tier so they match un-discounted scoring.
			if prev.ScoringVersion < 2 {
				sev = sev.Bump(1)
			}
			if prev.NeedsScoringRebaseline() {
				st.recordUpgradeHost(hostLow, lastSeen)
			}
			st.Findings[k] = sev
			st.FindingLastSeen[k] = lastSeen
		}
		if prev.NeedsScoringRebaseline() {
			// A legacy client may have only a CVE or trusted-client entry.
			// Its first probe also establishes a fresh action baseline.
			infraHosts := activeInfraHostSet(snap)
			for k := range prev.ExactCVEs {
				host, _, _ := strings.Cut(k, "|")
				host = observationHostKey(host)
				_, active := activeHosts[host]
				_, probed := probedHostKeys[host]
				_, infra := infraHosts[host]
				seen := observationLastSeen(prev.ExactCVELastSeen[k], prev.UpdatedAt, now)
				if !infra && (!active || !probed) && now.Sub(seen) <= offlineFindingTTL {
					st.recordUpgradeHost(host, seen)
				}
			}
			if !prev.UpdatedAt.IsZero() && now.Sub(prev.UpdatedAt) <= offlineFindingTTL {
				for mac := range prev.TrustedClients {
					host := config.CanonicalMAC(mac)
					if _, active := activeHosts[host]; !active {
						st.recordUpgradeHost(host, prev.UpdatedAt)
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

// recordUpgradeHost dates the marker from the client's most recent legacy observation.
func (st *State) recordUpgradeHost(host string, seen time.Time) {
	if host == "" || !seen.After(st.UpgradeCarriedHosts[host]) {
		return
	}
	if st.UpgradeCarriedHosts == nil {
		st.UpgradeCarriedHosts = make(map[string]time.Time)
	}
	st.UpgradeCarriedHosts[host] = seen
}

// activeClientHostSet indexes the currently online clients by their finding and action keys.
func activeClientHostSet(snap *unifi.Snapshot) map[string]struct{} {
	if snap == nil {
		return nil
	}
	activeHosts := make(map[string]struct{}, len(snap.Clients)*2)
	for _, cl := range snap.Clients {
		AddClientHostKeys(activeHosts, cl)
	}
	return activeHosts
}

// AddClientHostKeys indexes the host identifiers used in finding and action IDs
// so the same client can be recognized in the inventory and in probe coverage.
func AddClientHostKeys(keys map[string]struct{}, cl unifi.Client) {
	if mac := strings.ToLower(strings.TrimSpace(cl.MAC)); mac != "" {
		keys[mac] = struct{}{}
		if cm := config.CanonicalMAC(mac); cm != "" {
			keys[cm] = struct{}{}
		}
	}
	if id := strings.ToLower(strings.TrimSpace(cl.ID)); id != "" {
		keys[id] = struct{}{}
	}
	for _, ip := range cl.AllIPs() {
		keys[strings.ToLower(ip)] = struct{}{}
		keys[canonicalIsolationIP(ip)] = struct{}{}
	}
}

// observationHostKey normalizes a finding or action host. An IP can also have
// twelve hex digits, so recognize addresses before parsing a possible MAC.
func observationHostKey(host string) string {
	host = strings.TrimSpace(host)
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap().String()
	}
	return config.CanonicalMAC(host)
}

// activeInfraHostSet indexes controller-managed devices whose posture is observed
// independently of the client probe schedule.
func activeInfraHostSet(snap *unifi.Snapshot) map[string]struct{} {
	hosts := make(map[string]struct{})
	if snap != nil {
		for _, d := range snap.Devices {
			for _, key := range []string{d.MAC, config.CanonicalMAC(d.MAC), d.ID, d.IP, canonicalIsolationIP(d.IP)} {
				if key = strings.ToLower(strings.TrimSpace(key)); key != "" {
					hosts[key] = struct{}{}
				}
			}
		}
	}
	return hosts
}

// onlineIPOwners leaves an empty owner for ambiguous or unidentified addresses
// so a reassigned address cannot inherit an unrelated client's action history.
func onlineIPOwners(snap *unifi.Snapshot) map[string]string {
	owners := make(map[string]string)
	if snap != nil {
		for _, cl := range snap.Clients {
			mac, _ := config.ParseCanonicalMAC(cl.MAC)
			for _, ip := range cl.AllIPs() {
				ip = canonicalIsolationIP(ip)
				if owner, ok := owners[ip]; ok && owner != mac {
					owners[ip] = ""
				} else {
					owners[ip] = mac
				}
			}
		}
	}
	return owners
}

// knownClientIPs gives a current claim precedence over the last known owner,
// including when multiple clients now claim a previously unambiguous address.
func knownClientIPs(prev *State, online map[string]string) map[string]string {
	known := maps.Clone(online)
	if prev != nil {
		for ip, mac := range prev.KnownClientIPs {
			ip = canonicalIsolationIP(ip)
			if _, claimed := online[ip]; !claimed {
				known[ip] = mac
			}
		}
	}
	return known
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

// observationLastSeen uses the baseline timestamp when older state lacks a
// per-item observation time. A fresh seed starts its retention window today.
func observationLastSeen(seen, updatedAt, now time.Time) time.Time {
	if !seen.IsZero() {
		return seen
	}
	if !updatedAt.IsZero() {
		return updatedAt
	}
	return now
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
	lastSeen := observationLastSeen(prev.FindingLastSeen[oldKey], prev.UpdatedAt, now)
	return carryHostObservation(observationHostKey(hostID), lastSeen, now, activeHosts, probedHostKeys, prev.CarriedFindings[oldKey])
}

// carryHostObservation keeps recent evidence until the host returns and is probed.
func carryHostObservation(host string, lastSeen, now time.Time, activeHosts, probedHostKeys map[string]struct{}, previouslyCarried bool) bool {
	if now.Sub(lastSeen) > offlineFindingTTL {
		return false
	}
	if _, isActive := activeHosts[host]; !isActive {
		return true
	}
	if probedHostKeys != nil {
		_, wasProbed := probedHostKeys[host]
		return !wasProbed
	}
	return previouslyCarried
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
	if prev.NeedsScoringRebaseline() {
		return Diff{}
	}
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

// ComputeActionDiff compares the current scan's ranked remediation actions
// against prev and produces both the alert diff and the updated action maps to
// persist in State.
//
// Inputs:
//   - prev: previous persisted State. A nil prev treats current actions as new
//     and emits them in newActions; an existing State needing a scoring
//     rebaseline or with a nil Actions map seeds the action maps silently
//     without emitting new or escalated alerts.
//   - snap: current UniFi snapshot used to resolve online hosts, infrastructure
//     devices, port forwards, and IP-to-MAC ownership.
//   - current: action alerts built for the current scan.
//   - probedHostKeys: hosts actively probed in this cycle (nil means probe
//     coverage is unavailable, so the previous carry-forward flag decides
//     retention for an online host).
//   - cveMatched: whether exact-version CVE matching ran in this cycle (when
//     false, patch actions are carried forward rather than resolved).
//
// Return values:
//   - newActions, escalatedActions: sorted alerts for newly introduced actions
//     and existing actions whose priority increased.
//   - resolvedIDs: sorted action IDs no longer active or eligible for carry-forward.
//   - nextActions, nextLastSeen, nextPeakAt: retained action priorities and UTC
//     timestamps (priority peaks are preserved for offlineFindingTTL even when
//     an absent protected host temporarily lowers measured benefit).
//   - nextCarried: actions currently retained only via online-unprobed carry-forward.
//   - nextAssets: per-action map of normalized protected client hosts to last-seen time.
//   - nextOwners: canonical WAN backend IP-to-MAC ownership map retained for offline continuity.
//
// Key invariants: IP-keyed WAN service actions are normalized to MAC-anchored
// IDs once a client MAC is known, duplicate fallback port-forward actions
// (act:wan-pf:*) are suppressed while a carried WAN service bundle covers them
// at equal or higher priority, and hosts awaiting their first probe after a
// scoring upgrade are suppressed from new-action alerts until probed.
func ComputeActionDiff(
	prev *State,
	snap *unifi.Snapshot,
	current []ActionAlert,
	probedHostKeys map[string]struct{},
	cveMatched bool,
) (newActions, escalatedActions []ActionAlert, resolvedIDs []string, nextActions map[string]string, nextLastSeen, nextPeakAt map[string]time.Time, nextCarried map[string]bool, nextAssets map[string]map[string]time.Time, nextOwners map[string]string) {
	now := time.Now().UTC()
	onlineOwners := onlineIPOwners(snap)
	knownOwners := knownClientIPs(prev, onlineOwners)
	byID := make(map[string]ActionAlert, len(current))
	nextActions = make(map[string]string, len(current))
	nextLastSeen = make(map[string]time.Time, len(current))
	nextPeakAt = make(map[string]time.Time, len(current))
	nextAssets = make(map[string]map[string]time.Time)
	nextCarried = make(map[string]bool)
	for _, a := range current {
		// The blast-radius action builder already resolves online hosts from
		// current inventory. Only substitute a remembered MAC when no online
		// client currently claims the address.
		a.ID = wanServiceMACID(a.ID, knownOwners, onlineOwners)
		if a.ID == "" || ActionPriorityRank(a.Priority) <= ActionPriorityRank(nextActions[a.ID]) {
			continue
		}
		if a.Severity == 0 {
			a.Severity = ActionPrioritySeverity(a.Priority)
		}
		byID[a.ID] = a
		nextActions[a.ID] = a.Priority
		nextLastSeen[a.ID] = now
		nextPeakAt[a.ID] = now
	}
	seed := prev != nil && (prev.NeedsScoringRebaseline() || prev.Actions == nil)
	if prev == nil || seed {
		prev = &State{}
	}
	activeHosts := activeClientHostSet(snap)
	infraHosts := activeInfraHostSet(snap)
	upgradeHosts := upgradeActionHosts(prev.UpgradeCarriedHosts, snap, now)
	aliases, migrated := previousWANServiceAliases(prev, byID, onlineOwners, now)
	for _, a := range byID {
		oldID := cmp.Or(aliases[a.ID], a.ID)
		lastSeen := observationLastSeen(prev.ActionLastSeen[oldID], prev.UpdatedAt, now)
		if assetTrackedAction(a.ID) {
			assets, _ := actionAssetObservations(prev, oldID, a.AffectedAssets, lastSeen, now, infraHosts, activeHosts, probedHostKeys)
			if len(assets) > 0 {
				nextAssets[a.ID] = assets
			}
		}
		old, exists := prev.Actions[oldID]
		if !exists {
			if seed {
				continue
			}
			if _, marked := upgradeHosts[observationHostKey(actionClientHost(a.ID))]; marked {
				continue
			}
			newActions = append(newActions, a)
			continue
		}
		switch cmp.Compare(ActionPriorityRank(a.Priority), ActionPriorityRank(old)) {
		case -1:
			// A temporarily absent protected host can lower the measured benefit.
			// Keep the last peak without extending its window on weaker evidence.
			peakAt := observationLastSeen(prev.ActionPeakAt[oldID], lastSeen, now)
			if now.Sub(peakAt) <= offlineFindingTTL {
				nextActions[a.ID], nextPeakAt[a.ID] = old, peakAt
			}
		case 1:
			a.Previous = old
			escalatedActions = append(escalatedActions, a)
		}
	}
	carriedBundles := make(map[wanService]int)
	for id, priority := range prev.Actions {
		if _, observed := nextActions[id]; observed || migrated[id] {
			continue
		}
		lastSeen := observationLastSeen(prev.ActionLastSeen[id], prev.UpdatedAt, now)
		keep, unprobed, assets := carryMissingAction(id, prev, snap, lastSeen, now, cveMatched, infraHosts, activeHosts, probedHostKeys)
		if service, ok := parseWANService(id); keep && ok {
			keep = service.hasPublicRoute(snap, knownOwners)
			if keep {
				carriedBundles[service] = max(carriedBundles[service], ActionPriorityRank(priority))
			}
		}
		if !keep {
			resolvedIDs = append(resolvedIDs, id)
			continue
		}
		nextActions[id] = priority
		nextLastSeen[id] = lastSeen
		if peakAt := prev.ActionPeakAt[id]; !peakAt.IsZero() {
			nextPeakAt[id] = peakAt
		}
		if len(assets) > 0 {
			nextAssets[id] = assets
		}
		if unprobed {
			nextCarried[id] = true
		}
	}
	// While a WAN backend client is offline, its bundled act:wan-service action
	// is carried forward above, while the gateway still emits a raw
	// act:wan-pf:<id> action for the port forward alone. Suppress that fallback
	// duplicate unless the port-forward action now has strictly higher priority.
	if len(carriedBundles) > 0 {
		covered := make(map[string]int)
		for _, pf := range snap.PortForwards {
			if pf.ID == "" && pf.Name != "" && !snap.UniquePortForwardName(pf.Name) {
				continue
			}
			for s, rank := range carriedBundles {
				if s.matchesForward(pf, knownOwners) {
					key := cmp.Or(pf.ID, pf.Name, canonicalIsolationIP(pf.FwdIP)+":"+s.proto+"/"+strconv.Itoa(s.port))
					id := "act:wan-pf:" + key
					covered[id] = max(covered[id], rank)
				}
			}
		}
		newActions = slices.DeleteFunc(newActions, func(a ActionAlert) bool {
			if ActionPriorityRank(a.Priority) > covered[a.ID] {
				return false
			}
			delete(nextActions, a.ID)
			delete(nextLastSeen, a.ID)
			delete(nextPeakAt, a.ID)
			return true
		})
	}
	order := func(a, b ActionAlert) int {
		return cmp.Or(cmp.Compare(ActionPriorityRank(b.Priority), ActionPriorityRank(a.Priority)), strings.Compare(a.ID, b.ID))
	}
	slices.SortFunc(newActions, order)
	slices.SortFunc(escalatedActions, order)
	slices.Sort(resolvedIDs)
	nextOwners = wanBackendOwners(snap, knownOwners, onlineOwners, nextActions)
	// Preserve the IP-to-MAC bridge for any current IP-keyed WAN service action
	// that was rewritten onto a remembered MAC and kept in nextActions so
	// subsequent offline cycles continue matching the same MAC-anchored ID.
	for _, a := range current {
		if s, ok := parseWANService(a.ID); ok && knownOwners[s.host] != "" && nextActions[wanServiceMACID(a.ID, knownOwners, onlineOwners)] != "" {
			nextOwners[s.host] = knownOwners[s.host]
		}
	}
	return
}

// upgradeActionHosts expands recent scoring-upgrade host markers to all
// identifiers (MAC, client ID, IPs) of matching online clients so the
// blast-radius action builder recognizes them after reconnects.
func upgradeActionHosts(markers map[string]time.Time, snap *unifi.Snapshot, now time.Time) map[string]struct{} {
	if len(markers) == 0 {
		return nil
	}
	recent := make(map[string]struct{})
	for host, seen := range markers {
		if host != "" && now.Sub(seen) <= offlineFindingTTL {
			recent[observationHostKey(host)] = struct{}{}
		}
	}
	hosts := maps.Clone(recent)
	if snap != nil {
		for _, cl := range snap.Clients {
			keys := make(map[string]struct{})
			AddClientHostKeys(keys, cl)
			for key := range keys {
				if _, marked := recent[key]; marked {
					maps.Copy(hosts, keys)
					break
				}
			}
		}
	}
	return hosts
}

// normalizeActionAssetHost strips the "managed:<host>" wrapper or the
// "child:" prefix and final colon-delimited component emitted by blast-radius
// analysis. For a child ID whose suffix contains additional colons,
// activeActionAssetHost completes parent resolution against inventory.
func normalizeActionAssetHost(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if rest, ok := strings.CutPrefix(s, "child:"); ok {
		if i := strings.LastIndexByte(rest, ':'); i >= 0 {
			return rest[:i]
		}
	}
	if rest, ok := strings.CutPrefix(s, "managed:"); ok {
		return rest
	}
	return s
}

// activeActionAssetHost resolves child IDs that contain colons by looking for
// the longest known parent. Infrastructure parents have their own observations.
func activeActionAssetHost(raw string, infraHosts, activeHosts map[string]struct{}) string {
	host := normalizeActionAssetHost(raw)
	child := strings.HasPrefix(strings.ToLower(strings.TrimSpace(raw)), "child:")
	for host != "" {
		key := observationHostKey(host)
		if _, infra := infraHosts[key]; infra {
			return ""
		}
		if _, active := activeHosts[key]; active {
			return key
		}
		i := strings.LastIndexByte(host, ':')
		if !child || i < 0 {
			break
		}
		host = host[:i]
	}
	return ""
}

// actionAssetObservations gives each absent host its own retention window so
// observing another host cannot extend it.
func actionAssetObservations(prev *State, id string, current []string, lastSeen, now time.Time, infraHosts, activeHosts, probedHostKeys map[string]struct{}) (map[string]time.Time, bool) {
	assets := make(map[string]time.Time, len(current))
	var onlineUnprobed bool
	for raw, seen := range prev.ActionAssets[id] {
		host := observationHostKey(raw)
		if strings.HasPrefix(host, "child:") || strings.HasPrefix(host, "managed:") {
			// Older baselines stored raw blast-radius asset IDs instead of
			// canonical client keys; resolve them to active non-infrastructure
			// clients before checking retention.
			host = activeActionAssetHost(host, infraHosts, activeHosts)
		}
		seen = observationLastSeen(seen, lastSeen, now)
		if _, infra := infraHosts[host]; host == "" || infra || !seen.After(assets[host]) {
			continue
		}
		if !carryHostObservation(host, seen, now, activeHosts, probedHostKeys, prev.CarriedActions[id]) {
			continue
		}
		assets[host] = seen
		if _, online := activeHosts[host]; online {
			onlineUnprobed = true
		}
	}
	for _, raw := range current {
		if host := activeActionAssetHost(raw, infraHosts, activeHosts); host != "" {
			assets[host] = now
		}
	}
	return assets, onlineUnprobed
}

// carryMissingAction decides whether a previously active action missing from
// the current scan should be carried forward (offline/unprobed client, skipped
// CVE matching, or transient version-banner miss) versus marked resolved.
func carryMissingAction(id string, prev *State, snap *unifi.Snapshot, lastSeen, now time.Time, cveMatched bool, infraHosts, activeHosts, probedHostKeys map[string]struct{}) (keep, onlineUnprobed bool, assets map[string]time.Time) {
	// Keep patch actions when CVE matching did not run in this scan or while
	// still inside transientPatchActionGrace after a missed version banner.
	if (strings.HasPrefix(id, "act:patch:") || strings.HasPrefix(id, "act:patch-product:")) && (!cveMatched || now.Sub(lastSeen) <= transientPatchActionGrace) {
		return true, prev.CarriedActions[id], nil
	}
	if snap == nil {
		return false, false, nil
	}
	// Resolve gateway-routed policy actions immediately once gateway policies
	// confirm the referenced ALLOW rule is disabled or deleted.
	if rule, routed := strings.CutPrefix(id, "act:gateway-routed:"); routed && snap.Visibility != nil && snap.Visibility.GatewayPoliciesAvailable {
		if !slices.ContainsFunc(snap.FirewallPolicies, func(p unifi.FirewallPolicy) bool {
			return p.Enabled && cmp.Or(p.ID, p.Name) == rule && strings.EqualFold(strings.TrimSpace(p.Action), "ALLOW")
		}) {
			return false, false, nil
		}
	}
	host := observationHostKey(actionClientHost(id))
	if assetTrackedAction(id) {
		assets, onlineUnprobed = actionAssetObservations(prev, id, nil, lastSeen, now, infraHosts, activeHosts, probedHostKeys)
		// A WAN bundle action ID still names its backend even when blast-radius
		// analysis emitted no separate AffectedAssets; skip the fallback host
		// check only when that backend already has its own tracked window above.
		if _, tracked := prev.ActionAssets[id][host]; tracked {
			host = ""
		}
	}
	if _, infra := infraHosts[host]; host != "" && !infra && carryHostObservation(host, lastSeen, now, activeHosts, probedHostKeys, prev.CarriedActions[id]) {
		_, online := activeHosts[host]
		return true, onlineUnprobed || online, assets
	}
	return len(assets) > 0, onlineUnprobed, assets
}

// previousWANServiceAliases identifies IP-based actions from before the first
// client observation. When several addresses merge, inherit the highest
// priority and its most recent peak.
func previousWANServiceAliases(prev *State, current map[string]ActionAlert, onlineOwners map[string]string, now time.Time) (aliases map[string]string, migrated map[string]bool) {
	peakAt := func(id string) time.Time {
		seen := observationLastSeen(prev.ActionLastSeen[id], prev.UpdatedAt, now)
		return observationLastSeen(prev.ActionPeakAt[id], seen, now)
	}
	aliases, migrated = make(map[string]string), make(map[string]bool)
	for id, priority := range prev.Actions {
		macID := wanServiceMACID(id, onlineOwners, nil)
		if macID == id || current[macID].ID == "" || prev.Actions[macID] != "" {
			continue
		}
		migrated[id] = true
		other := aliases[macID]
		rank := cmp.Compare(ActionPriorityRank(priority), ActionPriorityRank(prev.Actions[other]))
		if other == "" || rank > 0 || (rank == 0 && peakAt(id).After(peakAt(other))) {
			aliases[macID] = id
		}
	}
	return aliases, migrated
}

// wanService identifies the backend socket shared by a bundle of public routes.
type wanService struct {
	host, proto string
	port        int
}

// parseWANService parses an "act:wan-service:<host>:<proto>/<port>" action ID,
// splitting at the last colon so colons inside IPv6 and MAC addresses stay
// intact, and returns the canonicalized backend host, transport, and port.
func parseWANService(id string) (wanService, bool) {
	tail, ok := strings.CutPrefix(id, "act:wan-service:")
	i := strings.LastIndexByte(tail, ':')
	if !ok || i <= 0 {
		return wanService{}, false
	}
	proto, portText, _ := strings.Cut(tail[i+1:], "/")
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 || (proto != "tcp" && proto != "udp") {
		return wanService{}, false
	}
	return wanService{canonicalIsolationIP(tail[:i]), proto, port}, true
}

// wanServiceMACID gives an offline backend the identity used for its online action.
func wanServiceMACID(id string, owners, excludedIPs map[string]string) string {
	s, ok := parseWANService(id)
	if !ok {
		return id
	}
	mac := owners[s.host]
	if _, excluded := excludedIPs[s.host]; excluded || mac == "" {
		return id
	}
	return "act:wan-service:" + mac + ":" + s.proto + "/" + strconv.Itoa(s.port)
}

// wanBackendOwners limits persisted identities to configured backends and
// addresses targeted by active or carried WAN service actions.
func wanBackendOwners(snap *unifi.Snapshot, owners, online, actions map[string]string) map[string]string {
	retained := make(map[string]string)
	add := func(ip string) {
		ip = canonicalIsolationIP(ip)
		if mac := owners[ip]; mac != "" {
			retained[ip] = mac
		}
	}
	if snap != nil {
		for _, pf := range snap.PortForwards {
			add(pf.FwdIP)
		}
		for _, m := range snap.DynamicMappings {
			add(m.InternalIP)
		}
		for _, r := range snap.ProxyRoutes {
			if r.PublicExposed {
				add(r.BackendIP)
			}
		}
		for _, t := range snap.PublishedTunnels {
			add(t.BackendIP)
		}
	}
	onlineMACs := make(map[string]bool)
	for _, mac := range online {
		onlineMACs[mac] = true
	}
	for id := range actions {
		s, ok := parseWANService(id)
		if !ok {
			continue
		}
		add(s.host)
		// A single-address host identifies the backend even without route
		// inventory. On a multihomed host, keep the addresses public rules
		// actually target. Ignore old privacy addresses once a host returns.
		var candidate string
		var candidates int
		for ip, mac := range owners {
			if mac != s.host || (onlineMACs[mac] && online[ip] != mac) || isNonRoutableIP(ip) {
				continue
			}
			candidate, candidates = ip, candidates+1
			if snap != nil && s.firewallTargets(snap, ip, mac) {
				retained[ip] = mac
			}
		}
		if candidates == 1 {
			retained[candidate] = s.host
		}
	}
	return retained
}

// targetsIP accepts both forms of a bundle's host identity.
func (s wanService) targetsIP(ip string, owners map[string]string) bool {
	ip = canonicalIsolationIP(ip)
	return s.host == ip || s.host == owners[ip]
}

// matchesForward reports whether an enabled port forward exposes s's transport
// and port on s's backend host, falling back to DstPort when FwdPort is omitted
// for untranslated forwards.
func (s wanService) matchesForward(pf unifi.PortForward, owners map[string]string) bool {
	pf.FwdPort = firstNonEmptyStr(pf.FwdPort, pf.DstPort)
	return pf.ExposesEndpoint(s.port, s.proto) && s.targetsIP(pf.FwdIP, owners)
}

// hasPublicRoute distinguishes a hidden service from a removed publication.
func (s wanService) hasPublicRoute(snap *unifi.Snapshot, owners map[string]string) bool {
	for _, pf := range snap.PortForwards {
		if s.matchesForward(pf, owners) {
			return true
		}
	}
	for _, m := range snap.DynamicMappings {
		if m.IntPort == s.port && strings.EqualFold(m.Transport, s.proto) && s.targetsIP(m.InternalIP, owners) &&
			(m.ExpiresAt == nil || m.ExpiresAt.After(snap.CollectedAt)) {
			return true
		}
	}
	if s.proto == "tcp" {
		for _, r := range snap.ProxyRoutes {
			if r.PublicExposed && r.BackendPort == s.port && s.targetsIP(r.BackendIP, owners) {
				return true
			}
		}
		for _, t := range snap.PublishedTunnels {
			if t.BackendPort == s.port && s.targetsIP(t.BackendIP, owners) {
				return true
			}
		}
	}
	if _, err := netip.ParseAddr(s.host); err == nil {
		return s.firewallTargets(snap, s.host, owners[s.host])
	}
	var hasAddress bool
	for ip, mac := range owners {
		if mac != s.host {
			continue
		}
		hasAddress = true
		if s.firewallTargets(snap, ip, mac) {
			return true
		}
	}
	return !hasAddress && s.firewallTargets(snap, "", s.host)
}

// firewallTargets checks whether an inbound rule can open a new connection to
// this socket. Without a known address, only host-wide selectors can match.
func (s wanService) firewallTargets(snap *unifi.Snapshot, ip, mac string) bool {
	if len(snap.FirewallPolicies) == 0 || isNonRoutableIP(ip) {
		return false
	}
	network, _ := lookupNetworkByIP(snap, ip)
	fam := "ipv4"
	if strings.Contains(ip, ":") {
		fam = "ipv6"
	}
	for _, p := range snap.FirewallPolicies {
		if !p.Enabled || !strings.EqualFold(p.Action, "ALLOW") || !strings.EqualFold(p.Source.ZoneName, "External") ||
			!matchesConnState(p.ConnectionStates, "new") || !matchesPolicyProtocol(p.Protocol, p.ProtocolNegated, s.proto) {
			continue
		}
		dst := p.Destination
		if strings.EqualFold(dst.ZoneName, "External") || strings.EqualFold(dst.ZoneName, "Gateway") ||
			(ip == "" && (len(dst.IPs) > 0 || len(dst.NetworkIDs) > 0)) {
			continue
		}
		if ip != "" && !matchesIPFamily(p.IPVersion, fam) {
			continue
		}
		zone := cmp.Or(network.ZoneName, dst.ZoneName)
		if match, _ := matchesEndpoint(dst, zone, network.ID, network.Name, ip, mac, s.port, fam); match != matchNo {
			return true
		}
	}
	return false
}

// assetTrackedAction identifies controls whose measured benefit depends on
// which protected hosts were visible during the scan.
func assetTrackedAction(id string) bool {
	return strings.HasPrefix(id, "act:move-iot:") || strings.HasPrefix(id, "act:port-ext-switch:") || strings.HasPrefix(id, "act:vlan-") || strings.HasPrefix(id, "act:l2-") ||
		strings.HasPrefix(id, "act:wifi-iso:") || strings.HasPrefix(id, "act:port-ext:") || strings.HasPrefix(id, "act:port-tags:") ||
		strings.HasPrefix(id, "act:gateway-routed:") || strings.HasPrefix(id, "act:switch-routed:") || strings.HasPrefix(id, "act:wan-service:")
}

// actionClientHost extracts the host identifier (MAC or IP) from client-scoped
// action IDs:
//   - "act:patch:<...>:<host>", "act:patch-product:<...>:<host>", "act:check-host:<...>:<host>"
//   - "act:check:<checkID>:<host>:<port>[:tcp|:udp]"
//   - "act:service:<host>:<proto>/<port>", "act:wan-service:<host>:<proto>/<port>"
//
// Splitting only on the known leading/trailing delimiters keeps colons inside
// MACs and IPv6 addresses intact. Network-level control IDs return "".
func actionClientHost(id string) string {
	body, ok := strings.CutPrefix(id, "act:")
	if !ok {
		return ""
	}
	kind, tail, _ := strings.Cut(body, ":")
	switch kind {
	case "patch", "patch-product", "check-host":
		_, host, _ := strings.Cut(tail, ":")
		return host
	case "check":
		_, tail, _ = strings.Cut(tail, ":")
		tail = strings.TrimSuffix(strings.TrimSuffix(tail, ":tcp"), ":udp")
	case "service", "wan-service":
	default:
		return ""
	}
	if i := strings.LastIndexByte(tail, ':'); i >= 0 {
		return tail[:i]
	}
	return ""
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
		// Older baselines stored host lists with a single timestamp per action.
		legacy := struct {
			*State
			Hosts map[string][]string `json:"action_assets"`
		}{State: &st}
		if json.Unmarshal(raw, &legacy) != nil {
			return nil, fmt.Errorf("parse state %q: %w", path, err)
		}
		now := time.Now().UTC()
		st.ActionAssets = make(map[string]map[string]time.Time, len(legacy.Hosts))
		for id, hosts := range legacy.Hosts {
			seen := observationLastSeen(st.ActionLastSeen[id], st.UpdatedAt, now)
			assets := make(map[string]time.Time, len(hosts))
			for _, host := range hosts {
				assets[observationHostKey(host)] = seen
			}
			st.ActionAssets[id] = assets
		}
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
	return vlanTiers(snap, netCfg, isolatedZoneSet(snap))
}

// vlanTiers assigns trust and isolation after resolving the effective firewall zones.
func vlanTiers(snap *unifi.Snapshot, netCfg config.NetworkConfig, isoZones map[string]bool) (trusted, isolated map[string]struct{}) {
	trusted = toLowerSet(netCfg.TrustedVLANs)
	isolated = toLowerSet(netCfg.IsolatedVLANs)
	if snap == nil {
		return trusted, isolated
	}

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

// zoneLANNetworks returns all non-WAN, non-remote-VPN networks assigned to
// zone, or a zone-only placeholder when the snapshot lists no networks in zone.
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

// endpointCoversNetwork reports whether ep unconditionally matches all ports
// and all hosts on n without target or port negation.
func endpointCoversNetwork(ep unifi.PolicyEndpoint, n unifi.Network) bool {
	return !ep.NegatePort && ep.CoversAllPorts() && !ep.NegateTarget &&
		endpointUnconditionallyMatchesNetwork(ep, n.ZoneName, n, false)
}

// blocksCoverNetworkPairs reports whether every (src, dst) network pair is
// unconditionally covered by at least one block policy in blocks.
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
	return newPolicyOracle(snap).isolatedZones()
}

// isolatedZones checks the candidate zones against the same routing evidence used for isolation cells.
func (o *Oracle) isolatedZones() map[string]bool {
	snap := o.snap
	zones := map[string]bool{
		"hotspot": true,
		"dmz":     true,
	}
	if len(o.sortedPolicies) == 0 || !o.gwPoliciesAvailable {
		return zones
	}
	candidates := blanketBlockZones(snap, false)
	intNets := zoneLANNetworks(snap, "Internal")
	for srcLow, srcRaw := range candidates {
		srcNets := zoneLANNetworks(snap, srcRaw)
		pinholeIntent := config.IsolationIntent{
			ApprovedPaths: narrowPinholePathsForZone(o.sortedPolicies, srcRaw),
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
					cell := o.evaluateBoundary(
						nil, pinholeIntent, srcNet, dstNet, srcRaw, "Internal", fam, "deny", nil,
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
						// Re-probe UDP/53 against a non-pinhole Internal host on
						// gateway-routed pairs to confirm an explicit BLOCK/REJECT
						// rule (ruleID != "") blocks general UDP/53 transit rather
						// than relying on implicit zone defaults or a broad DNS allow.
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
							udpDec := evaluateGatewayPolicies(o.sortedPolicies, pathQuery{
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
	return isNetworkInSet(cl.NetworkName, set) || isNetworkInSet(cl.VLAN, set)
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
