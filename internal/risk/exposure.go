// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package risk

import (
	"cmp"
	"fmt"
	"io/fs"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/unifi"
	"gopkg.in/yaml.v3"
)

// ExposureRule classifies a WAN port-forwarding rule deterministically into a
// known traffic class (such as expected P2P, public web proxy, or dangerous
// admin/RPC exposure) so operators only get escalated alerts for genuinely
// risky forwards.
type ExposureRule struct {
	// ID uniquely identifies the exposure rule.
	ID string `yaml:"id"`

	// Name is a concise label for the matched traffic class.
	Name string `yaml:"name"`

	// Class groups forwards by operational intent ("expected-p2p",
	// "vpn-entrypoint", "web-entrypoint", "remote-admin", "dangerous-rpc",
	// "dangerous-remote").
	Class string `yaml:"class"`

	// Severity is the baseline severity for this exposure class.
	Severity checks.Severity `yaml:"severity"`

	// Proto optionally restricts matching to a specific protocol ("tcp", "udp").
	Proto string `yaml:"proto"`

	// Ports lists destination or internal ports matched by this rule.
	Ports []int `yaml:"ports"`

	// NameRegex optionally matches the user's UniFi port-forward rule name.
	NameRegex string `yaml:"name_regex"`

	// Summary explains why this exposure class is benign, review-worthy, or dangerous.
	Summary string `yaml:"summary"`

	// Actions suggests concrete remediation or verification steps.
	Actions []string `yaml:"actions"`

	nameRe *regexp.Regexp
}

// ExposureAssessment records the deterministic classification of a single
// enabled UniFi WAN port-forwarding rule.
type ExposureAssessment struct {
	// Forward is the underlying UniFi port-forward rule.
	Forward unifi.PortForward `json:"forward"`

	// Client is the resolved internal host receiving the forwarded traffic.
	Client unifi.Client `json:"client"`

	// Class is the matched category (e.g., "expected-p2p", "web-entrypoint", "dangerous-rpc").
	Class string `json:"class"`

	// RuleName is the human-readable classification label.
	RuleName string `json:"rule_name"`

	// Severity is the effective severity after optional source/VLAN checks.
	Severity checks.Severity `json:"severity"`

	// Summary explains the risk posture of this forward.
	Summary string `json:"summary"`

	// Actions lists recommended follow-up actions.
	Actions []string `json:"actions,omitempty"`
}

// PostureNote captures a deterministic network-wide architectural observation
// (for example, an unused isolated IoT VLAN while vulnerable IoT devices sit
// on a trusted VLAN).
type PostureNote struct {
	// Severity ranks the importance of the architectural observation.
	Severity checks.Severity `json:"severity"`

	// Title summarizes the posture observation.
	Title string `json:"title"`

	// Detail explains the specific UniFi objects involved and how to improve them.
	Detail string `json:"detail"`
}

// ExposureClassifier evaluates UniFi port forwards against a declarative set of
// YAML ExposureRules.
type ExposureClassifier struct {
	rules []*ExposureRule
}

// LoadExposureClassifier reads and compiles all YAML exposure rules from fsys.
func LoadExposureClassifier(fsys fs.FS) (*ExposureClassifier, error) {
	var paths []string
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk exposure rules: %w", err)
	}
	sort.Strings(paths)

	var rules []*ExposureRule
	for _, p := range paths {
		raw, err := fs.ReadFile(fsys, p)
		if err != nil {
			return nil, fmt.Errorf("read exposure rule %q: %w", p, err)
		}
		var batch []*ExposureRule
		if err := yaml.Unmarshal(raw, &batch); err != nil {
			return nil, fmt.Errorf("parse exposure rule %q: %w", p, err)
		}
		for _, r := range batch {
			if r.NameRegex != "" {
				re, err := regexp.Compile(r.NameRegex)
				if err != nil {
					return nil, fmt.Errorf("compile exposure rule %q regex: %w", r.ID, err)
				}
				r.nameRe = re
			}
			rules = append(rules, r)
		}
	}
	return &ExposureClassifier{rules: rules}, nil
}

// Classify matches an enabled UniFi PortForward against the ordered rule list,
// falling back to an unclassified MEDIUM assessment when no rule matches.
// Optional probe profiles let SSH entrypoints escalate severity via
// ObservedSSHAccess when password or credential-free login is observed.
func (c *ExposureClassifier) Classify(pf unifi.PortForward, cl unifi.Client, profiles ...probe.HostProfile) ExposureAssessment {
	if c != nil {
		for _, r := range c.rules {
			if r.matches(pf) {
				assessment := ExposureAssessment{
					Forward:  pf,
					Client:   cl,
					Class:    r.Class,
					RuleName: r.Name,
					Severity: r.Severity,
					Summary:  strings.TrimSpace(r.Summary),
					Actions:  r.Actions,
				}
				// ssh-entrypoint rules confine the backend strictly to port 22,
				// so query observed SSH auth methods on that listener directly.
				if assessment.Class == "ssh-entrypoint" {
					switch ObservedSSHAccess(profiles, cl, pf.FwdIP, 22) {
					case "none":
						assessment.Severity = checks.SeverityCritical
						assessment.Summary = "The SSH server accepted login without credentials. Require authentication and restrict WAN access."
					case "password":
						assessment.Severity = checks.SeverityHigh
						assessment.Summary = "SSH offers password or keyboard-interactive authentication. Restrict WAN access and verify account authentication settings."
					}
				}

				return assessment
			}
		}
	}

	return ExposureAssessment{
		Forward:  pf,
		Client:   cl,
		Class:    "unclassified-wan",
		RuleName: "Unclassified WAN Port Forward",
		Severity: checks.SeverityMedium,
		Summary:  "Verify this service truly needs public internet exposure. Prefer WireGuard VPN access or restrict allowed source IPs.",
		Actions:  []string{"review_port_forward", "restrict_wan_source_ip"},
	}
}

// ObservedSSHAccess inspects probed SSH host profiles for cl on (ip, port) and
// returns the strongest observed authentication exposure: "none" (unauthenticated
// login accepted), "password" (password or keyboard-interactive offered),
// "publickey" (exact listener advertised only "publickey" for the probed
// account), or "" (no conclusive profile).
// Exact listener IP matches take precedence; an observation on the same host's
// other address family can still surface "none" or "password" risks, whereas
// "publickey" requires an exact listener IP match because key-only enforcement
// on one address family does not guarantee the other listener is key-only.
func ObservedSSHAccess(profiles []probe.HostProfile, cl unifi.Client, ip string, port int) string {
	identity := func(c unifi.Client) string {
		return cmp.Or(config.CanonicalMAC(c.MAC), c.ID, canonicalIsolationIP(c.PrimaryIP()))
	}
	host := identity(cl)
	listener, err := netip.ParseAddr(strings.TrimSpace(ip))
	if host == "" || err != nil {
		return ""
	}
	listener = listener.Unmap()
	var exact, fallback string
	for _, hp := range profiles {
		s := hp.SSH
		if s == nil || s.Port != port || identity(hp.Client) != host {
			continue
		}
		addr, err := netip.ParseAddr(hp.EffectiveProbeIP())
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		auth := &fallback
		if addr == listener {
			auth = &exact
		} else if addr.Is4() == listener.Is4() {
			continue
		}
		switch {
		case s.NoneAuthAccepted:
			*auth = "none"
		case *auth != "none" && (slices.Contains(s.AuthMethods, "password") || slices.Contains(s.AuthMethods, "keyboard-interactive")):
			*auth = "password"
		case addr == listener && exact == "" && slices.Equal(s.AuthMethods, []string{"publickey"}):
			exact = "publickey"
		}
	}
	return cmp.Or(exact, fallback)
}

// matches evaluates whether a PortForward satisfies an ExposureRule's protocol,
// port list, or optional rule-name regex.
func (r *ExposureRule) matches(pf unifi.PortForward) bool {
	// Require exact protocol and single-purpose backend ports for SSH
	// entrypoints so broader multi-port or mixed-transport forwards that merely
	// overlap port 22 do not get narrowed to an SSH-only classification.
	if r.Class == "ssh-entrypoint" {
		return pf.Enabled && strings.EqualFold(pf.Proto, r.Proto) && pf.OnlyBackendPort(r.Ports...)
	}
	if r.Proto != "" && !pf.MatchesTransport(r.Proto) {
		return false
	}

	// Never allow WAN-side DstPort fallback to classify an unrelated internal
	// service as a benign/informational P2P or VPN listener (for example,
	// forwarding WAN 4001 -> internal 8096 must stay unclassified medium).
	isBenign := r.Class == "expected-p2p" || r.Class == "vpn-entrypoint" || r.Severity <= checks.SeverityInfo

	portHit := false
	for _, p := range r.Ports {
		if pf.ExposesPort(p) || (!isBenign && portSpecMatches(pf.DstPort, p)) {
			portHit = true
			break
		}
	}

	// On benign expected-p2p / vpn-entrypoint rules, require portHit AND
	// name_regex when name_regex is specified so ambiguous ports (like 9000 for
	// Portainer/MinIO/php-fpm) are never misclassified as safe P2P listeners.
	if isBenign {
		if !portHit {
			return false
		}
		if r.nameRe != nil {
			return r.nameRe.MatchString(pf.Name)
		}
		return true
	}
	if portHit {
		return true
	}
	if r.nameRe != nil && r.nameRe.MatchString(pf.Name) {
		return true
	}
	return false
}

// portSpecMatches parses a UniFi port specification ("80", "8000-8010", "80,443")
// and checks whether port falls inside it.
func portSpecMatches(spec string, port int) bool {
	for _, token := range strings.Split(spec, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if startStr, endStr, ok := strings.Cut(token, "-"); ok {
			start, err1 := strconv.Atoi(strings.TrimSpace(startStr))
			end, err2 := strconv.Atoi(strings.TrimSpace(endStr))
			if err1 == nil && err2 == nil && port >= start && port <= end {
				return true
			}
			continue
		}
		if single, err := strconv.Atoi(token); err == nil && single == port {
			return true
		}
	}
	return false
}

// AnalyzePosture inspects UniFi's structural network topology (zones, isolation
// flags, client placement, and active findings) to emit generic architectural
// guidance without relying on user-chosen VLAN names.
func AnalyzePosture(snap *unifi.Snapshot, findings []checks.Finding, netCfg config.NetworkConfig) []PostureNote {
	if snap == nil {
		return nil
	}
	trustedSet, isolatedSet := resolveVLANTiers(snap, netCfg)

	// Count active clients per network name.
	clientsPerNet := make(map[string]int, len(snap.Networks))
	for _, cl := range snap.Clients {
		if cl.NetworkName != "" {
			clientsPerNet[strings.ToLower(cl.NetworkName)]++
		}
	}

	// Identify all structurally isolated LAN networks (excluding WAN/VPN) and
	// track which ones currently hold zero active clients.
	var isolatedNets []unifi.Network
	var emptyIsolatedNets []unifi.Network
	for _, n := range snap.Networks {
		purposeLower := strings.ToLower(strings.TrimSpace(n.Purpose))
		zoneLower := strings.ToLower(strings.TrimSpace(n.ZoneName))
		if purposeLower == "wan" || purposeLower == "remote-user-vpn" ||
			zoneLower == "external" || zoneLower == "vpn" || zoneLower == "gateway" {
			continue
		}
		lower := strings.ToLower(strings.TrimSpace(n.Name))
		_, isIso := isolatedSet[lower]
		if !isIso && n.VLAN != "" {
			_, isIso = isolatedSet[strings.ToLower(strings.TrimSpace(n.VLAN))]
		}
		if !isIso {
			continue
		}
		isolatedNets = append(isolatedNets, n)
		if clientsPerNet[lower] == 0 {
			emptyIsolatedNets = append(emptyIsolatedNets, n)
		}
	}

	// Collect every host with a confirmed LAN service exposure sitting on a
	// non-isolated (trusted/internal) network.
	exposedInternalHosts := make(map[string]struct{})
	for _, f := range findings {
		if f.Port > 0 && !f.IsInventoryOnly() && matchesVLAN(f.Client, trustedSet) {
			exposedInternalHosts[f.Client.DisplayName()] = struct{}{}
		}
	}

	var notes []PostureNote
	if len(exposedInternalHosts) > 0 {
		hostNames := make([]string, 0, len(exposedInternalHosts))
		for h := range exposedInternalHosts {
			hostNames = append(hostNames, h)
		}
		sort.Strings(hostNames)

		switch {
		case len(isolatedNets) == 0 && len(snap.Networks) > 0:
			// Flat network topology: no isolated/guest/DMZ network exists at all.
			notes = append(notes, PostureNote{
				Severity: checks.SeverityMedium,
				Title:    "Flat internal network topology with no isolated VLAN configured",
				Detail:   fmt.Sprintf("No isolated, DMZ, or guest VLAN is configured in UniFi while %d host(s) with confirmed LAN exposures (%s) share the internal network. Creating an isolated VLAN/zone for untrusted or embedded appliances lowers lateral-movement blast radius.", len(hostNames), strings.Join(hostNames, ", ")),
			})
		case len(emptyIsolatedNets) > 0:
			// One or more configured isolated networks currently hold zero clients.
			var netLabels []string
			for _, n := range emptyIsolatedNets {
				label := n.Name
				if n.VLAN != "" {
					label = fmt.Sprintf("%s (VLAN %s)", n.Name, n.VLAN)
				}
				netLabels = append(netLabels, label)
			}
			sort.Strings(netLabels)
			notes = append(notes, PostureNote{
				Severity: checks.SeverityMedium,
				Title:    fmt.Sprintf("Unused isolated network(s) (%s) while exposed hosts sit on Internal LAN", strings.Join(netLabels, ", ")),
				Detail:   fmt.Sprintf("Isolated network(s) %s currently have 0 active clients, while %d host(s) with confirmed LAN exposures (%s) sit on internal networks. Moving untrusted or embedded appliances onto an isolated VLAN lowers blast radius.", strings.Join(netLabels, ", "), len(hostNames), strings.Join(hostNames, ", ")),
			})
		}
	}

	// Flag unnamed MAC-only clients that receive active WAN port forwards.
	clientsByIP := make(map[string]unifi.Client, len(snap.Clients))
	for _, cl := range snap.Clients {
		if cl.IP != "" {
			clientsByIP[cl.IP] = cl
		}
	}
	seenUnnamed := make(map[string]struct{})
	for _, pf := range snap.PortForwards {
		if !pf.Enabled {
			continue
		}
		cl, ok := clientsByIP[pf.FwdIP]
		if !ok {
			continue
		}
		if strings.EqualFold(cl.DisplayName(), cl.MAC) {
			if _, dup := seenUnnamed[cl.IP]; dup {
				continue
			}
			seenUnnamed[cl.IP] = struct{}{}
			notes = append(notes, PostureNote{
				Severity: checks.SeverityInfo,
				Title:    fmt.Sprintf("Unnamed WAN-exposed host (%s / %s)", cl.IP, cl.MAC),
				Detail:   fmt.Sprintf("Port forward %q targets %s, which has no friendly alias in UniFi. Naming this host/container in UniFi makes alerts immediately recognizable.", pf.Name, cl.IP),
			})
		}
	}

	return notes
}

// auditFirewallPolicies evaluates UniFi Zone-Based Firewall policies generically
// to catch high-risk user-defined ALLOW rules (such as WAN-to-Gateway access,
// broad WAN-to-LAN allows, or unrestricted isolated-zone-to-Internal leaks).
func auditFirewallPolicies(snap *unifi.Snapshot) []checks.Finding {
	if snap == nil || len(snap.FirewallPolicies) == 0 || (snap.Visibility != nil && !snap.Visibility.GatewayPoliciesAvailable) {
		return nil
	}

	// Use isolation-intended zones (including custom zones with leaking or
	// shadowed BLOCK policies) so broad ALLOW rules defeating custom-zone
	// isolation are still flagged as isolation leaks.
	isoZones := intendedIsolatedZoneSet(snap)
	gwName, _, gwIP := findGatewayIdentity(snap)

	// Sort policies by Index so we can detect when an earlier broad BLOCK/REJECT
	// rule already shadows a later ALLOW policy on the same zone pair.
	sorted := orderedFirewallPolicies(snap.FirewallPolicies)

	// Skip reporting a dead ALLOW rule only when a strictly earlier (lower Index)
	// unconditional blanket deny covers the same zone pair, IP family, and
	// protocol (including via protocol negation handled by protocolCovers).
	// Equal-index, scheduled, stateful, target- or port-negated, or unsupported
	// denies never shadow a later ALLOW.
	isShadowedByEarlierDeny := func(pos int, pol unifi.FirewallPolicy) bool {
		for k := 0; k < pos; k++ {
			earlier := sorted[k]
			if earlier.Index >= pol.Index {
				continue
			}
			if !earlier.Enabled || earlier.UnsupportedReason != "" || earlier.Source.UnsupportedSelector != "" || earlier.Destination.UnsupportedSelector != "" || !earlier.Source.CoversAllPorts() || earlier.Source.NegatePort {
				continue
			}
			act := strings.ToUpper(strings.TrimSpace(earlier.Action))
			if act != "BLOCK" && act != "REJECT" && act != "DROP" {
				continue
			}
			if !strings.EqualFold(earlier.Source.ZoneName, pol.Source.ZoneName) ||
				!strings.EqualFold(earlier.Destination.ZoneName, pol.Destination.ZoneName) {
				continue
			}
			if !matchesIPFamily(earlier.IPVersion, firstNonEmptyStr(pol.IPVersion, "both")) &&
				!strings.EqualFold(earlier.IPVersion, "both") && earlier.IPVersion != "" {
				continue
			}
			if earlier.Source.AnyTarget && earlier.Destination.AnyTarget && earlier.Destination.CoversAllPorts() &&
				protocolCovers(earlier.Protocol, earlier.ProtocolNegated, pol.Protocol, pol.ProtocolNegated) &&
				len(earlier.ConnectionStates) == 0 && earlier.Schedule == "" &&
				!earlier.Source.NegateTarget && !earlier.Destination.NegateTarget && !earlier.Destination.NegatePort {
				return true
			}
		}
		return false
	}

	var findings []checks.Finding
	for pos, pol := range sorted {
		if !pol.Enabled || !strings.EqualFold(pol.Action, "ALLOW") {
			continue
		}
		// Skip response-only / established-only ALLOW rules that never permit
		// inbound NEW connections.
		if !matchesConnState(pol.ConnectionStates, "new") {
			continue
		}
		// Skip UniFi built-in system policies (port-forward auto-rules, DHCPv6,
		// WireGuard listener, etc.); port forwards are audited separately via WANSurface.
		if strings.EqualFold(pol.Origin, "SYSTEM_DEFINED") {
			continue
		}
		if isShadowedByEarlierDeny(pos, pol) {
			continue
		}

		srcZone := strings.ToLower(strings.TrimSpace(pol.Source.ZoneName))
		dstZone := strings.ToLower(strings.TrimSpace(pol.Destination.ZoneName))
		if srcZone == "" || dstZone == "" {
			continue
		}

		zonePath := fmt.Sprintf("%s -> %s", pol.Source.ZoneName, pol.Destination.ZoneName)
		portDesc := formatPolicyPorts(pol.Destination)
		protoDesc := formatPolicyProtocol(pol.Protocol, pol.ProtocolNegated)
		partialReason := firstNonEmptyStr(pol.UnsupportedReason, pol.Source.UnsupportedSelector, pol.Destination.UnsupportedSelector)
		partialNote := ""
		if partialReason != "" {
			partialNote = fmt.Sprintf("; partially evaluated (%s)", partialReason)
		}

		switch {
		case srcZone == "external" && dstZone == "gateway":
			sev := checks.SeverityHigh
			title := fmt.Sprintf("WAN-to-Gateway Firewall Policy Allows Direct Access (%s)", pol.Name)
			if partialReason == "" && pol.Source.AnyTarget && pol.Destination.AnyTarget && pol.Source.CoversAllPorts() && !pol.Source.NegatePort && pol.Destination.CoversAllPorts() && !pol.Destination.NegatePort {
				sev = checks.SeverityCritical
				title = fmt.Sprintf("Unrestricted WAN-to-Gateway Firewall Policy (%s)", pol.Name)
			}
			reasons := []string{fmt.Sprintf("user-defined ALLOW policy on %s", zonePath)}
			if partialReason != "" {
				reasons = append(reasons, fmt.Sprintf("partially evaluated selector (%s)", partialReason))
			}
			findings = append(findings, checks.Finding{
				CheckID:           "UB-UNIFI-FW-WAN-GW",
				Title:             title,
				Category:          "firewall-policy",
				BaseSeverity:      sev,
				EffectiveSeverity: sev,
				RiskReasons:       reasons,
				Client: unifi.Client{
					MAC:         "fw:" + pol.ID,
					IP:          gwIP,
					Name:        gwName,
					NetworkName: zonePath,
				},
				Evidence: fmt.Sprintf("enabled policy %q allows %s (protocol=%s, ports=%s, src=%s%s)",
					pol.Name, zonePath, protoDesc, portDesc, formatPolicyTarget(pol.Source), partialNote),
				Remediation: checks.Remediation{
					Summary:      "Remove or restrict this WAN-to-Gateway ALLOW rule. Never expose gateway management services (SSH/HTTPS) or unrestricted ports directly to the public internet; use VPN access instead.",
					UniFiActions: []string{"disable_or_restrict_firewall_policy", "use_wireguard_vpn"},
				},
			})

		case srcZone == "external" && dstZone != "external":
			sev := checks.SeverityHigh
			title := fmt.Sprintf("WAN-to-LAN Firewall Policy Allows Inbound Traffic (%s)", pol.Name)
			if partialReason == "" && (pol.Destination.AnyPort || pol.Destination.CoversAllPorts() || pol.Destination.AnyTarget) {
				sev = checks.SeverityCritical
				title = fmt.Sprintf("Broad WAN-to-LAN Firewall Policy (%s)", pol.Name)
			}
			reasons := []string{fmt.Sprintf("user-defined ALLOW policy on %s", zonePath)}
			if partialReason != "" {
				reasons = append(reasons, fmt.Sprintf("partially evaluated selector (%s)", partialReason))
			}
			findings = append(findings, checks.Finding{
				CheckID:           "UB-UNIFI-FW-WAN-LAN",
				Title:             title,
				Category:          "firewall-policy",
				BaseSeverity:      sev,
				EffectiveSeverity: sev,
				RiskReasons:       reasons,
				Client: unifi.Client{
					MAC:         "fw:" + pol.ID,
					IP:          firstOrFallback(pol.Destination.IPs, gwIP),
					Name:        fmt.Sprintf("Firewall Policy (%s)", pol.Name),
					NetworkName: zonePath,
				},
				Evidence: fmt.Sprintf("enabled policy %q allows %s (protocol=%s, target=%s, ports=%s%s)",
					pol.Name, zonePath, protoDesc, formatPolicyTarget(pol.Destination), portDesc, partialNote),
				Remediation: checks.Remediation{
					Summary:      "Verify whether inbound WAN traffic to this internal zone is strictly required. Scope destination IPs, ports, and allowed WAN source IPs, or replace with VPN access.",
					UniFiActions: []string{"restrict_firewall_policy", "use_wireguard_vpn"},
				},
			})

		case isoZones[srcZone] && dstZone == "internal":
			// Allow pinpoint pinholes (explicit destination IP + explicit port),
			// but flag broad zone-to-Internal ALLOW rules (including 1-65535 ranges)
			// that defeat isolation.
			if !pol.Destination.AnyTarget && !pol.Destination.CoversAllPorts() {
				continue
			}
			findings = append(findings, checks.Finding{
				CheckID:           "UB-UNIFI-FW-ISO-LEAK",
				Title:             fmt.Sprintf("Broad Isolated-to-Internal Firewall Policy (%s)", pol.Name),
				Category:          "firewall-policy",
				BaseSeverity:      checks.SeverityHigh,
				EffectiveSeverity: checks.SeverityHigh,
				RiskReasons:       []string{fmt.Sprintf("weakens isolation on %s", zonePath)},
				Client: unifi.Client{
					MAC:         "fw:" + pol.ID,
					IP:          firstOrFallback(pol.Destination.IPs, gwIP),
					Name:        fmt.Sprintf("Firewall Policy (%s)", pol.Name),
					NetworkName: zonePath,
				},
				Evidence: fmt.Sprintf("enabled policy %q allows %s (protocol=%s, target=%s, ports=%s)",
					pol.Name, zonePath, protoDesc, formatPolicyTarget(pol.Destination), portDesc),
				Remediation: checks.Remediation{
					Summary:      "Restrict inter-zone ALLOW rules from isolated networks to specific destination IPs and ports so compromised devices cannot scan or pivot across internal networks.",
					UniFiActions: []string{"scope_inter_zone_policy"},
				},
			})
		}
	}
	return findings
}

// findGatewayIdentity returns the display name, MAC and IP for the UniFi
// gateway from snap.Devices so firewall policy findings display cleanly.
func findGatewayIdentity(snap *unifi.Snapshot) (name, mac, ip string) {
	for _, d := range snap.Devices {
		modelLower := strings.ToLower(d.Model)
		if strings.Contains(modelLower, "udm") || strings.Contains(modelLower, "ucg") ||
			strings.Contains(modelLower, "uxg") || strings.Contains(modelLower, "usg") ||
			strings.Contains(modelLower, "efg") || strings.EqualFold(d.Type, "ugw") ||
			strings.EqualFold(d.Type, "udm") || strings.EqualFold(d.Type, "ucg") || strings.EqualFold(d.Type, "uxg") {
			n := d.Name
			if n == "" {
				n = d.Model
			}
			return n, d.MAC, d.IP
		}
	}
	return "UniFi Gateway", "", ""
}

// formatPolicyPorts formats a PolicyEndpoint's destination port restriction.
func formatPolicyPorts(ep unifi.PolicyEndpoint) string {
	if ep.CoversAllPorts() {
		return "any"
	}
	parts := make([]string, 0, len(ep.Ports)+len(ep.PortRanges))
	for _, p := range ep.Ports {
		parts = append(parts, strconv.Itoa(p))
	}
	for _, r := range ep.PortRanges {
		parts = append(parts, fmt.Sprintf("%d-%d", r.Start, r.End))
	}
	if len(parts) == 0 {
		return "any"
	}
	return strings.Join(parts, ",")
}

// formatPolicyTarget formats a PolicyEndpoint's IP/target restriction.
func formatPolicyTarget(ep unifi.PolicyEndpoint) string {
	if ep.AnyTarget {
		return "any"
	}
	if len(ep.IPs) > 0 {
		return strings.Join(ep.IPs, ",")
	}
	return "filtered"
}

// protocolCovers reports whether an earlier policy's protocol selector is a
// superset of (fully shadows) a later policy's protocol selector.
func protocolCovers(earlierProto string, earlierNeg bool, targetProto string, targetNeg bool) bool {
	ep := strings.ToLower(strings.TrimSpace(earlierProto))
	tp := strings.ToLower(strings.TrimSpace(targetProto))
	if ep == "tcp/udp" {
		ep = "tcp_udp"
	}
	if tp == "tcp/udp" {
		tp = "tcp_udp"
	}
	if ep == "" || ep == "all" || ep == "any" {
		return !earlierNeg
	}
	if earlierNeg {
		// A negated protocol (e.g., NOT tcp) never covers composite selectors
		// (all, any, tcp_udp) or another negated selector; it only covers a
		// concrete single protocol that differs from the excluded protocol.
		if targetNeg || tp == "" || tp == "all" || tp == "any" || tp == "tcp_udp" {
			return false
		}
		return !matchesProtocol(ep, tp)
	}
	// A specific positive protocol covers a wildcard target only if the target
	// is negated (negating all protocols matches nothing); an unnegated wildcard
	// is strictly broader than a single protocol.
	if tp == "" || tp == "all" || tp == "any" {
		return targetNeg
	}
	if targetNeg {
		return false
	}
	return matchesProtocol(ep, tp)
}

// formatPolicyProtocol renders a policy protocol selector cleanly for evidence.
func formatPolicyProtocol(proto string, negated bool) string {
	p := strings.TrimSpace(proto)
	if p == "" {
		p = "all"
	}
	if negated {
		return "not " + p
	}
	return p
}

// firstOrFallback returns items[0] when non-empty, otherwise fallback.
func firstOrFallback(items []string, fallback string) string {
	if len(items) > 0 && items[0] != "" {
		return items[0]
	}
	return fallback
}
