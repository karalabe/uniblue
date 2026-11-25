// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package risk

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/unifi"
)

// IsolationVerdict describes the evaluated outcome for one directed boundary cell.
type IsolationVerdict string

const (
	// IsolationApproved means an explicitly approved workflow is permitted as intended.
	IsolationApproved IsolationVerdict = "approved"
	// IsolationBlockedOK means an unintended path is effectively blocked as intended.
	IsolationBlockedOK IsolationVerdict = "blocked-ok"
	// IsolationViolation means configured policy permits a path that violates site intent.
	IsolationViolation IsolationVerdict = "violation"
	// IsolationBrokenDependency means an approved dependency (e.g. DNS/printing) is blocked.
	IsolationBrokenDependency IsolationVerdict = "broken-dependency"
	// IsolationUnknown means required enforcement evidence (e.g. switch ACL or gateway policies) is missing.
	IsolationUnknown IsolationVerdict = "unknown"
)

// IsolationCell records one evaluated network isolation path across a specific
// source, destination function, transport, port, IP family, and enforcement point.
type IsolationCell struct {
	SourceZone       string           `json:"source_zone"`
	SourceNetwork    string           `json:"source_network,omitempty"`
	DestZone         string           `json:"dest_zone"`
	DestNetwork      string           `json:"dest_network,omitempty"`
	DestHost         string           `json:"dest_host,omitempty"`
	DestIP           string           `json:"dest_ip,omitempty"`
	DestFunction     string           `json:"dest_function"`
	Transport        string           `json:"transport"`
	Port             int              `json:"port,omitempty"`
	IPFamily         string           `json:"ip_family"` // "ipv4" | "ipv6"
	PathKind         string           `json:"path_kind"` // "gateway-routed" | "switch-routed" | "same-ap-wifi" | "cross-ap-wifi" | "wired-same-vlan" | "mixed-same-vlan" | "gateway-local"
	Enforcer         string           `json:"enforcer"`  // device/layer actually enforcing the boundary
	Expected         string           `json:"expected"`  // "allow" | "deny"
	Effective        string           `json:"effective"` // "allow" | "deny" | "unknown"
	Verdict          IsolationVerdict `json:"verdict"`
	DecisiveRuleID   string           `json:"decisive_rule_id,omitempty"`
	DecisiveRuleName string           `json:"decisive_rule_name,omitempty"`
	DecisiveReason   string           `json:"decisive_reason,omitempty"`
	MissingInput     string           `json:"missing_input,omitempty"`
	RecommendedFix   string           `json:"recommended_fix,omitempty"`
}

// IsolationMatrix summarizes effective isolation policy evaluation across zones,
// IPv4/IPv6 families, gateway vs switch routing, and Wi-Fi/wired L2 boundaries.
type IsolationMatrix struct {
	Cells          []IsolationCell `json:"cells,omitempty"`
	ApprovedCount  int             `json:"approved_count"`
	BlockedOKCount int             `json:"blocked_ok_count"`
	ViolationCount int             `json:"violation_count"`
	UnknownCount   int             `json:"unknown_count"`
	BrokenDepCount int             `json:"broken_dep_count"`
}

type pathQuery struct {
	srcZone    string
	srcNetID   string
	srcNetName string
	srcIP      string
	srcMAC     string
	srcPort    int
	dstZone    string
	dstNetID   string
	dstNetName string
	dstIP      string
	dstMAC     string
	proto      string
	port       int
	ipFamily   string // "ipv4" | "ipv6"
	state      string // "new" | "established"
}

type policyDecision struct {
	action       string // "allow" | "deny" | "unknown"
	ruleID       string
	ruleName     string
	reason       string
	missingInput string
}

type endpointSpec struct {
	proto    string
	port     int
	function string
}

// EvaluateIsolation resolves effective gateway, L3-switch, AP, and L2-switch
// isolation boundaries across Guest, IoT, Camera, Trusted, and Management zones
// for both IPv4 and IPv6, emitting actionable findings only on real policy
// violations and keeping approved paths out of the action queue.
func EvaluateIsolation(
	snap *unifi.Snapshot,
	rawFindings []checks.Finding,
	netCfg config.NetworkConfig,
) (*IsolationMatrix, []checks.Finding, []PostureNote) {
	if snap == nil {
		return nil, nil, nil
	}

	matrix := &IsolationMatrix{}
	var findings []checks.Finding
	var notes []PostureNote

	trustedSet, isolatedSet := resolveVLANTiers(snap, netCfg)
	intent := netCfg.IsolationPolicy
	gwName, gwIP := findGatewayIdentity(snap)

	// Determine whether gateway firewall policy telemetry is genuinely available.
	// Never certify a path as blocked-ok when the controller failed to supply
	// firewall policies or uses a legacy API without zone policies.
	gwPoliciesAvailable := true
	gwMissingReason := ""
	if snap.Visibility != nil {
		gwPoliciesAvailable = snap.Visibility.GatewayPoliciesAvailable
		if !gwPoliciesAvailable {
			gwMissingReason = "gateway firewall policies were unavailable from the controller"
			for _, f := range snap.Visibility.MissingFeeds {
				if strings.Contains(strings.ToLower(f), "firewall") {
					gwMissingReason = f
					break
				}
			}
		}
	} else if len(snap.Zones) == 0 && len(snap.FirewallPolicies) == 0 {
		gwPoliciesAvailable = false
		gwMissingReason = "snapshot includes no firewall zones or policies"
	}

	// Index networks and resolve roles (guest, iot, camera, management, trusted).
	netByName := make(map[string]unifi.Network, len(snap.Networks))
	netByID := make(map[string]unifi.Network, len(snap.Networks))
	for _, n := range snap.Networks {
		if n.Name != "" {
			netByName[strings.ToLower(n.Name)] = n
		}
		if n.ID != "" {
			netByID[n.ID] = n
		}
	}

	var untrustedNets []unifi.Network
	var trustedNets []unifi.Network
	var mgmtNets []unifi.Network
	for _, n := range snap.Networks {
		p := strings.ToLower(strings.TrimSpace(n.Purpose))
		z := strings.ToLower(strings.TrimSpace(n.ZoneName))
		if p == "wan" || p == "wan2" || p == "remote-user-vpn" || z == "external" || z == "vpn" || z == "gateway" {
			continue
		}
		if isManagementNetwork(n, intent) {
			mgmtNets = append(mgmtNets, n)
			continue
		}
		if isNetworkInSet(n.Name, isolatedSet) || isGuestNetwork(n, intent) || isCameraNetwork(n, intent) {
			untrustedNets = append(untrustedNets, n)
		} else if isNetworkInSet(n.Name, trustedSet) {
			trustedNets = append(trustedNets, n)
		}
	}

	bmcClients := identifyBMCClients(snap, rawFindings, mgmtNets)
	printerClients := identifyPrinterClients(snap, rawFindings, intent)

	sortedPolicies := make([]unifi.FirewallPolicy, len(snap.FirewallPolicies))
	copy(sortedPolicies, snap.FirewallPolicies)
	sort.SliceStable(sortedPolicies, func(i, j int) bool {
		if sortedPolicies[i].Index != sortedPolicies[j].Index {
			return sortedPolicies[i].Index < sortedPolicies[j].Index
		}
		return i < j
	})

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

	addCell := func(cell IsolationCell) {
		matrix.Cells = append(matrix.Cells, cell)
		switch cell.Verdict {
		case IsolationApproved:
			matrix.ApprovedCount++
		case IsolationBlockedOK:
			matrix.BlockedOKCount++
		case IsolationViolation:
			matrix.ViolationCount++
		case IsolationBrokenDependency:
			matrix.BrokenDepCount++
		case IsolationUnknown:
			matrix.UnknownCount++
		}
	}

	// 1. Evaluate Untrusted/Guest -> BMC paths across IPv4 and IPv6 using real
	// family-specific addresses and observed BMC service endpoints.
	for _, bmc := range bmcClients {
		bmcNet := lookupClientNetwork(bmc, netByID, netByName)
		bmcZone := strings.TrimSpace(bmcNet.ZoneName)
		endpoints := bmcServiceEndpoints(bmc, rawFindings)
		for _, srcNet := range untrustedNets {
			if strings.EqualFold(srcNet.Name, bmc.NetworkName) {
				continue
			}
			srcZone := strings.TrimSpace(srcNet.ZoneName)
			for _, ep := range endpoints {
				for _, fam := range []string{"ipv4", "ipv6"} {
					if fam == "ipv6" && !siteHasIPv6Context(snap, srcNet, bmcNet, bmc) {
						continue
					}
					targetIP := clientAddressForFamily(bmc, fam)
					expected := "deny"
					if hasApprovedPath(intent.ApprovedPaths, srcZone, srcNet.Name, bmc, bmcZone, "bmc", ep.proto, ep.port, fam) {
						expected = "allow"
					}
					cell := evaluateRoutedPath(
						snap, sortedPolicies, gwPoliciesAvailable, gwMissingReason,
						switchACLStatus, switchACLReason, gwName, srcNet, bmcNet,
						pathQuery{
							srcZone:    srcZone,
							srcNetID:   srcNet.ID,
							srcNetName: srcNet.Name,
							dstZone:    bmcZone,
							dstNetID:   bmcNet.ID,
							dstNetName: bmcNet.Name,
							dstIP:      targetIP,
							dstMAC:     bmc.MAC,
							proto:      ep.proto,
							port:       ep.port,
							ipFamily:   fam,
							state:      "new",
						}, bmc.DisplayName(), ep.function, expected,
					)

					if cell.Verdict == IsolationViolation {
						addrDisp := firstNonEmptyStr(targetIP, bmc.IP)
						cell.RecommendedFix = fmt.Sprintf(
							"Narrow or remove %s rule %q on %s so %s cannot initiate %s %s/%d connections to BMC %s (%s); restrict BMC access strictly to approved admin workstations while preserving established management sessions.",
							strings.ToUpper(fam), cell.DecisiveRuleName, cell.Enforcer, srcNet.Name, strings.ToUpper(fam), strings.ToUpper(ep.proto), ep.port, bmc.DisplayName(), addrDisp,
						)
						checkID := "UB-UNIFI-ISO-BMC-PATH"
						if fam == "ipv6" {
							checkID = "UB-UNIFI-ISO-BMC-IPV6"
						}
						findings = append(findings, checks.Finding{
							CheckID:           checkID,
							Title:             fmt.Sprintf("Configured %s Path Permits %s -> BMC %s (%s)", strings.ToUpper(fam), srcNet.Name, bmc.DisplayName(), cell.DecisiveRuleName),
							Category:          "isolation-policy",
							ClaimKind:         checks.ClaimConfiguredAccess,
							Property:          fmt.Sprintf("isolation-bmc-%s-%s-%s-%d", strings.ToLower(srcNet.Name), fam, ep.proto, ep.port),
							Transport:         ep.proto,
							BaseSeverity:      checks.SeverityHigh,
							EffectiveSeverity: checks.SeverityHigh,
							RiskReasons: []string{
								fmt.Sprintf("configured %s access from %s (%s) to BMC %s via %q", fam, srcNet.Name, srcZone, bmc.DisplayName(), cell.DecisiveRuleName),
							},
							Client:   bmc,
							Port:     ep.port,
							Evidence: fmt.Sprintf("source=%s (%s) -> dest=%s (%s, function=%s, family=%s, enforcer=%s, decisive_rule=%q)", srcNet.Name, srcZone, bmc.DisplayName(), addrDisp, ep.function, fam, cell.Enforcer, cell.DecisiveRuleName),
							Remediation: checks.Remediation{
								Summary:      cell.RecommendedFix,
								UniFiActions: []string{"narrow_firewall_policy", "restrict_bmc_access_to_admin_ips"},
							},
						})
					}
					addCell(cell)
				}
			}
		}
	}

	// 2. Evaluate Guest/Untrusted -> Printer (Approved IPPS Printing vs Blocked Printer Admin)
	// across both IPv4 and IPv6 whenever IPv6 context is present on the site/printer.
	for _, prn := range printerClients {
		prnNet := lookupClientNetwork(prn, netByID, netByName)
		prnZone := strings.TrimSpace(prnNet.ZoneName)
		printPort := printerServicePort(prn, rawFindings, intent)
		cupsAdminOn631 := hasCUPSAdminFinding(prn, rawFindings)

		for _, srcNet := range untrustedNets {
			if !isGuestNetwork(srcNet, intent) && !strings.EqualFold(srcNet.ZoneName, "hotspot") {
				continue
			}
			srcZone := strings.TrimSpace(srcNet.ZoneName)

			for _, fam := range []string{"ipv4", "ipv6"} {
				if fam == "ipv6" && !siteHasIPv6Context(snap, srcNet, prnNet, prn) {
					continue
				}
				prnAddr := clientAddressForFamily(prn, fam)
				addrDisp := firstNonEmptyStr(prnAddr, prn.IP)

				// 2a. IPPS/IPP Printing (default TCP 631).
				ippsExpected := "deny"
				if hasApprovedPath(intent.ApprovedPaths, srcZone, srcNet.Name, prn, prnZone, "printing", "tcp", printPort, fam) {
					ippsExpected = "allow"
				}
				ippsCell := evaluateRoutedPath(
					snap, sortedPolicies, gwPoliciesAvailable, gwMissingReason,
					switchACLStatus, switchACLReason, gwName, srcNet, prnNet,
					pathQuery{
						srcZone:    srcZone,
						srcNetID:   srcNet.ID,
						srcNetName: srcNet.Name,
						dstZone:    prnZone,
						dstNetID:   prnNet.ID,
						dstNetName: prnNet.Name,
						dstIP:      prnAddr,
						dstMAC:     prn.MAC,
						proto:      "tcp",
						port:       printPort,
						ipFamily:   fam,
						state:      "new",
					}, prn.DisplayName(), "ipps-printing", ippsExpected,
				)
				if ippsCell.Verdict == IsolationBrokenDependency {
					ippsCell.RecommendedFix = fmt.Sprintf(
						"Allow %s -> %s (%s, %s) strictly on TCP %d (IPPS) for approved printing while keeping printer administration (TCP 80/443) denied.",
						srcNet.Name, prn.DisplayName(), addrDisp, fam, printPort,
					)
					notes = append(notes, PostureNote{
						Severity: checks.SeverityMedium,
						Title:    fmt.Sprintf("Approved guest printing path blocked (%s -> %s IPPS :%d, %s)", srcNet.Name, prn.DisplayName(), printPort, fam),
						Detail:   ippsCell.RecommendedFix,
					})
				}
				addCell(ippsCell)

				// If CUPS exposes unauthenticated /admin on the same 631 printing socket
				// and guests can reach 631, surface the shared-socket admin violation.
				if cupsAdminOn631 && ippsCell.Effective == "allow" {
					sharedCell := IsolationCell{
						SourceZone:       srcZone,
						SourceNetwork:    srcNet.Name,
						DestZone:         prnZone,
						DestNetwork:      prnNet.Name,
						DestHost:         prn.DisplayName(),
						DestIP:           addrDisp,
						DestFunction:     "printer-admin-shared-ipp",
						Transport:        "tcp",
						Port:             printPort,
						IPFamily:         fam,
						PathKind:         ippsCell.PathKind,
						Enforcer:         ippsCell.Enforcer + " + CUPS /admin",
						Expected:         "deny",
						Effective:        "allow",
						Verdict:          IsolationViolation,
						DecisiveRuleID:   ippsCell.DecisiveRuleID,
						DecisiveRuleName: ippsCell.DecisiveRuleName,
						DecisiveReason:   fmt.Sprintf("CUPS serves /admin on TCP %d (%s) alongside IPP printing, reachable via %q", printPort, fam, ippsCell.DecisiveRuleName),
						RecommendedFix:   fmt.Sprintf("Restrict CUPS /admin on %s to localhost/admin IPs in cupsd.conf because firewall rules on TCP %d cannot separate printing from CUPS administration.", prn.DisplayName(), printPort),
					}
					findings = append(findings, checks.Finding{
						CheckID:           "UB-UNIFI-ISO-PRINTER-ADMIN",
						Title:             fmt.Sprintf("Guest Network Can Reach CUPS Administration on Shared Print Port (%s -> %s:%d, %s)", srcNet.Name, prn.DisplayName(), printPort, fam),
						Category:          "isolation-policy",
						ClaimKind:         checks.ClaimConfiguredAccess,
						Property:          fmt.Sprintf("isolation-printer-admin-%s-%s-%d", strings.ToLower(srcNet.Name), fam, printPort),
						Transport:         "tcp",
						BaseSeverity:      checks.SeverityHigh,
						EffectiveSeverity: checks.SeverityHigh,
						Client:            prn,
						Port:              printPort,
						Evidence:          sharedCell.DecisiveReason,
						Remediation: checks.Remediation{
							Summary:      sharedCell.RecommendedFix,
							UniFiActions: []string{"restrict_cups_admin_acl"},
						},
					})
					addCell(sharedCell)
				}

				// 2b. Dedicated Printer Web Administration (TCP 443 / 80) must be denied from Guest.
				for _, adminPort := range []int{443, 80} {
					adminCell := evaluateRoutedPath(
						snap, sortedPolicies, gwPoliciesAvailable, gwMissingReason,
						switchACLStatus, switchACLReason, gwName, srcNet, prnNet,
						pathQuery{
							srcZone:    srcZone,
							srcNetID:   srcNet.ID,
							srcNetName: srcNet.Name,
							dstZone:    prnZone,
							dstNetID:   prnNet.ID,
							dstNetName: prnNet.Name,
							dstIP:      prnAddr,
							dstMAC:     prn.MAC,
							proto:      "tcp",
							port:       adminPort,
							ipFamily:   fam,
							state:      "new",
						}, prn.DisplayName(), "printer-admin", "deny",
					)

					if adminCell.Verdict == IsolationViolation {
						adminCell.RecommendedFix = fmt.Sprintf(
							"Restrict rule %q so %s can reach %s (%s, %s) only on TCP %d (IPPS printing) and deny printer web administration on TCP %d.",
							adminCell.DecisiveRuleName, srcNet.Name, prn.DisplayName(), addrDisp, fam, printPort, adminPort,
						)
						findings = append(findings, checks.Finding{
							CheckID:           "UB-UNIFI-ISO-PRINTER-ADMIN",
							Title:             fmt.Sprintf("Guest Network Can Reach Printer Administration (%s -> %s:%d, %s)", srcNet.Name, prn.DisplayName(), adminPort, fam),
							Category:          "isolation-policy",
							ClaimKind:         checks.ClaimConfiguredAccess,
							Property:          fmt.Sprintf("isolation-printer-admin-%s-%s-%d", strings.ToLower(srcNet.Name), fam, adminPort),
							Transport:         "tcp",
							BaseSeverity:      checks.SeverityMedium,
							EffectiveSeverity: checks.SeverityMedium,
							Client:            prn,
							Port:              adminPort,
							Evidence:          fmt.Sprintf("source=%s (%s) -> printer=%s (%s:%d, %s) allowed by %q", srcNet.Name, srcZone, prn.DisplayName(), addrDisp, adminPort, fam, adminCell.DecisiveRuleName),
							Remediation: checks.Remediation{
								Summary:      adminCell.RecommendedFix,
								UniFiActions: []string{"scope_inter_zone_policy"},
							},
						})
					}
					addCell(adminCell)
				}
			}
		}
	}

	// 2c. Evaluate any custom operator-declared ApprovedPaths (e.g., camera->NVR,
	// monitor->UPS, workstation->backup) not already handled by BMC or Printer checks.
	for _, ap := range intent.ApprovedPaths {
		if ap.Port <= 0 {
			continue
		}
		fnLow := strings.ToLower(strings.TrimSpace(ap.Function))
		if strings.Contains(fnLow, "bmc") || strings.Contains(fnLow, "print") || strings.Contains(fnLow, "ipp") {
			continue
		}
		proto := strings.ToLower(strings.TrimSpace(ap.Transport))
		if proto == "" {
			proto = "tcp"
		}
		funcLabel := firstNonEmptyStr(ap.Function, ap.Name, fmt.Sprintf("approved-%s-%d", proto, ap.Port))
		var srcNets []unifi.Network
		if strings.TrimSpace(ap.SourceZone) != "" {
			for _, n := range snap.Networks {
				if strings.EqualFold(n.ZoneName, ap.SourceZone) || strings.EqualFold(n.Name, ap.SourceZone) {
					srcNets = append(srcNets, n)
				}
			}
		}
		if len(srcNets) == 0 {
			continue
		}
		type approvedTarget struct {
			client unifi.Client
			net    unifi.Network
		}
		var targets []approvedTarget
		if ap.DestIP != "" {
			dstClient := unifi.Client{IP: ap.DestIP}
			for _, cl := range snap.Clients {
				for _, ip := range cl.AllIPs() {
					if canonicalIsolationIP(ip) != "" && canonicalIsolationIP(ip) == canonicalIsolationIP(ap.DestIP) {
						dstClient = cl
						break
					}
				}
			}
			dstNet := lookupClientNetwork(dstClient, netByID, netByName)
			if dstNet.Name == "" && ap.DestZone != "" {
				for _, n := range snap.Networks {
					if strings.EqualFold(n.ZoneName, ap.DestZone) || strings.EqualFold(n.Name, ap.DestZone) {
						dstNet = n
						break
					}
				}
			}
			if dstNet.Name != "" {
				targets = append(targets, approvedTarget{client: dstClient, net: dstNet})
			}
		} else if strings.TrimSpace(ap.DestRole) != "" {
			for _, cl := range snap.Clients {
				clNet := lookupClientNetwork(cl, netByID, netByName)
				if ap.DestZone != "" && !strings.EqualFold(clNet.ZoneName, ap.DestZone) && !strings.EqualFold(clNet.Name, ap.DestZone) {
					continue
				}
				if clNet.Name == "" {
					continue
				}
				if clientMatchesApprovedRole(cl, rawFindings, ap.DestRole, ap.Function) {
					targets = append(targets, approvedTarget{client: cl, net: clNet})
				}
			}
		}
		if len(targets) == 0 && ap.DestZone != "" {
			for _, n := range snap.Networks {
				if strings.EqualFold(n.ZoneName, ap.DestZone) || strings.EqualFold(n.Name, ap.DestZone) {
					targets = append(targets, approvedTarget{net: n})
					break
				}
			}
		}
		if len(targets) == 0 {
			continue
		}
		fams := []string{"ipv4"}
		switch strings.ToLower(strings.TrimSpace(ap.IPVersion)) {
		case "ipv6":
			fams = []string{"ipv6"}
		case "both", "ipv4_and_ipv6":
			fams = []string{"ipv4", "ipv6"}
		}
		for _, tgt := range targets {
			dstClient := tgt.client
			dstNet := tgt.net
			dstZone := firstNonEmptyStr(dstNet.ZoneName, ap.DestZone)
			dstName := firstNonEmptyStr(dstClient.DisplayName(), ap.DestIP, dstNet.Name)
			for _, srcNet := range srcNets {
				srcZone := strings.TrimSpace(srcNet.ZoneName)
				for _, fam := range fams {
					if fam == "ipv6" && !siteHasIPv6Context(snap, srcNet, dstNet, dstClient) {
						continue
					}
					dstAddr := firstNonEmptyStr(clientAddressForFamily(dstClient, fam), ap.DestIP)
					cell := evaluateRoutedPath(
						snap, sortedPolicies, gwPoliciesAvailable, gwMissingReason,
						switchACLStatus, switchACLReason, gwName, srcNet, dstNet,
						pathQuery{
							srcZone:    srcZone,
							srcNetID:   srcNet.ID,
							srcNetName: srcNet.Name,
							dstZone:    dstZone,
							dstNetID:   dstNet.ID,
							dstNetName: dstNet.Name,
							dstIP:      dstAddr,
							dstMAC:     dstClient.MAC,
							proto:      proto,
							port:       ap.Port,
							ipFamily:   fam,
							state:      "new",
						}, dstName, funcLabel, "allow",
					)
					if cell.Verdict == IsolationBrokenDependency {
						cell.RecommendedFix = fmt.Sprintf(
							"Allow %s -> %s (%s, %s) on %s %d to restore approved workflow %q.",
							srcNet.Name, dstName, dstAddr, fam, strings.ToUpper(proto), ap.Port, firstNonEmptyStr(ap.Name, funcLabel),
						)
						notes = append(notes, PostureNote{
							Severity: checks.SeverityMedium,
							Title:    fmt.Sprintf("Approved workflow blocked (%s -> %s %s:%d, %s)", srcNet.Name, dstName, strings.ToUpper(proto), ap.Port, fam),
							Detail:   cell.RecommendedFix,
						})
					}
					addCell(cell)
				}
			}
		}
	}

	// 3. Evaluate L3 Switch-Routed and Inter-Zone Untrusted -> Trusted Boundaries
	// (including IPv4/IPv6 parity and switch ACL availability) plus gateway admin and DNS/DHCP.
	gwIPs := allGatewayIPs(snap, gwIP)
	for _, srcNet := range untrustedNets {
		srcZone := strings.TrimSpace(srcNet.ZoneName)
		for _, dstNet := range trustedNets {
			dstZone := strings.TrimSpace(dstNet.ZoneName)
			for _, fam := range []string{"ipv4", "ipv6"} {
				if fam == "ipv6" && !siteHasIPv6Context(snap, srcNet, dstNet, unifi.Client{}) {
					continue
				}
				cell := evaluateTransitBoundary(
					snap, rawFindings, sortedPolicies, intent, gwPoliciesAvailable, gwMissingReason,
					switchACLStatus, switchACLReason, gwName, srcNet, dstNet,
					srcZone, dstZone, fam,
				)
				if cell.Verdict == IsolationViolation {
					cell.RecommendedFix = fmt.Sprintf(
						"Block or narrow %s rule %q on %s so %s cannot initiate new connections into trusted network %s (preserve established return traffic).",
						strings.ToUpper(fam), cell.DecisiveRuleName, cell.Enforcer, srcNet.Name, dstNet.Name,
					)
					findings = append(findings, checks.Finding{
						CheckID:           "UB-UNIFI-ISO-TRUSTED-TRANSIT",
						Title:             fmt.Sprintf("Isolated Network Permitted %s Transit to Trusted LAN (%s -> %s)", strings.ToUpper(fam), srcNet.Name, dstNet.Name),
						Category:          "isolation-policy",
						ClaimKind:         checks.ClaimConfiguredAccess,
						Property:          fmt.Sprintf("isolation-transit-%s-%s-%s", strings.ToLower(srcNet.Name), strings.ToLower(dstNet.Name), fam),
						Transport:         cell.Transport,
						BaseSeverity:      checks.SeverityHigh,
						EffectiveSeverity: checks.SeverityHigh,
						Client:            unifi.Client{MAC: "iso:" + srcNet.ID + ":" + dstNet.ID, IP: gwIP, Name: fmt.Sprintf("%s -> %s", srcNet.Name, dstNet.Name), NetworkName: srcNet.Name},
						Port:              cell.Port,
						Evidence:          fmt.Sprintf("source=%s (%s) -> dest=%s (%s, family=%s, proto=%s/%d, enforcer=%s, decisive_rule=%q)", srcNet.Name, srcZone, dstNet.Name, dstZone, fam, cell.Transport, cell.Port, cell.Enforcer, cell.DecisiveRuleName),
						Remediation: checks.Remediation{
							Summary:      cell.RecommendedFix,
							UniFiActions: []string{"block_untrusted_to_trusted_transit"},
						},
					})
				} else if cell.Verdict == IsolationUnknown && cell.MissingInput != "" {
					notes = append(notes, PostureNote{
						Severity: checks.SeverityLow,
						Title:    fmt.Sprintf("Isolation verdict unknown for %s -> %s (%s)", srcNet.Name, dstNet.Name, strings.ToUpper(fam)),
						Detail:   cell.MissingInput,
					})
				}
				addCell(cell)
			}
		}

		// 3b. Untrusted -> Gateway Administration (always enforced by the Gateway Zone Firewall, never an L3 switch).
		gwAdminCell := evaluateGatewayAdminBoundary(
			snap, sortedPolicies, gwPoliciesAvailable, gwMissingReason,
			switchACLStatus, switchACLReason, gwName, gwIPs, srcNet, srcZone,
		)
		if gwAdminCell.Verdict == IsolationViolation {
			gwAdminCell.RecommendedFix = fmt.Sprintf(
				"Block %s -> Gateway administration (TCP 443/22) in rule %q while keeping Gateway DHCP (UDP 67) and DNS (UDP 53) allowed.",
				srcNet.Name, gwAdminCell.DecisiveRuleName,
			)
			findings = append(findings, checks.Finding{
				CheckID:           "UB-UNIFI-ISO-GW-ADMIN",
				Title:             fmt.Sprintf("Untrusted Network Permitted Gateway Administration (%s -> %s)", srcNet.Name, gwName),
				Category:          "isolation-policy",
				ClaimKind:         checks.ClaimConfiguredAccess,
				Property:          "isolation-gw-admin-" + strings.ToLower(srcNet.Name),
				Transport:         gwAdminCell.Transport,
				BaseSeverity:      checks.SeverityHigh,
				EffectiveSeverity: checks.SeverityHigh,
				Client:            unifi.Client{MAC: "gw:" + srcNet.ID, IP: gwIP, Name: gwName, NetworkName: srcNet.Name + " -> Gateway"},
				Port:              gwAdminCell.Port,
				Evidence:          fmt.Sprintf("source=%s (%s) -> gateway=%s (function=gateway-admin, family=ipv4, proto=%s/%d, decisive_rule=%q)", srcNet.Name, srcZone, gwName, gwAdminCell.Transport, gwAdminCell.Port, gwAdminCell.DecisiveRuleName),
				Remediation: checks.Remediation{
					Summary:      gwAdminCell.RecommendedFix,
					UniFiActions: []string{"block_untrusted_gateway_admin"},
				},
			})
		}
		addCell(gwAdminCell)

		// 3c. Essential Gateway Dependencies (DNS UDP 53 & DHCP UDP 67) when gateway policies are available:
		// flag only if an explicit rule breaks them (broken-dependency).
		if gwPoliciesAvailable {
			for _, dep := range []endpointSpec{
				{proto: "udp", port: 53, function: "gateway-dns"},
				{proto: "udp", port: 67, function: "gateway-dhcp"},
			} {
				srcPort := 0
				if dep.function == "gateway-dhcp" {
					// DHCPv4 clients originate requests from UDP port 68 to server port 67.
					srcPort = 68
				}
				depCell := evaluateRoutedPath(
					snap, sortedPolicies, gwPoliciesAvailable, gwMissingReason,
					switchACLStatus, switchACLReason, gwName, srcNet, unifi.Network{Name: "Gateway", ZoneName: "Gateway"},
					pathQuery{
						srcZone:    srcZone,
						srcNetID:   srcNet.ID,
						srcNetName: srcNet.Name,
						srcPort:    srcPort,
						dstZone:    "Gateway",
						dstNetName: "Gateway",
						dstIP:      gwIP,
						proto:      dep.proto,
						port:       dep.port,
						ipFamily:   "ipv4",
						state:      "new",
					}, gwName, dep.function, "allow",
				)
				// Only surface broken-dependency or explicit allow (don't clutter matrix with noisy default-deny DNS/DHCP when no Gateway policy mentions them).
				if depCell.DecisiveRuleID != "" {
					if depCell.Verdict == IsolationBrokenDependency {
						depCell.RecommendedFix = fmt.Sprintf(
							"Permit %s -> Gateway %s (%s/%d) before rule %q so clients retain connectivity.",
							srcNet.Name, dep.function, strings.ToUpper(dep.proto), dep.port, depCell.DecisiveRuleName,
						)
						notes = append(notes, PostureNote{
							Severity: checks.SeverityMedium,
							Title:    fmt.Sprintf("Gateway %s dependency blocked for %s", dep.function, srcNet.Name),
							Detail:   depCell.RecommendedFix,
						})
					}
					addCell(depCell)
				}
			}
		}
	}

	// 4. Evaluate Same-VLAN L2 Peer Isolation (Same-AP Wi-Fi, Cross-AP Wi-Fi, Wired, Mixed).
	sameVLANCells, sameVLANFindings := evaluateSameVLANPeerIsolation(snap, intent, switchACLStatus, switchACLReason, isolatedSet)
	for _, c := range sameVLANCells {
		addCell(c)
	}
	findings = append(findings, sameVLANFindings...)

	return matrix, findings, notes
}

// evaluateRoutedPath resolves the enforcement owner (Gateway vs L3 Switch) and
// computes the effective allow/deny/unknown decision for a single routed path.
func evaluateRoutedPath(
	snap *unifi.Snapshot,
	sortedPolicies []unifi.FirewallPolicy,
	gwPoliciesAvailable bool,
	gwMissingReason string,
	switchACLStatus, switchACLReason, gwName string,
	srcNet, dstNet unifi.Network,
	q pathQuery,
	destHost, destFunction, expected string,
) IsolationCell {
	isGatewayLocal := strings.EqualFold(q.dstZone, "gateway")
	pathKind := "gateway-routed"
	if isGatewayLocal {
		pathKind = "gateway-local"
	}

	cell := IsolationCell{
		SourceZone:    firstNonEmptyStr(q.srcZone, srcNet.Name),
		SourceNetwork: srcNet.Name,
		DestZone:      firstNonEmptyStr(q.dstZone, dstNet.Name),
		DestNetwork:   dstNet.Name,
		DestHost:      destHost,
		DestIP:        q.dstIP,
		DestFunction:  destFunction,
		Transport:     q.proto,
		Port:          q.port,
		IPFamily:      q.ipFamily,
		PathKind:      pathKind,
		Enforcer:      gwName + " (Zone Firewall)",
		Expected:      expected,
	}

	// Gateway-local traffic is ALWAYS evaluated by the UniFi Gateway itself,
	// never by an L3 switch ACL.
	if !isGatewayLocal {
		l3SwitchMAC := firstNonEmptyStr(srcNet.RouterDeviceMAC, dstNet.RouterDeviceMAC)
		if l3SwitchMAC != "" {
			cell.PathKind = "switch-routed"
			swName := deviceNameByMAC(snap, l3SwitchMAC)
			cell.Enforcer = swName + " (L3 Switch ACL)"
			if switchACLStatus != "complete" {
				cell.Effective = "unknown"
				cell.Verdict = IsolationUnknown
				cell.MissingInput = fmt.Sprintf(
					"Switch ACL unavailable for L3 switch %s (%s); gateway firewall rules do not govern switch-routed inter-VLAN traffic.",
					swName, switchACLReason,
				)
				cell.RecommendedFix = fmt.Sprintf(
					"Collect switch ACL configuration from %s (or move routing for %s to the UniFi gateway) to verify effective isolation.",
					swName, firstNonEmptyStr(srcNet.Name, dstNet.Name),
				)
				return cell
			}
			dec := evaluateSwitchACLs(snap.SwitchACLs, l3SwitchMAC, q)
			applyDecisionToCell(&cell, dec)
			return cell
		}
	}

	// Gateway-routed or gateway-local path: require real gateway firewall policy telemetry.
	if !gwPoliciesAvailable {
		cell.Effective = "unknown"
		cell.Verdict = IsolationUnknown
		cell.MissingInput = fmt.Sprintf(
			"Gateway firewall policy telemetry is unavailable (%s); isolation cannot be verified without controller firewall rules.",
			firstNonEmptyStr(gwMissingReason, "firewall policy feed missing"),
		)
		cell.RecommendedFix = "Grant read access to UniFi firewall zones and policies (Integration API v1) to verify effective gateway isolation."
		return cell
	}
	if strings.TrimSpace(q.srcZone) == "" || strings.TrimSpace(q.dstZone) == "" {
		cell.Effective = "unknown"
		cell.Verdict = IsolationUnknown
		cell.MissingInput = fmt.Sprintf(
			"Unresolved firewall zone for %s -> %s; controller did not map one or both networks to a Zone-Based Firewall zone.",
			srcNet.Name, dstNet.Name,
		)
		return cell
	}

	dec := evaluateGatewayPolicies(sortedPolicies, q)
	applyDecisionToCell(&cell, dec)
	return cell
}

func applyDecisionToCell(cell *IsolationCell, dec policyDecision) {
	cell.Effective = dec.action
	cell.DecisiveRuleID = dec.ruleID
	cell.DecisiveRuleName = dec.ruleName
	cell.DecisiveReason = dec.reason
	cell.MissingInput = dec.missingInput

	switch dec.action {
	case "unknown":
		cell.Verdict = IsolationUnknown
	case "allow":
		if cell.Expected == "allow" {
			cell.Verdict = IsolationApproved
		} else {
			cell.Verdict = IsolationViolation
		}
	case "deny":
		if cell.Expected == "deny" {
			cell.Verdict = IsolationBlockedOK
		} else {
			cell.Verdict = IsolationBrokenDependency
		}
	default:
		cell.Verdict = IsolationUnknown
	}
}

// evaluateGatewayPolicies walks ordered UniFi Zone-Based Firewall policies
// respecting Index order, IP family (IPv4 vs IPv6), connection state (new vs
// established/return), schedules, protocol, zone, network ID, IP/CIDR, MAC,
// negation, and port selectors.
func evaluateGatewayPolicies(policies []unifi.FirewallPolicy, q pathQuery) policyDecision {
	for _, pol := range policies {
		if !pol.Enabled {
			continue
		}
		if !matchesIPFamily(pol.IPVersion, q.ipFamily) {
			continue
		}

		// Handle automatic stateful return traffic for ALLOW rules in the reverse direction.
		if strings.EqualFold(q.state, "established") && pol.MatchReturnTraffic && strings.EqualFold(pol.Action, "ALLOW") {
			if matchesPolicyProtocol(pol.Protocol, pol.ProtocolNegated, q.proto) {
				revSrc, _ := matchesEndpoint(pol.Source, q.dstZone, q.dstNetID, q.dstNetName, q.dstIP, q.dstMAC, 0)
				revDst, _ := matchesEndpoint(pol.Destination, q.srcZone, q.srcNetID, q.srcNetName, q.srcIP, q.srcMAC, q.srcPort)
				if revSrc == matchYes && revDst == matchYes {
					return policyDecision{
						action:   "allow",
						ruleID:   pol.ID,
						ruleName: pol.Name,
						reason:   fmt.Sprintf("matched automatic return traffic for ALLOW rule %q (index=%d)", pol.Name, pol.Index),
					}
				}
			}
		}

		if !matchesConnState(pol.ConnectionStates, q.state) {
			continue
		}
		if pol.UnsupportedReason != "" {
			if (pol.Source.ZoneName == "" || strings.EqualFold(pol.Source.ZoneName, q.srcZone)) &&
				(pol.Destination.ZoneName == "" || strings.EqualFold(pol.Destination.ZoneName, q.dstZone)) {
				return policyDecision{
					action:       "unknown",
					ruleID:       pol.ID,
					ruleName:     pol.Name,
					missingInput: fmt.Sprintf("Policy %q uses an unsupported construct (%s)", pol.Name, pol.UnsupportedReason),
				}
			}
			continue
		}
		if !matchesPolicyProtocol(pol.Protocol, pol.ProtocolNegated, q.proto) {
			continue
		}

		srcMatch, srcReason := matchesEndpoint(pol.Source, q.srcZone, q.srcNetID, q.srcNetName, q.srcIP, q.srcMAC, q.srcPort)
		if srcMatch == matchNo {
			continue
		}
		dstMatch, dstReason := matchesEndpoint(pol.Destination, q.dstZone, q.dstNetID, q.dstNetName, q.dstIP, q.dstMAC, q.port)
		if dstMatch == matchNo {
			continue
		}

		if pol.Schedule != "" {
			return policyDecision{
				action:       "unknown",
				ruleID:       pol.ID,
				ruleName:     pol.Name,
				missingInput: fmt.Sprintf("Policy %q is conditional on schedule %q", pol.Name, pol.Schedule),
			}
		}
		if srcMatch == matchUnknown || dstMatch == matchUnknown {
			reason := firstNonEmptyStr(srcReason, dstReason)
			return policyDecision{
				action:       "unknown",
				ruleID:       pol.ID,
				ruleName:     pol.Name,
				missingInput: fmt.Sprintf("Policy %q uses an unsupported or unresolved selector (%s)", pol.Name, reason),
			}
		}

		act := strings.ToUpper(strings.TrimSpace(pol.Action))
		if act == "ALLOW" {
			return policyDecision{
				action:   "allow",
				ruleID:   pol.ID,
				ruleName: pol.Name,
				reason:   fmt.Sprintf("matched ALLOW rule %q (index=%d, family=%s, proto=%s)", pol.Name, pol.Index, firstNonEmptyStr(pol.IPVersion, "both"), firstNonEmptyStr(pol.Protocol, "all")),
			}
		}
		if act == "BLOCK" || act == "REJECT" || act == "DROP" {
			return policyDecision{
				action:   "deny",
				ruleID:   pol.ID,
				ruleName: pol.Name,
				reason:   fmt.Sprintf("matched %s rule %q (index=%d, family=%s)", act, pol.Name, pol.Index, firstNonEmptyStr(pol.IPVersion, "both")),
			}
		}
	}

	// Default UniFi Zone-Based Firewall disposition when controller policies were
	// confirmed retrieved and no explicit rule matched.
	srcZ := strings.ToLower(strings.TrimSpace(q.srcZone))
	dstZ := strings.ToLower(strings.TrimSpace(q.dstZone))
	if srcZ == dstZ {
		return policyDecision{action: "allow", ruleName: "Zone Default (Intra-Zone)", reason: "default intra-zone allow"}
	}
	if srcZ == "internal" {
		return policyDecision{action: "allow", ruleName: "Zone Default (Internal Outbound)", reason: "default Internal-initiated allow"}
	}
	return policyDecision{
		action:   "deny",
		ruleName: fmt.Sprintf("Zone Default (%s -> %s)", q.srcZone, q.dstZone),
		reason:   "default inter-zone deny for isolated/untrusted zone",
	}
}

func evaluateSwitchACLs(acls []unifi.SwitchACL, switchMAC string, q pathQuery) policyDecision {
	sorted := make([]unifi.SwitchACL, len(acls))
	copy(sorted, acls)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Index != sorted[j].Index {
			return sorted[i].Index < sorted[j].Index
		}
		return i < j
	})
	swLower := strings.ToLower(strings.TrimSpace(switchMAC))
	for _, acl := range sorted {
		if !acl.Enabled {
			continue
		}
		if len(acl.DeviceMACs) > 0 {
			if swLower == "" || !containsFold(acl.DeviceMACs, swLower) {
				continue
			}
		}
		if len(acl.NetworkIDs) > 0 {
			netHit := (q.srcNetID != "" && containsFold(acl.NetworkIDs, q.srcNetID)) ||
				(q.srcNetName != "" && containsFold(acl.NetworkIDs, q.srcNetName)) ||
				(q.dstNetID != "" && containsFold(acl.NetworkIDs, q.dstNetID)) ||
				(q.dstNetName != "" && containsFold(acl.NetworkIDs, q.dstNetName))
			if !netHit {
				continue
			}
		}
		if !matchesIPFamily(acl.IPVersion, q.ipFamily) || !matchesProtocol(acl.Protocol, q.proto) {
			continue
		}
		sm, sr := matchesEndpoint(acl.Source, q.srcZone, q.srcNetID, q.srcNetName, q.srcIP, q.srcMAC, q.srcPort)
		dm, dr := matchesEndpoint(acl.Destination, q.dstZone, q.dstNetID, q.dstNetName, q.dstIP, q.dstMAC, q.port)
		if sm == matchNo || dm == matchNo {
			continue
		}
		if sm == matchUnknown || dm == matchUnknown {
			return policyDecision{action: "unknown", ruleID: acl.ID, ruleName: acl.Name, missingInput: firstNonEmptyStr(sr, dr)}
		}
		if strings.EqualFold(acl.Action, "ALLOW") {
			return policyDecision{action: "allow", ruleID: acl.ID, ruleName: acl.Name, reason: "matched switch ACL ALLOW"}
		}
		return policyDecision{action: "deny", ruleID: acl.ID, ruleName: acl.Name, reason: "matched switch ACL BLOCK"}
	}
	return policyDecision{action: "allow", ruleName: "Switch L2/L3 Default", reason: "default switch forwarding without explicit deny ACL"}
}

func evaluateSameVLANPeerIsolation(
	snap *unifi.Snapshot,
	intent config.IsolationIntent,
	switchACLStatus, switchACLReason string,
	isolatedSet map[string]struct{},
) ([]IsolationCell, []checks.Finding) {
	var cells []IsolationCell
	var findings []checks.Finding
	reqSet := toLowerSet(intent.RequireSameVLANIsolation)

	wlansByNet := make(map[string][]unifi.WLANConfig)
	for _, w := range snap.WLANs {
		if w.Enabled && w.NetworkName != "" {
			wlansByNet[strings.ToLower(w.NetworkName)] = append(wlansByNet[strings.ToLower(w.NetworkName)], w)
		}
	}

	portIso := make(map[string]bool)
	portMACCount := make(map[string]int)
	for _, d := range snap.Devices {
		dm := strings.ToLower(d.MAC)
		for _, p := range d.Ports {
			k := fmt.Sprintf("%s|%d", dm, p.PortIdx)
			portIso[k] = p.Isolation
			portMACCount[k] = p.MACTableCount
		}
	}

	for _, n := range snap.Networks {
		nLow := strings.ToLower(n.Name)
		_, explicitReq := reqSet[nLow]
		_, isIso := isolatedSet[nLow]
		if !explicitReq && !isIso && !isGuestNetwork(n, intent) {
			continue
		}
		zoneLabel := firstNonEmptyStr(n.ZoneName, n.Name)

		var wiredClients []unifi.Client
		apSet := make(map[string]int)
		wiredSwitches := make(map[string]struct{})
		for _, cl := range snap.Clients {
			if !strings.EqualFold(cl.NetworkName, n.Name) {
				continue
			}
			if cl.IsWired {
				wiredClients = append(wiredClients, cl)
				if cl.SwitchMAC != "" {
					wiredSwitches[strings.ToLower(cl.SwitchMAC)] = struct{}{}
				}
			} else if cl.APMAC != "" {
				apSet[strings.ToLower(cl.APMAC)]++
			}
		}

		// Same-AP and Cross-AP Wi-Fi paths.
		for _, w := range wlansByNet[nLow] {
			if w.L2Isolation {
				cells = append(cells, IsolationCell{
					SourceZone:     zoneLabel,
					SourceNetwork:  n.Name,
					DestZone:       zoneLabel,
					DestNetwork:    n.Name,
					DestFunction:   "same-vlan-wifi-peers",
					Transport:      "all",
					IPFamily:       "ipv4",
					PathKind:       "same-ap-wifi",
					Enforcer:       fmt.Sprintf("UniFi AP (SSID %q L2 Isolation)", w.Name),
					Expected:       "deny",
					Effective:      "deny",
					Verdict:        IsolationBlockedOK,
					DecisiveReason: "WLAN client device isolation blocks peer-to-peer traffic on the same AP",
				})
			} else if explicitReq {
				c := IsolationCell{
					SourceZone:     zoneLabel,
					SourceNetwork:  n.Name,
					DestZone:       zoneLabel,
					DestNetwork:    n.Name,
					DestFunction:   "same-vlan-wifi-peers",
					Transport:      "all",
					IPFamily:       "ipv4",
					PathKind:       "same-ap-wifi",
					Enforcer:       fmt.Sprintf("UniFi AP (SSID %q)", w.Name),
					Expected:       "deny",
					Effective:      "allow",
					Verdict:        IsolationViolation,
					DecisiveReason: "WLAN l2_isolation is disabled",
					RecommendedFix: fmt.Sprintf("Enable Client Device Isolation on SSID %q.", w.Name),
				}
				cells = append(cells, c)
				findings = append(findings, checks.Finding{
					CheckID:           "UB-UNIFI-ISO-SAME-VLAN",
					Title:             fmt.Sprintf("Same-AP Wi-Fi Client Isolation Disabled on %s (%s)", n.Name, w.Name),
					Category:          "isolation-policy",
					ClaimKind:         checks.ClaimConfiguredAccess,
					Property:          "isolation-same-ap-" + strings.ToLower(w.Name),
					BaseSeverity:      checks.SeverityMedium,
					EffectiveSeverity: checks.SeverityMedium,
					Client:            unifi.Client{MAC: "wlan:" + w.ID, Name: w.Name, NetworkName: n.Name},
					Evidence:          fmt.Sprintf("SSID %q on %s has l2_isolation=false while same-VLAN isolation is required", w.Name, n.Name),
					Remediation: checks.Remediation{
						Summary:      c.RecommendedFix,
						UniFiActions: []string{"enable_wlan_l2_isolation"},
					},
				})
			}

			// Cross-AP Wi-Fi requires switch port isolation or switch ACL beyond AP-local isolation.
			if len(apSet) >= 2 && (explicitReq || w.IsGuest) {
				if switchACLStatus != "complete" {
					cells = append(cells, IsolationCell{
						SourceZone:     zoneLabel,
						SourceNetwork:  n.Name,
						DestZone:       zoneLabel,
						DestNetwork:    n.Name,
						DestFunction:   "cross-ap-wifi-peers",
						Transport:      "all",
						IPFamily:       "ipv4",
						PathKind:       "cross-ap-wifi",
						Enforcer:       "UniFi Switch (ACL / Port Isolation)",
						Expected:       "deny",
						Effective:      "unknown",
						Verdict:        IsolationUnknown,
						MissingInput:   fmt.Sprintf("Clients span %d APs on %s and %s; AP-only isolation does not verify cross-AP switching.", len(apSet), n.Name, switchACLReason),
						RecommendedFix: "Verify switch ACLs or AP uplink port isolation on switches serving this isolated VLAN.",
					})
				} else {
					dec := evaluateSwitchACLs(snap.SwitchACLs, "", pathQuery{
						srcZone:    zoneLabel,
						srcNetID:   n.ID,
						srcNetName: n.Name,
						dstZone:    zoneLabel,
						dstNetID:   n.ID,
						dstNetName: n.Name,
						proto:      "all",
						ipFamily:   "ipv4",
						state:      "new",
					})
					c := IsolationCell{
						SourceZone:    zoneLabel,
						SourceNetwork: n.Name,
						DestZone:      zoneLabel,
						DestNetwork:   n.Name,
						DestFunction:  "cross-ap-wifi-peers",
						Transport:     "all",
						IPFamily:      "ipv4",
						PathKind:      "cross-ap-wifi",
						Enforcer:      "UniFi Switch (L2 Switch ACL)",
						Expected:      "deny",
					}
					applyDecisionToCell(&c, dec)
					if c.Verdict == IsolationViolation {
						c.RecommendedFix = fmt.Sprintf("Add a switch ACL blocking intra-VLAN peer traffic on %s or isolate AP switch ports.", n.Name)
						findings = append(findings, checks.Finding{
							CheckID:           "UB-UNIFI-ISO-SAME-VLAN",
							Title:             fmt.Sprintf("Cross-AP Wi-Fi Peer Traffic Permitted on %s", n.Name),
							Category:          "isolation-policy",
							ClaimKind:         checks.ClaimConfiguredAccess,
							Property:          "isolation-cross-ap-" + nLow,
							BaseSeverity:      checks.SeverityMedium,
							EffectiveSeverity: checks.SeverityMedium,
							Client:            unifi.Client{MAC: "vlan:" + n.ID, Name: n.Name, NetworkName: n.Name},
							Evidence:          fmt.Sprintf("clients span %d APs on %s and switch ACLs do not block intra-VLAN peer traffic (%s)", len(apSet), n.Name, c.DecisiveRuleName),
							Remediation: checks.Remediation{
								Summary:      c.RecommendedFix,
								UniFiActions: []string{"add_switch_l2_isolation_acl"},
							},
						})
					}
					cells = append(cells, c)
				}
			}
		}

		// Wired same-VLAN peer isolation (gateway never sees local L2 switching).
		// Port isolation alone guarantees L2 peer isolation ONLY when all wired
		// clients sit on a single switch, on distinct isolated ports, with at
		// most 1 MAC per port (ruling out cross-switch uplinks and unmanaged
		// downstream switches behind an isolated port).
		if len(wiredClients) >= 2 || (explicitReq && len(wiredClients) >= 1) {
			allPortsIsolated := len(wiredClients) > 0 && len(wiredSwitches) == 1
			seenPort := make(map[string]struct{}, len(wiredClients))
			if allPortsIsolated {
				for _, wc := range wiredClients {
					if wc.SwitchMAC == "" || wc.SwitchPort <= 0 {
						allPortsIsolated = false
						break
					}
					pk := fmt.Sprintf("%s|%d", strings.ToLower(wc.SwitchMAC), wc.SwitchPort)
					if !portIso[pk] || portMACCount[pk] > 1 {
						allPortsIsolated = false
						break
					}
					if _, dup := seenPort[pk]; dup {
						allPortsIsolated = false
						break
					}
					seenPort[pk] = struct{}{}
				}
			}
			if allPortsIsolated {
				cells = append(cells, IsolationCell{
					SourceZone:     zoneLabel,
					SourceNetwork:  n.Name,
					DestZone:       zoneLabel,
					DestNetwork:    n.Name,
					DestFunction:   "same-vlan-wired-peers",
					Transport:      "all",
					IPFamily:       "ipv4",
					PathKind:       "wired-same-vlan",
					Enforcer:       "UniFi Switch (L2 Port Isolation)",
					Expected:       "deny",
					Effective:      "deny",
					Verdict:        IsolationBlockedOK,
					DecisiveReason: "all wired clients sit on distinct isolated ports on one switch",
				})
			} else if explicitReq {
				if switchACLStatus != "complete" {
					cells = append(cells, IsolationCell{
						SourceZone:     zoneLabel,
						SourceNetwork:  n.Name,
						DestZone:       zoneLabel,
						DestNetwork:    n.Name,
						DestFunction:   "same-vlan-wired-peers",
						Transport:      "all",
						IPFamily:       "ipv4",
						PathKind:       "wired-same-vlan",
						Enforcer:       "UniFi Switch (ACL)",
						Expected:       "deny",
						Effective:      "unknown",
						Verdict:        IsolationUnknown,
						MissingInput:   fmt.Sprintf("Switch ACL unavailable (%s); gateway firewall cannot filter same-VLAN wired switching on %s (multi-switch or shared-port L2 traffic is not isolated by port flags alone).", switchACLReason, n.Name),
						RecommendedFix: fmt.Sprintf("Enable switch port isolation on distinct single-switch ports or provide switch ACL data for %s.", n.Name),
					})
				} else {
					sortedSwitches := make([]string, 0, len(wiredSwitches))
					for m := range wiredSwitches {
						sortedSwitches = append(sortedSwitches, m)
					}
					sort.Strings(sortedSwitches)
					if len(sortedSwitches) == 0 {
						sortedSwitches = []string{""}
					}
					// Evaluate ACLs across every switch carrying wired clients on this VLAN;
					// worst verdict wins (allow > unknown > deny) deterministically.
					var worstDec policyDecision
					worstSW := ""
					for idxSW, swMAC := range sortedSwitches {
						dec := evaluateSwitchACLs(snap.SwitchACLs, swMAC, pathQuery{
							srcZone:    zoneLabel,
							srcNetID:   n.ID,
							srcNetName: n.Name,
							dstZone:    zoneLabel,
							dstNetID:   n.ID,
							dstNetName: n.Name,
							proto:      "all",
							ipFamily:   "ipv4",
							state:      "new",
						})
						if idxSW == 0 ||
							dec.action == "allow" ||
							(dec.action == "unknown" && worstDec.action != "allow") {
							worstDec = dec
							worstSW = swMAC
						}
						if worstDec.action == "allow" {
							break
						}
					}
					enforcer := "UniFi Switch (L2 Switch ACL)"
					if worstSW != "" {
						enforcer = deviceNameByMAC(snap, worstSW) + " (L2 Switch ACL)"
					}
					c := IsolationCell{
						SourceZone:    zoneLabel,
						SourceNetwork: n.Name,
						DestZone:      zoneLabel,
						DestNetwork:   n.Name,
						DestFunction:  "same-vlan-wired-peers",
						Transport:     "all",
						IPFamily:      "ipv4",
						PathKind:      "wired-same-vlan",
						Enforcer:      enforcer,
						Expected:      "deny",
					}
					applyDecisionToCell(&c, worstDec)
					if c.Verdict == IsolationViolation {
						c.RecommendedFix = fmt.Sprintf("Enable switch port isolation on wired %s ports or add a switch L2 deny ACL.", n.Name)
						findings = append(findings, checks.Finding{
							CheckID:           "UB-UNIFI-ISO-SAME-VLAN",
							Title:             fmt.Sprintf("Same-VLAN Wired Peer Traffic Permitted on %s", n.Name),
							Category:          "isolation-policy",
							ClaimKind:         checks.ClaimConfiguredAccess,
							Property:          "isolation-wired-" + nLow,
							BaseSeverity:      checks.SeverityMedium,
							EffectiveSeverity: checks.SeverityMedium,
							Client:            unifi.Client{MAC: "vlan:" + n.ID, Name: n.Name, NetworkName: n.Name},
							Evidence:          fmt.Sprintf("wired clients on %s lack port isolation and switch ACLs permit intra-VLAN traffic (%s)", n.Name, c.DecisiveRuleName),
							Remediation: checks.Remediation{
								Summary:      c.RecommendedFix,
								UniFiActions: []string{"enable_switch_port_isolation"},
							},
						})
					}
					cells = append(cells, c)
				}
			}
		}

		// Mixed wired <-> Wi-Fi peers on the same isolated VLAN.
		if explicitReq && len(wiredClients) >= 1 && len(apSet) >= 1 {
			if switchACLStatus != "complete" {
				cells = append(cells, IsolationCell{
					SourceZone:     zoneLabel,
					SourceNetwork:  n.Name,
					DestZone:       zoneLabel,
					DestNetwork:    n.Name,
					DestFunction:   "same-vlan-mixed-peers",
					Transport:      "all",
					IPFamily:       "ipv4",
					PathKind:       "mixed-same-vlan",
					Enforcer:       "UniFi Switch (ACL / Port Isolation)",
					Expected:       "deny",
					Effective:      "unknown",
					Verdict:        IsolationUnknown,
					MissingInput:   fmt.Sprintf("Both wired and wireless clients share %s and %s; AP isolation alone does not isolate wired-to-Wi-Fi traffic.", n.Name, switchACLReason),
					RecommendedFix: fmt.Sprintf("Isolate switch ports or apply a switch L2 ACL on %s.", n.Name),
				})
			} else {
				dec := evaluateSwitchACLs(snap.SwitchACLs, "", pathQuery{
					srcZone:    zoneLabel,
					srcNetID:   n.ID,
					srcNetName: n.Name,
					dstZone:    zoneLabel,
					dstNetID:   n.ID,
					dstNetName: n.Name,
					proto:      "all",
					ipFamily:   "ipv4",
					state:      "new",
				})
				c := IsolationCell{
					SourceZone:    zoneLabel,
					SourceNetwork: n.Name,
					DestZone:      zoneLabel,
					DestNetwork:   n.Name,
					DestFunction:  "same-vlan-mixed-peers",
					Transport:     "all",
					IPFamily:      "ipv4",
					PathKind:      "mixed-same-vlan",
					Enforcer:      "UniFi Switch (L2 Switch ACL)",
					Expected:      "deny",
				}
				applyDecisionToCell(&c, dec)
				if c.Verdict == IsolationViolation {
					c.RecommendedFix = fmt.Sprintf("Isolate wired switch ports and AP uplinks or add a switch L2 deny ACL on %s.", n.Name)
					findings = append(findings, checks.Finding{
						CheckID:           "UB-UNIFI-ISO-SAME-VLAN",
						Title:             fmt.Sprintf("Same-VLAN Wired-to-Wi-Fi Peer Traffic Permitted on %s", n.Name),
						Category:          "isolation-policy",
						ClaimKind:         checks.ClaimConfiguredAccess,
						Property:          "isolation-mixed-" + nLow,
						BaseSeverity:      checks.SeverityMedium,
						EffectiveSeverity: checks.SeverityMedium,
						Client:            unifi.Client{MAC: "vlan:" + n.ID, Name: n.Name, NetworkName: n.Name},
						Evidence:          fmt.Sprintf("wired and Wi-Fi clients on %s can communicate via switch (%s)", n.Name, c.DecisiveRuleName),
						Remediation: checks.Remediation{
							Summary:      c.RecommendedFix,
							UniFiActions: []string{"add_switch_l2_isolation_acl"},
						},
					})
				}
				cells = append(cells, c)
			}
		}
	}
	return cells, findings
}

type triMatch int

const (
	matchNo triMatch = iota
	matchYes
	matchUnknown
)

func matchesEndpoint(ep unifi.PolicyEndpoint, zone, netID, netName, ip, mac string, port int) (triMatch, string) {
	if ep.ZoneID != "" && ep.ZoneName == "" {
		return matchUnknown, fmt.Sprintf("unresolved firewall zone ID %q", ep.ZoneID)
	}
	if ep.ZoneName != "" && !strings.EqualFold(ep.ZoneName, zone) {
		return matchNo, ""
	}
	if ep.UnsupportedSelector != "" {
		return matchUnknown, ep.UnsupportedSelector
	}

	// Evaluate port constraints first when the query fixes a concrete port:
	// a definitive port mismatch (matchNo) rules out the policy even if the
	// target selector names a host IP not fixed in a zone-level query.
	portUnknownReason := ""
	if !ep.AnyPort {
		if !ep.HasPortConstraint() {
			portUnknownReason = "port group selector unresolved"
		} else if port == 0 {
			portUnknownReason = "policy restricts specific port(s) not fixed in query"
		} else {
			portState := matchNo
			if ep.MatchesPort(port) {
				portState = matchYes
			}
			if ep.NegatePort {
				if portState == matchYes {
					portState = matchNo
				} else {
					portState = matchYes
				}
			}
			if portState == matchNo {
				return matchNo, ""
			}
		}
	}

	if !ep.AnyTarget {
		hasSelector := len(ep.IPs) > 0 || len(ep.NetworkIDs) > 0 || len(ep.MACs) > 0
		if !hasSelector {
			return matchUnknown, "opaque target filter without IP/network/MAC details"
		}
		targetState := matchNo
		if len(ep.NetworkIDs) > 0 {
			if (netID != "" && containsFold(ep.NetworkIDs, netID)) || (netName != "" && containsFold(ep.NetworkIDs, netName)) {
				targetState = matchYes
			}
		}
		if targetState != matchYes && len(ep.MACs) > 0 {
			if mac == "" {
				targetState = matchUnknown
			} else if containsFold(ep.MACs, mac) {
				targetState = matchYes
			}
		}
		if targetState != matchYes && len(ep.IPs) > 0 {
			if ip == "" {
				// Rule targets specific IPs while query evaluates a whole zone/network.
				targetState = matchUnknown
			} else {
				for _, candidate := range ep.IPs {
					m := ipMatchesSelectorTri(ip, candidate)
					if m == matchYes {
						targetState = matchYes
						break
					}
					if m == matchUnknown && targetState == matchNo {
						targetState = matchUnknown
					}
				}
			}
		}
		if targetState == matchUnknown {
			return matchUnknown, "policy targets specific or unparsed IP/MAC not resolved in query"
		}
		if ep.NegateTarget {
			if targetState == matchYes {
				targetState = matchNo
			} else {
				targetState = matchYes
			}
		}
		if targetState == matchNo {
			return matchNo, ""
		}
	}

	if portUnknownReason != "" {
		return matchUnknown, portUnknownReason
	}
	return matchYes, ""
}

func ipMatchesSelectorTri(targetIP, selector string) triMatch {
	targetIP = strings.TrimSpace(targetIP)
	selector = strings.TrimSpace(selector)
	if targetIP == "" || selector == "" {
		return matchUnknown
	}
	if strings.EqualFold(targetIP, selector) {
		return matchYes
	}
	addr, err1 := netip.ParseAddr(targetIP)
	if err1 != nil {
		return matchUnknown
	}
	addr = addr.Unmap()
	if pfx, err2 := netip.ParsePrefix(selector); err2 == nil {
		if pfx.Contains(addr) {
			return matchYes
		}
		return matchNo
	}
	if sAddr, err3 := netip.ParseAddr(selector); err3 == nil {
		if addr == sAddr.Unmap() {
			return matchYes
		}
		return matchNo
	}
	// Support IP ranges such as "10.0.1.10-10.0.1.40".
	if startStr, endStr, ok := strings.Cut(selector, "-"); ok {
		a1, e1 := netip.ParseAddr(strings.TrimSpace(startStr))
		a2, e2 := netip.ParseAddr(strings.TrimSpace(endStr))
		if e1 == nil && e2 == nil {
			a1, a2 = a1.Unmap(), a2.Unmap()
			if a1.Is4() == addr.Is4() && a2.Is4() == addr.Is4() {
				if addr.Compare(a1) >= 0 && addr.Compare(a2) <= 0 {
					return matchYes
				}
				return matchNo
			}
			return matchNo
		}
	}
	return matchUnknown
}

func clientAddressForFamily(cl unifi.Client, fam string) string {
	if strings.EqualFold(fam, "ipv6") {
		for _, ip6 := range cl.IPv6 {
			if addr, err := netip.ParseAddr(strings.TrimSpace(ip6)); err == nil && addr.Is6() {
				return addr.String()
			}
		}
		if addr, err := netip.ParseAddr(strings.TrimSpace(cl.IP)); err == nil && addr.Is6() {
			return addr.String()
		}
		return ""
	}
	if addr, err := netip.ParseAddr(strings.TrimSpace(cl.IP)); err == nil && addr.Is4() {
		return addr.String()
	}
	return cl.IP
}

func bmcServiceEndpoints(bmc unifi.Client, rawFindings []checks.Finding) []endpointSpec {
	seen := make(map[string]bool)
	var out []endpointSpec
	add := func(proto string, port int, fn string) {
		key := fmt.Sprintf("%s:%d", proto, port)
		if seen[key] || port <= 0 {
			return
		}
		seen[key] = true
		out = append(out, endpointSpec{proto: proto, port: port, function: fn})
	}
	for _, f := range rawFindings {
		if !sameClient(f.Client, bmc) {
			continue
		}
		if f.CheckID == "UB-0019" || (f.Port == 623 && strings.EqualFold(f.EffectiveTransport(), "udp")) {
			add("udp", 623, "bmc-ipmi")
			continue
		}
		if f.Category == "oob-bmc" || f.CheckID == "UB-0020" {
			p := f.Port
			if p <= 0 {
				p = 443
			}
			add(f.EffectiveTransport(), p, "bmc-redfish-admin")
		}
	}
	if len(out) == 0 {
		add("tcp", 443, "bmc-redfish-admin")
	}
	return out
}

func printerServicePort(prn unifi.Client, rawFindings []checks.Finding, intent config.IsolationIntent) int {
	for _, f := range rawFindings {
		if sameClient(f.Client, prn) && f.Port > 0 && (f.Port == 631 || strings.Contains(strings.ToLower(f.Title), "ipp")) {
			return f.Port
		}
	}
	for _, ap := range intent.ApprovedPaths {
		if ap.Port > 0 && (ap.DestIP == prn.IP || strings.Contains(strings.ToLower(ap.Function), "print")) {
			return ap.Port
		}
	}
	return 631
}

func hasCUPSAdminFinding(prn unifi.Client, rawFindings []checks.Finding) bool {
	for _, f := range rawFindings {
		if sameClient(f.Client, prn) && f.CheckID == "UB-0041" {
			return true
		}
	}
	return false
}

func sameClient(a, b unifi.Client) bool {
	if a.MAC != "" && b.MAC != "" && strings.EqualFold(a.MAC, b.MAC) {
		return true
	}
	return a.IP != "" && b.IP != "" && a.IP == b.IP
}

func lookupClientNetwork(cl unifi.Client, netByID, netByName map[string]unifi.Network) unifi.Network {
	if cl.NetworkID != "" {
		if n, ok := netByID[cl.NetworkID]; ok {
			return n
		}
	}
	if cl.NetworkName != "" {
		if n, ok := netByName[strings.ToLower(cl.NetworkName)]; ok {
			return n
		}
	}
	return unifi.Network{Name: cl.NetworkName}
}

func matchesIPFamily(ruleVer, queryFam string) bool {
	rv := strings.ToLower(strings.TrimSpace(ruleVer))
	qf := strings.ToLower(strings.TrimSpace(queryFam))
	if rv == "" || rv == "both" || rv == "ipv4_and_ipv6" {
		return true
	}
	return rv == qf
}

func matchesConnState(states []string, queryState string) bool {
	if len(states) == 0 {
		return true
	}
	for _, s := range states {
		if strings.EqualFold(strings.TrimSpace(s), queryState) {
			return true
		}
	}
	return false
}

func matchesPolicyProtocol(ruleProto string, negated bool, queryProto string) bool {
	rp := strings.ToLower(strings.TrimSpace(ruleProto))
	if rp == "" || rp == "all" || rp == "any" {
		return !negated
	}
	base := matchesProtocol(rp, queryProto)
	if negated {
		return !base
	}
	return base
}

func matchesProtocol(ruleProto, queryProto string) bool {
	rp := strings.ToLower(strings.TrimSpace(ruleProto))
	qp := strings.ToLower(strings.TrimSpace(queryProto))
	if rp == "" || rp == "all" || rp == "any" {
		return true
	}
	if qp == "" || qp == "all" {
		return false
	}
	if (rp == "tcp_udp" || rp == "tcp/udp") && (qp == "tcp" || qp == "udp") {
		return true
	}
	return rp == qp
}

func siteHasIPv6Context(snap *unifi.Snapshot, a, b unifi.Network, cl unifi.Client) bool {
	if a.IPv6Subnet != "" || b.IPv6Subnet != "" || len(cl.IPv6) > 0 {
		return true
	}
	for _, pol := range snap.FirewallPolicies {
		if strings.EqualFold(pol.IPVersion, "ipv6") {
			return true
		}
	}
	// Prefix-delegated IPv6 networks often omit static IPv6Subnet in UniFi while
	// clients on those networks carry live IPv6 addresses.
	for _, c := range snap.Clients {
		if len(c.IPv6) == 0 {
			continue
		}
		if (a.Name != "" && strings.EqualFold(c.NetworkName, a.Name)) ||
			(b.Name != "" && strings.EqualFold(c.NetworkName, b.Name)) ||
			(a.ID != "" && c.NetworkID == a.ID) ||
			(b.ID != "" && c.NetworkID == b.ID) {
			return true
		}
	}
	return false
}

func hasApprovedPath(paths []config.ApprovedPath, srcZone, srcNet string, dst unifi.Client, dstZone, fnHint, proto string, port int, fam string) bool {
	for _, ap := range paths {
		if ap.SourceZone != "" && !strings.EqualFold(ap.SourceZone, srcZone) && !strings.EqualFold(ap.SourceZone, srcNet) {
			continue
		}
		if ap.DestIP != "" && !strings.EqualFold(ap.DestIP, dst.IP) && !containsFold(dst.IPv6, ap.DestIP) {
			continue
		}
		if ap.DestZone != "" && !strings.EqualFold(ap.DestZone, dstZone) && !strings.EqualFold(ap.DestZone, dst.NetworkName) {
			continue
		}
		if ap.Port > 0 && ap.Port != port {
			continue
		}
		if ap.Transport != "" && !matchesProtocol(ap.Transport, proto) {
			continue
		}
		if ap.IPVersion != "" && !matchesIPFamily(ap.IPVersion, fam) {
			continue
		}
		if fnHint != "" {
			fnLow := strings.ToLower(fnHint)
			if ap.Function != "" && !matchesApprovedRoleOrFunc(ap.Function, fnLow) && !matchesApprovedRoleOrFunc(ap.DestRole, fnLow) {
				continue
			}
			// Check DestRole independently so an approved path with dest_role="printer"
			// and empty function never approves a BMC path on the same port.
			if ap.DestRole != "" && !matchesApprovedRoleOrFunc(ap.DestRole, fnLow) {
				continue
			}
		}
		return true
	}
	return false
}

func matchesApprovedRoleOrFunc(field, hint string) bool {
	f := strings.ToLower(strings.TrimSpace(field))
	h := strings.ToLower(strings.TrimSpace(hint))
	if f == "" || h == "" {
		return false
	}
	if strings.Contains(f, h) || strings.Contains(h, f) {
		return true
	}
	// Normalize common stems ("printer" <-> "printing" / "ipps-printing").
	if strings.Contains(f, "print") && strings.Contains(h, "print") {
		return true
	}
	return false
}

func canonicalIsolationIP(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap().String()
	}
	return strings.ToLower(s)
}

func clientMatchesApprovedRole(cl unifi.Client, rawFindings []checks.Finding, roleHint, fnHint string) bool {
	hint := strings.ToLower(strings.TrimSpace(firstNonEmptyStr(roleHint, fnHint)))
	if hint == "" {
		return false
	}
	nameText := strings.ToLower(strings.TrimSpace(cl.Name + " " + cl.Hostname + " " + cl.OUI))
	hasFindingText := func(tokens ...string) bool {
		for _, f := range rawFindings {
			if !sameClient(f.Client, cl) {
				continue
			}
			ft := strings.ToLower(f.Title + " " + f.Category + " " + f.CheckID + " " + f.Property)
			for _, tok := range tokens {
				if strings.Contains(ft, tok) {
					return true
				}
			}
		}
		return false
	}
	hasFindingPort := func(ports ...int) bool {
		for _, f := range rawFindings {
			if !sameClient(f.Client, cl) {
				continue
			}
			for _, p := range ports {
				if f.Port == p {
					return true
				}
			}
		}
		return false
	}
	containsAnyToken := func(text string, tokens ...string) bool {
		for _, tok := range tokens {
			if strings.Contains(text, tok) {
				return true
			}
		}
		return false
	}

	switch {
	case strings.Contains(hint, "print") || strings.Contains(hint, "ipp"):
		return containsAnyToken(nameText, "print", "cups", "laserjet", "brother", "epson", "canon") ||
			hasFindingPort(631, 9100) || hasFindingText("ipp", "printer", "cups")
	case strings.Contains(hint, "bmc") || strings.Contains(hint, "ipmi") || strings.Contains(hint, "idrac") || strings.Contains(hint, "ilo"):
		return bmcIdentityPattern.MatchString(cl.Name) || bmcIdentityPattern.MatchString(cl.Hostname) ||
			hasFindingText("oob-bmc", "ub-0019", "ub-0020", "ipmi", "redfish")
	case strings.Contains(hint, "ups") || strings.Contains(hint, "nut") || strings.Contains(hint, "pdu") || strings.Contains(hint, "power"):
		return containsAnyToken(nameText, "ups", "nut", "apc", "eaton", "cyberpower", "pdu") ||
			hasFindingPort(3493) || hasFindingText("ups", "nut", "pdu", "power")
	case strings.Contains(hint, "nvr") || strings.Contains(hint, "recorder") || strings.Contains(hint, "camera") || strings.Contains(hint, "cam"):
		return containsAnyToken(nameText, "nvr", "recorder", "cam", "protect", "frigate", "reolink", "hikvision", "dahua", "axis") ||
			hasFindingPort(554) || hasFindingText("camera", "nvr", "rtsp", "onvif")
	case strings.Contains(hint, "backup") || strings.Contains(hint, "nas") || strings.Contains(hint, "storage"):
		return containsAnyToken(nameText, "backup", "pbs", "veeam", "urbackup", "nas", "truenas", "synology", "qnap") ||
			hasFindingPort(8007) || hasFindingText("backup", "proxmox backup", "veeam", "nas")
	case strings.Contains(hint, "pbx") || strings.Contains(hint, "sip") || strings.Contains(hint, "voip") || strings.Contains(hint, "voice"):
		return containsAnyToken(nameText, "pbx", "sip", "voip", "asterisk", "freepbx", "grandstream", "yealink", "polycom") ||
			hasFindingPort(5060, 5061) || hasFindingText("sip", "pbx", "voip")
	default:
		return strings.Contains(nameText, hint) || hasFindingText(hint)
	}
}

func isTransitProbeApproved(
	snap *unifi.Snapshot,
	rawFindings []checks.Finding,
	paths []config.ApprovedPath,
	srcZone, srcNet string,
	dstNet unifi.Network,
	dstIP, proto string,
	port int,
	fam string,
) bool {
	canonDstIP := canonicalIsolationIP(dstIP)
	var dstClient unifi.Client
	hasDstClient := false
	if canonDstIP != "" && snap != nil {
		for _, cl := range snap.Clients {
			for _, ip := range cl.AllIPs() {
				if canonicalIsolationIP(ip) == canonDstIP {
					dstClient = cl
					hasDstClient = true
					break
				}
			}
			if hasDstClient {
				break
			}
		}
	}

	for _, ap := range paths {
		if ap.SourceZone != "" && !strings.EqualFold(ap.SourceZone, srcZone) && !strings.EqualFold(ap.SourceZone, srcNet) {
			continue
		}
		if ap.DestZone != "" && !strings.EqualFold(ap.DestZone, dstNet.ZoneName) && !strings.EqualFold(ap.DestZone, dstNet.Name) {
			continue
		}
		if ap.DestIP != "" {
			if canonDstIP == "" || canonicalIsolationIP(ap.DestIP) != canonDstIP {
				continue
			}
		}
		if ap.Port <= 0 {
			// A port-less approval cannot suppress arbitrary ports in transit evaluation.
			continue
		}
		if ap.Port != port {
			continue
		}
		if ap.Transport != "" && !matchesProtocol(ap.Transport, proto) {
			continue
		}
		if ap.IPVersion != "" && !matchesIPFamily(ap.IPVersion, fam) {
			continue
		}
		// When an approval scopes by destination role (e.g., dest_role: "ups"),
		// never suppress a zone-wide ALLOW rule or a host that does not actually
		// hold the approved role.
		if strings.TrimSpace(ap.DestRole) != "" {
			if !hasDstClient || !clientMatchesApprovedRole(dstClient, rawFindings, ap.DestRole, ap.Function) {
				continue
			}
		}
		return true
	}
	return false
}

// allGatewayIPs collects the gateway's primary IP plus every VLAN gateway
// interface IP parsed from snap.Networks[*].Subnet (e.g., 192.168.10.1 from
// 192.168.10.1/24) so gateway-admin rules targeting a specific VLAN gateway IP
// are accurately matched.
func allGatewayIPs(snap *unifi.Snapshot, gwIP string) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(ip string) {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			return
		}
		if addr, err := netip.ParseAddr(ip); err == nil {
			ip = addr.Unmap().String()
		} else {
			return
		}
		if _, dup := seen[ip]; dup {
			return
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
	}
	add(gwIP)
	for _, n := range snap.Networks {
		if hostStr, _, ok := strings.Cut(strings.TrimSpace(n.Subnet), "/"); ok {
			add(hostStr)
		}
	}
	if len(out) == 0 {
		return []string{""}
	}
	return out
}

// collectBoundaryPorts returns representative ports for [start, end] that are
// guaranteed to hit at least one uncovered port if any port in [start, end] is
// not blocked by earlier denyPorts / denyRanges.
func collectBoundaryPorts(start, end int, denyPorts []int, denyRanges []unifi.PortRange) []int {
	if start < 1 {
		start = 1
	}
	if end < start {
		end = start
	}
	if end > 65535 {
		end = 65535
	}
	seen := make(map[int]struct{})
	var out []int
	add := func(p int) {
		if p < start || p > end {
			return
		}
		if _, dup := seen[p]; dup {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	add(start)
	add(end)
	for _, dp := range denyPorts {
		add(dp - 1)
		add(dp + 1)
	}
	for _, dr := range denyRanges {
		rs, re := dr.Start, dr.End
		if re < rs {
			re = rs
		}
		add(rs - 1)
		add(re + 1)
	}
	return out
}

// evaluateTransitBoundary evaluates an untrusted-to-trusted network pair across
// TCP 443, UDP 53, AND every concrete (protocol, port, target IP) referenced by
// enabled ALLOW policies (or L3 switch ACLs when switch-routed) between the pair,
// using exact deny-boundary port sampling so partially-blocked ranges and L3
// switch exceptions are never misreported as "blocked-ok".
func evaluateTransitBoundary(
	snap *unifi.Snapshot,
	rawFindings []checks.Finding,
	sortedPolicies []unifi.FirewallPolicy,
	intent config.IsolationIntent,
	gwPoliciesAvailable bool,
	gwMissingReason, switchACLStatus, switchACLReason, gwName string,
	srcNet, dstNet unifi.Network,
	srcZone, dstZone, fam string,
) IsolationCell {
	type probeTarget struct {
		proto string
		port  int
		dstIP string
	}
	seen := make(map[probeTarget]struct{})
	var probes []probeTarget
	var addProbe func(proto string, port int, dstIP string)
	addProbe = func(proto string, port int, dstIP string) {
		proto = strings.ToLower(strings.TrimSpace(proto))
		if proto == "" || proto == "all" || proto == "any" || proto == "tcp_udp" || proto == "tcp/udp" {
			addProbe("tcp", port, dstIP)
			addProbe("udp", port, dstIP)
			return
		}
		pt := probeTarget{proto: proto, port: port, dstIP: strings.TrimSpace(dstIP)}
		if _, dup := seen[pt]; dup {
			return
		}
		seen[pt] = struct{}{}
		probes = append(probes, pt)
	}

	// Default baseline probes across TCP and UDP.
	addProbe("tcp", 443, "")
	addProbe("udp", 53, "")

	// Also probe every protocol/port/target explicitly opened by enabled ALLOW
	// rules on the actual enforcer (L3 switch ACLs when switch-routed, otherwise
	// gateway firewall policies) targeting srcNet/srcZone -> dstNet/dstZone.
	dstIPSample := ""
	if hostStr, _, ok := strings.Cut(strings.TrimSpace(dstNet.Subnet), "/"); ok {
		if _, err := netip.ParseAddr(hostStr); err == nil && fam == "ipv4" {
			dstIPSample = hostStr
		}
	}
	sampleTargetIPs := func(ep unifi.PolicyEndpoint) []string {
		if len(ep.IPs) == 0 {
			return []string{""}
		}
		var ips []string
		for _, cand := range ep.IPs {
			if sample := sampleIPFromSelector(cand, fam); sample != "" {
				ips = append(ips, sample)
			}
		}
		if len(ips) == 0 && dstIPSample != "" {
			return []string{dstIPSample}
		}
		if len(ips) == 0 {
			return []string{""}
		}
		return ips
	}
	addEndpointProbes := func(pr string, ep unifi.PolicyEndpoint, tip string, denyPorts []int, denyRanges []unifi.PortRange) {
		if ep.AnyPort || (!ep.HasPortConstraint() && len(ep.Ports) == 0 && len(ep.PortRanges) == 0) {
			addProbe(pr, 443, tip)
			for _, cand := range collectBoundaryPorts(1, 65535, denyPorts, denyRanges) {
				if cand != 1 && cand != 65535 {
					addProbe(pr, cand, tip)
				}
			}
			return
		}
		if ep.NegatePort {
			for _, cand := range collectBoundaryPorts(1, 65535, append(denyPorts, ep.Ports...), append(denyRanges, ep.PortRanges...)) {
				addProbe(pr, cand, tip)
			}
			return
		}
		for _, p := range ep.Ports {
			addProbe(pr, p, tip)
		}
		for _, r := range ep.PortRanges {
			for _, p := range collectBoundaryPorts(r.Start, r.End, denyPorts, denyRanges) {
				addProbe(pr, p, tip)
			}
		}
	}

	l3SwitchMAC := firstNonEmptyStr(srcNet.RouterDeviceMAC, dstNet.RouterDeviceMAC)
	if l3SwitchMAC != "" {
		sortedACLs := make([]unifi.SwitchACL, len(snap.SwitchACLs))
		copy(sortedACLs, snap.SwitchACLs)
		sort.SliceStable(sortedACLs, func(i, j int) bool {
			if sortedACLs[i].Index != sortedACLs[j].Index {
				return sortedACLs[i].Index < sortedACLs[j].Index
			}
			return i < j
		})
		swLower := strings.ToLower(strings.TrimSpace(l3SwitchMAC))
		var priorDenyPorts []int
		var priorDenyRanges []unifi.PortRange
		for _, acl := range sortedACLs {
			if !acl.Enabled || !matchesIPFamily(acl.IPVersion, fam) {
				continue
			}
			if len(acl.DeviceMACs) > 0 && !containsFold(acl.DeviceMACs, swLower) {
				continue
			}
			if len(acl.NetworkIDs) > 0 {
				netHit := (srcNet.ID != "" && containsFold(acl.NetworkIDs, srcNet.ID)) ||
					(srcNet.Name != "" && containsFold(acl.NetworkIDs, srcNet.Name)) ||
					(dstNet.ID != "" && containsFold(acl.NetworkIDs, dstNet.ID)) ||
					(dstNet.Name != "" && containsFold(acl.NetworkIDs, dstNet.Name))
				if !netHit {
					continue
				}
			}
			if acl.Source.ZoneName != "" && !strings.EqualFold(acl.Source.ZoneName, srcZone) {
				continue
			}
			if acl.Destination.ZoneName != "" && !strings.EqualFold(acl.Destination.ZoneName, dstZone) {
				continue
			}
			if !strings.EqualFold(acl.Action, "ALLOW") {
				if !acl.Destination.AnyPort && !acl.Destination.NegatePort {
					priorDenyPorts = append(priorDenyPorts, acl.Destination.Ports...)
					priorDenyRanges = append(priorDenyRanges, acl.Destination.PortRanges...)
				}
				continue
			}
			targetIPs := sampleTargetIPs(acl.Destination)
			for _, tip := range targetIPs {
				addEndpointProbes(acl.Protocol, acl.Destination, tip, priorDenyPorts, priorDenyRanges)
			}
		}
	} else {
		var priorDenyPorts []int
		var priorDenyRanges []unifi.PortRange
		for _, pol := range sortedPolicies {
			if !pol.Enabled || !matchesIPFamily(pol.IPVersion, fam) {
				continue
			}
			if pol.Source.ZoneName != "" && !strings.EqualFold(pol.Source.ZoneName, srcZone) {
				continue
			}
			if pol.Destination.ZoneName != "" && !strings.EqualFold(pol.Destination.ZoneName, dstZone) {
				continue
			}
			if !strings.EqualFold(pol.Action, "ALLOW") {
				if !pol.Destination.AnyPort && !pol.Destination.NegatePort {
					priorDenyPorts = append(priorDenyPorts, pol.Destination.Ports...)
					priorDenyRanges = append(priorDenyRanges, pol.Destination.PortRanges...)
				}
				continue
			}
			targetIPs := sampleTargetIPs(pol.Destination)
			protos := []string{pol.Protocol}
			if pol.ProtocolNegated {
				protos = []string{"tcp", "udp"}
			}
			for _, pr := range protos {
				for _, tip := range targetIPs {
					addEndpointProbes(pr, pol.Destination, tip, priorDenyPorts, priorDenyRanges)
				}
			}
		}
	}

	var firstCell IsolationCell
	var unknownCell *IsolationCell
	for i, pt := range probes {
		if i > 0 && isTransitProbeApproved(snap, rawFindings, intent.ApprovedPaths, srcZone, srcNet.Name, dstNet, pt.dstIP, pt.proto, pt.port, fam) {
			continue
		}
		cell := evaluateRoutedPath(
			snap, sortedPolicies, gwPoliciesAvailable, gwMissingReason,
			switchACLStatus, switchACLReason, gwName, srcNet, dstNet,
			pathQuery{
				srcZone:    srcZone,
				srcNetID:   srcNet.ID,
				srcNetName: srcNet.Name,
				dstZone:    dstZone,
				dstNetID:   dstNet.ID,
				dstNetName: dstNet.Name,
				dstIP:      pt.dstIP,
				proto:      pt.proto,
				port:       pt.port,
				ipFamily:   fam,
				state:      "new",
			}, dstNet.Name, "trusted-lan-transit", "deny",
		)
		if i == 0 {
			firstCell = cell
		}
		if cell.Verdict == IsolationViolation {
			return cell
		}
		if cell.Verdict == IsolationUnknown && unknownCell == nil {
			cp := cell
			unknownCell = &cp
		}
	}
	if unknownCell != nil {
		return *unknownCell
	}
	return firstCell
}

// evaluateGatewayAdminBoundary evaluates Untrusted -> Gateway management access
// across TCP 443, 22, 80, 8443 and all gateway interface IPs so non-443 admin
// ALLOW rules (like SSH :22) are caught rather than masked by a tcp/443 deny.
func evaluateGatewayAdminBoundary(
	snap *unifi.Snapshot,
	sortedPolicies []unifi.FirewallPolicy,
	gwPoliciesAvailable bool,
	gwMissingReason, switchACLStatus, switchACLReason, gwName string,
	gwIPs []string,
	srcNet unifi.Network,
	srcZone string,
) IsolationCell {
	adminPorts := []int{443, 22, 80, 8443}
	var firstCell IsolationCell
	var unknownCell *IsolationCell
	first := true
	for _, gip := range gwIPs {
		for _, port := range adminPorts {
			cell := evaluateRoutedPath(
				snap, sortedPolicies, gwPoliciesAvailable, gwMissingReason,
				switchACLStatus, switchACLReason, gwName, srcNet, unifi.Network{Name: "Gateway", ZoneName: "Gateway"},
				pathQuery{
					srcZone:    srcZone,
					srcNetID:   srcNet.ID,
					srcNetName: srcNet.Name,
					dstZone:    "Gateway",
					dstNetName: "Gateway",
					dstIP:      gip,
					proto:      "tcp",
					port:       port,
					ipFamily:   "ipv4",
					state:      "new",
				}, gwName, "gateway-admin", "deny",
			)
			if first {
				firstCell = cell
				first = false
			}
			if cell.Verdict == IsolationViolation {
				return cell
			}
			if cell.Verdict == IsolationUnknown && unknownCell == nil {
				cp := cell
				unknownCell = &cp
			}
		}
	}
	if unknownCell != nil {
		return *unknownCell
	}
	return firstCell
}

func sampleIPFromSelector(selector, fam string) string {
	s := strings.TrimSpace(selector)
	wantV6 := strings.EqualFold(fam, "ipv6")
	if addr, err := netip.ParseAddr(s); err == nil {
		addr = addr.Unmap()
		if addr.Is6() == wantV6 {
			return addr.String()
		}
		return ""
	}
	if pfx, err := netip.ParsePrefix(s); err == nil {
		addr := pfx.Addr().Unmap()
		if addr.Is6() == wantV6 {
			return addr.String()
		}
		return ""
	}
	if startStr, _, ok := strings.Cut(s, "-"); ok {
		if addr, err := netip.ParseAddr(strings.TrimSpace(startStr)); err == nil {
			addr = addr.Unmap()
			if addr.Is6() == wantV6 {
				return addr.String()
			}
		}
	}
	return ""
}

func isManagementNetwork(n unifi.Network, intent config.IsolationIntent) bool {
	if containsFold(intent.ManagementVLANs, n.Name) || containsFold(intent.ManagementVLANs, n.VLAN) {
		return true
	}
	return oobVLANPattern.MatchString(n.Name) || oobVLANPattern.MatchString(n.ZoneName)
}

func isGuestNetwork(n unifi.Network, intent config.IsolationIntent) bool {
	if containsFold(intent.GuestVLANs, n.Name) || containsFold(intent.GuestVLANs, n.VLAN) {
		return true
	}
	return strings.EqualFold(n.Purpose, "guest") || strings.EqualFold(n.ZoneName, "hotspot") ||
		strings.Contains(strings.ToLower(n.Name), "guest")
}

func isCameraNetwork(n unifi.Network, intent config.IsolationIntent) bool {
	if containsFold(intent.CameraVLANs, n.Name) || containsFold(intent.CameraVLANs, n.VLAN) {
		return true
	}
	low := strings.ToLower(n.Name)
	return strings.Contains(low, "camera") || strings.Contains(low, "cam") || strings.Contains(low, "nvr")
}

func identifyBMCClients(snap *unifi.Snapshot, rawFindings []checks.Finding, mgmtNets []unifi.Network) []unifi.Client {
	clientByKey := make(map[string]unifi.Client, len(snap.Clients))
	for _, cl := range snap.Clients {
		if m := strings.ToLower(strings.TrimSpace(cl.MAC)); m != "" {
			clientByKey[m] = cl
		}
		if cl.IP != "" {
			clientByKey[cl.IP] = cl
		}
	}
	bmcByKey := make(map[string]unifi.Client)
	for _, f := range rawFindings {
		if f.Category == "oob-bmc" || f.CheckID == "UB-0020" || f.CheckID == "UB-0019" {
			cl := f.Client
			// Prefer the richer snapshot Client record (which carries IPv6 addresses).
			if full, ok := clientByKey[strings.ToLower(strings.TrimSpace(cl.MAC))]; ok {
				cl = full
			} else if full, ok := clientByKey[cl.IP]; ok {
				cl = full
			}
			k := firstNonEmptyStr(strings.ToLower(cl.MAC), cl.IP)
			if k != "" {
				bmcByKey[k] = cl
			}
		}
	}
	for _, cl := range snap.Clients {
		if bmcIdentityPattern.MatchString(cl.Name) || bmcIdentityPattern.MatchString(cl.Hostname) {
			k := firstNonEmptyStr(strings.ToLower(cl.MAC), cl.IP)
			if k != "" {
				bmcByKey[k] = cl
			}
		}
	}
	out := make([]unifi.Client, 0, len(bmcByKey))
	for _, cl := range bmcByKey {
		out = append(out, cl)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

func identifyPrinterClients(snap *unifi.Snapshot, rawFindings []checks.Finding, intent config.IsolationIntent) []unifi.Client {
	clientByKey := make(map[string]unifi.Client, len(snap.Clients))
	for _, cl := range snap.Clients {
		if m := strings.ToLower(strings.TrimSpace(cl.MAC)); m != "" {
			clientByKey[m] = cl
		}
		if cl.IP != "" {
			clientByKey[cl.IP] = cl
		}
	}
	prnByKey := make(map[string]unifi.Client)
	for _, f := range rawFindings {
		if f.Port == 631 || strings.Contains(strings.ToLower(f.Title), "ipp") || strings.Contains(strings.ToLower(f.Title), "printer") {
			cl := f.Client
			if full, ok := clientByKey[strings.ToLower(strings.TrimSpace(cl.MAC))]; ok {
				cl = full
			} else if full, ok := clientByKey[cl.IP]; ok {
				cl = full
			}
			k := firstNonEmptyStr(strings.ToLower(cl.MAC), cl.IP)
			if k != "" {
				prnByKey[k] = cl
			}
		}
	}
	for _, ap := range intent.ApprovedPaths {
		if strings.Contains(strings.ToLower(ap.Function), "print") || strings.Contains(strings.ToLower(ap.DestRole), "printer") || ap.Port == 631 {
			for _, cl := range snap.Clients {
				if (ap.DestIP != "" && cl.IP == ap.DestIP) || strings.Contains(strings.ToLower(cl.Name+cl.Hostname), "print") {
					k := firstNonEmptyStr(strings.ToLower(cl.MAC), cl.IP)
					if k != "" {
						prnByKey[k] = cl
					}
				}
			}
		}
	}
	out := make([]unifi.Client, 0, len(prnByKey))
	for _, cl := range prnByKey {
		out = append(out, cl)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

func deviceNameByMAC(snap *unifi.Snapshot, mac string) string {
	for _, d := range snap.Devices {
		if strings.EqualFold(d.MAC, mac) {
			return firstNonEmptyStr(d.Name, d.Model, d.MAC)
		}
	}
	return mac
}

func containsFold(list []string, target string) bool {
	for _, item := range list {
		if strings.EqualFold(strings.TrimSpace(item), strings.TrimSpace(target)) {
			return true
		}
	}
	return false
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}
