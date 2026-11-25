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
	Cells          []IsolationCell      `json:"cells,omitempty"`
	Containment    []NetworkContainment `json:"containment,omitempty"`
	ApprovedCount  int                  `json:"approved_count"`
	BlockedOKCount int                  `json:"blocked_ok_count"`
	ViolationCount int                  `json:"violation_count"`
	UnknownCount   int                  `json:"unknown_count"`
	BrokenDepCount int                  `json:"broken_dep_count"`
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
	intendedIsoZones := intendedIsolatedZoneSet(snap)
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
		if isNetworkInSet(n.Name, isolatedSet) || isGuestNetwork(n, intent) || isCameraNetwork(n, intent) ||
			(intendedIsoZones[z] && !isNetworkInSet(n.Name, trustedSet)) {
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
		dedicatedWorkflow := strings.Contains(fnLow, "bmc") || strings.Contains(fnLow, "print") || strings.Contains(fnLow, "ipp")
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
		missingRole := len(targets) == 0 && ap.DestIP == "" && strings.TrimSpace(ap.DestRole) != ""
		if dedicatedWorkflow && !missingRole {
			continue
		}
		if len(targets) == 0 && ap.DestZone != "" {
			for _, n := range snap.Networks {
				if strings.EqualFold(n.ZoneName, ap.DestZone) || strings.EqualFold(n.Name, ap.DestZone) {
					targets = append(targets, approvedTarget{net: n})
					if !missingRole {
						break
					}
				}
			}
		}
		if missingRole && len(targets) == 0 {
			targets = append(targets, approvedTarget{})
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
					if missingRole {
						addCell(IsolationCell{
							SourceZone: srcZone, SourceNetwork: srcNet.Name,
							DestZone: dstZone, DestNetwork: dstNet.Name, DestFunction: funcLabel,
							Transport: proto, Port: ap.Port, IPFamily: fam, Expected: "allow",
							Effective: "unknown", Verdict: IsolationUnknown,
							MissingInput:   fmt.Sprintf("No inventory device matched destination role %q.", ap.DestRole),
							RecommendedFix: "Identify the destination device or supply its address to verify this workflow.",
						})
						continue
					}
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

		// 3b. Untrusted -> Gateway Administration (always enforced by the Gateway Zone Firewall, never an L3 switch)
		// across IPv4 and, whenever IPv6 context exists on the source network or gateway policies, IPv6.
		for _, fam := range []string{"ipv4", "ipv6"} {
			if fam == "ipv6" && !gatewayHasIPv6Context(snap, srcNet, sortedPolicies) {
				continue
			}
			gwIPsFam := allGatewayIPsForFamily(snap, gwIP, fam, srcNet, sortedPolicies)
			gwAdminCell := evaluateGatewayAdminBoundary(
				snap, sortedPolicies, gwPoliciesAvailable, gwMissingReason,
				switchACLStatus, switchACLReason, gwName, gwIPsFam, srcNet, srcZone, fam,
			)
			if gwAdminCell.Verdict == IsolationViolation {
				gwAdminCell.RecommendedFix = fmt.Sprintf(
					"Block %s -> Gateway %s administration (TCP 443/22) in rule %q while keeping Gateway DHCP and DNS allowed.",
					srcNet.Name, strings.ToUpper(fam), gwAdminCell.DecisiveRuleName,
				)
				findings = append(findings, checks.Finding{
					CheckID:           "UB-UNIFI-ISO-GW-ADMIN",
					Title:             fmt.Sprintf("Untrusted Network Permitted %s Gateway Administration (%s -> %s)", strings.ToUpper(fam), srcNet.Name, gwName),
					Category:          "isolation-policy",
					ClaimKind:         checks.ClaimConfiguredAccess,
					Property:          fmt.Sprintf("isolation-gw-admin-%s-%s", strings.ToLower(srcNet.Name), fam),
					Transport:         gwAdminCell.Transport,
					BaseSeverity:      checks.SeverityHigh,
					EffectiveSeverity: checks.SeverityHigh,
					Client:            unifi.Client{MAC: "gw:" + srcNet.ID, IP: firstNonEmptyStr(gwAdminCell.DestIP, gwIP), Name: gwName, NetworkName: srcNet.Name + " -> Gateway"},
					Port:              gwAdminCell.Port,
					Evidence:          fmt.Sprintf("source=%s (%s) -> gateway=%s (function=gateway-admin, family=%s, proto=%s/%d, decisive_rule=%q)", srcNet.Name, srcZone, gwName, fam, gwAdminCell.Transport, gwAdminCell.Port, gwAdminCell.DecisiveRuleName),
					Remediation: checks.Remediation{
						Summary:      gwAdminCell.RecommendedFix,
						UniFiActions: []string{"block_untrusted_gateway_admin"},
					},
				})
			}
			addCell(gwAdminCell)
		}

		// 3c. Essential Gateway Dependencies (DNS UDP 53 & DHCP UDP 67) when gateway policies are available:
		// flag only if an explicit rule breaks them (broken-dependency). Check both the source
		// VLAN's own gateway interface IP (from srcNet.Subnet) and the primary gateway IP so
		// DNS/DHCP ALLOW rules scoped to the VLAN's local gateway IP are recognized as approved.
		if gwPoliciesAvailable {
			var depDstIPs []string
			if vlanGW := subnetGatewayIP(srcNet.Subnet); vlanGW != "" {
				depDstIPs = append(depDstIPs, vlanGW)
			}
			if gwIP != "" && (len(depDstIPs) == 0 || depDstIPs[0] != gwIP) {
				depDstIPs = append(depDstIPs, gwIP)
			}
			if len(depDstIPs) == 0 {
				depDstIPs = []string{""}
			}
			deps := []endpointSpec{
				{proto: "udp", port: 67, function: "gateway-dhcp"},
			}
			// Offline networks (Allow Internet Access disabled) may intentionally
			// block DNS to prevent DNS tunneling; only treat Gateway DNS as a
			// required dependency when internet access is not disabled.
			if srcNet.InternetAccessEnabled == nil || *srcNet.InternetAccessEnabled {
				deps = append([]endpointSpec{{proto: "udp", port: 53, function: "gateway-dns"}}, deps...)
			}
			for _, dep := range deps {
				srcPort := 0
				if dep.function == "gateway-dhcp" {
					// DHCPv4 clients originate requests from UDP port 68 to server port 67.
					srcPort = 68
				}
				var depCell IsolationCell
				for idxIP, candidateIP := range depDstIPs {
					cand := evaluateRoutedPath(
						snap, sortedPolicies, gwPoliciesAvailable, gwMissingReason,
						switchACLStatus, switchACLReason, gwName, srcNet, unifi.Network{Name: "Gateway", ZoneName: "Gateway"},
						pathQuery{
							srcZone:    srcZone,
							srcNetID:   srcNet.ID,
							srcNetName: srcNet.Name,
							srcPort:    srcPort,
							dstZone:    "Gateway",
							dstNetName: "Gateway",
							dstIP:      candidateIP,
							proto:      dep.proto,
							port:       dep.port,
							ipFamily:   "ipv4",
							state:      "new",
						}, gwName, dep.function, "allow",
					)
					if idxIP == 0 {
						depCell = cand
					}
					if cand.Verdict == IsolationApproved {
						depCell = cand
						break
					}
					if depCell.DecisiveRuleID == "" && cand.DecisiveRuleID != "" {
						depCell = cand
					}
				}
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

	// 5. Evaluate 4-axis Network Containment (Peers, LAN Egress, Internet Egress,
	// LAN Inbound) and smart Guest/IoT/Camera archetypes for every isolated VLAN.
	containment, contCells, contFindings, contNotes := evaluateNetworkContainment(
		snap, sortedPolicies, intent, gwPoliciesAvailable, gwMissingReason,
		switchACLStatus, switchACLReason, gwName, gwIP,
		untrustedNets, trustedNets, matrix.Cells,
	)
	matrix.Containment = containment
	for _, c := range contCells {
		addCell(c)
	}
	findings = append(findings, contFindings...)
	notes = append(notes, contNotes...)

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
				revSrc, _ := matchesEndpoint(pol.Source, q.dstZone, q.dstNetID, q.dstNetName, q.dstIP, q.dstMAC, 0, q.ipFamily)
				revDst, _ := matchesEndpoint(pol.Destination, q.srcZone, q.srcNetID, q.srcNetName, q.srcIP, q.srcMAC, q.srcPort, q.ipFamily)
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

		srcMatch, srcReason := matchesEndpoint(pol.Source, q.srcZone, q.srcNetID, q.srcNetName, q.srcIP, q.srcMAC, q.srcPort, q.ipFamily)
		if srcMatch == matchNo {
			continue
		}
		dstMatch, dstReason := matchesEndpoint(pol.Destination, q.dstZone, q.dstNetID, q.dstNetName, q.dstIP, q.dstMAC, q.port, q.ipFamily)
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
				reason:   fmt.Sprintf("matched ALLOW rule %q (index=%d, family=%s, proto=%s)", pol.Name, pol.Index, firstNonEmptyStr(pol.IPVersion, "both"), formatPolicyProtocol(pol.Protocol, pol.ProtocolNegated)),
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
		sm, sr := matchesEndpoint(acl.Source, q.srcZone, q.srcNetID, q.srcNetName, q.srcIP, q.srcMAC, q.srcPort, q.ipFamily)
		dm, dr := matchesEndpoint(acl.Destination, q.dstZone, q.dstNetID, q.dstNetName, q.dstIP, q.dstMAC, q.port, q.ipFamily)
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

func matchesEndpoint(ep unifi.PolicyEndpoint, zone, netID, netName, ip, mac string, port int, ipFamily string) (triMatch, string) {
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
				// If every IP selector in the rule belongs strictly to the
				// opposite IP family (e.g., an IPv4-only selector evaluated
				// against an IPv6 query), no address of ipFamily can match.
				if ipFamily != "" && allSelectorsOppositeFamily(ep.IPs, ipFamily) {
					// targetState stays matchNo (and NegateTarget below will invert if set).
				} else {
					targetState = matchUnknown
				}
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
	if rp == "ipv6-icmp" {
		rp = "icmpv6"
	}
	if qp == "ipv6-icmp" {
		qp = "icmpv6"
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

// splitIdentityTokens tokenizes a hostname, display name, OUI, or finding label
// into lowercase alphanumeric word tokens (plus alphabetic stems when followed
// by digits, such as "ups01" -> "ups"), preventing substring false positives
// like "cups-printserver" matching "ups".
func splitIdentityTokens(text string) map[string]struct{} {
	out := make(map[string]struct{})
	words := strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
	})
	for _, w := range words {
		if w == "" {
			continue
		}
		out[w] = struct{}{}
		trimmed := strings.TrimRight(w, "0123456789")
		if len(trimmed) >= 2 && trimmed != w {
			out[trimmed] = struct{}{}
		}
	}
	return out
}

// pluralRoleToken handles regular plurals and role acronyms such as NASes.
func pluralRoleToken(word string) string {
	for _, ending := range []string{"s", "x", "z", "ch", "sh"} {
		if strings.HasSuffix(word, ending) {
			return word + "es"
		}
	}
	return word + "s"
}

func hasAnyWordToken(tokSet map[string]struct{}, want ...string) bool {
	for _, w := range want {
		w = strings.ToLower(strings.TrimSpace(w))
		if w == "" {
			continue
		}
		if _, ok := tokSet[w]; ok {
			return true
		}
		if len(w) >= 3 {
			if _, ok := tokSet[pluralRoleToken(w)]; ok {
				return true
			}
		}
	}
	return false
}

func clientMatchesApprovedRole(cl unifi.Client, rawFindings []checks.Finding, roleHint, fnHint string) bool {
	hint := strings.ToLower(strings.TrimSpace(firstNonEmptyStr(roleHint, fnHint)))
	if hint == "" {
		return false
	}
	hintTokens := splitIdentityTokens(hint)
	nameTokens := splitIdentityTokens(cl.Name + " " + cl.Hostname + " " + cl.OUI)
	ouiLow := strings.ToLower(strings.TrimSpace(cl.OUI))

	findingTokens := make(map[string]struct{})
	findingPorts := make(map[int]struct{})
	findingCheckIDs := make(map[string]struct{})
	for _, f := range rawFindings {
		if !sameClient(f.Client, cl) {
			continue
		}
		if f.Port > 0 {
			findingPorts[f.Port] = struct{}{}
		}
		if f.CheckID != "" {
			findingCheckIDs[strings.ToLower(strings.TrimSpace(f.CheckID))] = struct{}{}
		}
		for tok := range splitIdentityTokens(f.Title + " " + f.Category + " " + f.CheckID + " " + f.Property) {
			findingTokens[tok] = struct{}{}
		}
	}
	hasFindingPort := func(ports ...int) bool {
		for _, p := range ports {
			if _, ok := findingPorts[p]; ok {
				return true
			}
		}
		return false
	}
	hasFindingToken := func(tokens ...string) bool {
		return hasAnyWordToken(findingTokens, tokens...)
	}
	hasCheckID := func(ids ...string) bool {
		for _, id := range ids {
			if _, ok := findingCheckIDs[strings.ToLower(id)]; ok {
				return true
			}
		}
		return false
	}

	isObservedPrinter := hasFindingPort(631, 9100) || hasFindingToken("ipp", "ipps", "printer", "cups") ||
		hasAnyWordToken(nameTokens, "printer", "printserver", "cups", "laserjet")
	isObservedUPS := hasFindingPort(3493) || hasFindingToken("ups", "nut", "pdu", "upsd") ||
		strings.Contains(ouiLow, "american power conversion") || strings.Contains(ouiLow, "cyberpower") ||
		strings.Contains(ouiLow, "eaton") || strings.Contains(ouiLow, "tripp lite")

	switch {
	case hasAnyWordToken(hintTokens, "print", "printer", "printers", "printing", "ipp", "ipps", "cups"):
		return hasFindingPort(631, 9100) || hasFindingToken("ipp", "ipps", "printer", "cups") ||
			hasAnyWordToken(nameTokens, "print", "printer", "printers", "printserver", "cups", "laserjet", "brother", "epson", "canon")
	case hasAnyWordToken(hintTokens, "bmc", "bmcs", "ipmi", "idrac", "ilo", "redfish"):
		return hasCheckID("ub-0019", "ub-0020", "ub-2026-0001", "ub-2026-0002") ||
			hasFindingToken("oob", "bmc", "ipmi", "redfish", "idrac", "ilo") ||
			bmcIdentityPattern.MatchString(cl.Name) || bmcIdentityPattern.MatchString(cl.Hostname)
	case hasAnyWordToken(hintTokens, "ups", "upses", "nut", "pdu", "pdus", "power"):
		if isObservedUPS {
			return true
		}
		// Never classify an observed printer/CUPS server as a UPS based on name hints.
		if isObservedPrinter {
			return false
		}
		return hasAnyWordToken(nameTokens, "ups", "nut", "apc", "eaton", "cyberpower", "pdu")
	case hasAnyWordToken(hintTokens, "nvr", "nvrs", "recorder", "recorders", "camera", "cameras", "cam", "cams"):
		return hasFindingPort(554) || hasFindingToken("camera", "nvr", "rtsp", "onvif") ||
			hasAnyWordToken(nameTokens, "nvr", "recorder", "camera", "cameras", "cam", "cams", "protect", "frigate", "reolink", "hikvision", "dahua", "axis")
	case hasAnyWordToken(hintTokens, "backup", "backups", "nas", "storage"):
		return hasFindingPort(8007) || hasFindingToken("backup", "pbs", "veeam", "nas", "synology", "truenas") ||
			hasAnyWordToken(nameTokens, "backup", "backups", "pbs", "veeam", "urbackup", "nas", "truenas", "synology", "qnap")
	case hasAnyWordToken(hintTokens, "pbx", "pbxs", "sip", "voip", "voice"):
		return hasFindingPort(5060, 5061) || hasFindingToken("sip", "pbx", "voip") ||
			hasAnyWordToken(nameTokens, "pbx", "sip", "voip", "asterisk", "freepbx", "grandstream", "yealink", "polycom")
	default:
		matches := func(tok string) bool {
			return hasAnyWordToken(nameTokens, tok) || hasFindingToken(tok)
		}
		for tok := range hintTokens {
			if matches(tok) {
				continue
			}
			found := false
			for _, suffix := range []string{"es", "s"} {
				if stem, ok := strings.CutSuffix(tok, suffix); ok && len(stem) >= 3 && pluralRoleToken(stem) == tok && matches(stem) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return len(hintTokens) > 0
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
		// When an approval scopes by destination role or function without a fixed
		// DestIP (e.g., dest_role: "ups" or function: "ipps-printing"), never
		// suppress a zone-wide ALLOW rule or a host that does not actually hold
		// the approved role or function.
		if strings.TrimSpace(ap.DestRole) != "" || (strings.TrimSpace(ap.DestIP) == "" && strings.TrimSpace(ap.Function) != "") {
			if !hasDstClient || !clientMatchesApprovedRole(dstClient, rawFindings, ap.DestRole, ap.Function) {
				continue
			}
		}
		return true
	}
	return false
}

// gatewayHasIPv6Context reports whether Untrusted -> Gateway isolation should
// also be evaluated for IPv6 (true when srcNet has IPv6 addressing/clients or
// any enabled policy targeting Gateway explicitly references IPv6).
func gatewayHasIPv6Context(snap *unifi.Snapshot, srcNet unifi.Network, policies []unifi.FirewallPolicy) bool {
	if strings.TrimSpace(srcNet.IPv6Subnet) != "" {
		return true
	}
	if snap != nil {
		for _, cl := range snap.Clients {
			if len(cl.IPv6) == 0 {
				continue
			}
			if (srcNet.ID != "" && cl.NetworkID == srcNet.ID) ||
				(srcNet.Name != "" && strings.EqualFold(cl.NetworkName, srcNet.Name)) {
				return true
			}
		}
	}
	srcZone := strings.TrimSpace(srcNet.ZoneName)
	for _, pol := range policies {
		if !pol.Enabled {
			continue
		}
		if pol.Destination.ZoneName != "" && !strings.EqualFold(pol.Destination.ZoneName, "gateway") {
			continue
		}
		if pol.Source.ZoneName != "" && srcZone != "" && !strings.EqualFold(pol.Source.ZoneName, srcZone) {
			continue
		}
		if strings.EqualFold(pol.IPVersion, "ipv6") {
			return true
		}
		for _, sel := range pol.Destination.IPs {
			if selectorFamilyTri(sel) == "ipv6" {
				return true
			}
		}
	}
	return false
}

// allGatewayIPsForFamily collects gateway interface IPs of family fam ("ipv4"
// or "ipv6") from gwIP, snap.Networks subnets, and any explicit gateway-targeted
// ALLOW policies so both zone-wide and host-targeted gateway admin rules match.
func allGatewayIPsForFamily(snap *unifi.Snapshot, gwIP, fam string, srcNet unifi.Network, policies []unifi.FirewallPolicy) []string {
	wantV6 := strings.EqualFold(fam, "ipv6")
	seen := make(map[string]struct{})
	var out []string
	add := func(ip string) {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			return
		}
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return
		}
		addr = addr.Unmap()
		if addr.Is6() != wantV6 {
			return
		}
		s := addr.String()
		if _, dup := seen[s]; dup {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}

	// Prefer srcNet's own gateway interface IP first, then primary gwIP and other VLAN gateway IPs.
	if wantV6 {
		if s := sampleNetworkIPv6(srcNet, nil); s != "" {
			add(s)
		}
		add(gwIP)
		if snap != nil {
			for _, n := range snap.Networks {
				if s := sampleNetworkIPv6(n, nil); s != "" {
					add(s)
				}
			}
		}
	} else {
		if s := subnetGatewayIP(srcNet.Subnet); s != "" {
			add(s)
		}
		add(gwIP)
		if snap != nil {
			for _, n := range snap.Networks {
				if hostStr, _, ok := strings.Cut(strings.TrimSpace(n.Subnet), "/"); ok {
					add(hostStr)
				}
			}
		}
	}

	srcZone := strings.TrimSpace(srcNet.ZoneName)
	for _, pol := range policies {
		if !pol.Enabled || !strings.EqualFold(pol.Action, "ALLOW") || !matchesIPFamily(pol.IPVersion, fam) {
			continue
		}
		if pol.Destination.ZoneName != "" && !strings.EqualFold(pol.Destination.ZoneName, "gateway") {
			continue
		}
		if pol.Source.ZoneName != "" && srcZone != "" && !strings.EqualFold(pol.Source.ZoneName, srcZone) {
			continue
		}
		if !pol.Destination.AnyTarget && !pol.Destination.NegateTarget {
			for _, sel := range pol.Destination.IPs {
				if s := sampleIPFromSelector(sel, fam); s != "" {
					add(s)
				}
			}
		}
	}

	if len(out) == 0 {
		return []string{""}
	}
	return out
}

// networkPrefixForFamily returns the parsed IPv4 or IPv6 CIDR prefix for net.
func networkPrefixForFamily(n unifi.Network, fam string) (netip.Prefix, bool) {
	wantV6 := strings.EqualFold(fam, "ipv6")
	raw := n.Subnet
	if wantV6 {
		raw = n.IPv6Subnet
	}
	s := strings.TrimSpace(raw)
	if s == "" {
		return netip.Prefix{}, false
	}
	pfx, err := netip.ParsePrefix(s)
	if err != nil || pfx.Addr().Unmap().Is6() != wantV6 {
		return netip.Prefix{}, false
	}
	return pfx.Masked(), true
}

// ipBelongsToNetwork reports whether ip (of family fam) belongs to net. When
// net defines a subnet for fam, strict CIDR containment decides; otherwise
// client ownership and exclusion against sibling networks' subnets decide.
func ipBelongsToNetwork(ip string, net unifi.Network, snap *unifi.Snapshot, fam string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	wantV6 := strings.EqualFold(fam, "ipv6")
	if addr.Is6() != wantV6 {
		return false
	}
	if pfx, ok := networkPrefixForFamily(net, fam); ok {
		return pfx.Contains(addr)
	}
	if snap != nil {
		for _, cl := range snap.Clients {
			onNet := (net.ID != "" && cl.NetworkID == net.ID) || (net.Name != "" && strings.EqualFold(cl.NetworkName, net.Name))
			for _, cip := range cl.AllIPs() {
				if ca, cerr := netip.ParseAddr(strings.TrimSpace(cip)); cerr == nil && ca.Unmap() == addr {
					return onNet
				}
			}
		}
		for _, other := range snap.Networks {
			if (net.ID != "" && other.ID == net.ID) || (net.Name != "" && strings.EqualFold(other.Name, net.Name)) {
				continue
			}
			if opfx, ok := networkPrefixForFamily(other, fam); ok && opfx.Contains(addr) {
				return false
			}
		}
	}
	return true
}

// approvedHostIPsFor returns the concrete destination host IPs on dstNet that
// are explicitly approved for (srcZone, srcNet, dstNet, proto, port, fam) via
// DestIP or DestRole, plus whether an unrestricted zone-level approval covers
// all hosts in dstNet for that endpoint.
func approvedHostIPsFor(
	snap *unifi.Snapshot,
	rawFindings []checks.Finding,
	paths []config.ApprovedPath,
	srcZone, srcNet string,
	dstNet unifi.Network,
	proto string,
	port int,
	fam string,
) ([]string, bool) {
	seen := make(map[string]struct{})
	var ips []string
	addIP := func(raw string) {
		c := canonicalIsolationIP(raw)
		if c == "" {
			return
		}
		if selectorFamilyTri(c) != strings.ToLower(strings.TrimSpace(fam)) {
			return
		}
		if _, dup := seen[c]; dup {
			return
		}
		seen[c] = struct{}{}
		ips = append(ips, c)
	}
	wholeNet := false
	for _, ap := range paths {
		if ap.SourceZone != "" && !strings.EqualFold(ap.SourceZone, srcZone) && !strings.EqualFold(ap.SourceZone, srcNet) {
			continue
		}
		if ap.DestZone != "" && !strings.EqualFold(ap.DestZone, dstNet.ZoneName) && !strings.EqualFold(ap.DestZone, dstNet.Name) {
			continue
		}
		if ap.Port <= 0 || ap.Port != port {
			continue
		}
		if ap.Transport != "" && !matchesProtocol(ap.Transport, proto) {
			continue
		}
		if ap.IPVersion != "" && !matchesIPFamily(ap.IPVersion, fam) {
			continue
		}
		if strings.TrimSpace(ap.DestIP) != "" {
			addIP(ap.DestIP)
			continue
		}
		if strings.TrimSpace(ap.DestRole) != "" || strings.TrimSpace(ap.Function) != "" {
			if snap != nil {
				for _, cl := range snap.Clients {
					if !clientMatchesApprovedRole(cl, rawFindings, ap.DestRole, ap.Function) {
						continue
					}
					if addr := clientAddressForFamily(cl, fam); addr != "" && ipBelongsToNetwork(addr, dstNet, snap, fam) {
						addIP(addr)
					}
				}
			}
			continue
		}
		wholeNet = true
	}
	return ips, wholeNet
}

// endpointMatchesNetworkSelector reports whether ep's NetworkIDs filter can
// match net (respecting AnyTarget and NegateTarget).
func endpointMatchesNetworkSelector(ep unifi.PolicyEndpoint, net unifi.Network) bool {
	if ep.AnyTarget || len(ep.NetworkIDs) == 0 {
		return true
	}
	hit := (net.ID != "" && containsFold(ep.NetworkIDs, net.ID)) ||
		(net.Name != "" && containsFold(ep.NetworkIDs, net.Name))
	if ep.NegateTarget {
		return !hit
	}
	return hit
}

// isSingleHostSelector reports whether sel parses strictly as a single IPv4
// (/32) or IPv6 (/128) host address, returning its canonical address string.
func isSingleHostSelector(sel string) (string, bool) {
	s := strings.TrimSpace(sel)
	if s == "" {
		return "", false
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Unmap().String(), true
	}
	if pfx, err := netip.ParsePrefix(s); err == nil {
		addr := pfx.Addr().Unmap()
		if (addr.Is4() && pfx.Bits() == 32) || (addr.Is6() && pfx.Bits() == 128) {
			return addr.String(), true
		}
		return "", false
	}
	if startStr, endStr, ok := strings.Cut(s, "-"); ok {
		a1, e1 := netip.ParseAddr(strings.TrimSpace(startStr))
		a2, e2 := netip.ParseAddr(strings.TrimSpace(endStr))
		if e1 == nil && e2 == nil && a1.Unmap() == a2.Unmap() {
			return a1.Unmap().String(), true
		}
	}
	return "", false
}

// narrowPinholePathsForZone extracts synthetic ApprovedPaths strictly for
// single-host (/32 or /128) narrow-port ALLOW pinholes (such as DNS 53 or
// NTP 123) on srcZone -> Internal. Wider CIDRs (like /25), multi-host ranges,
// AnyPort, negated selectors, or broad port ranges are never tolerated.
func narrowPinholePathsForZone(sorted []unifi.FirewallPolicy, srcZone string) []config.ApprovedPath {
	var out []config.ApprovedPath
	for _, pol := range sorted {
		if !pol.Enabled || !strings.EqualFold(pol.Action, "ALLOW") {
			continue
		}
		if !strings.EqualFold(pol.Source.ZoneName, srcZone) || !strings.EqualFold(pol.Destination.ZoneName, "internal") {
			continue
		}
		if pol.ProtocolNegated || pol.Destination.AnyTarget || pol.Destination.NegateTarget ||
			pol.Destination.AnyPort || pol.Destination.NegatePort || pol.Destination.CoversAllPorts() ||
			!pol.Destination.HasPortConstraint() || len(pol.Destination.NetworkIDs) > 0 || len(pol.Destination.MACs) > 0 ||
			len(pol.Destination.IPs) == 0 || len(pol.Destination.IPs) > 4 {
			continue
		}
		var hostIPs []string
		allSingle := true
		for _, sel := range pol.Destination.IPs {
			ip, ok := isSingleHostSelector(sel)
			if !ok {
				allSingle = false
				break
			}
			hostIPs = append(hostIPs, ip)
		}
		if !allSingle {
			continue
		}
		var ports []int
		narrowPorts := true
		for _, p := range pol.Destination.Ports {
			if p > 0 && p <= 65535 {
				ports = append(ports, p)
			}
		}
		for _, r := range pol.Destination.PortRanges {
			if r.Start > 0 && r.Start == r.End && r.Start <= 65535 {
				ports = append(ports, r.Start)
			} else {
				narrowPorts = false
				break
			}
		}
		if !narrowPorts || len(ports) == 0 || len(ports) > 4 {
			continue
		}
		proto := strings.ToLower(strings.TrimSpace(pol.Protocol))
		if proto == "all" || proto == "any" {
			proto = ""
		}
		for _, ip := range hostIPs {
			for _, p := range ports {
				out = append(out, config.ApprovedPath{
					SourceZone: srcZone,
					DestZone:   "Internal",
					DestIP:     ip,
					Transport:  proto,
					Port:       p,
					IPVersion:  pol.IPVersion,
				})
			}
		}
	}
	return out
}

const (
	// maxExactBoundaryEvals bounds exact equivalence-class evaluations per
	// boundary pair. If an allow rule's uncovered space exceeds this cap without
	// hitting a concrete violation, UniBlue returns IsolationUnknown rather than
	// issuing a potentially false IsolationBlockedOK.
	maxExactBoundaryEvals = 16384

	// syntheticOtherMAC represents an arbitrary host MAC on a network not
	// explicitly listed in any MAC-based policy selector.
	syntheticOtherMAC = "02:ff:ff:ff:ff:fe"
)

type ipInterval struct {
	lo netip.Addr
	hi netip.Addr
}

type portInterval struct {
	lo int
	hi int
}

// parseSelectorInterval parses a single IP, CIDR prefix, or "start-end" IP
// range of family fam ("ipv4" or "ipv6") into a closed netip.Addr interval.
func parseSelectorInterval(sel, fam string) (ipInterval, bool) {
	wantV6 := strings.EqualFold(fam, "ipv6")
	s := strings.TrimSpace(sel)
	if s == "" {
		return ipInterval{}, false
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		addr = addr.Unmap()
		if addr.Is6() != wantV6 {
			return ipInterval{}, false
		}
		return ipInterval{lo: addr, hi: addr}, true
	}
	if pfx, err := netip.ParsePrefix(s); err == nil {
		if pfx.Addr().Unmap().Is6() != wantV6 {
			return ipInterval{}, false
		}
		m := pfx.Masked()
		return ipInterval{lo: m.Addr().Unmap(), hi: lastAddrOfPrefix(m)}, true
	}
	if startStr, endStr, ok := strings.Cut(s, "-"); ok {
		a1, e1 := netip.ParseAddr(strings.TrimSpace(startStr))
		a2, e2 := netip.ParseAddr(strings.TrimSpace(endStr))
		if e1 != nil || e2 != nil {
			return ipInterval{}, false
		}
		a1, a2 = a1.Unmap(), a2.Unmap()
		if a1.Is6() != wantV6 || a2.Is6() != wantV6 {
			return ipInterval{}, false
		}
		if a1.Compare(a2) > 0 {
			a1, a2 = a2, a1
		}
		return ipInterval{lo: a1, hi: a2}, true
	}
	return ipInterval{}, false
}

// partitionIPIntervals splits net's address space for fam into disjoint atomic
// intervals where every IP selector in selectors and every address in
// extraPoints has a constant membership truth value. When net has a CIDR
// prefix for fam, the entire prefix is partitioned; when net has no prefix,
// real client IPs on net (plus any positive selector intervals belonging to
// net) form the domain so negated exclusions never fabricate out-of-network
// addresses like 0.0.0.0.
func partitionIPIntervals(
	net unifi.Network,
	snap *unifi.Snapshot,
	fam string,
	positiveSelectors []string,
	negatedSelectors []string,
	extraPoints []netip.Addr,
) []ipInterval {
	wantV6 := strings.EqualFold(fam, "ipv6")
	netPfx, hasNetPfx := networkPrefixForFamily(net, fam)

	if hasNetPfx {
		domLo := netPfx.Addr().Unmap()
		domHi := lastAddrOfPrefix(netPfx)
		starts := []netip.Addr{domLo}
		addInterval := func(lo, hi netip.Addr) {
			if !lo.IsValid() || !hi.IsValid() {
				return
			}
			lo, hi = lo.Unmap(), hi.Unmap()
			if lo.Is6() != wantV6 || hi.Is6() != wantV6 {
				return
			}
			if lo.Compare(hi) > 0 {
				lo, hi = hi, lo
			}
			if hi.Compare(domLo) < 0 || lo.Compare(domHi) > 0 {
				return
			}
			if lo.Compare(domLo) < 0 {
				lo = domLo
			}
			if hi.Compare(domHi) > 0 {
				hi = domHi
			}
			starts = append(starts, lo)
			if hi.Compare(domHi) < 0 {
				if nxt := hi.Next(); nxt.IsValid() {
					starts = append(starts, nxt)
				}
			}
		}

		for _, sel := range positiveSelectors {
			if iv, ok := parseSelectorInterval(sel, fam); ok {
				addInterval(iv.lo, iv.hi)
			}
		}
		for _, sel := range negatedSelectors {
			if iv, ok := parseSelectorInterval(sel, fam); ok {
				addInterval(iv.lo, iv.hi)
			}
		}
		for _, pt := range extraPoints {
			addInterval(pt, pt)
		}

		sort.Slice(starts, func(i, j int) bool {
			return starts[i].Compare(starts[j]) < 0
		})
		uniq := starts[:0]
		for _, s := range starts {
			if len(uniq) == 0 || uniq[len(uniq)-1] != s {
				uniq = append(uniq, s)
			}
		}

		preferred, _ := netip.ParseAddr(strings.TrimSpace(sampleNetworkIPForFamily(net, snap, fam)))
		preferred = preferred.Unmap()

		out := make([]ipInterval, 0, len(uniq))
		for i, lo := range uniq {
			hi := domHi
			if i+1 < len(uniq) {
				hi = uniq[i+1].Prev()
			}
			if !hi.IsValid() || lo.Compare(hi) > 0 {
				continue
			}
			iv := ipInterval{lo: lo, hi: hi}
			rep := representativeIPInInterval(iv, netPfx, true, preferred)
			if rep != "" && ipBelongsToNetwork(rep, net, snap, fam) {
				out = append(out, iv)
			}
		}
		return out
	}

	// Subnet-less network: build domain from real clients on net, positive
	// selectors belonging to net, and approved host points (falling back to
	// sampleIPOutsideSelectors only when no clients exist on net).
	var domains []ipInterval
	hasClient := false
	if snap != nil && (net.ID != "" || net.Name != "") {
		for _, cl := range snap.Clients {
			if (net.ID == "" || cl.NetworkID != net.ID) &&
				(net.Name == "" || !strings.EqualFold(cl.NetworkName, net.Name)) {
				continue
			}
			for _, raw := range cl.AllIPs() {
				if a, err := netip.ParseAddr(strings.TrimSpace(raw)); err == nil {
					a = a.Unmap()
					if a.Is6() == wantV6 {
						hasClient = true
						domains = append(domains, ipInterval{lo: a, hi: a})
					}
				}
			}
		}
	}
	for _, sel := range positiveSelectors {
		if iv, ok := parseSelectorInterval(sel, fam); ok {
			if ipBelongsToNetwork(iv.lo.String(), net, snap, fam) || ipBelongsToNetwork(iv.hi.String(), net, snap, fam) {
				domains = append(domains, iv)
			}
		}
	}
	for _, pt := range extraPoints {
		if pt.IsValid() && pt.Unmap().Is6() == wantV6 && ipBelongsToNetwork(pt.Unmap().String(), net, snap, fam) {
			u := pt.Unmap()
			domains = append(domains, ipInterval{lo: u, hi: u})
		}
	}
	if !hasClient {
		if s := sampleNetworkIPForFamily(net, snap, fam); s != "" {
			if a, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil && a.Unmap().Is6() == wantV6 {
				u := a.Unmap()
				domains = append(domains, ipInterval{lo: u, hi: u})
			}
		}
		allExcl := make([]string, 0, len(positiveSelectors)+len(negatedSelectors))
		allExcl = append(allExcl, positiveSelectors...)
		allExcl = append(allExcl, negatedSelectors...)
		if outIP := sampleIPOutsideSelectors(net, snap, fam, allExcl); outIP != "" {
			if a, err := netip.ParseAddr(strings.TrimSpace(outIP)); err == nil && a.Unmap().Is6() == wantV6 {
				u := a.Unmap()
				domains = append(domains, ipInterval{lo: u, hi: u})
			}
		}
	}
	if len(domains) == 0 {
		return nil
	}

	// Merge overlapping domain intervals, then split each merged span by all
	// positive/negated selectors and extraPoints.
	sort.Slice(domains, func(i, j int) bool {
		if c := domains[i].lo.Compare(domains[j].lo); c != 0 {
			return c < 0
		}
		return domains[i].hi.Compare(domains[j].hi) < 0
	})
	mergedDom := domains[:1]
	for _, cur := range domains[1:] {
		last := &mergedDom[len(mergedDom)-1]
		if cur.lo.Compare(last.hi) <= 0 || (last.hi.Next().IsValid() && cur.lo == last.hi.Next()) {
			if cur.hi.Compare(last.hi) > 0 {
				last.hi = cur.hi
			}
		} else {
			mergedDom = append(mergedDom, cur)
		}
	}

	var splitters []ipInterval
	for _, sel := range positiveSelectors {
		if iv, ok := parseSelectorInterval(sel, fam); ok {
			splitters = append(splitters, iv)
		}
	}
	for _, sel := range negatedSelectors {
		if iv, ok := parseSelectorInterval(sel, fam); ok {
			splitters = append(splitters, iv)
		}
	}
	for _, pt := range extraPoints {
		if pt.IsValid() && pt.Unmap().Is6() == wantV6 {
			u := pt.Unmap()
			splitters = append(splitters, ipInterval{lo: u, hi: u})
		}
	}

	preferred, _ := netip.ParseAddr(strings.TrimSpace(sampleNetworkIPForFamily(net, snap, fam)))
	preferred = preferred.Unmap()

	var out []ipInterval
	for _, span := range mergedDom {
		starts := []netip.Addr{span.lo}
		for _, sp := range splitters {
			if sp.hi.Compare(span.lo) < 0 || sp.lo.Compare(span.hi) > 0 {
				continue
			}
			lo, hi := sp.lo, sp.hi
			if lo.Compare(span.lo) < 0 {
				lo = span.lo
			}
			if hi.Compare(span.hi) > 0 {
				hi = span.hi
			}
			starts = append(starts, lo)
			if hi.Compare(span.hi) < 0 {
				if nxt := hi.Next(); nxt.IsValid() {
					starts = append(starts, nxt)
				}
			}
		}
		sort.Slice(starts, func(i, j int) bool {
			return starts[i].Compare(starts[j]) < 0
		})
		uniq := starts[:0]
		for _, s := range starts {
			if len(uniq) == 0 || uniq[len(uniq)-1] != s {
				uniq = append(uniq, s)
			}
		}
		for i, lo := range uniq {
			hi := span.hi
			if i+1 < len(uniq) {
				hi = uniq[i+1].Prev()
			}
			if !hi.IsValid() || lo.Compare(hi) > 0 {
				continue
			}
			iv := ipInterval{lo: lo, hi: hi}
			rep := representativeIPInInterval(iv, netip.Prefix{}, false, preferred)
			if rep != "" && ipBelongsToNetwork(rep, net, snap, fam) {
				out = append(out, iv)
			}
		}
	}
	return out
}

func representativeIPInInterval(iv ipInterval, netPfx netip.Prefix, hasNetPfx bool, preferred netip.Addr) string {
	if iv.lo == iv.hi {
		return iv.lo.String()
	}
	if preferred.IsValid() && preferred.Compare(iv.lo) >= 0 && preferred.Compare(iv.hi) <= 0 {
		return preferred.String()
	}
	if hasNetPfx && iv.lo == netPfx.Addr().Unmap() {
		if nxt := iv.lo.Next(); nxt.IsValid() && nxt.Compare(iv.hi) <= 0 {
			return nxt.String()
		}
	}
	return iv.lo.String()
}

// partitionPortIntervals splits [1, 65535] into disjoint atomic intervals where
// every port in ports and every range in ranges has a constant membership truth
// value.
func partitionPortIntervals(ports []int, ranges []unifi.PortRange) []portInterval {
	bounds := make([]int, 0, 2+2*len(ports)+2*len(ranges))
	bounds = append(bounds, 1, 65536)
	for _, p := range ports {
		if p < 1 || p > 65535 {
			continue
		}
		bounds = append(bounds, p, p+1)
	}
	for _, r := range ranges {
		s, e := r.Start, r.End
		if e < s {
			e = s
		}
		if s < 1 {
			s = 1
		}
		if e > 65535 {
			e = 65535
		}
		if s > e {
			continue
		}
		bounds = append(bounds, s, e+1)
	}
	sort.Ints(bounds)
	uniq := bounds[:0]
	for _, b := range bounds {
		if len(uniq) == 0 || uniq[len(uniq)-1] != b {
			uniq = append(uniq, b)
		}
	}
	out := make([]portInterval, 0, len(uniq))
	for i := 0; i+1 < len(uniq); i++ {
		lo, hi := uniq[i], uniq[i+1]-1
		if lo <= hi && lo >= 1 && hi <= 65535 {
			out = append(out, portInterval{lo: lo, hi: hi})
		}
	}
	return out
}

func representativePortInInterval(iv portInterval) int {
	for _, pref := range []int{443, 80, 22, 53} {
		if pref >= iv.lo && pref <= iv.hi {
			return pref
		}
	}
	return iv.lo
}

// endpointCanMatchTarget reports whether ep's zone/network/IP/MAC selectors can
// match (or return matchUnknown for) the given concrete (ip, mac) candidate.
func endpointCanMatchTarget(ep unifi.PolicyEndpoint, zone, netID, netName, ip, mac, fam string) bool {
	epNoPort := ep
	epNoPort.AnyPort = true
	m, _ := matchesEndpoint(epNoPort, zone, netID, netName, ip, mac, 0, fam)
	return m != matchNo
}

// endpointCanMatchPort reports whether ep's port selector can match (or return
// matchUnknown for) port.
func endpointCanMatchPort(ep unifi.PolicyEndpoint, port int) bool {
	if ep.AnyPort || port == 0 {
		return true
	}
	if !ep.HasPortConstraint() {
		return true
	}
	hit := ep.MatchesPort(port)
	if ep.NegatePort {
		return !hit
	}
	return hit
}

// collectApprovedPointsFor returns every destination IP (on dstNet of family
// fam) and every destination port referenced by matching ApprovedPaths for
// (srcZone, srcNet, dstNet, proto, fam).
func collectApprovedPointsFor(
	snap *unifi.Snapshot,
	rawFindings []checks.Finding,
	paths []config.ApprovedPath,
	srcZone, srcNet string,
	dstNet unifi.Network,
	proto, fam string,
) ([]netip.Addr, []int) {
	wantV6 := strings.EqualFold(fam, "ipv6")
	seenIP := make(map[netip.Addr]struct{})
	seenPort := make(map[int]struct{})
	var ips []netip.Addr
	var ports []int

	addIP := func(raw string) {
		a, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil {
			return
		}
		a = a.Unmap()
		if a.Is6() != wantV6 {
			return
		}
		if _, dup := seenIP[a]; dup {
			return
		}
		seenIP[a] = struct{}{}
		ips = append(ips, a)
	}
	addPort := func(p int) {
		if p < 1 || p > 65535 {
			return
		}
		if _, dup := seenPort[p]; dup {
			return
		}
		seenPort[p] = struct{}{}
		ports = append(ports, p)
	}

	for _, ap := range paths {
		if ap.SourceZone != "" && !strings.EqualFold(ap.SourceZone, srcZone) && !strings.EqualFold(ap.SourceZone, srcNet) {
			continue
		}
		if ap.DestZone != "" && !strings.EqualFold(ap.DestZone, dstNet.ZoneName) && !strings.EqualFold(ap.DestZone, dstNet.Name) {
			continue
		}
		if ap.Port <= 0 {
			continue
		}
		if ap.Transport != "" && !matchesProtocol(ap.Transport, proto) {
			continue
		}
		if ap.IPVersion != "" && !matchesIPFamily(ap.IPVersion, fam) {
			continue
		}
		addPort(ap.Port)
		if strings.TrimSpace(ap.DestIP) != "" {
			addIP(ap.DestIP)
			continue
		}
		if (strings.TrimSpace(ap.DestRole) != "" || strings.TrimSpace(ap.Function) != "") && snap != nil {
			for _, cl := range snap.Clients {
				if !clientMatchesApprovedRole(cl, rawFindings, ap.DestRole, ap.Function) {
					continue
				}
				for _, raw := range cl.AllIPs() {
					if ipBelongsToNetwork(raw, dstNet, snap, fam) {
						addIP(raw)
					}
				}
			}
		}
	}
	return ips, ports
}

// mergePortIntervals normalizes and merges overlapping or adjacent port
// intervals inside [1, 65535] into sorted disjoint intervals.
func mergePortIntervals(in []portInterval) []portInterval {
	if len(in) == 0 {
		return nil
	}
	norm := make([]portInterval, 0, len(in))
	for _, iv := range in {
		lo, hi := iv.lo, iv.hi
		if hi < lo {
			hi = lo
		}
		if lo < 1 {
			lo = 1
		}
		if hi > 65535 {
			hi = 65535
		}
		if lo <= hi {
			norm = append(norm, portInterval{lo: lo, hi: hi})
		}
	}
	if len(norm) == 0 {
		return nil
	}
	sort.Slice(norm, func(i, j int) bool {
		if norm[i].lo != norm[j].lo {
			return norm[i].lo < norm[j].lo
		}
		return norm[i].hi < norm[j].hi
	})
	merged := norm[:1]
	for _, cur := range norm[1:] {
		last := &merged[len(merged)-1]
		if cur.lo <= last.hi+1 {
			if cur.hi > last.hi {
				last.hi = cur.hi
			}
		} else {
			merged = append(merged, cur)
		}
	}
	return merged
}

// portBlockedByMerged reports whether p falls inside any interval of sorted
// disjoint merged intervals.
func portBlockedByMerged(merged []portInterval, p int) bool {
	if len(merged) == 0 || p < 1 || p > 65535 {
		return false
	}
	idx := sort.Search(len(merged), func(i int) bool {
		return merged[i].hi >= p
	})
	return idx < len(merged) && merged[idx].lo <= p
}

// endpointPortIntervals returns the exact merged port intervals matched by ep
// (returning ok=false when ep has an unresolved port selector).
func endpointPortIntervals(ep unifi.PolicyEndpoint) ([]portInterval, bool) {
	if ep.AnyPort {
		return []portInterval{{lo: 1, hi: 65535}}, true
	}
	if !ep.HasPortConstraint() {
		return nil, false
	}
	raw := make([]portInterval, 0, len(ep.Ports)+len(ep.PortRanges))
	for _, p := range ep.Ports {
		if p >= 1 && p <= 65535 {
			raw = append(raw, portInterval{lo: p, hi: p})
		}
	}
	for _, r := range ep.PortRanges {
		lo, hi := r.Start, r.End
		if hi < lo {
			hi = lo
		}
		raw = append(raw, portInterval{lo: lo, hi: hi})
	}
	pos := mergePortIntervals(raw)
	if !ep.NegatePort {
		return pos, true
	}
	// Complement of pos inside [1, 65535].
	var comp []portInterval
	cur := 1
	for _, iv := range pos {
		if cur < iv.lo {
			comp = append(comp, portInterval{lo: cur, hi: iv.lo - 1})
		}
		cur = iv.hi + 1
	}
	if cur <= 65535 {
		comp = append(comp, portInterval{lo: cur, hi: 65535})
	}
	return comp, true
}

// endpointUnconditionallyMatchesNetwork reports whether ep matches EVERY host
// on net (regardless of IP or MAC) without any unresolved/unsupported selector.
func endpointUnconditionallyMatchesNetwork(ep unifi.PolicyEndpoint, zone string, net unifi.Network, requireAnyPort bool) bool {
	if (ep.ZoneID != "" && ep.ZoneName == "") || ep.UnsupportedSelector != "" {
		return false
	}
	if ep.ZoneName != "" && !strings.EqualFold(ep.ZoneName, zone) {
		return false
	}
	if requireAnyPort && !ep.AnyPort {
		return false
	}
	if ep.AnyTarget {
		return true
	}
	if ep.NegateTarget || len(ep.IPs) > 0 || len(ep.MACs) > 0 || len(ep.NetworkIDs) == 0 {
		return false
	}
	return (net.ID != "" && containsFold(ep.NetworkIDs, net.ID)) ||
		(net.Name != "" && containsFold(ep.NetworkIDs, net.Name))
}

type boundaryRule struct {
	allow              bool
	src                unifi.PolicyEndpoint
	dst                unifi.PolicyEndpoint
	priorUncondBlocked []portInterval
}

// evaluateTransitBoundary verifies an untrusted-to-trusted network pair across
// TCP, UDP, and any other allow-referenced protocols using exact equivalence
// partitioning over source IPs, destination IPs, MACs, and port ranges across
// every relevant rule and approved exception. It returns IsolationBlockedOK
// only when every class covered by an allow rule is proven blocked or approved,
// returning IsolationUnknown if exact coverage cannot be completed.
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
	srcIPSample := sampleNetworkIPForFamily(srcNet, snap, fam)
	dstIPSample := sampleNetworkIPForFamily(dstNet, snap, fam)

	baseDstIP := func(proto string, port int) string {
		if approvedIPs, _ := approvedHostIPsFor(snap, rawFindings, intent.ApprovedPaths, srcZone, srcNet.Name, dstNet, proto, port, fam); len(approvedIPs) > 0 {
			if outside := sampleIPOutsideSelectors(dstNet, snap, fam, approvedIPs); outside != "" {
				return outside
			}
		}
		return dstIPSample
	}

	type evalKey struct {
		proto  string
		port   int
		srcIP  string
		srcMAC string
		dstIP  string
		dstMAC string
	}
	evaluated := make(map[evalKey]struct{})
	var firstCell IsolationCell
	hasFirst := false
	var unknownCell *IsolationCell

	evalOne := func(proto string, port int, srcIP, srcMAC, dstIP, dstMAC string, allowSkipApproved bool) (IsolationCell, bool) {
		k := evalKey{
			proto:  proto,
			port:   port,
			srcIP:  strings.TrimSpace(srcIP),
			srcMAC: strings.ToLower(strings.TrimSpace(srcMAC)),
			dstIP:  strings.TrimSpace(dstIP),
			dstMAC: strings.ToLower(strings.TrimSpace(dstMAC)),
		}
		if _, dup := evaluated[k]; dup {
			return IsolationCell{}, false
		}
		evaluated[k] = struct{}{}

		if allowSkipApproved && isTransitProbeApproved(snap, rawFindings, intent.ApprovedPaths, srcZone, srcNet.Name, dstNet, k.dstIP, k.proto, k.port, fam) {
			return IsolationCell{}, false
		}
		cell := evaluateRoutedPath(
			snap, sortedPolicies, gwPoliciesAvailable, gwMissingReason,
			switchACLStatus, switchACLReason, gwName, srcNet, dstNet,
			pathQuery{
				srcZone:    srcZone,
				srcNetID:   srcNet.ID,
				srcNetName: srcNet.Name,
				srcIP:      k.srcIP,
				srcMAC:     k.srcMAC,
				dstZone:    dstZone,
				dstNetID:   dstNet.ID,
				dstNetName: dstNet.Name,
				dstIP:      k.dstIP,
				dstMAC:     k.dstMAC,
				proto:      k.proto,
				port:       k.port,
				ipFamily:   fam,
				state:      "new",
			}, dstNet.Name, "trusted-lan-transit", "deny",
		)
		if cell.Verdict == IsolationViolation {
			if isTransitProbeApproved(snap, rawFindings, intent.ApprovedPaths, srcZone, srcNet.Name, dstNet, k.dstIP, k.proto, k.port, fam) {
				return IsolationCell{}, false
			}
			return cell, true
		}
		if !hasFirst {
			firstCell = cell
			hasFirst = true
		}
		if cell.Verdict == IsolationUnknown && unknownCell == nil {
			cp := cell
			unknownCell = &cp
		}
		return IsolationCell{}, false
	}

	// Run baseline TCP 443 and UDP 53 probes first so missing telemetry,
	// unresolved zones, or wide allow rules fail fast and firstCell captures the
	// decisive baseline block rule.
	if viol, ok := evalOne("tcp", 443, srcIPSample, "", baseDstIP("tcp", 443), "", false); ok {
		return viol
	}
	if !gwPoliciesAvailable && firstNonEmptyStr(srcNet.RouterDeviceMAC, dstNet.RouterDeviceMAC) == "" {
		return firstCell
	}
	if viol, ok := evalOne("udp", 53, srcIPSample, "", baseDstIP("udp", 53), "", true); ok {
		return viol
	}

	l3SwitchMAC := firstNonEmptyStr(srcNet.RouterDeviceMAC, dstNet.RouterDeviceMAC)
	if l3SwitchMAC != "" && switchACLStatus != "complete" {
		return firstCell
	}
	if l3SwitchMAC == "" && (strings.TrimSpace(srcZone) == "" || strings.TrimSpace(dstZone) == "") {
		return firstCell
	}

	// Partition on every named selector, including blocks. All remaining IP
	// protocols match the same selectors (wildcards and complements).
	protos := []string{"tcp", "udp"}
	seenProto := map[string]struct{}{"tcp": {}, "udp": {}}
	addProto := func(raw string) {
		p := strings.ToLower(strings.TrimSpace(raw))
		if p == "ipv6-icmp" {
			p = "icmpv6"
		}
		if p == "" || p == "all" || p == "any" || p == "tcp_udp" || p == "tcp/udp" {
			return
		}
		if _, dup := seenProto[p]; dup {
			return
		}
		seenProto[p] = struct{}{}
		protos = append(protos, p)
	}

	var sortedACLs []unifi.SwitchACL
	if l3SwitchMAC != "" {
		sortedACLs = make([]unifi.SwitchACL, len(snap.SwitchACLs))
		copy(sortedACLs, snap.SwitchACLs)
		sort.SliceStable(sortedACLs, func(i, j int) bool {
			if sortedACLs[i].Index != sortedACLs[j].Index {
				return sortedACLs[i].Index < sortedACLs[j].Index
			}
			return i < j
		})
		for _, acl := range sortedACLs {
			if acl.Enabled && matchesIPFamily(acl.IPVersion, fam) {
				addProto(acl.Protocol)
			}
		}
	} else {
		for _, pol := range sortedPolicies {
			if pol.Enabled && matchesIPFamily(pol.IPVersion, fam) {
				addProto(pol.Protocol)
			}
		}
	}

	icmp := "icmp"
	if fam == "ipv6" {
		icmp = "icmpv6"
	}
	// Prefer a concrete witness for the remaining class. If all these names
	// already occur, a permitted residual class can only establish uncertainty.
	const unnamedProtocol = "<unlisted IP protocol>"
	representative := unnamedProtocol
	for _, name := range []string{icmp, "gre", "esp", "ah", "sctp"} {
		if _, named := seenProto[name]; !named {
			representative = name
			break
		}
	}
	protos = append(protos, representative)

	srcNetPfx, hasSrcNetPfx := networkPrefixForFamily(srcNet, fam)
	dstNetPfx, hasDstNetPfx := networkPrefixForFamily(dstNet, fam)
	prefSrc, _ := netip.ParseAddr(strings.TrimSpace(srcIPSample))
	prefSrc = prefSrc.Unmap()
	prefDst, _ := netip.ParseAddr(strings.TrimSpace(dstIPSample))
	prefDst = prefDst.Unmap()

	defaultAllows := l3SwitchMAC != "" ||
		strings.EqualFold(strings.TrimSpace(srcZone), strings.TrimSpace(dstZone)) ||
		strings.EqualFold(strings.TrimSpace(srcZone), "internal")

	incompleteCoverage := false
	totalRuleEvals := 0

	for _, pr := range protos {
		var allowRules []boundaryRule
		var srcPosSelectors, srcNegSelectors []string
		var dstPosSelectors, dstNegSelectors []string
		var dstPorts []int
		var dstPortRanges []unifi.PortRange
		var uncondBlockedRaw []portInterval
		var uncondBlockedMerged []portInterval
		sawIndeterminateRule := false
		srcMACSet := make(map[string]struct{})
		dstMACSet := make(map[string]struct{})
		hasSrcMAC := false
		hasDstMAC := false

		isFullPortBlock := func(merged []portInterval) bool {
			return len(merged) == 1 && merged[0].lo == 1 && merged[0].hi == 65535
		}

		recordRuleEndpoints := func(allow bool, srcEP, dstEP unifi.PolicyEndpoint, indeterminate bool) {
			if indeterminate {
				sawIndeterminateRule = true
			}
			if !endpointMatchesNetworkSelector(srcEP, srcNet) || !endpointMatchesNetworkSelector(dstEP, dstNet) {
				return
			}
			if !allow {
				// Record unconditional whole-network BLOCK port intervals so
				// later shadowed ALLOW rules skip already-blocked port ranges
				// without quadratic scanning, unless an earlier rule was
				// indeterminate (scheduled/unsupported) and must stay observable.
				if !sawIndeterminateRule && (pr == "tcp" || pr == "udp" || dstEP.AnyPort) &&
					endpointUnconditionallyMatchesNetwork(srcEP, srcZone, srcNet, true) &&
					endpointUnconditionallyMatchesNetwork(dstEP, dstZone, dstNet, false) {
					if ivs, ok := endpointPortIntervals(dstEP); ok {
						uncondBlockedRaw = append(uncondBlockedRaw, ivs...)
						uncondBlockedMerged = mergePortIntervals(uncondBlockedRaw)
						return
					}
					sawIndeterminateRule = true
				}
			} else {
				// Skip an ALLOW rule completely shadowed on every port by
				// earlier unconditional whole-network BLOCK rules.
				if !sawIndeterminateRule && isFullPortBlock(uncondBlockedMerged) {
					return
				}
				var priorCopy []portInterval
				if !sawIndeterminateRule && len(uncondBlockedMerged) > 0 {
					priorCopy = append([]portInterval(nil), uncondBlockedMerged...)
				}
				allowRules = append(allowRules, boundaryRule{
					allow:              true,
					src:                srcEP,
					dst:                dstEP,
					priorUncondBlocked: priorCopy,
				})
			}
			if !srcEP.AnyTarget {
				if srcEP.NegateTarget {
					srcNegSelectors = append(srcNegSelectors, srcEP.IPs...)
				} else {
					srcPosSelectors = append(srcPosSelectors, srcEP.IPs...)
				}
				for _, m := range srcEP.MACs {
					ml := strings.ToLower(strings.TrimSpace(m))
					if ml != "" {
						hasSrcMAC = true
						srcMACSet[ml] = struct{}{}
					}
				}
			}
			if !dstEP.AnyTarget {
				if dstEP.NegateTarget {
					dstNegSelectors = append(dstNegSelectors, dstEP.IPs...)
				} else {
					dstPosSelectors = append(dstPosSelectors, dstEP.IPs...)
				}
				for _, m := range dstEP.MACs {
					ml := strings.ToLower(strings.TrimSpace(m))
					if ml != "" {
						hasDstMAC = true
						dstMACSet[ml] = struct{}{}
					}
				}
			}
			if !dstEP.AnyPort {
				dstPorts = append(dstPorts, dstEP.Ports...)
				dstPortRanges = append(dstPortRanges, dstEP.PortRanges...)
			}
		}

		if l3SwitchMAC != "" {
			swLower := strings.ToLower(strings.TrimSpace(l3SwitchMAC))
			for _, acl := range sortedACLs {
				if !acl.Enabled || !matchesIPFamily(acl.IPVersion, fam) || !matchesProtocol(acl.Protocol, pr) {
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
				indet := acl.Source.UnsupportedSelector != "" || acl.Destination.UnsupportedSelector != ""
				recordRuleEndpoints(strings.EqualFold(acl.Action, "ALLOW"), acl.Source, acl.Destination, indet)
			}
		} else {
			for _, pol := range sortedPolicies {
				if !pol.Enabled || !matchesIPFamily(pol.IPVersion, fam) || !matchesConnState(pol.ConnectionStates, "new") {
					continue
				}
				if !matchesPolicyProtocol(pol.Protocol, pol.ProtocolNegated, pr) {
					continue
				}
				if pol.Source.ZoneName != "" && !strings.EqualFold(pol.Source.ZoneName, srcZone) {
					continue
				}
				if pol.Destination.ZoneName != "" && !strings.EqualFold(pol.Destination.ZoneName, dstZone) {
					continue
				}
				indet := pol.UnsupportedReason != "" || pol.Schedule != "" ||
					pol.Source.UnsupportedSelector != "" || pol.Destination.UnsupportedSelector != ""
				recordRuleEndpoints(strings.EqualFold(pol.Action, "ALLOW"), pol.Source, pol.Destination, indet)
			}
		}

		if defaultAllows && (sawIndeterminateRule || !isFullPortBlock(uncondBlockedMerged)) {
			anyEP := unifi.PolicyEndpoint{AnyTarget: true, AnyPort: true}
			var priorCopy []portInterval
			if !sawIndeterminateRule && len(uncondBlockedMerged) > 0 {
				priorCopy = append([]portInterval(nil), uncondBlockedMerged...)
			}
			allowRules = append(allowRules, boundaryRule{
				allow:              true,
				src:                anyEP,
				dst:                anyEP,
				priorUncondBlocked: priorCopy,
			})
		}
		if len(allowRules) == 0 {
			continue
		}

		// Include all approved destination host IPs and ports AND each allow
		// rule's prior unconditional block intervals (never post-allow blocks!)
		// so every unblocked, unapproved port interval is isolated cleanly.
		approvedIPs, approvedPorts := collectApprovedPointsFor(snap, rawFindings, intent.ApprovedPaths, srcZone, srcNet.Name, dstNet, pr, fam)
		dstPorts = append(dstPorts, approvedPorts...)
		for _, ar := range allowRules {
			for _, iv := range ar.priorUncondBlocked {
				dstPortRanges = append(dstPortRanges, unifi.PortRange{Start: iv.lo, End: iv.hi})
			}
		}

		srcIntervals := partitionIPIntervals(srcNet, snap, fam, srcPosSelectors, srcNegSelectors, nil)
		dstIntervals := partitionIPIntervals(dstNet, snap, fam, dstPosSelectors, dstNegSelectors, approvedIPs)

		var srcReps []string
		for _, iv := range srcIntervals {
			if rep := representativeIPInInterval(iv, srcNetPfx, hasSrcNetPfx, prefSrc); rep != "" {
				srcReps = append(srcReps, rep)
			}
		}
		if len(srcReps) == 0 && srcIPSample != "" {
			srcReps = []string{srcIPSample}
		}

		var dstReps []string
		for _, iv := range dstIntervals {
			if rep := representativeIPInInterval(iv, dstNetPfx, hasDstNetPfx, prefDst); rep != "" {
				dstReps = append(dstReps, rep)
			}
		}
		if len(dstReps) == 0 && dstIPSample != "" {
			dstReps = []string{dstIPSample}
		}

		endpointNeedsEmptyIPProbe := func(ep unifi.PolicyEndpoint) bool {
			if ep.AnyTarget || ep.NegateTarget || len(ep.IPs) == 0 {
				return true
			}
			for _, sel := range ep.IPs {
				if selectorFamilyTri(sel) == "" {
					return true
				}
			}
			return false
		}

		var srcMACs []string
		if hasSrcMAC {
			for m := range srcMACSet {
				srcMACs = append(srcMACs, m)
			}
			sort.Strings(srcMACs)
			srcMACs = append(srcMACs, syntheticOtherMAC)
		} else {
			srcMACs = []string{""}
		}

		var dstMACs []string
		if hasDstMAC {
			for m := range dstMACSet {
				dstMACs = append(dstMACs, m)
			}
			sort.Strings(dstMACs)
			dstMACs = append(dstMACs, syntheticOtherMAC)
		} else {
			dstMACs = []string{""}
		}

		var portReps []int
		if pr == "tcp" || pr == "udp" {
			for _, iv := range partitionPortIntervals(dstPorts, dstPortRanges) {
				portReps = append(portReps, representativePortInInterval(iv))
			}
		} else {
			portReps = []int{0}
		}

		// Evaluate every (src, dst, port) equivalence class covered by each
		// ALLOW rule (or implicit allow default).
		for _, ar := range allowRules {
			type endpointCandidate struct {
				ip  string
				mac string
			}
			var matchSrc []endpointCandidate
			effSrcReps := srcReps
			if len(effSrcReps) == 0 && endpointNeedsEmptyIPProbe(ar.src) {
				effSrcReps = []string{""}
			}
			for _, sip := range effSrcReps {
				for _, smac := range srcMACs {
					if endpointCanMatchTarget(ar.src, srcZone, srcNet.ID, srcNet.Name, sip, smac, fam) {
						matchSrc = append(matchSrc, endpointCandidate{ip: sip, mac: smac})
					}
				}
			}
			if len(matchSrc) == 0 {
				continue
			}

			var matchDst []endpointCandidate
			effDstReps := dstReps
			if len(effDstReps) == 0 && endpointNeedsEmptyIPProbe(ar.dst) {
				effDstReps = []string{""}
			}
			for _, dip := range effDstReps {
				for _, dmac := range dstMACs {
					if endpointCanMatchTarget(ar.dst, dstZone, dstNet.ID, dstNet.Name, dip, dmac, fam) {
						matchDst = append(matchDst, endpointCandidate{ip: dip, mac: dmac})
					}
				}
			}
			if len(matchDst) == 0 {
				continue
			}

			var matchPorts []int
			for _, p := range portReps {
				if portBlockedByMerged(ar.priorUncondBlocked, p) {
					continue
				}
				if endpointCanMatchPort(ar.dst, p) {
					matchPorts = append(matchPorts, p)
				}
			}
			if len(matchPorts) == 0 {
				continue
			}

			for _, sc := range matchSrc {
				for _, dc := range matchDst {
					for _, p := range matchPorts {
						totalRuleEvals++
						if totalRuleEvals > maxExactBoundaryEvals {
							incompleteCoverage = true
							goto nextProto
						}
						if viol, ok := evalOne(pr, p, sc.ip, sc.mac, dc.ip, dc.mac, true); ok {
							if pr == unnamedProtocol {
								viol.Transport = ""
								viol.Effective = "unknown"
								viol.Verdict = IsolationUnknown
								viol.MissingInput = "Cannot certify isolation for IP protocols outside the named selectors."
							}
							return viol
						}
					}
				}
			}
		}
	nextProto:
	}

	if unknownCell != nil {
		return *unknownCell
	}
	if incompleteCoverage {
		cell := firstCell
		if !hasFirst {
			cell = IsolationCell{
				SourceZone:    firstNonEmptyStr(srcZone, srcNet.Name),
				SourceNetwork: srcNet.Name,
				DestZone:      firstNonEmptyStr(dstZone, dstNet.Name),
				DestNetwork:   dstNet.Name,
				DestHost:      dstNet.Name,
				DestFunction:  "trusted-lan-transit",
				Transport:     "tcp",
				IPFamily:      fam,
				PathKind:      "gateway-routed",
				Enforcer:      gwName + " (Zone Firewall)",
				Expected:      "deny",
			}
		}
		cell.Effective = "unknown"
		cell.Verdict = IsolationUnknown
		cell.MissingInput = fmt.Sprintf(
			"Policy evaluation space for %s -> %s (%s) exceeded exact verification limit (%d classes); cannot certify blocked-ok without complete coverage.",
			srcNet.Name, dstNet.Name, strings.ToUpper(fam), maxExactBoundaryEvals,
		)
		return cell
	}
	return firstCell
}

// evaluateGatewayAdminBoundary evaluates Untrusted -> Gateway management access
// across TCP 443, 22, 80, 8443, every source IP equivalence class in srcNet,
// and all gateway interface IPs for the requested address family ("ipv4" or
// "ipv6") so narrow earlier blocks never mask neighbor sources or alternate
// gateway IPs.
func evaluateGatewayAdminBoundary(
	snap *unifi.Snapshot,
	sortedPolicies []unifi.FirewallPolicy,
	gwPoliciesAvailable bool,
	gwMissingReason, switchACLStatus, switchACLReason, gwName string,
	gwIPs []string,
	srcNet unifi.Network,
	srcZone, fam string,
) IsolationCell {
	adminPorts := []int{443, 22, 80, 8443}
	srcIPSample := sampleNetworkIPForFamily(srcNet, snap, fam)

	var srcPosSelectors, srcNegSelectors []string
	srcMACSet := make(map[string]struct{})
	hasSrcMAC := false
	for _, pol := range sortedPolicies {
		if !pol.Enabled || !matchesIPFamily(pol.IPVersion, fam) || !matchesConnState(pol.ConnectionStates, "new") {
			continue
		}
		if pol.Destination.ZoneName != "" && !strings.EqualFold(pol.Destination.ZoneName, "gateway") {
			continue
		}
		if pol.Source.ZoneName != "" && srcZone != "" && !strings.EqualFold(pol.Source.ZoneName, srcZone) {
			continue
		}
		if !endpointMatchesNetworkSelector(pol.Source, srcNet) {
			continue
		}
		if !pol.Source.AnyTarget {
			if pol.Source.NegateTarget {
				srcNegSelectors = append(srcNegSelectors, pol.Source.IPs...)
			} else {
				srcPosSelectors = append(srcPosSelectors, pol.Source.IPs...)
			}
			for _, m := range pol.Source.MACs {
				ml := strings.ToLower(strings.TrimSpace(m))
				if ml != "" {
					hasSrcMAC = true
					srcMACSet[ml] = struct{}{}
				}
			}
		}
	}

	srcNetPfx, hasSrcNetPfx := networkPrefixForFamily(srcNet, fam)
	prefSrc, _ := netip.ParseAddr(strings.TrimSpace(srcIPSample))
	prefSrc = prefSrc.Unmap()

	var srcIPs []string
	for _, iv := range partitionIPIntervals(srcNet, snap, fam, srcPosSelectors, srcNegSelectors, nil) {
		if rep := representativeIPInInterval(iv, srcNetPfx, hasSrcNetPfx, prefSrc); rep != "" {
			srcIPs = append(srcIPs, rep)
		}
	}
	if len(srcIPs) == 0 {
		srcIPs = []string{srcIPSample}
	}

	var srcMACs []string
	if hasSrcMAC {
		for m := range srcMACSet {
			srcMACs = append(srcMACs, m)
		}
		sort.Strings(srcMACs)
		srcMACs = append(srcMACs, syntheticOtherMAC)
	} else {
		srcMACs = []string{""}
	}

	var firstCell IsolationCell
	var unknownCell *IsolationCell
	first := true
	evals := 0
	incomplete := false
	for _, sip := range srcIPs {
		for _, smac := range srcMACs {
			for _, gip := range gwIPs {
				for _, port := range adminPorts {
					evals++
					if evals > maxExactBoundaryEvals {
						incomplete = true
						goto doneGW
					}
					cell := evaluateRoutedPath(
						snap, sortedPolicies, gwPoliciesAvailable, gwMissingReason,
						switchACLStatus, switchACLReason, gwName, srcNet, unifi.Network{Name: "Gateway", ZoneName: "Gateway"},
						pathQuery{
							srcZone:    srcZone,
							srcNetID:   srcNet.ID,
							srcNetName: srcNet.Name,
							srcIP:      sip,
							srcMAC:     smac,
							dstZone:    "Gateway",
							dstNetName: "Gateway",
							dstIP:      gip,
							proto:      "tcp",
							port:       port,
							ipFamily:   fam,
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
		}
	}
doneGW:
	if unknownCell != nil {
		return *unknownCell
	}
	if incomplete {
		firstCell.Effective = "unknown"
		firstCell.Verdict = IsolationUnknown
		firstCell.MissingInput = fmt.Sprintf(
			"Gateway admin evaluation space for %s (%s) exceeded exact verification limit (%d classes).",
			srcNet.Name, strings.ToUpper(fam), maxExactBoundaryEvals,
		)
		return firstCell
	}
	return firstCell
}

// subnetGatewayIP parses the gateway interface IP from a UniFi network subnet
// string such as "192.168.50.1/24".
func subnetGatewayIP(subnet string) string {
	hostStr, _, ok := strings.Cut(strings.TrimSpace(subnet), "/")
	if !ok {
		return ""
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(hostStr))
	if err != nil {
		return ""
	}
	return addr.Unmap().String()
}

// sampleNetworkIPv6 returns a representative IPv6 address on net, preferring
// net.IPv6Subnet and falling back to an active client's IPv6 address on net.
func sampleNetworkIPv6(net unifi.Network, snap *unifi.Snapshot) string {
	if s := strings.TrimSpace(net.IPv6Subnet); s != "" {
		if pfx, err := netip.ParsePrefix(s); err == nil {
			addr := pfx.Addr().Unmap()
			if addr.Is6() {
				if addr == pfx.Masked().Addr() && pfx.Bits() < 128 {
					addr = addr.Next()
				}
				return addr.String()
			}
		}
	}
	if snap != nil {
		fallback := ""
		for _, cl := range snap.Clients {
			if (net.ID == "" || cl.NetworkID != net.ID) &&
				(net.Name == "" || !strings.EqualFold(cl.NetworkName, net.Name)) {
				continue
			}
			for _, raw := range cl.IPv6 {
				if addr, err := netip.ParseAddr(strings.TrimSpace(raw)); err == nil && addr.Is6() {
					if !addr.IsLinkLocalUnicast() {
						return addr.String()
					}
					if fallback == "" {
						fallback = addr.String()
					}
				}
			}
		}
		if fallback != "" {
			return fallback
		}
	}
	return ""
}

// sampleNetworkIPForFamily returns a valid representative IP address on net
// for the requested address family ("ipv4" or "ipv6").
func sampleNetworkIPForFamily(net unifi.Network, snap *unifi.Snapshot, fam string) string {
	if strings.EqualFold(fam, "ipv6") {
		return sampleNetworkIPv6(net, snap)
	}
	if gw := subnetGatewayIP(net.Subnet); gw != "" {
		if addr, err := netip.ParseAddr(gw); err == nil && addr.Is4() {
			return addr.String()
		}
	}
	if snap != nil {
		for _, cl := range snap.Clients {
			if (net.ID == "" || cl.NetworkID != net.ID) &&
				(net.Name == "" || !strings.EqualFold(cl.NetworkName, net.Name)) {
				continue
			}
			if addr, err := netip.ParseAddr(strings.TrimSpace(cl.IP)); err == nil && addr.Is4() {
				return addr.String()
			}
		}
	}
	return ""
}

// zoneHasIPv6Context reports whether any network or client in zoneLow or
// Internal carries IPv6 addressing, or any firewall policy explicitly targets IPv6.
func zoneHasIPv6Context(snap *unifi.Snapshot, zoneLow string) bool {
	if snap == nil {
		return false
	}
	zoneNets := make(map[string]struct{})
	zoneNetIDs := make(map[string]struct{})
	for _, n := range snap.Networks {
		nz := strings.ToLower(strings.TrimSpace(n.ZoneName))
		if nz != zoneLow && nz != "internal" {
			continue
		}
		if strings.TrimSpace(n.IPv6Subnet) != "" {
			return true
		}
		if n.Name != "" {
			zoneNets[strings.ToLower(strings.TrimSpace(n.Name))] = struct{}{}
		}
		if n.ID != "" {
			zoneNetIDs[n.ID] = struct{}{}
		}
	}
	for _, cl := range snap.Clients {
		if len(cl.IPv6) == 0 {
			continue
		}
		if _, ok := zoneNetIDs[cl.NetworkID]; ok {
			return true
		}
		if _, ok := zoneNets[strings.ToLower(strings.TrimSpace(cl.NetworkName))]; ok {
			return true
		}
	}
	for _, pol := range snap.FirewallPolicies {
		if pol.Enabled && strings.EqualFold(pol.IPVersion, "ipv6") {
			return true
		}
	}
	return false
}

// selectorFamilyTri classifies a single IP, CIDR, or IP-range selector as
// "ipv4", "ipv6", or "" (unparseable).
func selectorFamilyTri(selector string) string {
	s := strings.TrimSpace(selector)
	if s == "" {
		return ""
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		if addr.Unmap().Is6() {
			return "ipv6"
		}
		return "ipv4"
	}
	if pfx, err := netip.ParsePrefix(s); err == nil {
		if pfx.Addr().Unmap().Is6() {
			return "ipv6"
		}
		return "ipv4"
	}
	if startStr, endStr, ok := strings.Cut(s, "-"); ok {
		a1, e1 := netip.ParseAddr(strings.TrimSpace(startStr))
		a2, e2 := netip.ParseAddr(strings.TrimSpace(endStr))
		if e1 == nil && e2 == nil {
			a1, a2 = a1.Unmap(), a2.Unmap()
			if a1.Is6() && a2.Is6() {
				return "ipv6"
			}
			if a1.Is4() && a2.Is4() {
				return "ipv4"
			}
		}
	}
	return ""
}

// allSelectorsOppositeFamily reports whether selectors is non-empty and every
// entry parses strictly to the opposite address family of fam.
func allSelectorsOppositeFamily(selectors []string, fam string) bool {
	if len(selectors) == 0 || fam == "" {
		return false
	}
	want := strings.ToLower(strings.TrimSpace(fam))
	for _, sel := range selectors {
		sf := selectorFamilyTri(sel)
		if sf == "" || sf == want {
			return false
		}
	}
	return true
}

// lastAddrOfPrefix returns the highest address in pfx for both IPv4 and IPv6.
func lastAddrOfPrefix(pfx netip.Prefix) netip.Addr {
	masked := pfx.Masked()
	addr := masked.Addr().Unmap()
	bits := masked.Bits()
	if addr.Is4() {
		b := addr.As4()
		u := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		var hostMask uint32
		if bits < 32 {
			hostMask = ^uint32(0) >> uint(bits)
		}
		end := u | hostMask
		return netip.AddrFrom4([4]byte{byte(end >> 24), byte(end >> 16), byte(end >> 8), byte(end)})
	}
	b := addr.As16()
	for i := bits; i < 128; i++ {
		b[i/8] |= 1 << (7 - uint(i%8))
	}
	return netip.AddrFrom16(b)
}

// selectorBoundaryNeighbors returns addresses immediately adjacent to selector
// in address order (used to step just outside excluded IPs, CIDRs, or ranges).
func selectorBoundaryNeighbors(selector, fam string) []netip.Addr {
	s := strings.TrimSpace(selector)
	wantV6 := strings.EqualFold(fam, "ipv6")
	var out []netip.Addr
	add := func(a netip.Addr) {
		if a.IsValid() && a.Unmap().Is6() == wantV6 {
			out = append(out, a.Unmap())
		}
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		a := addr.Unmap()
		if a.Is6() == wantV6 {
			add(a.Prev())
			add(a.Next())
		}
		return out
	}
	if pfx, err := netip.ParsePrefix(s); err == nil {
		if pfx.Addr().Unmap().Is6() == wantV6 {
			first := pfx.Masked().Addr().Unmap()
			last := lastAddrOfPrefix(pfx)
			add(first.Prev())
			add(last.Next())
		}
		return out
	}
	if startStr, endStr, ok := strings.Cut(s, "-"); ok {
		a1, e1 := netip.ParseAddr(strings.TrimSpace(startStr))
		a2, e2 := netip.ParseAddr(strings.TrimSpace(endStr))
		if e1 == nil && e2 == nil {
			a1, a2 = a1.Unmap(), a2.Unmap()
			if a1.Is6() == wantV6 && a2.Is6() == wantV6 {
				add(a1.Prev())
				add(a2.Next())
			}
		}
	}
	return out
}

// ipMatchesNoSelector reports whether ip definitively does not match any
// selector in excluded.
func ipMatchesNoSelector(ip string, excluded []string) bool {
	for _, sel := range excluded {
		if ipMatchesSelectorTri(ip, sel) != matchNo {
			return false
		}
	}
	return true
}

// sampleIPOutsideSelectors chooses a valid IP address of family fam belonging
// to net (when net defines a subnet for fam) that does not match any selector
// in excluded. Returns "" if net has a subnet for fam and every candidate in
// that subnet is covered by excluded.
func sampleIPOutsideSelectors(net unifi.Network, snap *unifi.Snapshot, fam string, excluded []string) string {
	wantV6 := strings.EqualFold(fam, "ipv6")
	var netPfx netip.Prefix
	hasPfx := false
	rawSub := net.Subnet
	if wantV6 {
		rawSub = net.IPv6Subnet
	}
	if s := strings.TrimSpace(rawSub); s != "" {
		if pfx, err := netip.ParsePrefix(s); err == nil && pfx.Addr().Unmap().Is6() == wantV6 {
			netPfx = pfx
			hasPfx = true
		}
	}

	usable := func(a netip.Addr) bool {
		if !a.IsValid() {
			return false
		}
		a = a.Unmap()
		if a.Is6() != wantV6 || a.IsUnspecified() || a.IsMulticast() {
			return false
		}
		if hasPfx && !netPfx.Contains(a) {
			return false
		}
		return ipMatchesNoSelector(a.String(), excluded)
	}

	// 1. Prefer an actual active client IP on net that is outside excluded.
	hasNetClient := false
	if snap != nil && (net.ID != "" || net.Name != "") {
		for _, cl := range snap.Clients {
			if (net.ID == "" || cl.NetworkID != net.ID) &&
				(net.Name == "" || !strings.EqualFold(cl.NetworkName, net.Name)) {
				continue
			}
			if wantV6 {
				for _, raw := range cl.IPv6 {
					if a, err := netip.ParseAddr(strings.TrimSpace(raw)); err == nil && a.Unmap().Is6() {
						hasNetClient = true
						if usable(a) {
							return a.Unmap().String()
						}
					}
				}
				if a, err := netip.ParseAddr(strings.TrimSpace(cl.IP)); err == nil && a.Unmap().Is6() {
					hasNetClient = true
					if usable(a) {
						return a.Unmap().String()
					}
				}
			} else if a, err := netip.ParseAddr(strings.TrimSpace(cl.IP)); err == nil && a.Unmap().Is4() {
				hasNetClient = true
				if usable(a) {
					return a.Unmap().String()
				}
			}
		}
	}

	// When net has no configured subnet for fam but does have active clients of
	// family fam, every active client was checked above and covered by excluded;
	// do not invent synthetic out-of-network addresses.
	if !hasPfx && hasNetClient {
		return ""
	}

	// 2. Try boundary neighbors just outside each excluded selector.
	for _, sel := range excluded {
		for _, cand := range selectorBoundaryNeighbors(sel, fam) {
			if usable(cand) {
				return cand.String()
			}
		}
	}

	// 3. Try standard host positions within net's configured subnet.
	if hasPfx {
		first := netPfx.Masked().Addr().Unmap()
		last := lastAddrOfPrefix(netPfx)
		cands := []netip.Addr{
			netPfx.Addr().Unmap(),
			first.Next(),
			first.Next().Next(),
			last.Prev(),
			first,
			last,
		}
		for _, c := range cands {
			if usable(c) {
				return c.String()
			}
		}
		return ""
	}

	// 4. When net has no subnet configured for fam, try deterministic fallback
	// documentation/private addresses of fam outside excluded.
	fallbacks := []string{"192.0.2.250", "10.255.255.250", "172.16.255.250"}
	if wantV6 {
		fallbacks = []string{"fd00:ffff::1", "2001:db8:ffff::1", "fd00:fffe::1"}
	}
	for _, fb := range fallbacks {
		if a, err := netip.ParseAddr(fb); err == nil && usable(a) {
			return a.String()
		}
	}
	return ""
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
