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

	// 2. Evaluate Guest/Untrusted -> Printer (Approved IPPS Printing vs Blocked Printer Admin).
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

			// 2a. IPPS/IPP Printing (default TCP 631).
			ippsExpected := "deny"
			if hasApprovedPath(intent.ApprovedPaths, srcZone, srcNet.Name, prn, prnZone, "printing", "tcp", printPort, "ipv4") {
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
					dstIP:      clientAddressForFamily(prn, "ipv4"),
					dstMAC:     prn.MAC,
					proto:      "tcp",
					port:       printPort,
					ipFamily:   "ipv4",
					state:      "new",
				}, prn.DisplayName(), "ipps-printing", ippsExpected,
			)
			if ippsCell.Verdict == IsolationBrokenDependency {
				ippsCell.RecommendedFix = fmt.Sprintf(
					"Allow %s -> %s (%s) strictly on TCP %d (IPPS) for approved printing while keeping printer administration (TCP 80/443) denied.",
					srcNet.Name, prn.DisplayName(), prn.IP, printPort,
				)
				notes = append(notes, PostureNote{
					Severity: checks.SeverityMedium,
					Title:    fmt.Sprintf("Approved guest printing path blocked (%s -> %s IPPS :%d)", srcNet.Name, prn.DisplayName(), printPort),
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
					DestIP:           prn.IP,
					DestFunction:     "printer-admin-shared-ipp",
					Transport:        "tcp",
					Port:             printPort,
					IPFamily:         "ipv4",
					PathKind:         ippsCell.PathKind,
					Enforcer:         ippsCell.Enforcer + " + CUPS /admin",
					Expected:         "deny",
					Effective:        "allow",
					Verdict:          IsolationViolation,
					DecisiveRuleID:   ippsCell.DecisiveRuleID,
					DecisiveRuleName: ippsCell.DecisiveRuleName,
					DecisiveReason:   fmt.Sprintf("CUPS serves /admin on TCP %d alongside IPP printing, reachable via %q", printPort, ippsCell.DecisiveRuleName),
					RecommendedFix:   fmt.Sprintf("Restrict CUPS /admin on %s to localhost/admin IPs in cupsd.conf because firewall rules on TCP %d cannot separate printing from CUPS administration.", prn.DisplayName(), printPort),
				}
				findings = append(findings, checks.Finding{
					CheckID:           "UB-UNIFI-ISO-PRINTER-ADMIN",
					Title:             fmt.Sprintf("Guest Network Can Reach CUPS Administration on Shared Print Port (%s -> %s:%d)", srcNet.Name, prn.DisplayName(), printPort),
					Category:          "isolation-policy",
					ClaimKind:         checks.ClaimConfiguredAccess,
					Property:          fmt.Sprintf("isolation-printer-admin-%s-%d", strings.ToLower(srcNet.Name), printPort),
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
						dstIP:      clientAddressForFamily(prn, "ipv4"),
						dstMAC:     prn.MAC,
						proto:      "tcp",
						port:       adminPort,
						ipFamily:   "ipv4",
						state:      "new",
					}, prn.DisplayName(), "printer-admin", "deny",
				)

				if adminCell.Verdict == IsolationViolation {
					adminCell.RecommendedFix = fmt.Sprintf(
						"Restrict rule %q so %s can reach %s (%s) only on TCP %d (IPPS printing) and deny printer web administration on TCP %d.",
						adminCell.DecisiveRuleName, srcNet.Name, prn.DisplayName(), prn.IP, printPort, adminPort,
					)
					findings = append(findings, checks.Finding{
						CheckID:           "UB-UNIFI-ISO-PRINTER-ADMIN",
						Title:             fmt.Sprintf("Guest Network Can Reach Printer Administration (%s -> %s:%d)", srcNet.Name, prn.DisplayName(), adminPort),
						Category:          "isolation-policy",
						ClaimKind:         checks.ClaimConfiguredAccess,
						Property:          fmt.Sprintf("isolation-printer-admin-%s-%d", strings.ToLower(srcNet.Name), adminPort),
						Transport:         "tcp",
						BaseSeverity:      checks.SeverityMedium,
						EffectiveSeverity: checks.SeverityMedium,
						Client:            prn,
						Port:              adminPort,
						Evidence:          fmt.Sprintf("source=%s (%s) -> printer=%s (%s:%d) allowed by %q", srcNet.Name, srcZone, prn.DisplayName(), prn.IP, adminPort, adminCell.DecisiveRuleName),
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
						proto:      "tcp",
						port:       443,
						ipFamily:   fam,
						state:      "new",
					}, dstNet.Name, "trusted-lan-transit", "deny",
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
						Transport:         "tcp",
						BaseSeverity:      checks.SeverityHigh,
						EffectiveSeverity: checks.SeverityHigh,
						Client:            unifi.Client{MAC: "iso:" + srcNet.ID + ":" + dstNet.ID, IP: gwIP, Name: fmt.Sprintf("%s -> %s", srcNet.Name, dstNet.Name), NetworkName: srcNet.Name},
						Port:              443,
						Evidence:          fmt.Sprintf("source=%s (%s) -> dest=%s (%s, family=%s, enforcer=%s, decisive_rule=%q)", srcNet.Name, srcZone, dstNet.Name, dstZone, fam, cell.Enforcer, cell.DecisiveRuleName),
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
		gwAdminCell := evaluateRoutedPath(
			snap, sortedPolicies, gwPoliciesAvailable, gwMissingReason,
			switchACLStatus, switchACLReason, gwName, srcNet, unifi.Network{Name: "Gateway", ZoneName: "Gateway"},
			pathQuery{
				srcZone:    srcZone,
				srcNetID:   srcNet.ID,
				srcNetName: srcNet.Name,
				dstZone:    "Gateway",
				dstNetName: "Gateway",
				dstIP:      gwIP,
				proto:      "tcp",
				port:       443,
				ipFamily:   "ipv4",
				state:      "new",
			}, gwName, "gateway-admin", "deny",
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
				Transport:         "tcp",
				BaseSeverity:      checks.SeverityHigh,
				EffectiveSeverity: checks.SeverityHigh,
				Client:            unifi.Client{MAC: "gw:" + srcNet.ID, IP: gwIP, Name: gwName, NetworkName: srcNet.Name + " -> Gateway"},
				Port:              443,
				Evidence:          fmt.Sprintf("source=%s (%s) -> gateway=%s (function=gateway-admin, family=ipv4, decisive_rule=%q)", srcNet.Name, srcZone, gwName, gwAdminCell.DecisiveRuleName),
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
			if matchesProtocol(pol.Protocol, q.proto) {
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
			if strings.EqualFold(pol.Source.ZoneName, q.srcZone) && strings.EqualFold(pol.Destination.ZoneName, q.dstZone) {
				return policyDecision{
					action:       "unknown",
					ruleID:       pol.ID,
					ruleName:     pol.Name,
					missingInput: fmt.Sprintf("Policy %q uses an unsupported construct (%s)", pol.Name, pol.UnsupportedReason),
				}
			}
			continue
		}
		if !matchesProtocol(pol.Protocol, q.proto) {
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
	for _, d := range snap.Devices {
		dm := strings.ToLower(d.MAC)
		for _, p := range d.Ports {
			portIso[fmt.Sprintf("%s|%d", dm, p.PortIdx)] = p.Isolation
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
		if len(wiredClients) >= 2 || (explicitReq && len(wiredClients) >= 1) {
			allPortsIsolated := len(wiredClients) > 0
			for _, wc := range wiredClients {
				if wc.SwitchMAC == "" || wc.SwitchPort <= 0 || !portIso[fmt.Sprintf("%s|%d", strings.ToLower(wc.SwitchMAC), wc.SwitchPort)] {
					allPortsIsolated = false
					break
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
					DecisiveReason: "all wired switch ports on this VLAN have L2 port isolation enabled",
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
						MissingInput:   fmt.Sprintf("Switch ACL unavailable (%s); gateway firewall cannot filter same-VLAN wired switching on %s.", switchACLReason, n.Name),
						RecommendedFix: fmt.Sprintf("Enable switch port isolation or provide switch ACL data for %s.", n.Name),
					})
				} else {
					swMAC := ""
					for m := range wiredSwitches {
						swMAC = m
						break
					}
					enforcer := "UniFi Switch (L2 Switch ACL)"
					if swMAC != "" {
						enforcer = deviceNameByMAC(snap, swMAC) + " (L2 Switch ACL)"
					}
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
					applyDecisionToCell(&c, dec)
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
	if ep.ZoneName != "" && !strings.EqualFold(ep.ZoneName, zone) {
		return matchNo, ""
	}
	if ep.UnsupportedSelector != "" {
		return matchUnknown, ep.UnsupportedSelector
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
					if ipMatchesSelector(ip, candidate) {
						targetState = matchYes
						break
					}
				}
			}
		}
		if targetState == matchUnknown {
			return matchUnknown, "policy targets specific host IP/MAC not fixed in zone-level query"
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

	if !ep.AnyPort {
		if len(ep.Ports) == 0 {
			return matchUnknown, "port group selector unresolved"
		}
		if port == 0 {
			return matchUnknown, "policy restricts specific port(s) not fixed in query"
		}
		portState := matchNo
		for _, p := range ep.Ports {
			if p == port {
				portState = matchYes
				break
			}
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
	return matchYes, ""
}

func ipMatchesSelector(targetIP, selector string) bool {
	targetIP = strings.TrimSpace(targetIP)
	selector = strings.TrimSpace(selector)
	if strings.EqualFold(targetIP, selector) {
		return true
	}
	addr, err1 := netip.ParseAddr(targetIP)
	if err1 != nil {
		return false
	}
	if pfx, err2 := netip.ParsePrefix(selector); err2 == nil {
		return pfx.Contains(addr)
	}
	if sAddr, err3 := netip.ParseAddr(selector); err3 == nil {
		return addr == sAddr
	}
	return false
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
		if fnHint != "" && ap.Function != "" && !strings.Contains(strings.ToLower(ap.Function), strings.ToLower(fnHint)) && !strings.Contains(strings.ToLower(ap.DestRole), strings.ToLower(fnHint)) {
			continue
		}
		return true
	}
	return false
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
