// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package risk

import (
	"fmt"
	"iter"
	"net/netip"
	"slices"
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
	// SourceZone is the firewall zone where the connection originates.
	SourceZone string `json:"source_zone"`
	// SourceNetwork names the originating VLAN or the permitted WAN sources.
	SourceNetwork string `json:"source_network,omitempty"`
	// DestZone is the firewall zone containing the destination.
	DestZone string `json:"dest_zone"`
	// DestNetwork names the network containing the destination.
	DestNetwork string `json:"dest_network,omitempty"`
	// DestHost identifies the evaluated host or network by its display name.
	DestHost string `json:"dest_host,omitempty"`
	// DestIP is the destination address used for the decision.
	DestIP string `json:"dest_ip,omitempty"`
	// DestFunction identifies the service or boundary being evaluated.
	DestFunction string `json:"dest_function"`
	// Transport is the evaluated protocol or "all" for a protocol-independent path.
	Transport string `json:"transport"`
	// Port is the destination port when the decision identifies one.
	Port int `json:"port,omitempty"`
	// IPFamily is "ipv4", "ipv6", or "both" for a family-independent decision.
	IPFamily string `json:"ip_family"`
	// PathKind describes how traffic reaches the destination.
	PathKind string `json:"path_kind"`
	// Enforcer names the device or setting responsible for the decision.
	Enforcer string `json:"enforcer"`
	// EnforcerMACs identifies the enforcing devices by their canonical hardware addresses.
	EnforcerMACs []string `json:"enforcer_macs,omitempty"`
	// Expected records whether site intent requires "allow" or "deny".
	Expected string `json:"expected"`
	// Effective records the configured outcome as "allow", "deny", or "unknown".
	Effective string `json:"effective"`
	// Verdict compares the effective outcome with the expected one.
	Verdict IsolationVerdict `json:"verdict"`
	// DecisiveRuleID identifies the matching rule in the controller.
	DecisiveRuleID string `json:"decisive_rule_id,omitempty"`
	// DecisiveRuleName names the matching rule or default disposition.
	DecisiveRuleName string `json:"decisive_rule_name,omitempty"`
	// DecisiveReason explains which evidence determined the outcome.
	DecisiveReason string `json:"decisive_reason,omitempty"`
	// MissingInput identifies the evidence needed to resolve an unknown outcome.
	MissingInput string `json:"missing_input,omitempty"`
	// RecommendedFix describes the change needed to meet site intent.
	RecommendedFix string `json:"recommended_fix,omitempty"`
}

// IsolationMatrix summarizes effective isolation policy evaluation across zones,
// IPv4/IPv6 families, gateway vs switch routing, and Wi-Fi/wired L2 boundaries.
type IsolationMatrix struct {
	// Cells holds every individual evaluated isolation path across routed and L2 boundaries.
	Cells []IsolationCell `json:"cells,omitempty"`

	// Containment holds the 4-axis containment summary (Peers, LAN Egress,
	// Internet Egress, LAN Inbound) for each isolated or targeted VLAN.
	Containment []NetworkContainment `json:"containment,omitempty"`

	// ApprovedCount counts cells with verdict IsolationApproved.
	ApprovedCount int `json:"approved_count"`

	// BlockedOKCount counts cells with verdict IsolationBlockedOK.
	BlockedOKCount int `json:"blocked_ok_count"`

	// ViolationCount counts cells with verdict IsolationViolation.
	ViolationCount int `json:"violation_count"`

	// UnknownCount counts cells with verdict IsolationUnknown due to missing or ambiguous evidence.
	UnknownCount int `json:"unknown_count"`

	// BrokenDepCount counts cells with verdict IsolationBrokenDependency where an approved workflow is blocked.
	BrokenDepCount int `json:"broken_dep_count"`
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

	return NewOracle(snap, netCfg).evaluateIsolation(rawFindings, netCfg)
}

// evaluateIsolation computes the complete IsolationMatrix, policy-violation
// findings, and posture notes using the Oracle's pre-indexed snapshot and site
// isolation intent.
func (o *Oracle) evaluateIsolation(rawFindings []checks.Finding, netCfg config.NetworkConfig) (*IsolationMatrix, []checks.Finding, []PostureNote) {
	snap := o.snap
	matrix := &IsolationMatrix{}
	var findings []checks.Finding
	var notes []PostureNote

	trustedSet, isolatedSet := vlanTiers(snap, netCfg, o.isolatedZones())
	intendedIsoZones := intendedIsolatedZoneSet(snap)
	intent := o.intent

	var untrustedNets []unifi.Network
	var trustedNets []unifi.Network
	var containmentNets []unifi.Network
	// Always include VLANs explicitly named in containment policy lists even if
	// they currently reside in the Internal zone without UniFi network isolation.
	var explicitTargets []string
	for _, group := range [][]string{intent.IoTVLANs, intent.NoInternetVLANs, intent.StrictInboundVLANs, intent.RequireSameVLANIsolation} {
		explicitTargets = append(explicitTargets, group...)
	}
	explicit := toLowerSet(explicitTargets)
	for _, n := range snap.Networks {
		p := strings.ToLower(strings.TrimSpace(n.Purpose))
		z := strings.ToLower(strings.TrimSpace(n.ZoneName))
		if p == "wan" || p == "wan2" || p == "remote-user-vpn" || z == "external" || z == "vpn" || z == "gateway" {
			continue
		}
		targeted := isNetworkInSet(n.Name, explicit) || (n.VLAN != "" && isNetworkInSet(n.VLAN, explicit))
		if targeted {
			containmentNets = append(containmentNets, n)
		}
		if isManagementNetwork(n, intent) {
			continue
		}
		vlan := unifi.Client{NetworkName: n.Name, VLAN: n.VLAN}
		if matchesVLAN(vlan, isolatedSet) || isGuestNetwork(n, intent) || isCameraNetwork(n, intent) ||
			(intendedIsoZones[z] && !matchesVLAN(vlan, trustedSet)) {
			untrustedNets = append(untrustedNets, n)
			if !targeted {
				containmentNets = append(containmentNets, n)
			}
		} else if matchesVLAN(vlan, trustedSet) {
			trustedNets = append(trustedNets, n)
		}
	}

	bmcClients := o.ManagementControllers(rawFindings)
	printerClients := o.identifyPrinterClients(rawFindings)

	// Keep address-specific evidence in the matrix and report each host finding once.
	hostFindings := make(map[string]bool)
	addHostFinding := func(f checks.Finding) {
		key := f.Key()
		if !hostFindings[key] {
			hostFindings[key] = true
			findings = append(findings, f)
		}
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
		bmcNet := o.network(bmc.NetworkID, bmc.NetworkName)
		bmcZone := strings.TrimSpace(bmcNet.ZoneName)
		endpoints := bmcServiceEndpoints(bmc, rawFindings)
		for _, srcNet := range untrustedNets {
			if srcNet.MatchesIdentity(bmc.NetworkID, bmc.NetworkName) {
				continue
			}
			srcZone := strings.TrimSpace(srcNet.ZoneName)
			for _, ep := range endpoints {
				for fam, targetIP := range hostTargets(bmc, []string{"ipv4", "ipv6"}) {
					if fam == "ipv6" && !siteHasIPv6Context(snap, srcNet, bmcNet, bmc, false) {
						continue
					}
					target := unifi.Client{NetworkName: bmc.NetworkName, IP: targetIP}
					expected := "deny"
					if hasApprovedPath(intent.ApprovedPaths, srcZone, srcNet.Name, target, bmcZone, "bmc", ep.proto, ep.port, fam) {
						expected = "allow"
					}
					cell := o.evaluateRoutedPath(
						srcNet, bmcNet,
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
						addrDisp := firstNonEmptyStr(targetIP, "address unknown")
						cell.RecommendedFix = fmt.Sprintf(
							"Narrow or remove %s rule %q on %s so %s cannot initiate %s %s/%d connections to BMC %s (%s); restrict BMC access strictly to approved admin workstations while preserving established management sessions.",
							strings.ToUpper(fam), cell.DecisiveRuleName, cell.Enforcer, srcNet.Name, strings.ToUpper(fam), strings.ToUpper(ep.proto), ep.port, bmc.DisplayName(), addrDisp,
						)
						checkID := "UB-UNIFI-ISO-BMC-PATH"
						if fam == "ipv6" {
							checkID = "UB-UNIFI-ISO-BMC-IPV6"
						}
						addHostFinding(checks.Finding{
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
		prnNet := o.network(prn.NetworkID, prn.NetworkName)
		prnZone := strings.TrimSpace(prnNet.ZoneName)
		printPort := printerServicePort(prn, rawFindings, intent)
		cupsAdminOn631 := hasCUPSAdminFinding(prn, rawFindings)

		for _, srcNet := range untrustedNets {
			if !isGuestNetwork(srcNet, intent) && !strings.EqualFold(srcNet.ZoneName, "hotspot") {
				continue
			}
			srcZone := strings.TrimSpace(srcNet.ZoneName)

			noted := make(map[string]bool)
			for fam, prnAddr := range hostTargets(prn, []string{"ipv4", "ipv6"}) {
				if fam == "ipv6" && !siteHasIPv6Context(snap, srcNet, prnNet, prn, false) {
					continue
				}
				target := unifi.Client{NetworkName: prn.NetworkName, IP: prnAddr}
				addrDisp := firstNonEmptyStr(prnAddr, "address unknown")

				// 2a. IPPS/IPP Printing (default TCP 631).
				ippsExpected := "deny"
				if hasApprovedPath(intent.ApprovedPaths, srcZone, srcNet.Name, target, prnZone, "printing", "tcp", printPort, fam) {
					ippsExpected = "allow"
				}
				ippsCell := o.evaluateRoutedPath(
					srcNet, prnNet,
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
					if !noted[fam] {
						noted[fam] = true
						notes = append(notes, PostureNote{
							Severity: checks.SeverityMedium,
							Title:    fmt.Sprintf("Approved guest printing path blocked (%s -> %s IPPS :%d, %s)", srcNet.Name, prn.DisplayName(), printPort, fam),
							Detail:   ippsCell.RecommendedFix,
						})
					}
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
						DestIP:           prnAddr,
						DestFunction:     "printer-admin-shared-ipp",
						Transport:        "tcp",
						Port:             printPort,
						IPFamily:         fam,
						PathKind:         ippsCell.PathKind,
						Enforcer:         ippsCell.Enforcer + " + CUPS /admin",
						EnforcerMACs:     ippsCell.EnforcerMACs,
						Expected:         "deny",
						Effective:        "allow",
						Verdict:          IsolationViolation,
						DecisiveRuleID:   ippsCell.DecisiveRuleID,
						DecisiveRuleName: ippsCell.DecisiveRuleName,
						DecisiveReason:   fmt.Sprintf("CUPS serves /admin on TCP %d (%s) alongside IPP printing, reachable via %q", printPort, fam, ippsCell.DecisiveRuleName),
						RecommendedFix:   fmt.Sprintf("Restrict CUPS /admin on %s to localhost/admin IPs in cupsd.conf because firewall rules on TCP %d cannot separate printing from CUPS administration.", prn.DisplayName(), printPort),
					}
					addHostFinding(checks.Finding{
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
					adminCell := o.evaluateRoutedPath(
						srcNet, prnNet,
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
						addHostFinding(checks.Finding{
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
				if clientHasIP(cl, ap.DestIP) {
					dstClient = cl
					break
				}
			}
			dstNet := o.network(dstClient.NetworkID, dstClient.NetworkName)
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
				clNet := o.network(cl.NetworkID, cl.NetworkName)
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
		case "":
			if selectorFamilyTri(ap.DestIP) == "ipv6" {
				fams = []string{"ipv6"}
			}
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
			if ap.DestIP != "" {
				// A host approval covers only the named address, even on a dual-stack client.
				dstClient.IP, dstClient.IPv6 = ap.DestIP, nil
			}
			for _, srcNet := range srcNets {
				srcZone := strings.TrimSpace(srcNet.ZoneName)
				noted := make(map[string]bool)
				for fam, dstAddr := range hostTargets(dstClient, fams) {
					if ap.DestIP != "" && dstAddr == "" {
						continue
					}
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
					if fam == "ipv6" && !siteHasIPv6Context(snap, srcNet, dstNet, dstClient, false) {
						continue
					}
					cell := o.evaluateRoutedPath(
						srcNet, dstNet,
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
						if !noted[fam] {
							noted[fam] = true
							notes = append(notes, PostureNote{
								Severity: checks.SeverityMedium,
								Title:    fmt.Sprintf("Approved workflow blocked (%s -> %s %s:%d, %s)", srcNet.Name, dstName, strings.ToUpper(proto), ap.Port, fam),
								Detail:   cell.RecommendedFix,
							})
						}
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
				if fam == "ipv6" && !siteHasIPv6Context(snap, srcNet, dstNet, unifi.Client{}, false) {
					continue
				}
				cell := o.boundaryWithApproval(
					rawFindings, intent, srcNet, dstNet, srcZone, dstZone, fam, "deny", nil, o.builtinDNS,
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
						Client:            unifi.Client{MAC: "iso:" + srcNet.ID + ":" + dstNet.ID, IP: o.gwIP, Name: fmt.Sprintf("%s -> %s", srcNet.Name, dstNet.Name), NetworkName: srcNet.Name},
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
			if fam == "ipv6" && !gatewayHasIPv6Context(snap, srcNet, o.sortedPolicies) {
				continue
			}
			gwIPsFam := allGatewayIPsForFamily(snap, o.gwIP, fam, srcNet, o.sortedPolicies)
			gwAdminCell := o.evaluateGatewayAdminBoundary(
				gwIPsFam, srcNet, srcZone, fam,
			)
			if gwAdminCell.Verdict == IsolationViolation {
				gwAdminCell.RecommendedFix = fmt.Sprintf(
					"Block %s -> Gateway %s administration (TCP 443/22) in rule %q while keeping Gateway DHCP and DNS allowed.",
					srcNet.Name, strings.ToUpper(fam), gwAdminCell.DecisiveRuleName,
				)
				findings = append(findings, checks.Finding{
					CheckID:           "UB-UNIFI-ISO-GW-ADMIN",
					Title:             fmt.Sprintf("Untrusted Network Permitted %s Gateway Administration (%s -> %s)", strings.ToUpper(fam), srcNet.Name, o.gwName),
					Category:          "isolation-policy",
					ClaimKind:         checks.ClaimConfiguredAccess,
					Property:          fmt.Sprintf("isolation-gw-admin-%s-%s", strings.ToLower(srcNet.Name), fam),
					Transport:         gwAdminCell.Transport,
					BaseSeverity:      checks.SeverityHigh,
					EffectiveSeverity: checks.SeverityHigh,
					Client:            unifi.Client{MAC: "gw:" + srcNet.ID, IP: gwAdminCell.DestIP, Name: o.gwName, NetworkName: srcNet.Name + " -> Gateway"},
					Port:              gwAdminCell.Port,
					Evidence:          fmt.Sprintf("source=%s (%s) -> gateway=%s (function=gateway-admin, family=%s, proto=%s/%d, decisive_rule=%q)", srcNet.Name, srcZone, o.gwName, fam, gwAdminCell.Transport, gwAdminCell.Port, gwAdminCell.DecisiveRuleName),
					Remediation: checks.Remediation{
						Summary:      gwAdminCell.RecommendedFix,
						UniFiActions: []string{"block_untrusted_gateway_admin"},
					},
				})
			} else if gwAdminCell.Verdict == IsolationUnknown && gwAdminCell.MissingInput != "" {
				notes = append(notes, PostureNote{
					Severity: checks.SeverityLow,
					Title:    fmt.Sprintf("Isolation verdict unknown for %s -> Gateway (%s)", srcNet.Name, strings.ToUpper(fam)),
					Detail:   gwAdminCell.MissingInput,
				})
			}
			addCell(gwAdminCell)
		}

		// 3c. Essential Gateway Dependencies (DNS UDP 53 & DHCP UDP 67) when gateway policies are available:
		// flag only if an explicit rule breaks them (broken-dependency). Check both the source
		// VLAN's own gateway interface IP (from srcNet.Subnet) and the primary gateway IP so
		// DNS/DHCP ALLOW rules scoped to the VLAN's local gateway IP are recognized as approved.
		if o.gwPoliciesAvailable {
			var depDstIPs []string
			depDstIPs = slices.AppendSeq(depDstIPs, gatewayInterfaceIPs(srcNet, "ipv4"))
			if o.gwIP != "" && (len(depDstIPs) == 0 || depDstIPs[0] != o.gwIP) {
				depDstIPs = append(depDstIPs, o.gwIP)
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
					cand := o.evaluateRoutedPath(
						srcNet, unifi.Network{Name: "Gateway", ZoneName: "Gateway"},
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
						}, o.gwName, dep.function, "allow",
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

	// Evaluate 4-axis network containment (Peers, LAN Egress, Internet Egress,
	// and LAN Inbound) for every isolated or explicitly targeted VLAN.
	containment, contCells, contFindings, contNotes := o.evaluateNetworkContainment(
		rawFindings,
		containmentNets, trustedNets, matrix.Cells,
	)
	matrix.Containment = containment
	for _, c := range contCells {
		addCell(c)
	}
	findings = append(findings, contFindings...)
	notes = append(notes, contNotes...)

	return matrix, findings, notes
}

// applyDecisionToCell copies dec's effective action, decisive rule metadata,
// and missing-input note onto cell, then derives cell.Verdict by comparing
// dec.action against cell.Expected.
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
// negation, and port selectors. When multiple enabled policies share the same
// Index and produce conflicting or unknown outcomes for q, the verdict degrades
// conservatively to unknown rather than depending on response order.
func evaluateGatewayPolicies(policies []unifi.FirewallPolicy, q pathQuery) policyDecision {
	evalPolicy := func(pol unifi.FirewallPolicy) (policyDecision, bool) {
		if !pol.Enabled {
			return policyDecision{}, false
		}
		if !matchesIPFamily(pol.IPVersion, q.ipFamily) {
			return policyDecision{}, false
		}

		// Handle automatic stateful return traffic for ALLOW rules in the reverse direction.
		if strings.EqualFold(q.state, "established") && pol.MatchReturnTraffic && strings.EqualFold(pol.Action, "ALLOW") {
			if matchesPolicyProtocol(pol.Protocol, pol.ProtocolNegated, q.proto) {
				revSrc, _ := matchesEndpoint(pol.Source, q.dstZone, q.dstNetID, q.dstNetName, q.dstIP, q.dstMAC, q.port, q.ipFamily)
				revDst, _ := matchesEndpoint(pol.Destination, q.srcZone, q.srcNetID, q.srcNetName, q.srcIP, q.srcMAC, q.srcPort, q.ipFamily)
				if revSrc != matchNo && revDst != matchNo && (pol.UnsupportedReason != "" || pol.Schedule != "" || revSrc == matchUnknown || revDst == matchUnknown) {
					return policyDecision{action: "unknown", ruleID: pol.ID, ruleName: pol.Name, missingInput: "conditional automatic return traffic"}, true
				}
				if revSrc == matchYes && revDst == matchYes {
					return policyDecision{
						action:   "allow",
						ruleID:   pol.ID,
						ruleName: pol.Name,
						reason:   fmt.Sprintf("matched automatic return traffic for ALLOW rule %q (index=%d)", pol.Name, pol.Index),
					}, true
				}
			}
		}

		if !matchesConnState(pol.ConnectionStates, q.state) {
			return policyDecision{}, false
		}
		if pol.UnsupportedReason != "" {
			if (pol.Source.ZoneName == "" || strings.EqualFold(pol.Source.ZoneName, q.srcZone)) &&
				(pol.Destination.ZoneName == "" || strings.EqualFold(pol.Destination.ZoneName, q.dstZone)) {
				return policyDecision{
					action:       "unknown",
					ruleID:       pol.ID,
					ruleName:     pol.Name,
					missingInput: fmt.Sprintf("Policy %q uses an unsupported construct (%s)", pol.Name, pol.UnsupportedReason),
				}, true
			}
			return policyDecision{}, false
		}
		if !matchesPolicyProtocol(pol.Protocol, pol.ProtocolNegated, q.proto) {
			return policyDecision{}, false
		}

		srcMatch, srcReason := matchesEndpoint(pol.Source, q.srcZone, q.srcNetID, q.srcNetName, q.srcIP, q.srcMAC, q.srcPort, q.ipFamily)
		if srcMatch == matchNo {
			return policyDecision{}, false
		}
		dstMatch, dstReason := matchesEndpoint(pol.Destination, q.dstZone, q.dstNetID, q.dstNetName, q.dstIP, q.dstMAC, q.port, q.ipFamily)
		if dstMatch == matchNo {
			return policyDecision{}, false
		}

		if pol.Schedule != "" {
			return policyDecision{
				action:       "unknown",
				ruleID:       pol.ID,
				ruleName:     pol.Name,
				missingInput: fmt.Sprintf("Policy %q is conditional on schedule %q", pol.Name, pol.Schedule),
			}, true
		}
		if srcMatch == matchUnknown || dstMatch == matchUnknown {
			reason := firstNonEmptyStr(srcReason, dstReason)
			return policyDecision{
				action:       "unknown",
				ruleID:       pol.ID,
				ruleName:     pol.Name,
				missingInput: fmt.Sprintf("Policy %q uses an unsupported or unresolved selector (%s)", pol.Name, reason),
			}, true
		}

		act := strings.ToUpper(strings.TrimSpace(pol.Action))
		if act == "ALLOW" {
			return policyDecision{
				action:   "allow",
				ruleID:   pol.ID,
				ruleName: pol.Name,
				reason:   fmt.Sprintf("matched ALLOW rule %q (index=%d, family=%s, proto=%s)", pol.Name, pol.Index, firstNonEmptyStr(pol.IPVersion, "both"), formatPolicyProtocol(pol.Protocol, pol.ProtocolNegated)),
			}, true
		}
		if act == "BLOCK" || act == "REJECT" || act == "DROP" {
			return policyDecision{
				action:   "deny",
				ruleID:   pol.ID,
				ruleName: pol.Name,
				reason:   fmt.Sprintf("matched %s rule %q (index=%d, family=%s)", act, pol.Name, pol.Index, firstNonEmptyStr(pol.IPVersion, "both")),
			}, true
		}
		return policyDecision{}, false
	}

	// Evaluate in ascending Index groups so conflicting enabled rules sharing
	// the same Index cannot produce an order-dependent definitive verdict.
	for i := 0; i < len(policies); {
		idx := policies[i].Index
		j := i + 1
		for j < len(policies) && policies[j].Index == idx {
			j++
		}
		var (
			matched bool
			dec     policyDecision
		)
		for k := i; k < j; k++ {
			d, ok := evalPolicy(policies[k])
			if !ok {
				continue
			}
			if !matched {
				matched = true
				dec = d
				continue
			}
			if d.action == "unknown" || dec.action == "unknown" || d.action != dec.action {
				return policyDecision{
					action:       "unknown",
					ruleID:       dec.ruleID,
					ruleName:     dec.ruleName,
					missingInput: fmt.Sprintf("Ambiguous firewall policy priority: conflicting rules share index %d", idx),
				}
			}
		}
		if matched {
			return dec
		}
		i = j
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

// orderedSwitchACLs orders switch ACLs according to UniFi switch processing
// precedence (MAC ACLs before IP ACLs, then ascending Index within each class),
// preserving wire order on ties.
func orderedSwitchACLs(acls []unifi.SwitchACL) []unifi.SwitchACL {
	sorted := append([]unifi.SwitchACL(nil), acls...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := strings.EqualFold(sorted[i].RuleType, "MAC"), strings.EqualFold(sorted[j].RuleType, "MAC")
		if a != b {
			return a
		}
		return sorted[i].Index < sorted[j].Index
	})
	return sorted
}

// evaluateSwitchACLs evaluates ordered UniFi switch ACL rules scoped to
// switchMAC for the directed query q, returning the first matching verdict or
// the default switch forwarding allow when no rule matches.
func evaluateSwitchACLs(acls []unifi.SwitchACL, switchMAC string, q pathQuery) policyDecision {
	swLower := strings.ToLower(strings.TrimSpace(switchMAC))
	for _, acl := range acls {
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

type triMatch int

const (
	matchNo triMatch = iota
	matchYes
	matchUnknown
)

// matchesEndpoint evaluates ep's zone, port, network, MAC, and IP constraints
// against a concrete or partially specified query, returning matchYes, matchNo,
// or matchUnknown (with a reason). Among constraints the matcher reaches,
// definitive mismatches take precedence over missing evidence in other
// dimensions so an unrelated rule does not cause a spurious unknown verdict
// (an unresolved zone ID or unsupported selector can still return matchUnknown
// earlier).
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
		if ep.NegateTarget && ep.HasCompoundTarget() {
			return matchUnknown, "ambiguous compound target negation"
		}
		hasSelector := len(ep.IPs) > 0 || len(ep.NetworkIDs) > 0 || len(ep.MACs) > 0
		if !hasSelector {
			return matchUnknown, "opaque target filter without IP/network/MAC details"
		}
		targetState := matchYes
		// Independent dimensions are conjunctive. A definitive mismatch
		// dominates missing evidence in another dimension.
		combine := func(m triMatch) {
			if m == matchNo || targetState == matchYes {
				targetState = m
			}
		}
		if len(ep.NetworkIDs) > 0 {
			switch {
			case netID == "" && netName == "":
				combine(matchUnknown)
			case !containsFold(ep.NetworkIDs, netID) && !containsFold(ep.NetworkIDs, netName):
				combine(matchNo)
			}
		}
		if len(ep.MACs) > 0 {
			switch {
			case mac == "":
				combine(matchUnknown)
			case !containsFold(ep.MACs, mac):
				combine(matchNo)
			}
		}
		if len(ep.IPs) > 0 {
			m := matchNo
			for _, v := range ep.IPs {
				r := ipMatchesSelectorTri(ip, v, ipFamily)
				if r == matchYes {
					m = r
					break
				}
				if r == matchUnknown {
					m = r
				}
			}
			// Even an unidentified gateway interface has a unicast address.
			if m == matchUnknown && ip == "" && strings.EqualFold(zone, "Gateway") && ipFamily != "" && unicastSelectorFamily(ep.IPs, ipFamily) == matchNo {
				m = matchNo
			}
			combine(m)
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

// ipMatchesSelectorTri matches an exact IP, prefix, or inclusive address range.
// For a missing address, the family alone can rule out a selector or prove a /0 match.
func ipMatchesSelectorTri(targetIP, selector, fam string) triMatch {
	targetIP = strings.TrimSpace(targetIP)
	selector = strings.TrimSpace(selector)
	if targetIP == "" {
		if sf := selectorFamilyTri(selector); fam != "" && sf != "" {
			if !strings.EqualFold(sf, fam) {
				return matchNo
			}
			if p, err := netip.ParsePrefix(selector); err == nil && p.Bits() == 0 {
				return matchYes
			}
		}
		return matchUnknown
	}
	if selector == "" {
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

// hostTargets yields routable addresses for cross-VLAN checks. When a host has
// no routable address in a family it yields "" so zone-level checks still
// evaluate, except when a host only has non-routable IPv6 addresses (such as
// link-local fe80::), which cannot be reached across VLANs.
func hostTargets(cl unifi.Client, families []string) iter.Seq2[string, string] {
	return func(yield func(string, string) bool) {
		for _, fam := range families {
			raw := peerAddresses(cl, fam)
			ips := slices.DeleteFunc(slices.Clone(raw), isNonRoutableIP)
			if len(ips) == 0 {
				if strings.EqualFold(fam, "ipv6") && len(raw) > 0 {
					continue
				}
				if !yield(fam, "") {
					return
				}
				continue
			}
			for _, ip := range ips {
				if !yield(fam, ip) {
					return
				}
			}
		}
	}
}

// bmcServiceEndpoints collects deduplicated IPMI and Redfish/HTTPS service
// endpoints observed for bmc in rawFindings, defaulting to TCP 443 when no
// probe findings were recorded.
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

// printerServicePort resolves the printing TCP port for prn from observed IPP
// findings or matching ApprovedPaths, falling back to standard IPP/IPPS port 631.
func printerServicePort(prn unifi.Client, rawFindings []checks.Finding, intent config.IsolationIntent) int {
	for _, f := range rawFindings {
		if sameClient(f.Client, prn) && f.Port > 0 && (f.Port == 631 || strings.Contains(strings.ToLower(f.Title), "ipp")) {
			return f.Port
		}
	}
	for _, ap := range intent.ApprovedPaths {
		if ap.Port > 0 && (clientHasIP(prn, ap.DestIP) || (ap.DestIP == "" && strings.Contains(strings.ToLower(ap.Function), "print"))) {
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

// clientHasIP matches a configured host address against every inventory alias.
func clientHasIP(cl unifi.Client, ip string) bool {
	want := canonicalIsolationIP(ip)
	return want != "" && slices.ContainsFunc(cl.AllIPs(), func(raw string) bool { return canonicalIsolationIP(raw) == want })
}

func sameClient(a, b unifi.Client) bool {
	if a.MAC != "" && b.MAC != "" && strings.EqualFold(a.MAC, b.MAC) {
		return true
	}
	return a.IP != "" && b.IP != "" && a.IP == b.IP
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

// siteHasIPv6Context checks both VLANs, the target client, and IPv6 policies.
// On-link queries also consider clients whose only IPv6 address is link-local.
func siteHasIPv6Context(snap *unifi.Snapshot, a, b unifi.Network, cl unifi.Client, onLink bool) bool {
	if len(networkPrefixesForFamily(a, "ipv6")) > 0 || len(networkPrefixesForFamily(b, "ipv6")) > 0 {
		return true
	}
	for _, raw := range cl.AllIPs() {
		addr, err := netip.ParseAddr(raw)
		if err == nil && addr.Unmap().Is6() && (addr.IsGlobalUnicast() || onLink && addr.IsLinkLocalUnicast()) {
			return true
		}
	}
	for _, pol := range snap.FirewallPolicies {
		if !pol.Enabled {
			continue
		}
		if strings.EqualFold(pol.IPVersion, "ipv6") || matchesIPFamily(pol.IPVersion, "ipv6") &&
			(gatewayIPv6Target(pol.Source) == matchYes || gatewayIPv6Target(pol.Destination) == matchYes) {
			return true
		}
	}
	for _, n := range []unifi.Network{a, b} {
		for range networkClientAddresses(n, snap, "ipv6", onLink) {
			return true
		}
	}
	return false
}

// hasApprovedPath reports whether any operator-configured ApprovedPath permits
// traffic from (srcZone, srcNet) to dst on (proto, port, fam) matching fnHint.
func hasApprovedPath(paths []config.ApprovedPath, srcZone, srcNet string, dst unifi.Client, dstZone, fnHint, proto string, port int, fam string) bool {
	for _, ap := range paths {
		if ap.SourceZone != "" && !strings.EqualFold(ap.SourceZone, srcZone) && !strings.EqualFold(ap.SourceZone, srcNet) {
			continue
		}
		if ap.DestIP != "" && !slices.Contains(peerAddresses(dst, fam), canonicalIsolationIP(ap.DestIP)) {
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

// clientMatchesApprovedRole reports whether cl fulfills an approved destination
// role or function (such as printer, BMC, UPS, NVR, backup, PBX, or custom
// role words) using observed probe findings, ports, vendor OUI, and tokenized
// host identity.
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

// isTransitProbeApproved reports whether a specific transit counterexample
// (dstIP, proto, port, fam) is covered by an explicit port-scoped ApprovedPath,
// verifying the resolved destination client's role whenever the approval sets
// DestRole or sets Function without a fixed DestIP.
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
		// When an approval sets DestRole, or sets Function without a fixed DestIP
		// (e.g., dest_role: "ups" or function: "ipps-printing"), never suppress a
		// zone-wide ALLOW rule or a host that does not actually hold the approved
		// role or function.
		if strings.TrimSpace(ap.DestRole) != "" || (strings.TrimSpace(ap.DestIP) == "" && strings.TrimSpace(ap.Function) != "") {
			if !hasDstClient || !clientMatchesApprovedRole(dstClient, rawFindings, ap.DestRole, ap.Function) {
				continue
			}
		}
		return true
	}
	return false
}

var gatewayAdminPorts = []int{443, 22, 80, 8443}

// gatewayAdminPolicy reports whether the rule can apply to a management
// connection from this zone. Discovery and address assignment use other services.
func gatewayAdminPolicy(pol unifi.FirewallPolicy, srcZone, fam string) bool {
	return pol.Enabled && matchesIPFamily(pol.IPVersion, fam) && matchesConnState(pol.ConnectionStates, "new") &&
		(pol.Destination.ZoneName == "" || strings.EqualFold(pol.Destination.ZoneName, "gateway")) &&
		(srcZone == "" || pol.Source.ZoneName == "" || strings.EqualFold(pol.Source.ZoneName, srcZone)) &&
		matchesPolicyProtocol(pol.Protocol, pol.ProtocolNegated, "tcp") &&
		slices.ContainsFunc(gatewayAdminPorts, func(p int) bool { return endpointCanMatchPort(pol.Destination, p) })
}

// gatewayHasIPv6Context checks for IPv6 addressing on the source VLAN or
// IPv6 management policy. Multicast groups do not identify a gateway interface.
func gatewayHasIPv6Context(snap *unifi.Snapshot, srcNet unifi.Network, policies []unifi.FirewallPolicy) bool {
	if len(networkPrefixesForFamily(srcNet, "ipv6")) > 0 {
		return true
	}
	for range networkClientAddresses(srcNet, snap, "ipv6", true) {
		return true
	}
	for _, pol := range policies {
		if !gatewayAdminPolicy(pol, srcNet.ZoneName, "ipv6") {
			continue
		}
		if srcNet.ID != "" && len(pol.Source.NetworkIDs) > 0 && containsFold(pol.Source.NetworkIDs, srcNet.ID) == pol.Source.NegateTarget {
			continue
		}
		src, dst := gatewayIPv6Target(pol.Source), gatewayIPv6Target(pol.Destination)
		if src != matchNo && dst != matchNo && (src == matchYes || dst == matchYes || strings.EqualFold(pol.IPVersion, "ipv6")) {
			return true
		}
	}
	return false
}

// gatewayIPv6Target distinguishes an IPv6 selector from an endpoint that leaves
// the family unspecified. A multicast-only selector cannot match an admin socket.
func gatewayIPv6Target(ep unifi.PolicyEndpoint) triMatch {
	if ep.AnyTarget || len(ep.IPs) == 0 {
		return matchUnknown
	}
	state := unicastSelectorFamily(ep.IPs, "ipv6")
	if ep.NegateTarget && state == matchNo {
		return matchUnknown
	}
	return state
}

// unicastSelectorFamily reports whether any selector contains a unicast address
// in fam. An unparseable selector leaves the answer unknown.
func unicastSelectorFamily(selectors []string, fam string) triMatch {
	state := matchNo
	for _, sel := range selectors {
		if iv, ok := parseSelectorInterval(sel, fam); ok {
			if iv.containsUnicast() {
				return matchYes
			}
		} else if selectorFamilyTri(sel) == "" {
			state = matchUnknown
		}
	}
	return state
}

// containsUnicast reports whether a selector interval contains any address that
// could identify an interface, including one on the local link.
func (iv ipInterval) containsUnicast() bool {
	if iv.lo == iv.hi {
		return gatewayUnicast(iv.lo)
	}
	if iv.lo.Is6() {
		return !iv.lo.IsMulticast() && iv.hi.Compare(netip.IPv6Loopback()) > 0
	}
	return !(iv.lo.IsMulticast() && iv.hi.IsMulticast() || iv.lo.IsLoopback() && iv.hi.IsLoopback())
}

// gatewayUnicast accepts interface addresses, including a gateway on the local link.
func gatewayUnicast(addr netip.Addr) bool {
	return addr.IsGlobalUnicast() || addr.IsLinkLocalUnicast()
}

// allGatewayIPsForFamily collects candidate management addresses from the
// source VLAN, gateway inventory, other interfaces, and applicable admin allows.
// An empty witness preserves uncertainty when no interface address is known.
func allGatewayIPsForFamily(snap *unifi.Snapshot, gwIP, fam string, srcNet unifi.Network, policies []unifi.FirewallPolicy) []string {
	wantV6 := strings.EqualFold(fam, "ipv6")
	// A subnet-directed broadcast is never an interface, even if a rule names it.
	broadcasts := make(map[netip.Addr]bool)
	if !wantV6 {
		addBroadcast := func(n unifi.Network) {
			if p, err := netip.ParsePrefix(strings.TrimSpace(n.Subnet)); err == nil && p.Addr().Is4() && p.Bits() <= 30 {
				broadcasts[lastAddrOfPrefix(p)] = true
			}
		}
		addBroadcast(srcNet)
		if snap != nil {
			for _, n := range snap.Networks {
				addBroadcast(n)
			}
		}
	}
	seen := make(map[string]struct{})
	var out []string
	add := func(ip string) {
		addr, err := netip.ParseAddr(strings.TrimSpace(ip))
		if err != nil {
			return
		}
		addr = addr.Unmap()
		if addr.Is6() != wantV6 || !gatewayUnicast(addr) || broadcasts[addr] {
			return
		}
		s := addr.String()
		if _, dup := seen[s]; dup {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}

	// Prefer the source VLAN's interface when several gateways have the same verdict.
	addNetwork := func(n unifi.Network) {
		for ip := range gatewayInterfaceIPs(n, fam) {
			add(ip)
		}
	}
	addNetwork(srcNet)
	add(gwIP)
	if snap != nil {
		for _, n := range snap.Networks {
			addNetwork(n)
		}
	}

	srcZone := strings.TrimSpace(srcNet.ZoneName)
	for _, pol := range policies {
		if !strings.EqualFold(pol.Action, "ALLOW") || !gatewayAdminPolicy(pol, srcZone, fam) {
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

// networkPrefixesForFamily keeps every prefix that can contain the query address.
func networkPrefixesForFamily(n unifi.Network, fam string) []netip.Prefix {
	wantV6 := strings.EqualFold(fam, "ipv6")
	return slices.DeleteFunc(n.Prefixes(), func(p netip.Prefix) bool { return p.Addr().Is6() != wantV6 })
}

// ipBelongsToNetwork reports whether ip (of family fam) belongs to net. When
// configured prefixes or client attachments establish ownership, they take
// precedence over inference from the absence of competing subnets.
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
	prefixes := networkPrefixesForFamily(net, fam)
	if slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Contains(addr) }) {
		return true
	}
	if snap != nil {
		observed := false
		for _, cl := range snap.Clients {
			if clientHasIP(cl, ip) {
				if net.MatchesIdentity(cl.NetworkID, cl.NetworkName) {
					return true
				}
				observed = true
			}
		}
		if observed || len(prefixes) > 0 {
			return false
		}
		for _, other := range snap.Networks {
			if net.MatchesIdentity(other.ID, other.Name) {
				continue
			}
			if slices.ContainsFunc(networkPrefixesForFamily(other, fam), func(p netip.Prefix) bool { return p.Contains(addr) }) {
				return false
			}
		}
	}
	return len(prefixes) == 0
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
					for _, addr := range peerAddresses(cl, fam) {
						if ipBelongsToNetwork(addr, dstNet, snap, fam) {
							addIP(addr)
						}
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
	if ep.AnyTarget || ep.UnsupportedSelector != "" || (ep.NegateTarget && ep.HasCompoundTarget()) || len(ep.NetworkIDs) == 0 {
		return true
	}
	if net.ID == "" && net.Name == "" {
		// An unresolved network (for example, a zone-only placeholder or WAN
		// fallback without WAN inventory) cannot be ruled out against NetworkIDs.
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

// partitionIPIntervals splits the known address space at policy and approval
// boundaries. Observations can extend a configured prefix or establish that a
// subnet-less VLAN uses this family, allowing policy selectors to cover offline hosts.
func partitionIPIntervals(
	net unifi.Network,
	snap *unifi.Snapshot,
	fam string,
	positiveSelectors []string,
	negatedSelectors []string,
	extraPoints []netip.Addr,
) []ipInterval {
	wantV6 := strings.EqualFold(fam, "ipv6")
	var domains []ipInterval
	prefixes := networkPrefixesForFamily(net, fam)
	for _, p := range prefixes {
		domains = append(domains, ipInterval{lo: p.Masked().Addr(), hi: lastAddrOfPrefix(p)})
	}
	observed := make(map[netip.Addr]bool)
	for addr := range networkClientAddresses(net, snap, fam, false) {
		if !slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Contains(addr) }) {
			domains = append(domains, ipInterval{lo: addr, hi: addr})
			observed[addr] = true
		}
	}
	if len(prefixes) == 0 {
		hasClient := len(domains) > 0
		external := strings.EqualFold(net.ZoneName, "External")
		if !hasClient && !external {
			return nil
		}
		for _, sel := range positiveSelectors {
			if iv, ok := parseSelectorInterval(sel, fam); ok && (external || iv.containsUnicast()) &&
				(ipBelongsToNetwork(iv.lo.String(), net, snap, fam) || ipBelongsToNetwork(iv.hi.String(), net, snap, fam)) {
				domains = append(domains, iv)
			}
		}
		for _, pt := range extraPoints {
			if ipBelongsToNetwork(pt.String(), net, snap, fam) {
				domains = append(domains, ipInterval{lo: pt.Unmap(), hi: pt.Unmap()})
			}
		}
		if !hasClient {
			sample := sampleIPOutsideSelectors(net, snap, fam, slices.Concat(positiveSelectors, negatedSelectors))
			if addr, err := netip.ParseAddr(sample); err == nil {
				domains = append(domains, ipInterval{lo: addr, hi: addr})
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
		if cur.lo.Compare(last.hi) <= 0 {
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
			iv := ipInterval{lo: lo, hi: hi}
			// An attached client already establishes ownership of its own address.
			if len(prefixes) > 0 || iv.lo == iv.hi && observed[iv.lo] || ipBelongsToNetwork(representativeIPInInterval(iv, nil, preferred), net, snap, fam) {
				out = append(out, iv)
			}
		}
	}
	return out
}

// representativeIPInInterval picks a deterministic probe IP inside iv,
// preferring preferred when contained and skipping the subnet network address
// when a subsequent host address exists in iv.
func representativeIPInInterval(iv ipInterval, prefixes []netip.Prefix, preferred netip.Addr) string {
	if iv.lo == iv.hi {
		return iv.lo.String()
	}
	if preferred.IsValid() && preferred.Compare(iv.lo) >= 0 && preferred.Compare(iv.hi) <= 0 {
		return preferred.String()
	}
	if slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return iv.lo == p.Masked().Addr() }) {
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

// representativePortInInterval chooses a deterministic probe port inside iv,
// preferring common service ports (443, 80, 22, 53) when present.
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

// boundaryRule captures one candidate counterexample rule (or default
// disposition) collected during boundary analysis together with the merged
// destination port intervals unconditionally covered by strictly earlier rules
// of the opposite action so shadowed port ranges can be skipped.
type boundaryRule struct {
	allow              bool
	src                unifi.PolicyEndpoint
	dst                unifi.PolicyEndpoint
	priorUncondBlocked []portInterval
}

// peerEndpoints constrains a boundary evaluation to concrete source and
// destination clients across either routed or same-VLAN Oracle queries.
// Leaving a side empty keeps that side network-wide (for example, traffic
// behind a wireless AP or a lone wired client on a VLAN).
type peerEndpoints struct {
	// concrete pins missing client IP/MAC attributes as empty so selector
	// checks report unknown instead of expanding to whole-VLAN sampling.
	// Whole-VLAN containment leaves concrete false so omitted sides stay unconstrained.
	concrete bool
	src      unifi.Client
	dst      unifi.Client
}

// peerAddresses extracts every IP address of client c matching fam ("ipv4" or
// "ipv6"), preserving secondary IPv6 aliases alongside the primary IPv4 address.
func peerAddresses(c unifi.Client, fam string) []string {
	var out []string
	for _, raw := range c.AllIPs() {
		if ip, err := netip.ParseAddr(raw); err == nil && (fam == "ipv4") == ip.Unmap().Is4() {
			if addr := ip.Unmap().String(); !slices.Contains(out, addr) {
				out = append(out, addr)
			}
		}
	}
	return out
}

// evaluateBoundary searches the full address, port, MAC, and protocol domain
// between srcNet and dstNet for a counterexample to expected ("deny" or
// "allow"). Invoking it for both expectations distinguishes a mixed/restricted
// policy from an unconditional allow or deny while preserving exact first-match
// rule ordering.
func (o *Oracle) evaluateBoundary(
	rawFindings []checks.Finding,
	intent config.IsolationIntent,
	srcNet, dstNet unifi.Network,
	srcZone, dstZone, fam, expected string,
	peers *peerEndpoints,
) IsolationCell {
	return o.boundaryWithApproval(rawFindings, intent, srcNet, dstNet, srcZone, dstZone, fam, expected, peers, nil)
}

// builtinDNS reports whether cell was decided by UniFi's built-in
// SYSTEM_DEFINED "Allow Public DNS" policy confined strictly to port 53.
// Verifying the winning rule in o.sortedPolicies ensures a user-created or
// broader rule with the same name is never exempted.
func (o *Oracle) builtinDNS(cell IsolationCell) bool {
	if !strings.EqualFold(cell.DecisiveRuleName, "Allow Public DNS") || cell.Port != 53 || cell.PathKind != "gateway-routed" || !strings.EqualFold(cell.DestZone, "Internal") {
		return false
	}
	found := false
	for _, p := range o.sortedPolicies {
		if !p.Enabled || p.ID != cell.DecisiveRuleID || p.Name != cell.DecisiveRuleName {
			continue
		}
		if !strings.EqualFold(p.Origin, "SYSTEM_DEFINED") || !p.Destination.OnlyPort(53) {
			return false
		}
		found = true
	}
	return found
}

// boundaryWithApproval searches the full (protocol, source IP/MAC/port,
// destination IP/MAC/port) domain between srcNet and dstNet for a counterexample
// to expected ("deny" or "allow") while continuing past flows accepted by
// intent.ApprovedPaths or approve.
//
// Evaluation runs in four phases:
//  1. Fast-path baseline probes (TCP 443 and UDP 53) to catch missing telemetry,
//     unresolved zones, or blanket openings immediately.
//  2. Per-protocol rule collection over switch ACLs and gateway policies,
//     tracking unconditionally blocked port intervals so strictly later
//     shadowed rules can be pruned.
//  3. Equivalence-class partitioning of source/destination IP intervals, MACs,
//     and source/destination port intervals from all collected selectors and
//     approved endpoints.
//  4. Bounded counterexample search across the partitioned classes, returning
//     the first unapproved counterexample or IsolationUnknown if coverage hits
//     maxExactBoundaryEvals.
func (o *Oracle) boundaryWithApproval(rawFindings []checks.Finding, intent config.IsolationIntent,
	srcNet, dstNet unifi.Network, srcZone, dstZone, fam, expected string, peers *peerEndpoints, approve func(IsolationCell) bool) IsolationCell {
	var approvedCell *IsolationCell
	srcIPSample := sampleNetworkIPForFamily(srcNet, o.snap, fam)
	dstIPSample := sampleNetworkIPForFamily(dstNet, o.snap, fam)

	var fixedSrc, fixedDst []string
	var fixedSrcMAC, fixedDstMAC string
	if peers != nil {
		fixedSrc = peerAddresses(peers.src, fam)
		fixedDst = peerAddresses(peers.dst, fam)
		fixedSrcMAC, fixedDstMAC = peers.src.MAC, peers.dst.MAC
		if peers.concrete {
			if len(fixedSrc) == 0 && (peers.src.MAC != "" || peers.src.IP != "") {
				fixedSrc = []string{""}
			}
			if len(fixedDst) == 0 {
				fixedDst = []string{""}
			}
		}
		if len(fixedSrc) > 0 {
			srcIPSample = fixedSrc[0]
		}
		if len(fixedDst) > 0 {
			dstIPSample = fixedDst[0]
		}
	}
	// Exclude non-public, bogon, and local site subnets when searching the
	// External zone so internet-egress witnesses always target public space.
	var externalExclusions []string
	var excludedPrefixes []netip.Prefix
	if dstZone == "External" && (peers == nil || !peers.concrete) {
		externalExclusions = []string{
			"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
			"169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "192.0.2.0/24",
			"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32",
			"3fff::/20", "224.0.0.0/4", "240.0.0.0/4", "::/96", "::ffff:0:0/96",
			"fc00::/7", "fe80::/10", "ff00::/8",
		}
		for _, local := range o.snap.Networks {
			for _, prefix := range networkPrefixesForFamily(local, fam) {
				externalExclusions = append(externalExclusions, prefix.String())
			}
		}
		for _, raw := range externalExclusions {
			if prefix, err := netip.ParsePrefix(raw); err == nil {
				excludedPrefixes = append(excludedPrefixes, prefix)
			}
		}
		dstIPSample = "1.1.1.1"
		if fam == "ipv6" {
			dstIPSample = "2606:4700:4700::1111"
		}
	}
	baseDstIP := func(proto string, port int) string {
		if approvedIPs, _ := approvedHostIPsFor(o.snap, rawFindings, intent.ApprovedPaths, srcZone, srcNet.Name, dstNet, proto, port, fam); len(approvedIPs) > 0 {
			if outside := sampleIPOutsideSelectors(dstNet, o.snap, fam, approvedIPs); outside != "" {
				return outside
			}
		}
		return dstIPSample
	}

	type evalKey struct {
		proto   string
		port    int
		srcPort int
		srcIP   string
		srcMAC  string
		dstIP   string
		dstMAC  string
	}
	evaluated := make(map[evalKey]struct{})
	var firstCell IsolationCell
	hasFirst := false
	var unknownCell *IsolationCell

	evaluate := o.evaluateRoutedPath
	if peers != nil && peers.concrete && len(fixedSrc) != 0 {
		// A missing address on an identified client cannot stand in for the whole VLAN.
		evaluate = o.routedCell
	}
	evalOne := func(proto string, port, srcPort int, srcIP, srcMAC, dstIP, dstMAC string, allowSkipApproved bool) (IsolationCell, bool) {
		if len(externalExclusions) > 0 {
			ip, err := netip.ParseAddr(dstIP)
			if err != nil {
				return IsolationCell{}, false
			}
			for _, prefix := range excludedPrefixes {
				if prefix.Contains(ip) {
					return IsolationCell{}, false
				}
			}
		}
		k := evalKey{
			proto:   proto,
			port:    port,
			srcPort: srcPort,
			srcIP:   strings.TrimSpace(srcIP),
			srcMAC:  strings.ToLower(strings.TrimSpace(srcMAC)),
			dstIP:   strings.TrimSpace(dstIP),
			dstMAC:  strings.ToLower(strings.TrimSpace(dstMAC)),
		}
		if _, dup := evaluated[k]; dup {
			return IsolationCell{}, false
		}
		evaluated[k] = struct{}{}

		if expected == "deny" && allowSkipApproved && isTransitProbeApproved(o.snap, rawFindings, intent.ApprovedPaths, srcZone, srcNet.Name, dstNet, k.dstIP, k.proto, k.port, fam) {
			return IsolationCell{}, false
		}
		cell := evaluate(
			srcNet, dstNet,
			pathQuery{
				srcZone:    srcZone,
				srcNetID:   srcNet.ID,
				srcNetName: srcNet.Name,
				srcIP:      k.srcIP,
				srcPort:    k.srcPort,
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
			}, dstNet.Name, "trusted-lan-transit", expected,
		)
		if cell.Verdict == IsolationViolation && approve != nil && approve(cell) {
			cell.Expected, cell.Verdict = "allow", IsolationApproved
			approvedCell = &cell
			return IsolationCell{}, false
		}
		if cell.Verdict == IsolationViolation || cell.Verdict == IsolationBrokenDependency {
			if expected == "deny" && isTransitProbeApproved(o.snap, rawFindings, intent.ApprovedPaths, srcZone, srcNet.Name, dstNet, k.dstIP, k.proto, k.port, fam) {
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
	if viol, ok := evalOne("tcp", 443, 49152, srcIPSample, fixedSrcMAC, baseDstIP("tcp", 443), fixedDstMAC, false); ok {
		return viol
	}
	path := routingOwners(srcNet, dstNet, srcZone, dstZone)
	useGateway := slices.Contains(path, gatewayOwner) && o.gwPoliciesAvailable && strings.TrimSpace(srcZone) != "" && strings.TrimSpace(dstZone) != ""
	useSwitch := len(path) > 0 && path[0] != gatewayOwner && o.switchACLStatus == "complete"
	if !useGateway && !useSwitch {
		return firstCell
	}
	if viol, ok := evalOne("udp", 53, 49152, srcIPSample, fixedSrcMAC, baseDstIP("udp", 53), fixedDstMAC, true); ok {
		return viol
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
	if useSwitch {
		sortedACLs = o.sortedACLs
		for _, acl := range sortedACLs {
			if acl.Enabled && matchesIPFamily(acl.IPVersion, fam) && path.includesACL(acl.DeviceMACs) {
				addProto(acl.Protocol)
			}
		}
	}
	if useGateway {
		for _, pol := range o.sortedPolicies {
			if pol.Enabled && matchesIPFamily(pol.IPVersion, fam) {
				addProto(pol.Protocol)
			}
		}
	}

	icmp := "icmp"
	if fam == "ipv6" {
		icmp = "icmpv6"
	}
	// Pick a concrete IP protocol name outside every named rule selector to
	// represent the residual protocol class. If every candidate name already
	// appears in a rule, fall back to the unnamedProtocol sentinel; a hit on
	// that sentinel cannot name a concrete protocol and therefore degrades to
	// IsolationUnknown instead of fabricating a protocol name.
	const unnamedProtocol = "<unlisted IP protocol>"
	representative := unnamedProtocol
	for _, name := range []string{icmp, "gre", "esp", "ah", "sctp"} {
		if _, named := seenProto[name]; !named {
			representative = name
			break
		}
	}
	protos = append(protos, representative)

	srcPrefixes := networkPrefixesForFamily(srcNet, fam)
	dstPrefixes := networkPrefixesForFamily(dstNet, fam)
	prefSrc, _ := netip.ParseAddr(strings.TrimSpace(srcIPSample))
	prefSrc = prefSrc.Unmap()
	prefDst, _ := netip.ParseAddr(strings.TrimSpace(dstIPSample))
	prefDst = prefDst.Unmap()

	defaultAllows := useSwitch ||
		strings.EqualFold(strings.TrimSpace(srcZone), strings.TrimSpace(dstZone)) ||
		strings.EqualFold(strings.TrimSpace(srcZone), "internal")

	// The solver always treats allowRules/defaultAllows as counterexample
	// candidates to expected. When verifying expected == "allow", invert the
	// default polarity (and each rule's polarity in recordRuleEndpoints) so
	// deny rules and default-deny become the counterexamples searched for.
	if expected == "allow" {
		defaultAllows = !defaultAllows
	}
	incompleteCoverage := false
	totalRuleEvals := 0

	for _, pr := range protos {
		var allowRules []boundaryRule
		var srcPosSelectors, srcNegSelectors []string
		var dstPosSelectors, dstNegSelectors []string
		var srcPorts, dstPorts []int
		var srcRanges []unifi.PortRange
		var dstPortRanges []unifi.PortRange
		var pendingIntervals []portInterval
		var uncondBlockedMerged []portInterval
		// Many consecutive deny rules can precede the first allow. Merge
		// their intervals once when the ordered search actually needs them.
		mergePending := func() {
			if len(pendingIntervals) > 0 {
				uncondBlockedMerged = mergePortIntervals(append(uncondBlockedMerged, pendingIntervals...))
				pendingIntervals = pendingIntervals[:0]
			}
		}
		sawIndeterminateRule := false
		srcMACSet := make(map[string]struct{})
		dstMACSet := make(map[string]struct{})
		hasSrcMAC := false
		hasDstMAC := false

		isFullPortBlock := func(merged []portInterval) bool {
			return len(merged) == 1 && merged[0].lo == 1 && merged[0].hi == 65535
		}

		// Buffer unconditional deny intervals across policies that share the
		// same Index before merging them into uncondBlockedMerged. Equal-index
		// rules have undefined relative precedence, so a deny must never shadow
		// an allow at the same Index; both must stay visible to trigger unknown.
		var groupBlocked []portInterval
		deferBlocks := false
		flushGroupBlocked := func() {
			if len(groupBlocked) == 0 {
				return
			}
			for _, iv := range groupBlocked {
				if iv.lo == 1 && iv.hi == 65535 {
					uncondBlockedMerged = []portInterval{iv}
					pendingIntervals = pendingIntervals[:0]
					break
				}
				if !isFullPortBlock(uncondBlockedMerged) {
					pendingIntervals = append(pendingIntervals, iv)
				}
			}
			groupBlocked = groupBlocked[:0]
		}

		recordRuleEndpoints := func(allow bool, srcEP, dstEP unifi.PolicyEndpoint, indeterminate bool) {
			// Mirror the expected == "allow" polarity inversion so deny rules
			// are collected as counterexample candidates while unconditional
			// allows prune strictly later shadowed denies.
			if expected == "allow" {
				allow = !allow
			}
			if indeterminate {
				sawIndeterminateRule = true
			}
			if !endpointMatchesNetworkSelector(srcEP, srcNet) || !endpointMatchesNetworkSelector(dstEP, dstNet) {
				return
			}
			srcPorts = append(srcPorts, srcEP.Ports...)
			srcRanges = append(srcRanges, srcEP.PortRanges...)
			if indeterminate {
				allow = true
			}
			switch {
			case len(path) > 1:
				// Rules on distinct enforcers cannot shadow one another; collect
				// every selector and evaluate their joint partitions below.
			case !allow:
				// Record unconditional whole-network BLOCK port intervals so
				// strictly later shadowed ALLOW rules skip already-blocked port
				// ranges without quadratic scanning, unless an earlier rule was
				// indeterminate (scheduled/unsupported) and must stay observable.
				if !sawIndeterminateRule && (pr == "tcp" || pr == "udp" || dstEP.AnyPort) &&
					endpointUnconditionallyMatchesNetwork(srcEP, srcZone, srcNet, true) &&
					endpointUnconditionallyMatchesNetwork(dstEP, dstZone, dstNet, false) {
					if ivs, ok := endpointPortIntervals(dstEP); ok {
						if deferBlocks {
							groupBlocked = append(groupBlocked, ivs...)
						} else if isFullPortBlock(ivs) {
							uncondBlockedMerged = ivs
							pendingIntervals = pendingIntervals[:0]
						} else if !isFullPortBlock(uncondBlockedMerged) {
							pendingIntervals = append(pendingIntervals, ivs...)
						}
						return
					}
					sawIndeterminateRule = true
				}
			default:
				mergePending()
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

		for _, acl := range sortedACLs {
			if !acl.Enabled || !matchesIPFamily(acl.IPVersion, fam) || !matchesProtocol(acl.Protocol, pr) {
				continue
			}
			if !path.includesACL(acl.DeviceMACs) {
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
		if useGateway {
			// Walk gateway policies in equal-Index groups with deferBlocks so
			// unconditional denies only prune rules at strictly higher Indexes.
			deferBlocks = true
			for i := 0; i < len(o.sortedPolicies); {
				idx := o.sortedPolicies[i].Index
				j := i + 1
				for j < len(o.sortedPolicies) && o.sortedPolicies[j].Index == idx {
					j++
				}
				for k := i; k < j; k++ {
					pol := o.sortedPolicies[k]
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
				flushGroupBlocked()
				i = j
			}
			deferBlocks = false
		}

		mergePending()
		// Append a catch-all boundaryRule whenever the default disposition is
		// an unblocked counterexample, or when multiple enforcers share the path
		// (len(path) > 1) because independent enforcers cannot shadow one
		// another and their joint selector partitions must all be probed.
		if len(path) > 1 || (defaultAllows && (sawIndeterminateRule || !isFullPortBlock(uncondBlockedMerged))) {
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
		approvedIPs, approvedPorts := collectApprovedPointsFor(o.snap, rawFindings, intent.ApprovedPaths, srcZone, srcNet.Name, dstNet, pr, fam)
		dstPorts = append(dstPorts, approvedPorts...)
		for _, ar := range allowRules {
			for _, iv := range ar.priorUncondBlocked {
				dstPortRanges = append(dstPortRanges, unifi.PortRange{Start: iv.lo, End: iv.hi})
			}
		}

		srcNeg := srcNegSelectors
		if strings.EqualFold(srcZone, "External") {
			srcNeg = append(append([]string(nil), srcNegSelectors...), nonRoutableExternalCIDRs(fam)...)
		}
		srcIntervals := partitionIPIntervals(srcNet, o.snap, fam, srcPosSelectors, srcNeg, nil)
		dstIntervals := partitionIPIntervals(dstNet, o.snap, fam, append(dstPosSelectors, externalExclusions...), dstNegSelectors, approvedIPs)

		var srcReps []string
		for _, iv := range srcIntervals {
			if rep := representativeIPInInterval(iv, srcPrefixes, prefSrc); rep != "" {
				if strings.EqualFold(srcZone, "External") && isNonRoutableIP(rep) {
					continue
				}
				srcReps = append(srcReps, rep)
			}
		}
		if len(srcReps) == 0 && srcIPSample != "" {
			srcReps = []string{srcIPSample}
		}

		var dstReps []string
		for _, iv := range dstIntervals {
			if rep := representativeIPInInterval(iv, dstPrefixes, prefDst); rep != "" {
				dstReps = append(dstReps, rep)
			}
		}
		if len(dstReps) == 0 && dstIPSample != "" {
			dstReps = []string{dstIPSample}
		}

		// An empty address preserves uncertainty for any selector that could
		// match this family. Opposite-family literals can be ruled out directly.
		endpointNeedsEmptyIPProbe := func(ep unifi.PolicyEndpoint) bool {
			return ep.AnyTarget || ep.NegateTarget || !allSelectorsOppositeFamily(ep.IPs, fam)
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

		if len(fixedSrc) > 0 {
			srcReps = fixedSrc
		}
		if len(fixedDst) > 0 {
			dstReps = fixedDst
		}
		if fixedSrcMAC != "" || (peers != nil && peers.concrete && len(fixedSrc) != 0) {
			srcMACs = []string{fixedSrcMAC}
		}
		if fixedDstMAC != "" || (peers != nil && peers.concrete) {
			dstMACs = []string{fixedDstMAC}
		}
		sourcePorts := []int{0}
		if pr == "tcp" || pr == "udp" {
			sourcePorts = nil
			for _, iv := range partitionPortIntervals(srcPorts, srcRanges) {
				sourcePorts = append(sourcePorts, representativePortInInterval(iv))
			}
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
						for _, sport := range sourcePorts {
							totalRuleEvals++
							if totalRuleEvals > maxExactBoundaryEvals {
								incompleteCoverage = true
								goto nextProto
							}
							if viol, ok := evalOne(pr, p, sport, sc.ip, sc.mac, dc.ip, dc.mac, true); ok {
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
				Enforcer:      o.gwName + " (Zone Firewall)",
				EnforcerMACs:  enforcerMACs(o.gwMAC),
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
	if approvedCell != nil {
		return *approvedCell
	}
	return firstCell
}

// evaluateGatewayAdminBoundary evaluates Untrusted -> Gateway management access
// across TCP 443, 22, 80, 8443, every source IP equivalence class in srcNet,
// and all gateway interface IPs for the requested address family ("ipv4" or
// "ipv6") so narrow earlier blocks never mask neighbor sources or alternate
// gateway IPs.
func (o *Oracle) evaluateGatewayAdminBoundary(
	gwIPs []string,
	srcNet unifi.Network,
	srcZone, fam string,
) IsolationCell {
	srcIPSample := sampleNetworkIPForFamily(srcNet, o.snap, fam)

	gateway := unifi.Network{Name: "Gateway", ZoneName: "Gateway"}
	query := pathQuery{srcZone: srcZone, dstZone: gateway.ZoneName, ipFamily: fam, state: "new"}
	srcIPs, srcMACs := o.sourceRepresentatives(srcNet, gateway, query, srcIPSample)

	var firstCell IsolationCell
	var unknownCell *IsolationCell
	first := true
	evals := 0
	incomplete := false
	for _, sip := range srcIPs {
		for _, smac := range srcMACs {
			for _, gip := range gwIPs {
				for _, port := range gatewayAdminPorts {
					evals++
					if evals > maxExactBoundaryEvals {
						incomplete = true
						goto doneGW
					}
					cell := o.evaluateRoutedPath(
						srcNet, gateway,
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
						}, o.gwName, "gateway-admin", "deny",
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

// gatewayInterfaceIPs yields addresses reported on gateway-owned interfaces.
// A bare prefix describes the VLAN without identifying its router's address.
func gatewayInterfaceIPs(n unifi.Network, fam string) iter.Seq[string] {
	return func(yield func(string) bool) {
		if n.RouterDeviceMAC != "" || n.RouterUnresolved {
			return
		}
		for _, p := range networkPrefixesForFamily(n, fam) {
			if (p.Bits() == p.Addr().BitLen() || p.Addr() != p.Masked().Addr()) && !yield(p.Addr().String()) {
				return
			}
		}
	}
}

// networkClientAddresses yields observed unicast addresses on the specified VLAN.
// Link-local addresses are usable for peers and the gateway on the same link.
func networkClientAddresses(net unifi.Network, snap *unifi.Snapshot, fam string, onLink bool) iter.Seq[netip.Addr] {
	wantV6 := strings.EqualFold(fam, "ipv6")
	return func(yield func(netip.Addr) bool) {
		if snap == nil {
			return
		}
		for _, cl := range snap.Clients {
			if !net.MatchesIdentity(cl.NetworkID, cl.NetworkName) {
				continue
			}
			for _, raw := range cl.AllIPs() {
				addr, err := netip.ParseAddr(raw)
				addr = addr.Unmap()
				if err != nil || addr.Is6() != wantV6 || !(addr.IsGlobalUnicast() || onLink && addr.IsLinkLocalUnicast()) {
					continue
				}
				if !yield(addr) {
					return
				}
			}
		}
	}
}

// prefixHost preserves the reported interface address and uses the first IPv6
// host when the controller supplies a delegated network address.
func prefixHost(p netip.Prefix) netip.Addr {
	if p.Addr().Is6() && p.Bits() < 128 && p.Addr() == p.Masked().Addr() {
		return p.Addr().Next()
	}
	return p.Addr()
}

// sampleNetworkIPForFamily returns an address from the network inventory so
// policies scoped to an unknown local subnet retain an unknown verdict.
func sampleNetworkIPForFamily(net unifi.Network, snap *unifi.Snapshot, fam string) string {
	if prefixes := networkPrefixesForFamily(net, fam); len(prefixes) > 0 {
		return prefixHost(prefixes[0]).String()
	}
	for addr := range networkClientAddresses(net, snap, fam, false) {
		return addr.String()
	}
	return ""
}

// zoneHasIPv6Context reports whether any network or client in zoneLow or
// Internal carries IPv6 addressing, or any firewall policy explicitly targets IPv6.
func zoneHasIPv6Context(snap *unifi.Snapshot, zoneLow string) bool {
	if snap == nil {
		return false
	}
	for _, n := range snap.Networks {
		nz := strings.ToLower(strings.TrimSpace(n.ZoneName))
		if nz != zoneLow && nz != "internal" {
			continue
		}
		if len(networkPrefixesForFamily(n, "ipv6")) > 0 {
			return true
		}
		for range networkClientAddresses(n, snap, "ipv6", true) {
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
		if ipMatchesSelectorTri(ip, sel, "") != matchNo {
			return false
		}
	}
	return true
}

// sampleIPOutsideSelectors searches observed clients and configured prefixes
// for an address outside the exclusions. Only External can supply a fallback
// address when the controller has no address inventory for this family.
func sampleIPOutsideSelectors(net unifi.Network, snap *unifi.Snapshot, fam string, excluded []string) string {
	wantV6 := strings.EqualFold(fam, "ipv6")
	prefixes := networkPrefixesForFamily(net, fam)
	usable := func(a netip.Addr) bool {
		a = a.Unmap()
		if !a.IsGlobalUnicast() || a.Is6() != wantV6 {
			return false
		}
		if len(prefixes) > 0 && !slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Contains(a) }) {
			return false
		}
		return ipMatchesNoSelector(a.String(), excluded)
	}

	hasClient := false
	for addr := range networkClientAddresses(net, snap, fam, false) {
		hasClient = true
		if ipMatchesNoSelector(addr.String(), excluded) {
			return addr.String()
		}
	}
	if len(prefixes) == 0 && (hasClient || !strings.EqualFold(net.ZoneName, "External")) {
		return ""
	}

	// Selector boundaries can leave a narrow permitted gap inside a prefix.
	for _, sel := range excluded {
		for _, cand := range selectorBoundaryNeighbors(sel, fam) {
			if usable(cand) {
				return cand.String()
			}
		}
	}

	// Check both ends of each prefix when the exclusions lie elsewhere.
	for _, netPfx := range prefixes {
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
	}
	if len(prefixes) > 0 {
		return ""
	}

	// A subnet-less External zone still represents sources outside the selectors.
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

// sampleIPFromSelector keeps any explicit interface address in a CIDR and
// uses the lower endpoint of a valid range for gateway policy matching.
func sampleIPFromSelector(selector, fam string) string {
	s := strings.TrimSpace(selector)
	wantV6 := strings.EqualFold(fam, "ipv6")
	if pfx, err := netip.ParsePrefix(s); err == nil {
		addr := pfx.Addr().Unmap()
		if addr.Is6() == wantV6 {
			return addr.String()
		}
		return ""
	}
	if iv, ok := parseSelectorInterval(s, fam); ok {
		return iv.lo.String()
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

// ManagementControllers returns deduplicated, IP-sorted out-of-band server
// management controllers (BMCs such as IPMI, iDRAC, iLO, and Redfish consoles)
// identified from both rawFindings (oob-bmc, UB-0019, UB-0020) and snapshot
// client name/hostname patterns, hydrated against the snapshot client inventory.
func (o *Oracle) ManagementControllers(rawFindings []checks.Finding) []unifi.Client {
	bmcByKey := make(map[string]unifi.Client)
	for _, f := range rawFindings {
		if f.Category == "oob-bmc" || f.CheckID == "UB-0020" || f.CheckID == "UB-0019" {
			cl := o.inventoryClient(f.Client)
			k := firstNonEmptyStr(strings.ToLower(cl.MAC), cl.IP)
			if k != "" {
				bmcByKey[k] = cl
			}
		}
	}
	for _, cl := range o.snap.Clients {
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

// identifyPrinterClients combines printing evidence with the printers named in site policy.
func (o *Oracle) identifyPrinterClients(rawFindings []checks.Finding) []unifi.Client {
	prnByKey := make(map[string]unifi.Client)
	for _, f := range rawFindings {
		if f.Port == 631 || strings.Contains(strings.ToLower(f.Title), "ipp") || strings.Contains(strings.ToLower(f.Title), "printer") {
			cl := o.inventoryClient(f.Client)
			k := firstNonEmptyStr(strings.ToLower(cl.MAC), cl.IP)
			if k != "" {
				prnByKey[k] = cl
			}
		}
	}
	for _, ap := range o.intent.ApprovedPaths {
		if strings.Contains(strings.ToLower(ap.Function), "print") || strings.Contains(strings.ToLower(ap.DestRole), "printer") || ap.Port == 631 {
			for _, cl := range o.snap.Clients {
				if clientHasIP(cl, ap.DestIP) || strings.Contains(strings.ToLower(cl.Name+cl.Hostname), "print") {
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
