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
	"time"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/unifi"
)

// AnalyzeExtendedNetworkChecks evaluates extended network, infrastructure,
// dependency, and operational health checks from controller and owner-supplied
// telemetry while strictly preserving legitimate dependencies and avoiding
// overstatement when upstream evidence is absent.
func AnalyzeExtendedNetworkChecks(
	snap *unifi.Snapshot,
	netCfg config.NetworkConfig,
) ([]checks.Finding, []PostureNote) {
	if snap == nil {
		return nil, nil
	}
	var findings []checks.Finding
	var notes []PostureNote
	gwName, gwIP := findGatewayIdentity(snap)
	gwClient := unifi.Client{MAC: "gw:" + snap.Site, IP: gwIP, Name: gwName}

	// 1. Upstream NAT / CGNAT WAN reachability disclaimer (never overstate
	// public internet reachability behind RFC1918 / RFC6598 CGNAT WAN IPs).
	if snap.Health != nil && snap.Health.WANIP != "" {
		if addr, err := netip.ParseAddr(strings.TrimSpace(snap.Health.WANIP)); err == nil {
			if isPrivateOrCGNAT(addr) && len(snap.PortForwards) > 0 {
				notes = append(notes, PostureNote{
					Severity: checks.SeverityInfo,
					Title:    fmt.Sprintf("Gateway WAN IP (%s) is behind upstream NAT / CGNAT", snap.Health.WANIP),
					Detail:   "Local port forwards establish configured gateway translations, not guaranteed direct public internet reachability. Verify upstream ISP/router NAT or use an independent external vantage before concluding internet exposure.",
				})
			}
		}
	}

	// 2. Dynamic UPnP / NAT-PMP / PCP mapping drift (separate from merely enabling UPnP).
	now := time.Now().UTC()
	for _, dm := range snap.DynamicMappings {
		if dm.Approved {
			continue
		}
		if dm.ExpiresAt != nil && dm.ExpiresAt.Before(now) {
			continue
		}
		sev := checks.SeverityMedium
		if dm.OwnerIP != "" && dm.InternalIP != "" && dm.OwnerIP != dm.InternalIP {
			sev = checks.SeverityHigh // third-party mapping!
		}
		findings = append(findings, checks.Finding{
			CheckID:           "UB-UNIFI-DYNAMIC-NAT-MAPPING",
			Title:             fmt.Sprintf("Active %s Dynamic Mapping (%s:%d -> %s:%d)", strings.ToUpper(dm.Protocol), strings.ToUpper(dm.Transport), dm.ExtPort, dm.InternalIP, dm.IntPort),
			Category:          "nat-mapping",
			ClaimKind:         checks.ClaimConfiguredAccess,
			Property:          fmt.Sprintf("dynamic-nat-%s-%d", dm.Transport, dm.ExtPort),
			Transport:         dm.Transport,
			BaseSeverity:      sev,
			EffectiveSeverity: sev,
			Client:            unifi.Client{IP: dm.InternalIP, Name: firstNonEmptyStr(dm.InternalIP, gwName)},
			Port:              dm.IntPort,
			Evidence:          fmt.Sprintf("%s lease maps external %s/%d to %s:%d (requested_by=%s)", dm.Protocol, dm.Transport, dm.ExtPort, dm.InternalIP, dm.IntPort, firstNonEmptyStr(dm.OwnerIP, "unknown")),
			Remediation: checks.Remediation{
				Summary:      "Verify whether this dynamic port mapping is an approved console/game lease; otherwise remove the mapping and restrict UPnP/NAT-PMP segments while preserving approved consoles.",
				UniFiActions: []string{"review_dynamic_nat_mapping", "restrict_upnp_segments"},
			},
		})
	}

	// 3. Public Reverse Proxy vs Direct Unauthenticated Backend Bypass & Admin VHost Publication.
	for _, pr := range snap.ProxyRoutes {
		if pr.PublicExposed && pr.AdminVHost && pr.FrontendAuth != nil && !*pr.FrontendAuth {
			findings = append(findings, checks.Finding{
				CheckID:           "UB-UNIFI-PROXY-ADMIN-PUBLIC",
				Title:             fmt.Sprintf("Internal Admin Virtual Host Published Without Frontend Auth (%s)", pr.Hostname),
				Category:          "proxy-publication",
				ClaimKind:         checks.ClaimConfiguredAccess,
				Property:          "proxy-admin-" + pr.Hostname,
				Transport:         "tcp",
				BaseSeverity:      checks.SeverityHigh,
				EffectiveSeverity: checks.SeverityHigh,
				Client:            unifi.Client{IP: pr.BackendIP, Name: pr.Hostname},
				Port:              pr.BackendPort,
				Evidence:          fmt.Sprintf("public reverse proxy (%s) publishes admin hostname %q to %s:%d with frontend_auth=false", pr.ProxyIP, pr.Hostname, pr.BackendIP, pr.BackendPort),
				Remediation: checks.Remediation{
					Summary:      "Remove internal admin hostnames from public ingress or require strong proxy authentication, and restrict origin backend access strictly to the proxy IP.",
					UniFiActions: []string{"restrict_proxy_admin_vhost", "restrict_origin_to_proxy"},
				},
			})
		} else if pr.PublicExposed && pr.AdminVHost && pr.FrontendAuth == nil {
			notes = append(notes, PostureNote{
				Severity: checks.SeverityInfo,
				Title:    fmt.Sprintf("Frontend authentication unknown for public admin vhost %q", pr.Hostname),
				Detail:   fmt.Sprintf("Public proxy route %q -> %s:%d does not declare frontend_auth; verify proxy authentication is enforced.", pr.Hostname, pr.BackendIP, pr.BackendPort),
			})
		}
		if pr.FrontendAuth != nil && *pr.FrontendAuth && pr.BackendAuth != nil && !*pr.BackendAuth {
			notes = append(notes, PostureNote{
				Severity: checks.SeverityMedium,
				Title:    fmt.Sprintf("Authenticated proxy %q fronts unauthenticated backend %s:%d", pr.Hostname, pr.BackendIP, pr.BackendPort),
				Detail:   "Ensure firewall/host rules allow origin access only from the reverse proxy IP so LAN or guest clients cannot bypass proxy authentication directly.",
			})
		}
	}

	// 4. Outbound Publishing Tunnels (Cloudflare Tunnel / Tailscale Funnel) exposing admin endpoints.
	for _, tun := range snap.PublishedTunnels {
		if !tun.AdminEndpoint {
			continue
		}
		pol := strings.ToLower(strings.TrimSpace(tun.AccessPolicy))
		switch pol {
		case "none", "public":
			findings = append(findings, checks.Finding{
				CheckID:           "UB-UNIFI-TUNNEL-ADMIN-PUBLIC",
				Title:             fmt.Sprintf("Outbound Tunnel Publishes Internal Admin Endpoint (%s via %s)", tun.Hostname, tun.Provider),
				Category:          "tunnel-publication",
				ClaimKind:         checks.ClaimConfiguredAccess,
				Property:          "tunnel-admin-" + tun.Hostname,
				Transport:         "tcp",
				BaseSeverity:      checks.SeverityHigh,
				EffectiveSeverity: checks.SeverityHigh,
				Client:            unifi.Client{IP: tun.BackendIP, Name: tun.Hostname},
				Port:              tun.BackendPort,
				Evidence:          fmt.Sprintf("tunnel provider=%s publishes %q -> %s:%d (role=%s, access_policy=%s)", tun.Provider, tun.Hostname, tun.BackendIP, tun.BackendPort, firstNonEmptyStr(tun.BackendRole, "admin"), pol),
				Remediation: checks.Remediation{
					Summary:      "Require an explicit authenticated access policy on this outbound tunnel route or unpublish the internal admin backend.",
					UniFiActions: []string{"require_tunnel_access_policy"},
				},
			})
		case "":
			notes = append(notes, PostureNote{
				Severity: checks.SeverityInfo,
				Title:    fmt.Sprintf("Access policy unknown for published admin tunnel %q (%s)", tun.Hostname, tun.Provider),
				Detail:   fmt.Sprintf("Tunnel %q -> %s:%d omits access_policy; verify whether Zero-Trust/SSO access control is enforced upstream.", tun.Hostname, tun.BackendIP, tun.BackendPort),
			})
		}
	}

	// 5. Duplicate or Overlapping LAN Subnets (IPv4 and IPv6).
	type netPfx struct {
		net unifi.Network
		pfx netip.Prefix
	}
	var lanPfxs []netPfx
	for _, n := range snap.Networks {
		p := strings.ToLower(strings.TrimSpace(n.Purpose))
		if p == "wan" || p == "wan2" {
			continue
		}
		if n.Subnet != "" {
			if pfx, err := netip.ParsePrefix(strings.TrimSpace(n.Subnet)); err == nil {
				lanPfxs = append(lanPfxs, netPfx{net: n, pfx: pfx.Masked()})
			}
		}
		if n.IPv6Subnet != "" {
			if pfx, err := netip.ParsePrefix(strings.TrimSpace(n.IPv6Subnet)); err == nil {
				lanPfxs = append(lanPfxs, netPfx{net: n, pfx: pfx.Masked()})
			}
		}
	}
	for i := 0; i < len(lanPfxs); i++ {
		for j := i + 1; j < len(lanPfxs); j++ {
			if lanPfxs[i].net.ID != "" && lanPfxs[i].net.ID == lanPfxs[j].net.ID {
				continue
			}
			if lanPfxs[i].pfx.Overlaps(lanPfxs[j].pfx) {
				findings = append(findings, checks.Finding{
					CheckID:           "UB-UNIFI-OVERLAPPING-SUBNETS",
					Title:             fmt.Sprintf("Overlapping LAN Subnets (%s %s and %s %s)", lanPfxs[i].net.Name, lanPfxs[i].pfx, lanPfxs[j].net.Name, lanPfxs[j].pfx),
					Category:          "network-health",
					ClaimKind:         checks.ClaimConfiguredAccess,
					Property:          fmt.Sprintf("overlap-%s-%s", lanPfxs[i].net.ID, lanPfxs[j].net.ID),
					BaseSeverity:      checks.SeverityMedium,
					EffectiveSeverity: checks.SeverityMedium,
					Client:            gwClient,
					Evidence:          fmt.Sprintf("network %q (%s) overlaps network %q (%s)", lanPfxs[i].net.Name, lanPfxs[i].pfx, lanPfxs[j].net.Name, lanPfxs[j].pfx),
					Remediation: checks.Remediation{
						Summary:      "Renumber one of the overlapping LAN/VPN subnets so longest-prefix routing and firewall selectors remain unambiguous.",
						UniFiActions: []string{"renumber_overlapping_subnet"},
					},
				})
			}
		}
	}

	// 6. Native VLAN Mismatch Across Known LLDP Switch Links (requires explicit VLAN IDs).
	devByMAC := make(map[string]unifi.Device, len(snap.Devices))
	for _, d := range snap.Devices {
		devByMAC[strings.ToLower(d.MAC)] = d
	}
	for _, child := range snap.Devices {
		if child.UplinkMAC == "" || child.UplinkPort <= 0 {
			continue
		}
		parent, ok := devByMAC[strings.ToLower(child.UplinkMAC)]
		if !ok {
			continue
		}
		var parentPort *unifi.SwitchPort
		for i := range parent.Ports {
			if parent.Ports[i].PortIdx == child.UplinkPort {
				parentPort = &parent.Ports[i]
				break
			}
		}
		var childUplink *unifi.SwitchPort
		for i := range child.Ports {
			if child.Ports[i].IsUplink {
				childUplink = &child.Ports[i]
				break
			}
		}
		if parentPort != nil && childUplink != nil {
			// Prefer explicit NativeNetworkID comparison; fall back to display name
			// only when both ports report explicit non-empty names and IDs aren't missing on just one side.
			mismatch := false
			if parentPort.NativeNetworkID != "" && childUplink.NativeNetworkID != "" {
				mismatch = !strings.EqualFold(parentPort.NativeNetworkID, childUplink.NativeNetworkID)
			} else if parentPort.NativeNetworkID == "" && childUplink.NativeNetworkID == "" &&
				parentPort.NativeNetworkName != "" && childUplink.NativeNetworkName != "" {
				mismatch = !strings.EqualFold(parentPort.NativeNetworkName, childUplink.NativeNetworkName)
			}
			if mismatch {
				findings = append(findings, checks.Finding{
					CheckID:           "UB-UNIFI-NATIVE-VLAN-MISMATCH",
					Title:             fmt.Sprintf("Native VLAN Mismatch Between %s #%d and %s #%d", parent.Name, parentPort.PortIdx, child.Name, childUplink.PortIdx),
					Category:          "switching",
					ClaimKind:         checks.ClaimConfiguredAccess,
					Property:          fmt.Sprintf("native-vlan-mismatch-%s-%d", strings.ToLower(parent.MAC), parentPort.PortIdx),
					BaseSeverity:      checks.SeverityMedium,
					EffectiveSeverity: checks.SeverityMedium,
					Client:            unifi.Client{MAC: parent.MAC, IP: parent.IP, Name: parent.Name},
					Port:              parentPort.PortIdx,
					Evidence:          fmt.Sprintf("%s port %d native=%q while downstream %s uplink port %d native=%q", parent.Name, parentPort.PortIdx, firstNonEmptyStr(parentPort.NativeNetworkName, parentPort.NativeNetworkID), child.Name, childUplink.PortIdx, firstNonEmptyStr(childUplink.NativeNetworkName, childUplink.NativeNetworkID)),
					Remediation: checks.Remediation{
						Summary:      "Align the native/untagged VLAN on both ends of this trunk link after verifying switch management reachability.",
						UniFiActions: []string{"align_trunk_native_vlan"},
					},
				})
			}
		}
	}

	// 7. IPv6 Broken by Blanket ICMPv6 Blocking (respecting earlier ALLOW rules and narrow scopes).
	sortedPols := make([]unifi.FirewallPolicy, len(snap.FirewallPolicies))
	copy(sortedPols, snap.FirewallPolicies)
	sort.SliceStable(sortedPols, func(i, j int) bool {
		if sortedPols[i].Index != sortedPols[j].Index {
			return sortedPols[i].Index < sortedPols[j].Index
		}
		return i < j
	})
	for idx, pol := range sortedPols {
		if !pol.Enabled {
			continue
		}
		act := strings.ToUpper(strings.TrimSpace(pol.Action))
		if act != "BLOCK" && act != "REJECT" && act != "DROP" {
			continue
		}
		if pol.ProtocolNegated || !strings.EqualFold(pol.Protocol, "icmpv6") || !pol.Destination.AnyPort || !pol.Destination.AnyTarget || !pol.Source.AnyTarget {
			continue
		}
		// Skip if an earlier enabled ALLOW policy explicitly permits ICMPv6 on the same zone pair.
		earlierAllowsICMPv6 := false
		for k := 0; k < idx; k++ {
			prev := sortedPols[k]
			if !prev.Enabled || !strings.EqualFold(prev.Action, "ALLOW") {
				continue
			}
			if !strings.EqualFold(prev.Source.ZoneName, pol.Source.ZoneName) ||
				!strings.EqualFold(prev.Destination.ZoneName, pol.Destination.ZoneName) {
				continue
			}
			explicitICMPv6 := !prev.ProtocolNegated && strings.EqualFold(prev.Protocol, "icmpv6")
			broadAllowICMPv6 := matchesPolicyProtocol(prev.Protocol, prev.ProtocolNegated, "icmpv6") &&
				prev.Source.AnyTarget && prev.Destination.AnyTarget && prev.Destination.CoversAllPorts()
			if explicitICMPv6 || broadAllowICMPv6 {
				earlierAllowsICMPv6 = true
				break
			}
		}
		if earlierAllowsICMPv6 {
			continue
		}
		findings = append(findings, checks.Finding{
			CheckID:           "UB-UNIFI-IPV6-BLANKET-ICMPV6-BLOCK",
			Title:             fmt.Sprintf("Blanket ICMPv6 Block May Break IPv6 Path MTU / Neighbor Discovery (%s)", pol.Name),
			Category:          "network-health",
			ClaimKind:         checks.ClaimConfiguredAccess,
			Property:          "icmpv6-blanket-" + pol.ID,
			BaseSeverity:      checks.SeverityMedium,
			EffectiveSeverity: checks.SeverityMedium,
			Client:            gwClient,
			Evidence:          fmt.Sprintf("enabled policy %q blocks all ICMPv6 across %s -> %s", pol.Name, pol.Source.ZoneName, pol.Destination.ZoneName),
			Remediation: checks.Remediation{
				Summary:      "Permit essential ICMPv6 error and link-local discovery types (RFC 4890: Packet Too Big, Time Exceeded, Neighbor/Router Discovery) while keeping inbound service restrictions.",
				UniFiActions: []string{"allow_essential_icmpv6"},
			},
		})
	}

	// 8. DHCP Pool Approaching Exhaustion (>= 85% utilization with usable pool).
	for _, n := range snap.Networks {
		if n.DHCPStart == "" || n.DHCPEnd == "" || n.ActiveLeases <= 0 {
			continue
		}
		size := dhcpPoolSize(n.DHCPStart, n.DHCPEnd)
		if size > 0 && float64(n.ActiveLeases)/float64(size) >= 0.85 {
			pct := int((float64(n.ActiveLeases) / float64(size)) * 100)
			notes = append(notes, PostureNote{
				Severity: checks.SeverityMedium,
				Title:    fmt.Sprintf("DHCP pool approaching exhaustion on %s (%d/%d leases, %d%%)", n.Name, n.ActiveLeases, size, pct),
				Detail:   "Resize the DHCP range, verify reservation overlaps, or shorten lease time to accommodate guest turnover.",
			})
		}
	}

	// 9. Critical Network Configuration Backup & Restore-Test Freshness (evaluated independently).
	if b := snap.BackupStatus; b != nil {
		scopeSuffix := ""
		if strings.TrimSpace(b.Scope) != "" {
			scopeSuffix = fmt.Sprintf(" (%s)", strings.TrimSpace(b.Scope))
		}
		if !b.BackupHealthy || b.LastBackupAt == nil || now.Sub(*b.LastBackupAt) > 30*24*time.Hour {
			notes = append(notes, PostureNote{
				Severity: checks.SeverityMedium,
				Title:    fmt.Sprintf("UniFi network configuration backup is missing or stale (>30 days)%s", scopeSuffix),
				Detail:   "Enable automated UniFi console backups and store an offline copy before firmware or policy changes.",
			})
		}
		if b.LastRestoreTestAt == nil || now.Sub(*b.LastRestoreTestAt) > 180*24*time.Hour {
			notes = append(notes, PostureNote{
				Severity: checks.SeverityLow,
				Title:    fmt.Sprintf("UniFi configuration backup has not been restore-tested recently%s", scopeSuffix),
				Detail:   "A recent backup alone does not verify recoverability; periodically test restoring to a spare or offline environment.",
			})
		}
	}

	// 10. Incomplete Site Visibility Report (names exact missing telemetry feeds).
	if vis := snap.Visibility; vis != nil && len(vis.MissingFeeds) > 0 {
		missing := append([]string(nil), vis.MissingFeeds...)
		sort.Strings(missing)
		notes = append(notes, PostureNote{
			Severity: checks.SeverityInfo,
			Title:    fmt.Sprintf("Incomplete site telemetry (%d feed(s) unavailable)", len(missing)),
			Detail:   fmt.Sprintf("Unavailable feeds: %s. Paths depending on missing controller or observer telemetry are explicitly marked unknown rather than assumed compliant.", strings.Join(missing, ", ")),
		})
	}

	return findings, notes
}

func isPrivateOrCGNAT(addr netip.Addr) bool {
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return true
	}
	// RFC 6598 Shared Address Space (100.64.0.0/10) used by ISP CGNAT.
	cgnat := netip.MustParsePrefix("100.64.0.0/10")
	return cgnat.Contains(addr)
}

func dhcpPoolSize(startStr, endStr string) int {
	a, err1 := netip.ParseAddr(strings.TrimSpace(startStr))
	b, err2 := netip.ParseAddr(strings.TrimSpace(endStr))
	if err1 != nil || err2 != nil || !a.Is4() || !b.Is4() {
		return 0
	}
	ab := a.As4()
	bb := b.As4()
	start := uint32(ab[0])<<24 | uint32(ab[1])<<16 | uint32(ab[2])<<8 | uint32(ab[3])
	end := uint32(bb[0])<<24 | uint32(bb[1])<<16 | uint32(bb[2])<<8 | uint32(bb[3])
	if end < start {
		return 0
	}
	return int(end - start + 1)
}
