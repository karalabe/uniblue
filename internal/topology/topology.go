// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package topology builds a structural, vendor-agnostic network topology model
// from a UniFi Snapshot and deterministic device classifications, and renders
// it as a clean, self-contained SVG diagram without mixing in per-device CVEs.
package topology

import (
	"fmt"
	"sort"
	"strings"

	"github.com/karalabe/uniblue/internal/classify"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/unifi"
)

// Placement indicates whether a client's current VLAN/zone placement looks
// appropriate from a purely structural network-segmentation perspective.
type Placement string

const (
	// PlacementOK marks devices whose current zone/VLAN placement is structurally sound.
	PlacementOK Placement = "ok"

	// PlacementReview marks devices whose placement warrants operator review
	// (e.g., out-of-band BMC, WAN-exposed proxy in Internal, or cameras on main LAN).
	PlacementReview Placement = "review"

	// PlacementIsolate marks embedded/IoT/AV appliances sitting on an Internal
	// network that are strong candidates for an isolated VLAN.
	PlacementIsolate Placement = "isolate"
)

// Model is the complete, deterministic network topology representation rendered
// by RenderSVG or exported as JSON by `uniblue topology`.
type Model struct {
	// Site is the UniFi site identifier.
	Site string `json:"site"`

	// ControllerType records how UniBlue connected ("integration-v1", "unifi-os", "classic").
	ControllerType string `json:"controller_type"`

	// Gateway holds the primary UniFi router/gateway device, if present.
	Gateway *InfraNode `json:"gateway,omitempty"`

	// Infra lists all non-gateway UniFi switches and access points.
	Infra []InfraNode `json:"infra,omitempty"`

	// WANRoutes summarizes active inbound WAN port forwards, VPN listeners, and
	// user-defined WAN firewall ALLOW policies.
	WANRoutes []WANRoute `json:"wan_routes,omitempty"`

	// Zones lists all UniFi firewall zones observed on the console (with network counts).
	Zones []ZoneSummary `json:"zones,omitempty"`

	// VLANs holds every configured LAN/VLAN grouped and sorted by firewall zone
	// (Internal networks first, followed by isolated/Hotspot/DMZ networks).
	VLANs []VLANGroup `json:"vlans"`

	// HasUnusedDMZ reports whether UniFi defines an empty DMZ zone while an
	// Internal host receives public WAN HTTP/HTTPS traffic.
	HasUnusedDMZ bool `json:"has_unused_dmz,omitempty"`

	// ClientCount is the total number of active LAN clients across all VLANs.
	ClientCount int `json:"client_count"`

	// DeviceCount is the total number of UniFi infrastructure devices.
	DeviceCount int `json:"device_count"`
}

// InfraNode summarizes a single UniFi gateway, switch, or access point along
// with its physical LLDP uplink.
type InfraNode struct {
	// Name is the friendly UniFi device name.
	Name string `json:"name"`

	// Model is the UniFi hardware model code.
	Model string `json:"model"`

	// IP is the management IP address.
	IP string `json:"ip"`

	// Version is the installed firmware version.
	Version string `json:"version"`

	// Uplink describes the parent device and port (e.g., "USW 24 PoE (port 12)").
	Uplink string `json:"uplink,omitempty"`

	// IsGateway marks the primary router/gateway device.
	IsGateway bool `json:"is_gateway,omitempty"`
}

// WANRoute describes one active inbound WAN path configured on the gateway.
type WANRoute struct {
	// Kind classifies the route ("port-forward", "vpn", or "firewall-policy").
	Kind string `json:"kind"`

	// Label is a concise, single-line route description.
	Label string `json:"label"`

	// Review highlights broad/unrestricted WAN rules visually.
	Review bool `json:"review,omitempty"`
}

// ZoneSummary records a firewall zone name and how many VLANs belong to it.
type ZoneSummary struct {
	// Name is the UniFi firewall zone name (e.g., "Internal", "Hotspot", "Dmz").
	Name string `json:"name"`

	// NetworkCount is the number of networks assigned to this zone.
	NetworkCount int `json:"network_count"`

	// Isolated reports whether this zone blocks initiating traffic to Internal.
	Isolated bool `json:"isolated,omitempty"`
}

// VLANGroup represents one LAN/VLAN column in the topology diagram.
type VLANGroup struct {
	// Name is the user-configured UniFi network name.
	Name string `json:"name"`

	// VLAN is the numeric 802.1Q VLAN tag.
	VLAN string `json:"vlan,omitempty"`

	// Subnet is the gateway CIDR range (e.g., "10.0.0.1/16").
	Subnet string `json:"subnet,omitempty"`

	// Purpose is UniFi's network purpose ("corporate", "guest", etc.).
	Purpose string `json:"purpose,omitempty"`

	// ZoneName is the resolved firewall zone name (or "Internal"/"Isolated" fallback).
	ZoneName string `json:"zone_name"`

	// Isolated reports whether UniFi structurally isolates this network from Internal.
	Isolated bool `json:"isolated"`

	// Clients lists all active hosts on this VLAN, sorted by placement and IP.
	Clients []ClientNode `json:"clients,omitempty"`
}

// ClientNode represents a single classified LAN endpoint within a VLANGroup.
type ClientNode struct {
	// Name is the display name of the client.
	Name string `json:"name"`

	// IP is the client's IPv4 address.
	IP string `json:"ip"`

	// MAC is the normalized hardware address.
	MAC string `json:"mac"`

	// Link describes how the host attaches (e.g., "Wired · port 23" or "Wi-Fi").
	Link string `json:"link"`

	// Class holds the deterministic device classification and resolved vendor.
	Class classify.Result `json:"class"`

	// Placement is the structural placement verdict ("ok", "review", or "isolate").
	Placement Placement `json:"placement"`

	// PlacementReason explains why Placement is "review" or "isolate", if applicable.
	PlacementReason string `json:"placement_reason,omitempty"`
}

// Build constructs a deterministic topology Model from a UniFi Snapshot,
// per-client deterministic classifications, and optional explicit VLAN overrides.
func Build(snap *unifi.Snapshot, classes map[string]classify.Result, netCfg config.NetworkConfig) *Model {
	m := &Model{
		Site:           snap.Site,
		ControllerType: snap.ControllerType,
		ClientCount:    len(snap.Clients),
		DeviceCount:    len(snap.Devices),
	}

	// 1. Separate the UniFi gateway from switches and access points.
	devNameByMAC := make(map[string]string, len(snap.Devices))
	for _, d := range snap.Devices {
		if d.MAC != "" {
			devNameByMAC[strings.ToLower(d.MAC)] = d.Name
		}
		node := InfraNode{
			Name:      d.Name,
			Model:     d.Model,
			IP:        d.IP,
			Version:   d.Version,
			IsGateway: isGatewayDevice(d),
		}
		if d.UplinkName != "" {
			if d.UplinkPort > 0 {
				node.Uplink = fmt.Sprintf("%s (port %d)", d.UplinkName, d.UplinkPort)
			} else {
				node.Uplink = d.UplinkName
			}
		}
		if node.IsGateway && m.Gateway == nil {
			cp := node
			m.Gateway = &cp
		} else {
			m.Infra = append(m.Infra, node)
		}
	}
	sort.Slice(m.Infra, func(i, j int) bool {
		// Group switches ahead of APs, then alphabetically by name.
		swI := strings.Contains(strings.ToLower(m.Infra[i].Model), "usw") || strings.Contains(strings.ToLower(m.Infra[i].Model), "switch")
		swJ := strings.Contains(strings.ToLower(m.Infra[j].Model), "usw") || strings.Contains(strings.ToLower(m.Infra[j].Model), "switch")
		if swI != swJ {
			return swI
		}
		return m.Infra[i].Name < m.Infra[j].Name
	})

	// 2. Summarize active inbound WAN routes (port forwards, VPN, user WAN policies).
	m.WANRoutes = buildWANRoutes(snap)

	// 3. Determine structurally isolated zones and networks without relying on VLAN names.
	isoZones := structuralIsolatedZones(snap)
	explicitTrusted := toLowerSet(netCfg.TrustedVLANs)
	explicitIsolated := toLowerSet(netCfg.IsolatedVLANs)

	hasDMZZone := false
	for _, z := range snap.Zones {
		zl := strings.ToLower(strings.TrimSpace(z.Name))
		if zl == "dmz" {
			hasDMZZone = true
		}
		m.Zones = append(m.Zones, ZoneSummary{
			Name:         z.Name,
			NetworkCount: len(z.NetworkIDs),
			Isolated:     isoZones[zl],
		})
	}
	sort.Slice(m.Zones, func(i, j int) bool {
		return zoneSortOrder(m.Zones[i].Name) < zoneSortOrder(m.Zones[j].Name)
	})

	// 4. Build VLAN groups for all LAN networks (skipping WAN/VPN entries).
	vlanIdxByKey := make(map[string]int)
	hasIsolatedVLAN := false
	hasDMZVLAN := false
	for _, n := range snap.Networks {
		pLower := strings.ToLower(strings.TrimSpace(n.Purpose))
		zLower := strings.ToLower(strings.TrimSpace(n.ZoneName))
		if pLower == "wan" || pLower == "remote-user-vpn" ||
			zLower == "external" || zLower == "vpn" || zLower == "gateway" {
			continue
		}

		iso := isNetworkIsolated(n, isoZones, explicitTrusted, explicitIsolated)
		zoneName := n.ZoneName
		if zoneName == "" {
			if iso {
				zoneName = "Isolated"
			} else {
				zoneName = "Internal"
			}
		}
		if iso {
			hasIsolatedVLAN = true
		}
		if strings.EqualFold(zoneName, "dmz") {
			hasDMZVLAN = true
		}

		g := VLANGroup{
			Name:     n.Name,
			VLAN:     n.VLAN,
			Subnet:   n.Subnet,
			Purpose:  n.Purpose,
			ZoneName: zoneName,
			Isolated: iso,
		}
		vlanIdxByKey[strings.ToLower(strings.TrimSpace(n.Name))] = len(m.VLANs)
		if n.ID != "" {
			vlanIdxByKey[n.ID] = len(m.VLANs)
		}
		m.VLANs = append(m.VLANs, g)
	}

	// Track which internal IPs receive public WAN HTTP/HTTPS forwards.
	wanWebIPs := make(map[string]bool)
	for _, pf := range snap.PortForwards {
		if pf.Enabled && pf.FwdIP != "" && (pf.ExposesPort(80) || pf.ExposesPort(443)) {
			wanWebIPs[pf.FwdIP] = true
		}
	}

	// 5. Place every active client into its VLAN group and evaluate structural placement.
	wanProxyInInternal := false
	for _, cl := range snap.Clients {
		idx := -1
		if cl.NetworkID != "" {
			if i, ok := vlanIdxByKey[cl.NetworkID]; ok {
				idx = i
			}
		}
		if idx < 0 && cl.NetworkName != "" {
			if i, ok := vlanIdxByKey[strings.ToLower(strings.TrimSpace(cl.NetworkName))]; ok {
				idx = i
			}
		}
		if idx < 0 {
			// Fallback bucket if a client's network wasn't returned by the controller.
			name := cl.NetworkName
			if name == "" {
				name = "Unassigned"
			}
			idx = len(m.VLANs)
			vlanIdxByKey[strings.ToLower(name)] = idx
			m.VLANs = append(m.VLANs, VLANGroup{Name: name, ZoneName: "Internal"})
		}

		key := cl.IP
		if key == "" {
			key = cl.MAC
		}
		cls := classes[key]
		if cls.Category == "" {
			cls.Category = classify.CategoryUnknown
		}

		vg := &m.VLANs[idx]
		placement, reason := evaluatePlacement(cl, cls, vg.Isolated, hasIsolatedVLAN, hasDMZZone, wanWebIPs[cl.IP])
		if !vg.Isolated && wanWebIPs[cl.IP] {
			wanProxyInInternal = true
		}

		vg.Clients = append(vg.Clients, ClientNode{
			Name:            cl.DisplayName(),
			IP:              cl.IP,
			MAC:             cl.MAC,
			Link:            formatClientLink(cl, devNameByMAC),
			Class:           cls,
			Placement:       placement,
			PlacementReason: reason,
		})
	}

	m.HasUnusedDMZ = hasDMZZone && !hasDMZVLAN && wanProxyInInternal

	// Sort VLANs: Internal/non-isolated first (sorted by VLAN ID/name), then Isolated.
	sort.Slice(m.VLANs, func(i, j int) bool {
		if m.VLANs[i].Isolated != m.VLANs[j].Isolated {
			return !m.VLANs[i].Isolated
		}
		if m.VLANs[i].VLAN != m.VLANs[j].VLAN {
			return compareNumericString(m.VLANs[i].VLAN, m.VLANs[j].VLAN) < 0
		}
		return m.VLANs[i].Name < m.VLANs[j].Name
	})

	// Sort clients inside each VLAN: OK -> Review -> Isolate, then category, then IP.
	for i := range m.VLANs {
		sort.Slice(m.VLANs[i].Clients, func(a, b int) bool {
			ca, cb := m.VLANs[i].Clients[a], m.VLANs[i].Clients[b]
			if placementOrder(ca.Placement) != placementOrder(cb.Placement) {
				return placementOrder(ca.Placement) < placementOrder(cb.Placement)
			}
			if ca.Class.Category != cb.Class.Category {
				return ca.Class.Category < cb.Class.Category
			}
			return ca.IP < cb.IP
		})
	}

	return m
}

// evaluatePlacement assesses whether a client's current network placement is
// structurally sound using only generic category, zone-isolation, and WAN-route
// facts (never per-device CVEs or personal VLAN names).
func evaluatePlacement(cl unifi.Client, cls classify.Result, inIsolated, hasIsolatedVLAN, hasDMZZone, isWANWeb bool) (Placement, string) {
	if inIsolated {
		return PlacementOK, ""
	}

	// WAN-facing reverse proxy sitting inside the Internal zone.
	if isWANWeb {
		if hasDMZZone {
			return PlacementReview, "WAN web entrypoint in Internal zone (consider DMZ)"
		}
		return PlacementReview, "WAN web entrypoint in Internal zone"
	}

	switch cls.Category {
	case classify.CategoryBMC:
		return PlacementReview, "Out-of-band BMC/IPMI — restrict to admin/management access"

	case classify.CategoryCamera:
		return PlacementReview, "Camera/doorbell on Internal LAN — consider dedicated or isolated VLAN"

	case classify.CategoryIoT:
		// Smart-home hubs (e.g., Home Assistant) often orchestrate across VLANs
		// and legitimately stay on Internal with rules into isolated VLANs.
		if strings.Contains(strings.ToLower(cls.Role), "hub") {
			return PlacementOK, ""
		}
		if hasIsolatedVLAN {
			return PlacementIsolate, "Embedded/IoT appliance on Internal — consider isolated VLAN"
		}
		return PlacementReview, "Embedded/IoT appliance on flat Internal LAN"

	case classify.CategoryMedia:
		if hasIsolatedVLAN {
			return PlacementIsolate, "AV/media appliance on Internal — consider isolated VLAN"
		}
		return PlacementReview, "AV/media appliance on flat Internal LAN"

	case classify.CategoryPrinter:
		if strings.Contains(strings.ToLower(cls.Role), "3d") {
			if hasIsolatedVLAN {
				return PlacementIsolate, "3D printer appliance on Internal — consider isolated VLAN"
			}
			return PlacementReview, "3D printer appliance on flat Internal LAN"
		}
		return PlacementOK, ""
	}

	return PlacementOK, ""
}

// buildWANRoutes extracts concise, operator-readable WAN ingress summaries from
// enabled port forwards, WireGuard/VPN rules, and user-defined External ALLOW policies.
func buildWANRoutes(snap *unifi.Snapshot) []WANRoute {
	var routes []WANRoute
	for _, pol := range snap.FirewallPolicies {
		if !pol.Enabled || !strings.EqualFold(pol.Action, "ALLOW") {
			continue
		}
		if !strings.EqualFold(pol.Source.ZoneName, "external") {
			continue
		}
		if strings.EqualFold(pol.Origin, "SYSTEM_DEFINED") {
			if strings.Contains(strings.ToLower(pol.Name), "wireguard") || strings.Contains(strings.ToLower(pol.Name), "vpn") {
				routes = append(routes, WANRoute{
					Kind:  "vpn",
					Label: fmt.Sprintf("%s -> %s", pol.Name, pol.Destination.ZoneName),
				})
			}
			continue
		}
		routes = append(routes, WANRoute{
			Kind:   "firewall-policy",
			Label:  fmt.Sprintf("Policy %q: External -> %s (%s)", pol.Name, pol.Destination.ZoneName, pol.Protocol),
			Review: true,
		})
	}

	// Group port forwards by target IP so multiple ports on the same host render cleanly.
	type fwdGroup struct {
		ip    string
		ports []string
		isWeb bool
	}
	byIP := make(map[string]*fwdGroup)
	var ips []string
	for _, pf := range snap.PortForwards {
		if !pf.Enabled || pf.FwdIP == "" {
			continue
		}
		g, ok := byIP[pf.FwdIP]
		if !ok {
			g = &fwdGroup{ip: pf.FwdIP}
			byIP[pf.FwdIP] = g
			ips = append(ips, pf.FwdIP)
		}
		g.ports = append(g.ports, pf.DstPort)
		if pf.ExposesPort(80) || pf.ExposesPort(443) {
			g.isWeb = true
		}
	}
	sort.Strings(ips)
	for _, ip := range ips {
		g := byIP[ip]
		sort.Strings(g.ports)
		routes = append(routes, WANRoute{
			Kind:   "port-forward",
			Label:  fmt.Sprintf("Ports %s -> %s", strings.Join(g.ports, ", "), g.ip),
			Review: g.isWeb,
		})
	}
	return routes
}

// structuralIsolatedZones mirrors internal/risk's structural zone isolation check.
func structuralIsolatedZones(snap *unifi.Snapshot) map[string]bool {
	zones := map[string]bool{"hotspot": true, "dmz": true}
	for _, pol := range snap.FirewallPolicies {
		if !pol.Enabled || (pol.Action != "BLOCK" && pol.Action != "REJECT") {
			continue
		}
		src := strings.ToLower(strings.TrimSpace(pol.Source.ZoneName))
		dst := strings.ToLower(strings.TrimSpace(pol.Destination.ZoneName))
		if src != "" && src != "internal" && src != "external" && src != "gateway" && dst == "internal" && pol.Destination.AnyTarget && pol.Destination.AnyPort {
			zones[src] = true
		}
	}
	return zones
}

// isNetworkIsolated determines whether n is structurally isolated from Internal.
func isNetworkIsolated(n unifi.Network, isoZones map[string]bool, explicitTrusted, explicitIsolated map[string]struct{}) bool {
	nameLower := strings.ToLower(strings.TrimSpace(n.Name))
	vlanLower := strings.ToLower(strings.TrimSpace(n.VLAN))
	if _, ok := explicitTrusted[nameLower]; ok {
		return false
	}
	if _, ok := explicitTrusted[vlanLower]; ok {
		return false
	}
	if _, ok := explicitIsolated[nameLower]; ok {
		return true
	}
	if _, ok := explicitIsolated[vlanLower]; ok {
		return true
	}
	return n.IsolationEnabled ||
		strings.EqualFold(n.Purpose, "guest") ||
		isoZones[strings.ToLower(strings.TrimSpace(n.ZoneName))]
}

// isGatewayDevice reports whether a UniFi infrastructure device is a gateway/router.
func isGatewayDevice(d unifi.Device) bool {
	m := strings.ToLower(d.Model)
	return strings.Contains(m, "udm") || strings.Contains(m, "ucg") ||
		strings.Contains(m, "uxg") || strings.Contains(m, "usg") ||
		strings.Contains(m, "efg") || strings.EqualFold(d.Type, "udm") ||
		strings.EqualFold(d.Type, "ugw")
}

// formatClientLink creates a compact physical/wireless attachment label.
func formatClientLink(cl unifi.Client, devNameByMAC map[string]string) string {
	if cl.IsWired {
		if cl.SwitchPort > 0 {
			if sw := devNameByMAC[cl.SwitchMAC]; sw != "" {
				return fmt.Sprintf("Port %d (%s)", cl.SwitchPort, sw)
			}
			return fmt.Sprintf("Wired · port %d", cl.SwitchPort)
		}
		return "Wired"
	}
	if cl.ESSID != "" {
		return "Wi-Fi · " + cl.ESSID
	}
	return "Wi-Fi"
}

func placementOrder(p Placement) int {
	switch p {
	case PlacementOK:
		return 0
	case PlacementReview:
		return 1
	case PlacementIsolate:
		return 2
	default:
		return 3
	}
}

func zoneSortOrder(name string) int {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "internal":
		return 0
	case "hotspot":
		return 1
	case "dmz":
		return 2
	case "vpn":
		return 3
	case "external":
		return 4
	case "gateway":
		return 5
	default:
		return 10
	}
}

func compareNumericString(a, b string) int {
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

func toLowerSet(items []string) map[string]struct{} {
	set := make(map[string]struct{}, len(items))
	for _, s := range items {
		if norm := strings.ToLower(strings.TrimSpace(s)); norm != "" {
			set[norm] = struct{}{}
		}
	}
	return set
}
