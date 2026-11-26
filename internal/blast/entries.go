// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package blast

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/karalabe/uniblue/internal/classify"
	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/risk"
	"github.com/karalabe/uniblue/internal/unifi"
)

// position interns a concrete network attachment used for Oracle reachability queries.
func (b *builder) position(p risk.Position) fact {
	if f, ok := b.positions[p]; ok {
		return f
	}
	f := fact{position, "", strconv.Itoa(len(b.positions))}
	b.positions[p] = f
	return f
}

func appliance(c classify.Category) bool {
	switch c {
	case classify.CategoryIoT, classify.CategoryCamera, classify.CategoryPrinter, classify.CategoryMedia:
		return true
	}
	return false
}

func namesNetwork(names []string, n unifi.Network) bool {
	return slices.ContainsFunc(names, func(s string) bool { return s != "" && (strings.EqualFold(s, n.Name) || s == n.ID || s == n.VLAN) })
}

// entries seeds assumed compromises on guest and appliance clients, adds a VLAN
// entry point for empty guest/IoT/camera networks, and adds open/guest Wi-Fi
// and outdoor physical port entry points.
func (b *builder) entries() {
	roles := map[string]string{}
	if b.Isolation != nil {
		for _, c := range b.Isolation.Containment {
			n := b.network(c.NetworkID, c.NetworkName)
			roles[networkKey(n)] = c.Archetype
		}
	}
	policy := b.NetCfg.IsolationPolicy
	for _, n := range b.Snapshot.Networks {
		k := networkKey(n)
		switch {
		case namesNetwork(policy.GuestVLANs, n) || strings.EqualFold(n.Purpose, "guest") || strings.EqualFold(n.Name, "guest"):
			roles[k] = "guest"
		case namesNetwork(policy.IoTVLANs, n) || strings.EqualFold(n.Name, "iot"):
			roles[k] = "iot"
		case namesNetwork(policy.CameraVLANs, n):
			roles[k] = "camera"
		}
	}
	occupied := map[string]bool{}
	byHost := map[string][]probe.OutboundDependency{}
	for _, p := range b.Profiles {
		h := hostKey(p.Client)
		byHost[h] = append(byHost[h], p.OutboundDependencies...)
	}
	b.cloud = make([]ClientEgress, 0)
	cloud := map[string][]ClientEgress{}
	siteClients := map[string]bool{}
	for _, cl := range b.Snapshot.Clients {
		siteClients[hostKey(cl)] = true
	}
	guestSSID := map[string]bool{}
	for _, w := range b.Snapshot.WLANs {
		if w.Enabled && w.IsGuest {
			guestSSID[w.Name] = true
		}
	}
	compromised := map[string]bool{}
	for _, a := range b.clients {
		cl := a.client
		n := b.network(cl.NetworkID, cl.NetworkName)
		k := networkKey(n)
		role := roles[k]
		isAppliance := appliance(b.roles[a.host].Category) || role == "camera" || role == "iot"
		if role == "guest" || isAppliance || guestSSID[cl.ESSID] || namesNetwork(b.NetCfg.IsolatedVLANs, n) {
			occupied[k] = true
			compromised[a.host] = true
		}
		if siteClients[a.host] || isAppliance || observedVendor(byHost[a.host]) {
			cloud[a.host] = append(cloud[a.host], b.egress(a, byHost[a.host], isAppliance))
		}
	}
	// A compromised device can originate traffic from every interface it owns.
	for _, a := range b.clients {
		if compromised[a.host] {
			b.link(root(AssumeBreach), b.position(risk.PositionForClient(a.client)), trivial, 0, 0)
			owner := fact{consequence, a.host, "control"}
			if i, ok := b.ids[owner]; ok && len(b.edges[i]) > 0 {
				b.link(root(AssumeBreach), owner, trivial, 0, 0)
			}
		}
	}
	for _, h := range sortedKeys(cloud) {
		// Local-only requires every attachment of the client to be blocked.
		assessments := cloud[h]
		best := assessments[0]
		for _, e := range assessments[1:] {
			if cloudOrder(e.State) > cloudOrder(best.State) {
				best = e
			}
		}
		b.cloud = append(b.cloud, best)
	}
	for _, n := range b.Snapshot.Networks {
		k := networkKey(n)
		role := roles[k]
		if !occupied[k] && (role == "iot" || role == "guest" || role == "camera") {
			b.link(root(AssumeBreach), b.position(risk.Position{NetworkID: n.ID, NetworkName: n.Name}), trivial, 0, 0)
		}
	}
	for _, w := range b.Snapshot.WLANs {
		if !w.Enabled || (!w.IsGuest && !strings.EqualFold(w.Security, "open")) {
			continue
		}
		n := b.network(w.NetworkID, w.NetworkName)
		// A wireless entrant can associate on any AP serving the SSID.
		aps := map[string]bool{}
		for _, a := range b.clients {
			if a.client.ESSID == w.Name && a.client.APMAC != "" {
				aps[a.client.APMAC] = true
			}
		}
		if len(aps) == 0 {
			aps[""] = true
		}
		for ap := range aps {
			b.link(root(WiFi), b.position(risk.Position{NetworkID: n.ID, NetworkName: n.Name, SSID: w.Name, APMAC: ap}), trivial, 0, 0)
		}
	}
	b.outdoor()
}

const (
	localOnly      = "local-only (policy)"
	cloudCapable   = "cloud-capable (unverified)"
	cloudConnected = "cloud-connected (observed)"
)

func cloudOrder(s string) int {
	switch s {
	case cloudConnected:
		return 4
	case cloudCapable:
		return 3
	case "internet access allowed (policy)":
		return 2
	case "unknown":
		return 1
	default:
		return 0
	}
}

// observedVendor reports whether outbound evidence directly attributes traffic
// to a vendor service rather than a static config, shared CDN, or opaque TLS.
func observedVendor(deps []probe.OutboundDependency) bool {
	for _, d := range deps {
		switch d.Category {
		case "vendor-control", "firmware-updates", "cloud-hub-relay":
		default:
			continue
		}
		switch d.AttributionLevel {
		case probe.AttributionConfiguredEgress, probe.AttributionHostingRangeOnly, probe.AttributionOpaqueEncrypted, probe.AttributionVendorFeed:
			continue
		}
		switch strings.ToLower(d.Source) {
		case "device-config", "owner-config", "owner-manifest", "vendor-feed":
			continue
		}
		return true
	}
	return false
}

// egress evaluates outbound internet reachability for one client attachment.
// Observed vendor traffic takes precedence over firewall policy alone.
func (b *builder) egress(a attachment, deps []probe.OutboundDependency, isAppliance bool) ClientEgress {
	e := ClientEgress{Asset: a.host, Name: b.assets[a.host].name, State: localOnly, Reason: "Firewall policy blocks outbound internet access on every address family checked."}
	allowed, missing := false, false
	for _, fam := range b.Oracle.Families(a.client) {
		c := b.Oracle.InternetEgress(a.client, fam)
		switch c.Effective {
		case "allow":
			allowed = true
		case "deny":
		default:
			missing = true
		}
	}
	switch {
	case observedVendor(deps):
		e.State = cloudConnected
		e.Reason = "Traffic records show an outbound connection to a vendor cloud service."
	case allowed && isAppliance:
		e.State = cloudCapable
		e.Reason = "This device can reach the internet; vendor cloud traffic has not been observed yet."
	case allowed:
		e.State = "internet access allowed (policy)"
		e.Reason = "Firewall policy allows outbound internet connections from this device."
	case missing:
		e.State = "unknown"
		e.Reason = "Not enough firewall or address data to confirm whether this device can reach the internet."
	}
	n := b.network(a.client.NetworkID, a.client.NetworkName)
	netName := cmp.Or(n.Name, "this network")
	if allowed && (isAppliance || e.State == cloudConnected) {
		id := b.action("act:vlan-egress:"+networkKey(n)+"->internet", "Limit internet access from "+netName, "Blocking outbound internet traffic stops these devices from contacting external servers. Confirm they do not need cloud access or updates first.", LaneReduceExposure, 2)
		b.link(root(CloudEgress), fact{consequence, a.host, "internet access"}, low, id, 0)
		for _, ap := range b.NetCfg.IsolationPolicy.ApprovedPaths {
			if (strings.EqualFold(ap.DestZone, "External") || strings.EqualFold(ap.DestZone, "Internet")) && (strings.EqualFold(ap.SourceZone, n.Name) || strings.EqualFold(ap.SourceZone, n.ZoneName)) {
				b.approved(id, ap.Name)
			}
		}
	}
	if !allowed && missing {
		b.verify(root(CloudEgress), "egress", cmp.Or(networkKey(n), a.host), "Check outbound internet rules for "+netName, "Not enough firewall or address data was available to verify whether devices on "+netName+" can reach the internet.")
	}
	return e
}

// outdoor models untagged and tagged VLAN access on outdoor sockets separately
// so removing trunk tags never earns credit for blocking native-VLAN traffic.
func (b *builder) outdoor() {
	raw := map[string]unifi.SwitchPort{}
	ref := func(mac string, port int) string { return fmt.Sprintf("%s:%d", canonicalMAC(mac), port) }
	for _, d := range b.Snapshot.Devices {
		for _, p := range d.Ports {
			raw[ref(d.MAC, p.PortIdx)] = p
		}
	}
	for _, sw := range b.SwitchPorts {
		for _, p := range sw.Ports {
			if (p.Zone != "external" && p.Zone != "external_uplink") || p.State == "disabled" || (!p.Enabled && p.State == "") {
				continue
			}
			key := ref(sw.MAC, p.PortIdx)
			sp := raw[key]
			name := fmt.Sprintf("port %d on %s", p.PortIdx, cmp.Or(sw.Name, sw.MAC))
			reason := "Anyone who can unplug or tap this outdoor cable can reach the networks assigned to this port."
			if !p.PortSecurityUnknown && (p.PortSecurity || len(p.PortSecurityMACs) > 0) {
				reason += " MAC pinning is only a speed bump because the camera's MAC address can be copied."
			}
			secure := b.action("act:port-ext:"+key, "Secure outdoor "+name, reason, LaneReduceExposure, 3)
			native := b.network(sp.NativeNetworkID, cmp.Or(p.NativeVLAN, sp.NativeNetworkName))
			if native.Name == "" || sp.IsolationUnknown {
				b.unknownPhysical = true
				b.verify(root(Physical), "port-profile", key, "Check the switch port profile for "+name, "The controller did not report which networks are assigned to this socket.")
			}
			unresolved := func(id string) bool { return b.network(id, "").Name == "" }
			missingMembers := slices.ContainsFunc(sp.TaggedNetworkIDs, unresolved) || slices.ContainsFunc(sp.ExcludedNetworkIDs, unresolved)
			customUnknown := sp.TaggedVLANUnknown || p.TaggedPolicy == "unknown" || missingMembers || (p.TaggedPolicy == "custom" && sp.TaggedNetworkIDs == nil && sp.ExcludedNetworkIDs == nil)
			if customUnknown {
				b.unknownPhysical = true
				b.verify(root(Physical), "tagged-vlans", key, "Check allowed VLANs on "+name, "The controller did not report the complete set of tagged VLANs on this port.")
			}
			for _, n := range b.Snapshot.Networks {
				if strings.EqualFold(n.ZoneName, "External") || strings.HasPrefix(strings.ToLower(n.Purpose), "wan") {
					continue
				}
				isNative := native.Name != "" && networkKey(n) == networkKey(native)
				tag := 0
				level := trivial
				if sp.IsolationUnknown {
					level = unknown
				}
				if !isNative {
					if p.TaggedPolicy != "all" && p.TaggedPolicy != "custom" && p.TaggedPolicy != "unknown" {
						continue
					}
					if p.TaggedPolicy == "custom" && (slices.Contains(sp.ExcludedNetworkIDs, n.ID) || (!missingMembers && sp.TaggedNetworkIDs != nil && !slices.Contains(sp.TaggedNetworkIDs, n.ID))) {
						continue
					}
					if customUnknown {
						level = unknown
					}
					tag = b.action("act:port-tags:"+key, "Remove unused tagged VLANs from "+name, "Extra tagged VLANs on this outdoor port can be reached from outside. Keep only the VLAN this device needs.", LaneReduceExposure, 1)
				}
				pos := risk.Position{NetworkID: n.ID, NetworkName: n.Name, SwitchMAC: sw.MAC, SwitchPort: p.PortIdx, IsWired: true}
				b.link(root(Physical), b.position(pos), level, secure, tag)
			}
		}
	}
}
