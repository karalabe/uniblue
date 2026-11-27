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
	"strings"

	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/risk"
	"github.com/karalabe/uniblue/internal/unifi"
)

// InfraReport describes the consequences of losing one infrastructure device or the site controller.
type InfraReport struct {
	// TargetID is the stable identifier (canonical MAC or "controller") for UI selection and deduplication.
	TargetID string `json:"target_id,omitempty"`
	// Target names the selected device or controller.
	Target string `json:"target"`
	// Scope identifies the role under review ("Controller", "Gateway", "Switch", or "AP").
	Scope string `json:"scope"`
	// HostedOn identifies the known physical host of the Network application.
	HostedOn string `json:"hosted_on,omitempty"`
	// HostedOnID identifies the controller host even when devices share its name.
	HostedOnID string `json:"hosted_on_id,omitempty"`
	// Manages lists adopted equipment the controller can reconfigure.
	Manages []string `json:"manages,omitempty"`
	// Ports lists the physical ports under the selected switch's control.
	Ports []int `json:"ports,omitempty"`
	// Downstream lists devices below the switch in the reported uplink tree.
	Downstream []string `json:"downstream,omitempty"`
	// Clients names directly affected clients and clients below the selected device.
	Clients []string `json:"clients,omitempty"`
	// UplinkVLANs names the networks confirmed on the upstream port.
	UplinkVLANs []string `json:"uplink_vlans,omitempty"`
	// UplinkUnknown means the full set of networks on the uplink could not be established.
	UplinkUnknown bool `json:"uplink_unknown,omitempty"`
	// RoutedVLANs names the VLANs whose routing policy the device controls.
	RoutedVLANs []string `json:"routed_vlans,omitempty"`
	// Effects lists modeled plain-language security impacts of compromising this
	// target. UniBlue never reads or dumps device credentials.
	Effects []string `json:"effects"`
	// Legs lists assessed inbound, outbound, and VPN transport legs traversing or
	// terminating at the target device, one direction at a time.
	Legs []TransportSurvival `json:"legs,omitempty"`
}

// infraRole maps the controller's normalized device types to the roles that enforce policy.
func infraRole(d unifi.Device) string {
	switch strings.ToLower(d.Type) {
	case "uap":
		return "AP"
	case "usw":
		return "Switch"
	case "udm", "ugw", "ucg", "uxg":
		return "Gateway"
	case "uck":
		return "Controller"
	}
	return ""
}

func deviceLabel(d unifi.Device) string { return cmp.Or(d.Name, d.Model, d.MAC) }

// controllerHost identifies the physical host running the Network application.
// It checks in.ControllerHost against adopted device IPs first, then client
// IPs and hostnames, falling back to a Cloud Key or a non-classic integrated
// gateway (UDM/UCG) console when no direct address match is found.
func controllerHost(in Input) unifi.Device {
	s := in.Snapshot
	var console unifi.Device
	for _, d := range s.Devices {
		if in.ControllerHost != "" && d.IP == in.ControllerHost {
			return d
		}
		if infraRole(d) == "Controller" || console.MAC == "" && integratedGateway(d) && s.ControllerType != "classic" {
			console = d
		}
	}
	for _, cl := range s.Clients {
		if in.ControllerHost != "" && (slices.Contains(cl.AllIPs(), in.ControllerHost) || strings.EqualFold(cl.Hostname, in.ControllerHost)) {
			return unifi.Device{ID: cl.ID, MAC: cl.MAC, IP: cl.PrimaryIP(), Name: cl.DisplayName(), Type: "controller"}
		}
	}
	if console.MAC == "" {
		console.Name = in.ControllerHost
	}
	return console
}

func integratedGateway(d unifi.Device) bool {
	return strings.EqualFold(d.Type, "udm") || strings.EqualFold(d.Type, "ucg")
}

// infraTarget resolves raw to the logical "controller" sentinel, a unique
// adopted infrastructure device matched by name or MAC, or the resolved
// controller host when it sits outside adopted inventory.
func infraTarget(s *unifi.Snapshot, host unifi.Device, raw string) (unifi.Device, string, error) {
	target := strings.TrimSpace(raw)
	if strings.EqualFold(target, "controller") {
		return unifi.Device{Name: "Network controller"}, "Controller", nil
	}
	matches := func(d unifi.Device) bool {
		return target != "" && (strings.EqualFold(d.Name, target) || canonicalMAC(d.MAC) == canonicalMAC(target))
	}
	var found []unifi.Device
	for _, d := range s.Devices {
		if matches(d) {
			found = append(found, d)
		}
	}
	if len(found) > 1 {
		return unifi.Device{}, "", fmt.Errorf("several devices are named %q. Select one by its MAC address", target)
	}
	if len(found) == 1 && infraRole(found[0]) != "" {
		return found[0], infraRole(found[0]), nil
	}
	if matches(host) {
		return host, "Controller", nil
	}
	return unifi.Device{}, "", fmt.Errorf("no supported infrastructure device matches %q", target)
}

// uplinkNetworks resolves the parent end of the cable. Missing membership can
// leave the native network known while preventing any conclusion about other tags.
func uplinkNetworks(s *unifi.Snapshot, child unifi.Device) ([]unifi.Network, bool) {
	for _, parent := range s.Devices {
		if child.UplinkMAC == "" || canonicalMAC(parent.MAC) != canonicalMAC(child.UplinkMAC) {
			continue
		}
		for _, p := range parent.Ports {
			if child.UplinkPort <= 0 || p.PortIdx != child.UplinkPort {
				continue
			}
			mode := p.TaggedPolicy()
			if mode == "disabled" {
				return nil, false
			}
			if p.ProfileManaged && p.IsolationUnknown {
				return nil, true
			}
			knownIDs := make(map[string]bool, len(s.Networks))
			for _, n := range s.Networks {
				knownIDs[n.ID] = true
			}
			missing := func(id string) bool { return !knownIDs[id] }
			// In custom tagged mode, TaggedNetworkIDs == nil means all non-excluded
			// VLANs are allowed; an unresolved exclusion ID prevents determining which
			// custom VLANs are carried, so custom VLANs are withheld and unknown is set.
			unknownExclusions := mode == "custom" && slices.ContainsFunc(p.ExcludedNetworkIDs, missing)
			unknown := mode == "unknown" || unknownExclusions || mode == "custom" && slices.ContainsFunc(p.TaggedNetworkIDs, missing)
			var nets []unifi.Network
			nativeKnown := false
			for _, n := range s.Networks {
				if wanNetwork(n) {
					continue
				}
				native := p.NativeNetworkID != "" && n.ID == p.NativeNetworkID ||
					p.NativeNetworkID == "" && n.Name != "" && strings.EqualFold(n.Name, p.NativeNetworkName)
				nativeKnown = nativeKnown || native
				custom := mode == "custom" && !unknownExclusions && (p.TaggedNetworkIDs == nil || slices.Contains(p.TaggedNetworkIDs, n.ID)) && !slices.Contains(p.ExcludedNetworkIDs, n.ID)
				if native || mode == "all" || custom {
					nets = append(nets, n)
				}
			}
			return nets, unknown || !nativeKnown
		}
	}
	return nil, true
}

func wanNetwork(n unifi.Network) bool {
	return strings.HasPrefix(strings.ToLower(n.Purpose), "wan") || strings.EqualFold(n.ZoneName, "External")
}

// vlanRouter returns the MAC of the device routing a local network. An empty
// MAC selects the site gateway only when the controller resolved the network.
func vlanRouter(n unifi.Network) (string, bool) {
	return canonicalMAC(n.RouterDeviceMAC), networkKey(n) != "" && !wanNetwork(n) && !n.RouterUnresolved
}

// switchSubtree follows LLDP toward the leaves and visits each MAC once, even in a stale loop.
func switchSubtree(s *unifi.Snapshot, root string) map[string]bool {
	children := make(map[string][]string)
	for _, d := range s.Devices {
		if d.MAC != "" && d.UplinkMAC != "" {
			parent := canonicalMAC(d.UplinkMAC)
			children[parent] = append(children[parent], canonicalMAC(d.MAC))
		}
	}
	seen := map[string]bool{root: true}
	queue := []string{root}
	for i := 0; i < len(queue); i++ {
		for _, child := range children[queue[i]] {
			if !seen[child] {
				seen[child] = true
				queue = append(queue, child)
			}
		}
	}
	return seen
}

// EvaluateAllInfra computes deterministic compromise reports for the site's
// controller and every adopted UniFi gateway, switch, and access point so
// interactive UIs and offline HTML exports can inspect each device immediately.
func EvaluateAllInfra(in Input) []InfraReport {
	if in.Snapshot == nil || len(in.Snapshot.Devices) == 0 {
		return nil
	}
	if in.Oracle == nil {
		in.Oracle = risk.NewOracle(in.Snapshot, in.NetCfg)
	}
	var out []InfraReport
	seen := make(map[string]bool)
	add := func(target string) {
		rep, err := EvaluateInfraCompromise(in, target)
		if err != nil {
			return
		}
		key := rep.Scope + "|" + cmp.Or(rep.TargetID, rep.Target)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, rep)
	}
	add("controller")
	for _, d := range in.Snapshot.Devices {
		if infraRole(d) == "" {
			continue
		}
		add(cmp.Or(d.MAC, d.Name))
	}
	scopeOrder := func(s string) int {
		switch s {
		case "Controller":
			return 0
		case "Gateway":
			return 1
		case "Switch":
			return 2
		case "AP":
			return 3
		default:
			return 4
		}
	}
	slices.SortFunc(out, func(a, b InfraReport) int {
		return cmp.Or(cmp.Compare(scopeOrder(a.Scope), scopeOrder(b.Scope)), cmp.Compare(a.Target, b.Target), cmp.Compare(a.TargetID, b.TargetID))
	})
	return out
}

// EvaluateInfraCompromise estimates the effects of losing a device identified by name or MAC.
// The reserved name "controller" selects the Network application independently of its host.
func EvaluateInfraCompromise(in Input, targetMAC string) (InfraReport, error) {
	if in.Snapshot == nil {
		return InfraReport{}, fmt.Errorf("the site inventory is missing")
	}
	s := in.Snapshot
	host := controllerHost(in)
	d, role, err := infraTarget(s, host, targetMAC)
	if err != nil {
		return InfraReport{}, err
	}
	targetID := canonicalMAC(d.MAC)
	if role == "Controller" {
		targetID = "controller"
	} else if targetID == "" {
		targetID = cmp.Or(d.ID, deviceLabel(d))
	}
	r := InfraReport{TargetID: targetID, Target: deviceLabel(d), Scope: role}
	mac := canonicalMAC(d.MAC)
	// An integrated gateway (UDM/UCG) hosting the Network application exposes
	// full controller privileges alongside its gateway role.
	control := role == "Controller" || integratedGateway(d) && mac != "" && mac == canonicalMAC(host.MAC)
	owned := map[string]bool{}
	if mac != "" {
		owned[mac] = true
	}
	var subtree map[string]bool
	switch role {
	case "AP":
		r.Effects = append(r.Effects, "Wi-Fi encryption ends at this AP. It can read wireless frames from its clients and bypass isolation between them.",
			"Wi-Fi passphrases and RADIUS shared secrets configured on this AP are exposed.")
	case "Switch":
		r.Effects = append(r.Effects, "This switch controls its ports, port isolation, and access rules. Devices farther along a path can still enforce their own rules.")
		subtree = switchSubtree(s, mac)
		for _, p := range d.Ports {
			r.Ports = append(r.Ports, p.PortIdx)
		}
		slices.Sort(r.Ports)
		for _, dev := range s.Devices {
			if key := canonicalMAC(dev.MAC); key != mac && subtree[key] {
				r.Downstream = append(r.Downstream, deviceLabel(dev))
			}
		}
	case "Gateway":
		r.Effects = append(r.Effects, "The gateway controls traffic it routes, its WAN links, and VPNs that end here. It can alter DHCP, DNS, IPv6 router advertisements, and NTP services it provides.")
	}
	if control {
		r.HostedOn = deviceLabel(host)
		r.HostedOnID = cmp.Or(canonicalMAC(host.MAC), host.ID, host.IP)
		r.Effects = append(r.Effects, "The controller can reconfigure adopted equipment. Site Wi-Fi passphrases, device SSH credentials, and controller administrator credentials are at risk.")
		for _, dev := range s.Devices {
			devMAC := canonicalMAC(dev.MAC)
			switch infraRole(dev) {
			case "AP", "Switch", "Gateway":
				if devMAC == "" || devMAC != mac {
					r.Manages = append(r.Manages, deviceLabel(dev))
				}
				if devMAC != "" {
					owned[devMAC] = true
				}
			}
		}
	}
	if in.Oracle == nil {
		in.Oracle = risk.NewOracle(s, in.NetCfg)
	}
	oracle := in.Oracle.WithCompromised(sortedKeys(owned)...)
	carried := make(map[string]risk.Position)
	if role == "AP" || role == "Switch" {
		nets, unknown := uplinkNetworks(s, d)
		r.UplinkUnknown = unknown
		for _, n := range nets {
			r.UplinkVLANs = append(r.UplinkVLANs, cmp.Or(n.Name, n.ID))
			pos := risk.Position{NetworkID: n.ID, NetworkName: n.Name, IsWired: true, SwitchMAC: d.UplinkMAC, SwitchPort: d.UplinkPort}
			carried[networkKey(n)] = pos
		}
	}
	gwOwned := role == "Gateway"
	for _, dev := range s.Devices {
		if infraRole(dev) == "Gateway" && owned[canonicalMAC(dev.MAC)] {
			gwOwned = true
			break
		}
	}
	routed := make(map[string]bool)
	byName := make(map[string]unifi.Network)
	for _, n := range s.Networks {
		byName[strings.ToLower(n.Name)] = n
		if router, ok := vlanRouter(n); ok && ((router == "" && gwOwned) || owned[router]) {
			r.RoutedVLANs = append(r.RoutedVLANs, cmp.Or(n.Name, n.ID))
			routed[networkKey(n)] = true
		}
	}

	if role == "Gateway" && s.Health != nil {
		for _, vpn := range s.Health.VPNConnections {
			class := "unknown"
			switch strings.ToLower(vpn.Type) {
			case "wireguard", "openvpn", "ipsec":
				class = "e2e"
			}
			r.Legs = append(r.Legs, TransportSurvival{From: cmp.Or(vpn.Name, "VPN client"), To: r.Target,
				Protocol: cmp.Or(vpn.Type, "VPN"), Address: d.IP, Class: class, Path: "VPN ends at the gateway", Reachability: "observed",
				Confidentiality: exposed, Integrity: exposed, Availability: exposed,
				Note: "The gateway holds the VPN session keys. Applications inside the tunnel may encrypt their own traffic."})
		}
	}

	profiles := make(map[string][]TransportSurvival)
	outbound := make(map[string][]TransportSurvival)
	for _, hp := range in.Profiles {
		id := hostKey(hp.Client)
		profiles[id] = append(profiles[id], inboundSurfaces(hp)...)
		for _, dep := range hp.OutboundDependencies {
			leg := assessTransport(probe.Service{Protocol: dep.Protocol}, probe.HTTPBanner{})
			leg.From, leg.To = hp.Client.DisplayName(), cmp.Or(dep.DestinationHost, dep.DestinationIP, dep.ServiceName)
			leg.Address, leg.Port, leg.Transport = dep.DestinationIP, dep.Port, dep.Transport
			leg.Path, leg.Reachability = "Outbound traffic", "unknown"
			// A flow record does not show whether the peer verified its keys.
			if leg.Confidentiality == resilient {
				leg.Confidentiality, leg.Integrity = conditional, conditional
				leg.Note = "The recorded protocol supports end-to-end encryption. The scan did not check this outbound session."
			}
			outbound[id] = append(outbound[id], leg)
		}
	}
	for _, cl := range s.Clients {
		if cl.NetworkID == "" {
			n := byName[strings.ToLower(cl.NetworkName)]
			if n.Name == "" {
				n = oracle.NetworkForAddress(cl.PrimaryIP())
			}
			cl.NetworkID, cl.NetworkName = n.ID, cmp.Or(cl.NetworkName, n.Name)
		}
		net := cmp.Or(cl.NetworkID, cl.NetworkName)
		parent := canonicalMAC(cl.SwitchMAC)
		if !cl.IsWired {
			parent = canonicalMAC(cl.APMAC)
		}
		up, onUplink := carried[net]
		directAP := !cl.IsWired && owned[parent]
		attached := subtree[parent] || owned[parent]
		// Include any known VLAN when the gateway is compromised, even VLANs routed
		// by L3 switches: the gateway still sits on upstream routed/WAN paths and
		// can initiate connections from the Gateway zone, though local peer traffic
		// does not cross it.
		viaRouter := routed[net] || (gwOwned && net != "")
		if attached || viaRouter {
			r.Clients = append(r.Clients, cl.DisplayName())
			r.Legs = append(r.Legs, outbound[hostKey(cl)]...)
		}
		if !attached && !viaRouter && !onUplink {
			continue
		}
		for _, leg := range profiles[hostKey(cl)] {
			if !slices.Contains(cl.AllIPs(), leg.Address) {
				continue
			}
			leg.From, leg.To = r.Target, cl.DisplayName()
			var pos risk.Position
			switch {
			case directAP:
				leg.Path = "Through the serving AP"
				pos = risk.Position{NetworkID: cl.NetworkID, NetworkName: cl.NetworkName, APMAC: cl.APMAC, SSID: cl.ESSID}
			case attached:
				if owned[canonicalMAC(cl.SwitchMAC)] && cl.IsWired {
					// A compromised switch can deliver frames directly to its own client port.
					leg.Path = "Through the switch"
					leg.Reachability = "allow"
				} else {
					// Traffic behind an intact downstream switch only crosses the
					// compromised upstream switch when leaving that downstream switch.
					leg.Path = "Downstream of the switch"
					pos = risk.Position{NetworkID: cl.NetworkID, NetworkName: cl.NetworkName, IsWired: true, SwitchMAC: d.MAC}
					leg.Availability = conditional
					if leg.Confidentiality == exposed {
						leg.Confidentiality = conditional
					}
					if leg.Integrity == exposed {
						leg.Integrity = conditional
					}
					leg.Note += " Local peer traffic on the downstream switch does not cross this upstream switch."
				}
			case viaRouter:
				leg.Path = "Routed traffic"
				if gwOwned {
					pos = risk.Position{NetworkID: risk.GatewayNetworkID, Zone: "Gateway"}
				} else {
					leg.Reachability = "allow"
				}
			case onUplink:
				// Carrying a VLAN on an uplink only affects traffic that actually
				// traverses that upstream trunk port, so exposure and availability
				// downgrade to conditional.
				leg.Path = "From the upstream port"
				pos = up
				leg.Availability = conditional
				leg.Note += " This assessment applies only if the traffic crosses the upstream port."
				if leg.Confidentiality == exposed {
					leg.Confidentiality = conditional
				}
				if leg.Integrity == exposed {
					leg.Integrity = conditional
				}
			}
			if leg.Reachability == "" {
				leg.Reachability = "unknown"
				if pos != (risk.Position{}) {
					dst := cl
					dst.IP, dst.IPv6 = leg.Address, nil
					cell := oracle.Service(pos, dst, leg.Transport, leg.Port, family(leg.Address))
					leg.Reachability = cell.Effective
				}
			}
			if leg.Reachability == "deny" {
				leg.Confidentiality, leg.Integrity, leg.Availability = unverified, unverified, unverified
				leg.Note = "A remaining access rule blocks new connections on this path."
			}
			if role == "Controller" {
				leg.Path += " after the controller reconfigures it"
			}
			if directAP {
				leg.Wireless = wirelessProtection(s.WLANs, cl)
			}
			r.Legs = append(r.Legs, leg)
		}
	}
	for _, list := range []*[]string{&r.UplinkVLANs, &r.RoutedVLANs, &r.Downstream, &r.Manages, &r.Clients} {
		slices.Sort(*list)
	}
	slices.SortFunc(r.Legs, func(a, b TransportSurvival) int {
		return cmp.Or(cmp.Compare(a.To, b.To), cmp.Compare(a.From, b.From), cmp.Compare(a.Address, b.Address), cmp.Compare(a.Transport, b.Transport), cmp.Compare(a.Port, b.Port), cmp.Compare(a.Protocol, b.Protocol))
	})
	return r, nil
}

// wirelessProtection summarizes L2 Wi-Fi peer confidentiality (WPA3-SAE vs
// WPA2-PSK) separately from L4/L7 application encryption, which can survive AP
// compromise.
func wirelessProtection(wlans []unifi.WLANConfig, cl unifi.Client) string {
	for _, w := range wlans {
		if !w.Enabled || w.Name != cl.ESSID || (w.NetworkID != "" && cl.NetworkID != "" && w.NetworkID != cl.NetworkID) {
			continue
		}
		if w.WPAMode == "wpa3" && w.Security == "wpapsk" {
			return "WPA3-SAE protects peer sessions from someone who only has the passphrase. The AP itself sees the traffic."
		}
		if w.Security == "wpapsk" {
			return "Peer privacy is conditional. With WPA2-PSK, a shared passphrase and a captured handshake can expose a peer's wireless traffic."
		}
	}
	return "The AP can read the wireless link. Peer protection depends on the Wi-Fi settings."
}
