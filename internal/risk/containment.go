// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package risk

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/unifi"
)

// ContainmentAxis summarizes one enforcement dimension of an isolated network.
type ContainmentAxis struct {
	// Violation reports whether at least one evaluated path violates the
	// expected isolation or connectivity policy on this axis.
	Violation bool `json:"violation,omitempty"`

	// State is the rolled-up enforcement posture:
	// "blocked", "isolated", "restricted", "partial", "open", or "unknown".
	State string `json:"state"`

	// Detail provides a concise human-readable summary of the decisive evidence.
	Detail string `json:"detail,omitempty"`
}

// NetworkContainment captures the 4-axis containment posture and automatically
// inferred archetype ("guest", "iot", "camera", "isolated") for one isolated network.
type NetworkContainment struct {
	// NetworkID is the UniFi network UUID, when known.
	NetworkID string `json:"network_id,omitempty"`

	// NetworkName is the human-readable VLAN/network name.
	NetworkName string `json:"network_name"`

	// VLAN is the numeric 802.1Q VLAN ID string, if assigned.
	VLAN string `json:"vlan,omitempty"`

	// ZoneName is the UniFi firewall zone owning this network.
	ZoneName string `json:"zone_name,omitempty"`

	// Archetype classifies the network workload ("guest", "iot", "camera", or "isolated").
	Archetype string `json:"archetype"`

	// ArchetypeReason explains which configuration, SSID, census, or metadata signal
	// determined Archetype.
	ArchetypeReason string `json:"archetype_reason,omitempty"`

	// Peers summarizes Layer-2 same-VLAN isolation across Wi-Fi SSIDs, switch port
	// isolation, AP uplinks, and switch ACLs.
	Peers ContainmentAxis `json:"peers"`

	// LANEgress summarizes outbound isolation from this network toward trusted LANs
	// and the gateway management plane.
	LANEgress ContainmentAxis `json:"lan_egress"`

	// InternetEgress summarizes outbound reachability from this network to External.
	InternetEgress ContainmentAxis `json:"internet_egress"`

	// LANInbound summarizes inbound reachability from trusted LANs into this network.
	LANInbound ContainmentAxis `json:"lan_inbound"`

	// SharedZoneWith lists sibling networks of a different archetype sharing ZoneName.
	SharedZoneWith []string `json:"shared_zone_with,omitempty"`
}

var (
	personalDevicePattern = regexp.MustCompile(`(?i)(^|[-_.\s(])(iphone|ipad|pixel|galaxy|macbook|imac|mac[-_\s]?mini|mac[-_\s]?studio|mac[-_\s]?pro|^mac\b|apple\s*watch|^watch\b|desktop-|laptop-|surface|thinkpad|oneplus|android|phone|tablet|laptop)($|[-_.\s)\d])`)
	cameraDevicePattern   = regexp.MustCompile(`(?i)(^|[-_.\s(])(camera|cam|doorbell|chime|nvr|cctv|hikvision|reolink|dahua|amcrest|axis|ring|arlo|wyze|eufy[-_\s]?cam)($|[-_.\s)\d])`)
	iotDevicePattern      = regexp.MustCompile(`(?i)(^|[-_.\s(])(roomba|irobot|roborock|espressif|esp32|esp8266|esphome|tasmota|shelly|tuya|sonoff|aqara|hue|tradfri|zigbee|zwave|matter|homekit|smart[-_\s]?plug|thermostat|ecobee|nest|daikin|mitsubishi|gree|hvac|zehnder|comfoconnect|xtool|laser|prusa|printer|laserjet|brother|epson|sonos|chromecast|roku|marantz|denon|homeassistant|appliance|sensor|vacuum|washer|dryer|fridge)($|[-_.\s)\d])`)

	guestMetaPattern  = regexp.MustCompile(`(?i)(^|[-_.\s])(guest|guests|visitor|visitors|public)($|[-_.\s])`)
	iotMetaPattern    = regexp.MustCompile(`(?i)(^|[-_.\s])(iot|smart|things|homeauto|automation|appliance|appliances|sensor|sensors|hvac|domotics)($|[-_.\s])`)
	cameraMetaPattern = regexp.MustCompile(`(?i)(^|[-_.\s])(camera|cameras|cam|cams|cctv|protect|nvr|security[-_\s]?cam)($|[-_.\s])`)
)

// classifyIsolatedArchetype infers whether an already-isolated network serves
// "guest", "iot", "camera", or generic "isolated" workloads without relying on
// UniFi's generic "guest" purpose or "Hotspot" zone name alone.
func classifyIsolatedArchetype(
	snap *unifi.Snapshot,
	n unifi.Network,
	intent config.IsolationIntent,
) (archetype, reason string, misplacedIoT []string) {
	if containsFold(intent.CameraVLANs, n.Name) || containsFold(intent.CameraVLANs, n.VLAN) {
		return "camera", "configured camera_vlans", nil
	}
	if containsFold(intent.IoTVLANs, n.Name) || containsFold(intent.IoTVLANs, n.VLAN) {
		return "iot", "configured iot_vlans", nil
	}
	if containsFold(intent.GuestVLANs, n.Name) || containsFold(intent.GuestVLANs, n.VLAN) {
		return "guest", "configured guest_vlans", nil
	}

	// An active captive portal / Hotspot guest SSID is a definitive Guest signal
	// because unattended IoT appliances cannot complete captive portals.
	for _, w := range snap.WLANs {
		if w.Enabled && strings.EqualFold(w.NetworkName, n.Name) && w.IsGuest {
			return "guest", fmt.Sprintf("captive portal SSID %q", w.Name), nil
		}
	}

	// Census active clients and historical known clients last seen on this VLAN.
	personalCnt, iotCnt, camCnt := 0, 0, 0
	seenMAC := make(map[string]struct{})
	var iotNames []string

	classifyText := func(name, hostname, oui string) string {
		combined := strings.TrimSpace(name + " " + hostname + " " + oui)
		if combined == "" {
			return ""
		}
		if cameraDevicePattern.MatchString(combined) {
			return "camera"
		}
		if iotDevicePattern.MatchString(combined) {
			return "iot"
		}
		if personalDevicePattern.MatchString(combined) {
			return "personal"
		}
		return ""
	}

	for _, cl := range snap.Clients {
		if !strings.EqualFold(cl.NetworkName, n.Name) {
			continue
		}
		if m := strings.ToLower(strings.TrimSpace(cl.MAC)); m != "" {
			seenMAC[m] = struct{}{}
		}
		switch classifyText(cl.Name, cl.Hostname, cl.OUI) {
		case "camera":
			camCnt++
		case "iot":
			iotCnt++
			if !isUbiquitiOUI(cl.OUI) {
				iotNames = append(iotNames, cl.DisplayName())
			}
		case "personal":
			personalCnt++
		}
	}
	for _, kc := range snap.KnownClients {
		if !strings.EqualFold(kc.LastNetworkName, n.Name) {
			continue
		}
		if m := strings.ToLower(strings.TrimSpace(kc.MAC)); m != "" {
			if _, dup := seenMAC[m]; dup {
				continue
			}
			seenMAC[m] = struct{}{}
		}
		switch classifyText(kc.Name, kc.Hostname, "") {
		case "camera":
			camCnt++
		case "iot":
			iotCnt++
			iotNames = append(iotNames, firstNonEmptyStr(kc.Name, kc.Hostname, kc.MAC))
		case "personal":
			personalCnt++
		}
	}

	metaArchetype, metaReason := classifyNetworkMetadata(n)

	if camCnt >= 2 && camCnt > personalCnt && camCnt >= iotCnt {
		return "camera", fmt.Sprintf("device census (%d camera(s))", camCnt), nil
	}
	if personalCnt >= 1 && personalCnt >= iotCnt && personalCnt > camCnt {
		r := fmt.Sprintf("device census (%d personal device(s))", personalCnt)
		if metaArchetype == "guest" && metaReason != "" {
			r += " and " + metaReason
		}
		return "guest", r, dedupeSortedStrings(iotNames)
	}
	if iotCnt >= 1 && iotCnt > personalCnt {
		r := fmt.Sprintf("device census (%d IoT/appliance(s))", iotCnt)
		if metaArchetype == "iot" && metaReason != "" {
			r += " and " + metaReason
		}
		return "iot", r, nil
	}

	if metaArchetype != "" {
		return metaArchetype, metaReason, nil
	}
	return "isolated", "isolated network", nil
}

// classifyNetworkMetadata infers a secondary archetype hint from the VLAN's
// DHCP domain name and network/zone labels (ignoring generic "Hotspot" / "DMZ"
// zone names since IoT and Guest VLANs commonly share them).
func classifyNetworkMetadata(n unifi.Network) (string, string) {
	dom := strings.TrimSpace(n.DomainName)
	if dom != "" {
		switch {
		case cameraMetaPattern.MatchString(dom):
			return "camera", fmt.Sprintf("DHCP domain %q", dom)
		case iotMetaPattern.MatchString(dom):
			return "iot", fmt.Sprintf("DHCP domain %q", dom)
		case guestMetaPattern.MatchString(dom):
			return "guest", fmt.Sprintf("DHCP domain %q", dom)
		}
	}
	// Check network name and non-generic zone name (never treat UniFi's built-in
	// "Hotspot" zone name alone as Guest, since IoT VLANs frequently share it).
	zoneHint := strings.TrimSpace(n.ZoneName)
	if strings.EqualFold(zoneHint, "hotspot") || strings.EqualFold(zoneHint, "dmz") {
		zoneHint = ""
	}
	combined := strings.TrimSpace(n.Name + " " + zoneHint)
	switch {
	case cameraMetaPattern.MatchString(combined):
		return "camera", fmt.Sprintf("network name %q", n.Name)
	case iotMetaPattern.MatchString(combined):
		return "iot", fmt.Sprintf("network name %q", n.Name)
	case guestMetaPattern.MatchString(combined):
		return "guest", fmt.Sprintf("network name %q", n.Name)
	}
	return "", ""
}

// isUbiquitiOUI reports whether an OUI string identifies first-party Ubiquiti
// or UniFi hardware (kept separate from third-party IoT migration hints).
func isUbiquitiOUI(oui string) bool {
	low := strings.ToLower(strings.TrimSpace(oui))
	return strings.Contains(low, "ubiquiti") || strings.Contains(low, "unifi")
}

// dedupeSortedStrings returns a sorted, case-insensitively deduplicated copy of in.
func dedupeSortedStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		key := strings.ToLower(s)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// evaluateNetworkContainment computes the 4-axis Containment Profile (Peers,
// LAN Egress, Internet Egress, LAN Inbound) for every isolated or explicitly
// targeted VLAN, emitting findings for real isolation gaps and archetype-aware
// recommendations without false alarms on Guest Wi-Fi.
func evaluateNetworkContainment(
	snap *unifi.Snapshot,
	rawFindings []checks.Finding,
	sortedPolicies []unifi.FirewallPolicy,
	intent config.IsolationIntent,
	gwPoliciesAvailable bool,
	gwMissingReason string,
	switchACLStatus, switchACLReason, gwName string,
	untrustedNets, trustedNets []unifi.Network,
	existingCells []IsolationCell,
) ([]NetworkContainment, []IsolationCell, []checks.Finding, []PostureNote) {
	if snap == nil || len(untrustedNets) == 0 {
		return nil, nil, nil, nil
	}

	var containments []NetworkContainment
	var cells []IsolationCell
	var findings []checks.Finding
	var notes []PostureNote

	noInternetSet := toLowerSet(intent.NoInternetVLANs)
	strictInboundSet := toLowerSet(intent.StrictInboundVLANs)

	// First pass: classify archetypes and track networks sharing a zone.
	type netEntry struct {
		net          unifi.Network
		archetype    string
		reason       string
		misplacedIoT []string
	}
	entries := make([]netEntry, 0, len(untrustedNets))
	zoneMembers := make(map[string][]netEntry)
	hasDedicatedIoTNet := false
	for _, n := range untrustedNets {
		arch, reason, misplaced := classifyIsolatedArchetype(snap, n, intent)
		ent := netEntry{net: n, archetype: arch, reason: reason, misplacedIoT: misplaced}
		entries = append(entries, ent)
		if z := strings.ToLower(strings.TrimSpace(n.ZoneName)); z != "" {
			zoneMembers[z] = append(zoneMembers[z], ent)
		}
		if arch == "iot" {
			hasDedicatedIoTNet = true
		}
	}

	routed := containmentEvaluator{
		snap:           snap,
		rawFindings:    rawFindings,
		policies:       sortedPolicies,
		intent:         intent,
		gatewayOK:      gwPoliciesAvailable,
		gatewayMissing: gwMissingReason,
		switchStatus:   switchACLStatus,
		switchMissing:  switchACLReason,
		gateway:        gwName,
	}
	for _, ent := range entries {
		n := ent.net
		nLow := strings.ToLower(strings.TrimSpace(n.Name))
		zoneLabel := firstNonEmptyStr(n.ZoneName, n.Name)

		nc := NetworkContainment{
			NetworkID:       n.ID,
			NetworkName:     n.Name,
			VLAN:            n.VLAN,
			ZoneName:        n.ZoneName,
			Archetype:       ent.archetype,
			ArchetypeReason: ent.reason,
		}

		// Record shared-zone siblings with a different archetype (e.g., IoT sharing
		// the Hotspot zone with Guest).
		if z := strings.ToLower(strings.TrimSpace(n.ZoneName)); z != "" {
			for _, peer := range zoneMembers[z] {
				if strings.EqualFold(peer.net.Name, n.Name) {
					continue
				}
				if peer.archetype != ent.archetype && (ent.archetype == "iot" || ent.archetype == "camera" || peer.archetype == "iot" || peer.archetype == "camera") {
					nc.SharedZoneWith = append(nc.SharedZoneWith, peer.net.Name)
				}
			}
			sort.Strings(nc.SharedZoneWith)
		}

		// Axis 1: Peer-to-peer L2 isolation (same-AP Wi-Fi, wired ports, mixed, cross-AP).
		peerAxis, peerCells, peerFindings := evaluatePeerContainmentAxis(snap, n, switchACLStatus, switchACLReason)
		nc.Peers = peerAxis
		cells = append(cells, peerCells...)
		findings = append(findings, peerFindings...)

		// Axis 2: LAN Egress (VLAN -> Internal / Gateway).
		nc.LANEgress = summarizeLANEgressAxis(n.Name, existingCells)

		// Axis 3: Internet Egress (VLAN -> External).
		_, explicitNoInet := noInternetSet[nLow]
		if !explicitNoInet && n.VLAN != "" {
			_, explicitNoInet = noInternetSet[strings.ToLower(n.VLAN)]
		}
		inetAxis, inetCells, inetFindings, inetNotes := routed.evaluateInternetEgress(n, ent.archetype, explicitNoInet)
		nc.InternetEgress = inetAxis
		cells = append(cells, inetCells...)
		findings = append(findings, inetFindings...)
		notes = append(notes, inetNotes...)

		// Axis 4: LAN Inbound (Internal -> VLAN).
		_, explicitStrictIn := strictInboundSet[nLow]
		if !explicitStrictIn && n.VLAN != "" {
			_, explicitStrictIn = strictInboundSet[strings.ToLower(n.VLAN)]
		}
		inAxis, inCells, inFindings, inNotes := routed.evaluateLANInbound(n, ent.archetype, explicitStrictIn, trustedNets)
		nc.LANInbound = inAxis
		cells = append(cells, inCells...)
		findings = append(findings, inFindings...)
		notes = append(notes, inNotes...)

		// Shared-zone architecture hint on IoT/Camera networks sharing Hotspot with Guest.
		if (ent.archetype == "iot" || ent.archetype == "camera") && len(nc.SharedZoneWith) > 0 {
			notes = append(notes, PostureNote{
				Severity: checks.SeverityLow,
				Title:    fmt.Sprintf("%s shares firewall zone %q with %s", n.Name, zoneLabel, strings.Join(nc.SharedZoneWith, ", ")),
				Detail:   fmt.Sprintf("Move %s into a dedicated %s firewall zone so you can block internet egress and restrict inbound LAN access independently of %s.", n.Name, strings.ToUpper(ent.archetype), strings.Join(nc.SharedZoneWith, ", ")),
			})
		}

		// Misplaced IoT appliances on a Guest network when a dedicated IoT VLAN exists.
		if ent.archetype == "guest" && hasDedicatedIoTNet && len(ent.misplacedIoT) > 0 {
			notes = append(notes, PostureNote{
				Severity: checks.SeverityLow,
				Title:    fmt.Sprintf("IoT device(s) sitting on Guest network %s (%s)", n.Name, strings.Join(ent.misplacedIoT, ", ")),
				Detail:   fmt.Sprintf("Consider moving %s from %s to your dedicated IoT network so they get IoT-specific internet and inbound policies.", strings.Join(ent.misplacedIoT, ", "), n.Name),
			})
		}

		containments = append(containments, nc)
	}

	sort.Slice(containments, func(i, j int) bool {
		return strings.ToLower(containments[i].NetworkName) < strings.ToLower(containments[j].NetworkName)
	})
	return containments, cells, findings, notes
}

// evaluatePeerContainmentAxis assesses Layer-2 client-to-client isolation on n
// across same-AP Wi-Fi l2_isolation, wired switch port isolation, mixed wired-to-AP
// paths, cross-AP uplinks, and directional IPv4/IPv6 switch ACLs.
func evaluatePeerContainmentAxis(snap *unifi.Snapshot, n unifi.Network, status, missing string) (ContainmentAxis, []IsolationCell, []checks.Finding) {
	// peerAttachment identifies one wired client or AP uplink attached to a switch port.
	type peerAttachment struct {
		label string
		sw    string
		mac   string
		port  int
		wired bool
	}
	type switchPortKey struct {
		sw  string
		idx int
	}
	type peerGap struct {
		clients  []string
		evidence []string
		fixes    []string
	}

	clients := make(map[string]unifi.Client)
	var wired, aps []peerAttachment
	wifiClients, unresolvedMedium := false, false
	for _, cl := range snap.Clients {
		if !(n.ID != "" && cl.NetworkID == n.ID) && !strings.EqualFold(cl.NetworkName, n.Name) {
			continue
		}
		if cl.IsWired {
			clients[cl.MAC] = cl
			wired = append(wired, peerAttachment{
				label: cl.DisplayName(),
				sw:    strings.ToLower(cl.SwitchMAC),
				mac:   cl.MAC,
				port:  cl.SwitchPort,
				wired: true,
			})
		} else if cl.APMAC != "" || cl.ESSID != "" {
			wifiClients = true
		} else {
			unresolvedMedium = true
		}
	}

	ports := make(map[switchPortKey]unifi.SwitchPort)
	for _, d := range snap.Devices {
		for _, p := range d.Ports {
			ports[switchPortKey{strings.ToLower(d.MAC), p.PortIdx}] = p
		}
		if strings.EqualFold(d.Type, "uap") {
			aps = append(aps, peerAttachment{
				label: firstNonEmptyStr(d.Name, d.MAC),
				sw:    strings.ToLower(d.UplinkMAC),
				port:  d.UplinkPort,
			})
		}
	}

	var (
		cells         []IsolationCell
		findings      []checks.Finding
		gapKinds      []string
		detail        string
		affectedPorts []string
	)
	gaps := make(map[string]*peerGap)
	allowed, blocked, unknown := false, false, false
	zone := firstNonEmptyStr(n.ZoneName, n.Name)

	record := func(c IsolationCell, refs []string) {
		c.SourceZone = zone
		c.DestZone = zone
		c.SourceNetwork = n.Name
		c.DestNetwork = n.Name
		c.Expected = "deny"
		cells = append(cells, c)
		switch c.Verdict {
		case IsolationBlockedOK:
			blocked = true
		case IsolationUnknown:
			unknown = true
			if detail == "" {
				detail = c.MissingInput
			}
		case IsolationViolation:
			if !allowed {
				detail = c.DecisiveReason
			}
			allowed = true
			g := gaps[c.PathKind]
			if g == nil {
				g = &peerGap{}
				gaps[c.PathKind] = g
				gapKinds = append(gapKinds, c.PathKind)
			}
			g.clients = append(g.clients, refs...)
			g.evidence = append(g.evidence, c.DecisiveReason)
			g.fixes = append(g.fixes, c.RecommendedFix)
		}
	}

	// Step 1: Evaluate same-AP Wi-Fi client device isolation on enabled SSIDs.
	hasWiFi := false
	for _, wlan := range snap.WLANs {
		if !wlan.Enabled || !strings.EqualFold(wlan.NetworkName, n.Name) {
			continue
		}
		hasWiFi = true
		c := IsolationCell{
			PathKind:       "same-ap-wifi",
			DestFunction:   "same-vlan-wifi-peers",
			Transport:      "all",
			IPFamily:       "both",
			Enforcer:       wlan.Name,
			Effective:      "deny",
			Verdict:        IsolationBlockedOK,
			DecisiveReason: "Same-AP client isolation enabled on " + wlan.Name,
		}
		if !wlan.L2Isolation {
			c.Effective = "allow"
			c.Verdict = IsolationViolation
			c.DecisiveReason = "Same-AP client isolation is disabled on " + wlan.Name
			c.RecommendedFix = "Enable Client Device Isolation on " + wlan.Name
		}
		if snap.Visibility != nil && !snap.Visibility.WLANsAvailable && c.Verdict == IsolationBlockedOK {
			c.Verdict = IsolationUnknown
			c.Effective = "unknown"
			c.MissingInput = "Current WLAN isolation settings unavailable for " + wlan.Name
		}
		record(c, nil)
	}
	if unresolvedMedium || (wifiClients && (!hasWiFi || len(aps) == 0)) {
		record(IsolationCell{
			PathKind:     "peer-attachment",
			Effective:    "unknown",
			Verdict:      IsolationUnknown,
			MissingInput: "Controller did not resolve all peer attachments on " + n.Name,
		}, nil)
	}

	// evaluatePair checks one switched peer pair (or a single wired host against
	// the VLAN when only one wired host is currently online). Port isolation only
	// isolates peers on the same switch when both ports are isolated and neither
	// wired port hides multiple MACs behind an unmanaged downstream switch.
	evaluatePair := func(a, b peerAttachment, kind string, single bool) {
		pa, okA := ports[switchPortKey{a.sw, a.port}]
		pb, okB := ports[switchPortKey{b.sw, b.port}]
		label := func(x peerAttachment) string {
			if x.sw != "" && x.port > 0 {
				return fmt.Sprintf("%s (%s Port %d)", x.label, deviceNameByMAC(snap, x.sw), x.port)
			}
			return x.label
		}
		path := label(a)
		if !single {
			path += " and " + label(b)
		}

		destFn := "same-vlan-wired-peers"
		if kind == "cross-ap-wifi" {
			destFn = "cross-ap-wifi-peers"
		} else if kind == "mixed-same-vlan" {
			destFn = "same-vlan-mixed-peers"
		}
		c := IsolationCell{
			PathKind:     kind,
			DestFunction: destFn,
			Enforcer:     "Switch port isolation",
			Transport:    "all",
			IPFamily:     "both",
		}

		shared := !single && a.sw == b.sw && a.port == b.port
		if okA && okB && !pa.IsolationUnknown && !pb.IsolationUnknown &&
			a.sw == b.sw && !shared && pa.Isolation && pb.Isolation &&
			(!a.wired || pa.MACTableCount <= 1) && (!b.wired || pb.MACTableCount <= 1) {
			c.Verdict = IsolationBlockedOK
			c.Effective = "deny"
			c.DecisiveReason = "Isolated switch ports: " + path
			record(c, nil)
			return
		}

		var fixPorts []string
		if okA && !pa.Isolation && !pa.IsolationUnknown {
			fixPorts = append(fixPorts, label(a))
		}
		if !single && okB && !pb.Isolation && !pb.IsolationUnknown {
			fixPorts = append(fixPorts, label(b))
		}
		c.RecommendedFix = "Verify switch port isolation and switch ACLs for " + path + "."
		if len(fixPorts) > 0 {
			c.RecommendedFix = "Enable port isolation on " + strings.Join(fixPorts, " and ") + ", or apply a switch peer isolation ACL."
		}

		if a.sw == "" || a.port <= 0 || b.port <= 0 || a.sw != b.sw || shared || status != "complete" {
			c.Verdict = IsolationUnknown
			c.Effective = "unknown"
			c.MissingInput = "Cannot verify the complete switched path for " + path
			if status != "complete" {
				c.MissingInput += ". Switch ACL unavailable: " + missing
			}
			record(c, nil)
			return
		}

		swNet := n
		swNet.RouterDeviceMAC = a.sw
		fams := []string{"ipv4"}
		if siteHasIPv6Context(snap, n, n, unifi.Client{}) {
			fams = append(fams, "ipv6")
		}
		for _, fam := range fams {
			// A unidirectional ACL can block A -> B while still permitting B -> A.
			// Evaluate both directions when two distinct endpoints are present.
			checkDir := func(src, dst peerAttachment) IsolationCell {
				peers := peerEndpoints{src: clients[src.mac], dst: clients[dst.mac]}
				if single {
					peers.dst = unifi.Client{}
				}
				return evaluateBoundary(
					snap, nil, nil, config.IsolationIntent{}, false, "",
					status, missing, "", swNet, swNet, zone, zone, fam, "deny", &peers,
				)
			}
			cell := checkDir(a, b)
			if !single && cell.Verdict != IsolationViolation {
				reverse := checkDir(b, a)
				if reverse.Verdict == IsolationViolation || reverse.Verdict == IsolationUnknown {
					cell = reverse
				}
			}

			cell.PathKind = kind
			cell.DestFunction = c.DestFunction
			cell.Enforcer = deviceNameByMAC(snap, a.sw) + " (switch ACL)"
			cell.RecommendedFix = c.RecommendedFix
			if cell.Verdict == IsolationViolation && (!okA || !okB || pa.IsolationUnknown || pb.IsolationUnknown) {
				cell.Verdict = IsolationUnknown
				cell.Effective = "unknown"
				cell.MissingInput = "Effective switch port settings unavailable for " + path
			}

			var refs []string
			if cell.Verdict == IsolationViolation {
				affectedPorts = append(affectedPorts, fixPorts...)
				cell.DecisiveReason = fmt.Sprintf("%s: peer traffic permitted by %s on %s", path, cell.DecisiveRuleName, strings.ToUpper(fam))
				for _, x := range []peerAttachment{a, b} {
					if x.wired && x.mac != "" && !containsFold(refs, x.mac) {
						refs = append(refs, strings.ToLower(x.mac))
					}
				}
				sort.Strings(refs)
			}
			record(cell, refs)
		}
	}

	// Sort attachments deterministically so evidence, findings, and webhook keys stay stable.
	sort.Slice(wired, func(i, j int) bool { return wired[i].mac < wired[j].mac })
	sort.Slice(aps, func(i, j int) bool {
		if aps[i].sw != aps[j].sw {
			return aps[i].sw < aps[j].sw
		}
		return aps[i].port < aps[j].port
	})

	// Step 2: Evaluate wired-to-wired, mixed wired-to-AP, and cross-AP pairs.
	// Cap the quadratic pair space on large sites while preserving already-found
	// violations and marking overflow explicitly as unverified.
	const maxPeerPaths = 2048
	pathCount := 0
	checkPair := func(a, b peerAttachment, kind string, single bool) bool {
		if pathCount == maxPeerPaths {
			if !unknown || detail == "" {
				detail = "Peer path evaluation limit reached"
			}
			record(IsolationCell{
				PathKind:     kind,
				Effective:    "unknown",
				Verdict:      IsolationUnknown,
				MissingInput: "Peer path evaluation limit reached",
			}, nil)
			return false
		}
		pathCount++
		evaluatePair(a, b, kind, single)
		return true
	}

evalPairs:
	for i, a := range wired {
		if len(wired) == 1 {
			if !checkPair(a, a, "wired-same-vlan", true) {
				break evalPairs
			}
		}
		for _, b := range wired[i+1:] {
			if !checkPair(a, b, "wired-same-vlan", false) {
				break evalPairs
			}
		}
		if wifiClients {
			for _, b := range aps {
				if !checkPair(a, b, "mixed-same-vlan", false) {
					break evalPairs
				}
			}
		}
	}
	if hasWiFi && pathCount < maxPeerPaths {
	evalAPs:
		for i, a := range aps {
			for _, b := range aps[i+1:] {
				if !checkPair(a, b, "cross-ap-wifi", false) {
					break evalAPs
				}
			}
		}
	}

	state := "unknown"
	switch {
	case allowed && blocked || unknown && (allowed || blocked):
		state = "partial"
	case allowed:
		state = "open"
	case blocked:
		state = "isolated"
	}

	// Emit at most one UB-UNIFI-ISO-SAME-VLAN finding per path kind anchored to
	// the VLAN entity, linking AffectedClientMACs so the UI highlights each
	// participating wired client and switch port without duplicating queue items.
	peerKindMeta := map[string]struct {
		prop    string
		title   string
		actions []string
	}{
		"wired-same-vlan": {
			prop:    "wired",
			title:   "Same-VLAN wired peer isolation gap on " + n.Name,
			actions: []string{"enable_switch_port_isolation", "add_switch_l2_isolation_acl"},
		},
		"cross-ap-wifi": {
			prop:    "cross-ap",
			title:   "Cross-AP Wi-Fi peer isolation gap on " + n.Name,
			actions: []string{"add_switch_l2_isolation_acl", "enable_switch_port_isolation"},
		},
		"same-ap-wifi": {
			prop:    "same-ap",
			title:   "Same-AP Wi-Fi peer isolation gap on " + n.Name,
			actions: []string{"enable_wlan_l2_isolation"},
		},
		"mixed-same-vlan": {
			prop:    "mixed",
			title:   "Wired-to-Wi-Fi peer isolation gap on " + n.Name,
			actions: []string{"enable_switch_port_isolation", "add_switch_l2_isolation_acl"},
		},
	}
	sort.Strings(gapKinds)
	for _, kind := range gapKinds {
		g := gaps[kind]
		meta := peerKindMeta[kind]
		findings = append(findings, checks.Finding{
			CheckID:            "UB-UNIFI-ISO-SAME-VLAN",
			Title:              meta.title,
			Category:           "isolation-policy",
			ClaimKind:          checks.ClaimConfiguredAccess,
			Property:           "isolation-" + meta.prop + "-" + strings.ToLower(n.Name),
			BaseSeverity:       checks.SeverityMedium,
			EffectiveSeverity:  checks.SeverityMedium,
			Client:             unifi.Client{MAC: "vlan:" + n.ID, Name: n.Name, NetworkName: n.Name},
			AffectedClientMACs: dedupeSortedStrings(g.clients),
			Evidence:           strings.Join(dedupeSortedStrings(g.evidence), "; "),
			Remediation: checks.Remediation{
				Summary:      strings.Join(dedupeSortedStrings(g.fixes), " "),
				UniFiActions: meta.actions,
			},
		})
	}

	if unisolated := dedupeSortedStrings(affectedPorts); len(unisolated) > 0 {
		detail = "Peer access permitted. Port isolation is disabled on " + strings.Join(unisolated, ", ")
	} else if detail == "" {
		detail = "No peer attachment evidence"
		if blocked {
			detail = "Peer isolation verified for the evaluated paths"
		}
	}
	return ContainmentAxis{State: state, Detail: detail, Violation: allowed}, cells, findings
}

// summarizeLANEgressAxis rolls up the already-evaluated LAN transit and
// gateway-admin isolation cells for netName into a single containment axis.
func summarizeLANEgressAxis(netName string, cells []IsolationCell) ContainmentAxis {
	hasViolation, hasUnknown, hasApproved, hasBlocked := false, false, false, false
	var violRule string
	for _, c := range cells {
		if !strings.EqualFold(c.SourceNetwork, netName) {
			continue
		}
		if c.PathKind != "gateway-routed" && c.PathKind != "switch-routed" && c.PathKind != "gateway-local" {
			continue
		}
		if strings.EqualFold(c.DestZone, "External") {
			continue
		}
		// Ignore essential DNS/DHCP gateway dependencies when summarizing egress isolation.
		if c.DestFunction == "gateway-dns" || c.DestFunction == "gateway-dhcp" {
			continue
		}
		switch c.Verdict {
		case IsolationViolation:
			hasViolation = true
			if violRule == "" {
				violRule = firstNonEmptyStr(c.DecisiveRuleName, c.DestNetwork)
			}
		case IsolationUnknown:
			hasUnknown = true
		case IsolationApproved:
			hasApproved = true
		case IsolationBlockedOK:
			hasBlocked = true
		}
	}
	switch {
	case hasViolation:
		return ContainmentAxis{State: "open", Violation: true, Detail: fmt.Sprintf("Permitted into LAN/Gateway via %q", violRule)}
	case hasUnknown:
		return ContainmentAxis{State: "unknown", Detail: "Gateway or switch policy telemetry incomplete"}
	case hasApproved && hasBlocked:
		return ContainmentAxis{State: "restricted", Detail: "Blocked by default with approved pinhole(s)"}
	case hasBlocked:
		return ContainmentAxis{State: "blocked", Detail: "Blocked from Internal LAN and Gateway admin"}
	default:
		return ContainmentAxis{State: "unknown", Detail: "No LAN egress boundary evaluated"}
	}
}

// containmentEvaluator bundles the shared snapshot and policy context needed to
// evaluate routed containment boundaries (Internet Egress and LAN Inbound)
// using the exact first-match boundary solver.
type containmentEvaluator struct {
	snap           *unifi.Snapshot
	rawFindings    []checks.Finding
	policies       []unifi.FirewallPolicy
	intent         config.IsolationIntent
	gatewayOK      bool
	gatewayMissing string
	switchStatus   string
	switchMissing  string
	gateway        string
}

// containmentBoundary identifies one directed network-to-network address-family
// boundary evaluated for Internet Egress or LAN Inbound containment.
type containmentBoundary struct {
	src unifi.Network
	dst unifi.Network
	fam string
}

// evaluateInternetEgress assesses outbound reachability from n to External
// across IPv4 and IPv6, honoring the network's Allow Internet Access toggle
// before running the exact gateway boundary solver.
func (e containmentEvaluator) evaluateInternetEgress(
	n unifi.Network,
	archetype string,
	strict bool,
) (ContainmentAxis, []IsolationCell, []checks.Finding, []PostureNote) {
	fams := []string{"ipv4"}
	if siteHasIPv6Context(e.snap, n, n, unifi.Client{}) {
		fams = append(fams, "ipv6")
	}

	// The network-level Allow Internet Access toggle is authoritative when disabled.
	if n.InternetAccessEnabled != nil && !*n.InternetAccessEnabled {
		var cells []IsolationCell
		for _, fam := range fams {
			c := IsolationCell{
				SourceZone:    n.ZoneName,
				SourceNetwork: n.Name,
				DestZone:      "External",
				DestNetwork:   "Internet",
				DestFunction:  "internet-egress",
				Transport:     "all",
				IPFamily:      fam,
				PathKind:      "gateway-routed",
				Enforcer:      e.gateway,
				Expected:      "deny",
			}
			if archetype == "guest" && !strict {
				c.Expected = "allow"
			}
			applyDecisionToCell(&c, policyDecision{
				action: "deny",
				reason: "Allow Internet Access is disabled on the network",
			})
			cells = append(cells, c)
		}
		return ContainmentAxis{
			State:     "blocked",
			Violation: cells[0].Verdict == IsolationBrokenDependency,
			Detail:    cells[0].DecisiveReason,
		}, cells, nil, nil
	}

	// Append a trailing External fallback rule so unmatched traffic uses the
	// controller's network internet setting when present, or yields unknown when
	// neither a catch-all External rule nor the network toggle was retrieved.
	anyEP := unifi.PolicyEndpoint{AnyTarget: true, AnyPort: true}
	fallback := unifi.FirewallPolicy{
		Enabled:     true,
		Name:        "External default",
		Protocol:    "all",
		Source:      anyEP,
		Destination: anyEP,
		Action:      "ALLOW",
	}
	fallback.Destination.ZoneName = "External"
	if n.InternetAccessEnabled == nil {
		fallback.UnsupportedReason = "controller omitted the External default"
	}
	policies := append(append([]unifi.FirewallPolicy(nil), e.policies...), fallback)

	// External traffic always traverses the gateway even for switch-routed VLANs.
	srcNet := n
	srcNet.RouterDeviceMAC = ""
	external := unifi.Network{
		Name:       "Internet",
		ZoneName:   "External",
		Subnet:     "0.0.0.0/0",
		IPv6Subnet: "2000::/3",
	}
	paths := make([]containmentBoundary, 0, len(fams))
	for _, fam := range fams {
		paths = append(paths, containmentBoundary{src: srcNet, dst: external, fam: fam})
	}
	return e.evaluateRoutedAxis(n, archetype, "internet-egress", true, strict, policies, paths)
}

// evaluateLANInbound assesses inbound reachability from each trusted LAN into n
// across IPv4 and IPv6 using the exact boundary solver.
func (e containmentEvaluator) evaluateLANInbound(
	n unifi.Network,
	archetype string,
	strict bool,
	trusted []unifi.Network,
) (ContainmentAxis, []IsolationCell, []checks.Finding, []PostureNote) {
	var paths []containmentBoundary
	for _, src := range trusted {
		if strings.EqualFold(src.Name, n.Name) {
			continue
		}
		paths = append(paths, containmentBoundary{src: src, dst: n, fam: "ipv4"})
		if siteHasIPv6Context(e.snap, src, n, unifi.Client{}) {
			paths = append(paths, containmentBoundary{src: src, dst: n, fam: "ipv6"})
		}
	}
	return e.evaluateRoutedAxis(n, archetype, "lan-inbound", false, strict, e.policies, paths)
}

// evaluateRoutedAxis evaluates each directed boundary for both permit and deny
// counterexamples so a mixed policy resolves to "restricted" while an
// unconditional allow or deny requires complete coverage of the opposite action.
func (e containmentEvaluator) evaluateRoutedAxis(
	n unifi.Network,
	archetype, function string,
	isInternet, strict bool,
	basePolicies []unifi.FirewallPolicy,
	paths []containmentBoundary,
) (ContainmentAxis, []IsolationCell, []checks.Finding, []PostureNote) {
	var (
		cells    []IsolationCell
		findings []checks.Finding
		notes    []PostureNote
	)

	sort.SliceStable(paths, func(i, j int) bool {
		if paths[i].src.Name != paths[j].src.Name {
			return paths[i].src.Name < paths[j].src.Name
		}
		return paths[i].fam < paths[j].fam
	})

	type permittedPath struct {
		cell       IsolationCell
		unapproved bool
	}
	states := make(map[string]bool)
	var permitted []permittedPath

	for _, path := range paths {
		policies := make([]unifi.FirewallPolicy, 0, len(basePolicies))
		for _, p := range basePolicies {
			if !p.Enabled || !matchesIPFamily(p.IPVersion, path.fam) {
				continue
			}
			if p.Source.ZoneName != "" && !strings.EqualFold(p.Source.ZoneName, path.src.ZoneName) {
				continue
			}
			if p.Destination.ZoneName != "" && !strings.EqualFold(p.Destination.ZoneName, path.dst.ZoneName) {
				continue
			}
			policies = append(policies, p)
		}
		if isInternet && len(policies) == 1 && policies[0].UnsupportedReason != "" {
			states["unknown"] = true
			cells = append(cells, IsolationCell{
				SourceZone:    n.ZoneName,
				SourceNetwork: n.Name,
				DestZone:      "External",
				DestNetwork:   "Internet",
				DestFunction:  function,
				PathKind:      "gateway-routed",
				Enforcer:      e.gateway,
				IPFamily:      path.fam,
				Expected:      "deny",
				Effective:     "unknown",
				Verdict:       IsolationUnknown,
				MissingInput:  policies[0].UnsupportedReason,
			})
			continue
		}

		check := func(expected string, intent config.IsolationIntent) IsolationCell {
			c := evaluateBoundary(
				e.snap, e.rawFindings, policies, intent,
				e.gatewayOK, e.gatewayMissing, e.switchStatus, e.switchMissing, e.gateway,
				path.src, path.dst, path.src.ZoneName, path.dst.ZoneName, path.fam, expected, nil,
			)
			c.DestFunction = function
			return c
		}

		// Search for any permitted path first; if one exists, also search for a
		// blocked path to distinguish "restricted" from "open".
		permit := check("deny", config.IsolationIntent{})
		state := "unknown"
		switch permit.Verdict {
		case IsolationBlockedOK:
			state = "blocked"
		case IsolationViolation:
			deny := check("allow", config.IsolationIntent{})
			switch deny.Verdict {
			case IsolationBrokenDependency:
				state = "restricted"
			case IsolationApproved:
				state = "open"
			}
			unapproved := strict
			if strict && len(e.intent.ApprovedPaths) > 0 {
				exception := check("deny", e.intent)
				unapproved = exception.Verdict == IsolationViolation
				if unapproved {
					permit = exception
				} else if exception.Verdict == IsolationUnknown {
					cells = append(cells, exception)
					state = "unknown"
				}
			}
			permitted = append(permitted, permittedPath{cell: permit, unapproved: unapproved})
			if !unapproved {
				permit.Expected = "allow"
				permit.Verdict = IsolationApproved
			}
		}
		states[state] = true
		cells = append(cells, permit)
	}

	state := "unknown"
	if len(states) > 1 {
		state = "partial"
	} else {
		for s := range states {
			state = s
		}
	}
	stateDetails := map[string]string{
		"blocked":    "All evaluated paths are blocked",
		"open":       "All evaluated paths permit new connections",
		"restricted": "Policy permits some connections and blocks others",
		"partial":    "Access differs across source networks or address families",
		"unknown":    "Insufficient policy or routing evidence",
	}
	detail := stateDetails[state]

	// Preserve every proved permit on a mixed boundary even if another path is unknown.
	for _, p := range permitted {
		id, fix := "", ""
		var actions []string
		sev := checks.SeverityLow
		parity := false
		if !strict {
			for _, other := range cells {
				if other.SourceNetwork == p.cell.SourceNetwork && other.IPFamily != p.cell.IPFamily && other.Verdict == IsolationBlockedOK {
					parity = true
					break
				}
			}
		}
		if p.unapproved || parity {
			sev = checks.SeverityHigh
			if isInternet {
				id = "UB-UNIFI-ISO-INTERNET-LEAK"
				fix = "Block unapproved traffic to External across all enabled address families."
				actions = []string{"disable_network_internet_access", "block_external_egress"}
			} else {
				id = "UB-UNIFI-ISO-INBOUND-LEAK"
				fix = "Restrict inbound access to approved controllers and ports across all enabled address families."
				actions = []string{"restrict_inbound_to_isolated_zone"}
			}
		} else if !strict && (state == "open" || state == "partial") && (archetype == "iot" || archetype == "camera") {
			id = "UB-UNIFI-ISO-" + strings.ToUpper(archetype)
			if isInternet {
				id += "-INTERNET"
				fix = "Restrict outbound internet access to required services."
				actions = []string{"disable_network_internet_access"}
				if archetype == "camera" {
					sev = checks.SeverityMedium
				}
			} else {
				id += "-INBOUND"
				fix = "Restrict LAN access to the hosts and ports that manage these devices."
				actions = []string{"restrict_inbound_to_isolated_zone"}
			}
		}
		if id == "" {
			continue
		}

		c := p.cell
		evidence := fmt.Sprintf("%s -> %s permits %s %s via %s", c.SourceNetwork, c.DestNetwork, c.IPFamily, c.Transport, c.DecisiveRuleName)
		if c.Port != 0 {
			evidence += fmt.Sprintf(" (port %d)", c.Port)
		}
		if parity {
			for i := range cells {
				if cells[i].Effective == "allow" && cells[i].SourceNetwork == c.SourceNetwork && cells[i].IPFamily == c.IPFamily {
					cells[i].Expected = "deny"
					cells[i].Verdict = IsolationViolation
				}
			}
		}
		findings = append(findings, checks.Finding{
			CheckID:           id,
			Title:             evidence,
			Category:          "isolation-policy",
			ClaimKind:         checks.ClaimConfiguredAccess,
			Property:          function + "-" + strings.ToLower(n.Name) + "-" + c.SourceNetwork + "-" + c.IPFamily,
			Transport:         c.Transport,
			Port:              c.Port,
			Client:            unifi.Client{MAC: "vlan:" + n.ID, Name: n.Name, NetworkName: n.Name},
			BaseSeverity:      sev,
			EffectiveSeverity: sev,
			Evidence:          evidence,
			Remediation: checks.Remediation{
				Summary:      fix,
				UniFiActions: actions,
			},
		})
	}

	if !isInternet && archetype == "guest" && state == "open" {
		notes = append(notes, PostureNote{
			Severity: checks.SeverityLow,
			Title:    "Internal LAN can initiate connections into Guest network " + n.Name,
			Detail:   detail,
		})
	}
	violation := false
	for _, c := range cells {
		if c.Verdict == IsolationViolation || c.Verdict == IsolationBrokenDependency {
			violation = true
			break
		}
	}
	return ContainmentAxis{State: state, Detail: detail, Violation: violation}, cells, findings, notes
}
