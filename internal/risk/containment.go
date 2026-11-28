// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package risk

import (
	"cmp"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"sort"
	"strconv"
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

// Heuristic patterns used to infer an isolated network's workload archetype
// when explicit config lists and captive-portal signals do not decide it.
// The first tier classifies individual hosts during the client census from
// display names, hostnames, and vendor OUIs; the second tier falls back to
// network-level metadata (DHCP domain names and network/zone labels).
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
		if !n.MatchesIdentity(cl.NetworkID, cl.NetworkName) {
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
func (o *Oracle) evaluateNetworkContainment(
	rawFindings []checks.Finding,
	untrustedNets, trustedNets []unifi.Network,
	existingCells []IsolationCell,
) ([]NetworkContainment, []IsolationCell, []checks.Finding, []PostureNote) {
	snap, intent := o.snap, o.intent
	if len(untrustedNets) == 0 {
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

	routed := containmentEvaluator{Oracle: o, rawFindings: rawFindings}
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
		peerAxis, peerCells, peerFindings := o.evaluatePeerContainmentAxis(n)
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

// peerGap aggregates same-VLAN peer-isolation evidence for one attachment path
// kind (same-AP Wi-Fi, wired-to-wired, wired-to-AP, or cross-AP). Evaluated and
// permitted counters track attachment paths, while the matrix keeps individual
// per-family decision cells.
type peerGap struct {
	kind, property, title, unit, function string

	evaluated, permitted int
	clients              map[string]bool
	ports                map[checks.SwitchPortRef]string
	ssids                map[string]bool
	rules                map[[3]string]*peerPermit // switch MAC, rule ID, rule name
	requiresACL, limited bool
}

// peerPermit tracks how many evaluated IPv4 (v4) and IPv6 (v6) paths a given
// switch ACL or default forwarding disposition permitted, plus one directional
// example flow for named ACL exceptions (default forwarding needs no example).
type peerPermit struct {
	name, example string
	v4, v6        int
}

// peerFamilies formats the witnessed IPv4/IPv6 flags for display, defaulting
// to "IPv4" when neither flag is set.
func peerFamilies(v4, v6 bool) string {
	if v4 && v6 {
		return "IPv4 and IPv6"
	}
	if v6 {
		return "IPv6"
	}
	return "IPv4"
}

// comparePeerPorts orders switch ports deterministically by switch MAC and
// numeric port index.
func comparePeerPorts(a, b checks.SwitchPortRef) int {
	if n := cmp.Compare(a.SwitchMAC, b.SwitchMAC); n != 0 {
		return n
	}
	return cmp.Compare(a.PortIdx, b.PortIdx)
}

// peerLabel bounds controller-supplied labels in dashboard summaries.
func peerLabel(s string) string {
	if r := []rune(s); len(r) > 64 {
		return string(r[:61]) + "..."
	}
	return s
}

// peerList caps a sorted display list while keeping omitted items visible.
func peerList(items []string, limit int, noun string) string {
	if len(items) > limit {
		omitted := len(items) - limit
		if omitted == 1 {
			noun = strings.TrimSuffix(noun, "s")
		}
		return fmt.Sprintf("%s, +%d more %s", strings.Join(items[:limit], ", "), omitted, noun)
	}
	if len(items) == 2 {
		return items[0] + " and " + items[1]
	}
	return strings.Join(items, ", ")
}

// peerPortList groups switch ports by switch and caps the total ports shown
// across switches. The caller sorts by switch MAC and numeric port index so
// trimming is deterministic.
func peerPortList(snap *unifi.Snapshot, refs []checks.SwitchPortRef, labels map[checks.SwitchPortRef]string, limit int) string {
	var groups []string
	shown := refs[:min(limit, len(refs))]
	for len(shown) > 0 {
		sw := shown[0].SwitchMAC
		var numbers []string
		for len(shown) > 0 && shown[0].SwitchMAC == sw {
			ref := shown[0]
			number := strconv.Itoa(ref.PortIdx)
			if label := labels[ref]; label != "" {
				number += " (" + peerLabel(label) + ")"
			}
			numbers = append(numbers, number)
			shown = shown[1:]
		}
		noun := " port "
		if len(numbers) > 1 {
			noun = " ports "
		}
		groups = append(groups, peerLabel(deviceNameByMAC(snap, sw))+noun+peerList(numbers, limit, "ports"))
	}
	if len(refs) > limit {
		noun := "ports"
		if len(refs)-limit == 1 {
			noun = "port"
		}
		groups = append(groups, fmt.Sprintf("+%d more %s", len(refs)-limit, noun))
	}
	return strings.Join(groups, ", ")
}

// peerRemediation builds switch-isolation remediation guidance. It recommends
// enabling Switch Port Isolation only when ports is non-empty (meaning access-port
// isolation alone closes every reported crossing), and adds ACL-narrowing steps
// whenever named permit exceptions exist.
func peerRemediation(network, families, ports, exceptions string, defaultAllow bool) checks.Remediation {
	var steps, actions []string
	if defaultAllow {
		acl := "a " + peerLabel(network) + " peer isolation ACL covering " + families
		if ports == "" {
			steps = append(steps, "Apply "+acl+".")
		} else {
			steps = append(steps, "Enable Switch Port Isolation on "+ports+", or apply "+acl+".")
			actions = append(actions, "enable_switch_port_isolation")
		}
		actions = append(actions, "add_switch_l2_isolation_acl")
	}
	if exceptions != "" {
		steps = append(steps, "Narrow "+exceptions+" and ensure remaining peer traffic on "+peerLabel(network)+" is denied.")
		actions = append(actions, "restrict_switch_acl")
	}
	return checks.Remediation{Summary: strings.Join(steps, " "), UniFiActions: actions}
}

// recordPermit increments the permitting rule's per-family path counter, saves
// a representative directional witness for named ACL exceptions, and populates
// cell.DecisiveReason and cell.RecommendedFix. The caller invokes it once per
// distinct rule on a pair and family even when both directions match.
func (g *peerGap) recordPermit(cell *IsolationCell, sw, from, to, fixPorts string) {
	key := [3]string{sw, cell.DecisiveRuleID, cell.DecisiveRuleName}
	rule := g.rules[key]
	if rule == nil {
		name := firstNonEmptyStr(cell.DecisiveRuleName, cell.DecisiveRuleID, "Unnamed switch ACL")
		rule = &peerPermit{name: peerLabel(name)}
		g.rules[key] = rule
	}
	if cell.IPFamily == "ipv4" {
		rule.v4++
	} else {
		rule.v6++
	}
	protocol := strings.ToUpper(cell.Transport)
	if cell.Port != 0 {
		protocol += "/" + strconv.Itoa(cell.Port)
	}
	family := peerFamilies(cell.IPFamily == "ipv4", cell.IPFamily == "ipv6")
	witness := fmt.Sprintf("%s %s from %s to %s", family, protocol, from, to)
	cell.DecisiveReason = rule.name + " permits " + witness
	isDefault := cell.DecisiveRuleID == "" && cell.DecisiveRuleName == "Switch L2/L3 Default"
	var exception string
	if !isDefault {
		exception = rule.name
		if rule.example == "" {
			rule.example = witness
		}
	}
	cell.RecommendedFix = peerRemediation(cell.SourceNetwork, family, fixPorts, exception, isDefault).Summary
}

// finding renders one VLAN-owned alert and a shorter containment-axis detail.
// Only the display lists are capped; entity references remain complete.
func (g *peerGap) finding(snap *unifi.Snapshot, n unifi.Network) (checks.Finding, string) {
	f := checks.Finding{
		CheckID:            "UB-UNIFI-ISO-SAME-VLAN",
		Title:              g.title + " peer isolation gap on " + n.Name,
		Category:           "isolation-policy",
		ClaimKind:          checks.ClaimConfiguredAccess,
		Property:           "isolation-" + g.property + "-" + strings.ToLower(n.Name),
		BaseSeverity:       checks.SeverityMedium,
		EffectiveSeverity:  checks.SeverityMedium,
		Client:             unifi.Client{MAC: "vlan:" + n.ID, Name: n.Name, NetworkName: n.Name},
		AffectedClientMACs: slices.Sorted(maps.Keys(g.clients)),
	}
	if len(g.ssids) > 0 {
		names := slices.Sorted(maps.Keys(g.ssids))
		for i := range names {
			names[i] = peerLabel(names[i])
		}
		ssids := "SSID "
		if len(names) > 1 {
			ssids = "SSIDs "
		}
		detail := "Client Device Isolation is off on " + ssids
		f.Evidence = detail + peerList(names, 6, "SSIDs") + "."
		f.Remediation = checks.Remediation{
			Summary:      "Enable Client Device Isolation on " + peerList(names, 6, "SSIDs") + ".",
			UniFiActions: []string{"enable_wlan_l2_isolation"},
		}
		return f, detail + peerList(names, 2, "SSIDs") + "."
	}

	unit := g.unit
	if g.limited {
		unit = "evaluated " + unit
	}
	paths := fmt.Sprintf("%d of %d %ss", g.permitted, g.evaluated, unit)
	count := paths + " permit traffic."
	if g.permitted == 1 {
		count = paths + " permits traffic."
	}
	if g.evaluated == 1 {
		paths = "the evaluated " + unit
		count = "The evaluated " + unit + " permits traffic."
	}
	refs := slices.SortedFunc(maps.Keys(g.ports), comparePeerPorts)
	f.AffectedSwitchPorts = refs
	detail := count
	var evidence []string
	var fixPorts string
	if len(refs) > 0 {
		evidence = append(evidence, "Switch Port Isolation is off on "+peerPortList(snap, refs, g.ports, 6)+".")
		detail += " Port isolation is off on " + peerPortList(snap, refs, nil, 2) + "."
		if !g.requiresACL {
			fixPorts = peerPortList(snap, refs, nil, 6)
		}
	}

	var permits, exceptions []string
	var v4, v6, defaultAllow, countInRule bool
	for key, rule := range g.rules {
		families := peerFamilies(rule.v4 > 0, rule.v6 > 0)
		v4, v6 = v4 || rule.v4 > 0, v6 || rule.v6 > 0
		name := rule.name
		if len(g.rules) > 1 {
			name += " on " + peerLabel(deviceNameByMAC(snap, key[0]))
		}
		desc := name + " permits " + families + " traffic"
		if rule.example != "" {
			desc += " (e.g. " + rule.example + ")"
			exceptions = append(exceptions, name)
		} else {
			defaultAllow = true
			// Combine the count with the rule only if every named family
			// was permitted on every one of the counted paths.
			if len(g.rules) == 1 && (rule.v4 == 0 || rule.v4 == g.permitted) && (rule.v6 == 0 || rule.v6 == g.permitted) {
				desc += " across " + paths
				countInRule = true
			}
		}
		permits = append(permits, desc)
	}
	if !countInRule {
		evidence = append(evidence, count)
	}
	slices.Sort(permits)
	evidence = append(evidence, peerList(permits, 6, "rules")+".")
	f.Evidence = strings.Join(evidence, " ")
	if len(refs) == 0 {
		if countInRule {
			detail = peerList(permits, 2, "rules") + "."
		} else {
			detail += " " + peerList(permits, 2, "rules") + "."
		}
	}
	slices.Sort(exceptions)
	f.Remediation = peerRemediation(n.Name, peerFamilies(v4, v6), fixPorts, peerList(exceptions, 6, "rules"), defaultAllow)
	return f, detail
}

// evaluatePeerContainmentAxis assesses Layer-2 client-to-client isolation on n
// across same-AP Wi-Fi l2_isolation, wired switch port isolation, mixed wired-to-AP
// paths, cross-AP uplinks, and directional IPv4/IPv6 switch ACLs.
func (o *Oracle) evaluatePeerContainmentAxis(n unifi.Network) (ContainmentAxis, []IsolationCell, []checks.Finding) {
	snap := o.snap
	var wired []peerAttachment
	aps := slices.Clone(o.apUplinks)
	wiredCount := make(map[checks.SwitchPortRef]int)
	seenClients := make(map[string]bool)
	wifiClients, unresolvedMedium := false, false
	apMACs := make(map[string][]string)
	for _, cl := range snap.Clients {
		if !n.MatchesIdentity(cl.NetworkID, cl.NetworkName) {
			continue
		}
		if cl.IsWired {
			ref := portRef(cl.SwitchMAC, cl.SwitchPort)
			cl.MAC = strings.ToLower(strings.TrimSpace(cl.MAC))
			id := firstNonEmptyStr(cl.MAC, cl.PrimaryIP())
			if id != "" && seenClients[id] {
				continue
			}
			seenClients[id] = true
			wiredCount[ref]++
			wired = append(wired, peerAttachment{label: cl.DisplayName(), ref: ref, client: cl})
		} else if cl.APMAC != "" || cl.ESSID != "" {
			wifiClients = true
			if mac, ok := config.ParseCanonicalMAC(cl.APMAC); ok {
				apMACs[cl.ESSID] = append(apMACs[cl.ESSID], mac)
			}
		} else {
			unresolvedMedium = true
		}
	}

	wiredGap := peerGap{kind: "wired-same-vlan", property: "wired", title: "Same-VLAN wired", unit: "wired peer pair", function: "same-vlan-wired-peers"}
	mixed := peerGap{kind: "mixed-same-vlan", property: "mixed", title: "Wired-to-Wi-Fi", unit: "wired-to-AP path", function: "same-vlan-mixed-peers"}
	crossAP := peerGap{kind: "cross-ap-wifi", property: "cross-ap", title: "Cross-AP Wi-Fi", unit: "cross-AP path", function: "cross-ap-wifi-peers"}
	sameAP := peerGap{kind: "same-ap-wifi", property: "same-ap", title: "Same-AP Wi-Fi", ssids: make(map[string]bool)}
	gaps := []*peerGap{&crossAP, &mixed, &sameAP, &wiredGap}
	for _, g := range gaps {
		g.clients = make(map[string]bool)
		g.ports = make(map[checks.SwitchPortRef]string)
		g.rules = make(map[[3]string]*peerPermit)
	}
	var cells []IsolationCell
	var findings []checks.Finding
	coverage := make(map[string]bool)
	allowed, blocked, unknown := false, false, false
	zone := firstNonEmptyStr(n.ZoneName, n.Name)
	// Stamp network/zone metadata onto each cell and roll its verdict into the
	// axis posture flags independently of the per-gap finding summaries.
	record := func(c IsolationCell) {
		c.SourceZone, c.DestZone = zone, zone
		c.SourceNetwork, c.DestNetwork = n.Name, n.Name
		c.Expected = "deny"
		cells = append(cells, c)
		switch c.Verdict {
		case IsolationBlockedOK:
			blocked = true
		case IsolationUnknown:
			unknown = true
		case IsolationViolation:
			allowed = true
		}
	}

	// Step 1: Evaluate same-AP Wi-Fi client device isolation on enabled SSIDs.
	hasWiFi := false
	for _, wlan := range snap.WLANs {
		if !wlan.Enabled || !strings.EqualFold(wlan.NetworkName, n.Name) {
			continue
		}
		hasWiFi = true
		c := o.sameAP(wlan)
		c.EnforcerMACs = dedupeSortedStrings(apMACs[wlan.Name])
		record(c)
		if c.Verdict == IsolationViolation {
			sameAP.ssids[firstNonEmptyStr(wlan.Name, wlan.ID, "unnamed SSID")] = true
			sameAP.permitted++
		} else if c.Verdict == IsolationUnknown {
			coverage["current WLAN isolation settings"] = true
		}
	}
	if unresolvedMedium || (wifiClients && (!hasWiFi || len(aps) == 0)) {
		coverage["peer attachments"] = true
		record(IsolationCell{
			PathKind:     "peer-attachment",
			Effective:    "unknown",
			Verdict:      IsolationUnknown,
			MissingInput: "Controller did not resolve all peer attachments on " + n.Name,
		})
	}

	// Detect downstream unmanaged switches or hubs behind a non-infrastructure
	// access port: peers sharing that segment can switch locally without
	// reaching the upstream UniFi switch. Record that uncertainty once so it
	// stays separate from cross-port flows the upstream switch can block.
	shared := make(map[checks.SwitchPortRef]bool)
	var downstream []checks.SwitchPortRef
	for _, ref := range slices.SortedFunc(maps.Keys(wiredCount), comparePeerPorts) {
		count := wiredCount[ref]
		p := o.ports[ref]
		if ref.SwitchMAC == "" || ref.PortIdx <= 0 || o.infrastructure[ref] {
			continue
		}
		// Only use MACTableCount > 1 on single-client ports when upstream port
		// isolation is known and enabled: an unisolated or unknown port already
		// surfaces through normal peer evaluation, whereas an isolated port
		// would otherwise mask unverified local switching behind a downstream hub.
		if count <= 1 && (p.IsolationUnknown || !p.Isolation || p.MACTableCount <= 1) {
			continue
		}
		shared[ref] = true
		socket := fmt.Sprintf("%s port %d", peerLabel(deviceNameByMAC(snap, ref.SwitchMAC)), ref.PortIdx)
		reason := fmt.Sprintf("%d attached clients", count)
		if p.MACTableCount > 1 {
			reason = fmt.Sprintf("%d learned MACs", p.MACTableCount)
		}
		downstream = append(downstream, ref)
		record(IsolationCell{
			PathKind:       wiredGap.kind,
			DestFunction:   wiredGap.function,
			IPFamily:       "both",
			Transport:      "all",
			Verdict:        IsolationUnknown,
			Effective:      "unknown",
			MissingInput:   "Downstream peer isolation is unverified on " + socket + " (" + reason + ").",
			RecommendedFix: "Verify downstream isolation or move peers to separate isolated access ports.",
		})
	}

	families := []string{"ipv4"}
	if siteHasIPv6Context(snap, n, n, unifi.Client{}, true) {
		families = append(families, "ipv6")
	}
	// Evaluate switch port isolation and directional ACLs for a pair of
	// attachments crossing the switch fabric. When single is true (only one
	// wired client exists on the VLAN), model a client-to-arbitrary-VLAN-peer
	// path by leaving the destination endpoint unconstrained.
	evaluatePair := func(a, b peerAttachment, g *peerGap, single bool) {
		g.evaluated++
		if a.ref == b.ref && shared[a.ref] {
			return
		}
		path := o.peerLabel(a)
		if !single {
			path += " and " + o.peerLabel(b)
		}
		cell, gap := o.peerPorts(a.ref, b.ref, path, single)
		if cell.Effective != "" {
			cell.PathKind, cell.DestFunction = g.kind, g.function
			record(cell)
			if gap != "" {
				coverage[gap] = true
			}
			return
		}
		endpoints := []peerAttachment{a}
		if !single {
			endpoints = append(endpoints, b)
		}
		var fixPorts []peerAttachment
		requiresACL := false
		for _, x := range endpoints {
			if o.ports[x.ref].Isolation {
				continue
			}
			if x.client.IsWired && !o.infrastructure[x.ref] {
				fixPorts = append(fixPorts, x)
			} else {
				// Enabling isolation on an AP trunk affects every carried VLAN.
				requiresACL = true
			}
		}
		var names []string
		if !requiresACL {
			for _, x := range fixPorts {
				names = append(names, o.peerLabel(x))
			}
		}
		fixSockets := strings.Join(names, " and ")
		knownPorts := o.peerPortSettingsKnown(a.ref, b.ref)
		permitted := false
		for _, fam := range families {
			// A lone client and an AP both leave one side of the ACL query network-wide.
			checkDir := func(src, dst peerAttachment) IsolationCell {
				peers := peerEndpoints{src: src.client, dst: dst.client}
				if single {
					peers.dst = unifi.Client{}
				}
				return o.peerACL(n, peers, a.ref.SwitchMAC, fam, "", 0)
			}
			from, to := o.peerLabel(a), o.peerLabel(b)
			cell := checkDir(a, b)
			if single {
				to = "a VLAN peer"
			} else if cell.Verdict != IsolationViolation || len(snap.SwitchACLs) > 0 {
				// Skip the reverse probe on default-allow when no switch ACLs
				// exist, since default switch forwarding behaves identically in
				// both directions and cannot reveal a second named rule.
				reverse := checkDir(b, a)
				// Keep one matrix cell per family. A different permitting ACL in
				// the other direction is also relevant to the operator's fix.
				if cell.Verdict == IsolationViolation {
					if knownPorts && reverse.Verdict == IsolationViolation &&
						(reverse.DecisiveRuleID != cell.DecisiveRuleID || reverse.DecisiveRuleName != cell.DecisiveRuleName) {
						g.recordPermit(&reverse, a.ref.SwitchMAC, to, from, fixSockets)
					}
				} else if reverse.Verdict == IsolationViolation || reverse.Verdict == IsolationUnknown {
					cell, from, to = reverse, to, from
				}
			}
			cell.PathKind, cell.DestFunction = g.kind, g.function
			if unknownPeerPorts(&cell, knownPorts, path) {
				coverage["effective switch port settings"] = true
			} else if cell.Verdict == IsolationUnknown {
				coverage[peerLabel(cell.MissingInput)] = true
			}
			if cell.Verdict == IsolationViolation {
				permitted = true
				g.recordPermit(&cell, a.ref.SwitchMAC, from, to, fixSockets)
			}
			record(cell)
		}
		if permitted {
			g.permitted++
			g.requiresACL = g.requiresACL || requiresACL
			for _, x := range endpoints {
				if x.client.MAC != "" {
					g.clients[x.client.MAC] = true
				}
			}
			for _, x := range fixPorts {
				if wiredCount[x.ref] > 1 {
					g.ports[x.ref] = o.ports[x.ref].Name
				} else {
					g.ports[x.ref] = x.label
				}
			}
		}
	}

	sort.Slice(wired, func(i, j int) bool {
		return firstNonEmptyStr(wired[i].client.MAC, wired[i].label) < firstNonEmptyStr(wired[j].client.MAC, wired[j].label)
	})
	sort.Slice(aps, func(i, j int) bool {
		if order := comparePeerPorts(aps[i].ref, aps[j].ref); order != 0 {
			return order < 0
		}
		return aps[i].label < aps[j].label
	})

	// Step 2: Evaluate wired-to-wired, mixed wired-to-AP, and cross-AP pairs.
	// Cap the quadratic pair space on large sites while preserving already-found
	// violations and marking overflow explicitly as unverified.
	const maxPeerPaths = 2048
	pathCount := 0
	limitReached := false
	checkPair := func(a, b peerAttachment, g *peerGap, single bool) bool {
		if pathCount == maxPeerPaths {
			limitReached = true
			g.limited = true
			record(IsolationCell{
				PathKind:     g.kind,
				Effective:    "unknown",
				Verdict:      IsolationUnknown,
				MissingInput: "Peer path evaluation limit reached",
			})
			return false
		}
		pathCount++
		evaluatePair(a, b, g, single)
		return true
	}

evalPairs:
	for i, a := range wired {
		if len(wired) == 1 {
			wiredGap.unit = "wired client-to-VLAN path"
			if !checkPair(a, a, &wiredGap, true) {
				break evalPairs
			}
		}
		for _, b := range wired[i+1:] {
			if !checkPair(a, b, &wiredGap, false) {
				break evalPairs
			}
		}
		if wifiClients {
			for _, b := range aps {
				if !checkPair(a, b, &mixed, false) {
					break evalPairs
				}
			}
		}
	}
	if hasWiFi && !limitReached {
	evalAPs:
		for i, a := range aps {
			for _, b := range aps[i+1:] {
				if !checkPair(a, b, &crossAP, false) {
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

	var details []string
	for _, g := range gaps {
		if g.permitted > 0 {
			f, detail := g.finding(snap, n)
			findings = append(findings, f)
			details = append(details, detail)
		}
	}
	if len(downstream) > 0 {
		details = append(details, "Downstream peer isolation is unverified on "+peerPortList(snap, downstream, nil, 2)+".")
	}
	if len(coverage) > 0 {
		details = append(details, "Unverified peer evidence ("+peerList(slices.Sorted(maps.Keys(coverage)), 2, "coverage gaps")+").")
	}
	if limitReached {
		details = append(details, "Peer path evaluation limit reached.")
	}
	if len(details) == 0 {
		if blocked {
			details = append(details, "Peer isolation verified for the evaluated paths")
		} else {
			details = append(details, "No peer attachment evidence")
		}
	}
	return ContainmentAxis{State: state, Detail: strings.Join(details, " "), Violation: allowed}, cells, findings
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
	*Oracle
	rawFindings []checks.Finding
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
	if siteHasIPv6Context(e.snap, n, n, unifi.Client{}, false) {
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
				Enforcer:      e.gwName,
				EnforcerMACs:  enforcerMACs(e.gwMAC),
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
	policies := e.policiesWithExternalDefault(n)

	// External traffic always traverses the gateway even for switch-routed VLANs.
	srcNet := n
	srcNet.RouterDeviceMAC, srcNet.RouterUnresolved = "", false
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
		if siteHasIPv6Context(e.snap, src, n, unifi.Client{}, false) {
			paths = append(paths, containmentBoundary{src: src, dst: n, fam: "ipv6"})
		}
	}
	return e.evaluateRoutedAxis(n, archetype, "lan-inbound", false, strict, e.sortedPolicies, paths)
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
		// If internet egress has only the synthetic trailing "External default"
		// rule and its UnsupportedReason is populated (no explicit External
		// policies matched and the controller omitted InternetAccessEnabled),
		// emit IsolationUnknown directly rather than running the solver.
		if isInternet && len(policies) == 1 && policies[0].UnsupportedReason != "" {
			states["unknown"] = true
			cells = append(cells, IsolationCell{
				SourceZone:    n.ZoneName,
				SourceNetwork: n.Name,
				DestZone:      "External",
				DestNetwork:   "Internet",
				DestFunction:  function,
				PathKind:      "gateway-routed",
				Enforcer:      e.gwName,
				EnforcerMACs:  enforcerMACs(e.gwMAC),
				IPFamily:      path.fam,
				Expected:      "deny",
				Effective:     "unknown",
				Verdict:       IsolationUnknown,
				MissingInput:  policies[0].UnsupportedReason,
			})
			continue
		}

		// Use the path's filtered rules, including the External fallback on egress.
		scoped := *e.Oracle
		scoped.sortedPolicies = policies
		check := func(expected string, intent config.IsolationIntent) IsolationCell {
			c := scoped.evaluateBoundary(e.rawFindings, intent,
				path.src, path.dst, path.src.ZoneName, path.dst.ZoneName, path.fam, expected, nil)
			c.DestFunction = function
			return c
		}

		// Two-pass counterexample search: first ask whether any flow is
		// permitted (expected="deny"). If a permit exists, invert the query
		// (expected="allow") to see whether any flow is blocked, distinguishing
		// "restricted" (some flows blocked) from "open" (every flow allowed).
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
			// Under strict mode, re-evaluate with configured ApprovedPaths so
			// only traffic outside approved pinholes remains an unapproved leak
			// (and any evaluation uncertainty stays visible as IsolationUnknown).
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
		// Even without explicit strict mode, blocking one IP family while
		// leaving the other open on the same source network indicates operator
		// intent to block this boundary, so escalate the open family as a High
		// dual-stack leak.
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
		// Flip matching allow cells to IsolationViolation when dual-stack
		// parity escalation applies so the matrix and axis Violation flag
		// stay consistent with the emitted High leak finding.
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
