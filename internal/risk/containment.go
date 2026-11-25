// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package risk

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/unifi"
)

// ContainmentAxis summarizes one enforcement dimension of an isolated network.
type ContainmentAxis struct {
	State  string `json:"state"`            // "blocked" | "isolated" | "restricted" | "partial" | "open" | "unknown"
	Detail string `json:"detail,omitempty"` // concise human-readable evidence
}

// NetworkContainment captures the 4-axis containment posture and automatically
// inferred archetype ("guest", "iot", "camera", "isolated") for one isolated network.
type NetworkContainment struct {
	NetworkID       string          `json:"network_id,omitempty"`
	NetworkName     string          `json:"network_name"`
	VLAN            string          `json:"vlan,omitempty"`
	ZoneName        string          `json:"zone_name,omitempty"`
	Archetype       string          `json:"archetype"` // "guest" | "iot" | "camera" | "isolated"
	ArchetypeReason string          `json:"archetype_reason,omitempty"`
	Peers           ContainmentAxis `json:"peers"`           // Wi-Fi L2, wired port isolation, cross-AP switch ACLs
	LANEgress       ContainmentAxis `json:"lan_egress"`      // VLAN -> Internal / Gateway
	InternetEgress  ContainmentAxis `json:"internet_egress"` // VLAN -> External (internet)
	LANInbound      ContainmentAxis `json:"lan_inbound"`     // Internal -> VLAN
	SharedZoneWith  []string        `json:"shared_zone_with,omitempty"`
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
// LAN Egress, Internet Egress, LAN Inbound) for every isolated/untrusted VLAN,
// emitting targeted findings for real leaks/gaps and archetype-appropriate
// recommendations without false alarms on Guest Wi-Fi.
func evaluateNetworkContainment(
	snap *unifi.Snapshot,
	sortedPolicies []unifi.FirewallPolicy,
	intent config.IsolationIntent,
	gwPoliciesAvailable bool,
	gwMissingReason string,
	switchACLStatus, switchACLReason, gwName, gwIP string,
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

	// Index switch port isolation, MAC counts, and site AP uplinks.
	portIso := make(map[string]bool)
	portMACCount := make(map[string]int)
	var siteAPs []unifi.Device
	for _, d := range snap.Devices {
		dm := strings.ToLower(strings.TrimSpace(d.MAC))
		for _, p := range d.Ports {
			k := fmt.Sprintf("%s|%d", dm, p.PortIdx)
			portIso[k] = p.Isolation
			portMACCount[k] = p.MACTableCount
		}
		if strings.EqualFold(d.Type, "uap") {
			siteAPs = append(siteAPs, d)
		}
	}

	// Check whether all site APs share one switch on distinct isolated uplink ports.
	allAPUplinksIsolated := len(siteAPs) >= 2
	if allAPUplinksIsolated {
		apSwitches := make(map[string]struct{})
		apPorts := make(map[string]struct{})
		for _, ap := range siteAPs {
			um := strings.ToLower(strings.TrimSpace(ap.UplinkMAC))
			if um == "" || ap.UplinkPort <= 0 {
				allAPUplinksIsolated = false
				break
			}
			apSwitches[um] = struct{}{}
			pk := fmt.Sprintf("%s|%d", um, ap.UplinkPort)
			if !portIso[pk] {
				allAPUplinksIsolated = false
				break
			}
			if _, dup := apPorts[pk]; dup {
				allAPUplinksIsolated = false
				break
			}
			apPorts[pk] = struct{}{}
		}
		if len(apSwitches) != 1 {
			allAPUplinksIsolated = false
		}
	}

	// Track existing same-VLAN findings/cells so we never duplicate alerts emitted
	// by evaluateSameVLANPeerIsolation when RequireSameVLANIsolation is set.
	existingCrossAPCell := make(map[string]bool)
	existingWiredCell := make(map[string]bool)
	for _, c := range existingCells {
		k := strings.ToLower(c.SourceNetwork)
		switch c.PathKind {
		case "cross-ap-wifi":
			existingCrossAPCell[k] = true
		case "wired-same-vlan":
			existingWiredCell[k] = true
		}
	}

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

		// --- Axis 1: Peer-to-peer L2 isolation (Wi-Fi, wired, cross-AP) ---
		peerAxis, peerCells, peerFindings := evaluatePeerContainmentAxis(
			snap, n, zoneLabel, switchACLStatus, switchACLReason,
			portIso, portMACCount, siteAPs, allAPUplinksIsolated,
			existingCrossAPCell[nLow], existingWiredCell[nLow],
		)
		nc.Peers = peerAxis
		cells = append(cells, peerCells...)
		findings = append(findings, peerFindings...)

		// --- Axis 2: LAN Egress (VLAN -> Internal / Gateway) ---
		nc.LANEgress = summarizeLANEgressAxis(n.Name, existingCells)

		// --- Axis 3: Internet Egress (VLAN -> External) ---
		_, explicitNoInet := noInternetSet[nLow]
		if !explicitNoInet && n.VLAN != "" {
			_, explicitNoInet = noInternetSet[strings.ToLower(n.VLAN)]
		}
		inetAxis, inetCells, inetFindings, inetNotes := evaluateInternetEgressAxis(
			snap, sortedPolicies, gwPoliciesAvailable, gwMissingReason,
			gwName, gwIP, n, zoneLabel, ent.archetype, explicitNoInet,
		)
		nc.InternetEgress = inetAxis
		cells = append(cells, inetCells...)
		findings = append(findings, inetFindings...)
		notes = append(notes, inetNotes...)

		// --- Axis 4: LAN Inbound (Internal -> VLAN) ---
		_, explicitStrictIn := strictInboundSet[nLow]
		if !explicitStrictIn && n.VLAN != "" {
			_, explicitStrictIn = strictInboundSet[strings.ToLower(n.VLAN)]
		}
		inAxis, inCells, inFindings, inNotes := evaluateLANInboundAxis(
			snap, sortedPolicies, gwPoliciesAvailable, gwMissingReason,
			gwName, gwIP, n, zoneLabel, ent.archetype, explicitStrictIn, trustedNets,
		)
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
// across Wi-Fi SSID l2_isolation, wired switch port isolation, AP uplink port
// isolation, and switch ACLs.
func evaluatePeerContainmentAxis(
	snap *unifi.Snapshot,
	n unifi.Network,
	zoneLabel, switchACLStatus, switchACLReason string,
	portIso map[string]bool,
	portMACCount map[string]int,
	siteAPs []unifi.Device,
	allAPUplinksIsolated bool,
	hasCrossAPCell, hasWiredCell bool,
) (ContainmentAxis, []IsolationCell, []checks.Finding) {
	var cells []IsolationCell
	var findings []checks.Finding
	nLow := strings.ToLower(strings.TrimSpace(n.Name))

	var wifiIso, wifiOpen []string
	for _, w := range snap.WLANs {
		if !w.Enabled || !strings.EqualFold(w.NetworkName, n.Name) {
			continue
		}
		if w.L2Isolation {
			wifiIso = append(wifiIso, w.Name)
		} else {
			wifiOpen = append(wifiOpen, w.Name)
		}
	}

	var wiredClients []unifi.Client
	wiredSwitches := make(map[string]struct{})
	wiredIsoCount := 0
	wiredOpenCount := 0
	seenPort := make(map[string]struct{})
	for _, cl := range snap.Clients {
		if !strings.EqualFold(cl.NetworkName, n.Name) || !cl.IsWired {
			continue
		}
		wiredClients = append(wiredClients, cl)
		sm := strings.ToLower(strings.TrimSpace(cl.SwitchMAC))
		if sm != "" {
			wiredSwitches[sm] = struct{}{}
		}
		pk := fmt.Sprintf("%s|%d", sm, cl.SwitchPort)
		_, dupPort := seenPort[pk]
		seenPort[pk] = struct{}{}
		if sm != "" && cl.SwitchPort > 0 && portIso[pk] && portMACCount[pk] <= 1 && !dupPort {
			wiredIsoCount++
		} else {
			wiredOpenCount++
		}
	}
	allWiredPortIsolated := len(wiredClients) > 0 && len(wiredSwitches) == 1 && wiredOpenCount == 0

	// Evaluate switch ACL intra-VLAN peer blocking if complete ACLs are available.
	aclBlocksPeers := false
	var aclDec policyDecision
	if switchACLStatus == "complete" {
		aclDec = evaluateSwitchACLs(snap.SwitchACLs, "", pathQuery{
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
		aclBlocksPeers = aclDec.action == "deny"
	}

	hasWiFi := len(wifiIso)+len(wifiOpen) > 0
	multiAP := hasWiFi && len(siteAPs) >= 2
	// UniFi's network-level "Isolate Network" flag (IsolationEnabled) enforces
	// Layer-3 gateway rules between VLANs, NOT Layer-2 same-VLAN switching on
	// UniFi switches. Cross-AP and wired peer isolation requires either switch
	// port isolation (single switch) or an explicit L2 switch deny ACL.
	crossAPIsolated := !multiAP || allAPUplinksIsolated || aclBlocksPeers

	// Emit cross-AP violation when switch ACLs are known complete and do not isolate peers.
	if multiAP && !crossAPIsolated && switchACLStatus == "complete" && !hasCrossAPCell {
		c := IsolationCell{
			SourceZone:       zoneLabel,
			SourceNetwork:    n.Name,
			DestZone:         zoneLabel,
			DestNetwork:      n.Name,
			DestFunction:     "cross-ap-wifi-peers",
			Transport:        "all",
			IPFamily:         "ipv4",
			PathKind:         "cross-ap-wifi",
			Enforcer:         "UniFi Switch (L2 Switch ACL)",
			Expected:         "deny",
			Effective:        "allow",
			Verdict:          IsolationViolation,
			DecisiveRuleName: aclDec.ruleName,
			DecisiveReason:   fmt.Sprintf("%d APs serve %s without switch ACL or AP uplink port isolation", len(siteAPs), n.Name),
			RecommendedFix:   fmt.Sprintf("Add a switch L2 ACL blocking intra-VLAN peer traffic on %s or enable Port Isolation on AP switch uplinks.", n.Name),
		}
		cells = append(cells, c)
		findings = append(findings, checks.Finding{
			CheckID:           "UB-UNIFI-ISO-SAME-VLAN",
			Title:             fmt.Sprintf("Cross-AP Wi-Fi Peer Traffic Permitted on %s", n.Name),
			Category:          "isolation-policy",
			ClaimKind:         checks.ClaimConfiguredAccess,
			Property:          "isolation-cross-ap-" + nLow,
			BaseSeverity:      checks.SeverityMedium,
			EffectiveSeverity: checks.SeverityMedium,
			Client:            unifi.Client{MAC: "vlan:" + n.ID, Name: n.Name, NetworkName: n.Name},
			Evidence:          fmt.Sprintf("%d APs serve %s with un-isolated AP uplinks and 0 blocking switch ACLs (%s)", len(siteAPs), n.Name, aclDec.ruleName),
			Remediation: checks.Remediation{
				Summary:      c.RecommendedFix,
				UniFiActions: []string{"add_switch_l2_isolation_acl", "enable_switch_port_isolation"},
			},
		})
	}

	// Emit wired peer violation when wired clients sit on un-isolated ports and
	// switch ACLs are known complete without a deny ACL.
	if len(wiredClients) > 0 && !allWiredPortIsolated && !aclBlocksPeers && switchACLStatus == "complete" && !hasWiredCell {
		c := IsolationCell{
			SourceZone:       zoneLabel,
			SourceNetwork:    n.Name,
			DestZone:         zoneLabel,
			DestNetwork:      n.Name,
			DestFunction:     "same-vlan-wired-peers",
			Transport:        "all",
			IPFamily:         "ipv4",
			PathKind:         "wired-same-vlan",
			Enforcer:         "UniFi Switch (L2 Port Isolation / ACL)",
			Expected:         "deny",
			Effective:        "allow",
			Verdict:          IsolationViolation,
			DecisiveRuleName: aclDec.ruleName,
			DecisiveReason:   fmt.Sprintf("%d wired client(s) on %s lack switch port isolation and switch ACLs do not block peer traffic", wiredOpenCount, n.Name),
			RecommendedFix:   fmt.Sprintf("Enable Switch Port Isolation on wired %s ports or add a switch L2 ACL blocking intra-VLAN peers.", n.Name),
		}
		cells = append(cells, c)
		findings = append(findings, checks.Finding{
			CheckID:           "UB-UNIFI-ISO-SAME-VLAN",
			Title:             fmt.Sprintf("Same-VLAN Wired Peer Traffic Permitted on %s", n.Name),
			Category:          "isolation-policy",
			ClaimKind:         checks.ClaimConfiguredAccess,
			Property:          "isolation-wired-" + nLow,
			BaseSeverity:      checks.SeverityMedium,
			EffectiveSeverity: checks.SeverityMedium,
			Client:            unifi.Client{MAC: "vlan:" + n.ID, Name: n.Name, NetworkName: n.Name},
			Evidence:          fmt.Sprintf("%d wired client(s) on %s are on un-isolated switch ports with no blocking switch ACL (%s)", wiredOpenCount, n.Name, aclDec.ruleName),
			Remediation: checks.Remediation{
				Summary:      c.RecommendedFix,
				UniFiActions: []string{"enable_switch_port_isolation", "add_switch_l2_isolation_acl"},
			},
		})
	}

	// Build concise summary axis.
	switch {
	case len(wifiOpen) > 0:
		state := "open"
		if len(wifiIso) > 0 || wiredIsoCount > 0 {
			state = "partial"
		}
		return ContainmentAxis{
			State:  state,
			Detail: fmt.Sprintf("Wi-Fi l2_isolation disabled on %s", strings.Join(wifiOpen, ", ")),
		}, cells, findings
	case len(wiredClients) > 0 && !allWiredPortIsolated && !aclBlocksPeers:
		if switchACLStatus != "complete" {
			state := "unknown"
			if len(wifiIso) > 0 || wiredIsoCount > 0 {
				state = "partial"
			}
			return ContainmentAxis{
				State:  state,
				Detail: fmt.Sprintf("%d wired port(s) not isolated; %s", wiredOpenCount, switchACLReason),
			}, cells, findings
		}
		state := "open"
		if len(wifiIso) > 0 || wiredIsoCount > 0 {
			state = "partial"
		}
		return ContainmentAxis{
			State:  state,
			Detail: fmt.Sprintf("%d wired client(s) lack port isolation and switch ACLs permit peer traffic", wiredOpenCount),
		}, cells, findings
	case multiAP && !crossAPIsolated:
		if switchACLStatus != "complete" {
			return ContainmentAxis{
				State:  "partial",
				Detail: fmt.Sprintf("Same-AP Wi-Fi isolated; cross-AP across %d APs unverified (%s)", len(siteAPs), switchACLReason),
			}, cells, findings
		}
		return ContainmentAxis{
			State:  "partial",
			Detail: fmt.Sprintf("Same-AP Wi-Fi isolated; cross-AP traffic across %d APs not blocked by switch ACLs", len(siteAPs)),
		}, cells, findings
	case len(wifiIso) > 0 || allWiredPortIsolated || aclBlocksPeers:
		var parts []string
		if len(wifiIso) > 0 {
			parts = append(parts, "Wi-Fi L2 isolated")
		}
		if allWiredPortIsolated {
			parts = append(parts, "wired ports isolated")
		}
		if aclBlocksPeers {
			parts = append(parts, "switch ACL blocks peers")
		} else if allAPUplinksIsolated && multiAP {
			parts = append(parts, "AP uplinks isolated")
		}
		return ContainmentAxis{
			State:  "isolated",
			Detail: strings.Join(parts, "; "),
		}, cells, findings
	default:
		return ContainmentAxis{
			State:  "unknown",
			Detail: "No active Wi-Fi SSID or wired clients on this VLAN",
		}, cells, findings
	}
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
		return ContainmentAxis{State: "open", Detail: fmt.Sprintf("Permitted into LAN/Gateway via %q", violRule)}
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

// evaluateInternetEgressAxis evaluates VLAN -> External internet reachability
// from both the network-level Allow Internet Access toggle and IPv4/IPv6
// gateway firewall policies, tailoring findings to the detected archetype.
func evaluateInternetEgressAxis(
	snap *unifi.Snapshot,
	sortedPolicies []unifi.FirewallPolicy,
	gwPoliciesAvailable bool,
	gwMissingReason string,
	gwName, gwIP string,
	n unifi.Network,
	zoneLabel, archetype string,
	explicitNoInternet bool,
) (ContainmentAxis, []IsolationCell, []checks.Finding, []PostureNote) {
	var cells []IsolationCell
	var findings []checks.Finding
	var notes []PostureNote
	nLow := strings.ToLower(strings.TrimSpace(n.Name))
	srcZone := strings.TrimSpace(n.ZoneName)

	// 1. Network-level "Allow Internet Access" toggle disabled is authoritative.
	if n.InternetAccessEnabled != nil && !*n.InternetAccessEnabled {
		expected := "deny"
		verdict := IsolationBlockedOK
		if archetype == "guest" && !explicitNoInternet {
			expected = "allow"
			verdict = IsolationBrokenDependency
		}
		cells = append(cells, IsolationCell{
			SourceZone:     zoneLabel,
			SourceNetwork:  n.Name,
			DestZone:       "External",
			DestNetwork:    "Internet",
			DestFunction:   "internet-egress",
			Transport:      "all",
			IPFamily:       "ipv4",
			PathKind:       "gateway-routed",
			Enforcer:       gwName + " (Network Setting)",
			Expected:       expected,
			Effective:      "deny",
			Verdict:        verdict,
			DecisiveReason: "Network Allow Internet Access toggle is disabled",
		})
		return ContainmentAxis{
			State:  "blocked",
			Detail: "Allow Internet Access disabled on network",
		}, cells, findings, notes
	}

	if !gwPoliciesAvailable {
		return ContainmentAxis{State: "unknown", Detail: gwMissingReason}, cells, findings, notes
	}

	// Check whether the snapshot actually contains External-zone policies for this source zone.
	hasExternalPolicy := false
	hasExplicitExtBlock := false
	hasNarrowExtAllow := false
	for _, pol := range sortedPolicies {
		if !pol.Enabled || !strings.EqualFold(pol.Destination.ZoneName, "External") {
			continue
		}
		if pol.Source.ZoneName != "" && !strings.EqualFold(pol.Source.ZoneName, srcZone) {
			continue
		}
		hasExternalPolicy = true
		act := strings.ToUpper(strings.TrimSpace(pol.Action))
		if (act == "BLOCK" || act == "DROP" || act == "REJECT") &&
			!strings.EqualFold(strings.TrimSpace(pol.Name), "Post-Authorization Restrictions") &&
			matchesConnState(pol.ConnectionStates, "new") &&
			pol.Destination.AnyTarget {
			hasExplicitExtBlock = true
		}
		if act == "ALLOW" && (!pol.Destination.AnyTarget || !pol.Destination.CoversAllPorts()) {
			hasNarrowExtAllow = true
		}
	}

	if !hasExternalPolicy && n.InternetAccessEnabled == nil {
		return ContainmentAxis{State: "unknown", Detail: "No External-zone firewall policies present"}, cells, findings, notes
	}

	// Evaluate representative public internet destinations (RFC 5737 / RFC 3849)
	// across IPv4 (and IPv6 when IPv6 context is present).
	fams := []string{"ipv4"}
	if strings.TrimSpace(n.IPv6Subnet) != "" || gatewayHasIPv6Context(snap, n, sortedPolicies) {
		fams = append(fams, "ipv6")
	}

	type famResult struct {
		fam      string
		allowed  bool
		unknown  bool
		dec      policyDecision
		probeIP  string
		probePrt int
	}
	var results []famResult
	for _, fam := range fams {
		dstIP := "198.51.100.1"
		if fam == "ipv6" {
			dstIP = "2001:db8:ffff::1"
		}
		// Probe HTTPS (443) and an arbitrary high port (49152) so narrow port-53/443
		// portal allows don't masquerade as full internet access.
		var worst policyDecision
		worstPort := 49152
		allowed := false
		unknown := false
		for _, port := range []int{49152, 443, 80} {
			dec := evaluateGatewayPolicies(sortedPolicies, pathQuery{
				srcZone:    srcZone,
				srcNetID:   n.ID,
				srcNetName: n.Name,
				dstZone:    "External",
				dstNetName: "External",
				dstIP:      dstIP,
				proto:      "tcp",
				port:       port,
				ipFamily:   fam,
				state:      "new",
			})
			if dec.action == "allow" {
				allowed = true
				worst = dec
				worstPort = port
				break
			}
			if dec.action == "unknown" && !unknown {
				unknown = true
				worst = dec
				worstPort = port
			}
			if worst.action == "" {
				worst = dec
				worstPort = port
			}
		}
		results = append(results, famResult{fam: fam, allowed: allowed, unknown: unknown, dec: worst, probeIP: dstIP, probePrt: worstPort})
	}

	anyAllowed := false
	anyBlocked := false
	anyUnknown := false
	var allowedFam famResult
	for _, r := range results {
		switch {
		case r.allowed:
			anyAllowed = true
			if allowedFam.fam == "" {
				allowedFam = r
			}
		case r.unknown:
			anyUnknown = true
		default:
			anyBlocked = true
		}
	}

	// Case A: All evaluated families block general internet egress.
	if !anyAllowed && !anyUnknown {
		state := "blocked"
		detail := "Outbound internet blocked by gateway firewall"
		if hasNarrowExtAllow {
			state = "restricted"
			detail = "Blocked by default with narrow External allow rule(s)"
		}
		cells = append(cells, IsolationCell{
			SourceZone:       zoneLabel,
			SourceNetwork:    n.Name,
			DestZone:         "External",
			DestNetwork:      "Internet",
			DestFunction:     "internet-egress",
			Transport:        "tcp",
			Port:             443,
			IPFamily:         results[0].fam,
			PathKind:         "gateway-routed",
			Enforcer:         gwName,
			Expected:         "deny",
			Effective:        "deny",
			Verdict:          IsolationBlockedOK,
			DecisiveRuleID:   results[0].dec.ruleID,
			DecisiveRuleName: results[0].dec.ruleName,
			DecisiveReason:   detail,
		})
		return ContainmentAxis{State: state, Detail: detail}, cells, findings, notes
	}

	if !anyAllowed && anyUnknown {
		return ContainmentAxis{State: "unknown", Detail: "External firewall rule contains unsupported selector"}, cells, findings, notes
	}

	// Case B: Partial block / leak (e.g., IPv4 blocked while IPv6 open, or explicit
	// External BLOCK rule shadowed by an earlier ALLOW).
	isLeak := anyBlocked || hasExplicitExtBlock || explicitNoInternet
	if isLeak {
		reason := fmt.Sprintf("Internet egress permitted on %s via %q", strings.ToUpper(allowedFam.fam), allowedFam.dec.ruleName)
		if anyBlocked {
			reason = fmt.Sprintf("IPv4/IPv6 internet parity gap: %s permitted via %q while another family is blocked", strings.ToUpper(allowedFam.fam), allowedFam.dec.ruleName)
		} else if hasExplicitExtBlock {
			reason = fmt.Sprintf("Explicit External block rule is shadowed by %q", allowedFam.dec.ruleName)
		}
		fix := fmt.Sprintf("Disable Allow Internet Access on %s or block %s -> External across both IPv4 and IPv6.", n.Name, zoneLabel)
		cells = append(cells, IsolationCell{
			SourceZone:       zoneLabel,
			SourceNetwork:    n.Name,
			DestZone:         "External",
			DestNetwork:      "Internet",
			DestIP:           allowedFam.probeIP,
			DestFunction:     "internet-egress",
			Transport:        "tcp",
			Port:             allowedFam.probePrt,
			IPFamily:         allowedFam.fam,
			PathKind:         "gateway-routed",
			Enforcer:         gwName,
			Expected:         "deny",
			Effective:        "allow",
			Verdict:          IsolationViolation,
			DecisiveRuleID:   allowedFam.dec.ruleID,
			DecisiveRuleName: allowedFam.dec.ruleName,
			DecisiveReason:   reason,
			RecommendedFix:   fix,
		})
		findings = append(findings, checks.Finding{
			CheckID:           "UB-UNIFI-ISO-INTERNET-LEAK",
			Title:             fmt.Sprintf("No-Internet Network Permitted %s Internet Access (%s -> External)", strings.ToUpper(allowedFam.fam), n.Name),
			Category:          "isolation-policy",
			ClaimKind:         checks.ClaimConfiguredAccess,
			Property:          fmt.Sprintf("isolation-internet-leak-%s-%s", nLow, allowedFam.fam),
			Transport:         "tcp",
			BaseSeverity:      checks.SeverityHigh,
			EffectiveSeverity: checks.SeverityHigh,
			Client:            unifi.Client{MAC: "vlan:" + n.ID, IP: gwIP, Name: n.Name, NetworkName: n.Name},
			Port:              allowedFam.probePrt,
			Evidence:          reason,
			Remediation: checks.Remediation{
				Summary:      fix,
				UniFiActions: []string{"disable_network_internet_access", "block_external_egress"},
			},
		})
		state := "open"
		if anyBlocked {
			state = "partial"
		}
		return ContainmentAxis{State: state, Detail: reason}, cells, findings, notes
	}

	// Case C: Unrestricted internet access ("open"). Tailor advice to archetype!
	detail := fmt.Sprintf("Unrestricted internet access (%s)", firstNonEmptyStr(allowedFam.dec.ruleName, "Allow Internet Access"))
	switch archetype {
	case "guest":
		// Guests need internet access; mark cleanly approved with zero warnings.
		cells = append(cells, IsolationCell{
			SourceZone:       zoneLabel,
			SourceNetwork:    n.Name,
			DestZone:         "External",
			DestNetwork:      "Internet",
			DestFunction:     "internet-egress",
			Transport:        "tcp",
			Port:             443,
			IPFamily:         allowedFam.fam,
			PathKind:         "gateway-routed",
			Enforcer:         gwName,
			Expected:         "allow",
			Effective:        "allow",
			Verdict:          IsolationApproved,
			DecisiveRuleID:   allowedFam.dec.ruleID,
			DecisiveRuleName: allowedFam.dec.ruleName,
			DecisiveReason:   "Guest network permits outbound internet as expected",
		})
		return ContainmentAxis{State: "open", Detail: "Open (expected for Guest devices)"}, cells, findings, notes
	case "camera":
		fix := fmt.Sprintf("Disable Allow Internet Access on %s (or block %s -> External) so cameras only communicate with your local NVR/Protect console.", n.Name, zoneLabel)
		findings = append(findings, checks.Finding{
			CheckID:           "UB-UNIFI-ISO-CAMERA-INTERNET",
			Title:             fmt.Sprintf("Camera Network Has Unrestricted Internet Access (%s)", n.Name),
			Category:          "isolation-policy",
			ClaimKind:         checks.ClaimConfiguredAccess,
			Property:          "isolation-camera-internet-" + nLow,
			Transport:         "tcp",
			BaseSeverity:      checks.SeverityMedium,
			EffectiveSeverity: checks.SeverityMedium,
			Client:            unifi.Client{MAC: "vlan:" + n.ID, IP: gwIP, Name: n.Name, NetworkName: n.Name},
			Evidence:          fmt.Sprintf("network=%s (archetype=camera) permits outbound internet via %q", n.Name, allowedFam.dec.ruleName),
			Remediation: checks.Remediation{
				Summary:      fix,
				UniFiActions: []string{"disable_network_internet_access"},
			},
		})
		return ContainmentAxis{State: "open", Detail: detail}, cells, findings, notes
	case "iot":
		fix := fmt.Sprintf("Disable Allow Internet Access on %s if devices operate locally, or move %s to a dedicated IoT zone and restrict External egress to only required cloud endpoints.", n.Name, n.Name)
		findings = append(findings, checks.Finding{
			CheckID:           "UB-UNIFI-ISO-IOT-INTERNET",
			Title:             fmt.Sprintf("IoT Network Has Unrestricted Internet Access (%s)", n.Name),
			Category:          "isolation-policy",
			ClaimKind:         checks.ClaimConfiguredAccess,
			Property:          "isolation-iot-internet-" + nLow,
			Transport:         "tcp",
			BaseSeverity:      checks.SeverityLow,
			EffectiveSeverity: checks.SeverityLow,
			Client:            unifi.Client{MAC: "vlan:" + n.ID, IP: gwIP, Name: n.Name, NetworkName: n.Name},
			Evidence:          fmt.Sprintf("network=%s (archetype=iot) permits unrestricted outbound internet via %q", n.Name, allowedFam.dec.ruleName),
			Remediation: checks.Remediation{
				Summary:      fix,
				UniFiActions: []string{"disable_network_internet_access"},
			},
		})
		return ContainmentAxis{State: "open", Detail: detail}, cells, findings, notes
	default:
		return ContainmentAxis{State: "open", Detail: detail}, cells, findings, notes
	}
}

// evaluateLANInboundAxis evaluates Internal -> VLAN inbound reachability across
// IPv4 and IPv6, distinguishing wide-open defaults, narrow controller allowlists,
// and partial-block parity leaks.
func evaluateLANInboundAxis(
	snap *unifi.Snapshot,
	sortedPolicies []unifi.FirewallPolicy,
	gwPoliciesAvailable bool,
	gwMissingReason string,
	gwName, gwIP string,
	n unifi.Network,
	zoneLabel, archetype string,
	explicitStrictInbound bool,
	trustedNets []unifi.Network,
) (ContainmentAxis, []IsolationCell, []checks.Finding, []PostureNote) {
	var cells []IsolationCell
	var findings []checks.Finding
	var notes []PostureNote

	if !gwPoliciesAvailable {
		return ContainmentAxis{State: "unknown", Detail: gwMissingReason}, cells, findings, notes
	}
	if len(trustedNets) == 0 {
		return ContainmentAxis{State: "unknown", Detail: "No trusted LAN network to evaluate inbound access"}, cells, findings, notes
	}

	dstZone := strings.TrimSpace(n.ZoneName)
	nLow := strings.ToLower(strings.TrimSpace(n.Name))

	// Check whether the snapshot actually contains Internal -> dstZone policies.
	hasInboundPolicy := false
	hasExplicitInboundBlock := false
	hasNarrowInboundAllow := false
	for _, pol := range sortedPolicies {
		if !pol.Enabled || !strings.EqualFold(pol.Destination.ZoneName, dstZone) {
			continue
		}
		if pol.Source.ZoneName != "" && !strings.EqualFold(pol.Source.ZoneName, "Internal") {
			continue
		}
		hasInboundPolicy = true
		act := strings.ToUpper(strings.TrimSpace(pol.Action))
		if (act == "BLOCK" || act == "DROP" || act == "REJECT") && matchesConnState(pol.ConnectionStates, "new") {
			hasExplicitInboundBlock = true
		}
		if act == "ALLOW" && (!pol.Source.AnyTarget || !pol.Destination.AnyTarget || !pol.Destination.CoversAllPorts()) {
			hasNarrowInboundAllow = true
		}
	}
	if !hasInboundPolicy {
		return ContainmentAxis{State: "unknown", Detail: "No Internal -> zone firewall policies present"}, cells, findings, notes
	}

	// Evaluate a representative generic LAN host initiating a connection to an
	// arbitrary port on the isolated VLAN across IPv4 (and IPv6 when configured).
	srcNet := trustedNets[0]
	srcZone := firstNonEmptyStr(srcNet.ZoneName, "Internal")
	fams := []string{"ipv4"}
	if siteHasIPv6Context(snap, srcNet, n, unifi.Client{}) {
		fams = append(fams, "ipv6")
	}

	anyAllowed, anyBlocked, anyUnknown := false, false, false
	var allowedFam string
	var allowedDec policyDecision
	var blockedDec policyDecision

	for _, fam := range fams {
		srcIP := containmentSampleIP(srcNet, fam)
		dstIP := containmentSampleIP(n, fam)
		dec := evaluateGatewayPolicies(sortedPolicies, pathQuery{
			srcZone:    srcZone,
			srcNetID:   srcNet.ID,
			srcNetName: srcNet.Name,
			srcIP:      srcIP,
			dstZone:    dstZone,
			dstNetID:   n.ID,
			dstNetName: n.Name,
			dstIP:      dstIP,
			proto:      "tcp",
			port:       49152,
			ipFamily:   fam,
			state:      "new",
		})
		switch dec.action {
		case "allow":
			anyAllowed = true
			if allowedFam == "" {
				allowedFam = fam
				allowedDec = dec
			}
		case "unknown":
			anyUnknown = true
		default:
			anyBlocked = true
			if blockedDec.action == "" {
				blockedDec = dec
			}
		}
	}

	if !anyAllowed && !anyUnknown {
		state := "blocked"
		detail := "New inbound connections from Internal LAN are blocked"
		if hasNarrowInboundAllow {
			state = "restricted"
			detail = "Blocked by default with narrow controller/port allow rule(s)"
		}
		cells = append(cells, IsolationCell{
			SourceZone:       srcZone,
			SourceNetwork:    srcNet.Name,
			DestZone:         zoneLabel,
			DestNetwork:      n.Name,
			DestFunction:     "lan-inbound",
			Transport:        "tcp",
			Port:             49152,
			IPFamily:         fams[0],
			PathKind:         "gateway-routed",
			Enforcer:         gwName,
			Expected:         "deny",
			Effective:        "deny",
			Verdict:          IsolationBlockedOK,
			DecisiveRuleID:   blockedDec.ruleID,
			DecisiveRuleName: blockedDec.ruleName,
			DecisiveReason:   detail,
		})
		return ContainmentAxis{State: state, Detail: detail}, cells, findings, notes
	}

	if !anyAllowed && anyUnknown {
		return ContainmentAxis{State: "unknown", Detail: "Inbound firewall rule contains unsupported selector"}, cells, findings, notes
	}

	// Leak when strict inbound was intended (explicit block rule or config).
	if anyBlocked || hasExplicitInboundBlock || explicitStrictInbound {
		reason := fmt.Sprintf("Inbound LAN -> %s permitted on %s via %q", n.Name, strings.ToUpper(allowedFam), allowedDec.ruleName)
		if anyBlocked {
			reason = fmt.Sprintf("IPv4/IPv6 inbound parity gap: Internal -> %s permitted on %s via %q", n.Name, strings.ToUpper(allowedFam), allowedDec.ruleName)
		}
		fix := fmt.Sprintf("Restrict Internal -> %s (%s) strictly to approved controller IPs and ports across both IPv4 and IPv6.", n.Name, zoneLabel)
		cells = append(cells, IsolationCell{
			SourceZone:       srcZone,
			SourceNetwork:    srcNet.Name,
			DestZone:         zoneLabel,
			DestNetwork:      n.Name,
			DestFunction:     "lan-inbound",
			Transport:        "tcp",
			Port:             49152,
			IPFamily:         allowedFam,
			PathKind:         "gateway-routed",
			Enforcer:         gwName,
			Expected:         "deny",
			Effective:        "allow",
			Verdict:          IsolationViolation,
			DecisiveRuleID:   allowedDec.ruleID,
			DecisiveRuleName: allowedDec.ruleName,
			DecisiveReason:   reason,
			RecommendedFix:   fix,
		})
		findings = append(findings, checks.Finding{
			CheckID:           "UB-UNIFI-ISO-INBOUND-LEAK",
			Title:             fmt.Sprintf("Strict Inbound Policy Leaks %s LAN Access into %s", strings.ToUpper(allowedFam), n.Name),
			Category:          "isolation-policy",
			ClaimKind:         checks.ClaimConfiguredAccess,
			Property:          fmt.Sprintf("isolation-inbound-leak-%s-%s", nLow, allowedFam),
			Transport:         "tcp",
			BaseSeverity:      checks.SeverityHigh,
			EffectiveSeverity: checks.SeverityHigh,
			Client:            unifi.Client{MAC: "vlan:" + n.ID, IP: gwIP, Name: n.Name, NetworkName: n.Name},
			Evidence:          reason,
			Remediation: checks.Remediation{
				Summary:      fix,
				UniFiActions: []string{"restrict_inbound_to_isolated_zone"},
			},
		})
		state := "open"
		if anyBlocked {
			state = "partial"
		}
		return ContainmentAxis{State: state, Detail: reason}, cells, findings, notes
	}

	// Default UniFi Internal -> Hotspot/IoT Allow All.
	detail := fmt.Sprintf("All Internal LAN hosts can initiate connections (%s)", firstNonEmptyStr(allowedDec.ruleName, "Allow All Traffic"))
	switch archetype {
	case "iot":
		fix := fmt.Sprintf("Restrict Internal -> %s (%s) to only the specific controller host(s) and ports that manage these devices (e.g., Home Assistant) and block broad inbound access.", n.Name, zoneLabel)
		findings = append(findings, checks.Finding{
			CheckID:           "UB-UNIFI-ISO-IOT-INBOUND",
			Title:             fmt.Sprintf("Broad LAN Inbound Access Permitted to IoT Network (%s)", n.Name),
			Category:          "isolation-policy",
			ClaimKind:         checks.ClaimConfiguredAccess,
			Property:          "isolation-iot-inbound-" + nLow,
			Transport:         "tcp",
			BaseSeverity:      checks.SeverityLow,
			EffectiveSeverity: checks.SeverityLow,
			Client:            unifi.Client{MAC: "vlan:" + n.ID, IP: gwIP, Name: n.Name, NetworkName: n.Name},
			Evidence:          detail,
			Remediation: checks.Remediation{
				Summary:      fix,
				UniFiActions: []string{"restrict_inbound_to_isolated_zone"},
			},
		})
	case "camera":
		fix := fmt.Sprintf("Restrict Internal -> %s (%s) strictly to your NVR/admin host(s) and block broad LAN inbound access.", n.Name, zoneLabel)
		findings = append(findings, checks.Finding{
			CheckID:           "UB-UNIFI-ISO-CAMERA-INBOUND",
			Title:             fmt.Sprintf("Broad LAN Inbound Access Permitted to Camera Network (%s)", n.Name),
			Category:          "isolation-policy",
			ClaimKind:         checks.ClaimConfiguredAccess,
			Property:          "isolation-camera-inbound-" + nLow,
			Transport:         "tcp",
			BaseSeverity:      checks.SeverityLow,
			EffectiveSeverity: checks.SeverityLow,
			Client:            unifi.Client{MAC: "vlan:" + n.ID, IP: gwIP, Name: n.Name, NetworkName: n.Name},
			Evidence:          detail,
			Remediation: checks.Remediation{
				Summary:      fix,
				UniFiActions: []string{"restrict_inbound_to_isolated_zone"},
			},
		})
	case "guest":
		notes = append(notes, PostureNote{
			Severity: checks.SeverityLow,
			Title:    fmt.Sprintf("Internal LAN can initiate connections into Guest network %s", n.Name),
			Detail:   fmt.Sprintf("UniFi's default %q rule allows Internal hosts to reach %s. Blocking Internal -> %s prevents accidental access to untrusted guest devices.", firstNonEmptyStr(allowedDec.ruleName, "Allow All Traffic"), n.Name, zoneLabel),
		})
	}
	return ContainmentAxis{State: "open", Detail: detail}, cells, findings, notes
}

// containmentSampleIP selects a representative non-gateway host address inside
// n's IPv4 or IPv6 subnet for generic inbound policy probing.
func containmentSampleIP(n unifi.Network, fam string) string {
	raw := strings.TrimSpace(n.Subnet)
	if fam == "ipv6" {
		raw = strings.TrimSpace(n.IPv6Subnet)
	}
	if pfx, err := netip.ParsePrefix(raw); err == nil {
		base := pfx.Masked().Addr()
		if base.Is4() {
			b := base.As4()
			if pfx.Bits() <= 30 {
				b[3] ^= 0xc8 // pick a non-gateway host (.200 on /24)
			}
			cand := netip.AddrFrom4(b)
			if pfx.Contains(cand) {
				return cand.String()
			}
		} else if base.Is6() {
			b := base.As16()
			if pfx.Bits() <= 120 {
				b[15] ^= 0xc8
			}
			cand := netip.AddrFrom16(b)
			if pfx.Contains(cand) {
				return cand.String()
			}
		}
		return base.String()
	}
	if fam == "ipv6" {
		return "fd00:ffff::c8"
	}
	return "10.255.255.200"
}
