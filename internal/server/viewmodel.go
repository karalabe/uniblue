// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package server

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/classify"
	"github.com/karalabe/uniblue/internal/cve"
	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/risk"
	"github.com/karalabe/uniblue/internal/topology"
	"github.com/karalabe/uniblue/internal/unifi"
)

// VerdictState is the unified four-state security/policy verdict derived once
// in Go and shared identically across Map, Inventory, Inspector, and Activity.
type VerdictState string

const (
	// VerdictOK means the entity was assessed and has zero active reasons.
	VerdictOK VerdictState = "ok"
	// VerdictUnknown means required assessment evidence is missing (e.g. unscanned host).
	VerdictUnknown VerdictState = "unknown"
	// VerdictReview means heuristic or version-unknown evidence needs operator judgment.
	VerdictReview VerdictState = "review"
	// VerdictExposed means an evidenced violation, failed check, policy mismatch, or exact CVE.
	VerdictExposed VerdictState = "exposed"
)

// Reason represents one concrete evidenced fact contributing to an entity's Verdict.
type Reason struct {
	ID          string       `json:"id"`
	State       VerdictState `json:"state"`
	Kind        string       `json:"kind"` // "check" | "cve" | "policy" | "placement" | "coverage" | "firmware"
	Ref         string       `json:"ref"`
	Title       string       `json:"title"`
	Severity    string       `json:"severity"`
	Expected    string       `json:"expected,omitempty"`
	Observed    string       `json:"observed,omitempty"`
	Evidence    string       `json:"evidence,omitempty"`
	Remediation string       `json:"remediation,omitempty"`
	Source      string       `json:"source"` // "probe" | "lldp" | "config" | "name-heuristic" | "nvd-cve" | "unifi-policy"
	Port        int          `json:"port,omitempty"`
}

// ServiceView represents one discovered network service on a host along with
// its computed reachability boundary and evidence provenance.
type ServiceView struct {
	Port             int    `json:"port"`
	Proto            string `json:"proto"` // "tcp" | "udp"
	Name             string `json:"name,omitempty"`
	Reachable        string `json:"reachable"` // "wan" | "wan-restricted" | "wan-cgnat" | "lan" | "vlan-only" | "advertised" | "unknown"
	State            string `json:"state,omitempty"`
	SourceRestricted bool   `json:"source_restricted,omitempty"`
	Exposed          bool   `json:"exposed,omitempty"`
	Severity         string `json:"severity,omitempty"`
	Label            string `json:"label,omitempty"`
}

// Entity is a stably-identified node shared across both lenses, the Inventory
// table, the docked Inspector, and Activity cross-links.
//
// ID conventions:
//
//	dev:<mac>
//	port:<mac>/<portIdx>
//	net:<id-or-name>
//	host:<mac>  (or host:ip/<ip> when MAC absent)
//	rule:<id>
//	wlan:<name>
type Entity struct {
	ID            string               `json:"id"`
	Kind          string               `json:"kind"` // "device" | "port" | "network" | "host" | "rule" | "wlan"
	Label         string               `json:"label"`
	Subtitle      string               `json:"subtitle,omitempty"`
	Role          string               `json:"role,omitempty"`        // "gateway"|"switch"|"ap"|"bmc"|"camera"|"server"|"iot"|...
	Side          string               `json:"side,omitempty"`        // "inside"|"outside"|"unknown"
	ZoneSource    string               `json:"zone_source,omitempty"` // "config"|"auto"|"parent_link"|"default"
	Weight        int                  `json:"weight"`
	State         VerdictState         `json:"state"`
	MaxSeverity   string               `json:"max_severity"`
	StateLabel    string               `json:"state_label"`
	Reasons       []Reason             `json:"reasons,omitempty"`
	PinNumber     int                  `json:"pin_number,omitempty"`
	ScannedAt     *time.Time           `json:"scanned_at,omitempty"`
	DeviceID      string               `json:"device_id,omitempty"`
	PortID        string               `json:"port_id,omitempty"`
	NetworkID     string               `json:"network_id,omitempty"`
	NetworkName   string               `json:"network_name,omitempty"`
	APID          string               `json:"ap_id,omitempty"`
	ESSID         string               `json:"essid,omitempty"`
	IP            string               `json:"ip,omitempty"`
	IPv6          []string             `json:"ipv6,omitempty"`
	MAC           string               `json:"mac,omitempty"`
	Vendor        string               `json:"vendor,omitempty"`
	Model         string               `json:"model,omitempty"`
	Firmware      string               `json:"firmware,omitempty"`
	IsWired       bool                 `json:"is_wired,omitempty"`
	IsBMC         bool                 `json:"is_bmc,omitempty"`
	ExactCVECount int                  `json:"exact_cve_count,omitempty"`
	PotCVECount   int                  `json:"pot_cve_count,omitempty"`
	Services      []ServiceView        `json:"services,omitempty"`
	ExactCVEs     []cve.ProductSummary `json:"exact_cves,omitempty"`
	PotentialCVEs []cve.ProductSummary `json:"potential_cves,omitempty"`

	// Bridge-to-child and outbound dependency metadata.
	ParentID              string                     `json:"parent_id,omitempty"`
	ChildIDs              []string                   `json:"child_ids,omitempty"`
	IdentitySource        string                     `json:"identity_source,omitempty"`
	DirectLANReachability string                     `json:"direct_lan_reachability,omitempty"`
	OutboundDependencies  []probe.OutboundDependency `json:"outbound_dependencies,omitempty"`

	// Port telemetry (Kind == "port")
	PortIdx       int      `json:"port_idx,omitempty"`
	PortZone      string   `json:"port_zone,omitempty"`
	PortState     string   `json:"port_state,omitempty"`
	Speed         int      `json:"speed,omitempty"`
	Media         string   `json:"media,omitempty"`
	PoEEnabled    bool     `json:"poe_enabled,omitempty"`
	PoEPower      string   `json:"poe_power,omitempty"`
	NativeVLAN    string   `json:"native_vlan,omitempty"`
	TaggedPolicy  string   `json:"tagged_policy,omitempty"`
	PortSecurity  bool     `json:"port_security,omitempty"`
	MACTableCount int      `json:"mac_table_count,omitempty"`
	STPState      string   `json:"stp_state,omitempty"`
	PeerIDs       []string `json:"peer_ids,omitempty"`
}

// QueueItem is one ranked entry in the Fix-Next rail. Queue[0] drives the
// top-of-page verdict sentence.
type QueueItem struct {
	Pin       int          `json:"pin"`
	Sentence  string       `json:"sentence"`
	Category  string       `json:"category"` // "perimeter"|"wan"|"bmc"|"service"|"controller"
	Severity  string       `json:"severity"`
	State     VerdictState `json:"state"`
	Score     int          `json:"score"`
	SubjectID string       `json:"subject_id"`
	EntityIDs []string     `json:"entity_ids"`
	ReasonRef string       `json:"reason_ref,omitempty"`
}

// WallGate represents one physical cable crossing the building perimeter wall.
type WallGate struct {
	PortID     string       `json:"port_id"`
	SwitchID   string       `json:"switch_id"`
	SwitchName string       `json:"switch_name"`
	PortIdx    int          `json:"port_idx"`
	TargetID   string       `json:"target_id,omitempty"`
	TargetName string       `json:"target_name"`
	Kind       string       `json:"kind"` // "feeder" | "drop"
	Inferred   bool         `json:"inferred"`
	State      VerdictState `json:"state"`
	PinNumber  int          `json:"pin_number,omitempty"`
	InlineFact string       `json:"inline_fact,omitempty"`
}

// WANFlow represents one inbound WAN firewall rule or port forward pointing to
// a concrete host, gateway, or zone boundary.
type WANFlow struct {
	ID         string       `json:"id"`
	Kind       string       `json:"kind"` // "firewall" | "forward"
	Label      string       `json:"label"`
	RuleName   string       `json:"rule_name"`
	TargetID   string       `json:"target_id,omitempty"`
	TargetIP   string       `json:"target_ip,omitempty"`
	TargetName string       `json:"target_name,omitempty"`
	Expected   bool         `json:"expected,omitempty"`
	State      VerdictState `json:"state"`
	Severity   string       `json:"severity"`
	PinNumber  int          `json:"pin_number,omitempty"`
}

// PhysicalRow represents one UniFi device row in the Physical Blueprint lens,
// ordered in real LLDP tree order with depth indentation (or UplinkUnknown).
type PhysicalRow struct {
	DeviceID      string   `json:"device_id"`
	Name          string   `json:"name"`
	Model         string   `json:"model"`
	IP            string   `json:"ip"`
	Type          string   `json:"type"`
	Version       string   `json:"version,omitempty"`
	Upgradable    bool     `json:"upgradable,omitempty"`
	Side          string   `json:"side"` // "inside" | "outside"
	ZoneSource    string   `json:"zone_source,omitempty"`
	Depth         int      `json:"depth"`
	UplinkUnknown bool     `json:"uplink_unknown,omitempty"`
	ParentID      string   `json:"parent_id,omitempty"`
	ParentPortID  string   `json:"parent_port_id,omitempty"`
	ParentLabel   string   `json:"parent_label,omitempty"`
	PortIDs       []string `json:"port_ids,omitempty"`
	SFPStartIdx   int      `json:"sfp_start_idx,omitempty"`
	ClientCount   int      `json:"client_count,omitempty"`
	SSIDs         []string `json:"ssids,omitempty"`
}

// LogicalLane represents one VLAN lane inside the Logical Zones lens.
type LogicalLane struct {
	NetworkID      string       `json:"network_id"`
	Name           string       `json:"name"`
	VLAN           string       `json:"vlan,omitempty"`
	Subnet         string       `json:"subnet,omitempty"`
	ZoneName       string       `json:"zone_name"`
	Isolated       bool         `json:"isolated"`
	ValveState     VerdictState `json:"valve_state"`
	ValveReason    string       `json:"valve_reason,omitempty"`
	BMCIDs         []string     `json:"bmc_ids,omitempty"`
	PinnedHostIDs  []string     `json:"pinned_host_ids,omitempty"`
	CleanHostIDs   []string     `json:"clean_host_ids,omitempty"`
	UnknownHostIDs []string     `json:"unknown_host_ids,omitempty"`
	TotalHosts     int          `json:"total_hosts"`
	MigrationHint  string       `json:"migration_hint,omitempty"`
}

// Census holds exact clickable filter counts derived from the same predicates
// used by the Map and Inventory views.
type Census struct {
	ExposedCount    int `json:"exposed_count"`
	ReviewCount     int `json:"review_count"`
	BMCCount        int `json:"bmc_count"`
	ExactCVEHosts   int `json:"exact_cve_hosts"`
	UnassessedCount int `json:"unassessed_count"`
	OpenWallGates   int `json:"open_wall_gates"`
	TotalWallGates  int `json:"total_wall_gates"`
}

// PresentationModel is the complete single-source-of-truth UI model built in Go.
type PresentationModel struct {
	Headline        string                       `json:"headline"`
	Census          Census                       `json:"census"`
	GatewayID       string                       `json:"gateway_id,omitempty"`
	Entities        map[string]*Entity           `json:"entities"`
	Queue           []QueueItem                  `json:"queue,omitempty"`
	Physical        []PhysicalRow                `json:"physical,omitempty"`
	WallGates       []WallGate                   `json:"wall_gates,omitempty"`
	Logical         []LogicalLane                `json:"logical,omitempty"`
	WANFlows        []WANFlow                    `json:"wan_flows,omitempty"`
	Isolation       *risk.IsolationMatrix        `json:"isolation,omitempty"`
	ServiceCoverage *probe.ServiceCoverageReport `json:"service_coverage,omitempty"`
	Copyright       string                       `json:"copyright"`
	License         string                       `json:"license"`
	RepoURL         string                       `json:"repo_url"`
}

func devEntityID(mac string) string { return "dev:" + strings.ToLower(strings.TrimSpace(mac)) }
func portEntityID(mac string, idx int) string {
	return fmt.Sprintf("port:%s/%d", strings.ToLower(strings.TrimSpace(mac)), idx)
}
func hostEntityID(cl unifi.Client) string {
	if m := strings.ToLower(strings.TrimSpace(cl.MAC)); m != "" {
		return "host:" + m
	}
	return "host:ip/" + strings.TrimSpace(cl.IP)
}
func netEntityID(id, name string) string {
	if strings.TrimSpace(id) != "" {
		return "net:" + strings.TrimSpace(id)
	}
	return "net:" + strings.ToLower(strings.TrimSpace(name))
}

// BuildPresentationModel derives the entire verdict, graph, queue, physical
// blueprint, and logical zone model once in Go so every UI widget and offline
// HTML export agrees 100%.
func BuildPresentationModel(
	snap *unifi.Snapshot,
	report risk.Report,
	topo *topology.Model,
	clients []ClientView,
	exactCVEs, potentialCVEs []cve.ProductSummary,
	profiles []probe.HostProfile,
) *PresentationModel {
	pm := &PresentationModel{
		Entities:  make(map[string]*Entity),
		Copyright: "© 2026 Péter Szilágyi",
		License:   "BSD-3-Clause",
		RepoURL:   "https://github.com/karalabe/uniblue",
	}
	if snap == nil {
		pm.Headline = "Waiting for UniFi snapshot…"
		return pm
	}

	// Index helper lookups.
	devByMAC := make(map[string]unifi.Device, len(snap.Devices))
	devByName := make(map[string]unifi.Device, len(snap.Devices))
	for _, d := range snap.Devices {
		mac := strings.ToLower(d.MAC)
		devByMAC[mac] = d
		devByName[strings.ToLower(d.Name)] = d
	}
	swByMAC := make(map[string]risk.SwitchDeviceView, len(report.SwitchPorts))
	for _, sw := range report.SwitchPorts {
		swByMAC[strings.ToLower(sw.MAC)] = sw
	}
	profileByIP := make(map[string]probe.HostProfile, len(profiles))
	for _, hp := range profiles {
		if hp.Client.IP != "" {
			profileByIP[hp.Client.IP] = hp
		}
	}

	// Index placement verdicts computed by topology.Build.
	placementByIP := make(map[string]topology.ClientNode)
	placementByMAC := make(map[string]topology.ClientNode)
	if topo != nil {
		for _, vg := range topo.VLANs {
			for _, cn := range vg.Clients {
				if cn.IP != "" {
					placementByIP[cn.IP] = cn
				}
				if cn.MAC != "" {
					placementByMAC[strings.ToLower(cn.MAC)] = cn
				}
			}
		}
	}

	// Index networks by name and ID.
	netEntByName := make(map[string]string)
	netIsolated := make(map[string]bool)
	for _, n := range snap.Networks {
		nid := netEntityID(n.ID, n.Name)
		netEntByName[strings.ToLower(n.Name)] = nid
		iso := n.IsolationEnabled || strings.EqualFold(n.Purpose, "guest") ||
			strings.EqualFold(n.ZoneName, "hotspot") || strings.EqualFold(n.ZoneName, "dmz")
		netIsolated[strings.ToLower(n.Name)] = iso
		pm.Entities[nid] = &Entity{
			ID:          nid,
			Kind:        "network",
			Label:       n.Name,
			Subtitle:    fmt.Sprintf("VLAN %s · %s", n.VLAN, n.Subnet),
			Role:        strings.ToLower(n.Purpose),
			Weight:      1,
			State:       VerdictOK,
			MaxSeverity: "ok",
			StateLabel:  "Matches policy",
			NetworkID:   nid,
			NetworkName: n.Name,
		}
	}

	// Index exact & potential CVEs per host IP (deduplicated per host+product).
	exactByIP := make(map[string][]cve.ProductSummary)
	for _, s := range exactCVEs {
		if s.Product.HostIP != "" {
			exactByIP[s.Product.HostIP] = append(exactByIP[s.Product.HostIP], s)
		}
	}
	potByIP := make(map[string][]cve.ProductSummary)
	for _, s := range potentialCVEs {
		if s.Product.HostIP != "" {
			potByIP[s.Product.HostIP] = append(potByIP[s.Product.HostIP], s)
		}
	}

	// Index WAN forwards by target IP.
	wanByIP := make(map[string][]risk.ExposureAssessment)
	for _, a := range report.WANSurface {
		ip := a.Forward.FwdIP
		if ip == "" {
			ip = a.Client.IP
		}
		if ip != "" {
			wanByIP[ip] = append(wanByIP[ip], a)
		}
	}

	// 1. Register UniFi Infrastructure Devices + Gateway ID.
	gwMAC := ""
	for _, d := range snap.Devices {
		t := strings.ToLower(d.Type)
		m := strings.ToLower(d.Model)
		if t == "udm" || t == "ugw" || t == "uxg" || strings.Contains(m, "udm") || strings.Contains(m, "ucg") {
			gwMAC = strings.ToLower(d.MAC)
			break
		}
	}
	if gwMAC == "" && len(snap.Devices) > 0 {
		gwMAC = strings.ToLower(snap.Devices[0].MAC)
	}
	if gwMAC != "" {
		pm.GatewayID = devEntityID(gwMAC)
	}

	for _, d := range snap.Devices {
		mac := strings.ToLower(d.MAC)
		id := devEntityID(mac)
		sw, hasSW := swByMAC[mac]
		side := "inside"
		zoneSrc := "default"
		if hasSW && sw.ExternalDevice {
			side = "outside"
			zoneSrc = sw.ZoneSource
		}
		role := "switch"
		t := strings.ToLower(d.Type)
		m := strings.ToLower(d.Model)
		switch {
		case mac == gwMAC:
			role = "gateway"
		case t == "uap" || strings.Contains(m, "iw") || strings.Contains(m, "ap"):
			role = "ap"
		}
		weight := 2
		if role == "gateway" {
			weight = 3
		}
		ent := &Entity{
			ID:          id,
			Kind:        "device",
			Label:       d.Name,
			Subtitle:    fmt.Sprintf("%s · %s", d.Model, d.IP),
			Role:        role,
			Side:        side,
			ZoneSource:  zoneSrc,
			Weight:      weight,
			State:       VerdictOK,
			MaxSeverity: "ok",
			StateLabel:  "Matches policy",
			DeviceID:    id,
			IP:          d.IP,
			MAC:         mac,
			Model:       d.Model,
			Firmware:    d.Version,
		}
		if d.Upgradable {
			ent.Reasons = append(ent.Reasons, Reason{
				ID:          "fw:" + mac,
				State:       VerdictReview,
				Kind:        "firmware",
				Ref:         "UB-UNIFI-FIRMWARE",
				Title:       "Firmware update available",
				Severity:    "low",
				Expected:    "Latest UniFi release",
				Observed:    d.Version,
				Evidence:    fmt.Sprintf("%s (%s) is running firmware %s with a newer release available", d.Name, d.Model, d.Version),
				Remediation: "Review Ubiquiti release notes and update device firmware.",
				Source:      "unifi-controller",
			})
		}
		pm.Entities[id] = ent
	}

	// 2. Register Clients / Hosts (single source of truth for checks + exact CVEs + BMCs + scan coverage!).
	clientByIP := make(map[string]ClientView, len(clients))
	clientByMAC := make(map[string]ClientView, len(clients))
	hostIDByIP := make(map[string]string, len(clients))
	hostIDByMAC := make(map[string]string, len(clients))
	apClientCount := make(map[string]int)

	for _, cv := range clients {
		cl := cv.Client
		mac := strings.ToLower(cl.MAC)
		hid := hostEntityID(cl)
		if cl.IP != "" {
			clientByIP[cl.IP] = cv
			hostIDByIP[cl.IP] = hid
		}
		if mac != "" {
			clientByMAC[mac] = cv
			hostIDByMAC[mac] = hid
		}
		if !cl.IsWired && cl.APMAC != "" {
			apClientCount[strings.ToLower(cl.APMAC)]++
		}

		isBMC := cv.Class.Category == classify.CategoryBMC ||
			strings.Contains(strings.ToLower(cl.Name+" "+cl.Hostname), "management console") ||
			strings.Contains(strings.ToLower(cl.Name+" "+cl.Hostname), "ipmi") ||
			strings.Contains(strings.ToLower(cl.Name+" "+cl.Hostname), "idrac") ||
			strings.Contains(strings.ToLower(cl.Name+" "+cl.Hostname), "asmb")

		role := string(cv.Class.Category)
		if isBMC {
			role = "bmc"
		}
		weight := 1
		if isBMC {
			weight = 3
		}
		if len(wanByIP[cl.IP]) > 0 {
			weight += 2
		}

		var portID, devID, apID string
		side := "inside"
		if cl.IsWired && cl.SwitchMAC != "" && cl.SwitchPort > 0 {
			sm := strings.ToLower(cl.SwitchMAC)
			devID = devEntityID(sm)
			portID = portEntityID(sm, cl.SwitchPort)
			if sw, ok := swByMAC[sm]; ok {
				if sw.ExternalDevice {
					side = "outside"
				} else {
					for _, sp := range sw.Ports {
						if sp.PortIdx == cl.SwitchPort && (sp.Zone == "external" || sp.Zone == "external_uplink") {
							side = "outside"
							break
						}
					}
				}
			}
		} else if !cl.IsWired && cl.APMAC != "" {
			apID = devEntityID(cl.APMAC)
			if sw, ok := swByMAC[strings.ToLower(cl.APMAC)]; ok && sw.ExternalDevice {
				side = "outside"
			}
		}

		ent := &Entity{
			ID:          hid,
			Kind:        "host",
			Label:       cl.DisplayName(),
			Subtitle:    cv.Class.Role,
			Role:        role,
			Side:        side,
			Weight:      weight,
			State:       VerdictOK,
			MaxSeverity: "ok",
			StateLabel:  "No findings",
			ScannedAt:   cv.LastScannedAt,
			DeviceID:    devID,
			PortID:      portID,
			NetworkID:   netEntByName[strings.ToLower(cl.NetworkName)],
			NetworkName: cl.NetworkName,
			APID:        apID,
			ESSID:       cl.ESSID,
			IP:          cl.IP,
			IPv6:        cl.IPv6,
			MAC:         mac,
			Vendor:      firstStr(cv.Class.Vendor, cl.OUI),
			IsWired:     cl.IsWired,
			IsBMC:       isBMC,
		}

		// Attach placement verdict computed by topology.Build.
		if pl, ok := placementByIP[cl.IP]; ok {
			if pl.Placement == topology.PlacementIsolate || pl.Placement == topology.PlacementReview {
				ent.Reasons = append(ent.Reasons, Reason{
					ID:          "place:" + hid,
					State:       VerdictReview,
					Kind:        "placement",
					Ref:         "VLAN-PLACEMENT",
					Title:       "VLAN placement review",
					Severity:    "low",
					Expected:    "Isolated / segmented VLAN",
					Observed:    cl.NetworkName,
					Evidence:    pl.PlacementReason,
					Remediation: "Consider moving this host onto an isolated VLAN matching its role.",
					Source:      "topology-placement",
				})
			}
		}

		// Attach Exact CVEs (independent Exposed verdict ).
		if exList := exactByIP[cl.IP]; len(exList) > 0 {
			ent.ExactCVEs = exList
			for i, s := range exList {
				ent.ExactCVECount += s.TotalCVEs
				sev := s.MaxSeverity.String()
				ver := strings.TrimSpace(s.Product.Label + " " + s.Product.Version)
				fix := "Upgrade to patched release"
				if s.MinFixedVersion != "" {
					fix = "Upgrade to >= " + s.MinFixedVersion
				}
				ent.Reasons = append(ent.Reasons, Reason{
					ID:          fmt.Sprintf("cve-exact:%s/%d", hid, i),
					State:       VerdictExposed,
					Kind:        "cve",
					Ref:         strings.Join(s.TopCVEs, ", "),
					Title:       fmt.Sprintf("%s: %d exact CVE(s) (max CVSS %.1f)", ver, s.TotalCVEs, s.MaxCVSS),
					Severity:    sev,
					Expected:    fix,
					Observed:    ver,
					Evidence:    fmt.Sprintf("%s matched %d exact CVE(s)%s: %s", ver, s.TotalCVEs, formatKEV(s.KEVCount), strings.Join(s.TopCVEs, ", ")),
					Remediation: fix,
					Source:      "nvd-cve",
				})
			}
		}
		if potList := potByIP[cl.IP]; len(potList) > 0 {
			ent.PotentialCVEs = potList
			for _, s := range potList {
				ent.PotCVECount += s.TotalCVEs
			}
		}

		// Build structured Services[] with computed reachability!
		hp := profileByIP[cl.IP]
		behindCGNAT := isSnapshotWANBehindCGNAT(snap)
		ent.Services = buildHostServices(cv, hp, wanByIP[cl.IP], netIsolated[strings.ToLower(cl.NetworkName)], behindCGNAT)
		if len(hp.OutboundDependencies) > 0 {
			ent.OutboundDependencies = hp.OutboundDependencies
		}

		// Register enrolled child devices managed behind bridges/NVRs/coordinators
		// (e.g., cameras on an NVR's private PoE network) with explicit provenance
		// and DirectLANReachability ("unknown" when behind private PoE).
		for _, ch := range hp.Children {
			cid := fmt.Sprintf("child:%s/%s", hid, ch.ID)
			reach := ch.DirectLANReachability
			if reach == "" {
				reach = "unknown"
			}
			chState := VerdictOK
			chLabel := "Child inventory"
			if reach == "unknown" {
				chState = VerdictUnknown
				chLabel = "Direct LAN reachability unknown"
			}
			ent.ChildIDs = append(ent.ChildIDs, cid)
			pm.Entities[cid] = &Entity{
				ID:                    cid,
				Kind:                  "child",
				Label:                 firstStr(ch.Name, ch.Model, ch.ID),
				Subtitle:              firstStr(ch.Role, "Bridged Child Device"),
				Role:                  firstStr(ch.Category, "iot"),
				Side:                  side,
				Weight:                1,
				State:                 chState,
				MaxSeverity:           "ok",
				StateLabel:            chLabel,
				ParentID:              hid,
				NetworkID:             ent.NetworkID,
				NetworkName:           ent.NetworkName,
				Vendor:                ch.Vendor,
				Model:                 ch.Model,
				Firmware:              ch.Firmware,
				IdentitySource:        ch.IdentitySource,
				DirectLANReachability: reach,
			}
		}

		pm.Entities[hid] = ent
	}

	// 3. Register Switch Ports & Wall Gates.
	for _, sw := range report.SwitchPorts {
		swMAC := strings.ToLower(sw.MAC)
		swID := devEntityID(swMAC)
		for _, p := range sw.Ports {
			pid := portEntityID(swMAC, p.PortIdx)
			side := "inside"
			if sw.ExternalDevice || p.Zone == "external" {
				side = "outside"
			}
			peerIDs := make([]string, 0, len(p.Peers))
			for _, peer := range p.Peers {
				pmac := strings.ToLower(peer.MAC)
				if peer.Kind == "device" || devByMAC[pmac].MAC != "" {
					peerIDs = append(peerIDs, devEntityID(pmac))
				} else if hid, ok := hostIDByMAC[pmac]; ok {
					peerIDs = append(peerIDs, hid)
				} else if hid, ok := hostIDByIP[peer.IP]; ok {
					peerIDs = append(peerIDs, hid)
				}
			}

			weight := 1
			if p.Zone == "external" || p.Zone == "external_uplink" {
				weight = 3
			}
			ent := &Entity{
				ID:            pid,
				Kind:          "port",
				Label:         fmt.Sprintf("%s #%d", sw.Name, p.PortIdx),
				Subtitle:      firstStr(p.Label, p.Name),
				Role:          p.Zone,
				Side:          side,
				ZoneSource:    p.ZoneSource,
				Weight:        weight,
				State:         VerdictOK,
				MaxSeverity:   "ok",
				StateLabel:    "Matches policy",
				DeviceID:      swID,
				PortID:        pid,
				NetworkID:     netEntByName[strings.ToLower(p.NativeVLAN)],
				NetworkName:   p.NativeVLAN,
				PortIdx:       p.PortIdx,
				PortZone:      p.Zone,
				PortState:     p.State,
				Speed:         p.Speed,
				Media:         p.Media,
				PoEEnabled:    p.PoEEnabled,
				PoEPower:      p.PoEPower,
				NativeVLAN:    p.NativeVLAN,
				TaggedPolicy:  p.TaggedPolicy,
				PortSecurity:  p.PortSecurity,
				MACTableCount: p.MACTableCount,
				STPState:      p.STPState,
				PeerIDs:       peerIDs,
			}

			// Add subtle Review reason for indoor active trunk access ports or inferred external drops.
			if p.Zone == "internal" && p.State == "active" && p.TaggedPolicy == "all" && len(p.Peers) > 0 {
				ent.Reasons = append(ent.Reasons, Reason{
					ID:          "port-trunk:" + pid,
					State:       VerdictReview,
					Kind:        "policy",
					Ref:         "PORT-TRUNK-ACCESS",
					Title:       "Access port carries All tagged VLANs",
					Severity:    "low",
					Expected:    "Tagged VLANs = Block All",
					Observed:    "Tagged VLANs = All",
					Evidence:    fmt.Sprintf("%s Port %d carries all tagged VLANs to end-host peer(s)", sw.Name, p.PortIdx),
					Remediation: "Set Tagged VLAN Management to Block All on non-uplink access ports.",
					Source:      "unifi-port",
					Port:        p.PortIdx,
				})
			}

			pm.Entities[pid] = ent

			// Record wall gates for indoor ports whose cable exits the secured building.
			if !sw.ExternalDevice && (p.Zone == "external_uplink" || p.Zone == "external") {
				targetID := ""
				targetName := firstStr(p.Label, p.Name)
				if len(p.Peers) > 0 {
					targetName = p.Peers[0].Name
					if len(peerIDs) > 0 {
						targetID = peerIDs[0]
					}
				}
				kind := "drop"
				if p.Zone == "external_uplink" {
					kind = "feeder"
				}
				inlineFact := fmt.Sprintf("%s · %s", p.NativeVLAN, p.TaggedPolicy)
				if p.PortSecurity {
					inlineFact += " · MAC lock"
				}
				pm.WallGates = append(pm.WallGates, WallGate{
					PortID:     pid,
					SwitchID:   swID,
					SwitchName: sw.Name,
					PortIdx:    p.PortIdx,
					TargetID:   targetID,
					TargetName: targetName,
					Kind:       kind,
					Inferred:   p.ZoneSource != "config",
					State:      VerdictOK, // updated after findings attach
					InlineFact: inlineFact,
				})
			}
		}
	}

	// 4. Attach ALL Confirmed Findings from report.Findings to their exact typed Entity!
	for idxF, f := range report.Findings {
		if f.CheckID == "UB-UNIFI-PORTFWD" || f.CheckID == "UB-UNIFI-FIRMWARE" {
			continue
		}
		fid := fmt.Sprintf("find:%s@%d", f.CheckID, idxF)
		sev := f.EffectiveSeverity.String()

		switch {
		case strings.HasPrefix(f.CheckID, "UB-UNIFI-PORT-"):
			swMAC := strings.ToLower(f.Client.MAC)
			pid := portEntityID(swMAC, f.Port)
			if f.CheckID == "UB-UNIFI-PORT-EXT-UNUSED-OPEN" {
				// Attach to each unused external port on this switch AND the switch device itself!
				if sw, ok := swByMAC[swMAC]; ok {
					for _, sp := range sw.Ports {
						if (sp.Zone == "external" || sp.Zone == "unused") && sp.State == "inactive_enabled" {
							if pe, ok := pm.Entities[portEntityID(swMAC, sp.PortIdx)]; ok {
								pe.Reasons = append(pe.Reasons, Reason{
									ID:          fmt.Sprintf("%s/%d", fid, sp.PortIdx),
									State:       VerdictExposed,
									Kind:        "policy",
									Ref:         f.CheckID,
									Title:       "Unused external port left enabled",
									Severity:    sev,
									Expected:    "Operation = Disabled",
									Observed:    "Enabled (inactive, " + sp.TaggedPolicy + ")",
									Evidence:    f.Evidence,
									Remediation: f.Remediation.Summary,
									Source:      "unifi-port",
									Port:        sp.PortIdx,
								})
							}
						}
					}
				}
				if de, ok := pm.Entities[devEntityID(swMAC)]; ok {
					de.Reasons = append(de.Reasons, Reason{
						ID:          fid,
						State:       VerdictExposed,
						Kind:        "policy",
						Ref:         f.CheckID,
						Title:       f.Title,
						Severity:    sev,
						Expected:    "Unused external ports disabled",
						Observed:    f.Evidence,
						Evidence:    f.Evidence,
						Remediation: f.Remediation.Summary,
						Source:      "unifi-port",
						Port:        f.Port,
					})
				}
			} else if pe, ok := pm.Entities[pid]; ok {
				expected := "Isolated VLAN + Block All + MAC Port Security"
				if f.CheckID == "UB-UNIFI-PORT-EXT-UPLINK" {
					expected = "Custom/Block All (isolated VLANs only)"
				} else if f.CheckID == "UB-UNIFI-PORT-EXT-MULTI-MAC" {
					expected = "1 learned MAC on exterior drop"
				}
				pe.Reasons = append(pe.Reasons, Reason{
					ID:          fid,
					State:       VerdictExposed,
					Kind:        "policy",
					Ref:         f.CheckID,
					Title:       f.Title,
					Severity:    sev,
					Expected:    expected,
					Observed:    fmt.Sprintf("VLAN=%s, Tagged=%s, MAC-lock=%v", pe.NativeVLAN, pe.TaggedPolicy, pe.PortSecurity),
					Evidence:    f.Evidence,
					Remediation: f.Remediation.Summary,
					Source:      "unifi-port",
					Port:        f.Port,
				})
			}

		case strings.HasPrefix(f.CheckID, "UB-UNIFI-FW-"):
			rid := fmt.Sprintf("rule:%s/%d", f.CheckID, idxF)
			ruleEnt := &Entity{
				ID:          rid,
				Kind:        "rule",
				Label:       f.Title,
				Subtitle:    f.Client.NetworkName,
				Role:        "firewall",
				Side:        "outside",
				Weight:      3,
				State:       VerdictExposed,
				MaxSeverity: sev,
				StateLabel:  "Mismatch",
				IP:          f.Client.IP,
				DeviceID:    pm.GatewayID,
				Reasons: []Reason{{
					ID:          fid,
					State:       VerdictExposed,
					Kind:        "policy",
					Ref:         f.CheckID,
					Title:       f.Title,
					Severity:    sev,
					Expected:    "Block / Restrict External ingress",
					Observed:    f.Evidence,
					Evidence:    f.Evidence,
					Remediation: f.Remediation.Summary,
					Source:      "unifi-policy",
				}},
			}
			pm.Entities[rid] = ruleEnt
			pm.WANFlows = append(pm.WANFlows, WANFlow{
				ID:         rid,
				Kind:       "firewall",
				Label:      f.Client.NetworkName + " ALLOW",
				RuleName:   f.Title,
				TargetID:   pm.GatewayID,
				TargetName: f.Client.DisplayName(),
				State:      VerdictExposed,
				Severity:   sev,
			})

		case strings.HasPrefix(f.CheckID, "UB-UNIFI-BMC-"):
			hid := hostIDByIP[f.Client.IP]
			if hid == "" {
				hid = hostIDByMAC[strings.ToLower(f.Client.MAC)]
			}
			if he, ok := pm.Entities[hid]; ok {
				he.IsBMC = true
				he.Role = "bmc"
				if he.Weight < 3 {
					he.Weight = 3
				}
				he.Reasons = append(he.Reasons, Reason{
					ID:          fid,
					State:       VerdictExposed,
					Kind:        "policy",
					Ref:         f.CheckID,
					Title:       f.Title,
					Severity:    sev,
					Expected:    "Dedicated OOB Management VLAN",
					Observed:    "Shared VLAN: " + f.Client.NetworkName,
					Evidence:    f.Evidence,
					Remediation: f.Remediation.Summary,
					Source:      "unifi-policy",
				})
			}

		case strings.HasPrefix(f.CheckID, "UB-UNIFI-ISO-"):
			// Effective isolation policy violations attach to their target host
			// (e.g. BMC or Printer) when known, falling back to Gateway.
			hid := hostIDByIP[f.Client.IP]
			if hid == "" {
				hid = hostIDByMAC[strings.ToLower(f.Client.MAC)]
			}
			target := pm.Entities[hid]
			if target == nil {
				target = pm.Entities[pm.GatewayID]
			}
			if target != nil {
				target.Reasons = append(target.Reasons, Reason{
					ID:          fid,
					State:       VerdictExposed,
					Kind:        "policy",
					Ref:         f.CheckID,
					Title:       f.Title,
					Severity:    sev,
					Expected:    "Deny untrusted cross-zone path",
					Observed:    f.Evidence,
					Evidence:    f.Evidence,
					Remediation: f.Remediation.Summary,
					Source:      "unifi-isolation",
					Port:        f.Port,
				})
			}

		case strings.HasPrefix(f.CheckID, "UB-UNIFI-"):
			// Site-level controller / SSH / UPnP / Honeypot / Wi-Fi findings attach to Gateway!
			if gw, ok := pm.Entities[pm.GatewayID]; ok {
				gw.Reasons = append(gw.Reasons, Reason{
					ID:          fid,
					State:       VerdictExposed,
					Kind:        "policy",
					Ref:         f.CheckID,
					Title:       f.Title,
					Severity:    sev,
					Expected:    "Hardened UniFi control plane",
					Observed:    f.Evidence,
					Evidence:    f.Evidence,
					Remediation: f.Remediation.Summary,
					Source:      "unifi-controller",
					Port:        f.Port,
				})
			}

		default:
			// Host-level LAN service / BMC probe finding!
			hid := hostIDByIP[f.Client.IP]
			if hid == "" {
				hid = hostIDByMAC[strings.ToLower(f.Client.MAC)]
			}
			if he, ok := pm.Entities[hid]; ok {
				if f.Category == "oob-bmc" {
					he.IsBMC = true
					he.Role = "bmc"
					if he.Weight < 3 {
						he.Weight = 3
					}
				}
				// Pure inventory observations (asset-identity / service-advertised /
				// service-observed at Info severity) enrich service and device
				// identity without turning an otherwise compliant host into Exposed.
				if f.IsInventoryOnly() {
					recordObservedService(he, f)
					continue
				}
				he.Reasons = append(he.Reasons, Reason{
					ID:          fid,
					State:       VerdictExposed,
					Kind:        "check",
					Ref:         f.CheckID,
					Title:       f.Title,
					Severity:    sev,
					Expected:    "Authenticated / modern protocol / isolated",
					Observed:    f.Evidence,
					Evidence:    f.Evidence,
					Remediation: f.Remediation.Summary,
					Source:      "probe",
					Port:        f.Port,
				})
				// Mark matching service as exposed (or add UDP service like IPMI 623 / SNMP 161).
				markServiceExposed(he, f)
			}
		}
	}

	// 5. Add WAN Port Forwards to WANFlows.
	for i, a := range report.WANSurface {
		targetIP := a.Forward.FwdIP
		targetID := hostIDByIP[targetIP]
		if targetID == "" && a.Client.MAC != "" {
			targetID = hostIDByMAC[strings.ToLower(a.Client.MAC)]
		}
		isExpected := a.Severity < checks.SeverityMedium
		st := VerdictReview
		if a.Severity >= checks.SeverityHigh {
			st = VerdictExposed
		} else if isExpected {
			st = VerdictOK
		}
		pm.WANFlows = append(pm.WANFlows, WANFlow{
			ID:         fmt.Sprintf("wanfwd:%d", i),
			Kind:       "forward",
			Label:      fmt.Sprintf("%s %s → %s:%s", strings.ToUpper(a.Forward.Proto), a.Forward.DstPort, targetIP, a.Forward.FwdPort),
			RuleName:   a.Forward.Name,
			TargetID:   targetID,
			TargetIP:   targetIP,
			TargetName: firstStr(a.Client.DisplayName(), targetIP),
			Expected:   isExpected,
			State:      st,
			Severity:   a.Severity.String(),
		})
	}

	// 6. Finalize Verdict State & Label for EVERY Entity (Single Source of Truth!).
	for _, ent := range pm.Entities {
		if ent.Kind == "child" {
			continue
		}
		finalizeEntityVerdict(ent)
	}

	// Attach effective isolation matrix and measurable service coverage metrics.
	pm.Isolation = report.Isolation
	if len(profiles) > 0 {
		sc := probe.ComputeServiceCoverage(profiles)
		pm.ServiceCoverage = &sc
	}

	// Propagate WallGate states from their backing Port entities.
	for i := range pm.WallGates {
		if pe, ok := pm.Entities[pm.WallGates[i].PortID]; ok {
			pm.WallGates[i].State = pe.State
			if pe.State == VerdictExposed || pe.State == VerdictReview {
				pm.Census.OpenWallGates++
			}
		}
	}
	pm.Census.TotalWallGates = len(pm.WallGates)

	// 7. Build Ranked Fix-Next Queue & Assign Deterministic Pin Numbers!
	pm.Queue = buildFixNextQueue(pm)
	for i := range pm.Queue {
		pin := i + 1
		pm.Queue[i].Pin = pin
		if ent, ok := pm.Entities[pm.Queue[i].SubjectID]; ok && ent.PinNumber == 0 {
			ent.PinNumber = pin
		}
	}
	// Mirror pin numbers onto WallGates and WANFlows.
	for i := range pm.WallGates {
		if pe, ok := pm.Entities[pm.WallGates[i].PortID]; ok {
			pm.WallGates[i].PinNumber = pe.PinNumber
		}
	}
	for i := range pm.WANFlows {
		if re, ok := pm.Entities[pm.WANFlows[i].ID]; ok {
			pm.WANFlows[i].PinNumber = re.PinNumber
		} else if te, ok := pm.Entities[pm.WANFlows[i].TargetID]; ok && !pm.WANFlows[i].Expected {
			pm.WANFlows[i].PinNumber = te.PinNumber
		}
	}

	// 8. Build Physical Blueprint Rows (real LLDP tree order + UplinkUnknown + APs without port tables!).
	pm.Physical = buildPhysicalRows(snap, swByMAC, gwMAC, apClientCount, pm.Entities)

	// 9. Build Logical Zone Lanes (BMCs always pinned in their real VLAN, clean hosts in dot grid!).
	pm.Logical = buildLogicalLanes(snap, topo, pm.Entities, netEntByName)

	// 10. Compute Census counts from the exact finalized entities!
	for _, ent := range pm.Entities {
		switch ent.Kind {
		case "host":
			if ent.IsBMC {
				pm.Census.BMCCount++
			}
			if ent.ExactCVECount > 0 {
				pm.Census.ExactCVEHosts++
			}
			switch ent.State {
			case VerdictExposed:
				pm.Census.ExposedCount++
			case VerdictReview:
				pm.Census.ReviewCount++
			case VerdictUnknown:
				pm.Census.UnassessedCount++
			}
		case "port", "rule", "device":
			if ent.State == VerdictExposed {
				pm.Census.ExposedCount++
			} else if ent.State == VerdictReview {
				pm.Census.ReviewCount++
			}
		}
	}

	// 11. Build 1-Sentence Verdict Headline!
	if len(pm.Queue) == 0 {
		pm.Headline = fmt.Sprintf("All clear — %d VLANs, %d devices, and %d wall gates match policy.", len(pm.Logical), len(snap.Devices), pm.Census.TotalWallGates)
	} else if len(pm.Queue) == 1 {
		pm.Headline = pm.Queue[0].Sentence
	} else {
		pm.Headline = fmt.Sprintf("%s (+%d more item%s in queue)", pm.Queue[0].Sentence, len(pm.Queue)-1, pluralS(len(pm.Queue)-1))
	}

	return pm
}

func finalizeEntityVerdict(ent *Entity) {
	// Sort reasons worst-first so the top reason is always visible first in the inspector!
	sort.SliceStable(ent.Reasons, func(i, j int) bool {
		if verdictRank(ent.Reasons[i].State) != verdictRank(ent.Reasons[j].State) {
			return verdictRank(ent.Reasons[i].State) > verdictRank(ent.Reasons[j].State)
		}
		return sevStrRank(ent.Reasons[i].Severity) > sevStrRank(ent.Reasons[j].Severity)
	})

	if len(ent.Reasons) == 0 {
		if ent.Kind == "host" && ent.ScannedAt == nil {
			ent.State = VerdictUnknown
			ent.MaxSeverity = "unknown"
			ent.StateLabel = "Unassessed"
			return
		}
		ent.State = VerdictOK
		ent.MaxSeverity = "ok"
		if ent.Kind == "host" {
			ent.StateLabel = "No findings"
		} else {
			ent.StateLabel = "Matches policy"
		}
		return
	}

	worstState := VerdictOK
	worstSev := "info"
	for _, r := range ent.Reasons {
		if verdictRank(r.State) > verdictRank(worstState) {
			worstState = r.State
		}
		if sevStrRank(r.Severity) > sevStrRank(worstSev) {
			worstSev = r.Severity
		}
	}
	ent.State = worstState
	ent.MaxSeverity = worstSev
	switch worstState {
	case VerdictExposed:
		if ent.Kind == "port" || ent.Kind == "rule" {
			ent.StateLabel = "Mismatch"
		} else {
			ent.StateLabel = "Exposed"
		}
	case VerdictReview:
		ent.StateLabel = "Review"
	case VerdictUnknown:
		ent.StateLabel = "Unassessed"
	default:
		ent.StateLabel = "Matches policy"
	}
}

func buildFixNextQueue(pm *PresentationModel) []QueueItem {
	var items []QueueItem
	for _, ent := range pm.Entities {
		if ent.State != VerdictExposed {
			continue
		}
		if ent.Kind == "device" && ent.Role != "gateway" {
			// Skip redundant device-level wrapper when its individual ports are already queued.
			hasOnlyPortRollup := true
			for _, r := range ent.Reasons {
				if r.Ref != "UB-UNIFI-PORT-EXT-UNUSED-OPEN" {
					hasOnlyPortRollup = false
				}
			}
			if hasOnlyPortRollup {
				// Keep one concise queue item for unused external ports on this switch.
				top := ent.Reasons[0]
				items = append(items, QueueItem{
					Sentence:  fmt.Sprintf("%s has unused external ports left open (%s)", ent.Label, top.Title),
					Category:  "perimeter",
					Severity:  top.Severity,
					State:     ent.State,
					Score:     sevStrRank(top.Severity)*10*ent.Weight + 5,
					SubjectID: ent.ID,
					EntityIDs: []string{ent.ID},
					ReasonRef: top.Ref,
				})
				continue
			}
		}
		if len(ent.Reasons) == 0 {
			continue
		}
		top := ent.Reasons[0]
		cat := "service"
		sentence := fmt.Sprintf("%s: %s", ent.Label, top.Title)
		related := []string{ent.ID}

		switch ent.Kind {
		case "port":
			cat = "perimeter"
			if ent.PortZone == "external_uplink" {
				sentence = fmt.Sprintf("%s carries %s VLANs to external %s", ent.Label, ent.TaggedPolicy, ent.Subtitle)
			} else if ent.PortZone == "external" {
				if ent.PortState == "inactive_enabled" {
					// Already aggregated per external switch device above to keep queue crisp!
					continue
				}
				sentence = fmt.Sprintf("%s (external) is unrestricted (%s / %s)", ent.Label, ent.NativeVLAN, ent.TaggedPolicy)
			}
			if ent.DeviceID != "" {
				related = append(related, ent.DeviceID)
			}
			related = append(related, ent.PeerIDs...)

		case "rule":
			cat = "wan"
			sentence = fmt.Sprintf("WAN rule allows %s on %s", ent.Subtitle, ent.Label)
			if ent.DeviceID != "" {
				related = append(related, ent.DeviceID)
			}

		case "device":
			cat = "controller"
			sentence = fmt.Sprintf("%s: %s", ent.Label, top.Title)

		case "host":
			if ent.IsBMC {
				cat = "bmc"
				sentence = fmt.Sprintf("BMC %s (%s) on %s: %s", ent.Label, ent.IP, ent.NetworkName, top.Title)
			} else if ent.ExactCVECount > 0 && top.Kind == "cve" {
				cat = "service"
				sentence = fmt.Sprintf("%s (%s): %d exact CVE(s) · 0 check findings", ent.Label, ent.NetworkName, ent.ExactCVECount)
			} else {
				cat = "service"
				sentence = fmt.Sprintf("%s (%s): %s", ent.Label, ent.NetworkName, top.Title)
			}
			if ent.PortID != "" {
				related = append(related, ent.PortID)
			}
			if ent.NetworkID != "" {
				related = append(related, ent.NetworkID)
			}
		}

		score := sevStrRank(ent.MaxSeverity) * 10 * ent.Weight
		if cat == "wan" {
			score += 25
		} else if cat == "bmc" {
			score += 20
		} else if cat == "perimeter" {
			score += 15
		}

		items = append(items, QueueItem{
			Sentence:  sentence,
			Category:  cat,
			Severity:  ent.MaxSeverity,
			State:     ent.State,
			Score:     score,
			SubjectID: ent.ID,
			EntityIDs: related,
			ReasonRef: top.Ref,
		})
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].Score != items[j].Score {
			return items[i].Score > items[j].Score
		}
		if sevStrRank(items[i].Severity) != sevStrRank(items[j].Severity) {
			return sevStrRank(items[i].Severity) > sevStrRank(items[j].Severity)
		}
		return items[i].SubjectID < items[j].SubjectID
	})
	return items
}

func buildPhysicalRows(
	snap *unifi.Snapshot,
	swByMAC map[string]risk.SwitchDeviceView,
	gwMAC string,
	apClientCount map[string]int,
	entities map[string]*Entity,
) []PhysicalRow {
	devByMAC := make(map[string]unifi.Device, len(snap.Devices))
	children := make(map[string][]string)
	var roots []string
	var unknownUplink []string

	for _, d := range snap.Devices {
		mac := strings.ToLower(d.MAC)
		devByMAC[mac] = d
	}
	for _, d := range snap.Devices {
		mac := strings.ToLower(d.MAC)
		parent := strings.ToLower(d.UplinkMAC)
		if mac == gwMAC {
			roots = append(roots, mac)
		} else if parent != "" && devByMAC[parent].MAC != "" {
			children[parent] = append(children[parent], mac)
		} else {
			unknownUplink = append(unknownUplink, mac)
		}
	}
	for p := range children {
		sort.Slice(children[p], func(i, j int) bool {
			di, dj := devByMAC[children[p][i]], devByMAC[children[p][j]]
			if di.UplinkPort != dj.UplinkPort {
				return di.UplinkPort < dj.UplinkPort
			}
			return di.Name < dj.Name
		})
	}

	// Collect enabled SSID names for AP rows.
	var enabledSSIDs []string
	for _, w := range snap.WLANs {
		if w.Enabled && w.Name != "" {
			enabledSSIDs = append(enabledSSIDs, w.Name)
		}
	}

	var rows []PhysicalRow
	visited := make(map[string]bool)
	var walk func(mac string, depth int, unknown bool)
	walk = func(mac string, depth int, unknown bool) {
		if visited[mac] {
			return
		}
		visited[mac] = true
		d := devByMAC[mac]
		sw, hasSW := swByMAC[mac]
		side := "inside"
		zoneSrc := ""
		if hasSW && sw.ExternalDevice {
			side = "outside"
			zoneSrc = sw.ZoneSource
		}

		var portIDs []string
		sfpStart := 0
		if hasSW {
			for _, p := range sw.Ports {
				portIDs = append(portIDs, portEntityID(mac, p.PortIdx))
				if sfpStart == 0 && strings.Contains(strings.ToUpper(p.Media), "SFP") {
					sfpStart = p.PortIdx
				}
			}
		}

		parentID := ""
		parentPortID := ""
		parentLabel := ""
		if d.UplinkMAC != "" {
			pmac := strings.ToLower(d.UplinkMAC)
			parentID = devEntityID(pmac)
			if d.UplinkPort > 0 {
				parentPortID = portEntityID(pmac, d.UplinkPort)
				parentLabel = fmt.Sprintf("%s #%d", firstStr(d.UplinkName, devByMAC[pmac].Name), d.UplinkPort)
				if pe, ok := entities[parentPortID]; ok && pe.PoEEnabled && pe.PoEPower != "" {
					parentLabel += " · ⚡" + pe.PoEPower + "W"
				}
			} else if d.UplinkName != "" {
				parentLabel = d.UplinkName
			}
		}

		row := PhysicalRow{
			DeviceID:      devEntityID(mac),
			Name:          d.Name,
			Model:         d.Model,
			IP:            d.IP,
			Type:          d.Type,
			Version:       d.Version,
			Upgradable:    d.Upgradable,
			Side:          side,
			ZoneSource:    zoneSrc,
			Depth:         depth,
			UplinkUnknown: unknown,
			ParentID:      parentID,
			ParentPortID:  parentPortID,
			ParentLabel:   parentLabel,
			PortIDs:       portIDs,
			SFPStartIdx:   sfpStart,
			ClientCount:   apClientCount[mac],
		}
		if strings.EqualFold(d.Type, "uap") || strings.Contains(strings.ToLower(d.Model), "iw") || strings.Contains(strings.ToLower(d.Model), "ap") {
			row.SSIDs = enabledSSIDs
		}
		rows = append(rows, row)
		for _, ch := range children[mac] {
			walk(ch, depth+1, false)
		}
	}

	for _, r := range roots {
		walk(r, 0, false)
	}
	sort.Slice(unknownUplink, func(i, j int) bool { return devByMAC[unknownUplink[i]].Name < devByMAC[unknownUplink[j]].Name })
	for _, u := range unknownUplink {
		walk(u, 0, true)
	}
	return rows
}

func buildLogicalLanes(
	snap *unifi.Snapshot,
	topo *topology.Model,
	entities map[string]*Entity,
	netEntByName map[string]string,
) []LogicalLane {
	// Index all host entities by lowercase VLAN name.
	hostsByNet := make(map[string][]*Entity)
	trustedExposedIoT := 0
	for _, ent := range entities {
		if ent.Kind != "host" {
			continue
		}
		key := strings.ToLower(ent.NetworkName)
		hostsByNet[key] = append(hostsByNet[key], ent)
	}

	var lanes []LogicalLane
	seenNet := make(map[string]bool)

	addLane := func(id, name, vlan, subnet, zone string, isolated bool) {
		key := strings.ToLower(name)
		seenNet[key] = true
		lane := LogicalLane{
			NetworkID:  id,
			Name:       name,
			VLAN:       vlan,
			Subnet:     subnet,
			ZoneName:   firstStr(zone, "Internal"),
			Isolated:   isolated,
			ValveState: VerdictOK,
		}
		hosts := hostsByNet[key]
		sort.Slice(hosts, func(i, j int) bool {
			if verdictRank(hosts[i].State) != verdictRank(hosts[j].State) {
				return verdictRank(hosts[i].State) > verdictRank(hosts[j].State)
			}
			return hosts[i].Label < hosts[j].Label
		})
		for _, h := range hosts {
			lane.TotalHosts++
			if h.IsBMC {
				lane.BMCIDs = append(lane.BMCIDs, h.ID)
				continue
			}
			if !isolated && h.State == VerdictExposed && (h.Role == "iot" || h.Role == "camera" || h.Role == "printer" || h.Role == "media") {
				trustedExposedIoT++
			}
			switch h.State {
			case VerdictExposed, VerdictReview:
				lane.PinnedHostIDs = append(lane.PinnedHostIDs, h.ID)
			case VerdictUnknown:
				lane.UnknownHostIDs = append(lane.UnknownHostIDs, h.ID)
			default:
				lane.CleanHostIDs = append(lane.CleanHostIDs, h.ID)
			}
		}
		lanes = append(lanes, lane)
	}

	if topo != nil && len(topo.VLANs) > 0 {
		for _, vg := range topo.VLANs {
			nid := netEntByName[strings.ToLower(vg.Name)]
			if nid == "" {
				nid = netEntityID("", vg.Name)
			}
			addLane(nid, vg.Name, vg.VLAN, vg.Subnet, vg.ZoneName, vg.Isolated)
		}
	} else {
		for _, n := range snap.Networks {
			iso := n.IsolationEnabled || strings.EqualFold(n.Purpose, "guest")
			addLane(netEntityID(n.ID, n.Name), n.Name, n.VLAN, n.Subnet, n.ZoneName, iso)
		}
	}

	// Add subtle migration hint only on empty isolated VLANs when exposed IoT actually sits on Trusted.
	for i := range lanes {
		if lanes[i].Isolated && lanes[i].TotalHosts == 0 && trustedExposedIoT > 0 {
			lanes[i].MigrationHint = fmt.Sprintf("%d exposed IoT/appliance host(s) on Trusted → move here", trustedExposedIoT)
		}
	}
	return lanes
}

func buildHostServices(cv ClientView, hp probe.HostProfile, wan []risk.ExposureAssessment, vlanIsolated, behindCGNAT bool) []ServiceView {
	type wanPortInfo struct {
		restricted bool
	}
	wanTCPPorts := make(map[int]wanPortInfo)
	wanUDPPorts := make(map[int]wanPortInfo)
	recordWAN := func(m map[int]wanPortInfo, port int, restricted bool) {
		if cur, exists := m[port]; exists {
			// If ANY matching forward is unrestricted (src=any), the endpoint is unrestricted.
			m[port] = wanPortInfo{restricted: cur.restricted && restricted}
		} else {
			m[port] = wanPortInfo{restricted: restricted}
		}
	}
	for _, a := range wan {
		if !a.Forward.Enabled {
			continue
		}
		ports := a.Forward.ExpandFwdPorts(64)
		restricted := a.Forward.IsSourceRestricted()
		for _, p := range ports {
			if a.Forward.MatchesTransport("tcp") {
				recordWAN(wanTCPPorts, p, restricted)
			}
			if a.Forward.MatchesTransport("udp") {
				recordWAN(wanUDPPorts, p, restricted)
			}
		}
	}
	wanReachLabel := func(info wanPortInfo) string {
		if behindCGNAT {
			return "wan-cgnat"
		}
		if info.restricted {
			return "wan-restricted"
		}
		return "wan"
	}

	protoByKey := make(map[string]probe.Service)
	for _, svc := range hp.Services {
		if svc.Port > 0 {
			t := strings.ToLower(strings.TrimSpace(svc.Transport))
			if t == "" {
				t = "tcp"
			}
			protoByKey[fmt.Sprintf("%s:%d", t, svc.Port)] = svc
		}
	}
	defaultReach := "lan"
	if vlanIsolated {
		defaultReach = "vlan-only"
	}

	var out []ServiceView
	seen := make(map[string]bool)
	for _, p := range cv.OpenPorts {
		key := fmt.Sprintf("tcp:%d", p)
		if seen[key] {
			continue
		}
		seen[key] = true
		reach := defaultReach
		srcRestricted := false
		if info, ok := wanTCPPorts[p]; ok {
			reach = wanReachLabel(info)
			srcRestricted = info.restricted
		}
		svcMeta := protoByKey[key]
		name := svcMeta.Protocol
		if name == "" {
			name = commonPortLabel(p)
		}
		out = append(out, ServiceView{
			Port:             p,
			Proto:            "tcp",
			Name:             name,
			Reachable:        reach,
			State:            firstStr(svcMeta.State, probe.ServiceStateCandidatePort),
			SourceRestricted: srcRestricted,
			Label:            fmt.Sprintf("%s :%d", strings.ToUpper(firstStr(name, "tcp")), p),
		})
	}
	// Include observed UDP or passive services from hp.Services that were not in TCP OpenPorts.
	for _, svc := range hp.Services {
		if svc.Port <= 0 {
			continue
		}
		t := strings.ToLower(strings.TrimSpace(svc.Transport))
		if t == "" {
			t = "tcp"
		}
		key := fmt.Sprintf("%s:%d", t, svc.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		reach := defaultReach
		srcRestricted := false
		if t == "tcp" {
			if info, ok := wanTCPPorts[svc.Port]; ok {
				reach = wanReachLabel(info)
				srcRestricted = info.restricted
			}
		} else if t == "udp" {
			if info, ok := wanUDPPorts[svc.Port]; ok {
				reach = wanReachLabel(info)
				srcRestricted = info.restricted
			}
		}
		name := firstStr(svc.Protocol, commonPortLabel(svc.Port))
		out = append(out, ServiceView{
			Port:             svc.Port,
			Proto:            t,
			Name:             name,
			Reachable:        reach,
			State:            firstStr(svc.State, probe.ServiceStateObservedProtocol),
			SourceRestricted: srcRestricted,
			Label:            fmt.Sprintf("%s :%d", strings.ToUpper(firstStr(name, t)), svc.Port),
		})
	}
	// Also record UDP-only WAN forwards as distinct UDP endpoints so a UDP forward
	// never conflates with a TCP service sharing the same port number.
	for p, info := range wanUDPPorts {
		key := fmt.Sprintf("udp:%d", p)
		if seen[key] {
			continue
		}
		seen[key] = true
		name := firstStr(commonPortLabel(p), "udp")
		out = append(out, ServiceView{
			Port:             p,
			Proto:            "udp",
			Name:             name,
			Reachable:        wanReachLabel(info),
			State:            "configured-forward",
			SourceRestricted: info.restricted,
			Label:            fmt.Sprintf("%s :%d", strings.ToUpper(name), p),
		})
	}
	return out
}

func isSnapshotWANBehindCGNAT(snap *unifi.Snapshot) bool {
	if snap == nil || snap.Health == nil || snap.Health.WANIP == "" {
		return false
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(snap.Health.WANIP))
	if err != nil {
		return false
	}
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return true
	}
	cgnat := netip.MustParsePrefix("100.64.0.0/10")
	return cgnat.Contains(addr)
}

func recordObservedService(ent *Entity, f checks.Finding) {
	if f.Port <= 0 {
		return
	}
	proto := f.EffectiveTransport()
	obsState := probe.ServiceStateObservedProtocol
	if f.ClaimKind == checks.ClaimServiceAdvertised {
		obsState = probe.ServiceStateAdvertisedService
	}
	for i := range ent.Services {
		if ent.Services[i].Port == f.Port && strings.EqualFold(ent.Services[i].Proto, proto) {
			ent.Services[i].Label = compactCheckChip(f)
			if obsState == probe.ServiceStateObservedProtocol {
				ent.Services[i].State = obsState
			}
			return
		}
	}
	reach := "lan"
	if f.ClaimKind == checks.ClaimServiceAdvertised {
		reach = "advertised"
	}
	ent.Services = append(ent.Services, ServiceView{
		Port:      f.Port,
		Proto:     proto,
		Name:      commonPortLabel(f.Port),
		Reachable: reach,
		State:     obsState,
		Exposed:   false,
		Label:     compactCheckChip(f),
	})
}

func markServiceExposed(ent *Entity, f checks.Finding) {
	if f.Port <= 0 {
		return
	}
	proto := f.EffectiveTransport()
	for i := range ent.Services {
		if ent.Services[i].Port == f.Port && strings.EqualFold(ent.Services[i].Proto, proto) {
			ent.Services[i].Exposed = true
			if sevStrRank(f.EffectiveSeverity.String()) > sevStrRank(ent.Services[i].Severity) {
				ent.Services[i].Severity = f.EffectiveSeverity.String()
			}
			ent.Services[i].Label = compactCheckChip(f)
			return
		}
	}
	ent.Services = append(ent.Services, ServiceView{
		Port:      f.Port,
		Proto:     proto,
		Name:      commonPortLabel(f.Port),
		Reachable: "lan",
		Exposed:   true,
		Severity:  f.EffectiveSeverity.String(),
		Label:     compactCheckChip(f),
	})
}

func compactCheckChip(f checks.Finding) string {
	switch f.CheckID {
	case "UB-0005":
		return fmt.Sprintf("VNC :%d", f.Port)
	case "UB-0020":
		return fmt.Sprintf("TLS 1.0/1.1 :%d", f.Port)
	case "UB-0021":
		return "SNMP public :161"
	case "UB-0030":
		return "IPMI RMCP+ :623"
	case "UB-2026-0001":
		return fmt.Sprintf("Zehnder :%d", f.Port)
	case "UB-2026-0002":
		return "AVR Telnet :23"
	case "UB-2026-0026":
		return "Cast API :8008"
	case "UB-2026-0061":
		return "Redfish :443"
	case "UB-2026-0062":
		return "BMC Web :443"
	case "UB-2026-0063":
		return "iDRAC/iLO :443"
	case "UB-2026-0064":
		return fmt.Sprintf("Intel AMT :%d", f.Port)
	case "UB-2026-0065":
		return fmt.Sprintf("iKVM :%d", f.Port)
	}
	if strings.Contains(f.CheckID, "SMB-V1") {
		return "SMBv1 :445"
	}
	if strings.Contains(f.CheckID, "SMB-SIGNING") {
		return "SMB Unsigned :445"
	}
	if strings.Contains(f.CheckID, "TLS-CERTIFICATE-EXPIRED") {
		return fmt.Sprintf("Expired Cert :%d", f.Port)
	}
	if f.Port > 0 {
		return fmt.Sprintf("%s :%d", f.CheckID, f.Port)
	}
	return f.CheckID
}

func commonPortLabel(p int) string {
	switch p {
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 53:
		return "dns"
	case 80:
		return "http"
	case 161:
		return "snmp"
	case 443:
		return "https"
	case 445:
		return "smb"
	case 554:
		return "rtsp"
	case 623:
		return "ipmi"
	case 1883:
		return "mqtt"
	case 3389:
		return "rdp"
	case 5900, 5901:
		return "vnc"
	case 8008:
		return "cast"
	case 8123:
		return "homeassistant"
	default:
		return ""
	}
}

func verdictRank(v VerdictState) int {
	switch v {
	case VerdictExposed:
		return 3
	case VerdictReview:
		return 2
	case VerdictUnknown:
		return 1
	default:
		return 0
	}
}

func sevStrRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

func formatKEV(n int) string {
	if n <= 0 {
		return ""
	}
	return fmt.Sprintf(" (%d CISA KEV)", n)
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
