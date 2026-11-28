// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package server

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/karalabe/uniblue/internal/blast"
	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/classify"
	"github.com/karalabe/uniblue/internal/config"
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
	// ID identifies this reason within the presentation model (a cross-linked reason can share its ID across entities).
	ID string `json:"id"`
	// State is the verdict level contributed by this reason ("exposed", "review", "unknown", or "ok").
	State VerdictState `json:"state"`
	// Kind classifies the finding category ("check", "cve", "policy", "placement", "coverage", or "firmware").
	Kind string `json:"kind"`
	// Ref is the check ID, CVE list, or synthetic policy code backing this reason.
	Ref string `json:"ref"`
	// Title is a concise headline describing the issue.
	Title string `json:"title"`
	// Severity is the normalized severity string ("critical", "high", "medium", "low", "info", or "unknown").
	Severity string `json:"severity"`
	// Expected states the desired compliant configuration or posture.
	Expected string `json:"expected,omitempty"`
	// Observed summarizes the live state that triggered this reason.
	Observed string `json:"observed,omitempty"`
	// Evidence holds the concrete probe output or controller detail proving the finding.
	Evidence string `json:"evidence,omitempty"`
	// Remediation describes the recommended operator action to clear this reason.
	Remediation string `json:"remediation,omitempty"`
	// Source identifies the subsystem that produced this reason ("probe",
	// "nvd-cve", "unifi-policy", "unifi-controller", "unifi-port",
	// "unifi-isolation", or "topology-placement").
	Source string `json:"source"`
	// Port is the associated TCP/UDP port or physical switch port index, when applicable.
	Port int `json:"port,omitempty"`
	// Secondary marks a cross-linked copy of a reason whose primary owner is another
	// entity (such as a port, rule, or network) so it is not double-counted in queues or census totals.
	Secondary bool `json:"secondary,omitempty"`
}

// ServiceView represents one discovered network service on a host along with
// its computed reachability boundary and evidence provenance.
type ServiceView struct {
	// Port is the TCP or UDP port number (or start port for a wide UDP forward range).
	Port int `json:"port"`
	// Proto is the transport protocol ("tcp" or "udp").
	Proto string `json:"proto"`
	// AddressFamily is "ipv4", "ipv6", "dual", or empty when merged or unknown/unspecified.
	AddressFamily string `json:"address_family,omitempty"`
	// Name is the detected protocol or well-known service name (e.g., "ssh", "https").
	Name string `json:"name,omitempty"`
	// Reachable describes the computed network boundary ("wan", "wan-restricted",
	// "wan-unknown", "wan-cgnat", "lan", "vlan-only", "advertised", or "unknown").
	Reachable string `json:"reachable"`
	// State records how the service was observed (e.g., "observed-protocol",
	// "candidate-port", "connect-only", "advertised-service", or "configured-forward").
	State string `json:"state,omitempty"`
	// SourceRestricted reports whether WAN access is limited to specific source IPs or CIDRs.
	SourceRestricted bool `json:"source_restricted,omitempty"`
	// Exposed is true when any non-inventory finding flagged this service (does not require an active check).
	Exposed bool `json:"exposed,omitempty"`
	// Severity is the highest finding severity attached to this service when Exposed is true.
	Severity string `json:"severity,omitempty"`
	// Label is the compact UI chip text rendered for this service (e.g., "HTTPS :443").
	Label string `json:"label,omitempty"`
	// observedIPs retains the exact listener addresses observed for this row so
	// subsequent findings attach to the matching listener instead of conflating
	// distinct addresses on dual-stack or multi-IP hosts.
	observedIPs []netip.Addr
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
//	rule:<idx>  (includes the finding's slice index and can shift between snapshots)
//	child:<parentID>/<childID>
type Entity struct {
	// controllerID preserves the adopted device ID alongside its MAC-based drawer ID.
	controllerID string

	// ID is the entity identifier following the conventions documented above (rule:<idx> IDs can shift between snapshots).
	ID string `json:"id"`
	// Kind identifies the entity category ("device", "port", "network", "host", "rule", or "child").
	Kind string `json:"kind"`
	// Label is the primary human-readable display name.
	Label string `json:"label"`
	// Subtitle holds secondary identity metadata such as device role, model/IP, or VLAN subnet.
	Subtitle string `json:"subtitle,omitempty"`
	// Role classifies the entity's function (e.g., "gateway", "switch", "ap", "bmc", "camera", "server", "iot", "firewall").
	Role string `json:"role,omitempty"`
	// Side indicates physical perimeter placement ("inside", "outside", or "unknown").
	Side string `json:"side,omitempty"`
	// ZoneSource records how Side or port zoning was determined ("config", "auto", "parent_link", or "default").
	ZoneSource string `json:"zone_source,omitempty"`
	// Weight is the priority multiplier used when ranking items in the Fix-Next queue.
	Weight int `json:"weight"`
	// State is the finalized four-state security verdict for this entity.
	State VerdictState `json:"state"`
	// MaxSeverity is the highest active reason severity on this entity, or "ok" / "unknown".
	MaxSeverity string `json:"max_severity"`
	// StateLabel is the short status phrase displayed in badges (e.g., "No findings", "Exposed", "Mismatch").
	StateLabel string `json:"state_label"`
	// Reasons lists all evidenced findings, CVEs, and review notes attached to this entity, sorted worst-first.
	Reasons []Reason `json:"reasons,omitempty"`
	// PinNumber is the 1-based Fix-Next queue rank assigned to this entity, or 0 if unpinned.
	PinNumber int `json:"pin_number,omitempty"`
	// ScannedAt records when this host was last actively probed, or nil if unscanned.
	ScannedAt *time.Time `json:"scanned_at,omitempty"`
	// Skipped is true when active probing was intentionally skipped for this host.
	Skipped bool `json:"skipped,omitempty"`
	// SkipReason explains why active probing was skipped.
	SkipReason string `json:"skip_reason,omitempty"`
	// DeviceID links a port, rule, or wired host to its parent UniFi infrastructure device entity ID.
	DeviceID string `json:"device_id,omitempty"`
	// PortID links a wired host (or port itself) to its physical switch port entity ID.
	PortID string `json:"port_id,omitempty"`
	// NetworkID links an entity to its owning VLAN network entity ID.
	NetworkID string `json:"network_id,omitempty"`
	// NetworkName is the human-readable VLAN or network name.
	NetworkName string `json:"network_name,omitempty"`
	// APID links a wireless host to the UniFi access point entity ID it is associated with.
	APID string `json:"ap_id,omitempty"`
	// ESSID is the Wi-Fi SSID name for wireless hosts.
	ESSID string `json:"essid,omitempty"`
	// IP is the primary IPv4 address (or primary management IP for devices).
	IP string `json:"ip,omitempty"`
	// IPv6 lists observed IPv6 addresses for this host.
	IPv6 []string `json:"ipv6,omitempty"`
	// MAC is the lowercase hardware MAC address.
	MAC string `json:"mac,omitempty"`
	// Vendor is the resolved hardware manufacturer name.
	Vendor string `json:"vendor,omitempty"`
	// Model is the hardware model string for UniFi devices and enrolled child devices.
	Model string `json:"model,omitempty"`
	// Firmware is the reported firmware version for UniFi devices and enrolled child devices.
	Firmware string `json:"firmware,omitempty"`
	// IsWired reports whether a host is connected over Ethernet rather than Wi-Fi.
	IsWired bool `json:"is_wired,omitempty"`
	// IsBMC reports whether a host was identified as an out-of-band server management controller.
	IsBMC bool `json:"is_bmc,omitempty"`
	// ExactCVECount is the total number of exact-version CVE matches on this host or device.
	ExactCVECount int `json:"exact_cve_count,omitempty"`
	// PotCVECount is the total number of non-exact potential CVE matches on this host or device (including known versions with ambiguous vendor backports).
	PotCVECount int `json:"pot_cve_count,omitempty"`
	// Services lists deduplicated listening and forwarded network services on this host.
	Services []ServiceView `json:"services,omitempty"`
	// ConnectOnlyPorts lists protected print or serial sink TCP ports where probing deliberately stopped after TCP connect.
	ConnectOnlyPorts []int `json:"connect_only_ports,omitempty"`
	// ExactCVEs holds the rolled-up exact-version CVE summaries attached to this entity.
	ExactCVEs []cve.ProductSummary `json:"exact_cves,omitempty"`
	// PotentialCVEs holds the rolled-up non-exact CVE verification summaries attached to this entity (including known versions with ambiguous vendor backports).
	PotentialCVEs []cve.ProductSummary `json:"potential_cves,omitempty"`

	// ParentID links an enrolled child device to its owning bridge, NVR, or UniFi device entity ID.
	ParentID string `json:"parent_id,omitempty"`
	// ChildIDs lists enrolled child entity IDs managed behind this host or device.
	ChildIDs []string `json:"child_ids,omitempty"`
	// IdentitySource records which inventory feed supplied a child device's identity.
	IdentitySource string `json:"identity_source,omitempty"`
	// DirectLANReachability reports whether a child device is directly reachable on the LAN ("unknown", "non-ip-radio", or "routed", copied from inventory).
	DirectLANReachability string `json:"direct_lan_reachability,omitempty"`
	// OutboundDependencies lists external internet or cloud endpoints associated with this host (can come from owner config or vendor feeds without observed traffic).
	OutboundDependencies []probe.OutboundDependency `json:"outbound_dependencies,omitempty"`

	// PortIdx is the 1-based physical port number on the parent switch or gateway (Kind == "port").
	PortIdx int `json:"port_idx,omitempty"`
	// PortZone is the physical perimeter zone classification (e.g., "internal", "external", "external_uplink", "unused", "wan").
	PortZone string `json:"port_zone,omitempty"`
	// PortState is the operational port status ("active", "inactive_enabled", or "disabled").
	PortState string `json:"port_state,omitempty"`
	// Speed is the negotiated link speed in Mbps.
	Speed int `json:"speed,omitempty"`
	// Media is the physical port media type (e.g., "GE", "SFP+").
	Media string `json:"media,omitempty"`
	// PoEEnabled reports whether Power over Ethernet is active on this port.
	PoEEnabled bool `json:"poe_enabled,omitempty"`
	// PoEPower is the formatted PoE power draw in watts.
	PoEPower string `json:"poe_power,omitempty"`
	// NativeVLAN is the untagged native network name assigned to this port.
	NativeVLAN string `json:"native_vlan,omitempty"`
	// TaggedPolicy summarizes tagged VLAN handling (e.g., "block_all", "all", "custom").
	TaggedPolicy string `json:"tagged_policy,omitempty"`
	// PortSecurityUnknown is true when the controller did not report MAC restriction state for this port.
	PortSecurityUnknown bool `json:"port_security_unknown,omitempty"`
	// PortSecurity reports whether MAC-address port security locking is enabled on this port.
	PortSecurity bool `json:"port_security,omitempty"`
	// PortIsolation reports whether switch port isolation is enabled on this port.
	PortIsolation bool `json:"port_isolation,omitempty"`
	// PortIsolationUnknown is true when the controller did not report port isolation state.
	PortIsolationUnknown bool `json:"port_isolation_unknown,omitempty"`
	// MACTableCount is the number of active MAC addresses learned on this switch port.
	MACTableCount int `json:"mac_table_count,omitempty"`
	// STPState is the Spanning Tree Protocol port state (e.g., "forwarding", "discarding", "blocking").
	STPState string `json:"stp_state,omitempty"`
	// PeerIDs lists the entity IDs of UniFi devices or clients connected to this port.
	PeerIDs []string `json:"peer_ids,omitempty"`
}

// QueueItem is one ranked entry in the Fix-Next rail. Queue[0] drives the
// top-of-page verdict sentence.
type QueueItem struct {
	// Pin is the 1-based rank displayed on map pins and queue rows.
	Pin int `json:"pin"`
	// Sentence is the plain-English summary rendered for this queue item.
	Sentence string `json:"sentence"`
	// Category groups the item ("perimeter", "wan", "bmc", "service", or "controller").
	Category string `json:"category"`
	// Severity is the item's effective severity string.
	Severity string `json:"severity"`
	// State is the underlying subject entity's verdict state.
	State VerdictState `json:"state"`
	// Score is the numeric priority score used to sort the queue descending.
	Score int `json:"score"`
	// SubjectID is the primary Entity.ID opened when the operator clicks this item.
	SubjectID string `json:"subject_id"`
	// EntityIDs lists the subject and related entity IDs highlighted together on the map.
	EntityIDs []string `json:"entity_ids"`
	// ReasonRef is the check ID, CVE reference, or policy code of the specific reason behind this queue item (a device can produce multiple queue items with different reasons).
	ReasonRef string `json:"reason_ref,omitempty"`
}

// WallGate represents one physical cable crossing the building perimeter wall.
type WallGate struct {
	// PortID is the indoor switch port entity ID feeding this exterior cable.
	PortID string `json:"port_id"`
	// SwitchID is the parent indoor switch entity ID.
	SwitchID string `json:"switch_id"`
	// SwitchName is the display name of the parent indoor switch.
	SwitchName string `json:"switch_name"`
	// PortIdx is the 1-based physical port number on the parent switch.
	PortIdx int `json:"port_idx"`
	// TargetID is the connected outdoor device or client entity ID, if resolved.
	TargetID string `json:"target_id,omitempty"`
	// TargetName is the display label of the outdoor peer or cable port.
	TargetName string `json:"target_name"`
	// Kind distinguishes a trunk uplink to an outdoor switch ("feeder") from an end-host cable ("drop").
	Kind string `json:"kind"`
	// Inferred is true when perimeter zoning was detected heuristically rather than via explicit config.
	Inferred bool `json:"inferred"`
	// State mirrors the backing port entity's finalized verdict state.
	State VerdictState `json:"state"`
	// PinNumber mirrors the backing port entity's Fix-Next pin number, if any.
	PinNumber int `json:"pin_number,omitempty"`
	// InlineFact summarizes the port's native VLAN, tagged policy, and MAC-lock status.
	InlineFact string `json:"inline_fact,omitempty"`
}

// WANFlow represents one inbound WAN firewall rule, port forward, or missing
// edge-telemetry indicator pointing to a host, gateway, or zone boundary.
type WANFlow struct {
	// ID is the backing rule entity ID, synthetic "wanfwd:<idx>", or "wan-coverage:missing".
	ID string `json:"id"`
	// Kind distinguishes inbound firewall rules ("firewall"), port forwards ("forward"),
	// and incomplete WAN telemetry warnings ("coverage").
	Kind string `json:"kind"`
	// Label is the compact protocol/port mapping or telemetry notice shown on the badge.
	Label string `json:"label"`
	// RuleName is the display name for this WAN entry (a UniFi rule or port-forward name, finding title, or coverage message).
	RuleName string `json:"rule_name"`
	// TargetID is the destination host or gateway entity ID, if resolved.
	TargetID string `json:"target_id,omitempty"`
	// TargetIP is the destination IP display field (from a port forward or firewall finding), if any.
	TargetIP string `json:"target_ip,omitempty"`
	// TargetName is the display name of the destination host or gateway.
	TargetName string `json:"target_name,omitempty"`
	// Expected is true for low-risk expected forwards (such as standard P2P or VPN ports).
	Expected bool `json:"expected,omitempty"`
	// State is the verdict state for this WAN entry.
	State VerdictState `json:"state"`
	// Severity is the assessed severity string ("critical", "high", "medium", "low", "info", or "unknown").
	Severity string `json:"severity"`
	// PinNumber mirrors the rule or target entity's Fix-Next pin number when unexpected.
	PinNumber int `json:"pin_number,omitempty"`
}

// PhysicalRow represents one UniFi device row in the Physical Blueprint lens,
// ordered in real LLDP tree order with depth indentation (or UplinkUnknown).
type PhysicalRow struct {
	// DeviceID is the UniFi device entity ID ("dev:<mac>").
	DeviceID string `json:"device_id"`
	// Name is the device display name.
	Name string `json:"name"`
	// Model is the UniFi hardware model string.
	Model string `json:"model"`
	// IP is the device management IP address.
	IP string `json:"ip"`
	// Type is the UniFi device type code (e.g., "udm", "usw", "uap").
	Type string `json:"type"`
	// Version is the currently installed firmware version.
	Version string `json:"version,omitempty"`
	// Upgradable reports whether the controller advertises a newer firmware release.
	Upgradable bool `json:"upgradable,omitempty"`
	// Side indicates perimeter placement ("inside" or "outside").
	Side string `json:"side"`
	// ZoneSource records why an outdoor device was marked "outside" ("config", "auto", or "parent_link").
	ZoneSource string `json:"zone_source,omitempty"`
	// Depth is the zero-based tree indentation depth below the root gateway.
	Depth int `json:"depth"`
	// UplinkUnknown is true when the device's parent uplink could not be resolved in the LLDP tree.
	UplinkUnknown bool `json:"uplink_unknown,omitempty"`
	// ParentID is the upstream UniFi device entity ID, if known.
	ParentID string `json:"parent_id,omitempty"`
	// ParentPortID is the upstream switch port entity ID feeding this device, if known.
	ParentPortID string `json:"parent_port_id,omitempty"`
	// ParentLabel is the formatted uplink label (including port index and PoE draw when available).
	ParentLabel string `json:"parent_label,omitempty"`
	// PortIDs lists the physical port entity IDs belonging to this device in port order.
	PortIDs []string `json:"port_ids,omitempty"`
	// SFPStartIdx is the first port index using SFP/SFP+ media (0 if none), used to split copper and fiber banks.
	SFPStartIdx int `json:"sfp_start_idx,omitempty"`
	// ClientCount is the number of wireless clients currently associated with this AP.
	ClientCount int `json:"client_count,omitempty"`
	// SSIDs is the site-wide enabled Wi-Fi SSID list copied onto each AP row (not per-AP radio broadcast telemetry).
	SSIDs []string `json:"ssids,omitempty"`
}

// LogicalLane represents one VLAN lane inside the Logical Zones lens.
type LogicalLane struct {
	// NetworkID is the network entity ID ("net:<id-or-name>").
	NetworkID string `json:"network_id"`
	// Name is the VLAN or network display name.
	Name string `json:"name"`
	// VLAN is the numeric VLAN tag string, if assigned.
	VLAN string `json:"vlan,omitempty"`
	// Subnet is the IPv4 CIDR configured for this network.
	Subnet string `json:"subnet,omitempty"`
	// ZoneName is the UniFi firewall zone name containing this network.
	ZoneName string `json:"zone_name"`
	// Isolated reports whether this VLAN is configured as isolated or guest-segmented.
	Isolated bool `json:"isolated"`
	// ValveState reflects the network entity's finalized verdict state for peer containment.
	ValveState VerdictState `json:"valve_state"`
	// ValveReason summarizes same-VLAN peer isolation details from Containment.
	ValveReason string `json:"valve_reason,omitempty"`
	// BMCIDs lists out-of-band BMC host entity IDs residing on this VLAN.
	BMCIDs []string `json:"bmc_ids,omitempty"`
	// PinnedHostIDs lists non-BMC hosts in Exposed or Review state on this VLAN.
	PinnedHostIDs []string `json:"pinned_host_ids,omitempty"`
	// CleanHostIDs lists non-BMC hosts in OK state on this VLAN.
	CleanHostIDs []string `json:"clean_host_ids,omitempty"`
	// UnknownHostIDs lists non-BMC hosts in Unknown (unassessed or skipped) state on this VLAN.
	UnknownHostIDs []string `json:"unknown_host_ids,omitempty"`
	// TotalHosts is the total number of hosts assigned to this VLAN lane.
	TotalHosts int `json:"total_hosts"`
	// MigrationHint suggests moving exposed trusted-VLAN IoT devices onto an empty isolated VLAN.
	MigrationHint string `json:"migration_hint,omitempty"`
	// Containment holds the four-axis isolation assessment (peers, LAN egress, internet, LAN inbound).
	Containment *risk.NetworkContainment `json:"containment,omitempty"`
}

// Census holds exact clickable filter counts derived from the same predicates
// used by the Map and Inventory views.
type Census struct {
	// ExposedCount is the number of host, port, rule, and device entities with a primary Exposed reason.
	ExposedCount int `json:"exposed_count"`
	// ReviewCount is the number of host, port, rule, and device entities in Review state.
	ReviewCount int `json:"review_count"`
	// BMCCount is the number of hosts classified as out-of-band server management controllers.
	BMCCount int `json:"bmc_count"`
	// ExactCVEHosts is the number of hosts and UniFi devices with at least one exact-version CVE match.
	ExactCVEHosts int `json:"exact_cve_hosts"`
	// UnassessedCount is the number of non-skipped hosts still awaiting an active probe.
	UnassessedCount int `json:"unassessed_count"`
	// OpenWallGates is the number of perimeter wall gates in Exposed or Review state.
	OpenWallGates int `json:"open_wall_gates"`
	// TotalWallGates is the total number of detected indoor-to-outdoor perimeter cables.
	TotalWallGates int `json:"total_wall_gates"`
}

// PresentationModel is the complete single-source-of-truth UI model built in Go.
type PresentationModel struct {
	// Headline is the one-sentence top-of-page posture verdict.
	Headline string `json:"headline"`
	// Census holds summary entity counts for dashboard filter pills.
	Census Census `json:"census"`
	// GatewayID is the entity ID of the primary UniFi gateway ("dev:<mac>").
	GatewayID string `json:"gateway_id,omitempty"`
	// Entities maps every entity ID to its finalized Entity record.
	Entities map[string]*Entity `json:"entities"`
	// Queue holds the score-ranked Fix-Next remediation items.
	Queue []QueueItem `json:"queue,omitempty"`
	// Physical holds UniFi infrastructure devices ordered in LLDP tree order.
	Physical []PhysicalRow `json:"physical,omitempty"`
	// WallGates lists physical switch ports feeding exterior cables across the perimeter wall.
	WallGates []WallGate `json:"wall_gates,omitempty"`
	// Logical holds VLAN lanes with grouped host IDs and containment metadata.
	Logical []LogicalLane `json:"logical,omitempty"`
	// WANFlows lists inbound WAN firewall rules, port forwards, and missing edge-telemetry indicators.
	WANFlows []WANFlow `json:"wan_flows,omitempty"`
	// Isolation holds the effective cross-zone and same-VLAN isolation matrix.
	Isolation *risk.IsolationMatrix `json:"isolation,omitempty"`
	// ServiceCoverage summarizes active-probe service identification coverage across probed hosts.
	ServiceCoverage *probe.ServiceCoverageReport `json:"service_coverage,omitempty"`
	// Visibility records which UniFi controller telemetry feeds succeeded or were missing.
	Visibility *unifi.SiteVisibility `json:"visibility,omitempty"`
	// Blast holds the evaluated 3-lane counterfactual action queue, egress profiles, and simulation graph.
	Blast *blast.Report `json:"blast,omitempty"`
	// InfraBlast holds per-device infrastructure compromise assessments for gateways, switches, APs, and controllers.
	InfraBlast []blast.InfraReport `json:"infra_blast,omitempty"`
	// Copyright is the footer attribution string rendered in the UI and offline exports.
	Copyright string `json:"copyright"`
	// AuthorURL is the author profile link shown alongside Copyright.
	AuthorURL string `json:"author_url,omitempty"`
	// License is the SPDX license identifier rendered in the footer.
	License string `json:"license"`
	// RepoURL is the project repository URL rendered in the footer.
	RepoURL string `json:"repo_url"`
}

func devEntityID(mac string) string { return "dev:" + strings.ToLower(strings.TrimSpace(mac)) }

// AttachBlast attaches the evaluated 3-lane action queue, egress profiles, and
// infrastructure compromise reports onto pm without altering existing entities.
func AttachBlast(pm *PresentationModel, report blast.Report, infra []blast.InfraReport) {
	if pm == nil {
		return
	}
	cp := report
	pm.Blast = &cp
	pm.InfraBlast = infra
}

// CollectTargetSignals queries historical KEV/CVE velocity for high-confidence
// fingerprinted products without mutating finding severities or alert baselines.
func CollectTargetSignals(cache *cve.Cache, products []cve.Product, now time.Time) []blast.TargetSignal {
	return CollectTargetSignalsCached(cache, products, now, nil)
}

// CollectTargetSignalsCached behaves like CollectTargetSignals while reusing
// caller-supplied per-(vendor, product) velocity results across recomputes so
// delta polls do not repeatedly re-read KEV and vendor shards.
func CollectTargetSignalsCached(cache *cve.Cache, products []cve.Product, now time.Time, memo map[string]cve.TargetVelocity) []blast.TargetSignal {
	if cache == nil || len(products) == 0 {
		return nil
	}
	if memo == nil {
		memo = make(map[string]cve.TargetVelocity)
	}
	var out []blast.TargetSignal
	for _, p := range products {
		if !p.HighConfidence || len(p.Vendors) == 0 || len(p.Products) == 0 {
			continue
		}
		key := strings.Join(p.Vendors, ",") + "|" + strings.Join(p.Products, ",")
		vel, ok := memo[key]
		if !ok {
			var err error
			vel, err = cache.ProductVelocity(p, now)
			if err != nil {
				continue
			}
			memo[key] = vel
		}
		if vel.Class != cve.VelocityHighProfile {
			continue
		}
		asset := strings.TrimSpace(p.HostIP)
		if asset == "" {
			continue
		}
		if len(p.Ports) == 0 {
			out = append(out, blast.TargetSignal{Asset: asset, Product: p.Label, Velocity: vel})
			continue
		}
		for _, ep := range p.Ports {
			out = append(out, blast.TargetSignal{
				Asset:    asset,
				Proto:    ep.Transport,
				Port:     ep.Port,
				Product:  p.Label,
				Velocity: vel,
			})
		}
	}
	return out
}

// AppendDeviceChildProfiles appends synthetic profiles for adopted UniFi
// devices that own enrolled bridge children (such as Protect cameras) so every
// CLI, UI, and export path evaluates the same child impact.
func AppendDeviceChildProfiles(snap *unifi.Snapshot, profiles []probe.HostProfile, devChildren map[string][]probe.ChildDevice) []probe.HostProfile {
	if snap == nil || len(devChildren) == 0 {
		return profiles
	}
	out := append([]probe.HostProfile(nil), profiles...)
	for _, d := range snap.Devices {
		if ch := devChildren[strings.ToLower(d.MAC)]; len(ch) > 0 {
			out = append(out, probe.HostProfile{
				Client:   unifi.Client{ID: d.ID, MAC: d.MAC, IP: d.IP, Name: d.Name},
				Children: ch,
			})
		}
	}
	return out
}

// EvaluateSiteBlast runs both the 3-lane counterfactual action queue and the
// per-device infrastructure compromise assessments from one shared snapshot.
// Callers must pass raw observed check findings (not scored report.Findings) so
// synthetic controller posture findings never leak into host service actions.
func EvaluateSiteBlast(
	snap *unifi.Snapshot,
	profiles []probe.HostProfile,
	rawFindings []checks.Finding,
	report risk.Report,
	netCfg config.NetworkConfig,
	checkList []*checks.Check,
	cveMatches []cve.Match,
	signals []blast.TargetSignal,
	controllerHost string,
) (blast.Report, []blast.InfraReport) {
	if snap == nil {
		return blast.Report{}, nil
	}
	assets, _ := classify.ResolveAssets(snap, profiles, netCfg.Assets)
	oracle := risk.NewOracle(snap, netCfg)
	in := blast.Input{
		ControllerHost: controllerHost,
		Snapshot:       snap,
		Profiles:       profiles,
		Findings:       rawFindings,
		Checks:         checkList,
		CVEMatches:     cveMatches,
		TargetSignals:  signals,
		Isolation:      report.Isolation,
		SwitchPorts:    report.SwitchPorts,
		Assets:         assets,
		NetCfg:         netCfg,
		Oracle:         oracle,
	}
	return blast.Evaluate(in), blast.EvaluateAllInfra(in)
}

// ActionAlertsFromBlast selects remediations with a measured reduction in exposure.
func ActionAlertsFromBlast(actions []blast.Action) []risk.ActionAlert {
	var alerts []risk.ActionAlert
	for _, a := range actions {
		if a.HighestTierReduced == "" || a.Lane == blast.LaneVerify {
			continue
		}
		priority := string(a.HighestTierReduced)
		alerts = append(alerts, risk.ActionAlert{
			ID: a.ID, Title: a.Title, Reason: a.Reason, Lane: string(a.Lane),
			Priority: priority, Severity: risk.ActionPrioritySeverity(priority),
			Benefits: a.Benefits, AffectedAssets: a.AffectedAssets, HighProfile: a.HighProfile,
		})
	}
	return alerts
}

// ApplyBlastActionsToDiff adds action changes to the outbound diff and returns
// the action baseline to persist. To avoid duplicate webhook alerts for the
// same root cause, it suppresses new patch actions already covered by a
// same-or-higher-severity CVE alert in newCVEs, and once an action baseline is
// live (or on a fresh baseline), suppresses new/escalated findings covered by
// an equally-or-more-severe blast action. A pre-existing baseline with no
// action history keeps its finding alerts for the cycle in which actions are
// first seeded.
func ApplyBlastActionsToDiff(diff *risk.Diff, prev *risk.State, snap *unifi.Snapshot, blastRep blast.Report, probedHostKeys map[string]struct{}, newCVEs []risk.CVEAlert, cveMatched bool) (map[string]string, map[string]time.Time, map[string]time.Time, map[string]bool, map[string]map[string]time.Time, map[string]string) {
	alerts := ActionAlertsFromBlast(blastRep.Actions)
	newActions, escalated, resolved, next, seen, peakAt, carried, assets, owners := risk.ComputeActionDiff(prev, snap, alerts, probedHostKeys, cveMatched)
	// Drop new patch actions that duplicate an exact CVE alert at equal or
	// higher severity in this same diff.
	if len(newCVEs) > 0 && len(newActions) > 0 {
		patchSevs := alertedPatchIDs(snap, newCVEs)
		newActions = slices.DeleteFunc(newActions, func(a risk.ActionAlert) bool {
			sev, ok := patchSevs[strings.ToLower(a.ID)]
			return ok && sev >= a.Severity
		})
	}
	diff.NewActions, diff.EscalatedActions, diff.ResolvedActionIDs = newActions, escalated, resolved
	// Once action history is live, drop finding alerts already superseded by a
	// blast action that meets or exceeds the finding's notification severity.
	live := prev == nil || (!prev.NeedsScoringRebaseline() && prev.Actions != nil)
	if live && (len(diff.NewFindings) > 0 || len(diff.EscalatedFindings) > 0) {
		alertSevByID := make(map[string]checks.Severity, len(alerts))
		for _, a := range alerts {
			id := strings.ToLower(a.ID)
			alertSevByID[id] = max(alertSevByID[id], a.Severity)
		}
		covered := func(f checks.Finding) bool { return blastCoversFinding(alertSevByID, snap, f) }
		diff.NewFindings = slices.DeleteFunc(diff.NewFindings, covered)
		diff.EscalatedFindings = slices.DeleteFunc(diff.EscalatedFindings, covered)
	}
	return next, seen, peakAt, carried, assets, owners
}

// alertedPatchIDs links exact CVE notifications to patch actions even when a CVE
// was fingerprinted on a secondary IP and the action identifies the host by MAC.
func alertedPatchIDs(snap *unifi.Snapshot, alerts []risk.CVEAlert) map[string]checks.Severity {
	hostByIP := make(map[string]string)
	if snap != nil {
		for _, cl := range snap.Clients {
			for _, ip := range cl.AllIPs() {
				hostByIP[strings.ToLower(ip)] = blastHostKey(cl)
			}
		}
		for _, d := range snap.Devices {
			hostByIP[strings.ToLower(d.IP)] = cmp.Or(config.CanonicalMAC(d.MAC), d.ID, d.IP)
		}
	}
	ids := make(map[string]checks.Severity)
	for _, c := range alerts {
		ip := strings.ToLower(strings.TrimSpace(c.HostIP))
		if ip != "" {
			prefixes := []string{"act:patch:" + strings.ToLower(c.CVEID) + ":"}
			if slug := blast.ProductSlug(c.Product); slug != "" {
				prefixes = append(prefixes, "act:patch-product:"+slug+":")
			}
			sev := c.Severity
			if c.KEV {
				sev = checks.SeverityCritical
			}
			for _, prefix := range prefixes {
				ids[prefix+ip] = max(ids[prefix+ip], sev)
				if host := hostByIP[ip]; host != "" {
					id := prefix + strings.ToLower(host)
					ids[id] = max(ids[id], sev)
				}
			}
		}
	}
	return ids
}

// blastHostKey matches the asset identity used to construct blast action IDs.
func blastHostKey(cl unifi.Client) string {
	return cmp.Or(config.CanonicalMAC(cl.MAC), cl.ID, strings.ToLower(cl.PrimaryIP()))
}

// blastCoversFinding checks whether an action for the same rule or socket
// would reach every notification threshold that the finding would reach.
func blastCoversFinding(alertSevByID map[string]checks.Severity, snap *unifi.Snapshot, f checks.Finding) bool {
	has := func(id string) bool {
		sev, ok := alertSevByID[strings.ToLower(id)]
		return ok && sev >= f.EffectiveSeverity
	}
	checkID := strings.ToLower(f.CheckID)
	switch checkID {
	case "ub-unifi-portfwd":
		return blastCoversForward(snap, f, has)
	case "ub-unifi-fw-wan-gw", "ub-unifi-fw-wan-lan", "ub-unifi-fw-iso-leak":
		id, ok := strings.CutPrefix(strings.ToLower(f.Client.MAC), "fw:")
		return ok && id != "" && (has("act:gateway-local:"+id) || has("act:gateway-routed:"+id) || has("act:switch-routed:"+id))
	}
	host := blastHostKey(f.Client)
	if host == "" || f.Port <= 0 || strings.HasPrefix(checkID, "ub-unifi-") {
		return false
	}
	key := "act:check:" + checkID + ":" + host + ":"
	proto, port := strings.ToLower(f.EffectiveTransport()), strconv.Itoa(f.Port)
	if has("act:check-host:"+checkID+":"+host) || has(key+proto+"/"+port) {
		return true
	}
	if proto == "tcp" {
		return has(key + port)
	}
	return has(key + port + ":" + proto)
}

// blastCoversForward resolves ID-less rules by their controller tuple. An
// aggregated act:wan-service: action can cover the forward only if it closes
// the same backend service.
func blastCoversForward(snap *unifi.Snapshot, f checks.Finding, has func(string) bool) bool {
	id, ok := strings.CutPrefix(strings.ToLower(f.Property), "portfwd:")
	if !ok || id == "" {
		return false
	}
	if snap == nil {
		return has("act:wan-pf:" + id)
	}
	host := blastHostKey(f.Client)
	for _, pf := range snap.PortForwards {
		if !pf.Enabled {
			continue
		}
		key := pf.ID
		if key == "" {
			key = fmt.Sprintf("%s-%s-%s-%s", pf.Proto, pf.DstPort, pf.FwdIP, pf.FwdPort)
		}
		if strings.ToLower(key) != id {
			continue
		}
		if pf.ID != "" && has("act:wan-pf:"+pf.ID) {
			return true
		}
		if pf.ID == "" && pf.Name != "" && has("act:wan-pf:"+pf.Name) && snap.UniquePortForwardName(pf.Name) {
			return true
		}
		port := f.Port
		if port <= 0 {
			if ports := pf.ExpandFwdPorts(1); len(ports) > 0 {
				port = ports[0]
			} else {
				// Blast represents a range by its first backend port.
				first, _, _ := strings.Cut(cmp.Or(pf.FwdPort, pf.DstPort), ",")
				first, _, _ = strings.Cut(first, "-")
				port, _ = strconv.Atoi(strings.TrimSpace(first))
			}
		}
		backend := strings.TrimSpace(pf.FwdIP)
		backendAddr, err := netip.ParseAddr(backend)
		if err == nil {
			backend = backendAddr.Unmap().String()
		}
		for _, proto := range []string{"tcp", "udp"} {
			if port <= 0 || !pf.MatchesTransport(proto) {
				continue
			}
			suffix := ":" + proto + "/" + strconv.Itoa(port)
			if pf.ID == "" && pf.Name == "" && has("act:wan-pf:"+backend+suffix) {
				return true
			}
			if (host != "" && has("act:wan-service:"+host+suffix)) ||
				(backend != "" && has("act:wan-service:"+backend+suffix)) {
				return true
			}
			for _, dev := range snap.Devices {
				addr, err := netip.ParseAddr(strings.TrimSpace(dev.IP))
				if err == nil && addr.Unmap() == backendAddr.Unmap() &&
					has("act:wan-service:"+cmp.Or(config.CanonicalMAC(dev.MAC), dev.ID, dev.IP)+suffix) {
					return true
				}
			}
		}
	}
	return false
}

// AttachDeviceChildren registers enrolled child devices (for example, UniFi
// Protect cameras or accessories managed by a UDM Pro / UNVR gateway) beneath
// their owning UniFi infrastructure device entity in pm.
func AttachDeviceChildren(pm *PresentationModel, devChildren map[string][]probe.ChildDevice) {
	if pm == nil || len(devChildren) == 0 {
		return
	}
	for mac, children := range devChildren {
		ent := pm.Entities[devEntityID(mac)]
		if ent == nil {
			continue
		}
		registerChildEntities(pm, ent, children)
	}
}

// registerChildEntities deduplicates and registers enrolled child devices
// (e.g., cameras behind an NVR or bridge) under "child:<parentID>/<childID>",
// leaving children with unknown direct LAN reachability in VerdictUnknown so
// unverified private segments are never presented as clean.
func registerChildEntities(pm *PresentationModel, parent *Entity, children []probe.ChildDevice) {
	if pm == nil || parent == nil || len(children) == 0 {
		return
	}
	existing := make(map[string]struct{}, len(parent.ChildIDs))
	for _, cid := range parent.ChildIDs {
		existing[cid] = struct{}{}
	}
	for _, ch := range children {
		cid := fmt.Sprintf("child:%s/%s", parent.ID, ch.ID)
		if _, dup := existing[cid]; dup {
			continue
		}
		existing[cid] = struct{}{}
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
		parent.ChildIDs = append(parent.ChildIDs, cid)
		pm.Entities[cid] = &Entity{
			ID:                    cid,
			Kind:                  "child",
			Label:                 firstStr(ch.Name, ch.Model, ch.ID),
			Subtitle:              firstStr(ch.Role, "Bridged Child Device"),
			Role:                  firstStr(ch.Category, "iot"),
			Side:                  parent.Side,
			Weight:                1,
			State:                 chState,
			MaxSeverity:           "ok",
			StateLabel:            chLabel,
			ParentID:              parent.ID,
			NetworkID:             parent.NetworkID,
			NetworkName:           parent.NetworkName,
			Vendor:                ch.Vendor,
			Model:                 ch.Model,
			Firmware:              ch.Firmware,
			IdentitySource:        ch.IdentitySource,
			DirectLANReachability: reach,
		}
	}
}
func portEntityID(mac string, idx int) string {
	return fmt.Sprintf("port:%s/%d", strings.ToLower(strings.TrimSpace(mac)), idx)
}
func hostEntityID(cl unifi.Client) string {
	if m := strings.ToLower(strings.TrimSpace(cl.MAC)); m != "" {
		return "host:" + m
	}
	return "host:ip/" + strings.TrimSpace(cl.PrimaryIP())
}
func netEntityID(id, name string) string {
	if strings.TrimSpace(id) != "" {
		return "net:" + strings.TrimSpace(id)
	}
	return "net:" + strings.ToLower(strings.TrimSpace(name))
}

// findingSubjectEntityID resolves the dashboard entity ID for a finding so
// Activity events for VLAN, isolation, gateway, WLAN, and UniFi device findings
// link directly to their live entity instead of appearing as offline hosts.
func findingSubjectEntityID(f checks.Finding, snap *unifi.Snapshot) string {
	mac := strings.ToLower(strings.TrimSpace(f.Client.MAC))
	if id, ok := strings.CutPrefix(mac, "vlan:"); ok {
		return netEntityID(id, f.Client.NetworkName)
	}
	if rest, ok := strings.CutPrefix(mac, "iso:"); ok {
		srcID, _, _ := strings.Cut(rest, ":")
		return netEntityID(srcID, f.Client.NetworkName)
	}
	if strings.HasPrefix(mac, "gw:") {
		if snap != nil {
			for _, d := range snap.Devices {
				t := strings.ToLower(strings.TrimSpace(d.Type))
				if t == "udm" || t == "ugw" || t == "uxg" {
					return devEntityID(d.MAC)
				}
			}
		}
		return ""
	}
	if strings.HasPrefix(mac, "wlan:") {
		if snap != nil {
			for _, n := range snap.Networks {
				if strings.EqualFold(n.Name, f.Client.NetworkName) {
					return netEntityID(n.ID, n.Name)
				}
			}
		}
		if f.Client.NetworkName != "" {
			return netEntityID("", f.Client.NetworkName)
		}
		return ""
	}
	if snap != nil && mac != "" {
		for _, d := range snap.Devices {
			if strings.EqualFold(d.MAC, mac) {
				return devEntityID(d.MAC)
			}
		}
	}
	return hostEntityID(f.Client)
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
		AuthorURL: "https://x.com/peter_szilagyi",
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
	profileByMAC := make(map[string]probe.HostProfile, len(profiles))
	for _, hp := range profiles {
		if m := strings.ToLower(strings.TrimSpace(hp.Client.MAC)); m != "" {
			profileByMAC[m] = hp
		}
		for _, ip := range hp.Client.AllIPs() {
			if k := strings.ToLower(strings.TrimSpace(ip)); k != "" {
				profileByIP[k] = hp
			}
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
	// Honor operator-configured isolated_vlans and custom isolated firewall zones
	// resolved by topology.Build when deciding service reachability ("vlan-only" vs "lan").
	if topo != nil {
		for _, vg := range topo.VLANs {
			if vg.Isolated {
				netIsolated[strings.ToLower(strings.TrimSpace(vg.Name))] = true
			}
		}
	}

	// Index exact & potential CVEs per host IP (supporting both IPv4 and IPv6).
	exactByIP := make(map[string][]cve.ProductSummary)
	for _, s := range exactCVEs {
		if k := strings.ToLower(strings.TrimSpace(s.Product.HostIP)); k != "" {
			exactByIP[k] = append(exactByIP[k], s)
		}
	}
	potByIP := make(map[string][]cve.ProductSummary)
	for _, s := range potentialCVEs {
		if k := strings.ToLower(strings.TrimSpace(s.Product.HostIP)); k != "" {
			potByIP[k] = append(potByIP[k], s)
		}
	}

	// Index WAN forwards by target IP (supporting both IPv4 and IPv6).
	wanByIP := make(map[netip.Addr][]risk.ExposureAssessment)
	for _, a := range report.WANSurface {
		ip := a.Forward.FwdIP
		if ip == "" {
			ip = a.Client.PrimaryIP()
		}
		if k := serviceAddr(ip); k.IsValid() {
			wanByIP[k] = append(wanByIP[k], a)
		}
	}
	lookupCVEsForIPs := func(idx map[string][]cve.ProductSummary, ips []string) []cve.ProductSummary {
		// One version can have separate advisories for package backports,
		// client tools and platform prerequisites.
		type advisoryKey struct {
			label, version, ip       string
			confidence               cve.Confidence
			clientOnly, needsContext bool
		}
		var out []cve.ProductSummary
		seen := make(map[advisoryKey]struct{})
		for _, ip := range ips {
			k := strings.ToLower(strings.TrimSpace(ip))
			for _, s := range idx[k] {
				dedup := advisoryKey{s.Product.Label, s.Product.Version, s.Product.HostIP, s.Confidence, s.ClientOnly, s.NeedsContext}
				if _, dup := seen[dedup]; dup {
					continue
				}
				seen[dedup] = struct{}{}
				out = append(out, s)
			}
		}
		return out
	}
	lookupWANForIPs := func(ips []string) []risk.ExposureAssessment {
		var out []risk.ExposureAssessment
		for _, ip := range ips {
			out = append(out, wanByIP[serviceAddr(ip)]...)
		}
		return out
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

			controllerID: d.ID,
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
		// Attach Exact and Potential CVEs matched against UniFi gateway/switch/AP firmware.
		if d.IP != "" {
			if exList := exactByIP[strings.ToLower(strings.TrimSpace(d.IP))]; len(exList) > 0 {
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
						ID:          fmt.Sprintf("cve-exact:%s/%d", id, i),
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
			if potList := potByIP[strings.ToLower(strings.TrimSpace(d.IP))]; len(potList) > 0 {
				ent.PotentialCVEs = potList
				for _, s := range potList {
					ent.PotCVECount += s.TotalCVEs
				}
			}
		}
		pm.Entities[id] = ent
	}

	// 2. Register clients and hosts (single source of truth for checks, exact CVEs, BMCs, and scan coverage).
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
		for _, v6 := range cl.IPv6 {
			v6 = strings.TrimSpace(v6)
			if v6 != "" {
				hostIDByIP[v6] = hid
				hostIDByIP[strings.ToLower(v6)] = hid
			}
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
		if len(lookupWANForIPs(cl.AllIPs())) > 0 {
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

		var scannedAt *time.Time
		if cv.LastScannedAt != nil && !cv.LastScannedAt.IsZero() {
			scannedAt = cv.LastScannedAt
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
			ScannedAt:   scannedAt,
			Skipped:     cv.Skipped,
			SkipReason:  cv.SkipReason,
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

		// Attach placement verdict computed by topology.Build (with MAC fallback for IPv6-only hosts).
		pl, hasPlacement := placementByIP[cl.IP]
		if !hasPlacement && mac != "" {
			pl, hasPlacement = placementByMAC[mac]
		}
		if hasPlacement {
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

		// Attach Exact CVEs (independent Exposed verdict) across IPv4 and IPv6 addresses.
		if exList := lookupCVEsForIPs(exactByIP, cl.AllIPs()); len(exList) > 0 {
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
		if potList := lookupCVEsForIPs(potByIP, cl.AllIPs()); len(potList) > 0 {
			ent.PotentialCVEs = potList
			for _, s := range potList {
				ent.PotCVECount += s.TotalCVEs
			}
		}

		// Build structured Services[] with computed reachability.
		hp := profileByIP[strings.ToLower(strings.TrimSpace(cl.PrimaryIP()))]
		if hp.Client.MAC == "" && hp.Client.PrimaryIP() == "" && mac != "" {
			hp = profileByMAC[mac]
		}
		behindCGNAT := isSnapshotWANBehindCGNAT(snap)
		ent.Services = buildHostServices(cv, hp, lookupWANForIPs(cl.AllIPs()), netIsolated[strings.ToLower(cl.NetworkName)], behindCGNAT)
		if len(hp.ConnectOnlyPorts) > 0 {
			ent.ConnectOnlyPorts = append([]int(nil), hp.ConnectOnlyPorts...)
		}
		if len(hp.OutboundDependencies) > 0 {
			ent.OutboundDependencies = hp.OutboundDependencies
		}

		// Register enrolled child devices managed behind bridges/NVRs/coordinators
		// (e.g., cameras on an NVR's private PoE network) with explicit provenance
		// and DirectLANReachability ("unknown" when behind private PoE).
		registerChildEntities(pm, ent, hp.Children)

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
				ID:                   pid,
				Kind:                 "port",
				Label:                fmt.Sprintf("%s #%d", sw.Name, p.PortIdx),
				Subtitle:             firstStr(p.Label, p.Name),
				Role:                 p.Zone,
				Side:                 side,
				ZoneSource:           p.ZoneSource,
				Weight:               weight,
				State:                VerdictOK,
				MaxSeverity:          "ok",
				StateLabel:           "Matches policy",
				DeviceID:             swID,
				PortID:               pid,
				NetworkID:            netEntByName[strings.ToLower(p.NativeVLAN)],
				NetworkName:          p.NativeVLAN,
				PortIdx:              p.PortIdx,
				PortZone:             p.Zone,
				PortState:            p.State,
				Speed:                p.Speed,
				Media:                p.Media,
				PoEEnabled:           p.PoEEnabled,
				PoEPower:             p.PoEPower,
				NativeVLAN:           p.NativeVLAN,
				TaggedPolicy:         p.TaggedPolicy,
				PortSecurity:         p.PortSecurity,
				PortSecurityUnknown:  p.PortSecurityUnknown,
				PortIsolation:        p.Isolation,
				PortIsolationUnknown: p.IsolationUnknown,
				MACTableCount:        p.MACTableCount,
				STPState:             p.STPState,
				PeerIDs:              peerIDs,
			}

			// Add a subtle Review reason for indoor active access ports carrying all tagged VLANs.
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
				if p.PortSecurity && !p.PortSecurityUnknown {
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

	// Helper to resolve a host entity by IPv4, IPv6, or MAC.
	lookupHostID := func(cl unifi.Client) string {
		if ip := strings.TrimSpace(cl.IP); ip != "" {
			if hid := hostIDByIP[ip]; hid != "" {
				return hid
			}
			if hid := hostIDByIP[strings.ToLower(ip)]; hid != "" {
				return hid
			}
		}
		if m := strings.ToLower(strings.TrimSpace(cl.MAC)); m != "" {
			if hid := hostIDByMAC[m]; hid != "" {
				return hid
			}
		}
		return ""
	}

	// 4. Attach confirmed findings from report.Findings to their target entities.
	for idxF, f := range report.Findings {
		if f.CheckID == "UB-UNIFI-PORTFWD" || f.CheckID == "UB-UNIFI-FIRMWARE" {
			continue
		}
		fid := fmt.Sprintf("find:%s@%d", f.CheckID, idxF)
		sev := f.EffectiveSeverity.String()

		switch {
		case strings.HasPrefix(f.CheckID, "UB-UNIFI-PORT-"):
			// Recover the owning switch MAC and port index across four fallbacks:
			// direct Client.SwitchMAC/SwitchPort, f.Property ("port:<mac>/<idx>"),
			// direct switch-MAC match on Client.MAC, or scanning switch port peers
			// by client MAC/IP so client-shaped port findings attach cleanly.
			swMAC := strings.ToLower(strings.TrimSpace(f.Client.SwitchMAC))
			portIdx := f.Client.SwitchPort
			if portIdx <= 0 {
				portIdx = f.Port
			}
			if swMAC == "" && strings.HasPrefix(f.Property, "port:") {
				rest := strings.TrimPrefix(f.Property, "port:")
				if mPart, pPart, ok := strings.Cut(rest, "/"); ok {
					swMAC = strings.ToLower(strings.TrimSpace(mPart))
					if portIdx <= 0 {
						_, _ = fmt.Sscanf(pPart, "%d", &portIdx)
					}
				}
			}
			if swMAC == "" {
				cand := strings.ToLower(strings.TrimSpace(f.Client.MAC))
				if _, ok := swByMAC[cand]; ok {
					swMAC = cand
				} else if _, ok := pm.Entities[portEntityID(cand, portIdx)]; ok {
					swMAC = cand
				} else if cand != "" || f.Client.IP != "" {
					for _, sw := range report.SwitchPorts {
						for _, sp := range sw.Ports {
							if portIdx > 0 && sp.PortIdx != portIdx {
								continue
							}
							for _, peer := range sp.Peers {
								if (cand != "" && strings.EqualFold(peer.MAC, cand)) ||
									(f.Client.IP != "" && peer.IP == f.Client.IP) {
									swMAC = strings.ToLower(sw.MAC)
									portIdx = sp.PortIdx
									break
								}
							}
							if swMAC != "" {
								break
							}
						}
						if swMAC != "" {
							break
						}
					}
				}
				if swMAC == "" {
					swMAC = cand
				}
			}

			pid := portEntityID(swMAC, portIdx)
			if f.CheckID == "UB-UNIFI-PORT-EXT-UNUSED-OPEN" {
				// Attach to each unused external/restricted port on this switch and the switch device itself.
				attached := false
				de, hasSwitchEnt := pm.Entities[devEntityID(swMAC)]
				hasExternalUnused := hasSwitchEnt && de.Side == "outside"
				if sw, ok := swByMAC[swMAC]; ok {
					if sw.ExternalDevice {
						hasExternalUnused = true
					}
					for _, sp := range sw.Ports {
						if (sp.Zone == "external" || sp.Zone == "unused") && sp.State == "inactive_enabled" {
							if sp.Zone == "external" {
								hasExternalUnused = true
							}
							if pe, ok := pm.Entities[portEntityID(swMAC, sp.PortIdx)]; ok {
								title := "Unused indoor port left enabled"
								if sp.Zone == "external" || sw.ExternalDevice {
									title = "Unused external port left enabled"
								}
								pe.Reasons = append(pe.Reasons, Reason{
									ID:          fmt.Sprintf("%s/%d", fid, sp.PortIdx),
									State:       VerdictExposed,
									Kind:        "policy",
									Ref:         f.CheckID,
									Title:       title,
									Severity:    sev,
									Expected:    "Operation = Disabled",
									Observed:    "Enabled (inactive, " + sp.TaggedPolicy + ")",
									Evidence:    f.Evidence,
									Remediation: f.Remediation.Summary,
									Source:      "unifi-port",
									Port:        sp.PortIdx,
									Secondary:   hasSwitchEnt,
								})
								attached = true
							}
						}
					}
				}
				if hasSwitchEnt {
					expected := "Unused indoor ports disabled"
					title := strings.ReplaceAll(f.Title, "Unused External Switch Ports", "Unused Indoor Switch Ports")
					if hasExternalUnused {
						expected = "Unused external ports disabled"
						title = f.Title
					}
					de.Reasons = append(de.Reasons, Reason{
						ID:          fid,
						State:       VerdictExposed,
						Kind:        "policy",
						Ref:         f.CheckID,
						Title:       title,
						Severity:    sev,
						Expected:    expected,
						Observed:    f.Evidence,
						Evidence:    f.Evidence,
						Remediation: f.Remediation.Summary,
						Source:      "unifi-port",
						Port:        portIdx,
					})
					attached = true
				}
				if !attached {
					if gw, ok := pm.Entities[pm.GatewayID]; ok {
						gw.Reasons = append(gw.Reasons, Reason{
							ID:          fid,
							State:       VerdictExposed,
							Kind:        "policy",
							Ref:         f.CheckID,
							Title:       f.Title,
							Severity:    sev,
							Expected:    "Unused ports disabled",
							Observed:    f.Evidence,
							Evidence:    f.Evidence,
							Remediation: f.Remediation.Summary,
							Source:      "unifi-port",
							Port:        portIdx,
						})
					}
				}
			} else {
				expected := "Isolated VLAN + Block All + MAC Port Security"
				switch f.CheckID {
				case "UB-UNIFI-PORT-EXT-UPLINK":
					expected = "Custom/Block All (isolated VLANs only)"
				case "UB-UNIFI-PORT-EXT-MULTI-MAC":
					expected = "1 learned MAC on exterior drop"
				case "UB-UNIFI-PORT-UNAUTHORIZED-MAC":
					expected = "Authorized MAC address in allowed_macs"
				case "UB-UNIFI-PORT-STP-BLOCKED":
					expected = "STP Forwarding (no L2 loop)"
				}
				attached := false
				if pe, ok := pm.Entities[pid]; ok {
					pe.Reasons = append(pe.Reasons, Reason{
						ID:          fid,
						State:       VerdictExposed,
						Kind:        "policy",
						Ref:         f.CheckID,
						Title:       f.Title,
						Severity:    sev,
						Expected:    expected,
						Observed:    fmt.Sprintf("VLAN=%s, Tagged=%s, MAC-lock=%s", pe.NativeVLAN, pe.TaggedPolicy, portSecurityLabel(pe.PortSecurity, pe.PortSecurityUnknown)),
						Evidence:    f.Evidence,
						Remediation: f.Remediation.Summary,
						Source:      "unifi-port",
						Port:        portIdx,
					})
					attached = true
				}
				// Also attach unauthorized-MAC findings to the intruding host when present,
				// marking it secondary when the port entity already owns the primary finding
				// so one finding is never double-counted in the fix-next queue or hero.
				if f.CheckID == "UB-UNIFI-PORT-UNAUTHORIZED-MAC" ||
					(f.Client.SwitchMAC != "" && !strings.EqualFold(f.Client.MAC, swMAC)) {
					if hid := lookupHostID(f.Client); hid != "" {
						if he, ok := pm.Entities[hid]; ok {
							he.Reasons = append(he.Reasons, Reason{
								ID:          fid + "/host",
								State:       VerdictExposed,
								Kind:        "policy",
								Ref:         f.CheckID,
								Title:       f.Title,
								Severity:    sev,
								Expected:    expected,
								Observed:    f.Evidence,
								Evidence:    f.Evidence,
								Remediation: f.Remediation.Summary,
								Source:      "unifi-port",
								Port:        portIdx,
								Secondary:   attached,
							})
							attached = true
						}
					}
				}
				// Never silently drop an unattached port finding: fall back to host, switch device, or gateway.
				if !attached {
					var fallback *Entity
					if hid := lookupHostID(f.Client); hid != "" {
						fallback = pm.Entities[hid]
					}
					if fallback == nil && swMAC != "" {
						fallback = pm.Entities[devEntityID(swMAC)]
					}
					if fallback == nil {
						fallback = pm.Entities[pm.GatewayID]
					}
					if fallback != nil {
						fallback.Reasons = append(fallback.Reasons, Reason{
							ID:          fid,
							State:       VerdictExposed,
							Kind:        "policy",
							Ref:         f.CheckID,
							Title:       f.Title,
							Severity:    sev,
							Expected:    expected,
							Observed:    f.Evidence,
							Evidence:    f.Evidence,
							Remediation: f.Remediation.Summary,
							Source:      "unifi-port",
							Port:        portIdx,
						})
					}
				}
			}

		case strings.HasPrefix(f.CheckID, "UB-UNIFI-FW-"):
			isWANSourced := f.CheckID == "UB-UNIFI-FW-WAN-GW" ||
				f.CheckID == "UB-UNIFI-FW-WAN-LAN" ||
				strings.HasPrefix(strings.ToLower(strings.TrimSpace(f.Client.NetworkName)), "external")
			if !isWANSourced {
				// Internal isolation leaks (e.g. UB-UNIFI-FW-ISO-LEAK) belong to isolation/gateway,
				// never "Open Doors to the Internet" (WANFlows).
				target := pm.Entities[lookupHostID(f.Client)]
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
				break
			}

			rid := fmt.Sprintf("rule:%s/%d", f.CheckID, idxF)
			targetIP := strings.TrimSpace(f.Client.IP)
			targetID := pm.GatewayID
			targetName := f.Client.DisplayName()
			if f.CheckID == "UB-UNIFI-FW-WAN-LAN" {
				if hid := lookupHostID(f.Client); hid != "" {
					if he, ok := pm.Entities[hid]; ok {
						targetID = hid
						targetName = he.Label
						he.Reasons = append(he.Reasons, Reason{
							ID:          fid + "/host",
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
							Port:        f.Port,
							Secondary:   true,
						})
					}
				}
			}
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
				IP:          targetIP,
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
				TargetID:   targetID,
				TargetIP:   targetIP,
				TargetName: targetName,
				State:      VerdictExposed,
				Severity:   sev,
			})

		case strings.HasPrefix(f.CheckID, "UB-UNIFI-BMC-"):
			hid := lookupHostID(f.Client)
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
			} else if gw, ok := pm.Entities[pm.GatewayID]; ok {
				gw.Reasons = append(gw.Reasons, Reason{
					ID:          fid,
					State:       VerdictExposed,
					Kind:        "policy",
					Ref:         f.CheckID,
					Title:       f.Title,
					Severity:    sev,
					Expected:    "Dedicated OOB Management VLAN",
					Observed:    f.Evidence,
					Evidence:    f.Evidence,
					Remediation: f.Remediation.Summary,
					Source:      "unifi-policy",
				})
			}

		case strings.HasPrefix(f.CheckID, "UB-UNIFI-ISO-"):
			// Attach effective isolation violations to their resolved subject
			// (owning network entity for vlan:/iso: findings, or target host
			// such as a BMC/Printer), falling back to the Gateway.
			target := pm.Entities[findingSubjectEntityID(f, snap)]
			if target == nil {
				target = pm.Entities[lookupHostID(f.Client)]
			}
			if target == nil {
				target = pm.Entities[pm.GatewayID]
			}
			if target != nil {
				expected := "Deny unapproved access"
				observed := f.Evidence
				if f.CheckID == "UB-UNIFI-ISO-SAME-VLAN" {
					expected = "Block traffic between VLAN peers"
					// Leave Observed empty because Evidence already holds the complete
					// peer-isolation summary rendered in both network and host drawers.
					observed = ""
				}
				reason := Reason{
					ID:          fid,
					State:       VerdictExposed,
					Kind:        "policy",
					Ref:         f.CheckID,
					Title:       f.Title,
					Severity:    sev,
					Expected:    expected,
					Observed:    observed,
					Evidence:    f.Evidence,
					Remediation: f.Remediation.Summary,
					Source:      "unifi-isolation",
					Port:        f.Port,
				}
				target.Reasons = append(target.Reasons, reason)
				// Cross-link the finding as a secondary reason onto the specific clients
				// and switch ports identified by the isolation evaluator so inspecting
				// those entities surfaces the peer exposure without double-counting it
				// in the Fix-Next queue or census totals.
				reason.Secondary = true
				seen := map[string]bool{target.ID: true}
				attach := func(id string) {
					if entity := pm.Entities[id]; entity != nil && !seen[id] {
						entity.Reasons = append(entity.Reasons, reason)
						seen[id] = true
					}
				}
				for _, mac := range f.AffectedClientMACs {
					attach(hostIDByMAC[strings.ToLower(mac)])
				}
				for _, ref := range f.AffectedSwitchPorts {
					attach(portEntityID(ref.SwitchMAC, ref.PortIdx))
				}
			}

		case strings.HasPrefix(f.CheckID, "UB-UNIFI-"):
			// Host-scoped UniFi findings (rogue wired AP, public admin tunnel/proxy,
			// dynamic NAT mapping) attach to the concrete host entity first, falling
			// back to a matching UniFi device or the gateway for site/WLAN findings.
			var target *Entity
			if hid := lookupHostID(f.Client); hid != "" {
				target = pm.Entities[hid]
			}
			if target == nil && f.Client.MAC != "" {
				target = pm.Entities[devEntityID(f.Client.MAC)]
			}
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
					Expected:    "Hardened UniFi control plane",
					Observed:    f.Evidence,
					Evidence:    f.Evidence,
					Remediation: f.Remediation.Summary,
					Source:      "unifi-controller",
					Port:        f.Port,
				})
			}

		default:
			// Host-level LAN service or BMC probe finding.
			hid := lookupHostID(f.Client)
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
				// Mark matching service as exposed (or add observed/UDP service like HomeKit, IPMI 623, SNMP 161).
				markServiceExposed(he, f, lookupWANForIPs(f.EndpointIPs()), netIsolated[strings.ToLower(he.NetworkName)], isSnapshotWANBehindCGNAT(snap))
			}
		}
	}

	// 5. Add WAN Port Forwards and missing WAN telemetry coverage indicators to WANFlows.
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
	missingWANFeeds := 0
	if vis := snap.Visibility; vis != nil {
		missingFW := !vis.GatewayPoliciesAvailable
		missingPF := !vis.PortForwardsAvailable && len(snap.PortForwards) == 0
		for _, mf := range vis.MissingFeeds {
			low := strings.ToLower(mf)
			if strings.Contains(low, "firewall") {
				missingFW = true
			}
			if strings.Contains(low, "port-forward") || strings.Contains(low, "port_forward") {
				missingPF = true
			}
		}
		if missingFW || missingPF {
			var missing []string
			if missingFW {
				missing = append(missing, "firewall policies")
			}
			if missingPF {
				missing = append(missing, "port forwards")
			}
			missingWANFeeds = len(missing)
			pm.WANFlows = append(pm.WANFlows, WANFlow{
				ID:         "wan-coverage:missing",
				Kind:       "coverage",
				Label:      "Missing telemetry: " + strings.Join(missing, ", "),
				RuleName:   "Internet edge visibility incomplete",
				TargetID:   pm.GatewayID,
				TargetName: "Gateway / Internet Edge",
				Expected:   false,
				State:      VerdictUnknown,
				Severity:   "unknown",
			})
		}
	}

	// Surface missing same-VLAN peer evidence as a Review reason on the network
	// entity so incomplete telemetry is never presented as verified isolation.
	if report.Isolation != nil {
		missing := make(map[string]bool)
		for _, c := range report.Isolation.Cells {
			if c.Verdict == risk.IsolationUnknown && c.SourceNetwork == c.DestNetwork {
				missing[c.SourceNetwork] = true
			}
		}
		for _, n := range report.Isolation.Containment {
			if !missing[n.NetworkName] && n.Peers.State != "unknown" {
				continue
			}
			if ent := pm.Entities[netEntByName[strings.ToLower(n.NetworkName)]]; ent != nil {
				ent.Reasons = append(ent.Reasons, Reason{
					ID:          "peer-coverage:" + ent.ID,
					Kind:        "coverage",
					State:       VerdictReview,
					Severity:    "unknown",
					Title:       "Peer isolation unverified",
					Evidence:    n.Peers.Detail,
					Remediation: "Verify switch and wireless attachment data for this network.",
					Source:      "unifi-isolation",
				})
			}
		}
	}
	// 6. Finalize verdict state and label for every entity.
	for _, ent := range pm.Entities {
		if ent.Kind == "child" {
			continue
		}
		finalizeEntityVerdict(ent)
	}

	// Attach effective isolation matrix, measurable service coverage metrics,
	// and site telemetry visibility so the UI never treats stale cached feeds as current.
	pm.Isolation = report.Isolation
	if len(profiles) > 0 {
		sc := probe.ComputeServiceCoverage(profiles)
		pm.ServiceCoverage = &sc
	}
	if snap.Visibility != nil {
		visCopy := *snap.Visibility
		visCopy.MissingFeeds = append([]string(nil), snap.Visibility.MissingFeeds...)
		pm.Visibility = &visCopy
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

	// 7. Build ranked fix-next queue and assign deterministic pin numbers.
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

	// 8. Build physical blueprint rows in LLDP tree order (including UplinkUnknown and APs without port tables).
	pm.Physical = buildPhysicalRows(snap, swByMAC, gwMAC, apClientCount, pm.Entities)

	// 9. Build logical zone lanes (BMCs stay pinned in their real VLAN, clean hosts group in the dot grid).
	pm.Logical = buildLogicalLanes(snap, topo, report.Isolation, pm.Entities, netEntByName)

	// 10. Compute census counts from the finalized entities.
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
				if hasPrimaryExposedReason(ent) {
					pm.Census.ExposedCount++
				}
			case VerdictReview:
				pm.Census.ReviewCount++
			case VerdictUnknown:
				if !ent.Skipped {
					pm.Census.UnassessedCount++
				}
			}
		case "port", "rule", "device":
			if ent.Kind == "device" && ent.ExactCVECount > 0 {
				pm.Census.ExactCVEHosts++
			}
			if ent.State == VerdictExposed {
				if hasPrimaryExposedReason(ent) {
					pm.Census.ExposedCount++
				}
			} else if ent.State == VerdictReview {
				pm.Census.ReviewCount++
			}
		}
	}

	// 11. Build one-sentence verdict headline.
	unexpectedWAN := 0
	unknownWAN := 0
	for _, wf := range pm.WANFlows {
		if wf.Kind == "coverage" || wf.State == VerdictUnknown {
			unknownWAN++
		} else if !wf.Expected || wf.State == VerdictExposed {
			unexpectedWAN++
		}
	}
	if missingWANFeeds > unknownWAN {
		unknownWAN = missingWANFeeds
	}
	if len(pm.Queue) == 0 {
		switch {
		case unexpectedWAN > 0:
			verb := "require"
			if unexpectedWAN == 1 {
				verb = "requires"
			}
			pm.Headline = fmt.Sprintf("%d unexpected WAN exposure%s %s review.", unexpectedWAN, pluralS(unexpectedWAN), verb)
		case unknownWAN > 0:
			pm.Headline = fmt.Sprintf("Coverage incomplete: %d WAN telemetry feed%s unavailable.", unknownWAN, pluralS(unknownWAN))
		case pm.Census.UnassessedCount > 0:
			pm.Headline = fmt.Sprintf("Assessment incomplete: %d host%s still unassessed.", pm.Census.UnassessedCount, pluralS(pm.Census.UnassessedCount))
		default:
			pm.Headline = fmt.Sprintf("All clear: %d VLANs, %d devices, and %d wall gates match policy.", len(pm.Logical), len(snap.Devices), pm.Census.TotalWallGates)
		}
	} else if len(pm.Queue) == 1 {
		pm.Headline = pm.Queue[0].Sentence
	} else {
		pm.Headline = fmt.Sprintf("%s (+%d more item%s in queue)", pm.Queue[0].Sentence, len(pm.Queue)-1, pluralS(len(pm.Queue)-1))
	}

	return pm
}

// hasPrimaryExposedReason reports whether ent owns at least one primary
// (non-secondary) Exposed reason, preventing cross-linked copies from inflating
// Census.ExposedCount.
func hasPrimaryExposedReason(ent *Entity) bool {
	if ent == nil || ent.State != VerdictExposed {
		return false
	}
	hasAnyExposed := false
	for _, r := range ent.Reasons {
		if r.State == VerdictExposed {
			hasAnyExposed = true
			if !r.Secondary {
				return true
			}
		}
	}
	return !hasAnyExposed
}

// primaryExposedReason returns the highest-ranked non-secondary Exposed reason
// on ent (relying on finalizeEntityVerdict having sorted ent.Reasons worst-first).
func primaryExposedReason(ent *Entity) (Reason, bool) {
	if ent == nil {
		return Reason{}, false
	}
	for _, r := range ent.Reasons {
		if r.State == VerdictExposed && !r.Secondary {
			return r, true
		}
	}
	return Reason{}, false
}

// finalizeEntityVerdict sorts ent.Reasons worst-first and derives ent.State,
// ent.MaxSeverity, and ent.StateLabel, preserving VerdictUnknown for skipped or
// unscanned hosts unless concrete Exposed evidence already applies.
func finalizeEntityVerdict(ent *Entity) {
	// Sort reasons worst-first so the highest-priority reason appears first in the inspector.
	sort.SliceStable(ent.Reasons, func(i, j int) bool {
		if verdictRank(ent.Reasons[i].State) != verdictRank(ent.Reasons[j].State) {
			return verdictRank(ent.Reasons[i].State) > verdictRank(ent.Reasons[j].State)
		}
		return sevStrRank(ent.Reasons[i].Severity) > sevStrRank(ent.Reasons[j].Severity)
	})

	isUnscannedHost := ent.Kind == "host" && (ent.ScannedAt == nil || ent.ScannedAt.IsZero())

	worstState := VerdictOK
	worstSev := "ok"
	if len(ent.Reasons) > 0 {
		worstSev = "info"
		for _, r := range ent.Reasons {
			if verdictRank(r.State) > verdictRank(worstState) {
				worstState = r.State
			}
			if sevStrRank(r.Severity) > sevStrRank(worstSev) {
				worstSev = r.Severity
			}
		}
	}

	if ent.Kind == "host" && ent.Skipped {
		if worstState == VerdictExposed {
			ent.State = VerdictExposed
			ent.MaxSeverity = worstSev
			ent.StateLabel = "Exposed"
			return
		}
		ent.State = VerdictUnknown
		ent.MaxSeverity = "unknown"
		if strings.Contains(strings.ToLower(ent.SkipReason), "exclud") {
			ent.StateLabel = "Excluded"
		} else {
			ent.StateLabel = "Skipped"
		}
		return
	}

	// An unscanned host stays Unknown (preserving any heuristic Review reasons)
	// unless concrete Exposed evidence already applies.
	if isUnscannedHost && worstState != VerdictExposed {
		ent.State = VerdictUnknown
		ent.MaxSeverity = "unknown"
		ent.StateLabel = "Unassessed"
		return
	}

	if len(ent.Reasons) == 0 {
		ent.State = VerdictOK
		ent.MaxSeverity = "ok"
		if ent.Kind == "host" {
			ent.StateLabel = "No findings"
		} else {
			ent.StateLabel = "Matches policy"
		}
		return
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

// buildFixNextQueue converts primary Exposed entities into score-ranked
// QueueItem entries, deduplicating secondary cross-links and aggregating
// unused open switch ports once per switch device.
func buildFixNextQueue(pm *PresentationModel) []QueueItem {
	var items []QueueItem
	for _, ent := range pm.Entities {
		if ent.State != VerdictExposed {
			continue
		}
		if len(ent.Reasons) == 0 {
			continue
		}

		// Emit one queue item per distinct exposed device/controller reason so
		// multiple gateway posture issues and firmware CVEs are each surfaced.
		if ent.Kind == "device" {
			seenKey := make(map[string]bool)
			for _, r := range ent.Reasons {
				if r.State != VerdictExposed {
					continue
				}
				if r.Ref == "UB-UNIFI-PORT-EXT-UNUSED-OPEN" {
					if seenKey[r.Ref] {
						continue
					}
					seenKey[r.Ref] = true
					hasExternal := ent.Side == "outside"
					if !hasExternal {
						for _, other := range pm.Entities {
							if other.Kind == "port" && other.DeviceID == ent.ID && other.PortZone == "external" && other.PortState == "inactive_enabled" {
								hasExternal = true
								break
							}
						}
					}
					phrase := "unused indoor ports"
					title := strings.ReplaceAll(r.Title, "Unused External Switch Ports", "Unused Indoor Switch Ports")
					if hasExternal {
						phrase = "unused external ports"
						title = r.Title
					}
					items = append(items, QueueItem{
						Sentence:  fmt.Sprintf("%s has %s left open (%s)", ent.Label, phrase, title),
						Category:  "perimeter",
						Severity:  r.Severity,
						State:     ent.State,
						Score:     sevStrRank(r.Severity)*10*ent.Weight + 15,
						SubjectID: ent.ID,
						EntityIDs: []string{ent.ID},
						ReasonRef: r.Ref,
					})
					continue
				}
				key := r.Ref + "|" + r.Title
				if seenKey[key] {
					continue
				}
				seenKey[key] = true
				score := sevStrRank(r.Severity) * 10 * ent.Weight
				if r.Kind == "cve" {
					score += 10
				}
				items = append(items, QueueItem{
					Sentence:  fmt.Sprintf("%s: %s", ent.Label, r.Title),
					Category:  "controller",
					Severity:  r.Severity,
					State:     ent.State,
					Score:     score,
					SubjectID: ent.ID,
					EntityIDs: []string{ent.ID},
					ReasonRef: r.Ref,
				})
			}
			continue
		}

		top, hasPrimary := primaryExposedReason(ent)
		if !hasPrimary {
			// Skip secondary copies already represented on their primary port/rule entity.
			continue
		}
		cat := "service"
		sentence := fmt.Sprintf("%s: %s", ent.Label, top.Title)
		related := []string{ent.ID}

		switch ent.Kind {
		case "port":
			cat = "perimeter"
			onlyUnusedOpen := ent.PortState == "inactive_enabled" && (ent.PortZone == "external" || ent.PortZone == "unused")
			if onlyUnusedOpen {
				for _, r := range ent.Reasons {
					if r.State == VerdictExposed && r.Ref != "UB-UNIFI-PORT-EXT-UNUSED-OPEN" {
						onlyUnusedOpen = false
						break
					}
				}
			}
			if onlyUnusedOpen && pm.Entities[ent.DeviceID] != nil {
				// Already aggregated once per switch device above so each unused port is counted once.
				continue
			}
			if ent.PortZone == "external_uplink" {
				sentence = fmt.Sprintf("%s carries %s VLANs to external %s", ent.Label, ent.TaggedPolicy, ent.Subtitle)
			} else if ent.PortZone == "external" && top.Ref == "UB-UNIFI-PORT-EXT-UNRESTRICTED" {
				sentence = fmt.Sprintf("%s (external) is unrestricted (%s / %s)", ent.Label, ent.NativeVLAN, ent.TaggedPolicy)
			} else {
				sentence = fmt.Sprintf("%s: %s", ent.Label, top.Title)
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

		case "host":
			if ent.IsBMC {
				cat = "bmc"
				sentence = fmt.Sprintf("BMC %s (%s) on %s: %s", ent.Label, ent.IP, ent.NetworkName, top.Title)
			} else if ent.ExactCVECount > 0 && top.Kind == "cve" {
				cat = "service"
				checkCount := 0
				for _, r := range ent.Reasons {
					if r.Kind == "check" {
						checkCount++
					}
				}
				sentence = fmt.Sprintf("%s (%s): %d exact CVE(s) · %d check finding%s", ent.Label, ent.NetworkName, ent.ExactCVECount, checkCount, pluralS(checkCount))
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
		if items[i].SubjectID != items[j].SubjectID {
			return items[i].SubjectID < items[j].SubjectID
		}
		if items[i].ReasonRef != items[j].ReasonRef {
			return items[i].ReasonRef < items[j].ReasonRef
		}
		return items[i].Sentence < items[j].Sentence
	})
	return items
}

// buildPhysicalRows walks the adopted UniFi infrastructure hierarchy in LLDP
// uplink tree order from the root gateway, appending devices with unresolved
// uplinks afterward with UplinkUnknown set.
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

// buildLogicalLanes groups host entities into per-VLAN LogicalLane entries
// (preserving BMCs in their actual VLAN, attaching containment verdicts, and
// ensuring hosts on unlisted or unassigned networks still appear in a lane).
func buildLogicalLanes(
	snap *unifi.Snapshot,
	topo *topology.Model,
	iso *risk.IsolationMatrix,
	entities map[string]*Entity,
	netEntByName map[string]string,
) []LogicalLane {
	containmentByNet := make(map[string]risk.NetworkContainment)
	if iso != nil {
		for _, nc := range iso.Containment {
			if k := strings.ToLower(strings.TrimSpace(nc.NetworkName)); k != "" {
				containmentByNet[k] = nc
			}
		}
	}
	// Index all host entities by lowercase VLAN name, mapping empty/unresolved names
	// to "unassigned" so they match topology.Build's "Unassigned" VLAN group.
	hostsByNet := make(map[string][]*Entity)
	labelByNetKey := make(map[string]string)
	trustedExposedIoT := 0
	for _, ent := range entities {
		if ent.Kind != "host" {
			continue
		}
		rawName := strings.TrimSpace(ent.NetworkName)
		if rawName == "" {
			rawName = "Unassigned"
		}
		key := strings.ToLower(rawName)
		hostsByNet[key] = append(hostsByNet[key], ent)
		if _, ok := labelByNetKey[key]; !ok {
			labelByNetKey[key] = rawName
		}
	}

	var lanes []LogicalLane
	seenNet := make(map[string]bool)

	addLane := func(id, name, vlan, subnet, zone string, isolated bool) {
		key := strings.ToLower(strings.TrimSpace(name))
		if key == "" {
			name = "Unassigned"
			key = "unassigned"
		}
		if seenNet[key] {
			return
		}
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
		if nc, ok := containmentByNet[key]; ok {
			cp := nc
			lane.Containment = &cp
			if network := entities[id]; network != nil {
				lane.ValveState = network.State
			}
			lane.ValveReason = nc.Peers.Detail
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
			isUniFiGear := strings.Contains(strings.ToLower(h.Vendor), "ubiquiti") || strings.Contains(strings.ToLower(h.Vendor), "unifi")
			if !isolated && !isUniFiGear && h.State == VerdictExposed && (h.Role == "iot" || h.Role == "camera" || h.Role == "printer" || h.Role == "media") {
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

	// Ensure any host whose network was absent from topo.VLANs / snap.Networks
	// (including "Unassigned") always appears in a deterministic lane.
	var extraKeys []string
	for k := range hostsByNet {
		if !seenNet[k] {
			extraKeys = append(extraKeys, k)
		}
	}
	sort.Strings(extraKeys)
	for _, k := range extraKeys {
		name := labelByNetKey[k]
		if name == "" {
			name = "Unassigned"
		}
		addLane(netEntityID("", name), name, "", "", "Internal", false)
	}

	// Add subtle migration hint only on empty isolated VLANs when exposed IoT actually sits on Trusted.
	for i := range lanes {
		if lanes[i].Isolated && lanes[i].TotalHosts == 0 && trustedExposedIoT > 0 {
			lanes[i].MigrationHint = fmt.Sprintf("%d exposed IoT/appliance host(s) on Trusted → move here", trustedExposedIoT)
		}
	}
	return lanes
}

// portForwardAddressFamily returns the effective address family ("ipv4",
// "ipv6", or "both") targeted by pf, preferring the literal FwdIP family when
// present and falling back to pf.IPVersion (defaulting to "ipv4").
func portForwardAddressFamily(pf unifi.PortForward) string {
	if addr, err := netip.ParseAddr(strings.TrimSpace(pf.FwdIP)); err == nil {
		if addr.Unmap().Is6() {
			return "ipv6"
		}
		return "ipv4"
	}
	switch strings.ToLower(strings.TrimSpace(pf.IPVersion)) {
	case "ipv6":
		return "ipv6"
	case "both", "ipv4_and_ipv6":
		return "both"
	default:
		return "ipv4"
	}
}

// serviceAddr parses and unmaps an IP literal so service observations and
// port-forward targets compare identically across IPv4 and IPv6 representations.
func serviceAddr(ip string) netip.Addr {
	addr, _ := netip.ParseAddr(strings.TrimSpace(ip))
	return addr.Unmap()
}

// serviceAddrs parses a slice of IP strings into valid unmapped netip.Addr
// values retained on each ServiceView for exact listener-address matching.
func serviceAddrs(ips ...string) []netip.Addr {
	var addrs []netip.Addr
	for _, ip := range ips {
		if addr := serviceAddr(ip); addr.IsValid() {
			addrs = append(addrs, addr)
		}
	}
	return addrs
}

func forwardMatchesAddressFamily(pf unifi.PortForward, svcFam string) bool {
	sf := strings.ToLower(strings.TrimSpace(svcFam))
	if sf == "" {
		return true
	}
	ff := portForwardAddressFamily(pf)
	if ff == "both" {
		return true
	}
	return ff == sf
}

func hasOpenPort(ports []int, target int) bool {
	for _, p := range ports {
		if p == target {
			return true
		}
	}
	return false
}

// wanSourceScope aggregates overlapping forwards in increasing order of reach.
type wanSourceScope uint8

const (
	wanRestricted wanSourceScope = iota
	wanUnresolved
	wanOpen
)

// forwardSourceScope distinguishes an unresolved controller object from an open rule.
func forwardSourceScope(p unifi.PortForward) wanSourceScope {
	if p.SourceUnknown {
		return wanUnresolved
	}
	if p.IsSourceRestricted() {
		return wanRestricted
	}
	return wanOpen
}

// reachLabel describes configured WAN reachability for the available source evidence.
func (s wanSourceScope) reachLabel(cgnat bool) string {
	switch {
	case cgnat:
		return "wan-cgnat"
	case s == wanUnresolved:
		return "wan-unknown"
	case s == wanRestricted:
		return "wan-restricted"
	default:
		return "wan"
	}
}

// buildHostServices builds the deduplicated per-host service rows with computed
// WAN, LAN, and VLAN reachability labels.
func buildHostServices(cv ClientView, hp probe.HostProfile, wan []risk.ExposureAssessment, vlanIsolated, behindCGNAT bool) []ServiceView {
	wanUDPPorts := make(map[int]wanSourceScope)
	type wideUDPForward struct {
		spec      string
		startPort int
		endPort   int
		scope     wanSourceScope
	}
	wideUDPBySpec := make(map[string]wideUDPForward)
	recordWideUDP := func(start, end int, scope wanSourceScope) {
		spec := fmt.Sprintf("%d-%d", start, end)
		if cur, exists := wideUDPBySpec[spec]; exists {
			cur.scope = max(cur.scope, scope)
			wideUDPBySpec[spec] = cur
		} else {
			wideUDPBySpec[spec] = wideUDPForward{
				spec:      spec,
				startPort: start,
				endPort:   end,
				scope:     scope,
			}
		}
	}
	const maxExpandedUDPPorts = 64
	for _, a := range wan {
		if !a.Forward.Enabled {
			continue
		}
		if a.Forward.MatchesTransport("udp") {
			spec := strings.TrimSpace(firstStr(a.Forward.FwdPort, a.Forward.DstPort))
			scope := forwardSourceScope(a.Forward)
			for _, seg := range strings.Split(spec, ",") {
				seg = strings.TrimSpace(seg)
				if seg == "" {
					continue
				}
				if startStr, endStr, ok := strings.Cut(seg, "-"); ok {
					start, err1 := strconv.Atoi(strings.TrimSpace(startStr))
					end, err2 := strconv.Atoi(strings.TrimSpace(endStr))
					if err1 != nil || err2 != nil || start < 1 || end > 65535 || end < start {
						continue
					}
					if end-start+1 <= maxExpandedUDPPorts {
						for p := start; p <= end; p++ {
							wanUDPPorts[p] = max(wanUDPPorts[p], scope)
						}
					} else {
						recordWideUDP(start, end, scope)
					}
					continue
				}
				if single, err := strconv.Atoi(seg); err == nil && single >= 1 && single <= 65535 {
					wanUDPPorts[single] = max(wanUDPPorts[single], scope)
				}
			}
		}
	}
	defaultReach := "lan"
	if vlanIsolated {
		defaultReach = "vlan-only"
	}
	// A forward targets one listener address even when several share a port and family.
	wanReachForEndpoint := func(port int, transport, addrFamily string, ip netip.Addr) (string, bool) {
		if !ip.IsValid() {
			return defaultReach, false
		}
		matched := false
		scope := wanRestricted
		for _, a := range wan {
			if !a.Forward.ExposesEndpoint(port, transport) {
				continue
			}
			if !forwardMatchesAddressFamily(a.Forward, addrFamily) {
				continue
			}
			if target := serviceAddr(firstStr(a.Forward.FwdIP, a.Client.PrimaryIP())); target != ip {
				continue
			}
			matched = true
			scope = max(scope, forwardSourceScope(a.Forward))
		}
		if !matched {
			return defaultReach, false
		}
		return scope.reachLabel(behindCGNAT), scope == wanRestricted
	}

	// Merge observations only after each listener has its own reachability label.
	servicesByEndpoint := make(map[string][]ServiceView)
	for _, svc := range hp.Services {
		if svc.Port <= 0 {
			continue
		}
		t := strings.ToLower(strings.TrimSpace(svc.Transport))
		if t == "" {
			t = "tcp"
		}
		epKey := fmt.Sprintf("%s:%d", t, svc.Port)
		listenerIP := hp.ServiceIP(svc)
		normFam := cmp.Or(probe.IPFamily([]string{listenerIP}), strings.ToLower(strings.TrimSpace(svc.AddressFamily)))
		ip := serviceAddr(listenerIP)
		reach, restricted := wanReachForEndpoint(svc.Port, t, normFam, ip)
		name := strings.TrimSpace(svc.Protocol)
		existing := servicesByEndpoint[epKey]
		merged := false
		for i := range existing {
			row := &existing[i]
			if !strings.EqualFold(row.Name, name) || row.Reachable != reach || row.SourceRestricted != restricted {
				continue
			}
			// A mixed row stays family-neutral when more observations arrive.
			if row.AddressFamily != normFam {
				row.AddressFamily = ""
			}
			row.State = firstStr(row.State, svc.State)
			if ip.IsValid() && !slices.Contains(row.observedIPs, ip) {
				row.observedIPs = append(row.observedIPs, ip)
			}
			merged = true
			break
		}
		if !merged {
			row := ServiceView{Port: svc.Port, Proto: t, AddressFamily: normFam, Name: name, State: svc.State,
				Reachable: reach, SourceRestricted: restricted}
			if ip.IsValid() {
				row.observedIPs = []netip.Addr{ip}
			}
			servicesByEndpoint[epKey] = append(existing, row)
		}
	}

	formatServiceLabel := func(name, transport string, port int, fam string, multiOnPort bool) string {
		base := fmt.Sprintf("%s :%d", strings.ToUpper(firstStr(name, transport)), port)
		if multiOnPort && fam != "" {
			switch strings.ToLower(fam) {
			case "ipv4":
				return base + " (IPv4)"
			case "ipv6":
				return base + " (IPv6)"
			default:
				return fmt.Sprintf("%s (%s)", base, fam)
			}
		}
		return base
	}

	// Older scans used the client's IPv4 address. Without a recorded probe
	// target, an IPv6-only scan can be attributed to a single inventory address.
	openIP := firstStr(hp.ProbeIP, cv.Client.IP)
	if openIP == "" && len(cv.Client.IPv6) == 1 {
		openIP = cv.Client.IPv6[0]
	}
	openAddr := serviceAddr(openIP)
	openFamily := probe.IPFamily([]string{openIP})

	var out []ServiceView
	seen := make(map[string]bool)
	emitObservedEndpoint := func(epKey string, port int, transport string, open bool) {
		if seen[epKey] {
			return
		}
		seen[epKey] = true
		svcs := servicesByEndpoint[epKey]
		if open {
			reach, restricted := wanReachForEndpoint(port, transport, openFamily, openAddr)
			// Treat openAddr as already represented only if an observed service row
			// explicitly recorded openAddr, or if an addressless row of matching family
			// shares default reachability (never letting an addressless row inherit a
			// WAN port forward targeting a specific IP).
			observed := slices.ContainsFunc(svcs, func(s ServiceView) bool {
				return slices.Contains(s.observedIPs, openAddr) || (len(s.observedIPs) == 0 && (s.AddressFamily == "" || s.AddressFamily == openFamily) && reach == defaultReach)
			})
			if len(svcs) == 0 || (openAddr.IsValid() && !observed) {
				state := probe.ServiceStateCandidatePort
				if hasOpenPort(hp.ConnectOnlyPorts, port) {
					state = "connect-only"
				}
				svcs = append(svcs, ServiceView{
					Port: port, Proto: transport, AddressFamily: openFamily, State: state,
					Reachable: reach, SourceRestricted: restricted, observedIPs: serviceAddrs(openIP),
				})
			}
		}
		for _, svc := range svcs {
			svc.Name = firstStr(svc.Name, commonPortLabel(port))
			svc.State = firstStr(svc.State, probe.ServiceStateObservedProtocol)
			svc.Label = formatServiceLabel(svc.Name, transport, port, svc.AddressFamily, len(svcs) > 1)
			out = append(out, svc)
		}
	}

	for _, p := range cv.OpenPorts {
		emitObservedEndpoint(fmt.Sprintf("tcp:%d", p), p, "tcp", true)
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
		emitObservedEndpoint(fmt.Sprintf("%s:%d", t, svc.Port), svc.Port, t, false)
	}
	// Also record UDP-only WAN forwards as distinct UDP endpoints in deterministic
	// sorted port order so a UDP forward never conflates with a TCP service.
	udpPorts := make([]int, 0, len(wanUDPPorts))
	for p := range wanUDPPorts {
		udpPorts = append(udpPorts, p)
	}
	sort.Ints(udpPorts)
	for _, p := range udpPorts {
		info := wanUDPPorts[p]
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
			Reachable:        info.reachLabel(behindCGNAT),
			State:            "configured-forward",
			SourceRestricted: info == wanRestricted,
			Label:            fmt.Sprintf("%s :%d", strings.ToUpper(name), p),
		})
	}
	// Surface wide UDP port-forward ranges (>64 ports) as a concise range chip
	// whenever no concrete UDP service inside that range was observed on the host.
	if len(wideUDPBySpec) > 0 {
		wideUDPForwards := make([]wideUDPForward, 0, len(wideUDPBySpec))
		for _, wf := range wideUDPBySpec {
			wideUDPForwards = append(wideUDPForwards, wf)
		}
		sort.Slice(wideUDPForwards, func(i, j int) bool {
			if wideUDPForwards[i].startPort != wideUDPForwards[j].startPort {
				return wideUDPForwards[i].startPort < wideUDPForwards[j].startPort
			}
			return wideUDPForwards[i].spec < wideUDPForwards[j].spec
		})
		for _, wf := range wideUDPForwards {
			coveredByObserved := false
			for _, svc := range hp.Services {
				t := strings.ToLower(strings.TrimSpace(svc.Transport))
				if t == "" {
					t = "tcp"
				}
				if t == "udp" && svc.Port >= wf.startPort && svc.Port <= wf.endPort {
					coveredByObserved = true
					break
				}
			}
			if coveredByObserved {
				continue
			}
			out = append(out, ServiceView{
				Port:             wf.startPort,
				Proto:            "udp",
				Name:             "udp",
				Reachable:        wf.scope.reachLabel(behindCGNAT),
				State:            "configured-forward",
				SourceRestricted: wf.scope == wanRestricted,
				Label:            fmt.Sprintf("UDP :%s", wf.spec),
			})
		}
	}
	return out
}

// isSnapshotWANBehindCGNAT is a reachability heuristic reporting whether the
// gateway's WAN IP falls in private (RFC 1918 or IPv6 ULA via Addr.IsPrivate),
// CGNAT (100.64.0.0/10), loopback, or link-local space; a private upstream
// address alone cannot prove whether an upstream router forwards traffic.
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

// findMatchingServiceIndex prefers listener addresses and falls back to legacy
// rows when the finding and service lack a shared address.
func findMatchingServiceIndex(services []ServiceView, f checks.Finding) int {
	proto := f.EffectiveTransport()
	ips := f.EndpointIPs()
	family := probe.IPFamily(ips)
	addrs := serviceAddrs(ips...)
	var matches, exact []int
	for i, svc := range services {
		if (family == "ipv4" || family == "ipv6") && svc.AddressFamily != "" && svc.AddressFamily != family {
			continue
		}
		if svc.Port != f.Port || !strings.EqualFold(svc.Proto, proto) {
			continue
		}
		if len(addrs) == 0 || len(svc.observedIPs) == 0 {
			matches = append(matches, i)
		} else if slices.ContainsFunc(addrs, func(ip netip.Addr) bool { return slices.Contains(svc.observedIPs, ip) }) {
			exact = append(exact, i)
		}
	}
	if len(exact) > 0 {
		matches = exact
	}
	if len(matches) == 0 {
		return -1
	}
	if len(matches) == 1 {
		return matches[0]
	}
	hay := strings.ToLower(f.Title + " " + f.Evidence + " " + f.CheckID + " " + f.Property)
	for _, idx := range matches {
		if name := strings.ToLower(strings.TrimSpace(services[idx].Name)); name != "" && strings.Contains(hay, name) {
			return idx
		}
	}
	return matches[0]
}

func appendFamilyTagIfNeeded(label, fam string, services []ServiceView, port int, proto string) string {
	if fam == "" {
		return label
	}
	count := 0
	for _, s := range services {
		if s.Port == port && strings.EqualFold(s.Proto, proto) {
			count++
		}
	}
	if count <= 1 {
		return label
	}
	switch strings.ToLower(fam) {
	case "ipv4":
		return label + " (IPv4)"
	case "ipv6":
		return label + " (IPv6)"
	default:
		return fmt.Sprintf("%s (%s)", label, fam)
	}
}

// recordObservedService enriches or appends a non-exposed ServiceView row from
// an inventory-only check finding (such as an mDNS advertisement or protocol
// banner) without turning the host into Exposed.
func recordObservedService(ent *Entity, f checks.Finding) {
	if f.Port <= 0 {
		return
	}
	proto := f.EffectiveTransport()
	obsState := probe.ServiceStateObservedProtocol
	if f.ClaimKind == checks.ClaimServiceAdvertised {
		obsState = probe.ServiceStateAdvertisedService
	}
	if idx := findMatchingServiceIndex(ent.Services, f); idx >= 0 {
		if !ent.Services[idx].Exposed {
			ent.Services[idx].Label = appendFamilyTagIfNeeded(compactCheckChip(f), ent.Services[idx].AddressFamily, ent.Services, f.Port, proto)
		}
		if obsState == probe.ServiceStateObservedProtocol {
			ent.Services[idx].State = obsState
		}
		return
	}
	reach := "lan"
	if f.ClaimKind == checks.ClaimServiceAdvertised {
		reach = "advertised"
	}
	ent.Services = append(ent.Services, ServiceView{
		Port:          f.Port,
		Proto:         proto,
		AddressFamily: probe.IPFamily(f.EndpointIPs()),
		Name:          commonPortLabel(f.Port),
		Reachable:     reach,
		State:         obsState,
		observedIPs:   serviceAddrs(f.EndpointIPs()...),
		Exposed:       false,
		Label:         compactCheckChip(f),
	})
}

// markServiceExposed flags the matching ServiceView row on ent as Exposed with
// its highest finding severity and compact chip label, or appends a new service
// row (with computed WAN/LAN/VLAN reachability) for findings on services not
// discovered by TCP port scanning (such as UDP IPMI/SNMP or HomeKit).
func markServiceExposed(ent *Entity, f checks.Finding, endpointWAN []risk.ExposureAssessment, vlanIsolated, behindCGNAT bool) {
	if f.Port <= 0 {
		return
	}
	proto := f.EffectiveTransport()
	newSev := f.EffectiveSeverity.String()
	if idx := findMatchingServiceIndex(ent.Services, f); idx >= 0 {
		wasExposed := ent.Services[idx].Exposed
		ent.Services[idx].Exposed = true
		if !wasExposed || sevStrRank(newSev) > sevStrRank(ent.Services[idx].Severity) {
			ent.Services[idx].Severity = newSev
			ent.Services[idx].Label = appendFamilyTagIfNeeded(compactCheckChip(f), ent.Services[idx].AddressFamily, ent.Services, f.Port, proto)
		}
		return
	}
	reach := "lan"
	if vlanIsolated {
		reach = "vlan-only"
	}
	srcRestricted := false
	matchedWAN := false
	scope := wanRestricted
	for _, a := range endpointWAN {
		if !a.Forward.ExposesEndpoint(f.Port, proto) {
			continue
		}
		matchedWAN = true
		scope = max(scope, forwardSourceScope(a.Forward))
	}
	if matchedWAN {
		srcRestricted = scope == wanRestricted
		reach = scope.reachLabel(behindCGNAT)
	}
	ent.Services = append(ent.Services, ServiceView{
		Port:             f.Port,
		Proto:            proto,
		AddressFamily:    probe.IPFamily(f.EndpointIPs()),
		Name:             commonPortLabel(f.Port),
		Reachable:        reach,
		SourceRestricted: srcRestricted,
		Exposed:          true,
		Severity:         newSev,
		observedIPs:      serviceAddrs(f.EndpointIPs()...),
		Label:            compactCheckChip(f),
	})
}

// compactCheckChip maps well-known UniBlue check IDs to short, readable service
// chip labels for host rows and inspector badges.
func compactCheckChip(f checks.Finding) string {
	switch f.CheckID {
	case "UB-0002":
		return fmt.Sprintf("VNC :%d", f.Port)
	case "UB-0009":
		return fmt.Sprintf("TLS 1.0/1.1 :%d", f.Port)
	case "UB-0010":
		return "Open DNS :53"
	case "UB-0012":
		return "SNMP public :161"
	case "UB-0019":
		return "IPMI RMCP+ :623"
	case "UB-0030":
		return fmt.Sprintf("Grafana :%d", f.Port)
	case "UB-0032":
		return fmt.Sprintf("Ollama :%d", f.Port)
	case "UB-0045":
		return "PJLink :4352"
	case "UB-2026-0007":
		return fmt.Sprintf("Bitcoin RPC :%d", f.Port)
	case "UB-2026-0009":
		return fmt.Sprintf("Eth Engine :%d", f.Port)
	case "UB-2026-0039":
		return fmt.Sprintf("Zehnder :%d", f.Port)
	case "UB-2026-0055":
		return fmt.Sprintf("OctoPrint :%d", f.Port)
	case "UB-2026-0056":
		return "AVR Telnet :23"
	case "UB-2026-0062":
		return "Cast API :8008"
	case "UB-2026-0063":
		return fmt.Sprintf("Roku ECP :%d", f.Port)
	case "UB-0020":
		return "Redfish :443"
	case "UB-2026-0001":
		return "BMC Web :443"
	case "UB-2026-0002":
		return "iDRAC/iLO :443"
	case "UB-2026-0003":
		return fmt.Sprintf("Intel AMT :%d", f.Port)
	case "UB-0021":
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

// commonPortLabel returns a fallback lowercase protocol name for well-known
// ports when active protocol fingerprinting did not identify one.
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

// portSecurityLabel keeps missing controller settings visible in observations and change events.
func portSecurityLabel(enabled, unknown bool) string {
	if unknown {
		return "unknown"
	}
	return strconv.FormatBool(enabled)
}
