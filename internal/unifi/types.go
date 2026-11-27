// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package unifi implements a minimal, read-only client for fetching topology,
// active clients, UniFi infrastructure inventory, and port-forwarding rules
// from both UniFi OS gateways (e.g., UDM Pro) and classic Network controllers
// (e.g., older Cloud Key Gen2 deployments).
package unifi

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Snapshot is a point-in-time inventory collected from a single UniFi site.
type Snapshot struct {
	// CollectedAt records when the snapshot was fetched from the controller.
	CollectedAt time.Time `json:"collected_at"`

	// Site is the UniFi site name queried (typically "default").
	Site string `json:"site"`

	// ControllerType records which API flavor responded ("unifi-os" or "classic").
	ControllerType string `json:"controller_type"`

	// Clients holds all currently active hosts reported by the controller.
	Clients []Client `json:"clients"`

	// Devices holds UniFi infrastructure gear (gateways, switches, access points).
	Devices []Device `json:"devices"`

	// Networks holds the configured LANs and VLANs on the site.
	Networks []Network `json:"networks"`

	// PortForwards holds WAN-to-LAN port-forwarding rules configured on the gateway.
	PortForwards []PortForward `json:"port_forwards"`

	// Zones holds UniFi Zone-Based Firewall zones when supported by the console.
	Zones []FirewallZone `json:"zones,omitempty"`

	// FirewallPolicies holds UniFi Zone-Based Firewall policies when supported
	// by the console.
	FirewallPolicies []FirewallPolicy `json:"firewall_policies,omitempty"`

	// WLANs holds configured Wi-Fi SSIDs and their security/isolation posture.
	WLANs []WLANConfig `json:"wlans,omitempty"`

	// RogueAPs holds neighboring/foreign BSSIDs observed by UniFi APs.
	RogueAPs []RogueAP `json:"rogue_aps,omitempty"`

	// SecuritySettings summarizes gateway/site security controls (SSH, UPnP,
	// IDS/IPS, Honeypot, DNS Shield, Teleport) without retaining credentials.
	SecuritySettings *SiteSecuritySettings `json:"security_settings,omitempty"`

	// Health summarizes WAN status, active public IP, and live VPN sessions.
	Health *SystemHealth `json:"health,omitempty"`

	// KnownClients holds historical client records from rest/user for dormant
	// wakeup and wired/wireless medium-swap anomaly detection.
	KnownClients []HistoricalClient `json:"known_clients,omitempty"`

	// RecentLogs holds recent security and admin activity events from the console.
	RecentLogs []ControllerLogEvent `json:"recent_logs,omitempty"`

	// SwitchACLs holds L2/L3 switch access control lists when exposed by the controller.
	SwitchACLs []SwitchACL `json:"switch_acls,omitempty"`

	// SwitchACLCoverage reports whether switch ACL telemetry is complete, partial,
	// unavailable from the controller API, or unsupported by a switch model.
	SwitchACLCoverage *SwitchACLCoverage `json:"switch_acl_coverage,omitempty"`

	// Visibility records which controller and site telemetry feeds were available
	// during this snapshot so isolation verdicts clearly distinguish "denied" from "unknown".
	Visibility *SiteVisibility `json:"visibility,omitempty"`

	// DynamicMappings holds active UPnP / NAT-PMP / PCP dynamic leases when available.
	DynamicMappings []DynamicPortMapping `json:"dynamic_mappings,omitempty"`

	// PublishedTunnels holds owner-declared outbound publishing tunnels (e.g., Cloudflare Tunnel, Tailscale Funnel).
	PublishedTunnels []PublishedTunnel `json:"published_tunnels,omitempty"`

	// ProxyRoutes holds owner-declared reverse proxy frontends and backend origins.
	ProxyRoutes []ProxyRoute `json:"proxy_routes,omitempty"`

	// BackupStatus holds owner-provided network backup freshness and last verified restore test.
	BackupStatus *BackupStatus `json:"backup_status,omitempty"`
}

// SwitchACL describes one L2/L3 switch access control rule enforced on a UniFi switch.
type SwitchACL struct {
	// RuleType preserves the hardware ACL class for MAC-before-IP evaluation.
	RuleType    string         `json:"rule_type,omitempty" yaml:"rule_type,omitempty"`
	ID          string         `json:"id" yaml:"id"`
	Name        string         `json:"name" yaml:"name"`
	Enabled     bool           `json:"enabled" yaml:"enabled"`
	Index       int            `json:"index" yaml:"index"`
	Action      string         `json:"action" yaml:"action"` // "ALLOW" | "BLOCK"
	IPVersion   string         `json:"ip_version,omitempty" yaml:"ip_version,omitempty"`
	Protocol    string         `json:"protocol,omitempty" yaml:"protocol,omitempty"`
	Source      PolicyEndpoint `json:"source" yaml:"source"`
	Destination PolicyEndpoint `json:"destination" yaml:"destination"`
	DeviceMACs  []string       `json:"device_macs,omitempty" yaml:"device_macs,omitempty"`
	NetworkIDs  []string       `json:"network_ids,omitempty" yaml:"network_ids,omitempty"`
}

// SwitchACLCoverage records whether switch ACL evidence was collected for a site.
type SwitchACLCoverage struct {
	Status string `json:"status" yaml:"status"` // "complete" | "partial" | "unavailable" | "unsupported-model"
	Reason string `json:"reason,omitempty" yaml:"reason,omitempty"`
}

// SiteVisibility tracks per-site telemetry completeness across controller feeds.
type SiteVisibility struct {
	ControllerVersion        string   `json:"controller_version,omitempty" yaml:"controller_version,omitempty"`
	APIMode                  string   `json:"api_mode,omitempty" yaml:"api_mode,omitempty"`
	GatewayPoliciesAvailable bool     `json:"gateway_policies_available" yaml:"gateway_policies_available"`
	SwitchACLsAvailable      bool     `json:"switch_acls_available" yaml:"switch_acls_available"`
	WLANsAvailable           bool     `json:"wlans_available" yaml:"wlans_available"`
	SettingsAvailable        bool     `json:"settings_available" yaml:"settings_available"`
	VPNAvailable             bool     `json:"vpn_available" yaml:"vpn_available"`
	PortForwardsAvailable    bool     `json:"port_forwards_available" yaml:"port_forwards_available"`
	PortProfilesAvailable    bool     `json:"port_profiles_available" yaml:"port_profiles_available"`
	DHCPAvailable            bool     `json:"dhcp_available" yaml:"dhcp_available"`
	MDNSReflectorKnown       bool     `json:"mdns_reflector_known" yaml:"mdns_reflector_known"`
	MissingFeeds             []string `json:"missing_feeds,omitempty" yaml:"missing_feeds,omitempty"`
}

// DynamicPortMapping captures one live UPnP / NAT-PMP / PCP dynamic NAT lease.
type DynamicPortMapping struct {
	Protocol   string     `json:"protocol" yaml:"protocol"` // "upnp" | "natpmp" | "pcp"
	Transport  string     `json:"transport" yaml:"transport"`
	ExtPort    int        `json:"ext_port" yaml:"ext_port"`
	InternalIP string     `json:"internal_ip" yaml:"internal_ip"`
	IntPort    int        `json:"int_port" yaml:"int_port"`
	OwnerIP    string     `json:"owner_ip,omitempty" yaml:"owner_ip,omitempty"`
	Source     string     `json:"source,omitempty" yaml:"source,omitempty"`
	Approved   bool       `json:"approved,omitempty" yaml:"approved,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`
}

// PublishedTunnel captures one owner-declared outbound publishing tunnel route.
type PublishedTunnel struct {
	Provider      string `json:"provider" yaml:"provider"` // "cloudflare-tunnel" | "tailscale-funnel" | "ngrok" | ...
	Hostname      string `json:"hostname" yaml:"hostname"`
	BackendIP     string `json:"backend_ip" yaml:"backend_ip"`
	BackendPort   int    `json:"backend_port" yaml:"backend_port"`
	BackendRole   string `json:"backend_role,omitempty" yaml:"backend_role,omitempty"`
	AccessPolicy  string `json:"access_policy,omitempty" yaml:"access_policy,omitempty"` // "authenticated" | "public" | "none" | "" (unknown)
	AdminEndpoint bool   `json:"admin_endpoint,omitempty" yaml:"admin_endpoint,omitempty"`
}

// ProxyRoute captures one owner-declared reverse proxy virtual host and origin backend.
// FrontendAuth and BackendAuth are pointers so omitted fields remain unknown rather
// than being treated as unauthenticated.
type ProxyRoute struct {
	ProxyIP       string `json:"proxy_ip" yaml:"proxy_ip"`
	Hostname      string `json:"hostname" yaml:"hostname"`
	PublicExposed bool   `json:"public_exposed" yaml:"public_exposed"`
	FrontendAuth  *bool  `json:"frontend_auth,omitempty" yaml:"frontend_auth,omitempty"`
	BackendIP     string `json:"backend_ip" yaml:"backend_ip"`
	BackendPort   int    `json:"backend_port" yaml:"backend_port"`
	BackendAuth   *bool  `json:"backend_auth,omitempty" yaml:"backend_auth,omitempty"`
	AdminVHost    bool   `json:"admin_vhost,omitempty" yaml:"admin_vhost,omitempty"`
}

// BackupStatus records owner-supplied controller backup and restore-test freshness.
type BackupStatus struct {
	LastBackupAt      *time.Time `json:"last_backup_at,omitempty" yaml:"last_backup_at,omitempty"`
	LastRestoreTestAt *time.Time `json:"last_restore_test_at,omitempty" yaml:"last_restore_test_at,omitempty"`
	Scope             string     `json:"scope,omitempty" yaml:"scope,omitempty"`
	BackupHealthy     bool       `json:"backup_healthy" yaml:"backup_healthy"`
}

// PortHintsByIP collects concrete destination TCP ports explicitly referenced
// for specific internal IPs by UniFi port forwards and ALLOW firewall policies.
// Wide ranges (>16 ports) are ignored so catch-all rules never trigger bulky scans.
func (s *Snapshot) PortHintsByIP() map[string][]int {
	if s == nil {
		return nil
	}
	const maxHintRange = 16
	byIP := make(map[string]map[int]struct{})
	add := func(ip string, port int) {
		ip = strings.TrimSpace(ip)
		if ip == "" || port < 1 || port > 65535 {
			return
		}
		if byIP[ip] == nil {
			byIP[ip] = make(map[int]struct{})
		}
		byIP[ip][port] = struct{}{}
	}

	for _, pf := range s.PortForwards {
		if !pf.Enabled || pf.FwdIP == "" {
			continue
		}
		// Only seed ports that include TCP (skip pure UDP forwards such as WireGuard).
		if pf.Proto != "" && strings.EqualFold(pf.Proto, "udp") {
			continue
		}
		for _, p := range expandPortSpec(pf.FwdPort, maxHintRange) {
			add(pf.FwdIP, p)
		}
	}

	for _, pol := range s.FirewallPolicies {
		if !pol.Enabled || !strings.EqualFold(pol.Action, "ALLOW") {
			continue
		}
		if strings.EqualFold(pol.Protocol, "udp") || strings.EqualFold(pol.Protocol, "icmp") {
			continue
		}
		if len(pol.Destination.IPs) == 0 || len(pol.Destination.Ports) == 0 {
			continue
		}
		for _, ip := range pol.Destination.IPs {
			for _, p := range pol.Destination.Ports {
				add(ip, p)
			}
		}
	}

	if len(byIP) == 0 {
		return nil
	}
	out := make(map[string][]int, len(byIP))
	for ip, set := range byIP {
		ports := make([]int, 0, len(set))
		for p := range set {
			ports = append(ports, p)
		}
		out[ip] = ports
	}
	return out
}

// UniquePortForwardName reports whether a name identifies exactly one enabled rule.
func (s *Snapshot) UniquePortForwardName(name string) bool {
	var matches int
	for _, pf := range s.PortForwards {
		if pf.Enabled && strings.EqualFold(pf.Name, name) {
			matches++
		}
	}
	return matches == 1
}

// expandPortSpec expands a UniFi port spec ("443", "80,443", "9000-9002") into
// concrete port numbers, skipping ranges wider than maxRange.
func expandPortSpec(spec string, maxRange int) []int {
	var ports []int
	for _, token := range strings.Split(spec, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if startStr, endStr, ok := strings.Cut(token, "-"); ok {
			start, err1 := strconv.Atoi(strings.TrimSpace(startStr))
			end, err2 := strconv.Atoi(strings.TrimSpace(endStr))
			if err1 == nil && err2 == nil && start >= 1 && end <= 65535 && end >= start && (end-start+1) <= maxRange {
				for p := start; p <= end; p++ {
					ports = append(ports, p)
				}
			}
			continue
		}
		if single, err := strconv.Atoi(token); err == nil && single >= 1 && single <= 65535 {
			ports = append(ports, single)
		}
	}
	return ports
}

// Client represents a connected endpoint on the local network as observed by
// UniFi (laptops, servers, IoT appliances, cameras, etc.).
type Client struct {
	// ID is the controller's inventory identifier when available.
	ID string `json:"id,omitempty"`

	// MAC is the normalized lowercase hardware address of the client.
	MAC string `json:"mac"`

	// IP is the client's current IPv4 address on the LAN.
	IP string `json:"ip"`

	// IPv6 holds any IPv6 addresses reported for this client by UniFi or local discovery.
	IPv6 []string `json:"ipv6,omitempty"`

	// Hostname is the DHCP or DNS hostname reported by the client.
	Hostname string `json:"hostname"`

	// Name is the user-assigned alias in UniFi, if any.
	Name string `json:"name"`

	// OUI is the hardware vendor inferred by UniFi from the MAC prefix.
	OUI string `json:"oui"`

	// NetworkID links the client back to its Network entry in the snapshot.
	NetworkID string `json:"network_id"`

	// NetworkName is the human-readable VLAN/network name resolved from Networks.
	NetworkName string `json:"network_name"`

	// VLAN is the numeric 802.1Q VLAN tag (empty or "0" for the untagged default LAN).
	VLAN string `json:"vlan"`

	// IsWired reports whether the client is connected over Ethernet rather than Wi-Fi.
	IsWired bool `json:"is_wired"`

	// ESSID is the Wi-Fi network SSID for wireless clients, when reported.
	ESSID string `json:"essid,omitempty"`

	// SwitchMAC is the MAC address of the parent UniFi switch for wired clients.
	SwitchMAC string `json:"switch_mac,omitempty"`

	// SwitchPort is the physical switch port index for wired clients.
	SwitchPort int `json:"switch_port,omitempty"`

	// APMAC is the MAC address of the parent UniFi access point for wireless clients.
	APMAC string `json:"ap_mac,omitempty"`

	// TxBytes is total bytes transmitted by the client (wired or wireless).
	TxBytes int64 `json:"tx_bytes,omitempty"`

	// RxBytes is total bytes received by the client (wired or wireless).
	RxBytes int64 `json:"rx_bytes,omitempty"`

	// FirstSeen is the Unix timestamp (seconds) when UniFi first observed this MAC.
	FirstSeen int64 `json:"first_seen,omitempty"`

	// LastSeen is the Unix timestamp (seconds) when UniFi last observed this MAC.
	LastSeen int64 `json:"last_seen,omitempty"`
}

// DisplayName returns the most readable identifier available for a client,
// preferring the user-assigned UniFi name over hostname, IP, and finally MAC.
func (c Client) DisplayName() string {
	switch {
	case c.Name != "":
		return c.Name
	case c.Hostname != "":
		return c.Hostname
	case c.IP != "":
		return c.IP
	case len(c.IPv6) > 0 && strings.TrimSpace(c.IPv6[0]) != "":
		return strings.TrimSpace(c.IPv6[0])
	default:
		return c.MAC
	}
}

// PrimaryIP returns the preferred routable IP address for probing and lookup:
// IPv4 when present, otherwise the first non-link-local IPv6 address, falling
// back to any non-empty IPv6 address.
func (c Client) PrimaryIP() string {
	if ip := strings.TrimSpace(c.IP); ip != "" {
		return ip
	}
	fallback := ""
	for _, raw := range c.IPv6 {
		ip := strings.TrimSpace(raw)
		if ip == "" {
			continue
		}
		if fallback == "" {
			fallback = ip
		}
		if !strings.HasPrefix(strings.ToLower(ip), "fe80:") {
			return ip
		}
	}
	return fallback
}

// AllIPs returns every deduplicated non-empty IPv4 and IPv6 address known for
// the client, with IPv4 first when present.
func (c Client) AllIPs() []string {
	var out []string
	seen := make(map[string]struct{}, 1+len(c.IPv6))
	add := func(raw string) {
		ip := strings.TrimSpace(raw)
		if ip == "" {
			return
		}
		key := strings.ToLower(ip)
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		out = append(out, ip)
	}
	add(c.IP)
	for _, ip6 := range c.IPv6 {
		add(ip6)
	}
	return out
}

// Device represents a piece of Ubiquiti infrastructure managed by the site
// (gateway, switch, or wireless access point).
type Device struct {
	// ID is the controller's inventory identifier when available.
	ID string `json:"id,omitempty"`

	// MAC is the device's hardware address.
	MAC string `json:"mac"`

	// IP is the management IP address of the UniFi device.
	IP string `json:"ip"`

	// Name is the friendly name configured in UniFi.
	Name string `json:"name"`

	// Model is the UniFi hardware model code (e.g., "UDMPRO", "U6-Pro").
	Model string `json:"model"`

	// Type categorizes the device (e.g., "udm", "usw", "uap").
	Type string `json:"type"`

	// Version is the currently installed firmware version string.
	Version string `json:"version"`

	// Upgradable reports whether the controller knows of a newer firmware release.
	Upgradable bool `json:"upgradable"`

	// UplinkMAC is the parent UniFi device MAC discovered via LLDP, if any.
	UplinkMAC string `json:"uplink_mac,omitempty"`

	// UplinkName is the parent UniFi device display name, if reported.
	UplinkName string `json:"uplink_name,omitempty"`

	// UplinkPort is the remote port number on the parent switch/gateway.
	UplinkPort int `json:"uplink_port,omitempty"`

	// Ports holds the physical Ethernet/SFP port table (merged with port_overrides)
	// for UniFi switches, gateways, and In-Wall APs.
	Ports []SwitchPort `json:"ports,omitempty"`

	// BSSIDs holds the exact wireless radio BSSIDs advertised by this UniFi AP
	// (extracted from stat/device vap_table) for exact evil-twin matching.
	BSSIDs []string `json:"bssids,omitempty"`
}

// SwitchPort describes one physical Ethernet or SFP port on a UniFi switch,
// gateway, or In-Wall AP, combining live link telemetry with configured VLAN,
// PoE, isolation, and MAC port-security settings.
type SwitchPort struct {
	// PortIdx is the 1-based physical port number.
	PortIdx int `json:"port_idx"`

	// Name is the user-assigned or default port label (e.g., "Port 1", "SFP+ 2").
	Name string `json:"name"`

	// Enabled reports whether the port is administratively enabled (not disabled/off).
	Enabled bool `json:"enabled"`

	// Up reports whether a physical Ethernet/SFP link is currently active.
	Up bool `json:"up"`

	// Speed is the negotiated link rate in Mbps (0 when link is down).
	Speed int `json:"speed"`

	// Media is the physical port type (e.g., "GE", "2.5GE", "SFP", "SFP+").
	Media string `json:"media,omitempty"`

	// IsUplink reports whether UniFi marks this port as the device's upstream link.
	IsUplink bool `json:"is_uplink,omitempty"`

	// IsWAN reports whether this port serves a WAN internet interface.
	IsWAN bool `json:"is_wan,omitempty"`

	// OpMode is the UniFi port operation mode ("switch", "off", "mirror", "aggregate").
	OpMode string `json:"op_mode,omitempty"`

	// Forward is the UniFi VLAN forwarding mode ("all", "native", "customize", "disabled").
	Forward string `json:"forward,omitempty"`

	// TaggedVLANMgmt is UniFi's explicit tagged-VLAN mode ("auto", "block_all", "custom").
	TaggedVLANMgmt string `json:"tagged_vlan_mgmt,omitempty"`

	// TaggedVLANUnknown reports that the effective tagged VLAN set was unavailable.
	TaggedVLANUnknown bool `json:"tagged_vlan_unknown,omitempty"`

	// TaggedNetworkIDs lists networks included in a custom tagged VLAN list.
	TaggedNetworkIDs []string `json:"-"`

	// ExcludedNetworkIDs lists networks excluded from a tagged trunk.
	ExcludedNetworkIDs []string `json:"-"`

	// NativeNetworkID is the configured native/untagged network ID (empty = default LAN).
	NativeNetworkID string `json:"native_network_id,omitempty"`

	// NativeNetworkName is the resolved human-readable native VLAN/network name.
	NativeNetworkName string `json:"native_network_name,omitempty"`

	// PortConfID is the UniFi switch port profile ID assigned to this port, if any.
	PortConfID string `json:"port_conf_id,omitempty"`

	// ProfileManaged reports whether this port's VLAN, forwarding, PoE, isolation,
	// or port-security settings are governed by its referenced port profile rather
	// than manual per-port overrides.
	ProfileManaged bool `json:"profile_managed,omitempty"`

	// PoEEnabled reports whether PoE power is currently being delivered on this port.
	PoEEnabled bool `json:"poe_enabled,omitempty"`

	// PoEMode is the configured PoE mode ("auto", "off", "passthrough", etc.).
	PoEMode string `json:"poe_mode,omitempty"`

	// PoEPower is the live power draw in watts when PoE is active.
	PoEPower string `json:"poe_power,omitempty"`

	// PoEPowerWatts is the numeric PoE draw in watts parsed from PoEPower.
	PoEPowerWatts float64 `json:"poe_power_watts,omitempty"`

	// PortSecurityEnabled reports whether MAC address allowlisting is enforced.
	PortSecurityEnabled bool `json:"port_security_enabled,omitempty"`

	// PortSecurityUnknown reports that the controller did not confirm the MAC restriction setting.
	PortSecurityUnknown bool `json:"port_security_unknown,omitempty"`

	// PortSecurityMACs lists explicitly allowed MAC addresses when port security is enabled.
	PortSecurityMACs []string `json:"port_security_macs,omitempty"`

	// Isolation reports whether L2 port isolation is enabled on this port.
	Isolation bool `json:"isolation,omitempty"`

	// IsolationUnknown reports that the port inherits its settings from a port
	// profile whose definition was missing from the snapshot, so the effective
	// L2 isolation setting could not be determined.
	IsolationUnknown bool `json:"isolation_unknown,omitempty"`

	// MACTableCount is the number of active MAC addresses learned on this port.
	MACTableCount int `json:"mac_table_count,omitempty"`

	// STPState is the Spanning Tree state ("forwarding", "discarding", "blocking", "disabled").
	STPState string `json:"stp_state,omitempty"`

	// STPStateChanges counts STP topology transitions on this port.
	STPStateChanges int `json:"stp_state_changes,omitempty"`

	// RXErrors counts receive frame errors on this port.
	RXErrors int64 `json:"rx_errors,omitempty"`

	// TXErrors counts transmit frame errors on this port.
	TXErrors int64 `json:"tx_errors,omitempty"`

	// RXDropped counts dropped inbound packets on this port.
	RXDropped int64 `json:"rx_dropped,omitempty"`

	// TXDropped counts dropped outbound packets on this port.
	TXDropped int64 `json:"tx_dropped,omitempty"`
}

// TaggedPolicy returns the effective forwarding mode for the port.
func (sp SwitchPort) TaggedPolicy() string {
	if !sp.Enabled {
		return "disabled"
	}
	if sp.TaggedVLANUnknown {
		return "unknown"
	}
	mode := strings.ToLower(sp.TaggedVLANMgmt)
	if mode == "" {
		mode = strings.ToLower(sp.Forward)
	}
	switch mode {
	case "block_all", "native":
		return "block_all"
	case "custom", "customize":
		if sp.TaggedNetworkIDs != nil || sp.ExcludedNetworkIDs != nil {
			return "custom"
		}
	case "disabled":
		return "disabled"
	case "auto", "all":
		if strings.EqualFold(sp.Forward, "native") {
			return "block_all"
		}
		return "all"
	}
	return "unknown"
}

// WLANConfig represents one UniFi Wi-Fi SSID and its encryption/isolation settings.
type WLANConfig struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	Security    string `json:"security"`     // "wpapsk", "open", "wep", "wpaeap"
	WPAMode     string `json:"wpa_mode"`     // "wpa2", "wpa3", "wpa1"
	WPA3Support bool   `json:"wpa3_support"` // WPA3 transition or WPA3-only enabled
	PMFMode     string `json:"pmf_mode"`     // "disabled", "optional", "required"
	L2Isolation bool   `json:"l2_isolation"`
	IsGuest     bool   `json:"is_guest"`
	NetworkID   string `json:"network_id,omitempty"`
	NetworkName string `json:"network_name,omitempty"`
}

// RogueAP represents a neighboring or foreign wireless BSSID observed by UniFi APs.
type RogueAP struct {
	BSSID    string `json:"bssid"`
	ESSID    string `json:"essid"`
	APMAC    string `json:"ap_mac,omitempty"`
	Channel  int    `json:"channel,omitempty"`
	Band     string `json:"band,omitempty"`
	Security string `json:"security,omitempty"`
	OUI      string `json:"oui,omitempty"`
	RSSI     int    `json:"rssi,omitempty"`
	IsRogue  bool   `json:"is_rogue,omitempty"`
	IsUBNT   bool   `json:"is_ubnt,omitempty"`
	IsAdhoc  bool   `json:"is_adhoc,omitempty"`
	LastSeen int64  `json:"last_seen,omitempty"`
}

// SiteSecuritySettings summarizes non-secret controller/gateway security posture
// parsed from /rest/setting (mgmt, usg, ips, doh, teleport).
type SiteSecuritySettings struct {
	SSHEnabled      bool `json:"ssh_enabled"`
	SSHPasswordAuth bool `json:"ssh_password_auth"`
	// SSHPasswordAuthKnown distinguishes an explicit password setting from missing telemetry.
	SSHPasswordAuthKnown bool     `json:"ssh_password_auth_known,omitempty"`
	SSHKeyCount          int      `json:"ssh_key_count"`
	UPnPEnabled          bool     `json:"upnp_enabled"`
	UPnPNATPMPEnabled    bool     `json:"upnp_nat_pmp_enabled"`
	UPnPSecureMode       bool     `json:"upnp_secure_mode"`
	IPSMode              string   `json:"ips_mode,omitempty"` // "ips", "ids", "disabled"
	HoneypotEnabled      bool     `json:"honeypot_enabled"`
	HoneypotIPs          []string `json:"honeypot_ips,omitempty"`
	DNSFiltering         bool     `json:"dns_filtering"`
	DoHState             string   `json:"doh_state,omitempty"` // "off", "auto", "custom"
	TeleportEnabled      bool     `json:"teleport_enabled"`
}

// VPNConnection describes one currently active remote-access VPN session.
type VPNConnection struct {
	ID       string `json:"id,omitempty"`
	Name     string `json:"name,omitempty"`
	User     string `json:"user,omitempty"`
	Type     string `json:"type,omitempty"`
	RemoteIP string `json:"remote_ip,omitempty"`
	LocalIP  string `json:"local_ip,omitempty"`
}

// SystemHealth summarizes gateway WAN health and active VPN sessions.
type SystemHealth struct {
	WANStatus      string          `json:"wan_status,omitempty"`
	WANIP          string          `json:"wan_ip,omitempty"`
	ActiveVPNUsers int             `json:"active_vpn_users"`
	VPNConnections []VPNConnection `json:"vpn_connections,omitempty"`
}

// HistoricalClient records a known client MAC from /rest/user for dormant
// reappearance and wired/Wi-Fi medium-swap detection.
type HistoricalClient struct {
	MAC             string `json:"mac"`
	Name            string `json:"name,omitempty"`
	Hostname        string `json:"hostname,omitempty"`
	IsWired         bool   `json:"is_wired"`
	FirstSeen       int64  `json:"first_seen,omitempty"`
	LastSeen        int64  `json:"last_seen,omitempty"`
	LastNetworkName string `json:"last_network_name,omitempty"`
}

// ControllerLogEvent represents a normalized security or admin activity event
// from UniFi's v2 System Log (or legacy stat/event fallback).
type ControllerLogEvent struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Category  string    `json:"category"` // "SECURITY", "ADMIN", "NETWORK", "CLIENT_DEVICES", ...
	Event     string    `json:"event"`    // "THREAT_BLOCKED", "ADMIN_ACCESS", ...
	Key       string    `json:"key,omitempty"`
	Severity  string    `json:"severity"` // "critical", "high", "medium", "low", "info"
	Title     string    `json:"title,omitempty"`
	Message   string    `json:"message"`
	SrcIP     string    `json:"src_ip,omitempty"`
	DstIP     string    `json:"dst_ip,omitempty"`
	Admin     string    `json:"admin,omitempty"`
	Device    string    `json:"device,omitempty"`
}

// Network describes a UniFi LAN or VLAN segment along with its structural
// isolation and firewall-zone placement reported by the controller.
type Network struct {
	// RouterUnresolved reports a switch-managed network whose router is missing from inventory.
	RouterUnresolved bool `json:"router_unresolved,omitempty"`
	// ID is the internal controller identifier referenced by clients and zones.
	ID string `json:"id"`

	// Name is the user-facing network name.
	Name string `json:"name"`

	// Purpose describes how UniFi uses the network (e.g., "corporate", "guest", "wan").
	Purpose string `json:"purpose"`

	// VLAN is the numeric VLAN tag assigned to the network, if VLAN tagging is enabled.
	VLAN string `json:"vlan"`

	// Subnet is the CIDR range configured on the gateway (e.g., "192.168.1.1/24").
	Subnet string `json:"subnet"`

	// IsolationEnabled reports whether UniFi's explicit Network Isolation flag
	// is enabled on this network.
	IsolationEnabled bool `json:"isolation_enabled,omitempty"`

	// InternetAccessEnabled reports UniFi's per-network "Allow Internet Access"
	// toggle when exposed by the controller (nil means omitted/unknown).
	InternetAccessEnabled *bool `json:"internet_access_enabled,omitempty"`

	// DomainName records the optional local DHCP domain configured on this
	// network (e.g., "iot", "guest", "localdomain").
	DomainName string `json:"domain_name,omitempty"`

	// ZoneID is the UniFi Zone-Based Firewall zone UUID containing this network.
	ZoneID string `json:"zone_id,omitempty"`

	// ZoneName is the resolved firewall zone name (e.g., "Internal", "Hotspot", "Dmz").
	ZoneName string `json:"zone_name,omitempty"`

	// IPv6Subnet records the IPv6 prefix assigned to this VLAN, if configured.
	IPv6Subnet string `json:"ipv6_subnet,omitempty"`

	// RouterDeviceMAC identifies the L3 switch MAC when inter-VLAN routing for
	// this VLAN is owned by an L3 switch rather than the gateway. Empty means
	// the site's primary UniFi gateway routes this VLAN.
	RouterDeviceMAC string `json:"router_device_mac,omitempty"`

	// DHCPGuardEnabled reports whether switch DHCP snooping/guard is enabled.
	DHCPGuardEnabled *bool `json:"dhcp_guard_enabled,omitempty"`

	// MDNSReflectorEnabled reports whether mDNS reflection/proxy is active on this VLAN.
	MDNSReflectorEnabled *bool `json:"mdns_reflector_enabled,omitempty"`

	// IGMPSnooping reports whether IGMP snooping is enabled on this VLAN.
	IGMPSnooping *bool `json:"igmp_snooping,omitempty"`

	// DNSServers lists DHCP-assigned DNS resolvers for this VLAN.
	DNSServers []string `json:"dns_servers,omitempty"`

	// DHCPStart, DHCPEnd, and ActiveLeases support DHCP pool exhaustion and overlap checks.
	DHCPStart    string `json:"dhcp_start,omitempty"`
	DHCPEnd      string `json:"dhcp_end,omitempty"`
	ActiveLeases int    `json:"active_leases,omitempty"`
}

// FirewallZone represents a UniFi Zone-Based Firewall zone grouping one or more
// networks under shared inter-zone traffic policies.
type FirewallZone struct {
	// ID is the zone UUID assigned by UniFi.
	ID string `json:"id"`

	// Name is the zone display name (e.g., "Internal", "External", "Hotspot", "Dmz", "Gateway").
	Name string `json:"name"`

	// Origin indicates whether UniFi created the zone ("SYSTEM_DEFINED") or the
	// operator created a custom zone ("USER_DEFINED").
	Origin string `json:"origin,omitempty"`

	// NetworkIDs lists the network UUIDs assigned to this zone.
	NetworkIDs []string `json:"network_ids,omitempty"`
}

// FirewallPolicy represents a single UniFi Zone-Based Firewall rule governing
// traffic between a source and destination zone.
type FirewallPolicy struct {
	// ID is the unique rule identifier on the console.
	ID string `json:"id"`

	// Name is the human-readable policy label.
	Name string `json:"name"`

	// Enabled reports whether the firewall policy is actively enforced.
	Enabled bool `json:"enabled"`

	// Action is the rule verdict ("ALLOW", "BLOCK", or "REJECT").
	Action string `json:"action"`

	// Origin distinguishes built-in rules ("SYSTEM_DEFINED") from operator rules ("USER_DEFINED").
	Origin string `json:"origin,omitempty"`

	// Index records the explicit rule evaluation order (lower evaluates first).
	Index int `json:"index,omitempty"`

	// IPVersion records the address family ("ipv4", "ipv6", or "both").
	// Empty defaults to "both" for backward compatibility with legacy fixtures.
	IPVersion string `json:"ip_version,omitempty"`

	// Protocol is the matched IP protocol ("all", "tcp", "udp", "tcp_udp", "icmp", "icmpv6", etc.).
	Protocol string `json:"protocol,omitempty"`

	// ProtocolNegated is true when protocolFilter.matchOpposite inverts the
	// protocol match (e.g., all protocols except UDP).
	ProtocolNegated bool `json:"protocol_negated,omitempty"`

	// ConnectionStates restricts matching to specific conntrack states
	// ("new", "established", "related", "invalid"). Empty matches all states.
	ConnectionStates []string `json:"connection_states,omitempty"`

	// MatchReturnTraffic is true when the rule automatically allows established
	// return packets for sessions permitted in the forward direction.
	MatchReturnTraffic bool `json:"match_return_traffic,omitempty"`

	// Schedule optionally names an active time schedule on this rule.
	Schedule string `json:"schedule,omitempty"`

	// UnsupportedReason records any top-level policy construct UniBlue cannot
	// evaluate deterministically (e.g., an unrecognized protocol filter).
	UnsupportedReason string `json:"unsupported_reason,omitempty"`

	// Source describes the traffic origin zone and optional IP/port filters.
	Source PolicyEndpoint `json:"source"`

	// Destination describes the traffic target zone and optional IP/port filters.
	Destination PolicyEndpoint `json:"destination"`

	// LoggingEnabled reports whether matches are logged to syslog/system log.
	LoggingEnabled bool `json:"logging_enabled,omitempty"`
}

// PortRange represents an inclusive TCP/UDP port range [Start, End] in 1..65535.
type PortRange struct {
	Start int `json:"start" yaml:"start"`
	End   int `json:"end" yaml:"end"`
}

// PolicyEndpoint captures the zone and optional IP/port constraints on one side
// of a UniFi FirewallPolicy.
type PolicyEndpoint struct {
	// ZoneID is the UniFi firewall zone UUID.
	ZoneID string `json:"zone_id" yaml:"zone_id"`

	// ZoneName is the resolved firewall zone display name.
	ZoneName string `json:"zone_name,omitempty" yaml:"zone_name,omitempty"`

	// IPs holds explicit IPv4/IPv6 addresses or CIDRs targeted by this endpoint, if filtered.
	IPs []string `json:"ips,omitempty" yaml:"ips,omitempty"`

	// NetworkIDs holds explicit UniFi network IDs or names matched by this endpoint.
	NetworkIDs []string `json:"network_ids,omitempty" yaml:"network_ids,omitempty"`

	// MACs holds explicit MAC addresses matched by this endpoint.
	MACs []string `json:"macs,omitempty" yaml:"macs,omitempty"`

	// Ports holds explicit port numbers matched by this endpoint, if filtered.
	Ports []int `json:"ports,omitempty" yaml:"ports,omitempty"`

	// PortRanges holds inclusive port ranges (including ranges wider than 16 ports)
	// matched by this endpoint so wide ranges are never silently dropped.
	PortRanges []PortRange `json:"port_ranges,omitempty" yaml:"port_ranges,omitempty"`

	// AnyTarget is true when no IP/network/MAC target filter narrows the zone.
	AnyTarget bool `json:"any_target" yaml:"any_target"`

	// AnyPort is true when no port filter narrows the matched ports.
	AnyPort bool `json:"any_port" yaml:"any_port"`

	// NegateTarget is true when matchOpposite inverts the target selector.
	NegateTarget bool `json:"negate_target,omitempty" yaml:"negate_target,omitempty"`

	// NegatePort is true when matchOpposite inverts the port selector.
	NegatePort bool `json:"negate_port,omitempty" yaml:"negate_port,omitempty"`

	// UnsupportedSelector records any opaque controller selector (e.g., dynamic
	// region/app/schedule group) that UniBlue cannot evaluate deterministically.
	UnsupportedSelector string `json:"unsupported_selector,omitempty" yaml:"unsupported_selector,omitempty"`
}

// HasCompoundTarget reports whether the endpoint restricts multiple independent
// dimensions. The legacy NegateTarget field cannot identify which one is inverted.
func (ep PolicyEndpoint) HasCompoundTarget() bool {
	return len(ep.MACs) > 0 && (len(ep.IPs) > 0 || len(ep.NetworkIDs) > 0) || len(ep.IPs) > 0 && len(ep.NetworkIDs) > 0
}

// MatchesPort reports whether port matches either Ports or PortRanges (ignoring NegatePort).
func (ep PolicyEndpoint) MatchesPort(port int) bool {
	if port < 1 || port > 65535 {
		return false
	}
	for _, p := range ep.Ports {
		if p == port {
			return true
		}
	}
	for _, r := range ep.PortRanges {
		if port >= r.Start && port <= r.End {
			return true
		}
	}
	return false
}

// OnlyPort reports whether a positive port selector is confined to the supplied ports.
func (ep PolicyEndpoint) OnlyPort(ports ...int) bool {
	if ep.AnyPort || ep.NegatePort || !ep.HasPortConstraint() {
		return false
	}
	for _, p := range ep.Ports {
		if !slices.Contains(ports, p) {
			return false
		}
	}
	for _, r := range ep.PortRanges {
		if !rangeWithinPorts(r.Start, r.End, ports) {
			return false
		}
	}
	return true
}

// HasPortConstraint reports whether this endpoint carries any concrete port or port range.
func (ep PolicyEndpoint) HasPortConstraint() bool {
	return len(ep.Ports) > 0 || len(ep.PortRanges) > 0
}

// CoversAllPorts reports whether this endpoint matches all ports 1..65535.
func (ep PolicyEndpoint) CoversAllPorts() bool {
	if ep.AnyPort || (!ep.HasPortConstraint() && !ep.NegatePort) {
		return true
	}
	if !ep.NegatePort {
		for _, r := range ep.PortRanges {
			if r.Start <= 1 && r.End >= 65535 {
				return true
			}
		}
	}
	return false
}

// PortForward represents a gateway NAT rule exposing an internal host and port
// to the public internet.
type PortForward struct {
	// DestinationIP selects the external address on which the rule listens.
	DestinationIP string `json:"destination_ip,omitempty"`
	// SourceUnknown reports an active source filter that could not be resolved.
	SourceUnknown bool `json:"source_unknown,omitempty"`
	// ID is the internal rule identifier on the controller.
	ID string `json:"id"`

	// Name is the human-readable label for the forwarding rule.
	Name string `json:"name"`

	// Enabled indicates whether the rule is actively forwarding traffic.
	Enabled bool `json:"enabled"`

	// Proto specifies the forwarded transport protocol ("tcp", "udp", or "tcp_udp").
	Proto string `json:"proto"`

	// DstPort is the external WAN port or port range (e.g., "443" or "8000-8010").
	DstPort string `json:"dst_port"`

	// FwdIP is the internal LAN destination IP address receiving forwarded traffic.
	FwdIP string `json:"fwd_ip"`

	// FwdPort is the internal LAN destination port or port range.
	FwdPort string `json:"fwd_port"`

	// Src restricts allowed source IPs on WAN ("any" means open to the whole internet).
	Src string `json:"src"`

	// Interface optionally names the external WAN interface (e.g., "wan", "wan2", "both").
	Interface string `json:"interface,omitempty"`

	// IPVersion optionally specifies "ipv4", "ipv6", or "both" (defaults to "ipv4").
	IPVersion string `json:"ip_version,omitempty"`
}

// ExposesPort reports whether an enabled port-forwarding rule forwards traffic
// to the given internal port (supporting single ports and "start-end" ranges).
func (p PortForward) ExposesPort(port int) bool {
	if !p.Enabled || port <= 0 {
		return false
	}
	return portMatchesSpec(p.FwdPort, port)
}

// OnlyBackendPort reports whether the backend is confined to the supplied ports.
// A forward without port translation inherits its WAN port specification.
func (p PortForward) OnlyBackendPort(ports ...int) bool {
	spec := strings.TrimSpace(p.FwdPort)
	if spec == "" {
		spec = p.DstPort
	}
	return onlyListedPorts(spec, ports)
}

// OnlyPorts reports whether the WAN and backend port lists both stay within ports.
func (p PortForward) OnlyPorts(ports ...int) bool {
	return p.OnlyBackendPort(ports...) && (p.DstPort == "" || onlyListedPorts(p.DstPort, ports))
}

// onlyListedPorts checks every token so a range cannot be classified by its first port.
func onlyListedPorts(spec string, ports []int) bool {
	for token := range strings.SplitSeq(spec, ",") {
		lo, hi, ranged := strings.Cut(token, "-")
		first, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil || !slices.Contains(ports, first) {
			return false
		}
		if ranged {
			last, err := strconv.Atoi(strings.TrimSpace(hi))
			if err != nil || !rangeWithinPorts(first, last, ports) {
				return false
			}
		}
	}
	return true
}

// rangeWithinPorts rejects wide ranges before checking their individual members.
func rangeWithinPorts(first, last int, ports []int) bool {
	if first < 1 || last > 65535 || last < first || last-first >= len(ports) {
		return false
	}
	for port := first; port <= last; port++ {
		if !slices.Contains(ports, port) {
			return false
		}
	}
	return true
}

// MatchesTransport reports whether this port-forward's transport protocol covers
// transport ("tcp" or "udp"). A UDP-only forward never matches TCP, and a
// TCP-only forward never matches UDP.
func (p PortForward) MatchesTransport(transport string) bool {
	t := strings.ToLower(strings.TrimSpace(transport))
	if t == "" {
		t = "tcp"
	}
	proto := strings.ToLower(strings.TrimSpace(p.Proto))
	if proto == "" || proto == "both" || proto == "all" || proto == "tcp_udp" || proto == "tcp/udp" {
		return t == "tcp" || t == "udp"
	}
	return proto == t
}

// ExposesEndpoint reports whether an enabled port-forwarding rule forwards
// traffic of the specified L4 transport ("tcp" or "udp") to internal port.
func (p PortForward) ExposesEndpoint(port int, transport string) bool {
	if !p.ExposesPort(port) {
		return false
	}
	return p.MatchesTransport(transport)
}

// IsSourceRestricted reports whether this port forward narrows allowed WAN
// sources away from the open internet ("any", "0.0.0.0/0", "::/0").
func (p PortForward) IsSourceRestricted() bool {
	if p.SourceUnknown {
		return false
	}
	s := strings.ToLower(strings.TrimSpace(p.Src))
	for _, part := range strings.Split(s, ",") {
		switch strings.TrimSpace(part) {
		case "", "any", "0.0.0.0/0", "::/0":
			return false
		}
	}
	return true
}

// ExpandFwdPorts expands the rule's translated internal destination port spec
// into concrete port numbers (skipping ranges wider than maxRange).
func (p PortForward) ExpandFwdPorts(maxRange int) []int {
	if maxRange <= 0 {
		maxRange = 64
	}
	return expandPortSpec(p.FwdPort, maxRange)
}

// ExpandDstPorts expands the rule's external WAN port spec into concrete port
// numbers (skipping ranges wider than maxRange).
func (p PortForward) ExpandDstPorts(maxRange int) []int {
	if maxRange <= 0 {
		maxRange = 64
	}
	return expandPortSpec(p.DstPort, maxRange)
}

// portMatchesSpec checks whether port falls inside a UniFi port specification
// such as "443", "8080-8090", or a comma-separated list like "80,443".
func portMatchesSpec(spec string, port int) bool {
	for _, token := range strings.Split(spec, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if startStr, endStr, ok := strings.Cut(token, "-"); ok {
			start, err1 := strconv.Atoi(strings.TrimSpace(startStr))
			end, err2 := strconv.Atoi(strings.TrimSpace(endStr))
			if err1 == nil && err2 == nil && port >= start && port <= end {
				return true
			}
			continue
		}
		if single, err := strconv.Atoi(token); err == nil && single == port {
			return true
		}
	}
	return false
}

// flexString unmarshals JSON values that UniFi controllers inconsistently emit
// as either strings or numbers (for example, VLAN tags and port numbers).
type flexString string

// UnmarshalJSON accepts a JSON string, number, or null and converts it to a
// plain string without failing on controller version differences.
func (f *flexString) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		*f = ""
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*f = flexString(s)
		return nil
	}
	var num json.Number
	if err := json.Unmarshal(data, &num); err == nil {
		*f = flexString(num.String())
		return nil
	}
	return nil
}

// apiEnvelope matches the standard {"meta": ..., "data": [...]} wrapper used
// across UniFi Network REST endpoints.
type apiEnvelope[T any] struct {
	Meta struct {
		RC  string `json:"rc"`
		Msg string `json:"msg"`
	} `json:"meta"`
	Data []T `json:"data"`
}

// rawClient maps the wire fields returned by /api/s/<site>/stat/sta.
type rawClient struct {
	// ID is the local station record identifier.
	ID string `json:"_id"`
	// UserID identifies the known client across station sessions.
	UserID        string     `json:"user_id"`
	MAC           string     `json:"mac"`
	IP            string     `json:"ip"`
	IPv6Addresses []string   `json:"ipv6_addresses"`
	Hostname      string     `json:"hostname"`
	Name          string     `json:"name"`
	OUI           string     `json:"oui"`
	NetworkID     string     `json:"network_id"`
	Network       string     `json:"network"`
	VLAN          flexString `json:"vlan"`
	IsWired       bool       `json:"is_wired"`
	ESSID         string     `json:"essid"`
	SwMAC         string     `json:"sw_mac"`
	SwPort        int        `json:"sw_port"`
	APMAC         string     `json:"ap_mac"`
	TxBytes       int64      `json:"tx_bytes"`
	RxBytes       int64      `json:"rx_bytes"`
	WiredTxBytes  int64      `json:"wired-tx_bytes"`
	WiredRxBytes  int64      `json:"wired-rx_bytes"`
	FirstSeen     int64      `json:"first_seen"`
	LastSeen      int64      `json:"last_seen"`
}

// rawDevice maps the wire fields returned by /api/s/<site>/stat/device.
type rawDevice struct {
	// ID is the local inventory identifier.
	ID string `json:"_id"`
	// ExternalID is the integration inventory identifier.
	ExternalID string `json:"external_id"`
	// DeviceID is an alternate controller device reference.
	DeviceID   string `json:"device_id"`
	MAC        string `json:"mac"`
	IP         string `json:"ip"`
	Name       string `json:"name"`
	Model      string `json:"model"`
	Type       string `json:"type"`
	Version    string `json:"version"`
	Upgradable bool   `json:"upgradable"`
	Uplink     *struct {
		UplinkMAC        string `json:"uplink_mac"`
		UplinkDeviceName string `json:"uplink_device_name"`
		UplinkRemotePort int    `json:"uplink_remote_port"`
	} `json:"uplink"`
	PortTable     []rawPort `json:"port_table"`
	PortOverrides []rawPort `json:"port_overrides"`
	VAPTable      []struct {
		BSSID string `json:"bssid"`
	} `json:"vap_table"`
}

// flexSTPCount unmarshals UniFi's stp_state_change_count, which modern switch
// firmware emits as an array of {mst, change_count} objects while older
// firmware may emit a plain integer.
type flexSTPCount int

func (f *flexSTPCount) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		*f = 0
		return nil
	}
	var n int
	if err := json.Unmarshal(data, &n); err == nil {
		*f = flexSTPCount(n)
		return nil
	}
	var entries []struct {
		ChangeCount int `json:"change_count"`
	}
	if err := json.Unmarshal(data, &entries); err == nil {
		total := 0
		for _, e := range entries {
			total += e.ChangeCount
		}
		*f = flexSTPCount(total)
		return nil
	}
	*f = 0
	return nil
}

// rawPort maps a single port entry in UniFi's port_table or port_overrides array.
type rawPort struct {
	// IncludedNetworkIDs is the alternate controller spelling for the inclusion list.
	IncludedNetworkIDs []string `json:"included_networkconf_ids"`
	// TaggedNetworkIDs holds the controller IDs included on this trunk.
	TaggedNetworkIDs []string `json:"tagged_networkconf_ids"`
	// ExcludedNetworkIDs holds the controller IDs omitted from this trunk.
	ExcludedNetworkIDs  []string     `json:"excluded_networkconf_ids"`
	PortIdx             int          `json:"port_idx"`
	Name                string       `json:"name"`
	Enable              *bool        `json:"enable"`
	Up                  bool         `json:"up"`
	Speed               int          `json:"speed"`
	Media               string       `json:"media"`
	IsUplink            bool         `json:"is_uplink"`
	NetworkName         string       `json:"network_name"`
	OpMode              string       `json:"op_mode"`
	Forward             string       `json:"forward"`
	TaggedVLANMgmt      string       `json:"tagged_vlan_mgmt"`
	NativeNetworkConfID string       `json:"native_networkconf_id"`
	PortConfID          string       `json:"portconf_id"`
	SettingPreference   string       `json:"setting_preference"`
	PoEEnable           bool         `json:"poe_enable"`
	PoEMode             string       `json:"poe_mode"`
	PoEPower            flexString   `json:"poe_power"`
	PortSecurityEnabled *bool        `json:"port_security_enabled"`
	PortSecurityMACs    []string     `json:"port_security_mac_address"`
	Isolation           *bool        `json:"isolation"`
	MACTableCount       int          `json:"mac_table_count"`
	STPState            string       `json:"stp_state"`
	STPStateChangeCount flexSTPCount `json:"stp_state_change_count"`
	RXErrors            int64        `json:"rx_errors"`
	TXErrors            int64        `json:"tx_errors"`
	RXDropped           int64        `json:"rx_dropped"`
	TXDropped           int64        `json:"tx_dropped"`
}

// rawPortConf maps a UniFi switch port profile from /api/s/<site>/rest/portconf.
type rawPortConf struct {
	// IncludedNetworkIDs is the alternate controller spelling for the inclusion list.
	IncludedNetworkIDs []string `json:"included_networkconf_ids"`
	// TaggedNetworkIDs holds the controller IDs included on this trunk.
	TaggedNetworkIDs []string `json:"tagged_networkconf_ids"`
	// ExcludedNetworkIDs holds the controller IDs omitted from this trunk.
	ExcludedNetworkIDs  []string `json:"excluded_networkconf_ids"`
	ID                  string   `json:"_id"`
	Name                string   `json:"name"`
	OpMode              string   `json:"op_mode"`
	Forward             string   `json:"forward"`
	TaggedVLANMgmt      string   `json:"tagged_vlan_mgmt"`
	NativeNetworkConfID string   `json:"native_networkconf_id"`
	PoEMode             string   `json:"poe_mode"`
	PortSecurityEnabled *bool    `json:"port_security_enabled"`
	PortSecurityMACs    []string `json:"port_security_mac_address"`
	Isolation           *bool    `json:"isolation"`
}

// rawNetwork maps the wire fields returned by /api/s/<site>/rest/networkconf.
type rawNetwork struct {
	// ExternalID is the integration network identifier.
	ExternalID string `json:"external_id"`
	// ZoneID references the local Network firewall zone.
	ZoneID                  string     `json:"firewall_zone_id"`
	ID                      string     `json:"_id"`
	Name                    string     `json:"name"`
	Purpose                 string     `json:"purpose"`
	VLAN                    flexString `json:"vlan"`
	IPSubnet                string     `json:"ip_subnet"`
	IPv6Subnet              string     `json:"ipv6_subnet"`
	NetworkIsolationEnabled bool       `json:"network_isolation_enabled"`
	InternetAccessEnabled   *bool      `json:"internet_access_enabled"`
	DomainName              string     `json:"domain_name"`
	GatewayType             string     `json:"gateway_type"`
	GatewayDevice           string     `json:"gateway_device"`
	DHCPDEnabled            *bool      `json:"dhcpd_enabled"`
	DHCPDStart              string     `json:"dhcpd_start"`
	DHCPDStop               string     `json:"dhcpd_stop"`
	DHCPGuardEnabled        *bool      `json:"dhcpguard_enabled"`
	MDNSEnabled             *bool      `json:"mdns_enabled"`
	IGMPSnooping            *bool      `json:"igmp_snooping"`
	DHCPDDNS1               string     `json:"dhcpd_dns_1"`
	DHCPDDNS2               string     `json:"dhcpd_dns_2"`
}

// rawPortForward maps the wire fields returned by /api/s/<site>/rest/portforward.
type rawPortForward struct {
	// SrcLimitingEnabled controls the active source restriction.
	SrcLimitingEnabled *bool `json:"src_limiting_enabled"`
	// SrcLimitingType selects an inline IP or firewall group.
	SrcLimitingType string `json:"src_limiting_type"`
	// SrcGroupID references the source address group.
	SrcGroupID string `json:"src_firewall_group_id"`
	// DestinationIP selects the external listening address.
	DestinationIP string     `json:"destination_ip"`
	ID            string     `json:"_id"`
	Name          string     `json:"name"`
	Enabled       bool       `json:"enabled"`
	Proto         string     `json:"proto"`
	DstPort       flexString `json:"dst_port"`
	Fwd           string     `json:"fwd"`
	FwdPort       flexString `json:"fwd_port"`
	Src           string     `json:"src"`
	PfwdInterface string     `json:"pfwd_interface"`
	IPVersion     string     `json:"ip_version"`
}

// integrationPage matches the standard pagination envelope returned by all
// list endpoints in the official UniFi Network Integration API v1.
type integrationPage[T any] struct {
	Offset     int  `json:"offset"`
	Limit      int  `json:"limit"`
	Count      int  `json:"count"`
	TotalCount *int `json:"totalCount"`
	Data       []T  `json:"data"`
}

// integrationSite maps a site entry returned by GET /integration/v1/sites.
type integrationSite struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	InternalReference string `json:"internalReference"`
}

// integrationClient maps a client entry returned by GET /integration/v1/sites/{id}/clients.
type integrationClient struct {
	// UplinkDeviceID identifies the serving AP or switch.
	UplinkDeviceID string   `json:"uplinkDeviceId"`
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Type           string   `json:"type"`
	MACAddress     string   `json:"macAddress"`
	IPAddress      string   `json:"ipAddress"`
	IPv6Addresses  []string `json:"ipv6Addresses"`
}

// integrationDevice maps a device entry returned by GET /integration/v1/sites/{id}/devices.
type integrationDevice struct {
	ID                string `json:"id"`
	MACAddress        string `json:"macAddress"`
	IPAddress         string `json:"ipAddress"`
	Name              string `json:"name"`
	Model             string `json:"model"`
	State             string `json:"state"`
	FirmwareVersion   string `json:"firmwareVersion"`
	FirmwareUpdatable bool   `json:"firmwareUpdatable"`
}

// integrationNetwork maps a network/VLAN entry returned by GET /integration/v1/sites/{id}/networks.
type integrationNetwork struct {
	// DeviceID identifies the routing switch for a switch-managed network.
	DeviceID string `json:"deviceId"`
	// MDNSForwardingEnabled reports mDNS reflection on Network 11.
	MDNSForwardingEnabled *bool `json:"mdnsForwardingEnabled"`
	// DHCPGuarding is present when DHCP guarding is configured.
	DHCPGuarding *struct {
		Trusted []string `json:"trustedDhcpServerIpAddresses"`
	} `json:"dhcpGuarding"`
	ID                    string     `json:"id"`
	Name                  string     `json:"name"`
	Purpose               string     `json:"purpose"`
	Management            string     `json:"management"`
	VLANID                flexString `json:"vlanId"`
	Subnet                string     `json:"subnet"`
	IPv6Subnet            string     `json:"ipv6Subnet"`
	IsolationEnabled      bool       `json:"isolationEnabled"`
	InternetAccessEnabled *bool      `json:"internetAccessEnabled"`
	ZoneID                string     `json:"zoneId"`
	RouterDeviceMAC       string     `json:"routerDeviceMac"`
	GatewayDevice         string     `json:"gatewayDevice"`
	DHCPStart             string     `json:"dhcpStart"`
	DHCPEnd               string     `json:"dhcpEnd"`
	DomainName            string     `json:"domainName"`
	DHCPGuardEnabled      *bool      `json:"dhcpGuardEnabled"`
	MDNSEnabled           *bool      `json:"mdnsEnabled"`
	IGMPSnooping          *bool      `json:"igmpSnooping"`
	DNSServers            []string   `json:"dnsServers"`
	IPv4Configuration     *struct {
		HostIPAddress     string `json:"hostIpAddress"`
		PrefixLength      int    `json:"prefixLength"`
		DHCPConfiguration *struct {
			Mode           string `json:"mode"`
			Enabled        *bool  `json:"enabled"`
			DomainName     string `json:"domainName"`
			IPAddressRange *struct {
				Start string `json:"start"`
				Stop  string `json:"stop"`
			} `json:"ipAddressRange"`
			// DNSOverride contains explicit DNS server overrides.
			DNSOverride          []string `json:"dnsServerIpAddressesOverride"`
			DNSServerIPAddresses []string `json:"dnsServerIpAddresses"`
		} `json:"dhcpConfiguration"`
	} `json:"ipv4Configuration"`
	IPv6Configuration *struct {
		Subnet        string `json:"subnet"`
		Prefix        string `json:"prefix"`
		HostIPAddress string `json:"hostIpAddress"`
		PrefixLength  int    `json:"prefixLength"`
	} `json:"ipv6Configuration"`
}

// integrationFirewallZone maps a zone entry returned by GET /integration/v1/sites/{id}/firewall/zones.
type integrationFirewallZone struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	NetworkIDs []string `json:"networkIds"`
	Metadata   *struct {
		Origin string `json:"origin"`
	} `json:"metadata"`
}

// integrationFirewallPolicy maps a policy entry returned by GET /integration/v1/sites/{id}/firewall/policies.
type integrationFirewallPolicy struct {
	// IPSecFilter constrains IPsec traffic when present.
	IPSecFilter string `json:"ipsecFilter"`
	ID          string `json:"id"`
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	Index       *int   `json:"index"`
	Action      struct {
		Type               string `json:"type"`
		AllowReturnTraffic bool   `json:"allowReturnTraffic"`
	} `json:"action"`
	Source                integrationPolicyEndpoint `json:"source"`
	Destination           integrationPolicyEndpoint `json:"destination"`
	ConnectionStateFilter []string                  `json:"connectionStateFilter"`
	MatchReturnTraffic    bool                      `json:"matchReturnTraffic"`
	Schedule              *struct {
		Mode string `json:"mode"`
		Name string `json:"name"`
	} `json:"schedule"`
	IPProtocolScope *struct {
		IPVersion      string `json:"ipVersion"`
		ProtocolFilter *struct {
			Type          string          `json:"type"`
			MatchOpposite bool            `json:"matchOpposite"`
			Protocol      json.RawMessage `json:"protocol"`
			NamedProtocol string          `json:"namedProtocol"`
			Preset        json.RawMessage `json:"preset"`
			PresetName    string          `json:"presetName"`
		} `json:"protocolFilter"`
	} `json:"ipProtocolScope"`
	LoggingEnabled bool `json:"loggingEnabled"`
	Metadata       *struct {
		Origin string `json:"origin"`
	} `json:"metadata"`
}

// integrationPolicyEndpoint maps the source or destination filter block of an
// Integration v1 firewall policy.
type integrationPolicyEndpoint struct {
	ZoneID        string                    `json:"zoneId"`
	TrafficFilter *integrationTrafficFilter `json:"trafficFilter"`
}

type integrationTrafficFilter struct {
	Type             string                      `json:"type"`
	IPAddressFilter  *integrationIPAddressFilter `json:"ipAddressFilter"`
	PortFilter       *integrationPortFilter      `json:"portFilter"`
	NetworkFilter    *integrationNetworkFilter   `json:"networkFilter"`
	MACAddressFilter *flexMACFilter              `json:"macAddressFilter"`
}

type integrationIPAddressFilter struct {
	Type                  string                   `json:"type"`
	MatchOpposite         bool                     `json:"matchOpposite"`
	TrafficMatchingListID string                   `json:"trafficMatchingListId"`
	Items                 []integrationFilterValue `json:"items"`
}

type integrationFilterValue struct {
	// Start is the first IP in a range.
	Start string `json:"start"`
	// Stop is the last IP in a range.
	Stop  string     `json:"stop"`
	Type  string     `json:"type"`
	Value flexString `json:"value"`
}

type integrationPortFilter struct {
	Type                  string                      `json:"type"`
	MatchOpposite         bool                        `json:"matchOpposite"`
	TrafficMatchingListID string                      `json:"trafficMatchingListId"`
	Items                 []integrationPortFilterItem `json:"items"`
}

type integrationPortFilterItem struct {
	// Stop is the inclusive end used by integration v1.
	Stop  int        `json:"stop"`
	Type  string     `json:"type"`
	Value flexString `json:"value"`
	Start int        `json:"start"`
	End   int        `json:"end"`
}

type integrationNetworkFilter struct {
	MatchOpposite bool     `json:"matchOpposite"`
	NetworkIDs    []string `json:"networkIds"`
}

// flexMACFilter decodes UniFi Integration API v1's macAddressFilter, which may
// be emitted either as a single MAC string ("aa:bb:cc:dd:ee:ff") or as a
// structured object ({macAddresses: [...], matchOpposite: bool}).
type flexMACFilter struct {
	MatchOpposite bool     `json:"matchOpposite"`
	MACAddresses  []string `json:"macAddresses"`
}

func (f *flexMACFilter) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		if norm := strings.TrimSpace(single); norm != "" {
			f.MACAddresses = []string{norm}
		}
		return nil
	}
	type alias flexMACFilter
	var obj alias
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	*f = flexMACFilter(obj)
	return nil
}

// integrationACLRule maps a switch ACL rule returned by GET /integration/v1/sites/{id}/acl-rules.
type integrationACLRule struct {
	// wireError records any strict schema validation error encountered while
	// decoding this rule so coverage is marked partial even when disabled.
	wireError string
	// Description is descriptive metadata.
	Description string `json:"description"`
	// Metadata records provenance without selector semantics.
	Metadata              json.RawMessage         `json:"metadata"`
	ID                    string                  `json:"id"`
	Type                  string                  `json:"type"` // "IPV4" | "IPV6" | "MAC"
	Name                  string                  `json:"name"`
	Enabled               *bool                   `json:"enabled"`
	Index                 *int                    `json:"index"`
	Action                string                  `json:"action"` // "ALLOW" | "BLOCK"
	ProtocolFilter        []string                `json:"protocolFilter"`
	NetworkIDFilter       string                  `json:"networkIdFilter"`
	NetworkIDs            []string                `json:"networkIds"`
	EnforcingDeviceFilter *integrationDeviceRef   `json:"enforcingDeviceFilter"`
	SourceFilter          *integrationACLEndpoint `json:"sourceFilter"`
	DestinationFilter     *integrationACLEndpoint `json:"destinationFilter"`
}

// integrationDeviceRef maps an enforcingDeviceFilter on an Integration v1 ACL rule.
type integrationDeviceRef struct {
	Type      string   `json:"type"`
	DeviceIDs []string `json:"deviceIds"`
}

// integrationACLEndpoint maps the sourceFilter or destinationFilter object on a
// UniFi Integration v1 switch ACL rule across UniFi Network 10.x and 11.x schemas.
type integrationACLEndpoint struct {
	Type                 string   `json:"type"`
	MatchOpposite        bool     `json:"matchOpposite"`
	NetworkIDs           []string `json:"networkIds"`
	IPAddressesOrSubnets []string `json:"ipAddressesOrSubnets"`
	IPAddresses          []string `json:"ipAddresses"`
	IPs                  []string `json:"ips"`
	MACAddresses         []string `json:"macAddresses"`
	PrefixLength         *int     `json:"prefixLength"`
	Ports                []int    `json:"ports"`
	PortFilter           []int    `json:"portFilter"`
	Items                []struct {
		Type  string     `json:"type"`
		Value flexString `json:"value"`
		Start int        `json:"start"`
		Stop  int        `json:"stop"`
		End   int        `json:"end"`
	} `json:"items"`
}

// integrationTrafficMatchingList maps a Network List (Port List or IP List)
// returned by GET /integration/v1/sites/{id}/traffic-matching-lists.
type integrationTrafficMatchingList struct {
	ID    string `json:"id"`
	Type  string `json:"type"` // "PORTS" | "IPV4_ADDRESSES" | "IPV6_ADDRESSES"
	Name  string `json:"name"`
	Items []struct {
		Type  string     `json:"type"`
		Value flexString `json:"value"`
		Start flexString `json:"start"`
		Stop  flexString `json:"stop"`
		End   int        `json:"end"`
	} `json:"items"`
}

// UnmarshalJSON preserves malformed ACLs as evidence of partial table coverage.
func (r *integrationACLRule) UnmarshalJSON(raw []byte) error {
	type plain integrationACLRule
	var v plain
	err := decodeWireRow(raw, "acl", &v)
	*r = integrationACLRule(v)
	if err != nil {
		r.wireError = err.Error()
	}
	return nil
}
