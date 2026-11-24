// Package unifi implements a minimal, read-only client for fetching topology,
// active clients, UniFi infrastructure inventory, and port-forwarding rules
// from both UniFi OS gateways (e.g., UDM Pro) and classic Network controllers
// (e.g., older Cloud Key Gen2 deployments).
package unifi

import (
	"encoding/json"
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
	// MAC is the normalized lowercase hardware address of the client.
	MAC string `json:"mac"`

	// IP is the client's current IPv4 address on the LAN.
	IP string `json:"ip"`

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
	default:
		return c.MAC
	}
}

// Device represents a piece of Ubiquiti infrastructure managed by the site
// (gateway, switch, or wireless access point).
type Device struct {
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

	// NativeNetworkID is the configured native/untagged network ID (empty = default LAN).
	NativeNetworkID string `json:"native_network_id,omitempty"`

	// NativeNetworkName is the resolved human-readable native VLAN/network name.
	NativeNetworkName string `json:"native_network_name,omitempty"`

	// PoEEnabled reports whether PoE power is currently being delivered on this port.
	PoEEnabled bool `json:"poe_enabled,omitempty"`

	// PoEMode is the configured PoE mode ("auto", "off", "passthrough", etc.).
	PoEMode string `json:"poe_mode,omitempty"`

	// PoEPower is the live power draw in watts when PoE is active.
	PoEPower string `json:"poe_power,omitempty"`

	// PortSecurityEnabled reports whether MAC address allowlisting is enforced.
	PortSecurityEnabled bool `json:"port_security_enabled,omitempty"`

	// PortSecurityMACs lists explicitly allowed MAC addresses when port security is enabled.
	PortSecurityMACs []string `json:"port_security_macs,omitempty"`

	// Isolation reports whether L2 port isolation is enabled on this port.
	Isolation bool `json:"isolation,omitempty"`

	// MACTableCount is the number of active MAC addresses learned on this port.
	MACTableCount int `json:"mac_table_count,omitempty"`
}

// Network describes a UniFi LAN or VLAN segment along with its structural
// isolation and firewall-zone placement reported by the controller.
type Network struct {
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

	// ZoneID is the UniFi Zone-Based Firewall zone UUID containing this network.
	ZoneID string `json:"zone_id,omitempty"`

	// ZoneName is the resolved firewall zone name (e.g., "Internal", "Hotspot", "Dmz").
	ZoneName string `json:"zone_name,omitempty"`
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

	// Protocol is the matched IP protocol ("all", "tcp", "udp", "tcp_udp", "icmp", etc.).
	Protocol string `json:"protocol,omitempty"`

	// Source describes the traffic origin zone and optional IP/port filters.
	Source PolicyEndpoint `json:"source"`

	// Destination describes the traffic target zone and optional IP/port filters.
	Destination PolicyEndpoint `json:"destination"`

	// LoggingEnabled reports whether matches are logged to syslog/system log.
	LoggingEnabled bool `json:"logging_enabled,omitempty"`
}

// PolicyEndpoint captures the zone and optional IP/port constraints on one side
// of a UniFi FirewallPolicy.
type PolicyEndpoint struct {
	// ZoneID is the UniFi firewall zone UUID.
	ZoneID string `json:"zone_id"`

	// ZoneName is the resolved firewall zone display name.
	ZoneName string `json:"zone_name,omitempty"`

	// IPs holds explicit IPv4/IPv6 addresses targeted by this endpoint, if filtered.
	IPs []string `json:"ips,omitempty"`

	// Ports holds explicit port numbers matched by this endpoint, if filtered.
	Ports []int `json:"ports,omitempty"`

	// AnyTarget is true when no IP/network/MAC target filter narrows the zone.
	AnyTarget bool `json:"any_target"`

	// AnyPort is true when no port filter narrows the matched ports.
	AnyPort bool `json:"any_port"`
}

// PortForward represents a gateway NAT rule exposing an internal host and port
// to the public internet.
type PortForward struct {
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
}

// ExposesPort reports whether an enabled port-forwarding rule forwards traffic
// to the given internal port (supporting single ports and "start-end" ranges).
func (p PortForward) ExposesPort(port int) bool {
	if !p.Enabled || port <= 0 {
		return false
	}
	return portMatchesSpec(p.FwdPort, port)
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
	MAC       string     `json:"mac"`
	IP        string     `json:"ip"`
	Hostname  string     `json:"hostname"`
	Name      string     `json:"name"`
	OUI       string     `json:"oui"`
	NetworkID string     `json:"network_id"`
	Network   string     `json:"network"`
	VLAN      flexString `json:"vlan"`
	IsWired   bool       `json:"is_wired"`
	ESSID     string     `json:"essid"`
	SwMAC     string     `json:"sw_mac"`
	SwPort    int        `json:"sw_port"`
	APMAC     string     `json:"ap_mac"`
}

// rawDevice maps the wire fields returned by /api/s/<site>/stat/device.
type rawDevice struct {
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
}

// rawPort maps a single port entry in UniFi's port_table or port_overrides array.
type rawPort struct {
	PortIdx             int        `json:"port_idx"`
	Name                string     `json:"name"`
	Enable              *bool      `json:"enable"`
	Up                  bool       `json:"up"`
	Speed               int        `json:"speed"`
	Media               string     `json:"media"`
	IsUplink            bool       `json:"is_uplink"`
	NetworkName         string     `json:"network_name"`
	OpMode              string     `json:"op_mode"`
	Forward             string     `json:"forward"`
	TaggedVLANMgmt      string     `json:"tagged_vlan_mgmt"`
	NativeNetworkConfID string     `json:"native_networkconf_id"`
	PoEEnable           bool       `json:"poe_enable"`
	PoEMode             string     `json:"poe_mode"`
	PoEPower            flexString `json:"poe_power"`
	PortSecurityEnabled *bool      `json:"port_security_enabled"`
	PortSecurityMACs    []string   `json:"port_security_mac_address"`
	Isolation           *bool      `json:"isolation"`
	MACTableCount       int        `json:"mac_table_count"`
}

// rawNetwork maps the wire fields returned by /api/s/<site>/rest/networkconf.
type rawNetwork struct {
	ID                      string     `json:"_id"`
	Name                    string     `json:"name"`
	Purpose                 string     `json:"purpose"`
	VLAN                    flexString `json:"vlan"`
	IPSubnet                string     `json:"ip_subnet"`
	NetworkIsolationEnabled bool       `json:"network_isolation_enabled"`
}

// rawPortForward maps the wire fields returned by /api/s/<site>/rest/portforward.
type rawPortForward struct {
	ID      string     `json:"_id"`
	Name    string     `json:"name"`
	Enabled bool       `json:"enabled"`
	Proto   string     `json:"proto"`
	DstPort flexString `json:"dst_port"`
	Fwd     string     `json:"fwd"`
	FwdPort flexString `json:"fwd_port"`
	Src     string     `json:"src"`
}

// integrationPage matches the standard pagination envelope returned by all
// list endpoints in the official UniFi Network Integration API v1.
type integrationPage[T any] struct {
	Offset     int `json:"offset"`
	Limit      int `json:"limit"`
	Count      int `json:"count"`
	TotalCount int `json:"totalCount"`
	Data       []T `json:"data"`
}

// integrationSite maps a site entry returned by GET /integration/v1/sites.
type integrationSite struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	InternalReference string `json:"internalReference"`
}

// integrationClient maps a client entry returned by GET /integration/v1/sites/{id}/clients.
type integrationClient struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	MACAddress string `json:"macAddress"`
	IPAddress  string `json:"ipAddress"`
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
	ID                string     `json:"id"`
	Name              string     `json:"name"`
	Purpose           string     `json:"purpose"`
	Management        string     `json:"management"`
	VLANID            flexString `json:"vlanId"`
	Subnet            string     `json:"subnet"`
	IsolationEnabled  bool       `json:"isolationEnabled"`
	ZoneID            string     `json:"zoneId"`
	IPv4Configuration *struct {
		HostIPAddress string `json:"hostIpAddress"`
		PrefixLength  int    `json:"prefixLength"`
	} `json:"ipv4Configuration"`
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
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Action  struct {
		Type string `json:"type"`
	} `json:"action"`
	Source          integrationPolicyEndpoint `json:"source"`
	Destination     integrationPolicyEndpoint `json:"destination"`
	IPProtocolScope *struct {
		IPVersion      string `json:"ipVersion"`
		ProtocolFilter *struct {
			Type     string `json:"type"`
			Protocol *struct {
				Name string `json:"name"`
			} `json:"protocol"`
			NamedProtocol string `json:"namedProtocol"`
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
	ZoneID        string `json:"zoneId"`
	TrafficFilter *struct {
		Type            string `json:"type"`
		IPAddressFilter *struct {
			Type          string `json:"type"`
			MatchOpposite bool   `json:"matchOpposite"`
			Items         []struct {
				Type  string     `json:"type"`
				Value flexString `json:"value"`
			} `json:"items"`
		} `json:"ipAddressFilter"`
		PortFilter *struct {
			Type          string `json:"type"`
			MatchOpposite bool   `json:"matchOpposite"`
			Items         []struct {
				Type  string     `json:"type"`
				Value flexString `json:"value"`
				Start int        `json:"start"`
				End   int        `json:"end"`
			} `json:"items"`
		} `json:"portFilter"`
		NetworkFilter *struct {
			NetworkIDs []string `json:"networkIds"`
		} `json:"networkFilter"`
		MACAddressFilter *struct {
			MACAddresses []string `json:"macAddresses"`
		} `json:"macAddressFilter"`
	} `json:"trafficFilter"`
}
