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
}

// Network describes a UniFi LAN or VLAN segment.
type Network struct {
	// ID is the internal Mongo/controller identifier referenced by clients.
	ID string `json:"id"`

	// Name is the user-facing network name (e.g., "Default", "IoT").
	Name string `json:"name"`

	// Purpose describes how UniFi uses the network (e.g., "corporate", "guest", "wan").
	Purpose string `json:"purpose"`

	// VLAN is the numeric VLAN tag assigned to the network, if VLAN tagging is enabled.
	VLAN string `json:"vlan"`

	// Subnet is the CIDR range configured on the gateway (e.g., "192.168.1.1/24").
	Subnet string `json:"subnet"`
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
}

// rawNetwork maps the wire fields returned by /api/s/<site>/rest/networkconf.
type rawNetwork struct {
	ID       string     `json:"_id"`
	Name     string     `json:"name"`
	Purpose  string     `json:"purpose"`
	VLAN     flexString `json:"vlan"`
	IPSubnet string     `json:"ip_subnet"`
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
	IPv4Configuration *struct {
		HostIPAddress string `json:"hostIpAddress"`
		PrefixLength  int    `json:"prefixLength"`
	} `json:"ipv4Configuration"`
}
