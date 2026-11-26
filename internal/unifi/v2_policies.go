// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package unifi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

// v2Zone uses the Network application's local IDs for membership and exposes
// a separate external ID for references from the integration API.
type v2Zone struct {
	// ID identifies this resource in the Network application.
	ID string `json:"_id"`
	// ExternalID identifies this resource in integration v1.
	ExternalID string `json:"external_id"`
	// Name is the controller display name.
	Name string `json:"name"`
	// NetworkIDs lists the referenced network configurations.
	NetworkIDs []string `json:"network_ids"`
	// Default identifies a built-in zone.
	Default bool `json:"default_zone"`
	// SiteID identifies the owning site on versions that include it.
	SiteID string `json:"site_id"`
	// Key is the optional controller identity of a built-in zone.
	Key *string `json:"zone_key"`
	// ReadOnly records the controller's edit restriction.
	ReadOnly bool `json:"attr_no_edit"`
	// CloudTemplate identifies controller-managed provisioning metadata.
	CloudTemplate json.RawMessage `json:"cloud_template"`
}

// firewallGroup contains the typed legacy objects referenced by v2 selectors and NAT.
type firewallGroup struct {
	// Name is the display name of the address or port group.
	Name string `json:"name"`
	// ID identifies this resource in the Network application.
	ID string `json:"_id"`
	// ExternalID identifies this resource in integration v1.
	ExternalID string `json:"external_id"`
	// Type selects the interpretation of the remaining fields.
	Type string `json:"group_type"`
	// Members contains the address or port expressions in this group.
	Members []string `json:"group_members"`
	// SiteID identifies the owning site on legacy controllers.
	SiteID string `json:"site_id"`
	// Description is an optional group label.
	Description string `json:"description"`
	// ShortID is the controller's numeric display identifier.
	ShortID int `json:"short_id"`
	// Source records the origin of the group definition.
	Source string `json:"source"`
	// ReadOnly and Permanent describe controller-managed groups.
	ReadOnly bool `json:"attr_no_edit"`
	// Permanent prevents deletion of a built-in group.
	Permanent bool `json:"attr_no_delete"`
}

// UnmarshalJSON validates zone identity before membership can select an enforcer.
func (z *v2Zone) UnmarshalJSON(raw []byte) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return fmt.Errorf("firewall-zone: expected object")
	}
	type wire v2Zone
	var row wire
	if err := json.Unmarshal(trimmed, &row); err != nil {
		return fmt.Errorf("firewall-zone: %w", err)
	}
	if row.ID == "" || row.Name == "" {
		return fmt.Errorf("firewall-zone: missing identity or name")
	}
	*z = v2Zone(row)
	return nil
}

// UnmarshalJSON validates group shapes before either firewall or NAT rules use them.
func (g *firewallGroup) UnmarshalJSON(raw []byte) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return fmt.Errorf("firewall-group: expected object")
	}
	type wire firewallGroup
	var row wire
	if err := json.Unmarshal(trimmed, &row); err != nil {
		return fmt.Errorf("firewall-group: %w", err)
	}
	if row.ID == "" || row.Type == "" || row.Members == nil {
		return fmt.Errorf("firewall-group: missing identity, type or members")
	}
	*g = firewallGroup(row)
	return nil
}

// v2Policy keeps wire discriminators separate from their sometimes stale parameters.
type v2Policy struct {
	// ID identifies this resource in the Network application.
	ID string `json:"_id"`
	// ExternalID identifies this resource in integration v1 when present.
	ExternalID string `json:"external_id"`
	// SiteID identifies the owning site on versions that include it.
	SiteID string `json:"site_id"`
	// Name is the controller display name.
	Name string `json:"name"`
	// Action is the verdict for matching traffic.
	Action string `json:"action"`
	// Enabled distinguishes an inactive rule from a missing enable flag.
	Enabled *bool `json:"enabled"`
	// Index is the explicit rule priority, including zero.
	Index *int `json:"index"`
	// Predefined identifies a controller-generated rule.
	Predefined *bool `json:"predefined"`
	// PredefinedID identifies a built-in template on versions that include it.
	PredefinedID string `json:"predefined_id"`
	// Family selects IPv4, IPv6, or both.
	Family string `json:"ip_version"`
	// Protocol is the transport or IP protocol selector.
	Protocol string `json:"protocol"`
	// OppositeProtocol inverts the protocol match.
	OppositeProtocol bool `json:"match_opposite_protocol"`
	// StateType selects all, response-only, or custom state matching.
	StateType string `json:"connection_state_type"`
	// States contains the explicit connection states for this rule.
	States []string `json:"connection_states"`
	// Return requests automatic return traffic for an allow rule.
	Return bool `json:"create_allow_respond"`
	// IPSec enables the IPsec predicate.
	IPSec bool `json:"match_ip_sec"`
	// IPSecType holds the IPsec predicate retained by the controller even when inactive.
	IPSecType string `json:"match_ip_sec_type"`
	// ICMP narrows IPv4 ICMP to a named message type.
	ICMP string `json:"icmp_typename"`
	// ICMPv6 narrows IPv6 ICMP to a named message type.
	ICMPv6 string `json:"icmp_v6_typename"`
	// Schedule describes when a rule is active.
	Schedule *v2Schedule `json:"schedule"`
	// Source restricts the initiating endpoint.
	Source v2Endpoint `json:"source"`
	// Destination restricts the receiving endpoint.
	Destination v2Endpoint `json:"destination"`
	// Logging enables logging for a match.
	Logging bool `json:"logging"`
	// Description is descriptive metadata without an enforcement effect.
	Description string `json:"description"`
	// OriginID identifies the configuration that generated a rule.
	OriginID string `json:"origin_id"`
	// OriginType classifies the configuration that generated a rule.
	OriginType string `json:"origin_type"`
	// Hits counts matches observed by the controller.
	Hits int64 `json:"hits"`
	// LastHit records the last observed match time.
	LastHit int64 `json:"last_hit"`
	// ReportFlow selects flow reporting for matching traffic.
	ReportFlow bool `json:"report_flow"`
	// ReportFlowSupported describes controller reporting capabilities.
	ReportFlowSupported bool `json:"report_flow_supported"`
	// ReadOnly records controller edit-lock metadata.
	ReadOnly bool `json:"attr_no_edit"`
	// Permanent records controller delete-lock metadata.
	Permanent bool `json:"attr_no_delete"`
	// HiddenID records internal controller UI hiding metadata.
	HiddenID string `json:"attr_hidden_id"`
	// CreatedAt records optional creation timestamp metadata.
	CreatedAt json.RawMessage `json:"created_at"`
	// UpdatedAt records optional modification timestamp metadata.
	UpdatedAt json.RawMessage `json:"updated_at"`
}

// v2Schedule distinguishes unconditional operation from a time-dependent match.
type v2Schedule struct {
	// Mode selects the controller's schedule variant.
	Mode string `json:"mode"`
	// Name is an optional schedule label.
	Name string `json:"name"`
	// Days is the controller's weekday selection.
	Days []json.RawMessage `json:"repeat_on_days"`
	// AllDay records the all-day option stored alongside the mode.
	AllDay bool `json:"time_all_day"`
	// Date records an optional one-time schedule date.
	Date json.RawMessage `json:"date"`
	// DateStart records an optional schedule range start date.
	DateStart json.RawMessage `json:"date_start"`
	// DateEnd records an optional schedule range end date.
	DateEnd json.RawMessage `json:"date_end"`
	// TimeRangeStart records an optional daily window start time.
	TimeRangeStart json.RawMessage `json:"time_range_start"`
	// TimeRangeEnd records an optional daily window end time.
	TimeRangeEnd json.RawMessage `json:"time_range_end"`
	// StartTime records an alternate window start key used by some firmware builds.
	StartTime json.RawMessage `json:"start_time"`
	// EndTime records an alternate window end key used by some firmware builds.
	EndTime json.RawMessage `json:"end_time"`
}

// v2Endpoint models target and port filters as independent predicates.
type v2Endpoint struct {
	// Zone identifies the firewall zone of this endpoint.
	Zone string `json:"zone_id"`
	// Target selects the target dimension.
	Target string `json:"matching_target"`
	// Subtype selects inline or referenced target values.
	Subtype string `json:"matching_target_type"`
	// IPs contains literal addresses, subnets, or address expressions.
	IPs []string `json:"ips"`
	// IPGroup references a legacy address group.
	IPGroup string `json:"ip_group_id"`
	// NetworkID identifies a single network scope.
	NetworkID string `json:"network_id"`
	// NetworkIDs lists the referenced network configurations.
	NetworkIDs []string `json:"network_ids"`
	// ClientMACs identifies clients selected by the CLIENT discriminator.
	ClientMACs []string `json:"client_macs"`
	// MACs contains hardware-address constraints.
	MACs []string `json:"macs"`
	// MAC is a single hardware-address constraint.
	MAC string `json:"mac"`
	// MatchMAC activates the additional MAC binding.
	MatchMAC bool `json:"match_mac"`
	// OppositeIPs inverts the address constraint.
	OppositeIPs bool `json:"match_opposite_ips"`
	// OppositeNetworks inverts the network constraint.
	OppositeNetworks bool `json:"match_opposite_networks"`
	// PortType selects wildcard, inline, or referenced ports.
	PortType string `json:"port_matching_type"`
	// Port contains an inline port specification.
	Port string `json:"port"`
	// PortGroup references a legacy port group.
	PortGroup string `json:"port_group_id"`
	// OppositePorts inverts the port constraint independently of the target.
	OppositePorts bool `json:"match_opposite_ports"`
}

// v2ACL is the Network application's policy-table schema. Missing required
// scalar fields must be distinguishable from explicit zero or false values.
type v2ACL struct {
	// ID identifies this resource in the Network application.
	ID string `json:"_id"`
	// Name is the controller display name.
	Name string `json:"name"`
	// Description is descriptive metadata without an enforcement effect.
	Description string `json:"description"`
	// SiteID identifies the owning Network site.
	SiteID string `json:"site_id"`
	// ExternalID identifies this resource in integration v1.
	ExternalID string `json:"external_id"`
	// Predefined identifies a controller-generated rule.
	Predefined bool `json:"predefined"`
	// PredefinedID identifies a built-in template on versions that include it.
	PredefinedID string `json:"predefined_id"`
	// OriginType classifies the configuration that generated a rule.
	OriginType string `json:"origin_type"`
	// OriginID identifies the configuration that generated a rule.
	OriginID string `json:"origin_id"`
	// ReadOnly records controller edit-lock metadata.
	ReadOnly bool `json:"attr_no_edit"`
	// Permanent records controller delete-lock metadata.
	Permanent bool `json:"attr_no_delete"`
	// HiddenID records internal controller UI hiding metadata.
	HiddenID string `json:"attr_hidden_id"`
	// CreatedAt records optional creation timestamp metadata.
	CreatedAt json.RawMessage `json:"created_at"`
	// UpdatedAt records optional modification timestamp metadata.
	UpdatedAt json.RawMessage `json:"updated_at"`
	// Enabled distinguishes an inactive rule from a missing enable flag.
	Enabled *bool `json:"enabled"`
	// Index is the explicit rule priority, including zero.
	Index *int `json:"acl_index"`
	// Type selects the interpretation of the remaining fields.
	Type string `json:"type"`
	// Action is the verdict for matching traffic.
	Action string `json:"action"`
	// Enforcers contains the MAC addresses of enforcing switches.
	Enforcers []string `json:"specific_enforcers"`
	// NetworkID identifies a single network scope.
	NetworkID string `json:"mac_acl_network_id"`
	// Protocol is the transport or IP protocol selector.
	Protocol string `json:"ip_acl_protocol"`
	// Source restricts the initiating endpoint.
	Source *v2ACLEndpoint `json:"traffic_source"`
	// Destination restricts the receiving endpoint.
	Destination *v2ACLEndpoint `json:"traffic_destination"`
}

// v2ACLEndpoint carries the type-specific selector and optional transport ports.
type v2ACLEndpoint struct {
	// Type selects the interpretation of the remaining fields.
	Type string `json:"type"`
	// MACs contains hardware-address constraints.
	MACs []string `json:"specific_mac_addresses"`
	// Networks lists the network scopes of a NETWORK selector.
	Networks []string `json:"network_ids"`
	// IPs contains literal addresses, subnets, or address expressions.
	IPs []string `json:"ips_or_subnets"`
	// Ports contains the transport ports allowed by the selector.
	Ports []int `json:"ports"`
}

// checkWireFields rejects unknown keys, including nested siblings that Go's
// ordinary JSON decoder ignores. Explicit JSON null on nested optional fields
// is permitted so required-field checks decide whether absence is an error.
// Paths identify schema changes without logging row values.
func checkWireFields(raw json.RawMessage, typ reflect.Type, path string) error {
	if typ == reflect.TypeFor[json.RawMessage]() {
		return nil
	}
	isNull := bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
	if typ.Kind() == reflect.Pointer {
		if isNull {
			return nil
		}
		typ = typ.Elem()
	} else if isNull && strings.Contains(path, ".") && !strings.HasSuffix(path, "]") {
		return nil
	}
	switch typ.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
			return fmt.Errorf("%s: expected object", path)
		}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if val, ok := fields[name]; ok && name != "" {
				if err := checkWireFields(val, f.Type, path+"."+name); err != nil {
					return err
				}
				delete(fields, name)
			}
		}
		for key := range fields {
			return fmt.Errorf("%s.%s: unknown field", path, key)
		}
	case reflect.Slice:
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil || items == nil {
			return fmt.Errorf("%s: expected array", path)
		}
		for i, item := range items {
			if err := checkWireFields(item, typ.Elem(), fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	default:
		if isNull {
			return fmt.Errorf("%s: unexpected null", path)
		}
	}
	return nil
}

// decodeWireRow validates the entire selector before its values can influence a verdict.
func decodeWireRow[T any](raw json.RawMessage, path string, dst *T) error {
	if err := checkWireFields(raw, reflect.TypeFor[T](), path); err != nil {
		return err
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// aliases maps only unambiguous resource-local identifiers to their canonical ID.
type aliases map[string]string

// add makes collisions unresolvable rather than choosing a resource by response order.
func (a aliases) add(id string, keys ...string) {
	if id == "" {
		return
	}
	for _, key := range keys {
		if key == "" {
			continue
		}
		if old, ok := a[key]; ok && old != id {
			a[key] = ""
		} else {
			a[key] = id
		}
	}
}

// resolveIDs requires every list member to match inventory in the same namespace.
func (a aliases) resolveIDs(ids []string) ([]string, bool) {
	var result []string
	for _, id := range ids {
		resolved := a[id]
		if resolved == "" {
			return nil, false
		}
		if !slices.Contains(result, resolved) {
			result = append(result, resolved)
		}
	}
	return result, true
}

// groupIndex supports both namespaces while retaining the controller's group type.
type groupIndex struct {
	ids  aliases
	rows map[string]firewallGroup
}

// indexGroups preserves unresolved aliases when controller inventory is inconsistent.
func indexGroups(groups []firewallGroup) groupIndex {
	g := groupIndex{make(aliases), make(map[string]firewallGroup)}
	for _, row := range groups {
		g.ids.add(row.ID, row.ID, row.ExternalID)
		g.rows[row.ID] = row
	}
	return g
}

// validIPSelector accepts exact addresses, CIDRs, or inclusive same-family ranges.
func validIPSelector(v string) bool {
	if _, err := netip.ParseAddr(v); err == nil {
		return true
	}
	if _, err := netip.ParsePrefix(v); err == nil {
		return true
	}
	start, stop, ok := strings.Cut(v, "-")
	a, e1 := netip.ParseAddr(start)
	b, e2 := netip.ParseAddr(stop)
	return ok && e1 == nil && e2 == nil && a.BitLen() == b.BitLen() && a.Compare(b) <= 0
}

// canonicalMAC requires a six-byte address usable by the inventory.
func canonicalMAC(v string) string {
	m, err := net.ParseMAC(v)
	if err != nil || len(m) != 6 {
		return ""
	}
	return m.String()
}

// addressGroup returns a complete, validated address list or an unresolved result.
func (g groupIndex) addressGroup(id string) ([]string, bool) {
	r := g.rows[g.ids[id]]
	if (r.Type != "address-group" && r.Type != "ipv6-address-group") || len(r.Members) == 0 {
		return nil, false
	}
	for _, v := range r.Members {
		if !validIPSelector(v) || strings.Contains(v, ":") != (r.Type == "ipv6-address-group") {
			return nil, false
		}
	}
	return r.Members, true
}

// policyEndpoint resolves object references before passing constraints to the evaluator.
func (e v2Endpoint) policyEndpoint(zones map[string]FirewallZone, nets aliases, groups groupIndex) PolicyEndpoint {
	z := zones[e.Zone]
	out := PolicyEndpoint{ZoneID: z.ID, ZoneName: z.Name, AnyTarget: true, AnyPort: true, NegatePort: e.OppositePorts}
	if z.ID == "" {
		out.UnsupportedSelector = "zone_id"
	}
	switch e.Target {
	case "ANY":
		// An ANY target can retain the SPECIFIC editor setting after its values are cleared.
		if e.Subtype != "" && e.Subtype != "ANY" && e.Subtype != "SPECIFIC" {
			out.UnsupportedSelector = "matching_target_type"
		}
	case "IP":
		out.NegateTarget = e.OppositeIPs
		switch e.Subtype {
		case "SPECIFIC":
			out.IPs = e.IPs
		case "OBJECT":
			out.IPs, _ = groups.addressGroup(e.IPGroup)
		default:
			out.UnsupportedSelector = "matching_target_type"
		}
		if len(out.IPs) == 0 {
			out.UnsupportedSelector = "ips/ip_group_id"
		}
	case "NETWORK":
		ids := e.NetworkIDs
		if e.NetworkID != "" {
			if len(ids) > 0 && !slices.Contains(ids, e.NetworkID) {
				out.UnsupportedSelector = "conflicting network_id"
			}
			ids = append(slices.Clone(ids), e.NetworkID)
		}
		out.NetworkIDs, _ = nets.resolveIDs(ids)
		if len(out.NetworkIDs) == 0 {
			out.UnsupportedSelector = "network_ids"
		}
		out.NegateTarget = e.OppositeNetworks
	case "CLIENT", "MAC":
		if e.Target == "CLIENT" {
			out.MACs = slices.Clone(e.ClientMACs)
		} else {
			out.MACs = slices.Clone(e.MACs)
			if e.MAC != "" {
				out.MACs = append(out.MACs, e.MAC)
			}
		}
		if len(out.MACs) == 0 {
			out.UnsupportedSelector = "mac selector"
		}
	default:
		out.UnsupportedSelector = "matching_target"
	}
	if e.Target != "IP" && e.Target != "ANY" && e.Subtype != "" && e.Subtype != "SPECIFIC" {
		out.UnsupportedSelector = "matching_target_type"
	}
	if e.MatchMAC && e.Target != "CLIENT" && e.Target != "MAC" {
		out.MACs = append(out.MACs, e.MAC)
		if out.NegateTarget {
			out.UnsupportedSelector = "negated target with MAC binding"
		}
	}
	for i, m := range out.MACs {
		out.MACs[i] = canonicalMAC(m)
		if out.MACs[i] == "" {
			out.UnsupportedSelector = "invalid MAC"
		}
	}
	for _, ip := range out.IPs {
		if !validIPSelector(ip) {
			out.UnsupportedSelector = "invalid IP"
		}
	}
	out.AnyTarget = e.Target == "ANY" && len(out.MACs) == 0
	var specs []string
	switch e.PortType {
	case "ANY":
		if e.OppositePorts {
			out.UnsupportedSelector = "negated ANY port"
		}
	case "SPECIFIC":
		specs = []string{e.Port}
	case "OBJECT":
		g := groups.rows[groups.ids[e.PortGroup]]
		if g.Type == "port-group" {
			specs = g.Members
		}
	default:
		out.UnsupportedSelector = "port_matching_type"
	}
	if e.PortType != "ANY" {
		out.AnyPort = false
		if len(specs) == 0 {
			out.UnsupportedSelector = "port_group_id"
		}
		for _, spec := range specs {
			p, r, bad := parsePolicyPortSpec(spec)
			if bad || len(p)+len(r) == 0 {
				out.UnsupportedSelector = "invalid port"
				break
			}
			out.Ports = append(out.Ports, p...)
			out.PortRanges = append(out.PortRanges, r...)
		}
	}
	return out
}

// policy normalizes state mode before consulting state values. Some response-only
// rules omit the redundant explicit state array.
func (w v2Policy) policy(zones map[string]FirewallZone, nets aliases, groups groupIndex) FirewallPolicy {
	p := FirewallPolicy{ID: w.ID, Name: w.Name, Enabled: true, Action: w.Action, Origin: "USER_DEFINED", Protocol: strings.ToLower(w.Protocol), ProtocolNegated: w.OppositeProtocol, IPVersion: strings.ToLower(w.Family), LoggingEnabled: w.Logging, MatchReturnTraffic: w.Action == "ALLOW" && w.Return, Source: w.Source.policyEndpoint(zones, nets, groups), Destination: w.Destination.policyEndpoint(zones, nets, groups)}
	if w.Predefined != nil && *w.Predefined {
		p.Origin = "SYSTEM_DEFINED"
	}
	if w.Enabled != nil {
		p.Enabled = *w.Enabled
	}
	if w.Index != nil {
		p.Index = *w.Index
	}
	if w.Action != "ALLOW" && w.Action != "BLOCK" && w.Action != "REJECT" {
		p.UnsupportedReason = "action"
	}
	switch p.IPVersion {
	case "ipv4", "ipv6", "both":
	case "ipv4_and_ipv6", "all":
		p.IPVersion = "both"
	default:
		p.IPVersion = "both"
		p.UnsupportedReason = "ip_version"
	}
	if p.Protocol == "" {
		p.UnsupportedReason = "protocol"
	}
	switch w.StateType {
	case "ALL":
	case "RESPOND_ONLY":
		p.ConnectionStates = []string{"established", "related"}
		if len(w.States) > 0 && !(len(w.States) == 2 && slices.Contains(w.States, "ESTABLISHED") && slices.Contains(w.States, "RELATED")) {
			p.UnsupportedReason = "conflicting RESPOND_ONLY states"
			p.ConnectionStates = nil
		}
	case "CUSTOM":
		if len(w.States) == 0 {
			p.UnsupportedReason = "connection_states"
		}
		for _, s := range w.States {
			s = strings.ToLower(s)
			if !slices.Contains([]string{"new", "invalid", "related", "established"}, s) {
				p.UnsupportedReason = "connection_states"
				p.ConnectionStates = nil
				break
			}
			p.ConnectionStates = append(p.ConnectionStates, s)
		}
	default:
		p.UnsupportedReason = "connection_state_type"
	}
	if w.IPSec {
		p.UnsupportedReason = "match_ip_sec"
	}
	for _, v := range []string{w.ICMP, w.ICMPv6} {
		if v != "" && !strings.EqualFold(v, "ANY") {
			p.UnsupportedReason = "ICMP typename"
		}
	}
	if w.Schedule != nil {
		switch w.Schedule.Mode {
		case "ALWAYS":
		case "":
			p.UnsupportedReason = "schedule.mode"
		default:
			p.Schedule = w.Schedule.Mode
		}
	}
	return p
}

// aclEndpoint accepts only documented combinations of class, selector, and ports.
func (w *v2ACLEndpoint) aclEndpoint(class, path string, nets aliases) PolicyEndpoint {
	p := PolicyEndpoint{AnyTarget: true, AnyPort: true}
	if w == nil {
		p.UnsupportedSelector = path
		return p
	}
	switch w.Type {
	case "ANY", "ALL":
	case "NETWORK":
		p.NetworkIDs, _ = nets.resolveIDs(w.Networks)
		if w.Networks == nil || (len(w.Networks) > 0 && len(p.NetworkIDs) == 0) {
			p.UnsupportedSelector = path + ".network_ids"
		}
	case "CLIENT_MAC":
		if w.MACs == nil {
			p.UnsupportedSelector = path + ".specific_mac_addresses"
		}
		for _, v := range w.MACs {
			if m := canonicalMAC(v); m != "" {
				p.MACs = append(p.MACs, m)
			} else {
				p.UnsupportedSelector = path + ".specific_mac_addresses"
			}
		}
	case "IP_OR_SUBNET":
		if len(w.IPs) == 0 {
			p.UnsupportedSelector = path + ".ips_or_subnets"
		}
		for _, v := range w.IPs {
			ip, _, _ := strings.Cut(v, "/")
			addr, err := netip.ParseAddr(ip)
			if err != nil || !validIPSelector(v) || (class == "IPV4") != addr.Is4() {
				p.UnsupportedSelector = path + ".ips_or_subnets"
			}
		}
		p.IPs = w.IPs
	default:
		p.UnsupportedSelector = path + ".type"
	}
	if (len(w.MACs) > 0 && (w.Type != "CLIENT_MAC" || class != "MAC")) || (len(w.IPs) > 0 && (w.Type != "IP_OR_SUBNET" || class == "MAC")) || (len(w.Networks) > 0 && w.Type != "NETWORK") {
		p.UnsupportedSelector = path + ": conflicting selectors"
	}
	p.AnyTarget = len(p.IPs)+len(p.NetworkIDs)+len(p.MACs) == 0
	for _, n := range w.Ports {
		if class == "MAC" || n < 1 || n > 65535 {
			p.UnsupportedSelector = path + ".ports"
		}
		p.Ports = append(p.Ports, n)
	}
	p.AnyPort = len(p.Ports) == 0
	return p
}

// decodeV2ACL retains malformed rows so coverage is independent of enabled's zero value.
func decodeV2ACL(raw json.RawMessage, nets, devices aliases) SwitchACL {
	var w v2ACL
	if err := decodeWireRow(raw, "acl", &w); err != nil {
		return SwitchACL{Source: PolicyEndpoint{UnsupportedSelector: err.Error()}}
	}
	a := SwitchACL{ID: w.ID, Name: w.Name, Action: w.Action, RuleType: w.Type, Protocol: "all", IPVersion: "both", Source: w.Source.aclEndpoint(w.Type, "acl.traffic_source", nets), Destination: w.Destination.aclEndpoint(w.Type, "acl.traffic_destination", nets)}
	if w.Enabled != nil {
		a.Enabled = *w.Enabled
	} else {
		a.Source.UnsupportedSelector = "acl.enabled"
	}
	if w.Index != nil && *w.Index >= 0 {
		a.Index = *w.Index
	} else {
		a.Source.UnsupportedSelector = "acl.acl_index"
	}
	if w.ID == "" {
		a.Source.UnsupportedSelector = "acl._id"
	}
	if w.Action != "ALLOW" && w.Action != "BLOCK" {
		a.Source.UnsupportedSelector = "acl.action"
	}
	switch w.Type {
	case "IPV4", "IPV6":
		a.IPVersion = strings.ToLower(w.Type)
	case "MAC":
	default:
		a.Source.UnsupportedSelector = "acl.type"
	}
	switch w.Protocol {
	case "ALL":
	case "":
		if w.Type == "IPV4" {
			a.Source.UnsupportedSelector = "acl.ip_acl_protocol"
		}
	case "TCP", "UDP", "TCP_AND_UDP":
		if w.Type != "IPV4" {
			a.Source.UnsupportedSelector = "acl.ip_acl_protocol"
		}
		a.Protocol = strings.ToLower(strings.ReplaceAll(w.Protocol, "_AND_", "_"))
	default:
		a.Source.UnsupportedSelector = "acl.ip_acl_protocol"
	}
	for _, id := range w.Enforcers {
		m := firstNonEmpty(devices[id], devices[canonicalMAC(id)])
		if m == "" {
			a.Source.UnsupportedSelector = "acl.specific_enforcers"
			break
		}
		a.DeviceMACs = append(a.DeviceMACs, m)
	}
	if w.NetworkID != "" {
		if id := nets[w.NetworkID]; id != "" && w.Type == "MAC" {
			a.NetworkIDs = []string{id}
		} else {
			a.Source.UnsupportedSelector = "acl.mac_acl_network_id"
		}
	}
	return a
}

// guestRestrictions retains invalid explicit settings as an uncertainty rather
// than widening or narrowing a built-in block by dropping individual entries.
type guestRestrictions struct {
	ips     []string
	invalid bool
}

// readGuestRestrictions reads only configured post-authorization subnets.
func readGuestRestrictions(rows []map[string]any) guestRestrictions {
	var g guestRestrictions
	for _, r := range rows {
		if r["key"] != "guest_access" {
			continue
		}
		for k, v := range r {
			suffix, ok := strings.CutPrefix(k, "restricted_subnet_")
			if !ok {
				continue
			}
			if _, err := strconv.ParseUint(suffix, 10, 32); err != nil {
				continue
			}
			ip, ok := v.(string)
			if !ok || !validIPSelector(ip) {
				g.invalid = true
			} else {
				g.ips = append(g.ips, ip)
			}
		}
	}
	slices.Sort(g.ips)
	return g
}

// applyGuestRestrictions supplies the implicit IPv4 hotspot target omitted by both APIs.
func applyGuestRestrictions(policies []FirewallPolicy, g guestRestrictions) {
	for i := range policies {
		p := &policies[i]
		if p.Origin != "SYSTEM_DEFINED" || p.Action != "BLOCK" || p.IPVersion != "ipv4" || !strings.EqualFold(p.Name, "Post-Authorization Restrictions") || !strings.EqualFold(p.Source.ZoneName, "Hotspot") || !strings.EqualFold(p.Destination.ZoneName, "External") || !p.Destination.AnyTarget || p.Destination.NegateTarget || p.Destination.UnsupportedSelector != "" {
			continue
		}
		if g.invalid {
			p.UnsupportedReason = "invalid guest_access restricted subnet"
			continue
		}
		p.Destination.AnyTarget = false
		p.Destination.IPs = g.ips
		if len(g.ips) == 0 {
			p.Destination.IPs = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
		}
	}
}
