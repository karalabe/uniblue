// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ServiceState classifies how strongly a service endpoint has been identified.
const (
	ServiceStateObservedProtocol  = "observed-protocol"
	ServiceStateAdvertisedService = "advertised-service"
	ServiceStateOwnerDeclared     = "owner-declared"
	ServiceStateCandidatePort     = "candidate-port"
	ServiceStateTLSUnknownApp     = "tls-unknown-app"
	ServiceStateUnknown           = "unknown"
)

// AttributionLevel records how specifically an outbound internet dependency is
// supported by available evidence (never overstating a CDN IP as a specific app).
const (
	AttributionConfiguredEgress = "configured-egress"
	AttributionVendorFeed       = "vendor-feed"
	AttributionGatewayOrDNS     = "gateway-or-dns-inferred"
	AttributionHostingRangeOnly = "hosting-range-only"
	AttributionOpaqueEncrypted  = "opaque-encrypted"
)

// OutboundDependency represents an external internet service contacted by a
// local LAN device, kept strictly distinct from services hosted by that device.
type OutboundDependency struct {
	// Category classifies the dependency ("vendor-control", "firmware-updates",
	// "dns-time", "identity-signin", "push-notifications", "voice-video-relay",
	// "cloud-storage", "productivity-saas", "shared-cdn", "vpn-tunnel",
	// "unknown-encrypted", "unknown").
	Category string `json:"category" yaml:"category"`

	// ServiceName names the service or hosting provider only as specifically as
	// evidence allows (e.g., "CloudFront CDN", "Microsoft 365", "Unknown TLS/QUIC").
	ServiceName string `json:"service_name" yaml:"service_name"`

	// DestinationHost is an optional SNI/DNS/configured hostname.
	DestinationHost string `json:"destination_host,omitempty" yaml:"destination_host,omitempty"`

	// DestinationIP is the observed remote endpoint IP, if any.
	DestinationIP string `json:"destination_ip,omitempty" yaml:"destination_ip,omitempty"`

	// Port is the remote destination port.
	Port int `json:"port,omitempty" yaml:"port,omitempty"`

	// Transport is "tcp", "udp", or "quic".
	Transport string `json:"transport,omitempty" yaml:"transport,omitempty"`

	// AddressFamily is "ipv4" or "ipv6".
	AddressFamily string `json:"address_family,omitempty" yaml:"address_family,omitempty"`

	// AttributionLevel records the confidence tier of this attribution.
	AttributionLevel string `json:"attribution_level" yaml:"attribution_level"`

	// Source records which feed supplied the observation ("zeek", "ipfix",
	// "unifi-flows", "device-config", "owner-manifest").
	Source string `json:"source" yaml:"source"`

	// Observer names the vantage point/VLAN/gateway that saw the flow.
	Observer string `json:"observer,omitempty" yaml:"observer,omitempty"`

	// ObservedAt records when the flow was observed (coarse bucket preferred).
	ObservedAt *time.Time `json:"observed_at,omitempty" yaml:"observed_at,omitempty"`
}

// PassiveFlowRecord represents one owner-supplied passive service or flow record
// (e.g., Zeek known_services, IPFIX summary, UniFi traffic-flow export, or
// owner service manifest). Importing passive observations identifies UDP
// services (DNS, NTP, QUIC, WireGuard, SNMP, syslog) and alternate TCP ports
// without transmitting packets to LAN hosts.
type PassiveFlowRecord struct {
	// Direction is "hosted" (local host is the responder/server) or "outbound"
	// (local host initiated an external connection). If empty, inferred from
	// whether LocalIP/RemoteIP is private/RFC1918 vs public.
	Direction string `json:"direction,omitempty" yaml:"direction,omitempty"`

	// LocalIP is the LAN client IP involved.
	LocalIP string `json:"local_ip" yaml:"local_ip"`

	// RemoteIP is the peer IP (optional for local hosted service records).
	RemoteIP string `json:"remote_ip,omitempty" yaml:"remote_ip,omitempty"`

	// RemoteHost is an optional DNS/SNI/configured hostname for outbound flows.
	RemoteHost string `json:"remote_host,omitempty" yaml:"remote_host,omitempty"`

	// Port is the service port (local listener port when hosted, remote port when outbound).
	Port int `json:"port" yaml:"port"`

	// Transport is "tcp", "udp", or "sctp".
	Transport string `json:"transport" yaml:"transport"`

	// Protocol is the observed L7 protocol (e.g., "dns", "ntp", "quic", "tls",
	// "wireguard", "snmp", "syslog", "http", "ssh", or "" when unknown).
	Protocol string `json:"protocol,omitempty" yaml:"protocol,omitempty"`

	// Application optionally names an owner-declared or protocol-confirmed app
	// (never guessed from TLS/QUIC/CDN IP alone).
	Application string `json:"application,omitempty" yaml:"application,omitempty"`

	// Category optionally classifies an outbound dependency.
	Category string `json:"category,omitempty" yaml:"category,omitempty"`

	// SharedCDN indicates the remote address belongs to shared hosting/CDN ranges
	// (e.g., CloudFront, Cloudflare, Fastly) so UniBlue preserves ambiguity.
	SharedCDN bool `json:"shared_cdn,omitempty" yaml:"shared_cdn,omitempty"`

	// ECHPresent indicates Encrypted ClientHello concealed the origin hostname.
	ECHPresent bool `json:"ech_present,omitempty" yaml:"ech_present,omitempty"`

	// Source names the telemetry producer ("zeek", "ipfix", "unifi-flows", "owner-config").
	Source string `json:"source,omitempty" yaml:"source,omitempty"`

	// Observer names the observing interface/VLAN/gateway.
	Observer string `json:"observer,omitempty" yaml:"observer,omitempty"`

	// ObservedAt records when the flow was observed.
	ObservedAt *time.Time `json:"observed_at,omitempty" yaml:"observed_at,omitempty"`
}

// LoadPassiveFlows loads passive service and flow metadata from a JSON or YAML file.
func LoadPassiveFlows(path string) ([]PassiveFlowRecord, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read passive flows %q: %w", path, err)
	}
	return ParsePassiveFlows(raw)
}

// ParsePassiveFlows decodes JSON or YAML passive flow records (accepting either
// a top-level array or a wrapper object with a "flows"/"records"/"services" key).
func ParsePassiveFlows(raw []byte) ([]PassiveFlowRecord, error) {
	var wrapper struct {
		Flows    []PassiveFlowRecord `json:"flows" yaml:"flows"`
		Records  []PassiveFlowRecord `json:"records" yaml:"records"`
		Services []PassiveFlowRecord `json:"services" yaml:"services"`
	}
	if err := yaml.Unmarshal(raw, &wrapper); err == nil &&
		(len(wrapper.Flows) > 0 || len(wrapper.Records) > 0 || len(wrapper.Services) > 0) {
		var out []PassiveFlowRecord
		out = append(out, wrapper.Flows...)
		out = append(out, wrapper.Records...)
		out = append(out, wrapper.Services...)
		return out, nil
	}
	var list []PassiveFlowRecord
	if err := json.Unmarshal(raw, &list); err == nil {
		return list, nil
	}
	if err := yaml.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("parse passive flows: %w", err)
	}
	return list, nil
}

// ApplyPassiveFlows merges owner-supplied passive service and flow observations
// onto matching HostProfiles:
//   - Hosted local services enrich hp.Services (marking exact transport, family,
//     and state, preserving "tls-unknown-app" / "unknown" when evidence shows
//     only TLS, QUIC, or an opaque socket).
//   - Outbound internet connections populate hp.OutboundDependencies and NEVER
//     misclassify the local client as hosting that external server.
func canonicalIPKey(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap().String()
	}
	return strings.ToLower(s)
}

func ApplyPassiveFlows(profiles []HostProfile, records []PassiveFlowRecord) {
	if len(profiles) == 0 || len(records) == 0 {
		return
	}
	idxByIP := make(map[string]int, len(profiles)*2)
	for i, hp := range profiles {
		for _, ip := range hp.Client.AllIPs() {
			if k := canonicalIPKey(ip); k != "" {
				idxByIP[k] = i
			}
		}
	}

	for _, rec := range records {
		idx, ok := idxByIP[canonicalIPKey(rec.LocalIP)]
		if !ok {
			continue
		}
		hp := &profiles[idx]
		transport := strings.ToLower(strings.TrimSpace(rec.Transport))
		if transport == "" {
			transport = "tcp"
		}
		dir := strings.ToLower(strings.TrimSpace(rec.Direction))
		if dir == "" {
			switch {
			case rec.RemoteIP != "" && !isPrivateOrLocalIP(rec.RemoteIP):
				dir = "outbound"
			case rec.RemoteIP == "":
				dir = "hosted"
			default:
				// Private-to-private flow with no explicit direction cannot safely
				// establish a hosted listener; skip rather than inventing one.
				continue
			}
		}

		if dir == "outbound" {
			dep := buildOutboundDependency(rec, transport)
			hp.OutboundDependencies = appendOutboundUnique(hp.OutboundDependencies, dep)
			continue
		}
		if dir != "hosted" && dir != "inbound" {
			continue
		}

		// Local hosted service record.
		proto := strings.ToLower(strings.TrimSpace(rec.Protocol))
		app := strings.ToLower(strings.TrimSpace(rec.Application))
		state := classifyPassiveServiceState(proto, app, rec.Source)
		labelProto := proto
		if app != "" {
			labelProto = app
		}
		if labelProto == "" {
			labelProto = "unknown"
		}

		// Do not duplicate an already-observed (transport, port) entry unless
		// enriching an unknown protocol with a typed protocol observation.
		updated := false
		for i := range hp.Services {
			curT := strings.ToLower(strings.TrimSpace(hp.Services[i].Transport))
			if curT == "" {
				curT = "tcp"
			}
			if hp.Services[i].Port == rec.Port && curT == transport {
				if hp.Services[i].Protocol == "" || hp.Services[i].Protocol == "unknown" {
					hp.Services[i].Protocol = labelProto
					hp.Services[i].State = state
				}
				updated = true
				break
			}
		}
		if !updated {
			hp.Services = append(hp.Services, Service{
				Port:          rec.Port,
				Transport:     transport,
				Protocol:      labelProto,
				State:         state,
				AddressFamily: ipFamilyOf(rec.LocalIP),
				Observer:      rec.Observer,
				ObservedAt:    rec.ObservedAt,
				TLS:           proto == "tls" || proto == "https" || proto == "quic" || proto == "dot",
			})
		}
	}

	for i := range profiles {
		sort.Slice(profiles[i].Services, func(a, b int) bool {
			if profiles[i].Services[a].Port != profiles[i].Services[b].Port {
				return profiles[i].Services[a].Port < profiles[i].Services[b].Port
			}
			return profiles[i].Services[a].Transport < profiles[i].Services[b].Transport
		})
	}
}

func classifyPassiveServiceState(proto, app, source string) string {
	if strings.EqualFold(source, "owner-config") || strings.EqualFold(source, "owner-manifest") {
		if app != "" || proto != "" {
			return ServiceStateOwnerDeclared
		}
	}
	if app != "" {
		return ServiceStateObservedProtocol
	}
	switch proto {
	case "", "unknown":
		return ServiceStateUnknown
	case "tls", "ssl", "dtls", "quic":
		// Explicitly preserve unknown application when evidence establishes only
		// TLS, DTLS, or QUIC transport encryption.
		return ServiceStateTLSUnknownApp
	default:
		return ServiceStateObservedProtocol
	}
}

func buildOutboundDependency(rec PassiveFlowRecord, transport string) OutboundDependency {
	proto := strings.ToLower(strings.TrimSpace(rec.Protocol))
	src := firstNonEmpty(rec.Source, "passive-flow")
	cat := strings.ToLower(strings.TrimSpace(rec.Category))
	attr := AttributionGatewayOrDNS
	svcName := rec.Application

	switch {
	case rec.SharedCDN:
		attr = AttributionHostingRangeOnly
		if cat == "" {
			cat = "shared-cdn"
		}
		if svcName == "" {
			svcName = "Shared CDN / Hosting (application unknown)"
		}
	case rec.ECHPresent || ((proto == "tls" || proto == "quic") && rec.RemoteHost == "" && svcName == ""):
		attr = AttributionOpaqueEncrypted
		if cat == "" {
			cat = "unknown-encrypted"
		}
		if svcName == "" {
			svcName = fmt.Sprintf("Encrypted %s endpoint (application unknown)", strings.ToUpper(firstNonEmpty(proto, transport)))
		}
	case strings.EqualFold(src, "device-config") || strings.EqualFold(src, "owner-config"):
		attr = AttributionConfiguredEgress
		if svcName == "" {
			svcName = firstNonEmpty(rec.RemoteHost, rec.RemoteIP, "Configured external service")
		}
	case strings.EqualFold(src, "vendor-feed"):
		attr = AttributionVendorFeed
		if svcName == "" {
			svcName = firstNonEmpty(rec.RemoteHost, "Vendor endpoint range")
		}
	default:
		if svcName == "" {
			if rec.RemoteHost != "" {
				svcName = rec.RemoteHost
			} else {
				attr = "unattributed-endpoint"
				svcName = "External endpoint (application unknown)"
			}
		}
	}

	if cat == "" {
		switch {
		case proto == "dns" || proto == "ntp" || proto == "dot" || proto == "doh":
			cat = "dns-time"
		case proto == "wireguard" || proto == "openvpn" || proto == "ikev2":
			cat = "vpn-tunnel"
		default:
			cat = "unknown"
		}
	}

	return OutboundDependency{
		Category:         cat,
		ServiceName:      svcName,
		DestinationHost:  rec.RemoteHost,
		DestinationIP:    rec.RemoteIP,
		Port:             rec.Port,
		Transport:        transport,
		AddressFamily:    ipFamilyOf(firstNonEmpty(rec.RemoteIP, rec.LocalIP)),
		AttributionLevel: attr,
		Source:           src,
		Observer:         rec.Observer,
		ObservedAt:       rec.ObservedAt,
	}
}

func appendOutboundUnique(existing []OutboundDependency, dep OutboundDependency) []OutboundDependency {
	for _, e := range existing {
		if e.DestinationIP == dep.DestinationIP && e.DestinationHost == dep.DestinationHost && e.Port == dep.Port && e.Transport == dep.Transport {
			return existing
		}
	}
	return append(existing, dep)
}

func isPrivateOrLocalIP(ipStr string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil {
		return false
	}
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast()
}

func ipFamilyOf(ipStr string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil {
		return ""
	}
	if addr.Is6() {
		return "ipv6"
	}
	return "ipv4"
}
