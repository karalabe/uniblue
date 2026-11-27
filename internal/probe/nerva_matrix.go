// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import (
	"fmt"
	"sort"
	"strings"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	// Ensure Nerva's plugin registry is initialized when auditing coverage.
	_ "github.com/praetorian-inc/nerva/pkg/scan"
)

// NervaPluginEntry describes one registered service recognizer in the pinned
// Nerva dependency along with whether UniBlue's active TCP adapter exercises it.
type NervaPluginEntry struct {
	// Name is the lowercase canonical recognizer name reported by Nerva.
	Name string `json:"name"`

	// Transports lists the registries ("tcp", "tls", "udp", "sctp") where this plugin is registered.
	Transports []string `json:"transports"`

	// ActiveTCPPath reports whether UniBlue's active TCP/TLS Nerva scan path can exercise this plugin.
	ActiveTCPPath bool `json:"active_tcp_path"`

	// PassiveNeeded reports that this plugin only supports non-TCP transports (UDP or SCTP) and relies on passive telemetry or dedicated probes.
	PassiveNeeded bool `json:"passive_needed"`
}

// ServiceCoverageReport makes service identification measurable per site/run,
// separating protocol-identified endpoints, advertised services, TLS-only
// unknown applications, candidate open ports, and unidentified endpoints across
// transport and address family.
type ServiceCoverageReport struct {
	// TotalObservedEndpoints is the count of locally hosted (transport, port, address family) endpoints deduplicated per host profile.
	TotalObservedEndpoints int `json:"total_observed_endpoints"`

	// ByState breaks down TotalObservedEndpoints by highest-ranked ServiceState.
	ByState map[string]int `json:"by_state"`

	// ByTransport breaks down TotalObservedEndpoints by transport ("tcp", "udp", "sctp").
	ByTransport map[string]int `json:"by_transport"`

	// ByAddressFamily breaks down TotalObservedEndpoints by address family ("ipv4", "ipv6", "dual").
	ByAddressFamily map[string]int `json:"by_address_family"`

	// ConnectOnlyPorts is the total count of open sink ports kept strictly connect-only (zero bytes written).
	ConnectOnlyPorts int `json:"connect_only_ports,omitempty"`

	// OutboundDependencies is the total count of external internet dependencies tracked separately from hosted services.
	OutboundDependencies int `json:"outbound_dependencies"`

	// PinnedNervaTotal is the total number of distinct service plugins compiled into the pinned Nerva dependency.
	PinnedNervaTotal int `json:"pinned_nerva_total"`

	// PinnedNervaTCPCapable is the number of compiled Nerva plugins reachable via TCP or TCP+TLS.
	PinnedNervaTCPCapable int `json:"pinned_nerva_tcp_capable"`

	// PinnedNervaUDPOnly is the number of compiled Nerva plugins supporting UDP (including UDP+SCTP) without TCP/TLS support.
	PinnedNervaUDPOnly int `json:"pinned_nerva_udp_only"`

	// PinnedNervaSCTPOnly is the number of compiled Nerva plugins registered only for SCTP.
	PinnedNervaSCTPOnly int `json:"pinned_nerva_sctp_only"`
}

// AuditPinnedNervaPlugins introspects the live Nerva plugin registry compiled
// into this UniBlue binary and reports every recognizer's transport eligibility.
func AuditPinnedNervaPlugins() []NervaPluginEntry {
	byName := make(map[string]map[string]bool)
	record := func(p plugins.Plugin, label string) {
		if p == nil {
			return
		}
		name := strings.ToLower(strings.TrimSpace(p.Name()))
		if name == "" {
			return
		}
		if byName[name] == nil {
			byName[name] = make(map[string]bool)
		}
		byName[name][label] = true
	}

	for _, p := range plugins.Plugins[plugins.TCP] {
		record(p, "tcp")
	}
	for _, p := range plugins.Plugins[plugins.TCPTLS] {
		record(p, "tls")
	}
	for _, p := range plugins.Plugins[plugins.UDP] {
		record(p, "udp")
	}
	for _, p := range plugins.Plugins[plugins.SCTP] {
		record(p, "sctp")
	}

	out := make([]NervaPluginEntry, 0, len(byName))
	for name, tset := range byName {
		var transports []string
		for _, t := range []string{"tcp", "tls", "udp", "sctp"} {
			if tset[t] {
				transports = append(transports, t)
			}
		}
		tcpCapable := tset["tcp"] || tset["tls"]
		out = append(out, NervaPluginEntry{
			Name:          name,
			Transports:    transports,
			ActiveTCPPath: tcpCapable,
			PassiveNeeded: !tcpCapable,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ComputeServiceCoverage computes exact, reproducible service identification
// metrics across all HostProfiles, keeping outbound dependencies strictly
// separate from locally hosted endpoints.
func ComputeServiceCoverage(profiles []HostProfile) ServiceCoverageReport {
	rep := ServiceCoverageReport{
		ByState:         make(map[string]int),
		ByTransport:     make(map[string]int),
		ByAddressFamily: make(map[string]int),
	}

	for _, entry := range AuditPinnedNervaPlugins() {
		rep.PinnedNervaTotal++
		if entry.ActiveTCPPath {
			rep.PinnedNervaTCPCapable++
		} else {
			hasUDP := false
			hasSCTP := false
			for _, t := range entry.Transports {
				if t == "udp" {
					hasUDP = true
				}
				if t == "sctp" {
					hasSCTP = true
				}
			}
			if hasUDP {
				rep.PinnedNervaUDPOnly++
			} else if hasSCTP {
				rep.PinnedNervaSCTPOnly++
			}
		}
	}

	// Rank states by evidence strength so protocol confirmation outranks owner
	// declarations, passive advertisements, TLS-only handshakes, and bare open ports.
	stateRank := func(s string) int {
		switch s {
		case ServiceStateObservedProtocol:
			return 6
		case ServiceStateOwnerDeclared:
			return 5
		case ServiceStateAdvertisedService:
			return 4
		case ServiceStateTLSUnknownApp:
			return 3
		case ServiceStateCandidatePort:
			return 2
		default:
			return 1
		}
	}

	for _, hp := range profiles {
		rep.ConnectOnlyPorts += len(hp.ConnectOnlyPorts)
		rep.OutboundDependencies += len(hp.OutboundDependencies)
		// Default to "ipv4" when a host profile has no parseable primary IP so
		// coverage buckets remain populated rather than keyed by an empty string.
		hostFamily := ipFamilyOf(hp.Client.PrimaryIP())
		if hostFamily == "" {
			hostFamily = "ipv4"
		}

		type endpointObs struct {
			transport string
			family    string
			state     string
		}
		bestByEndpoint := make(map[string]endpointObs)
		record := func(t string, port int, fam, state string) {
			if port <= 0 {
				return
			}
			if t == "" {
				t = "tcp"
			}
			if fam == "" {
				fam = hostFamily
			}
			key := fmt.Sprintf("%s:%d:%s", t, port, fam)
			if cur, exists := bestByEndpoint[key]; !exists || stateRank(state) > stateRank(cur.state) {
				bestByEndpoint[key] = endpointObs{transport: t, family: fam, state: state}
			}
		}

		for _, svc := range hp.Services {
			if svc.Port <= 0 {
				continue
			}
			t := strings.ToLower(strings.TrimSpace(svc.Transport))
			if t == "" {
				t = "tcp"
			}
			state := svc.State
			if state == "" {
				proto := strings.ToLower(strings.TrimSpace(svc.Protocol))
				switch proto {
				case "", "unknown":
					state = ServiceStateUnknown
				case "tls", "ssl", "dtls", "quic":
					state = ServiceStateTLSUnknownApp
				default:
					state = ServiceStateObservedProtocol
				}
			}
			record(t, svc.Port, firstNonEmpty(svc.AddressFamily, hostFamily), state)
		}

		// Advertised DNS-SD services (counted at advertised-service rank, above bare candidate-port).
		// Record under the host's probed address family rather than "dual" so
		// dual-stack hosts do not double-count the same advertised port.
		for _, md := range hp.MDNSServices {
			if md.Withdrawn || md.Port <= 0 {
				continue
			}
			t := firstNonEmpty(md.Transport, mdnsRealTransport(md.Type))
			fam := md.AddressFamily
			if fam == "" || fam == "dual" {
				fam = hostFamily
			}
			record(t, md.Port, fam, ServiceStateAdvertisedService)
		}

		// Open TCP ports with no higher-ranked protocol or advertisement remain candidate ports.
		for _, p := range hp.OpenPorts {
			record("tcp", p, hostFamily, ServiceStateCandidatePort)
		}

		for _, obs := range bestByEndpoint {
			rep.TotalObservedEndpoints++
			rep.ByState[obs.state]++
			rep.ByTransport[obs.transport]++
			rep.ByAddressFamily[obs.family]++
		}
	}
	return rep
}
