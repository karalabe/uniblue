// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checks

import (
	"sort"
	"strings"

	"github.com/karalabe/uniblue/internal/unifi"
)

// PlanGlobalPorts computes the bounded baseline TCP port list to sweep across
// all eligible hosts. It intentionally excludes ports belonging to checks that
// are passive (`observe`), UDP-only (`snmp`, `coap`, `natpmp`), explicitly
// `discovery_only`, or gated by host identity / passive discovery
// (`mdns_type_any`, `upnp_*`, `ws_type_regex`, `mac_prefix`, `hostname_regex`),
// so adding hundreds of device-specific rules adds zero TCP dials on unrelated
// LAN hosts.
func PlanGlobalPorts(basePorts []int, list []*Check) []int {
	seen := make(map[int]struct{}, len(basePorts))
	merged := make([]int, 0, len(basePorts))
	add := func(p int) {
		if p < 1 || p > 65535 {
			return
		}
		if _, dup := seen[p]; !dup {
			seen[p] = struct{}{}
			merged = append(merged, p)
		}
	}
	for _, p := range basePorts {
		add(p)
	}

	for _, chk := range list {
		if !isGlobalBaselineCheck(chk) {
			continue
		}
		for _, p := range chk.Preconditions.PortsAny {
			add(p)
		}
		for _, p := range chk.Preconditions.PortsAll {
			add(p)
		}
	}
	sort.Ints(merged)
	return merged
}

// PlanHostPorts returns per-host specialty TCP port hints for checks gated by
// MAC prefix or hostname regex (e.g., Zehnder ComfoConnect port 56747 only on
// hosts matching 14:4f:d7 or a ventilation hostname), merging seamlessly with
// UniFi's own PortHintsByIP().
func PlanHostPorts(clients []unifi.Client, list []*Check, baseHints map[string][]int) map[string][]int {
	out := make(map[string][]int, len(baseHints))
	sets := make(map[string]map[int]struct{}, len(baseHints))
	add := func(ip string, p int) {
		if ip == "" || p < 1 || p > 65535 {
			return
		}
		if sets[ip] == nil {
			sets[ip] = make(map[int]struct{})
		}
		sets[ip][p] = struct{}{}
	}
	for ip, ports := range baseHints {
		for _, p := range ports {
			add(ip, p)
		}
	}

	for _, chk := range list {
		if isGlobalBaselineCheck(chk) || isNonTCPProbe(chk.Probe.Type) {
			continue
		}
		// Only schedule identity-gated checks (MAC prefix or hostname regex)
		// onto hosts that actually match that identity.
		if len(chk.Preconditions.MACPrefix) == 0 && chk.compiled.hostname == nil {
			continue
		}
		for _, cl := range clients {
			if cl.IP == "" {
				continue
			}
			if !matchesClientIdentity(chk, cl) {
				continue
			}
			for _, p := range chk.Preconditions.PortsAny {
				add(cl.IP, p)
			}
			for _, p := range chk.Preconditions.PortsAll {
				add(cl.IP, p)
			}
		}
	}

	for ip, s := range sets {
		ports := make([]int, 0, len(s))
		for p := range s {
			ports = append(ports, p)
		}
		sort.Ints(ports)
		out[ip] = ports
	}
	return out
}

func isGlobalBaselineCheck(chk *Check) bool {
	if chk == nil || chk.Preconditions.DiscoveryOnly {
		return false
	}
	if isNonTCPProbe(chk.Probe.Type) {
		return false
	}
	p := chk.Preconditions
	if len(p.MDNSTypeAny) > 0 || p.UPnPDeviceRegex != "" || p.UPnPServiceRegex != "" || p.WSTypeRegex != "" {
		return false
	}
	if len(p.MACPrefix) > 0 || p.HostnameRegex != "" {
		return false
	}
	return true
}

func isNonTCPProbe(probeType string) bool {
	switch strings.ToLower(probeType) {
	case "observe", "snmp", "coap", "natpmp":
		return true
	default:
		return false
	}
}

func matchesClientIdentity(chk *Check, cl unifi.Client) bool {
	if len(chk.Preconditions.MACPrefix) > 0 && cl.MAC != "" {
		macLower := strings.ToLower(cl.MAC)
		for _, pfx := range chk.Preconditions.MACPrefix {
			if strings.HasPrefix(macLower, strings.ToLower(strings.TrimSpace(pfx))) {
				return true
			}
		}
	}
	if chk.compiled.hostname != nil {
		if chk.compiled.hostname.MatchString(cl.Hostname) || chk.compiled.hostname.MatchString(cl.Name) {
			return true
		}
	}
	return false
}
