// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package risk

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/unifi"
)

// externalNamePattern infers physically exposed outdoor/perimeter switches or
// port drops when the operator has not explicitly pinned them in config.yaml.
var externalNamePattern = regexp.MustCompile(`(?i)\b(garage|outdoor|exterior|external|outside|garden|gate|gatehouse|shed|barn|driveway|patio|porch|terrace|yard|balcony|street|perimeter|intercom|doorbell|front\s*door|back\s*door|carport)\b`)

// cameraPeerPattern flags ports directly powering IP cameras or doorbells that
// are frequently mounted outside the physical building perimeter.
var cameraPeerPattern = regexp.MustCompile(`(?i)\b(cam|camera|doorbell|intercom|g3|g4|g5|protect|hikvision|dahua|reolink|axis)\b`)

// PortPeer represents a wired client or downstream UniFi device attached to one
// physical switch port.
type PortPeer struct {
	// Name is the display name of the connected host or downstream switch/AP.
	Name string `json:"name"`

	// MAC is the normalized lowercase hardware address.
	MAC string `json:"mac"`

	// IP is the connected host's IPv4 address, if known.
	IP string `json:"ip,omitempty"`

	// Kind distinguishes "client" from downstream UniFi "device".
	Kind string `json:"kind"`

	// VLAN is the client's resolved network name, if known.
	VLAN string `json:"vlan,omitempty"`
}

// SwitchPortView merges live link state, VLAN/MAC configuration, physical
// perimeter zoning, connected peers, and security status for one switch port.
type SwitchPortView struct {
	PortIdx          int        `json:"port_idx"`
	Name             string     `json:"name"`
	Label            string     `json:"label,omitempty"`
	Zone             string     `json:"zone"`        // "external", "external_uplink", "internal", "uplink", "wan", "unused"
	ZoneSource       string     `json:"zone_source"` // "config", "auto", "parent_link", "default"
	State            string     `json:"state"`       // "active", "inactive_enabled", "disabled"
	Enabled          bool       `json:"enabled"`
	Up               bool       `json:"up"`
	Speed            int        `json:"speed"`
	Media            string     `json:"media,omitempty"`
	PoEEnabled       bool       `json:"poe_enabled,omitempty"`
	PoEMode          string     `json:"poe_mode,omitempty"`
	PoEPower         string     `json:"poe_power,omitempty"`
	PoEPowerWatts    float64    `json:"poe_power_watts,omitempty"`
	NativeVLAN       string     `json:"native_vlan,omitempty"`
	TaggedPolicy     string     `json:"tagged_policy"` // "all", "block_all", "custom", "disabled"
	PortSecurity     bool       `json:"port_security"`
	PortSecurityMACs []string   `json:"port_security_macs,omitempty"`
	Isolation        bool       `json:"isolation,omitempty"`
	MACTableCount    int        `json:"mac_table_count,omitempty"`
	STPState         string     `json:"stp_state,omitempty"`
	RXErrors         int64      `json:"rx_errors,omitempty"`
	TXErrors         int64      `json:"tx_errors,omitempty"`
	Peers            []PortPeer `json:"peers,omitempty"`
	Status           string     `json:"status"` // "ok", "warn", "critical"
	Issues           []string   `json:"issues,omitempty"`
}

// SwitchDeviceView summarizes physical port allocation and perimeter security
// for one UniFi switch, gateway, or In-Wall AP.
type SwitchDeviceView struct {
	Name                 string           `json:"name"`
	MAC                  string           `json:"mac"`
	IP                   string           `json:"ip"`
	Model                string           `json:"model"`
	Type                 string           `json:"type"`
	ExternalDevice       bool             `json:"external_device"`
	ZoneSource           string           `json:"zone_source,omitempty"`
	UplinkName           string           `json:"uplink_name,omitempty"`
	UplinkPort           int              `json:"uplink_port,omitempty"`
	TotalPorts           int              `json:"total_ports"`
	ActivePorts          int              `json:"active_ports"`
	InactiveEnabledPorts int              `json:"inactive_enabled_ports"`
	DisabledPorts        int              `json:"disabled_ports"`
	ExternalPorts        int              `json:"external_ports"`
	AtRiskPorts          int              `json:"at_risk_ports"`
	Ports                []SwitchPortView `json:"ports"`
}

// AnalyzeSwitchPorts inspects every UniFi device's physical Ethernet/SFP ports,
// resolves explicit and auto-inferred physical perimeter zones (including
// tracing LLDP uplinks from external switches back to indoor parent feeder
// ports), maps connected peers, and emits high-signal physical-layer security
// findings and per-switch posture notes.
func AnalyzeSwitchPorts(
	snap *unifi.Snapshot,
	netCfg config.NetworkConfig,
	trustedSet, isolatedSet map[string]struct{},
) ([]SwitchDeviceView, []checks.Finding, []PostureNote) {
	if snap == nil || len(snap.Devices) == 0 {
		return nil, nil, nil
	}

	// Build explicit config lookup sets.
	extDevSet := make(map[string]struct{}, len(netCfg.ExternalDevices))
	for _, raw := range netCfg.ExternalDevices {
		if norm := strings.ToLower(strings.TrimSpace(raw)); norm != "" {
			extDevSet[norm] = struct{}{}
		}
	}
	portRuleByKey := make(map[string]config.PhysicalPortRule, len(netCfg.PhysicalPorts))
	for _, r := range netCfg.PhysicalPorts {
		key := fmt.Sprintf("%s|%d", strings.ToLower(strings.TrimSpace(r.Device)), r.Port)
		portRuleByKey[key] = r
	}

	// Index connected wired clients and downstream UniFi devices by (parentMAC, portIdx).
	peersByPort := make(map[string][]PortPeer)
	for _, cl := range snap.Clients {
		if cl.SwitchMAC == "" || cl.SwitchPort <= 0 {
			continue
		}
		k := fmt.Sprintf("%s|%d", strings.ToLower(cl.SwitchMAC), cl.SwitchPort)
		peersByPort[k] = append(peersByPort[k], PortPeer{
			Name: cl.DisplayName(),
			MAC:  strings.ToLower(cl.MAC),
			IP:   cl.IP,
			Kind: "client",
			VLAN: cl.NetworkName,
		})
	}
	devByMAC := make(map[string]unifi.Device, len(snap.Devices))
	for _, d := range snap.Devices {
		mac := strings.ToLower(d.MAC)
		devByMAC[mac] = d
		if d.UplinkMAC != "" && d.UplinkPort > 0 {
			k := fmt.Sprintf("%s|%d", strings.ToLower(d.UplinkMAC), d.UplinkPort)
			peersByPort[k] = append(peersByPort[k], PortPeer{
				Name: d.Name,
				MAC:  mac,
				IP:   d.IP,
				Kind: "device",
			})
		}
	}

	// First pass: determine which UniFi devices are physically external, and
	// trace their LLDP uplinks back to the indoor parent switch feeder ports!
	isExtDev := make(map[string]string) // devMAC -> zoneSource ("config" or "auto")
	extFeederPorts := make(map[string]string)
	for _, d := range snap.Devices {
		mac := strings.ToLower(d.MAC)
		if _, ok := extDevSet[mac]; ok {
			isExtDev[mac] = "config"
		} else if _, ok := extDevSet[strings.ToLower(d.Name)]; ok {
			isExtDev[mac] = "config"
		} else if externalNamePattern.MatchString(d.Name) {
			isExtDev[mac] = "auto"
		}
	}
	for _, d := range snap.Devices {
		mac := strings.ToLower(d.MAC)
		if _, ext := isExtDev[mac]; !ext {
			continue
		}
		if d.UplinkMAC != "" && d.UplinkPort > 0 {
			parentMAC := strings.ToLower(d.UplinkMAC)
			// Only mark the parent port as external_uplink if the parent itself is indoor.
			if _, parentExt := isExtDev[parentMAC]; !parentExt {
				extFeederPorts[fmt.Sprintf("%s|%d", parentMAC, d.UplinkPort)] = d.Name
			}
		}
	}

	var views []SwitchDeviceView
	var findings []checks.Finding
	var notes []PostureNote

	for _, dev := range snap.Devices {
		if len(dev.Ports) == 0 {
			continue
		}
		devMAC := strings.ToLower(dev.MAC)
		extSource, devExternal := isExtDev[devMAC]

		dv := SwitchDeviceView{
			Name:           dev.Name,
			MAC:            devMAC,
			IP:             dev.IP,
			Model:          dev.Model,
			Type:           dev.Type,
			ExternalDevice: devExternal,
			ZoneSource:     extSource,
			UplinkName:     dev.UplinkName,
			UplinkPort:     dev.UplinkPort,
			TotalPorts:     len(dev.Ports),
			Ports:          make([]SwitchPortView, 0, len(dev.Ports)),
		}

		var extUnusedPorts []int
		var indoorUnusedPorts []int
		var indoorTrunkAccessPorts []int

		for _, sp := range dev.Ports {
			portKey := fmt.Sprintf("%s|%d", devMAC, sp.PortIdx)
			peers := peersByPort[portKey]
			sort.Slice(peers, func(i, j int) bool { return peers[i].Name < peers[j].Name })

			// Look up any explicit physical_ports rule by MAC or device name.
			rule, hasRule := portRuleByKey[portKey]
			if !hasRule {
				rule, hasRule = portRuleByKey[fmt.Sprintf("%s|%d", strings.ToLower(dev.Name), sp.PortIdx)]
			}

			state := "inactive_enabled"
			if !sp.Enabled {
				state = "disabled"
				dv.DisabledPorts++
			} else if sp.Up {
				state = "active"
				dv.ActivePorts++
			} else {
				dv.InactiveEnabledPorts++
			}

			taggedPolicy := normalizeTaggedPolicy(sp)

			// Resolve physical zone with clear precedence:
			// 1. Explicit config physical_ports rule
			// 2. WAN interface
			// 3. Parent feeder cable to an external switch/AP (external_uplink)
			// 4. Whole device marked external (config or auto)
			// 5. Device uplink / downstream indoor UniFi device link
			// 6. Auto-inferred outdoor/camera port name or camera peer
			// 7. Default indoor/internal
			zone := "internal"
			zoneSrc := "default"
			label := ""
			if hasRule {
				zone = strings.ToLower(strings.TrimSpace(rule.Zone))
				zoneSrc = "config"
				label = rule.Label
			} else if sp.IsWAN {
				zone = "wan"
				zoneSrc = "auto"
			} else if extChild, isFeeder := extFeederPorts[portKey]; isFeeder {
				zone = "external_uplink"
				zoneSrc = "parent_link"
				label = "Feeds external " + extChild
			} else if devExternal {
				if sp.IsUplink {
					zone = "uplink"
					zoneSrc = extSource
					label = "External device uplink"
				} else {
					zone = "external"
					zoneSrc = extSource
				}
			} else if sp.IsUplink || hasUniFiDevicePeer(peers) {
				zone = "uplink"
				zoneSrc = "auto"
			} else if externalNamePattern.MatchString(sp.Name) || hasCameraPeer(peers) {
				zone = "external"
				zoneSrc = "auto"
			}

			if zone == "external" || zone == "external_uplink" {
				dv.ExternalPorts++
			}

			nativeIsTrusted := isNetworkInSet(sp.NativeNetworkName, trustedSet)
			nativeIsIsolated := isNetworkInSet(sp.NativeNetworkName, isolatedSet)
			isTrunkAll := taggedPolicy == "all"

			pv := SwitchPortView{
				PortIdx:          sp.PortIdx,
				Name:             sp.Name,
				Label:            label,
				Zone:             zone,
				ZoneSource:       zoneSrc,
				State:            state,
				Enabled:          sp.Enabled,
				Up:               sp.Up,
				Speed:            sp.Speed,
				Media:            sp.Media,
				PoEEnabled:       sp.PoEEnabled,
				PoEMode:          sp.PoEMode,
				PoEPower:         sp.PoEPower,
				PoEPowerWatts:    sp.PoEPowerWatts,
				NativeVLAN:       sp.NativeNetworkName,
				TaggedPolicy:     taggedPolicy,
				PortSecurity:     sp.PortSecurityEnabled,
				PortSecurityMACs: sp.PortSecurityMACs,
				Isolation:        sp.Isolation,
				MACTableCount:    sp.MACTableCount,
				STPState:         sp.STPState,
				RXErrors:         sp.RXErrors,
				TXErrors:         sp.TXErrors,
				Peers:            peers,
				Status:           "ok",
			}

			// Evaluate physical-layer security rules for this port.
			switch zone {
			case "external_uplink":
				if sp.Enabled && (isTrunkAll || nativeIsTrusted) {
					pv.Status = "critical"
					var problems []string
					if isTrunkAll {
						problems = append(problems, "Tagged VLANs = All (full trunk leaving building)")
					}
					if nativeIsTrusted {
						problems = append(problems, fmt.Sprintf("Native VLAN %q is Trusted/Internal", sp.NativeNetworkName))
					}
					pv.Issues = append(pv.Issues, problems...)
					dv.AtRiskPorts++
					findings = append(findings, checks.Finding{
						CheckID:           "UB-UNIFI-PORT-EXT-UPLINK",
						Title:             fmt.Sprintf("Unrestricted Feeder Cable to External Equipment (%s Port %d)", dev.Name, sp.PortIdx),
						Category:          "physical-port",
						BaseSeverity:      checks.SeverityCritical,
						EffectiveSeverity: checks.SeverityCritical,
						RiskReasons:       []string{fmt.Sprintf("indoor port feeds external device (%s)", label)},
						Client: unifi.Client{
							MAC:         devMAC,
							IP:          dev.IP,
							Name:        fmt.Sprintf("%s Port %d", dev.Name, sp.PortIdx),
							NetworkName: sp.NativeNetworkName,
						},
						Port:     sp.PortIdx,
						Evidence: fmt.Sprintf("%s Port %d (%s): %s; Port Security=%v", dev.Name, sp.PortIdx, label, strings.Join(problems, "; "), sp.PortSecurityEnabled),
						Remediation: checks.Remediation{
							Summary: fmt.Sprintf(
								"This indoor switch port feeds physical equipment outside the secured perimeter (%s). Unplugging the outdoor switch grants direct Ethernet access to everything forwarded on this cable. Restrict Tagged VLAN Management to Custom (or Block All) carrying ONLY isolated external VLANs, move Native VLAN off %q, and enable MAC restriction where supported.",
								label, sp.NativeNetworkName,
							),
							UniFiActions: []string{
								"restrict_tagged_vlans_on_external_uplink",
								"move_native_vlan_to_isolated",
								"enable_port_security_mac_restrict",
							},
						},
					})
				}

			case "external":
				if !sp.Enabled {
					// Properly disabled external port -> OK!
				} else if !sp.Up {
					// Unused port on external switch or external drop still enabled!
					pv.Status = "warn"
					pv.Issues = append(pv.Issues, "Unused external port is still administratively enabled")
					if isTrunkAll {
						pv.Issues = append(pv.Issues, "Carries All tagged VLANs")
					}
					dv.AtRiskPorts++
					extUnusedPorts = append(extUnusedPorts, sp.PortIdx)
				} else {
					// Active external port! Check VLAN isolation, trunking, and MAC lock.
					var problems []string
					if isTrunkAll {
						problems = append(problems, "Tagged VLANs = All (VLAN-hopping trunk)")
					}
					if nativeIsTrusted {
						problems = append(problems, fmt.Sprintf("Native VLAN %q is Trusted/Internal", sp.NativeNetworkName))
					}
					if !sp.PortSecurityEnabled {
						problems = append(problems, "MAC Port Security disabled")
					}
					if len(problems) > 0 {
						sev := checks.SeverityHigh
						pv.Status = "warn"
						if isTrunkAll || nativeIsTrusted {
							sev = checks.SeverityCritical
							pv.Status = "critical"
						}
						pv.Issues = append(pv.Issues, problems...)
						dv.AtRiskPorts++
						peerDesc := formatPeers(peers)
						findings = append(findings, checks.Finding{
							CheckID:           "UB-UNIFI-PORT-EXT-UNRESTRICTED",
							Title:             fmt.Sprintf("Unrestricted External Physical Port (%s Port %d)", dev.Name, sp.PortIdx),
							Category:          "physical-port",
							BaseSeverity:      sev,
							EffectiveSeverity: sev,
							RiskReasons:       []string{fmt.Sprintf("physical port classified as external (%s)", zoneSrc)},
							Client: unifi.Client{
								MAC:         devMAC,
								IP:          dev.IP,
								Name:        fmt.Sprintf("%s Port %d", dev.Name, sp.PortIdx),
								NetworkName: sp.NativeNetworkName,
							},
							Port:     sp.PortIdx,
							Evidence: fmt.Sprintf("%s Port %d (peer: %s): %s", dev.Name, sp.PortIdx, peerDesc, strings.Join(problems, "; ")),
							Remediation: checks.Remediation{
								Summary: "A cable extending outside the secured physical perimeter is plugged into an unrestricted port. Assign this port to an isolated VLAN, set Tagged VLAN Management to Block All, and enable MAC Address Restriction (Port Security) pinned to the authorized device MAC.",
								UniFiActions: []string{
									"assign_isolated_native_vlan",
									"set_tagged_vlan_mgmt_block_all",
									"enable_port_security_mac_restrict",
								},
							},
						})
					}
				}

			case "unused":
				if sp.Enabled {
					pv.Status = "warn"
					pv.Issues = append(pv.Issues, "Port marked unused in policy is still enabled")
					dv.AtRiskPorts++
					extUnusedPorts = append(extUnusedPorts, sp.PortIdx)
				}

			case "internal":
				if sp.Enabled && !sp.Up {
					indoorUnusedPorts = append(indoorUnusedPorts, sp.PortIdx)
					if isTrunkAll {
						pv.Issues = append(pv.Issues, "Inactive port left enabled with All VLANs")
					}
				} else if sp.Enabled && sp.Up {
					// Active client access port on an Isolated VLAN that still allows All tagged VLANs!
					if nativeIsIsolated && isTrunkAll {
						pv.Status = "critical"
						pv.Issues = append(pv.Issues, "Isolated-VLAN access port still allows All tagged VLANs (VLAN-hopping risk)")
						dv.AtRiskPorts++
						findings = append(findings, checks.Finding{
							CheckID:           "UB-UNIFI-PORT-VLAN-HOP",
							Title:             fmt.Sprintf("Isolated Access Port Allows All Tagged VLANs (%s Port %d)", dev.Name, sp.PortIdx),
							Category:          "physical-port",
							BaseSeverity:      checks.SeverityHigh,
							EffectiveSeverity: checks.SeverityHigh,
							Client: unifi.Client{
								MAC:         devMAC,
								IP:          dev.IP,
								Name:        fmt.Sprintf("%s Port %d", dev.Name, sp.PortIdx),
								NetworkName: sp.NativeNetworkName,
							},
							Port:     sp.PortIdx,
							Evidence: fmt.Sprintf("%s Port %d (peer: %s) has isolated Native VLAN %q but Tagged VLAN Management is still %q", dev.Name, sp.PortIdx, formatPeers(peers), sp.NativeNetworkName, taggedPolicy),
							Remediation: checks.Remediation{
								Summary: "Setting an isolated Native VLAN while leaving Tagged VLAN Management on Allow All lets a compromised host send 802.1Q tagged frames to reach Trusted/Internal VLANs. Set Tagged VLAN Management to Block All on this access port.",
								UniFiActions: []string{
									"set_tagged_vlan_mgmt_block_all",
								},
							},
						})
					} else if isTrunkAll && len(peers) > 0 {
						// Active indoor client port with default Allow All VLANs.
						pv.Status = "warn"
						pv.Issues = append(pv.Issues, "Access port carries All tagged VLANs (consider Block All)")
						indoorTrunkAccessPorts = append(indoorTrunkAccessPorts, sp.PortIdx)
					}
				}
			}

			// Detect inline hubs / rogue mini-switches / MITM taps on external access ports
			// (multiple MAC addresses learned behind a single exterior cable drop).
			if zone == "external" && sp.Enabled && sp.Up && (sp.MACTableCount > 1 || len(peers) > 1) {
				macCount := sp.MACTableCount
				if len(peers) > macCount {
					macCount = len(peers)
				}
				pv.Status = "critical"
				pv.Issues = append(pv.Issues, fmt.Sprintf("Multiple MACs (%d) detected on external access port (possible inline hub/tap)", macCount))
				dv.AtRiskPorts++
				findings = append(findings, checks.Finding{
					CheckID:           "UB-UNIFI-PORT-EXT-MULTI-MAC",
					Title:             fmt.Sprintf("Multiple MACs on External Access Port (%s Port %d)", dev.Name, sp.PortIdx),
					Category:          "physical-port",
					BaseSeverity:      checks.SeverityCritical,
					EffectiveSeverity: checks.SeverityCritical,
					Client: unifi.Client{
						MAC:         devMAC,
						IP:          dev.IP,
						Name:        fmt.Sprintf("%s Port %d", dev.Name, sp.PortIdx),
						NetworkName: sp.NativeNetworkName,
					},
					Port:     sp.PortIdx,
					Evidence: fmt.Sprintf("%s Port %d (zone=external) has %d learned MACs (%s); single-device exterior cable drop should only present 1 MAC", dev.Name, sp.PortIdx, macCount, formatPeers(peers)),
					Remediation: checks.Remediation{
						Summary: "An exterior single-device cable drop is presenting multiple MAC addresses, which can indicate an unauthorized mini-switch, travel router, or inline hardware tap. Inspect the physical run and enable MAC Port Security locked to the authorized device MAC.",
						UniFiActions: []string{
							"inspect_physical_cable_run",
							"enable_port_security_mac_restrict",
						},
					},
				})
			}

			// Detect Spanning Tree (STP) loop blocking or high frame error counters.
			if sp.Enabled && (sp.STPState == "discarding" || sp.STPState == "blocking") {
				if pv.Status != "critical" {
					pv.Status = "warn"
				}
				pv.Issues = append(pv.Issues, fmt.Sprintf("STP state=%s (L2 loop blocked)", sp.STPState))
				dv.AtRiskPorts++
				findings = append(findings, checks.Finding{
					CheckID:           "UB-UNIFI-PORT-STP-BLOCKED",
					Title:             fmt.Sprintf("Switch Port Blocked by Spanning Tree (%s Port %d)", dev.Name, sp.PortIdx),
					Category:          "physical-port",
					BaseSeverity:      checks.SeverityHigh,
					EffectiveSeverity: checks.SeverityHigh,
					Client: unifi.Client{
						MAC:         devMAC,
						IP:          dev.IP,
						Name:        fmt.Sprintf("%s Port %d", dev.Name, sp.PortIdx),
						NetworkName: sp.NativeNetworkName,
					},
					Port:     sp.PortIdx,
					Evidence: fmt.Sprintf("%s Port %d STP state is %q (transitions=%d, peer=%s)", dev.Name, sp.PortIdx, sp.STPState, sp.STPStateChanges, formatPeers(peers)),
					Remediation: checks.Remediation{
						Summary: "Spanning Tree Protocol blocked this port due to a detected Layer-2 loop or rogue bridge BPDU. Check connected cabling and downstream devices for accidental loops or unauthorized switches.",
						UniFiActions: []string{
							"inspect_l2_loop_and_stp",
						},
					},
				})
			}
			if sp.Enabled && sp.Up && (sp.RXErrors+sp.TXErrors) >= 1000 {
				if pv.Status == "ok" {
					pv.Status = "warn"
				}
				pv.Issues = append(pv.Issues, fmt.Sprintf("High port errors (rx=%d, tx=%d)", sp.RXErrors, sp.TXErrors))
				notes = append(notes, PostureNote{
					Severity: checks.SeverityLow,
					Title:    fmt.Sprintf("High Ethernet error counters on %s Port %d", dev.Name, sp.PortIdx),
					Detail:   fmt.Sprintf("Port #%d (%s) reports %d RX errors and %d TX errors. Inspect cable termination, duplex negotiation, or PoE noise.", sp.PortIdx, formatPeers(peers), sp.RXErrors, sp.TXErrors),
				})
			}

			// Enforce explicit allowed_macs policy if configured for this port.
			if hasRule && len(rule.AllowedMACs) > 0 && len(peers) > 0 {
				allowSet := make(map[string]struct{}, len(rule.AllowedMACs))
				for _, m := range rule.AllowedMACs {
					allowSet[strings.ToLower(strings.TrimSpace(m))] = struct{}{}
				}
				for _, peer := range peers {
					if _, ok := allowSet[peer.MAC]; !ok {
						pv.Status = "critical"
						pv.Issues = append(pv.Issues, fmt.Sprintf("Unauthorized MAC %s (%s)", peer.MAC, peer.Name))
						dv.AtRiskPorts++
						findings = append(findings, checks.Finding{
							CheckID:           "UB-UNIFI-PORT-UNAUTHORIZED-MAC",
							Title:             fmt.Sprintf("Unauthorized Device Connected to %s Port %d", dev.Name, sp.PortIdx),
							Category:          "physical-port",
							BaseSeverity:      checks.SeverityCritical,
							EffectiveSeverity: checks.SeverityCritical,
							Client: unifi.Client{
								MAC:         peer.MAC,
								IP:          peer.IP,
								Name:        peer.Name,
								NetworkName: sp.NativeNetworkName,
							},
							Port:     sp.PortIdx,
							Evidence: fmt.Sprintf("MAC %s (%s) connected on %s Port %d is not in configured allowed_macs %v", peer.MAC, peer.Name, dev.Name, sp.PortIdx, rule.AllowedMACs),
							Remediation: checks.Remediation{
								Summary: "An unexpected physical device is plugged into a restricted switch port. Verify the physical cable drop immediately and enforce UniFi Port Security MAC allowlisting.",
								UniFiActions: []string{
									"verify_physical_cable_drop",
									"enable_port_security_mac_restrict",
								},
							},
						})
					}
				}
			}

			dv.Ports = append(dv.Ports, pv)
		}

		// Emit one crisp aggregated HIGH finding per switch for unused enabled
		// external (or policy-unused) ports so operators get clean actionable signal.
		if len(extUnusedPorts) > 0 {
			findings = append(findings, checks.Finding{
				CheckID:           "UB-UNIFI-PORT-EXT-UNUSED-OPEN",
				Title:             fmt.Sprintf("Unused External Switch Ports Left Enabled (%s: %d port(s))", dev.Name, len(extUnusedPorts)),
				Category:          "physical-port",
				BaseSeverity:      checks.SeverityHigh,
				EffectiveSeverity: checks.SeverityHigh,
				Client: unifi.Client{
					MAC:  devMAC,
					IP:   dev.IP,
					Name: dev.Name,
				},
				Port:     extUnusedPorts[0],
				Evidence: fmt.Sprintf("%s has %d unused external/restricted port(s) still administratively enabled: %s", dev.Name, len(extUnusedPorts), formatPortList(extUnusedPorts)),
				Remediation: checks.Remediation{
					Summary: "Unused Ethernet ports on physically external switches (or wall drops) remain live and will grant immediate LAN access if someone plugs in a cable. Disable unused ports in UniFi Port Manager (Operation = Disabled).",
					UniFiActions: []string{
						"disable_unused_external_ports",
					},
				},
			})
		}

		// Summarize indoor unused-enabled and default-trunk access ports cleanly
		// in Posture Notes to keep Findings razor-focused while preserving visibility.
		if len(indoorUnusedPorts) > 0 {
			notes = append(notes, PostureNote{
				Severity: checks.SeverityLow,
				Title:    fmt.Sprintf("%s has %d unused indoor port(s) left enabled", dev.Name, len(indoorUnusedPorts)),
				Detail:   fmt.Sprintf("Ports %s have no link up but remain administratively enabled. Disable unused ports (especially on accessible In-Wall APs) in UniFi Port Manager.", formatPortList(indoorUnusedPorts)),
			})
		}
		if len(indoorTrunkAccessPorts) > 0 {
			notes = append(notes, PostureNote{
				Severity: checks.SeverityInfo,
				Title:    fmt.Sprintf("%s has %d active access port(s) carrying All tagged VLANs", dev.Name, len(indoorTrunkAccessPorts)),
				Detail:   fmt.Sprintf("Ports %s connect end-user/IoT clients with Tagged VLAN Management = All. Set non-uplink access ports to Block All to prevent 802.1Q VLAN hopping.", formatPortList(indoorTrunkAccessPorts)),
			})
		}

		views = append(views, dv)
	}

	sort.Slice(views, func(i, j int) bool {
		if views[i].ExternalDevice != views[j].ExternalDevice {
			return views[i].ExternalDevice
		}
		return views[i].Name < views[j].Name
	})
	return views, findings, notes
}

func normalizeTaggedPolicy(sp unifi.SwitchPort) string {
	if !sp.Enabled {
		return "disabled"
	}
	switch strings.ToLower(sp.TaggedVLANMgmt) {
	case "block_all":
		return "block_all"
	case "custom":
		return "custom"
	case "auto":
		if strings.EqualFold(sp.Forward, "native") {
			return "block_all"
		}
		return "all"
	default:
		switch strings.ToLower(sp.Forward) {
		case "native":
			return "block_all"
		case "customize":
			return "custom"
		case "disabled":
			return "disabled"
		default:
			return "all"
		}
	}
}

func hasUniFiDevicePeer(peers []PortPeer) bool {
	for _, p := range peers {
		if p.Kind == "device" {
			return true
		}
	}
	return false
}

func hasCameraPeer(peers []PortPeer) bool {
	for _, p := range peers {
		if cameraPeerPattern.MatchString(p.Name) {
			return true
		}
	}
	return false
}

func isNetworkInSet(name string, set map[string]struct{}) bool {
	if name == "" || len(set) == 0 {
		return false
	}
	_, ok := set[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

func formatPeers(peers []PortPeer) string {
	if len(peers) == 0 {
		return "unidentified active link"
	}
	parts := make([]string, 0, len(peers))
	for _, p := range peers {
		if p.IP != "" {
			parts = append(parts, fmt.Sprintf("%s (%s)", p.Name, p.IP))
		} else {
			parts = append(parts, p.Name)
		}
	}
	return strings.Join(parts, ", ")
}

func formatPortList(ports []int) string {
	sort.Ints(ports)
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, fmt.Sprintf("#%d", p))
	}
	return strings.Join(parts, ", ")
}
