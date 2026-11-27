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
	"github.com/karalabe/uniblue/internal/unifi"
)

// isolatedSSIDPattern identifies SSID names whose operators almost certainly
// intend them to be segmented off the Trusted/Internal LAN.
var isolatedSSIDPattern = regexp.MustCompile(`(?i)\b(iot|guest|visitor|smart|camera|cam|things|untrusted|dmz|kids|external)\b`)

// bmcIdentityPattern identifies out-of-band server management consoles (BMCs)
// from their UniFi alias or hostname so UniBlue can flag shared-VLAN placement
// even before active IPMI/Redfish probing runs.
var bmcIdentityPattern = regexp.MustCompile(`(?i)(^|[-_.\s(])(ipmi|idrac|ilo[0-9]?|ikvm|bmc|asmb[0-9]?|megarac|mgmt[-_]?console|management\s+console|openbmc)($|[-_.\s)])`)

// oobVLANPattern matches dedicated out-of-band management VLAN names.
var oobVLANPattern = regexp.MustCompile(`(?i)\b(oob|mgmt|management|bmc|ipmi|idrac|ilo)\b`)

// UniFiPostureSummary packages site-wide UniFi controller security settings,
// Wi-Fi SSID inventory, neighboring AP counts, WAN/VPN health, and recent
// controller security/admin log highlights for JSON reports and the Web UI.
type UniFiPostureSummary struct {
	// Settings holds non-secret site-wide security controls (SSH, UPnP, IDS/IPS, Honeypot, DoH, Teleport).
	Settings *unifi.SiteSecuritySettings `json:"settings,omitempty"`

	// Health holds gateway WAN status, reported WAN IP, and active VPN session counts.
	Health *unifi.SystemHealth `json:"health,omitempty"`

	// WLANs lists configured Wi-Fi SSIDs and their encryption and isolation settings.
	WLANs []unifi.WLANConfig `json:"wlans,omitempty"`

	// NeighborAPs is the total count of neighboring/foreign BSSIDs observed in stat/rogueap.
	NeighborAPs int `json:"neighbor_aps"`

	// EvilTwinCount counts unique foreign BSSIDs advertising one of the site's enabled SSIDs.
	EvilTwinCount int `json:"evil_twin_count"`

	// RecentLogs holds recent security and admin activity events collected from the controller.
	RecentLogs []unifi.ControllerLogEvent `json:"recent_logs,omitempty"`
}

// AnalyzeUniFiPosture audits Wi-Fi security (WLAN configs + Evil-Twin/Rogue APs),
// UniFi device SSH, UPnP, IDS/IPS, Honeypot, DNS Shield, and recent controller
// security logs, emitting high-signal findings and clean posture notes.
func AnalyzeUniFiPosture(
	snap *unifi.Snapshot,
	trustedSet, isolatedSet map[string]struct{},
	mgmtVLANs ...string,
) (*UniFiPostureSummary, []checks.Finding, []PostureNote) {
	if snap == nil {
		return nil, nil, nil
	}

	summary := &UniFiPostureSummary{
		Settings:    snap.SecuritySettings,
		Health:      snap.Health,
		WLANs:       snap.WLANs,
		NeighborAPs: len(snap.RogueAPs),
		RecentLogs:  snap.RecentLogs,
	}

	var findings []checks.Finding
	var notes []PostureNote

	gw := primaryGatewayDevice(snap)

	// 1. Audit configured Wi-Fi SSIDs (encryption, PMF, L2 isolation, VLAN placement).
	enabledSSIDs := make(map[string]unifi.WLANConfig)
	var wpa2OnlySSIDs []string
	var noPMFSSIDs []string

	for _, w := range snap.WLANs {
		if !w.Enabled {
			continue
		}
		if w.Name != "" {
			enabledSSIDs[strings.ToLower(w.Name)] = w
		}

		wlanProp := "wlan:" + firstNonEmptyStr(w.ID, strings.ToLower(strings.TrimSpace(w.Name)))
		// Open or legacy WEP Wi-Fi network.
		if w.Security == "open" || w.Security == "wep" || w.Security == "" {
			sev := checks.SeverityCritical
			if w.IsGuest {
				sev = checks.SeverityHigh
			}
			findings = append(findings, checks.Finding{
				CheckID:           "UB-UNIFI-WIFI-OPEN",
				Title:             fmt.Sprintf("Unencrypted or Weak Wi-Fi Network (%s)", w.Name),
				Category:          "wifi-security",
				Property:          wlanProp,
				BaseSeverity:      sev,
				EffectiveSeverity: sev,
				Client: unifi.Client{
					MAC:         gw.MAC,
					IP:          gw.IP,
					Name:        "Wi-Fi: " + w.Name,
					NetworkName: w.NetworkName,
				},
				Evidence: fmt.Sprintf("SSID %q is enabled with security=%q on network %q (is_guest=%v)", w.Name, w.Security, w.NetworkName, w.IsGuest),
				Remediation: checks.Remediation{
					Summary: "Enable WPA2/WPA3 encryption on this SSID. Open or WEP wireless networks allow passive sniffing and unauthorized LAN access.",
					UniFiActions: []string{
						"enable_wpa2_wpa3_on_ssid",
					},
				},
			})
		} else {
			if !w.WPA3Support && w.WPAMode != "wpa3" {
				wpa2OnlySSIDs = append(wpa2OnlySSIDs, w.Name)
			}
			if w.PMFMode == "disabled" || w.PMFMode == "" {
				noPMFSSIDs = append(noPMFSSIDs, w.Name)
			}
		}

		// Guest / IoT SSID accidentally mapped onto a Trusted/Internal VLAN.
		isIntendedIsolated := w.IsGuest || isolatedSSIDPattern.MatchString(w.Name)
		if isIntendedIsolated && isNetworkInSet(w.NetworkName, trustedSet) {
			findings = append(findings, checks.Finding{
				CheckID:           "UB-UNIFI-WIFI-IOT-ON-TRUSTED",
				Title:             fmt.Sprintf("Guest/IoT Wi-Fi SSID Mapped to Trusted VLAN (%s -> %s)", w.Name, w.NetworkName),
				Category:          "wifi-security",
				Property:          wlanProp,
				BaseSeverity:      checks.SeverityHigh,
				EffectiveSeverity: checks.SeverityHigh,
				Client: unifi.Client{
					MAC:         gw.MAC,
					IP:          gw.IP,
					Name:        "Wi-Fi: " + w.Name,
					NetworkName: w.NetworkName,
				},
				Evidence: fmt.Sprintf("SSID %q (is_guest=%v) is bridged directly onto trusted/internal VLAN %q", w.Name, w.IsGuest, w.NetworkName),
				Remediation: checks.Remediation{
					Summary: "Assign Guest and IoT SSIDs to an isolated VLAN with Zone-Based Firewall isolation rather than your primary Trusted LAN.",
					UniFiActions: []string{
						"reassign_ssid_to_isolated_vlan",
					},
				},
			})
		}

		// Guest or IoT SSID missing Layer-2 Client Device Isolation (also applies to
		// any SSID mapped onto an isolated VLAN even if the SSID name itself is generic).
		isOnIsolatedVLAN := isNetworkInSet(w.NetworkName, isolatedSet)
		if (isIntendedIsolated || isOnIsolatedVLAN) && !w.L2Isolation {
			findings = append(findings, checks.Finding{
				CheckID:           "UB-UNIFI-WIFI-NO-L2-ISOLATION",
				Title:             fmt.Sprintf("Guest/IoT Wi-Fi Missing Client Device Isolation (%s)", w.Name),
				Category:          "wifi-security",
				Property:          wlanProp,
				BaseSeverity:      checks.SeverityMedium,
				EffectiveSeverity: checks.SeverityMedium,
				Client: unifi.Client{
					MAC:         gw.MAC,
					IP:          gw.IP,
					Name:        "Wi-Fi: " + w.Name,
					NetworkName: w.NetworkName,
				},
				Evidence: fmt.Sprintf("SSID %q (network=%q, is_guest=%v) has l2_isolation=false, allowing wireless clients to talk directly peer-to-peer", w.Name, w.NetworkName, w.IsGuest),
				Remediation: checks.Remediation{
					Summary: "Enable Client Device Isolation on Guest and untrusted IoT SSIDs so a compromised device cannot laterally scan other wireless clients.",
					UniFiActions: []string{
						"enable_wifi_client_isolation",
					},
				},
			})
		}
	}

	if len(wpa2OnlySSIDs) > 0 {
		sort.Strings(wpa2OnlySSIDs)
		notes = append(notes, PostureNote{
			Severity: checks.SeverityInfo,
			Title:    fmt.Sprintf("Wi-Fi SSID(s) running WPA2-only without WPA3 transition (%s)", strings.Join(wpa2OnlySSIDs, ", ")),
			Detail:   "Enabling WPA2/WPA3 Transition Mode with PMF=Optional hardens modern phones and laptops against offline handshake cracking while keeping legacy IoT compatible.",
		})
	} else if len(noPMFSSIDs) > 0 {
		sort.Strings(noPMFSSIDs)
		notes = append(notes, PostureNote{
			Severity: checks.SeverityInfo,
			Title:    fmt.Sprintf("Wi-Fi SSID(s) have Protected Management Frames (PMF) disabled (%s)", strings.Join(noPMFSSIDs, ", ")),
			Detail:   "Setting PMF to Optional or Required protects wireless clients against forged deauthentication floods.",
		})
	}

	// 2. Detect Evil-Twin SSID spoofing & Unauthorized APs plugged into our wired LAN.
	wiredClientsByPrefix := make(map[string]unifi.Client)
	for _, cl := range snap.Clients {
		if cl.IsWired && cl.MAC != "" {
			wiredClientsByPrefix[macStem(cl.MAC)] = cl
		}
	}

	seenEvil := make(map[string]struct{})
	seenRogueWired := make(map[string]struct{})
	for _, rap := range snap.RogueAPs {
		// Pass nil for knownOwnedVAPBSSIDs: stat/rogueap already excludes owned
		// radios and evil twins frequently spoof adopted AP BSSIDs, so never
		// suppress entries heuristically.
		if rap.BSSID == "" || isOwnedUniFiRadio(rap, nil) {
			continue
		}
		essidLower := strings.ToLower(strings.TrimSpace(rap.ESSID))
		if _, matchesOurs := enabledSSIDs[essidLower]; matchesOurs && essidLower != "" {
			if _, dup := seenEvil[rap.BSSID]; !dup {
				seenEvil[rap.BSSID] = struct{}{}
				summary.EvilTwinCount++
				findings = append(findings, checks.Finding{
					CheckID:           "UB-UNIFI-WIFI-EVIL-TWIN",
					Title:             fmt.Sprintf("Possible Evil-Twin Wi-Fi AP Broadcasting %q (%s)", rap.ESSID, rap.BSSID),
					Category:          "wifi-security",
					BaseSeverity:      checks.SeverityCritical,
					EffectiveSeverity: checks.SeverityCritical,
					Client: unifi.Client{
						MAC:  rap.BSSID,
						Name: fmt.Sprintf("Rogue AP (%s)", rap.ESSID),
						OUI:  rap.OUI,
					},
					Evidence: fmt.Sprintf("Foreign BSSID %s (vendor=%q, ch=%d, rssi=%d dBm, security=%q) is advertising your SSID %q", rap.BSSID, rap.OUI, rap.Channel, rap.RSSI, rap.Security, rap.ESSID),
					Remediation: checks.Remediation{
						Summary: "An unmanaged wireless radio is broadcasting your exact SSID. Verify whether this is an unadopted extender/hotspot or a rogue Evil-Twin AP attempting credential capture.",
						UniFiActions: []string{
							"investigate_evil_twin_bssid",
						},
					},
				})
			}
		}

		// Check whether a foreign BSSID shares the same hardware MAC stem as a wired LAN client
		// (e.g., someone plugged an unauthorized consumer router/AP into an Ethernet jack).
		if wiredCl, ok := wiredClientsByPrefix[macStem(rap.BSSID)]; ok {
			wiredKey := strings.ToLower(strings.TrimSpace(wiredCl.MAC))
			if _, dup := seenRogueWired[wiredKey]; dup {
				continue
			}
			seenRogueWired[wiredKey] = struct{}{}
			findings = append(findings, checks.Finding{
				CheckID:           "UB-UNIFI-WIFI-ROGUE-WIRED-AP",
				Title:             fmt.Sprintf("Unauthorized Wireless AP Connected to Wired LAN (%s)", wiredCl.DisplayName()),
				Category:          "wifi-security",
				BaseSeverity:      checks.SeverityHigh,
				EffectiveSeverity: checks.SeverityHigh,
				Client:            wiredCl,
				Evidence:          fmt.Sprintf("Foreign BSSID %s (SSID=%q, ch=%d) shares hardware MAC stem with wired LAN host %s (%s)", rap.BSSID, rap.ESSID, rap.Channel, wiredCl.DisplayName(), wiredCl.MAC),
				Remediation: checks.Remediation{
					Summary: "A wired client on your LAN appears to be broadcasting an unmanaged Wi-Fi network, which can bypass UniFi Wi-Fi security and VLAN isolation. Verify and disable unauthorized Wi-Fi radios.",
					UniFiActions: []string{
						"inspect_unauthorized_wired_ap",
					},
				},
			})
		}
	}

	// 3. Audit UniFi Site/Gateway Security Controls (SSH, UPnP, IDS/IPS, Honeypot, DoH, Teleport).
	if s := snap.SecuritySettings; s != nil {
		if s.SSHEnabled && s.SSHPasswordAuthKnown && s.SSHPasswordAuth {
			sev := checks.SeverityHigh
			detail := "password authentication enabled"
			if s.SSHKeyCount == 0 {
				detail = "password authentication enabled with 0 SSH public keys configured"
			}
			findings = append(findings, checks.Finding{
				CheckID:           "UB-UNIFI-SSH-PASSWORD",
				Title:             "UniFi Device SSH Enabled with Password Authentication",
				Category:          "unifi-config",
				BaseSeverity:      sev,
				EffectiveSeverity: sev,
				Client: unifi.Client{
					MAC:  gw.MAC,
					IP:   gw.IP,
					Name: gw.Name,
				},
				Port:     22,
				Evidence: fmt.Sprintf("Site Device Authentication has x_ssh_enabled=true and x_ssh_auth_password_enabled=true (%s)", detail),
				Remediation: checks.Remediation{
					Summary: "Device SSH is enabled across all adopted UniFi switches and APs using a shared site password. Disable Device SSH in UniFi Settings -> System -> Advanced when not actively debugging, or switch strictly to SSH public-key authentication.",
					UniFiActions: []string{
						"disable_unifi_device_ssh_or_enforce_keys",
					},
				},
			})
		} else if s.SSHEnabled {
			mode := "auth mode unknown"
			if s.SSHPasswordAuthKnown {
				mode = "key-only"
			}
			notes = append(notes, PostureNote{
				Severity: checks.SeverityLow,
				Title:    fmt.Sprintf("UniFi Device SSH is enabled (%s, %d SSH key(s))", mode, s.SSHKeyCount),
				Detail:   "Disable Device SSH when not actively troubleshooting to minimize the management attack surface on switches and APs.",
			})
		}

		if s.UPnPEnabled {
			findings = append(findings, checks.Finding{
				CheckID:           "UB-UNIFI-UPNP-ENABLED",
				Title:             "Gateway UPnP Enabled (Silent Dynamic WAN Port Forwards Allowed)",
				Category:          "unifi-config",
				BaseSeverity:      checks.SeverityHigh,
				EffectiveSeverity: checks.SeverityHigh,
				Client: unifi.Client{
					MAC:  gw.MAC,
					IP:   gw.IP,
					Name: gw.Name,
				},
				Evidence: fmt.Sprintf("Gateway UPnP is enabled (upnp_enabled=true, nat_pmp=%v, secure_mode=%v)", s.UPnPNATPMPEnabled, s.UPnPSecureMode),
				Remediation: checks.Remediation{
					Summary: "UPnP allows any LAN or IoT device (or malware) to silently open inbound WAN port forwards without appearing in static UniFi port-forward rules. Disable UPnP and create explicit port forwards only where needed.",
					UniFiActions: []string{
						"disable_gateway_upnp",
					},
				},
			})
		}

		if s.IPSMode == "disabled" || s.IPSMode == "off" {
			notes = append(notes, PostureNote{
				Severity: checks.SeverityMedium,
				Title:    "UniFi Intrusion Detection/Prevention (IDS/IPS) is disabled",
				Detail:   "Enabling Intrusion Prevention (Suricata) on the gateway provides signature-based detection and blocking for malware C2, exploit attempts, and port scans.",
			})
		}
		if !s.HoneypotEnabled {
			notes = append(notes, PostureNote{
				Severity: checks.SeverityLow,
				Title:    "UniFi Internal Honeypot is disabled",
				Detail:   "Enabling UniFi's internal Honeypot IP on internal VLANs provides zero-false-positive alerts if a compromised host begins horizontal LAN port scanning.",
			})
		}
		if s.DoHState == "off" {
			notes = append(notes, PostureNote{
				Severity: checks.SeverityInfo,
				Title:    "UniFi DNS Shield (DNS-over-HTTPS) is disabled",
				Detail:   "Enabling DNS Shield encrypts upstream DNS queries leaving your gateway against ISP/upstream tampering and snooping.",
			})
		}
		if s.TeleportEnabled {
			notes = append(notes, PostureNote{
				Severity: checks.SeverityInfo,
				Title:    "UniFi Teleport VPN remote access is enabled",
				Detail:   "Periodically audit active Teleport invitations and monitor live VPN session events in `uniblue serve`.",
			})
		}
	}

	// 4. Summarize recent 24h IDS/IPS threat & admin highlights cleanly in Posture Notes.
	var threatCount, honeypotCount, adminCount int
	for _, ev := range snap.RecentLogs {
		switch {
		case strings.Contains(ev.Event, "HONEYPOT"):
			honeypotCount++
		case ev.Category == "SECURITY" || strings.Contains(ev.Event, "THREAT"):
			threatCount++
		case ev.Category == "ADMIN":
			adminCount++
		}
	}
	if honeypotCount > 0 {
		findings = append(findings, checks.Finding{
			CheckID:           "UB-UNIFI-HONEYPOT-HIT",
			Title:             fmt.Sprintf("UniFi Internal Honeypot Triggered (%d hit(s) in 24h)", honeypotCount),
			Category:          "intrusion",
			BaseSeverity:      checks.SeverityCritical,
			EffectiveSeverity: checks.SeverityCritical,
			Client: unifi.Client{
				MAC:  gw.MAC,
				IP:   gw.IP,
				Name: gw.Name,
			},
			Evidence: fmt.Sprintf("Gateway reported %d internal honeypot hit(s) in the last 24 hours (indicates active horizontal LAN scanning)", honeypotCount),
			Remediation: checks.Remediation{
				Summary: "Investigate the source IP in UniFi System Log immediately. Internal honeypot hits indicate an unexpected host scanning private LAN addresses.",
				UniFiActions: []string{
					"investigate_honeypot_source_ip",
				},
			},
		})
	}
	if threatCount > 0 {
		notes = append(notes, PostureNote{
			Severity: checks.SeverityInfo,
			Title:    fmt.Sprintf("Gateway IDS/IPS blocked %d intrusion attempt(s) in the last 24h", threatCount),
			Detail:   "Inspect individual source/destination IPs in the live event stream (`uniblue serve`) or UniFi Security Detections.",
		})
	}
	if adminCount > 0 {
		notes = append(notes, PostureNote{
			Severity: checks.SeverityInfo,
			Title:    fmt.Sprintf("%d UniFi admin console access event(s) in the last 24h", adminCount),
			Detail:   "Live admin logins and configuration edits are streamed in real time by `uniblue serve`.",
		})
	}

	// 5. Audit Out-of-Band Server Management Consoles (BMCs) placed on shared VLANs.
	for _, cl := range snap.Clients {
		if !bmcIdentityPattern.MatchString(cl.Name) && !bmcIdentityPattern.MatchString(cl.Hostname) {
			continue
		}
		if oobVLANPattern.MatchString(cl.NetworkName) ||
			containsFold(mgmtVLANs, cl.NetworkName) ||
			(cl.VLAN != "" && containsFold(mgmtVLANs, cl.VLAN)) {
			continue
		}
		findings = append(findings, checks.Finding{
			CheckID:           "UB-UNIFI-BMC-SHARED-VLAN",
			Title:             fmt.Sprintf("Server Management Console (BMC) on Shared VLAN (%s)", cl.DisplayName()),
			Category:          "oob-bmc",
			BaseSeverity:      checks.SeverityHigh,
			EffectiveSeverity: checks.SeverityHigh,
			RiskReasons:       []string{fmt.Sprintf("ring-(-3) bare-metal BMC shares VLAN %q with regular hosts", cl.NetworkName)},
			Client:            cl,
			Evidence:          fmt.Sprintf("Out-of-band server management interface %s (%s) is attached to shared network %q instead of an isolated OOB Management VLAN", cl.DisplayName(), cl.IP, cl.NetworkName),
			Remediation: checks.Remediation{
				Summary: "Server BMCs (IPMI/iDRAC/iLO/ASMB/MegaRAC) run long-lived embedded firmware with bare-metal power, BIOS, virtual-USB boot, and KVM control. Place BMCs on a dedicated, firewall-isolated Out-of-Band Management VLAN reachable only from administrator IPs/VPN, and audit BMC firmware updates.",
				UniFiActions: []string{
					"move_bmc_to_dedicated_oob_mgmt_vlan",
					"restrict_bmc_access_to_admin_ips",
					"update_bmc_firmware",
				},
			},
		})
	}

	return summary, findings, notes
}

// primaryGatewayDevice locates the site's primary UniFi gateway from
// snap.Devices, matching gateway types/models first, then a root device with
// no uplink, then the first listed device, and finally a placeholder record.
func primaryGatewayDevice(snap *unifi.Snapshot) unifi.Device {
	for _, d := range snap.Devices {
		t := strings.ToLower(d.Type)
		m := strings.ToLower(d.Model)
		if t == "udm" || t == "ugw" || t == "uxg" ||
			strings.Contains(m, "udm") || strings.Contains(m, "ugw") ||
			strings.Contains(m, "uxg") || strings.Contains(m, "ucg") {
			return d
		}
	}
	for _, d := range snap.Devices {
		if d.UplinkName == "" {
			return d
		}
	}
	if len(snap.Devices) > 0 {
		return snap.Devices[0]
	}
	return unifi.Device{Name: "UniFi Gateway"}
}

// isOwnedUniFiRadio reports whether a rogue-AP entry is known to belong to an
// authoritative owned VAP BSSID list. UniFi's stat/rogueap feed reports
// neighboring/unmanaged radios rather than the site's own adopted VAPs, and an
// evil twin routinely clones or near-clones an adopted AP's BSSID (exact MAC,
// locally-administered octet-0 flip, or last-octet tweak with Ubiquiti's OUI),
// even when is_rogue is false. Therefore, never suppress entries by MAC-prefix
// heuristics or base device MAC similarity; only an explicit, non-rogue exact
// match against an authoritative known VAP BSSID list may suppress an entry.
func isOwnedUniFiRadio(rap unifi.RogueAP, knownOwnedVAPBSSIDs []string) bool {
	if rap.IsRogue || len(knownOwnedVAPBSSIDs) == 0 {
		return false
	}
	bssid := strings.ToLower(strings.TrimSpace(rap.BSSID))
	if bssid == "" {
		return false
	}
	for _, known := range knownOwnedVAPBSSIDs {
		if strings.ToLower(strings.TrimSpace(known)) == bssid {
			return true
		}
	}
	return false
}

// macStem returns the middle/OUI+device prefix (first 5 octets) used to
// correlate a dual-interface device's wired MAC with its Wi-Fi radio BSSID.
func macStem(mac string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(mac)), ":")
	if len(parts) != 6 {
		return strings.ToLower(strings.TrimSpace(mac))
	}
	return strings.Join(parts[:5], ":")
}
