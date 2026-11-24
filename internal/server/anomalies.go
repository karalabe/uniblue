package server

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/karalabe/uniblue/internal/classify"
	"github.com/karalabe/uniblue/internal/unifi"
)

const (
	// dormantWakeupThreshold flags a historically known MAC that wakes up after
	// being absent for at least 30 days.
	dormantWakeupThreshold = 30 * 24 * time.Hour

	// iotUploadSpikeWindow and iotUploadSpikeBytes detect an idle embedded/IoT
	// appliance suddenly uploading >= 50 MB within a 5-minute window (possible
	// exfiltration or botnet participation) with a 30m per-host alert cooldown.
	iotUploadSpikeWindow   = 5 * time.Minute
	iotUploadSpikeBytes    = 50 << 20 // 50 MiB
	iotUploadAlertCooldown = 30 * time.Minute

	// poeBaselineMinWatts and poeDropMaxWatts detect a powered PoE device (such
	// as an exterior camera drawing ~6-10W) being unplugged and replaced by a
	// non-PoE host/laptop/implant (< 0.5W) even if the attacker clones its MAC.
	poeBaselineMinWatts = 2.0
	poeDropMaxWatts     = 0.5
)

// txSample records a rolling byte baseline for client upload-spike detection.
type txSample struct {
	Bytes     int64
	At        time.Time
	LastAlert time.Time
}

// anomalyTracker holds in-memory baselines across poll intervals to detect
// physical tampering, behavioral anomalies, Evil-Twin APs, VPN/WAN transitions,
// controller security logs, and security configuration drift.
type anomalyTracker struct {
	poeBaselineWatts map[string]float64 // devMAC|portIdx -> max observed PoE watts
	knownHistory     map[string]unifi.HistoricalClient
	clientTx         map[string]txSample // mac -> rolling tx baseline
	seenLogIDs       map[string]struct{} // deduplicates v2 system-log events
	seenEvilTwins    map[string]struct{} // bssid -> already alerted
	lastVPNKeys      map[string]unifi.VPNConnection
	lastVPNCount     int
	lastWANIP        string
	lastWANStatus    string
	lastSecuritySig  string
	initialized      bool
}

func newAnomalyTracker() *anomalyTracker {
	return &anomalyTracker{
		poeBaselineWatts: make(map[string]float64),
		knownHistory:     make(map[string]unifi.HistoricalClient),
		clientTx:         make(map[string]txSample),
		seenLogIDs:       make(map[string]struct{}),
		seenEvilTwins:    make(map[string]struct{}),
		lastVPNKeys:      make(map[string]unifi.VPNConnection),
	}
}

// Seed initializes baselines from the first UniFi snapshot without firing
// spurious alerts for pre-existing state.
func (a *anomalyTracker) Seed(snap *unifi.Snapshot, ports map[string]portLiveState, now time.Time) {
	if snap == nil {
		return
	}
	for pk, p := range ports {
		if p.PoEPowerWatts >= poeBaselineMinWatts {
			a.poeBaselineWatts[pk] = p.PoEPowerWatts
		}
	}
	for _, hc := range snap.KnownClients {
		a.knownHistory[hc.MAC] = hc
	}
	for _, cl := range snap.Clients {
		k := clientKey(cl)
		if cl.TxBytes > 0 {
			a.clientTx[k] = txSample{Bytes: cl.TxBytes, At: now}
		}
	}
	for _, ev := range snap.RecentLogs {
		a.seenLogIDs[ev.ID] = struct{}{}
	}
	if snap.Health != nil {
		a.lastWANIP = snap.Health.WANIP
		a.lastWANStatus = snap.Health.WANStatus
		a.lastVPNCount = snap.Health.ActiveVPNUsers
		a.lastVPNKeys = indexVPNConnections(snap.Health.VPNConnections)
	}
	a.lastSecuritySig = securityConfigSignature(snap.SecuritySettings, snap.WLANs)
	a.initialized = true
}

// EvaluatePortAnomalies inspects per-port transitions for physical-layer
// tampering (PoE draw drop / MAC-spoofed cable swap, inline hub MAC-table
// surge, and Spanning Tree loop blocking).
func (a *anomalyTracker) EvaluatePortAnomalies(prevPorts, currPorts map[string]portLiveState) []LiveEvent {
	var events []LiveEvent
	for pk, curr := range currPorts {
		prev, existed := prevPorts[pk]
		if curr.PoEPowerWatts >= poeBaselineMinWatts && curr.PoEPowerWatts > a.poeBaselineWatts[pk] {
			a.poeBaselineWatts[pk] = curr.PoEPowerWatts
		}
		if !existed {
			continue
		}

		isExternal := curr.Zone == "external" || curr.Zone == "external_uplink"
		isAccess := curr.Zone == "external" || curr.Zone == "internal"

		// 1. PoE cable-swap / tamper detection:
		// A port that previously powered a PoE device (>= 2W, e.g., outdoor camera)
		// is now link UP while drawing < 0.5W (e.g., laptop/implant plugged into the
		// camera cable, potentially spoofing the camera's MAC address!).
		baseW := a.poeBaselineWatts[pk]
		wasDrawingPoE := prev.PoEPowerWatts >= poeBaselineMinWatts || (!prev.Up && curr.Up && baseW >= poeBaselineMinWatts)
		if curr.Up && baseW >= poeBaselineMinWatts && curr.PoEPowerWatts <= poeDropMaxWatts && wasDrawingPoE {
			sev := "high"
			if isExternal {
				sev = "critical"
			}
			events = append(events, LiveEvent{
				Type:     "port_poe_tamper",
				Severity: sev,
				Host:     fmt.Sprintf("%s Port %d", curr.DeviceName, curr.PortIdx),
				IP:       curr.DeviceIP,
				Summary: fmt.Sprintf("Possible physical cable swap on %s Port %d (zone=%s): link is UP with %.2fW PoE draw (baseline %.2fW — PoE device replaced by non-PoE host?)",
					curr.DeviceName, curr.PortIdx, curr.Zone, curr.PoEPowerWatts, baseW),
			})
		}

		// 2. Inline hub / rogue mini-switch detection (MAC table surge):
		// Non-uplink access port jumped from <= 1 learned MAC to >= 2 MACs.
		if isAccess && curr.Up && prev.MACTableCount <= 1 && curr.MACTableCount >= 2 {
			sev := "high"
			if isExternal {
				sev = "critical"
			}
			events = append(events, LiveEvent{
				Type:     "port_mac_surge",
				Severity: sev,
				Host:     fmt.Sprintf("%s Port %d", curr.DeviceName, curr.PortIdx),
				IP:       curr.DeviceIP,
				Summary: fmt.Sprintf("MAC table jumped %d -> %d on %s Port %d (zone=%s): possible unauthorized mini-switch, travel router, or inline tap",
					prev.MACTableCount, curr.MACTableCount, curr.DeviceName, curr.PortIdx, curr.Zone),
			})
		}

		// 3. Spanning Tree (STP) loop blocking transition.
		if (curr.STPState == "discarding" || curr.STPState == "blocking") && prev.STPState != curr.STPState {
			events = append(events, LiveEvent{
				Type:     "port_stp_blocked",
				Severity: "high",
				Host:     fmt.Sprintf("%s Port %d", curr.DeviceName, curr.PortIdx),
				IP:       curr.DeviceIP,
				Summary:  fmt.Sprintf("STP blocked %s Port %d (state=%s) — Layer-2 loop or rogue BPDU detected", curr.DeviceName, curr.PortIdx, curr.STPState),
			})
		}
	}
	return events
}

// EvaluateClientJoinAnomalies checks newly joined clients against UniFi's
// historical /rest/user records for dormant-device wakeups (>30d offline) and
// unexpected wired <-> Wi-Fi medium swaps.
func (a *anomalyTracker) EvaluateClientJoinAnomalies(cl unifi.Client, now time.Time) []LiveEvent {
	var events []LiveEvent
	hc, known := a.knownHistory[clientKey(cl)]
	if !known {
		return nil
	}

	if hc.LastSeen > 0 {
		lastTime := time.Unix(hc.LastSeen, 0).UTC()
		if gap := now.Sub(lastTime); gap >= dormantWakeupThreshold {
			days := int(gap.Hours() / 24)
			events = append(events, LiveEvent{
				Type:     "client_dormant_wakeup",
				Severity: "medium",
				Host:     cl.DisplayName(),
				IP:       cl.IP,
				Summary:  fmt.Sprintf("Dormant device %s (%s) woke up after %d day(s) offline on %s", cl.DisplayName(), cl.MAC, days, fallbackVLAN(cl.NetworkName)),
			})
		}
	}

	if hc.IsWired != cl.IsWired {
		prevMed, currMed := "Wi-Fi", "Wired"
		if hc.IsWired {
			prevMed, currMed = "Wired", "Wi-Fi"
		}
		events = append(events, LiveEvent{
			Type:     "client_medium_swap",
			Severity: "high",
			Host:     cl.DisplayName(),
			IP:       cl.IP,
			Summary:  fmt.Sprintf("Connection medium changed for %s (%s): historically %s, now %s on %s", cl.DisplayName(), cl.MAC, prevMed, currMed, fallbackVLAN(cl.NetworkName)),
		})
	}
	return events
}

// EvaluateIoTUploadSpikes detects sudden high-volume outbound traffic from
// embedded/IoT appliances (cameras, HVAC, printers, smart-home, media devices).
func (a *anomalyTracker) EvaluateIoTUploadSpikes(clients []unifi.Client, classes map[string]classify.Result, now time.Time) []LiveEvent {
	var events []LiveEvent
	for _, cl := range clients {
		if cl.TxBytes <= 0 {
			continue
		}
		k := clientKey(cl)
		sample, exists := a.clientTx[k]
		if !exists || cl.TxBytes < sample.Bytes {
			// New client or counter reset on reconnect.
			a.clientTx[k] = txSample{Bytes: cl.TxBytes, At: now, LastAlert: sample.LastAlert}
			continue
		}

		// Only evaluate upload spikes on embedded / IoT appliance categories
		// (skip servers, NAS, workstations, phones that legitimately upload bulk data).
		clsKey := cl.IP
		if clsKey == "" {
			clsKey = cl.MAC
		}
		cat := strings.ToLower(string(classes[clsKey].Category))
		if !isApplianceCategory(cat) {
			if now.Sub(sample.At) >= iotUploadSpikeWindow {
				sample.Bytes = cl.TxBytes
				sample.At = now
				a.clientTx[k] = sample
			}
			continue
		}

		delta := cl.TxBytes - sample.Bytes
		elapsed := now.Sub(sample.At)
		if delta >= iotUploadSpikeBytes && elapsed <= iotUploadSpikeWindow {
			if sample.LastAlert.IsZero() || now.Sub(sample.LastAlert) >= iotUploadAlertCooldown {
				mb := float64(delta) / (1024 * 1024)
				events = append(events, LiveEvent{
					Type:     "iot_upload_spike",
					Severity: "high",
					Host:     cl.DisplayName(),
					IP:       cl.IP,
					Summary:  fmt.Sprintf("IoT upload spike on %s (%s, %s): uploaded %.1f MB in %s", cl.DisplayName(), cl.IP, cat, mb, elapsed.Round(time.Second)),
				})
				sample.LastAlert = now
			}
			sample.Bytes = cl.TxBytes
			sample.At = now
			a.clientTx[k] = sample
		} else if elapsed >= iotUploadSpikeWindow {
			sample.Bytes = cl.TxBytes
			sample.At = now
			a.clientTx[k] = sample
		}
	}
	return events
}

// EvaluateSiteTelemetry detects new UniFi v2 system-log security/admin events,
// new Evil-Twin APs, VPN connect/disconnect sessions, WAN IP/status changes,
// and controller security/Wi-Fi config drift.
func (a *anomalyTracker) EvaluateSiteTelemetry(snap *unifi.Snapshot, freshLogs []unifi.ControllerLogEvent) []LiveEvent {
	if snap == nil {
		return nil
	}
	var events []LiveEvent

	// 1. Stream newly arrived UniFi System Log events (IDS/IPS, Honeypot, Admin logins, DHCP/Loops).
	for _, ev := range freshLogs {
		if ev.ID == "" {
			continue
		}
		if _, seen := a.seenLogIDs[ev.ID]; seen {
			continue
		}
		a.seenLogIDs[ev.ID] = struct{}{}
		evType := "controller_security"
		switch {
		case ev.Category == "ADMIN":
			evType = "admin_activity"
		case strings.Contains(ev.Event, "HONEYPOT"):
			evType = "honeypot_hit"
		case ev.Category == "SECURITY" || strings.Contains(ev.Event, "THREAT"):
			evType = "ids_threat"
		case strings.Contains(ev.Event, "DHCP") || strings.Contains(ev.Event, "LOOP"):
			evType = "network_alert"
		}
		events = append(events, LiveEvent{
			Type:     evType,
			Severity: ev.Severity,
			Host:     firstStr(ev.Device, ev.Admin, ev.SrcIP),
			IP:       ev.SrcIP,
			Summary:  ev.Message,
		})
	}
	// Cap seenLogIDs map size gently.
	if len(a.seenLogIDs) > 2000 {
		a.seenLogIDs = make(map[string]struct{}, len(freshLogs))
		for _, ev := range freshLogs {
			a.seenLogIDs[ev.ID] = struct{}{}
		}
	}

	// 2. Detect new Evil-Twin APs broadcasting one of our site's SSIDs.
	ourSSIDs := make(map[string]struct{}, len(snap.WLANs))
	for _, w := range snap.WLANs {
		if w.Enabled && w.Name != "" {
			ourSSIDs[strings.ToLower(w.Name)] = struct{}{}
		}
	}
	ownedMACs := make(map[string]struct{}, len(snap.Devices))
	for _, d := range snap.Devices {
		if d.MAC != "" {
			ownedMACs[strings.ToLower(d.MAC)] = struct{}{}
		}
	}
	for _, rap := range snap.RogueAPs {
		if rap.BSSID == "" || rap.ESSID == "" {
			continue
		}
		if _, match := ourSSIDs[strings.ToLower(rap.ESSID)]; !match {
			continue
		}
		if isOwnedRadioBSSID(rap.BSSID, ownedMACs) {
			continue
		}
		if _, alerted := a.seenEvilTwins[rap.BSSID]; !alerted {
			a.seenEvilTwins[rap.BSSID] = struct{}{}
			events = append(events, LiveEvent{
				Type:     "wifi_evil_twin",
				Severity: "critical",
				Host:     rap.BSSID,
				Summary:  fmt.Sprintf("Evil-Twin Wi-Fi AP detected: foreign BSSID %s (%s) broadcasting your SSID %q (ch %d, %d dBm)", rap.BSSID, rap.OUI, rap.ESSID, rap.Channel, rap.RSSI),
			})
		}
	}

	// 3. Detect WAN failover / public IP rotation and live VPN session connect/disconnect.
	if snap.Health != nil {
		if a.lastWANIP != "" && snap.Health.WANIP != "" && snap.Health.WANIP != a.lastWANIP {
			events = append(events, LiveEvent{
				Type:     "wan_ip_changed",
				Severity: "high",
				Summary:  fmt.Sprintf("Gateway public WAN IP changed (%s -> %s)", a.lastWANIP, snap.Health.WANIP),
			})
		}
		if a.lastWANStatus != "" && snap.Health.WANStatus != "" && snap.Health.WANStatus != a.lastWANStatus {
			sev := "info"
			if !strings.EqualFold(snap.Health.WANStatus, "ok") {
				sev = "high"
			}
			events = append(events, LiveEvent{
				Type:     "wan_status_changed",
				Severity: sev,
				Summary:  fmt.Sprintf("Gateway WAN health changed (%s -> %s)", a.lastWANStatus, snap.Health.WANStatus),
			})
		}
		if snap.Health.WANIP != "" {
			a.lastWANIP = snap.Health.WANIP
		}
		if snap.Health.WANStatus != "" {
			a.lastWANStatus = snap.Health.WANStatus
		}

		currVPN := indexVPNConnections(snap.Health.VPNConnections)
		for k, vc := range currVPN {
			if _, existed := a.lastVPNKeys[k]; !existed {
				events = append(events, LiveEvent{
					Type:     "vpn_connected",
					Severity: "medium",
					Host:     firstStr(vc.User, vc.Name, vc.LocalIP),
					IP:       vc.RemoteIP,
					Summary:  fmt.Sprintf("Remote VPN peer connected: %s (%s, remote=%s, local=%s)", firstStr(vc.User, vc.Name, "VPN user"), vc.Type, vc.RemoteIP, vc.LocalIP),
				})
			}
		}
		for k, vc := range a.lastVPNKeys {
			if _, still := currVPN[k]; !still {
				events = append(events, LiveEvent{
					Type:     "vpn_disconnected",
					Severity: "info",
					Host:     firstStr(vc.User, vc.Name, vc.LocalIP),
					IP:       vc.RemoteIP,
					Summary:  fmt.Sprintf("Remote VPN peer disconnected: %s (%s)", firstStr(vc.User, vc.Name, "VPN user"), vc.Type),
				})
			}
		}
		// Fallback counter alert when UniFi reports remote_user_num_active without per-connection details.
		if len(currVPN) == 0 && len(a.lastVPNKeys) == 0 && snap.Health.ActiveVPNUsers != a.lastVPNCount {
			sev := "info"
			verb := "disconnected"
			if snap.Health.ActiveVPNUsers > a.lastVPNCount {
				sev = "medium"
				verb = "connected"
			}
			events = append(events, LiveEvent{
				Type:     "vpn_session_changed",
				Severity: sev,
				Summary:  fmt.Sprintf("Active remote VPN users %s (%d -> %d)", verb, a.lastVPNCount, snap.Health.ActiveVPNUsers),
			})
		}
		a.lastVPNKeys = currVPN
		a.lastVPNCount = snap.Health.ActiveVPNUsers
	}

	// 4. Detect controller security setting or Wi-Fi SSID configuration drift.
	secSig := securityConfigSignature(snap.SecuritySettings, snap.WLANs)
	if a.lastSecuritySig != "" && secSig != "" && secSig != a.lastSecuritySig {
		events = append(events, LiveEvent{
			Type:     "config_drift",
			Severity: "high",
			Summary:  "UniFi site security settings or Wi-Fi SSID configuration changed — re-auditing posture",
		})
	}
	if secSig != "" {
		a.lastSecuritySig = secSig
	}

	// Refresh knownHistory map softly for future joins.
	for _, hc := range snap.KnownClients {
		if _, exists := a.knownHistory[hc.MAC]; !exists {
			a.knownHistory[hc.MAC] = hc
		}
	}

	return events
}

func indexVPNConnections(list []unifi.VPNConnection) map[string]unifi.VPNConnection {
	out := make(map[string]unifi.VPNConnection, len(list))
	for _, vc := range list {
		key := firstStr(vc.ID, fmt.Sprintf("%s|%s|%s", vc.User, vc.RemoteIP, vc.LocalIP))
		if key != "" {
			out[key] = vc
		}
	}
	return out
}

func securityConfigSignature(s *unifi.SiteSecuritySettings, wlans []unifi.WLANConfig) string {
	var parts []string
	if s != nil {
		parts = append(parts, fmt.Sprintf("sec:%v|%v|%d|%v|%v|%s|%v|%s|%v",
			s.SSHEnabled, s.SSHPasswordAuth, s.SSHKeyCount,
			s.UPnPEnabled, s.UPnPNATPMPEnabled, s.IPSMode,
			s.HoneypotEnabled, s.DoHState, s.TeleportEnabled))
	}
	for _, w := range wlans {
		parts = append(parts, fmt.Sprintf("wlan:%s|%v|%s|%s|%v|%s|%v|%v|%s",
			w.Name, w.Enabled, w.Security, w.WPAMode, w.WPA3Support, w.PMFMode, w.L2Isolation, w.IsGuest, w.NetworkName))
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
}

func isApplianceCategory(cat string) bool {
	switch cat {
	case "iot", "camera", "printer", "hvac", "smart-home", "media", "appliance", "sensor", "audio", "tv":
		return true
	default:
		return false
	}
}

func isOwnedRadioBSSID(bssid string, ownedMACs map[string]struct{}) bool {
	bParts := strings.Split(strings.ToLower(bssid), ":")
	if len(bParts) != 6 {
		return false
	}
	for om := range ownedMACs {
		if om == bssid {
			return true
		}
		oParts := strings.Split(om, ":")
		if len(oParts) == 6 && bParts[1] == oParts[1] && bParts[2] == oParts[2] && bParts[3] == oParts[3] && bParts[4] == oParts[4] {
			return true
		}
	}
	return false
}

func firstStr(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
