// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package unifi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// rawWLAN maps /api/s/<site>/rest/wlanconf entries.
type rawWLAN struct {
	ID            string `json:"_id"`
	Name          string `json:"name"`
	Enabled       bool   `json:"enabled"`
	Security      string `json:"security"`
	WPAMode       string `json:"wpa_mode"`
	WPA3Support   bool   `json:"wpa3_support"`
	PMFMode       string `json:"pmf_mode"`
	L2Isolation   bool   `json:"l2_isolation"`
	IsGuest       bool   `json:"is_guest"`
	NetworkConfID string `json:"networkconf_id"`
}

// rawRogueAP maps /api/s/<site>/stat/rogueap entries.
type rawRogueAP struct {
	BSSID    string `json:"bssid"`
	ESSID    string `json:"essid"`
	APMAC    string `json:"ap_mac"`
	Channel  int    `json:"channel"`
	Band     string `json:"band"`
	Security string `json:"security"`
	OUI      string `json:"oui"`
	RSSI     int    `json:"rssi"`
	IsRogue  bool   `json:"is_rogue"`
	IsUBNT   bool   `json:"is_ubnt"`
	IsAdhoc  bool   `json:"is_adhoc"`
	LastSeen int64  `json:"last_seen"`
}

// rawHealth maps /api/s/<site>/stat/health subsystem entries.
type rawHealth struct {
	Subsystem           string `json:"subsystem"`
	Status              string `json:"status"`
	WANIP               string `json:"wan_ip"`
	RemoteUserNumActive int    `json:"remote_user_num_active"`
}

// rawHistoricalUser maps /api/s/<site>/rest/user entries.
type rawHistoricalUser struct {
	MAC                     string `json:"mac"`
	Name                    string `json:"name"`
	Hostname                string `json:"hostname"`
	IsWired                 bool   `json:"is_wired"`
	FirstSeen               int64  `json:"first_seen"`
	LastSeen                int64  `json:"last_seen"`
	DisconnectTimestamp     int64  `json:"disconnect_timestamp"`
	LastConnectionNetName   string `json:"last_connection_network_name"`
	LastConnectionNetworkID string `json:"last_connection_network_id"`
}

// rawVPNConnectionsResponse maps GET /v2/api/site/<site>/vpn/connections.
type rawVPNConnectionsResponse struct {
	Connections []struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		User     string `json:"user"`
		Username string `json:"username"`
		Type     string `json:"type"`
		RemoteIP string `json:"remote_ip"`
		ClientIP string `json:"client_ip"`
		LocalIP  string `json:"local_ip"`
		IP       string `json:"ip"`
	} `json:"connections"`
}

// rawSystemLogEntry maps one item from POST /v2/api/site/<site>/system-log/all.
type rawSystemLogEntry struct {
	ID         string                     `json:"id"`
	Timestamp  int64                      `json:"timestamp"`
	Category   string                     `json:"category"`
	Event      string                     `json:"event"`
	Key        string                     `json:"key"`
	Severity   string                     `json:"severity"`
	TitleRaw   string                     `json:"title_raw"`
	MessageRaw string                     `json:"message_raw"`
	Parameters map[string]json.RawMessage `json:"parameters"`
}

// rawAdminActivityEntry maps one item from POST /v2/api/site/<site>/system-log/admin-activity.
type rawAdminActivityEntry struct {
	ID        string `json:"id"`
	Timestamp int64  `json:"timestamp"`
	Key       string `json:"key"`
	IP        string `json:"ip"`
	Platform  string `json:"platform"`
	Message   string `json:"message"`
	Admin     *struct {
		Name string `json:"name"`
	} `json:"admin"`
}

// siteTelemetry bundles best-effort security posture & event data fetched
// concurrently alongside core topology.
type siteTelemetry struct {
	wlans      []rawWLAN
	rogueAPs   []rawRogueAP
	settings   *SiteSecuritySettings
	health     *SystemHealth
	knownUsers []rawHistoricalUser
	recentLogs []ControllerLogEvent
}

// fetchSiteTelemetry concurrently retrieves Wi-Fi configs, neighboring rogue APs,
// non-secret security settings, WAN/VPN health, historical clients, and recent
// controller security/admin logs. Every sub-call is best-effort so older
// controllers or restricted permissions never break core snapshot collection.
func (c *Controller) fetchSiteTelemetry(ctx context.Context) siteTelemetry {
	var (
		wlanCh    = make(chan []rawWLAN, 1)
		rogueCh   = make(chan []rawRogueAP, 1)
		settingCh = make(chan *SiteSecuritySettings, 1)
		healthCh  = make(chan *SystemHealth, 1)
		usersCh   = make(chan []rawHistoricalUser, 1)
		logsCh    = make(chan []ControllerLogEvent, 1)
	)

	go func() {
		var env apiEnvelope[rawWLAN]
		if err := c.getJSON(ctx, c.apiPrefix+fmt.Sprintf("/api/s/%s/rest/wlanconf", c.site), &env); err == nil {
			wlanCh <- env.Data
			return
		}
		wlanCh <- nil
	}()
	go func() {
		var env apiEnvelope[rawRogueAP]
		if err := c.getJSON(ctx, c.apiPrefix+fmt.Sprintf("/api/s/%s/stat/rogueap", c.site), &env); err == nil {
			rogueCh <- env.Data
			return
		}
		rogueCh <- nil
	}()
	go func() {
		var env apiEnvelope[map[string]any]
		if err := c.getJSON(ctx, c.apiPrefix+fmt.Sprintf("/api/s/%s/rest/setting", c.site), &env); err == nil && len(env.Data) > 0 {
			settingCh <- parseSecuritySettings(env.Data)
			return
		}
		settingCh <- nil
	}()
	go func() {
		var env apiEnvelope[rawHealth]
		var h SystemHealth
		got := false
		if err := c.getJSON(ctx, c.apiPrefix+fmt.Sprintf("/api/s/%s/stat/health", c.site), &env); err == nil && len(env.Data) > 0 {
			got = true
			for _, item := range env.Data {
				switch strings.ToLower(item.Subsystem) {
				case "wan":
					h.WANStatus = item.Status
					h.WANIP = strings.TrimSpace(item.WANIP)
				case "vpn":
					h.ActiveVPNUsers = item.RemoteUserNumActive
				}
			}
		}
		var vpn rawVPNConnectionsResponse
		if err := c.getJSON(ctx, c.apiPrefix+fmt.Sprintf("/v2/api/site/%s/vpn/connections", c.site), &vpn); err == nil {
			got = true
			for _, vc := range vpn.Connections {
				user := vc.User
				if user == "" {
					user = vc.Username
				}
				localIP := vc.LocalIP
				if localIP == "" {
					localIP = vc.ClientIP
				}
				if localIP == "" {
					localIP = vc.IP
				}
				h.VPNConnections = append(h.VPNConnections, VPNConnection{
					ID:       vc.ID,
					Name:     vc.Name,
					User:     user,
					Type:     vc.Type,
					RemoteIP: vc.RemoteIP,
					LocalIP:  localIP,
				})
			}
			if len(h.VPNConnections) > h.ActiveVPNUsers {
				h.ActiveVPNUsers = len(h.VPNConnections)
			}
		}
		if got {
			healthCh <- &h
			return
		}
		healthCh <- nil
	}()
	go func() {
		var env apiEnvelope[rawHistoricalUser]
		if err := c.getJSON(ctx, c.apiPrefix+fmt.Sprintf("/api/s/%s/rest/user", c.site), &env); err == nil {
			usersCh <- env.Data
			return
		}
		usersCh <- nil
	}()
	go func() {
		logs, _ := c.FetchRecentLogs(ctx, time.Now().UTC().Add(-24*time.Hour))
		logsCh <- logs
	}()

	return siteTelemetry{
		wlans:      <-wlanCh,
		rogueAPs:   <-rogueCh,
		settings:   <-settingCh,
		health:     <-healthCh,
		knownUsers: <-usersCh,
		recentLogs: <-logsCh,
	}
}

// FetchRecentLogs queries UniFi's v2 System Log (security threats, critical
// alerts, network anomalies, and admin activity) since the given timestamp.
// Returns newest-first normalized events and fails gracefully on older consoles.
func (c *Controller) FetchRecentLogs(ctx context.Context, since time.Time) ([]ControllerLogEvent, error) {
	if c.controllerType == "" {
		if err := c.Login(ctx); err != nil {
			return nil, err
		}
	}
	nowMs := time.Now().UTC().UnixMilli()
	fromMs := since.UTC().UnixMilli()
	if fromMs <= 0 || fromMs > nowMs {
		fromMs = nowMs - int64((10 * time.Minute).Milliseconds())
	}

	payload := map[string]any{
		"timestampFrom": fromMs,
		"timestampTo":   nowMs,
		"pageNumber":    0,
		"pageSize":      50,
	}

	type allRes struct {
		items []rawSystemLogEntry
	}
	type adminRes struct {
		items []rawAdminActivityEntry
	}
	allCh := make(chan allRes, 1)
	adminCh := make(chan adminRes, 1)

	go func() {
		var resp struct {
			Data []rawSystemLogEntry `json:"data"`
		}
		if err := c.postJSON(ctx, c.apiPrefix+fmt.Sprintf("/v2/api/site/%s/system-log/all", c.site), payload, &resp); err == nil {
			allCh <- allRes{items: resp.Data}
			return
		}
		allCh <- allRes{}
	}()
	go func() {
		var resp struct {
			Data []rawAdminActivityEntry `json:"data"`
		}
		if err := c.postJSON(ctx, c.apiPrefix+fmt.Sprintf("/v2/api/site/%s/system-log/admin-activity", c.site), payload, &resp); err == nil {
			adminCh <- adminRes{items: resp.Data}
			return
		}
		adminCh <- adminRes{}
	}()

	ar := <-allCh
	admr := <-adminCh

	var events []ControllerLogEvent
	for _, entry := range ar.items {
		if !isSecurityRelevantLog(entry) {
			continue
		}
		params := extractLogParams(entry.Parameters)
		msg := interpolateLogTemplate(entry.MessageRaw, params)
		if msg == "" {
			msg = interpolateLogTemplate(entry.TitleRaw, params)
		}
		events = append(events, ControllerLogEvent{
			ID:        entry.ID,
			Timestamp: time.UnixMilli(entry.Timestamp).UTC(),
			Category:  strings.ToUpper(entry.Category),
			Event:     strings.ToUpper(entry.Event),
			Key:       entry.Key,
			Severity:  normalizeLogSeverity(entry.Severity, entry.Category, entry.Event),
			Title:     interpolateLogTemplate(entry.TitleRaw, params),
			Message:   msg,
			SrcIP:     firstNonEmpty(params["SRC_IP"], params["IP"]),
			DstIP:     params["DST_IP"],
			Device:    firstNonEmpty(params["DEVICE"], params["CONSOLE_NAME"]),
		})
	}
	for _, entry := range admr.items {
		adminName := "admin"
		if entry.Admin != nil && strings.TrimSpace(entry.Admin.Name) != "" {
			adminName = strings.TrimSpace(entry.Admin.Name)
		}
		params := map[string]string{
			"ADMIN":    adminName,
			"IP":       entry.IP,
			"PLATFORM": entry.Platform,
		}
		msg := interpolateLogTemplate(entry.Message, params)
		if msg == "" {
			msg = fmt.Sprintf("%s (%s) via %s from %s", adminName, entry.Key, entry.Platform, entry.IP)
		}
		sev := "medium"
		keyUp := strings.ToUpper(entry.Key)
		if strings.Contains(keyUp, "FAIL") || strings.Contains(keyUp, "DELETE") || strings.Contains(keyUp, "SSH") {
			sev = "high"
		}
		events = append(events, ControllerLogEvent{
			ID:        "admin:" + entry.ID,
			Timestamp: time.UnixMilli(entry.Timestamp).UTC(),
			Category:  "ADMIN",
			Event:     keyUp,
			Key:       entry.Key,
			Severity:  sev,
			Message:   msg,
			SrcIP:     entry.IP,
			Admin:     adminName,
		})
	}

	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.After(events[j].Timestamp)
	})
	return events, nil
}

// postJSON performs a read-only query POST (used by UniFi v2 system-log endpoints)
// and decodes its JSON response into dst.
func (c *Controller) postJSON(ctx context.Context, fullPath string, payload any, dst any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+fullPath, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}
	if c.csrfToken != "" {
		req.Header.Set("X-CSRF-Token", c.csrfToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", fullPath, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxControllerBodyBytes))
	if err != nil {
		return fmt.Errorf("read %s: %w", fullPath, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &httpStatusError{path: fullPath, status: resp.StatusCode}
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("decode %s: %w", fullPath, err)
	}
	return nil
}

// parseSecuritySettings extracts strictly non-secret security posture flags from
// /rest/setting records. Passwords and password hashes are intentionally ignored.
func parseSecuritySettings(items []map[string]any) *SiteSecuritySettings {
	s := &SiteSecuritySettings{}
	for _, m := range items {
		key, _ := m["key"].(string)
		switch strings.ToLower(key) {
		case "mgmt":
			s.SSHEnabled = mapBool(m, "x_ssh_enabled")
			s.SSHPasswordAuth = mapBool(m, "x_ssh_auth_password_enabled")
			if keys, ok := m["x_ssh_keys"].([]any); ok {
				s.SSHKeyCount = len(keys)
			}
		case "usg":
			s.UPnPEnabled = mapBool(m, "upnp_enabled")
			s.UPnPNATPMPEnabled = mapBool(m, "upnp_nat_pmp_enabled")
			s.UPnPSecureMode = mapBool(m, "upnp_secure_mode")
		case "ips":
			s.IPSMode = strings.ToLower(mapString(m, "ips_mode"))
			s.HoneypotEnabled = mapBool(m, "honeypot_enabled")
			s.DNSFiltering = mapBool(m, "dns_filtering")
			if hps, ok := m["honeypot"].([]any); ok {
				for _, hp := range hps {
					if hm, ok := hp.(map[string]any); ok {
						if ip := mapString(hm, "ip_address"); ip != "" {
							s.HoneypotIPs = append(s.HoneypotIPs, ip)
						}
					}
				}
				sort.Strings(s.HoneypotIPs)
			}
		case "doh":
			s.DoHState = strings.ToLower(mapString(m, "state"))
		case "teleport":
			s.TeleportEnabled = mapBool(m, "enabled")
		}
	}
	return s
}

func convertWLANs(raw []rawWLAN, netByID map[string]Network) []WLANConfig {
	if len(raw) == 0 {
		return nil
	}
	out := make([]WLANConfig, 0, len(raw))
	for _, w := range raw {
		netName := ""
		if n, ok := netByID[w.NetworkConfID]; ok {
			netName = n.Name
		}
		out = append(out, WLANConfig{
			ID:          w.ID,
			Name:        strings.TrimSpace(w.Name),
			Enabled:     w.Enabled,
			Security:    strings.ToLower(strings.TrimSpace(w.Security)),
			WPAMode:     strings.ToLower(strings.TrimSpace(w.WPAMode)),
			WPA3Support: w.WPA3Support,
			PMFMode:     strings.ToLower(strings.TrimSpace(w.PMFMode)),
			L2Isolation: w.L2Isolation,
			IsGuest:     w.IsGuest,
			NetworkID:   w.NetworkConfID,
			NetworkName: netName,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func convertRogueAPs(raw []rawRogueAP) []RogueAP {
	if len(raw) == 0 {
		return nil
	}
	out := make([]RogueAP, 0, len(raw))
	for _, r := range raw {
		out = append(out, RogueAP{
			BSSID:    strings.ToLower(strings.TrimSpace(r.BSSID)),
			ESSID:    strings.TrimSpace(r.ESSID),
			APMAC:    strings.ToLower(strings.TrimSpace(r.APMAC)),
			Channel:  r.Channel,
			Band:     r.Band,
			Security: r.Security,
			OUI:      r.OUI,
			RSSI:     r.RSSI,
			IsRogue:  r.IsRogue,
			IsUBNT:   r.IsUBNT,
			IsAdhoc:  r.IsAdhoc,
			LastSeen: r.LastSeen,
		})
	}
	return out
}

func convertHistoricalClients(raw []rawHistoricalUser, netByID map[string]Network) []HistoricalClient {
	if len(raw) == 0 {
		return nil
	}
	out := make([]HistoricalClient, 0, len(raw))
	for _, u := range raw {
		mac := strings.ToLower(strings.TrimSpace(u.MAC))
		if mac == "" {
			continue
		}
		lastSeen := u.LastSeen
		if u.DisconnectTimestamp > lastSeen {
			lastSeen = u.DisconnectTimestamp
		}
		netName := strings.TrimSpace(u.LastConnectionNetName)
		if netName == "" && u.LastConnectionNetworkID != "" {
			if n, ok := netByID[u.LastConnectionNetworkID]; ok {
				netName = n.Name
			}
		}
		out = append(out, HistoricalClient{
			MAC:             mac,
			Name:            strings.TrimSpace(u.Name),
			Hostname:        strings.TrimSpace(u.Hostname),
			IsWired:         u.IsWired,
			FirstSeen:       u.FirstSeen,
			LastSeen:        lastSeen,
			LastNetworkName: netName,
		})
	}
	return out
}

// isSecurityRelevantLog filters noisy routine Wi-Fi roaming/connect messages out
// of /system-log/all so only genuine security, intrusion, honeypot, DHCP/loop,
// failover, rogue-AP, and VPN events are surfaced.
func isSecurityRelevantLog(e rawSystemLogEntry) bool {
	cat := strings.ToUpper(e.Category)
	ev := strings.ToUpper(e.Event)
	key := strings.ToUpper(e.Key)
	sev := strings.ToUpper(e.Severity)

	if cat == "SECURITY" || cat == "THREATS" || cat == "ADMIN" {
		return true
	}
	for _, kw := range []string{
		"THREAT", "HONEYPOT", "IPS", "IDS", "ROGUE", "DHCP", "LOOP",
		"STP", "SPOOF", "CONFLICT", "FAILOVER", "WAN_", "VPN", "TELEPORT",
		"BLOCKED", "ATTACK", "MALWARE", "BRUTE", "UNAUTHORIZED", "TAMPER",
	} {
		if strings.Contains(ev, kw) || strings.Contains(key, kw) {
			return true
		}
	}
	return sev == "HIGH" || sev == "VERY_HIGH" || sev == "CRITICAL"
}

func extractLogParams(raw map[string]json.RawMessage) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		var s string
		if err := json.Unmarshal(v, &s); err == nil && s != "" {
			out[k] = s
			continue
		}
		var obj struct {
			Name string `json:"name"`
			ID   string `json:"id"`
			IP   string `json:"ip"`
		}
		if err := json.Unmarshal(v, &obj); err == nil {
			if val := firstNonEmpty(obj.Name, obj.IP, obj.ID); val != "" {
				out[k] = val
			}
		}
	}
	return out
}

func interpolateLogTemplate(tmpl string, params map[string]string) string {
	if tmpl == "" || len(params) == 0 {
		return tmpl
	}
	out := tmpl
	for k, v := range params {
		if v != "" {
			out = strings.ReplaceAll(out, "{"+k+"}", v)
		}
	}
	return out
}

func normalizeLogSeverity(rawSev, category, event string) string {
	ev := strings.ToUpper(event)
	if strings.Contains(ev, "HONEYPOT") || strings.Contains(ev, "ROGUE") {
		return "critical"
	}
	switch strings.ToUpper(strings.TrimSpace(rawSev)) {
	case "CRITICAL", "VERY_HIGH":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW":
		if strings.EqualFold(category, "SECURITY") {
			return "medium"
		}
		return "low"
	default:
		if strings.EqualFold(category, "SECURITY") {
			return "high"
		}
		return "info"
	}
}

func mapBool(m map[string]any, key string) bool {
	v, _ := m[key].(bool)
	return v
}

func mapString(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return strings.TrimSpace(v)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
