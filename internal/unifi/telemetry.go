// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package unifi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
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
	// Signal is the signed dBm reading on recent controllers.
	Signal   int   `json:"signal"`
	RSSI     int   `json:"rssi"`
	IsRogue  bool  `json:"is_rogue"`
	IsUBNT   bool  `json:"is_ubnt"`
	IsAdhoc  bool  `json:"is_adhoc"`
	LastSeen int64 `json:"last_seen"`
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
	MAC string `json:"mac"`
	// UseFixedIP indicates whether the stored fixed address is an active reservation.
	UseFixedIP              bool   `json:"use_fixedip"`
	FixedIP                 string `json:"fixed_ip"`
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
	Connections *[]struct {
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
	ID         string                     `json:"id"`
	Timestamp  int64                      `json:"timestamp"`
	Key        string                     `json:"key"`
	IP         string                     `json:"ip"`
	Platform   string                     `json:"platform"`
	Message    string                     `json:"message"`
	MessageRaw string                     `json:"message_raw"`
	Parameters map[string]json.RawMessage `json:"parameters"`
	Count      int                        `json:"count"`
	Object     string                     `json:"object"`
	Section    string                     `json:"section"`
	Changes    []json.RawMessage          `json:"changes"`
	Target     *struct {
		Name    string `json:"name"`
		Type    string `json:"type"`
		Section string `json:"section"`
	} `json:"target"`
	Admin *struct {
		Name string `json:"name"`
	} `json:"admin"`
}

// siteTelemetry bundles best-effort security posture & event data fetched
// concurrently alongside core topology.
type siteTelemetry struct {
	missing      []string
	wlans        []rawWLAN
	wlansOK      bool
	rogueAPs     []rawRogueAP
	settings     *SiteSecuritySettings
	guest        guestRestrictions
	settingsOK   bool
	health       *SystemHealth
	vpnOK        bool
	knownUsers   []rawHistoricalUser
	recentLogs   []ControllerLogEvent
	portConfs    []rawPortConf
	portConfsOK  bool
	portConfsErr error
}

// fetchSiteTelemetry concurrently retrieves Wi-Fi configs, neighboring rogue APs,
// non-secret security settings, WAN/VPN health, historical clients, switch port
// profiles, and recent controller security/admin logs. Every sub-call is
// best-effort so older controllers or restricted permissions never break core
// snapshot collection.
func (c *Controller) fetchSiteTelemetry(ctx context.Context) siteTelemetry {
	prefix, site := c.sessionPrefixAndSite()
	ref := url.PathEscape(site)
	base := prefix + "/api/s/" + ref + "/"
	wlans := asyncFeed(func() ([]rawWLAN, error) { return getLegacyRows[rawWLAN](ctx, c, base+"rest/wlanconf") })
	aps := asyncFeed(func() ([]rawRogueAP, error) { return getLegacyRows[rawRogueAP](ctx, c, base+"stat/rogueap") })
	users := asyncFeed(func() ([]rawHistoricalUser, error) { return getLegacyRows[rawHistoricalUser](ctx, c, base+"rest/user") })
	profiles := asyncFeed(func() ([]rawPortConf, error) { return getLegacyRows[rawPortConf](ctx, c, base+"rest/portconf") })
	settings := asyncFeed(func() ([]map[string]any, error) { return getLegacyRows[map[string]any](ctx, c, base+"rest/setting") })
	health := asyncFeed(func() ([]rawHealth, error) { return getLegacyRows[rawHealth](ctx, c, base+"stat/health") })
	logs := asyncFeed(func() ([]ControllerLogEvent, error) {
		return c.FetchRecentLogs(ctx, time.Now().UTC().Add(-24*time.Hour))
	})
	var vpn rawVPNConnectionsResponse
	vpnErr := c.getJSON(ctx, prefix+"/v2/api/site/"+ref+"/vpn/connections", &vpn)
	if vpnErr == nil && vpn.Connections == nil {
		vpnErr = errors.New("missing VPN connections array")
	}
	w, r, u, p, s, h, l := <-wlans, <-aps, <-users, <-profiles, <-settings, <-health, <-logs
	t := siteTelemetry{wlans: w.items, wlansOK: w.err == nil, rogueAPs: r.items, knownUsers: u.items, portConfs: p.items, portConfsOK: p.err == nil, portConfsErr: p.err, recentLogs: l.items, vpnOK: vpnErr == nil}
	t.missing = appendFeedError(t.missing, "rogue-aps", r.err)
	t.missing = appendFeedError(t.missing, "known-clients", u.err)
	t.missing = appendFeedError(t.missing, "health", h.err)
	t.missing = appendFeedError(t.missing, "vpn-connections", vpnErr)
	t.missing = appendFeedError(t.missing, "system-logs", l.err)
	if len(s.items) > 0 && s.err == nil {
		t.settingsOK = true
		t.settings = parseSecuritySettings(s.items)
		t.guest = readGuestRestrictions(s.items)
	}
	if len(h.items) > 0 || t.vpnOK {
		t.health = &SystemHealth{}
		for _, row := range h.items {
			switch strings.ToLower(row.Subsystem) {
			case "wan":
				t.health.WANStatus = row.Status
				t.health.WANIP = strings.TrimSpace(row.WANIP)
			case "vpn":
				t.health.ActiveVPNUsers = row.RemoteUserNumActive
			}
		}
		if t.vpnOK {
			for _, v := range *vpn.Connections {
				t.health.VPNConnections = append(t.health.VPNConnections, VPNConnection{ID: v.ID, Name: v.Name, User: firstNonEmpty(v.User, v.Username), Type: v.Type, RemoteIP: v.RemoteIP, LocalIP: firstNonEmpty(v.LocalIP, v.ClientIP, v.IP)})
			}
		}
		t.health.ActiveVPNUsers = max(t.health.ActiveVPNUsers, len(t.health.VPNConnections))
	}
	return t
}

// FetchRecentLogs queries UniFi's v2 System Log (security threats, critical
// alerts, network anomalies, and admin activity) since the given timestamp.
// Returns newest-first normalized events and fails gracefully on older consoles.
func (c *Controller) FetchRecentLogs(ctx context.Context, since time.Time) ([]ControllerLogEvent, error) {
	if c.currentControllerType() == "" {
		if err := c.Login(ctx); err != nil {
			return nil, err
		}
	}
	apiPrefix, site := c.sessionPrefixAndSite()
	site = url.PathEscape(site)
	nowMs := time.Now().UTC().UnixMilli()
	fromMs := since.UTC().UnixMilli()
	if fromMs <= 0 || fromMs > nowMs {
		fromMs = nowMs - int64((10 * time.Minute).Milliseconds())
	}

	base := apiPrefix + fmt.Sprintf("/v2/api/site/%s/system-log/", site)
	all := asyncFeed(func() ([]rawSystemLogEntry, error) {
		return fetchLogPages[rawSystemLogEntry](ctx, c, base+"all", fromMs, nowMs)
	})
	admin := asyncFeed(func() ([]rawAdminActivityEntry, error) {
		return fetchLogPages[rawAdminActivityEntry](ctx, c, base+"admin-activity", fromMs, nowMs)
	})
	ar, admr := <-all, <-admin

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
		logID := strings.TrimSpace(entry.ID)
		if logID == "" {
			logID = "syslog:" + stableHashID(fmt.Sprintf("%d|%s|%s|%s", entry.Timestamp, entry.Key, entry.Event, msg))
		}
		events = append(events, ControllerLogEvent{
			ID:        logID,
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
		params := extractLogParams(entry.Parameters)
		if params == nil {
			params = make(map[string]string, 8)
		}
		if params["ADMIN"] == "" {
			params["ADMIN"] = adminName
		}
		if params["IP"] == "" && entry.IP != "" {
			params["IP"] = entry.IP
		}
		if params["PLATFORM"] == "" && entry.Platform != "" {
			params["PLATFORM"] = entry.Platform
		}
		if params["COUNT"] == "" {
			if entry.Count > 0 {
				params["COUNT"] = strconv.Itoa(entry.Count)
			} else if len(entry.Changes) > 0 {
				params["COUNT"] = strconv.Itoa(len(entry.Changes))
			}
		}
		if params["OBJECT"] == "" {
			obj := strings.TrimSpace(entry.Object)
			if obj == "" && entry.Target != nil {
				obj = firstNonEmpty(entry.Target.Name, entry.Target.Type)
			}
			if obj != "" {
				params["OBJECT"] = obj
			}
		}
		if params["SECTION"] == "" {
			sec := strings.TrimSpace(entry.Section)
			if sec == "" && entry.Target != nil {
				sec = strings.TrimSpace(entry.Target.Section)
			}
			if sec != "" {
				params["SECTION"] = sec
			}
		}
		rawMsg := firstNonEmpty(entry.Message, entry.MessageRaw)
		msg := interpolateLogTemplate(rawMsg, params)
		if msg == "" {
			msg = fmt.Sprintf("%s (%s) via %s from %s", adminName, entry.Key, entry.Platform, entry.IP)
		}
		sev := "medium"
		keyUp := strings.ToUpper(entry.Key)
		if strings.Contains(keyUp, "FAIL") || strings.Contains(keyUp, "DELETE") || strings.Contains(keyUp, "SSH") {
			sev = "high"
		}
		adminID := strings.TrimSpace(entry.ID)
		if adminID == "" {
			adminID = stableHashID(fmt.Sprintf("%d|%s|%s|%s|%s", entry.Timestamp, entry.Key, adminName, entry.IP, msg))
		}
		events = append(events, ControllerLogEvent{
			ID:        "admin:" + adminID,
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
	return events, errors.Join(ar.err, admr.err)
}

func stableHashID(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

// postJSON performs a read-only query POST (used by UniFi v2 system-log endpoints)
// and decodes its JSON response into dst, transparently re-logging in once if
// the cookie session expired and retrying once on transient 429/5xx bursts.
func (c *Controller) postJSON(ctx context.Context, fullPath string, payload any, dst any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	var lastErr error
	relogged := false
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(250 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
		epoch := c.currentAuthEpoch()
		err := c.postJSONOnce(ctx, fullPath, raw, dst)
		if err == nil {
			c.clearPathUnauthorized(fullPath)
			return nil
		}
		lastErr = err
		if !relogged && c.canRelogin() && isSessionExpiredError(err) && !c.isPathUnauthorized(fullPath) {
			relogged = true
			if loginErr := c.relogin(ctx, epoch); loginErr != nil {
				return fmt.Errorf("re-authentication failed: %w (after %w)", loginErr, err)
			}
			// Retry immediately with the fresh session without consuming the transient retry slot.
			retryErr := c.postJSONOnce(ctx, fullPath, raw, dst)
			if retryErr == nil {
				c.clearPathUnauthorized(fullPath)
				return nil
			}
			if isSessionExpiredError(retryErr) {
				c.markPathUnauthorized(fullPath)
			}
			lastErr = retryErr
		}
		var apiErr *apiEnvelopeError
		if errors.As(lastErr, &apiErr) {
			return lastErr
		}
		var httpErr *httpStatusError
		if errors.As(lastErr, &httpErr) && httpErr.status != http.StatusTooManyRequests && httpErr.status < 500 {
			return lastErr
		}
	}
	return lastErr
}

func (c *Controller) postJSONOnce(ctx context.Context, fullPath string, raw []byte, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+fullPath, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}
	if tok := c.currentCSRFToken(); tok != "" {
		req.Header.Set("X-CSRF-Token", tok)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", fullPath, err)
	}
	defer resp.Body.Close()

	if tok := resp.Header.Get("X-CSRF-Token"); tok != "" {
		c.setCSRFToken(tok)
	}

	body, err := readControllerBody(resp.Body)
	if err != nil {
		return fmt.Errorf("read %s: %w", fullPath, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &httpStatusError{method: http.MethodPost, path: fullPath, status: resp.StatusCode, apiMsg: extractAPIErrorMsg(body)}
	}
	if err := checkAPIEnvelopeError(fullPath, body); err != nil {
		return err
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
		netID, netName := w.NetworkConfID, ""
		if n, ok := netByID[w.NetworkConfID]; ok {
			netID, netName = n.ID, n.Name
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
			NetworkID:   netID,
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
			RSSI:     signalDBM(r.Signal, r.RSSI),
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

var unresolvedLogPlaceholderPattern = regexp.MustCompile(`\{[A-Z][A-Z0-9_]*\}`)

func extractLogParams(raw map[string]json.RawMessage) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		val := decodeLogParamValue(v)
		if val == "" {
			continue
		}
		out[k] = val
		if up := strings.ToUpper(k); up != k && out[up] == "" {
			out[up] = val
		}
	}
	return out
}

const maxLogParamDecodeDepth = 8

var logPlaceholderPattern = regexp.MustCompile(`\{([A-Za-z0-9_]+)\}`)

func decodeLogParamValue(v json.RawMessage) string {
	return decodeLogParamValueDepth(v, 0)
}

func decodeLogParamValueDepth(v json.RawMessage, depth int) string {
	if depth > maxLogParamDecodeDepth {
		return ""
	}
	trimmed := bytes.TrimSpace(v)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return ""
	}
	// Dispatch on the leading JSON token byte so each nesting level runs at
	// most one unmarshal pass (O(n) total work instead of O(n^2) on nested JSON).
	switch trimmed[0] {
	case '"':
		var s string
		if err := json.Unmarshal(trimmed, &s); err == nil {
			return strings.TrimSpace(s)
		}
	case 't', 'f':
		var b bool
		if err := json.Unmarshal(trimmed, &b); err == nil {
			return strconv.FormatBool(b)
		}
	case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		var num json.Number
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.UseNumber()
		if err := dec.Decode(&num); err == nil && num.String() != "" {
			return num.String()
		}
	case '{':
		var obj struct {
			Name     string          `json:"name"`
			Value    json.RawMessage `json:"value"`
			Label    string          `json:"label"`
			Title    string          `json:"title"`
			IP       string          `json:"ip"`
			Hostname string          `json:"hostname"`
			MAC      string          `json:"mac"`
			Section  string          `json:"section"`
			Object   string          `json:"object"`
			ID       string          `json:"id"`
		}
		if err := json.Unmarshal(trimmed, &obj); err == nil {
			valStr := ""
			if len(obj.Value) > 0 && depth < maxLogParamDecodeDepth {
				valStr = decodeLogParamValueDepth(obj.Value, depth+1)
			}
			return firstNonEmpty(obj.Name, valStr, obj.Label, obj.Title, obj.IP, obj.Hostname, obj.MAC, obj.Section, obj.Object, obj.ID)
		}
	}
	return ""
}

func interpolateLogTemplate(tmpl string, params map[string]string) string {
	if tmpl == "" {
		return ""
	}
	upper := make(map[string]string, len(params))
	for k, v := range params {
		if v == "" {
			continue
		}
		uk := strings.ToUpper(k)
		if upper[uk] == "" {
			upper[uk] = v
		}
	}
	// Perform a single-pass template replacement so map iteration order has no
	// effect and literal braces inside parameter values (such as hostnames or
	// usernames) are never re-interpolated or stripped.
	stripped := false
	out := logPlaceholderPattern.ReplaceAllStringFunc(tmpl, func(tok string) string {
		key := tok[1 : len(tok)-1]
		if v := params[key]; v != "" {
			return v
		}
		if v := upper[strings.ToUpper(key)]; v != "" {
			return v
		}
		if unresolvedLogPlaceholderPattern.MatchString(tok) {
			stripped = true
			return ""
		}
		return tok
	})
	if stripped {
		out = strings.Join(strings.Fields(out), " ")
	}
	return strings.TrimSpace(out)
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
