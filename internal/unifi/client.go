package unifi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/karalabe/uniblue/internal/config"
)

const (
	// controllerIntegrationV1 identifies consoles accessed via the official
	// UniFi Network Integration API v1 using an X-API-Key token.
	controllerIntegrationV1 = "integration-v1"

	// controllerUniFiOS identifies modern UniFi OS consoles (UDM Pro, Cloud
	// Gateways, newer Cloud Keys) using local cookie auth under /proxy/network.
	controllerUniFiOS = "unifi-os"

	// controllerClassic identifies legacy standalone Network controllers and
	// older Cloud Key firmware serving API calls directly at /api/s/<site>.
	controllerClassic = "classic"

	// integrationV1Prefix is the local console mount path for UniFi's official
	// Network Integration API v1.
	integrationV1Prefix = "/proxy/network/integration/v1"

	// integrationPageLimit requests up to 200 items per page to minimize round
	// trips on medium-to-large home and SMB networks.
	integrationPageLimit = 200

	// maxControllerBodyBytes caps JSON payloads read from the controller so a
	// misconfigured URL cannot exhaust memory.
	maxControllerBodyBytes = 16 << 20
)

// Controller is a read-only client for a single UniFi controller or gateway.
type Controller struct {
	// baseURL is the trimmed controller URL without a trailing slash.
	baseURL string

	// site is the UniFi site name or reference configured by the user (typically "default").
	site string

	// siteID stores the resolved site UUID when speaking the Integration v1 API.
	siteID string

	// username and password are used when cookie-based login is active.
	username string
	password string

	// apiKey is sent via X-API-Key when token-based authentication is configured.
	apiKey string

	// httpClient carries TLS configuration, timeouts, and the session cookie jar.
	httpClient *http.Client

	// apiPrefix is "/proxy/network" for UniFi OS consoles or "" for classic
	// controllers, discovered automatically during Login.
	apiPrefix string

	// controllerType records which API flavor was detected during Login.
	controllerType string

	// csrfToken stores the X-CSRF-Token returned by UniFi OS during login.
	csrfToken string
}

// New constructs a Controller from the user's UniFi configuration. Call Login
// before FetchSnapshot (or let FetchSnapshot call it automatically).
func New(cfg config.UniFiConfig) (*Controller, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("init cookie jar: %w", err)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // local gateways typically serve self-signed certs
		},
	}

	return &Controller{
		baseURL:  strings.TrimRight(cfg.URL, "/"),
		site:     cfg.Site,
		username: cfg.Username,
		password: cfg.Password,
		apiKey:   cfg.APIKey,
		httpClient: &http.Client{
			Timeout:   cfg.Timeout,
			Jar:       jar,
			Transport: transport,
		},
	}, nil
}

// Login authenticates against the controller and auto-detects the appropriate
// API flavor:
//   - If an API key is configured, it prefers the official Integration v1 API
//     (/proxy/network/integration/v1) and resolves the site UUID.
//   - Otherwise it authenticates with local credentials against UniFi OS
//     (/api/auth/login) and falls back to classic controllers (/api/login).
func (c *Controller) Login(ctx context.Context) error {
	if c.apiKey != "" {
		return c.loginWithAPIKey(ctx)
	}

	// Attempt UniFi OS authentication first (UDM Pro / Cloud Gateway / modern
	// Cloud Key). A 404 signals an older standalone/Cloud Key controller that
	// uses the classic /api/login endpoint instead.
	status, err := c.postLogin(ctx, "/api/auth/login")
	if err == nil {
		c.apiPrefix = "/proxy/network"
		c.controllerType = controllerUniFiOS
		return nil
	}
	if status != http.StatusNotFound {
		return fmt.Errorf("unifi-os login failed: %w", err)
	}

	if _, err := c.postLogin(ctx, "/api/login"); err != nil {
		return fmt.Errorf("classic unifi login failed: %w", err)
	}
	c.apiPrefix = ""
	c.controllerType = controllerClassic
	return nil
}

// loginWithAPIKey resolves the configured site against UniFi's official Network
// Integration API v1 (/proxy/network/integration/v1/sites). If that endpoint is
// unavailable (e.g., an older controller behind an API key proxy), it falls
// back to probing legacy REST prefixes.
func (c *Controller) loginWithAPIKey(ctx context.Context) error {
	sites, err := fetchAllPages[integrationSite](ctx, c, integrationV1Prefix+"/sites")
	if err == nil {
		site, resolveErr := resolveIntegrationSite(sites, c.site)
		if resolveErr != nil {
			return resolveErr
		}
		c.siteID = site.ID
		c.controllerType = controllerIntegrationV1
		c.apiPrefix = "/proxy/network"
		return nil
	}

	// Fall back to legacy site REST endpoints only if the official integration
	// endpoint is absent (404); surface auth errors directly so bad keys are obvious.
	var httpErr *httpStatusError
	if errors.As(err, &httpErr) && httpErr.status != http.StatusNotFound {
		return fmt.Errorf("unifi integration api login failed: %w", err)
	}

	probes := []struct {
		prefix string
		kind   string
	}{
		{prefix: "/proxy/network", kind: controllerUniFiOS},
		{prefix: "", kind: controllerClassic},
	}
	var lastErr error
	for _, p := range probes {
		c.apiPrefix = p.prefix
		c.controllerType = p.kind
		var out apiEnvelope[rawNetwork]
		if probeErr := c.getJSON(ctx, c.apiPrefix+fmt.Sprintf("/api/s/%s/rest/networkconf", c.site), &out); probeErr == nil {
			return nil
		} else {
			lastErr = probeErr
		}
	}
	return fmt.Errorf("unifi api key probe failed: %w", errors.Join(err, lastErr))
}

// resolveIntegrationSite matches the user's configured site string against a
// site's UUID, internalReference (typically "default"), or display name.
func resolveIntegrationSite(sites []integrationSite, wanted string) (integrationSite, error) {
	if len(sites) == 0 {
		return integrationSite{}, errors.New("unifi integration api returned no sites")
	}
	want := strings.ToLower(strings.TrimSpace(wanted))
	for _, s := range sites {
		if strings.ToLower(s.ID) == want ||
			strings.ToLower(s.InternalReference) == want ||
			strings.ToLower(s.Name) == want {
			return s, nil
		}
	}
	// Single-site consoles often name their sole site something custom while
	// users leave config.yaml at the default "default".
	if len(sites) == 1 && (want == "" || want == "default") {
		return sites[0], nil
	}
	names := make([]string, 0, len(sites))
	for _, s := range sites {
		names = append(names, fmt.Sprintf("%s (ref=%s, id=%s)", s.Name, s.InternalReference, s.ID))
	}
	return integrationSite{}, fmt.Errorf("site %q not found; available sites: %s", wanted, strings.Join(names, ", "))
}

// postLogin submits local credentials to path and stores any CSRF token
// returned by the controller. It returns the HTTP status code so callers can
// distinguish 404 (wrong controller flavor) from credential errors.
func (c *Controller) postLogin(ctx context.Context, path string) (int, error) {
	payload, err := json.Marshal(map[string]string{
		"username": c.username,
		"password": c.password,
	})
	if err != nil {
		return 0, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("HTTP %d from %s", resp.StatusCode, path)
	}
	if token := resp.Header.Get("X-CSRF-Token"); token != "" {
		c.csrfToken = token
	}
	return resp.StatusCode, nil
}

// FetchSnapshot retrieves active clients, UniFi devices, networks, and WAN port
// forwards concurrently, then cross-links client records with resolved VLAN
// names so downstream risk scoring has complete topology context.
func (c *Controller) FetchSnapshot(ctx context.Context) (*Snapshot, error) {
	if c.controllerType == "" {
		if err := c.Login(ctx); err != nil {
			return nil, err
		}
	}
	if c.controllerType == controllerIntegrationV1 {
		return c.fetchIntegrationSnapshot(ctx)
	}
	return c.fetchLegacySnapshot(ctx)
}

// fetchIntegrationSnapshot queries UniFi's official Network Integration API v1
// endpoints concurrently with full pagination and resolves client VLANs via
// subnet CIDR matching when the client record omits network metadata.
func (c *Controller) fetchIntegrationSnapshot(ctx context.Context) (*Snapshot, error) {
	type clientsRes struct {
		items []integrationClient
		err   error
	}
	type devicesRes struct {
		items []integrationDevice
		err   error
	}
	type networksRes struct {
		items []integrationNetwork
		err   error
	}
	type forwardsRes struct {
		items []rawPortForward
	}
	type zonesRes struct {
		items []integrationFirewallZone
	}
	type policiesRes struct {
		items []integrationFirewallPolicy
	}
	type legacyClientsRes struct {
		items []rawClient
	}
	type legacyDevicesRes struct {
		items []rawDevice
	}

	clientsCh := make(chan clientsRes, 1)
	devicesCh := make(chan devicesRes, 1)
	networksCh := make(chan networksRes, 1)
	forwardsCh := make(chan forwardsRes, 1)
	zonesCh := make(chan zonesRes, 1)
	policiesCh := make(chan policiesRes, 1)
	legacyClientsCh := make(chan legacyClientsRes, 1)
	legacyDevicesCh := make(chan legacyDevicesRes, 1)

	siteBase := fmt.Sprintf("%s/sites/%s", integrationV1Prefix, c.siteID)

	go func() {
		items, err := fetchAllPages[integrationClient](ctx, c, siteBase+"/clients")
		clientsCh <- clientsRes{items: items, err: err}
	}()
	go func() {
		items, err := fetchAllPages[integrationDevice](ctx, c, siteBase+"/devices")
		devicesCh <- devicesRes{items: items, err: err}
	}()
	go func() {
		// Older Network 9.0 consoles may not expose /networks yet; treat 404 as
		// empty rather than failing the whole snapshot.
		items, err := fetchAllPages[integrationNetwork](ctx, c, siteBase+"/networks")
		var httpErr *httpStatusError
		if errors.As(err, &httpErr) && httpErr.status == http.StatusNotFound {
			err = nil
		}
		networksCh <- networksRes{items: items, err: err}
	}()
	go func() {
		// Port forwards are not yet exposed under /integration/v1 on all versions;
		// opportunistically attempt the legacy endpoint and ignore auth/404 denials.
		var env apiEnvelope[rawPortForward]
		if err := c.getJSON(ctx, c.apiPrefix+fmt.Sprintf("/api/s/%s/rest/portforward", c.site), &env); err == nil {
			forwardsCh <- forwardsRes{items: env.Data}
			return
		}
		forwardsCh <- forwardsRes{}
	}()
	go func() {
		// Zone-Based Firewall endpoints exist on UniFi Network 9+; silently
		// ignore 404/auth errors on older consoles.
		items, err := fetchAllPages[integrationFirewallZone](ctx, c, siteBase+"/firewall/zones")
		if err != nil {
			zonesCh <- zonesRes{}
			return
		}
		zonesCh <- zonesRes{items: items}
	}()
	go func() {
		items, err := fetchAllPages[integrationFirewallPolicy](ctx, c, siteBase+"/firewall/policies")
		if err != nil {
			policiesCh <- policiesRes{}
			return
		}
		policiesCh <- policiesRes{items: items}
	}()
	go func() {
		// Opportunistically fetch legacy stat/sta to enrich Integration v1 clients
		// with true DHCP hostnames, OUI strings, Wi-Fi SSIDs, and switch port links.
		var env apiEnvelope[rawClient]
		if err := c.getJSON(ctx, c.apiPrefix+fmt.Sprintf("/api/s/%s/stat/sta", c.site), &env); err == nil {
			legacyClientsCh <- legacyClientsRes{items: env.Data}
			return
		}
		legacyClientsCh <- legacyClientsRes{}
	}()
	go func() {
		// Opportunistically fetch legacy stat/device to attach physical LLDP uplinks.
		var env apiEnvelope[rawDevice]
		if err := c.getJSON(ctx, c.apiPrefix+fmt.Sprintf("/api/s/%s/stat/device", c.site), &env); err == nil {
			legacyDevicesCh <- legacyDevicesRes{items: env.Data}
			return
		}
		legacyDevicesCh <- legacyDevicesRes{}
	}()

	cr := <-clientsCh
	dr := <-devicesCh
	nr := <-networksCh
	fr := <-forwardsCh
	zr := <-zonesCh
	pr := <-policiesCh
	lcr := <-legacyClientsCh
	ldr := <-legacyDevicesCh

	if err := errors.Join(cr.err, dr.err, nr.err); err != nil {
		return nil, fmt.Errorf("fetch unifi integration snapshot: %w", err)
	}

	// Build firewall zone lookup maps (zoneID -> name and networkID -> zone)
	// so every network and firewall policy carries resolved human-readable zone names.
	zones := make([]FirewallZone, 0, len(zr.items))
	zoneNameByID := make(map[string]string, len(zr.items))
	zoneByNetID := make(map[string]FirewallZone)
	for _, rz := range zr.items {
		origin := ""
		if rz.Metadata != nil {
			origin = rz.Metadata.Origin
		}
		z := FirewallZone{
			ID:         rz.ID,
			Name:       rz.Name,
			Origin:     origin,
			NetworkIDs: rz.NetworkIDs,
		}
		zones = append(zones, z)
		zoneNameByID[z.ID] = z.Name
		for _, nid := range z.NetworkIDs {
			zoneByNetID[nid] = z
		}
	}

	// Enrich each network with its IPv4 subnet, isolation flag, zone ID, and
	// legacy purpose (since the Integration v1 list omits ipv4Configuration and purpose),
	// and retain legacy rest/networkconf records so switch port_table native_networkconf_id
	// values resolve to human-readable VLAN names.
	legacyNets := c.enrichIntegrationNetworks(ctx, siteBase, nr.items)

	type subnetEntry struct {
		prefix netip.Prefix
		net    Network
	}
	networks := make([]Network, 0, len(nr.items))
	var subnets []subnetEntry
	for _, rn := range nr.items {
		subnet := extractIntegrationSubnet(rn)
		purpose := strings.ToLower(strings.TrimSpace(rn.Purpose))
		if purpose == "" {
			purpose = strings.ToLower(rn.Management)
		}
		zoneID := rn.ZoneID
		zoneName := zoneNameByID[zoneID]
		if zoneName == "" {
			if z, ok := zoneByNetID[rn.ID]; ok {
				zoneID = z.ID
				zoneName = z.Name
			}
		}
		n := Network{
			ID:               rn.ID,
			Name:             rn.Name,
			Purpose:          purpose,
			VLAN:             string(rn.VLANID),
			Subnet:           subnet,
			IsolationEnabled: rn.IsolationEnabled,
			ZoneID:           zoneID,
			ZoneName:         zoneName,
		}
		networks = append(networks, n)

		if pfx, err := parseNetworkPrefix(subnet); err == nil {
			subnets = append(subnets, subnetEntry{prefix: pfx, net: n})
		}
	}

	policies := convertIntegrationPolicies(pr.items, zoneNameByID)

	legacyClientByMAC := make(map[string]rawClient, len(lcr.items))
	for _, lc := range lcr.items {
		if m := strings.ToLower(strings.TrimSpace(lc.MAC)); m != "" {
			legacyClientByMAC[m] = lc
		}
	}
	legacyDevByMAC := make(map[string]rawDevice, len(ldr.items))
	for _, ld := range ldr.items {
		if m := strings.ToLower(strings.TrimSpace(ld.MAC)); m != "" {
			legacyDevByMAC[m] = ld
		}
	}

	clients := make([]Client, 0, len(cr.items))
	for _, rc := range cr.items {
		mac := strings.ToLower(strings.TrimSpace(rc.MACAddress))
		cl := Client{
			MAC:      mac,
			IP:       strings.TrimSpace(rc.IPAddress),
			Hostname: strings.TrimSpace(rc.Name),
			Name:     strings.TrimSpace(rc.Name),
			IsWired:  strings.EqualFold(rc.Type, "WIRED"),
		}
		if lc, ok := legacyClientByMAC[mac]; ok {
			if h := strings.TrimSpace(lc.Hostname); h != "" {
				cl.Hostname = h
			}
			if o := strings.TrimSpace(lc.OUI); o != "" {
				cl.OUI = o
			}
			cl.ESSID = strings.TrimSpace(lc.ESSID)
			cl.SwitchMAC = strings.ToLower(strings.TrimSpace(lc.SwMAC))
			cl.SwitchPort = lc.SwPort
			cl.APMAC = strings.ToLower(strings.TrimSpace(lc.APMAC))
		}
		if addr, err := netip.ParseAddr(cl.IP); err == nil {
			// Pick the most specific matching CIDR (longest prefix) in case
			// overlapping subnets exist.
			bestBits := -1
			for _, se := range subnets {
				if se.prefix.Contains(addr) && se.prefix.Bits() > bestBits {
					bestBits = se.prefix.Bits()
					cl.NetworkID = se.net.ID
					cl.NetworkName = se.net.Name
					cl.VLAN = se.net.VLAN
				}
			}
		}
		clients = append(clients, cl)
	}

	netByID := make(map[string]Network, len(networks)+len(legacyNets))
	defaultNetName := defaultLANName(networks)
	for _, n := range networks {
		if n.ID != "" {
			netByID[n.ID] = n
		}
	}
	for _, ln := range legacyNets {
		if ln.ID != "" && ln.Name != "" {
			if _, exists := netByID[ln.ID]; !exists {
				netByID[ln.ID] = Network{
					ID:               ln.ID,
					Name:             ln.Name,
					Purpose:          strings.ToLower(strings.TrimSpace(ln.Purpose)),
					VLAN:             string(ln.VLAN),
					Subnet:           ln.IPSubnet,
					IsolationEnabled: ln.NetworkIsolationEnabled,
				}
			}
		}
	}

	devices := make([]Device, 0, len(dr.items))
	for _, rd := range dr.items {
		mac := strings.ToLower(strings.TrimSpace(rd.MACAddress))
		dev := Device{
			MAC:        mac,
			IP:         strings.TrimSpace(rd.IPAddress),
			Name:       strings.TrimSpace(rd.Name),
			Model:      rd.Model,
			Type:       strings.ToLower(rd.State),
			Version:    rd.FirmwareVersion,
			Upgradable: rd.FirmwareUpdatable,
		}
		if ld, ok := legacyDevByMAC[mac]; ok {
			if ld.Type != "" {
				dev.Type = strings.ToLower(ld.Type)
			}
			if ld.Uplink != nil {
				dev.UplinkMAC = strings.ToLower(strings.TrimSpace(ld.Uplink.UplinkMAC))
				dev.UplinkName = strings.TrimSpace(ld.Uplink.UplinkDeviceName)
				dev.UplinkPort = ld.Uplink.UplinkRemotePort
			}
			dev.Ports = convertSwitchPorts(ld, netByID, defaultNetName)
		}
		devices = append(devices, dev)
	}

	forwards := convertPortForwards(fr.items)

	return &Snapshot{
		CollectedAt:      time.Now().UTC(),
		Site:             c.site,
		ControllerType:   c.controllerType,
		Clients:          clients,
		Devices:          devices,
		Networks:         networks,
		PortForwards:     forwards,
		Zones:            zones,
		FirewallPolicies: policies,
	}, nil
}

// fetchLegacySnapshot queries the classic /api/s/<site>/... endpoints (proxied
// under /proxy/network on UniFi OS consoles) concurrently over typed channels.
func (c *Controller) fetchLegacySnapshot(ctx context.Context) (*Snapshot, error) {
	type clientsRes struct {
		items []rawClient
		err   error
	}
	type devicesRes struct {
		items []rawDevice
		err   error
	}
	type networksRes struct {
		items []rawNetwork
		err   error
	}
	type forwardsRes struct {
		items []rawPortForward
		err   error
	}

	clientsCh := make(chan clientsRes, 1)
	devicesCh := make(chan devicesRes, 1)
	networksCh := make(chan networksRes, 1)
	forwardsCh := make(chan forwardsRes, 1)

	go func() {
		var env apiEnvelope[rawClient]
		err := c.getJSON(ctx, c.apiPrefix+fmt.Sprintf("/api/s/%s/stat/sta", c.site), &env)
		clientsCh <- clientsRes{items: env.Data, err: err}
	}()
	go func() {
		var env apiEnvelope[rawDevice]
		err := c.getJSON(ctx, c.apiPrefix+fmt.Sprintf("/api/s/%s/stat/device", c.site), &env)
		devicesCh <- devicesRes{items: env.Data, err: err}
	}()
	go func() {
		var env apiEnvelope[rawNetwork]
		err := c.getJSON(ctx, c.apiPrefix+fmt.Sprintf("/api/s/%s/rest/networkconf", c.site), &env)
		networksCh <- networksRes{items: env.Data, err: err}
	}()
	go func() {
		var env apiEnvelope[rawPortForward]
		err := c.getJSON(ctx, c.apiPrefix+fmt.Sprintf("/api/s/%s/rest/portforward", c.site), &env)
		forwardsCh <- forwardsRes{items: env.Data, err: err}
	}()

	cr := <-clientsCh
	dr := <-devicesCh
	nr := <-networksCh
	fr := <-forwardsCh

	if err := errors.Join(cr.err, dr.err, nr.err, fr.err); err != nil {
		return nil, fmt.Errorf("fetch unifi snapshot: %w", err)
	}

	// Build lookup maps from networkconf so each active client carries both its
	// friendly VLAN name and numeric VLAN tag even when stat/sta omits one.
	networks := make([]Network, 0, len(nr.items))
	netByID := make(map[string]Network, len(nr.items))
	netByName := make(map[string]Network, len(nr.items))
	for _, rn := range nr.items {
		n := Network{
			ID:               rn.ID,
			Name:             rn.Name,
			Purpose:          strings.ToLower(strings.TrimSpace(rn.Purpose)),
			VLAN:             string(rn.VLAN),
			Subnet:           rn.IPSubnet,
			IsolationEnabled: rn.NetworkIsolationEnabled,
		}
		networks = append(networks, n)
		if n.ID != "" {
			netByID[n.ID] = n
		}
		if n.Name != "" {
			netByName[strings.ToLower(n.Name)] = n
		}
	}

	clients := make([]Client, 0, len(cr.items))
	for _, rc := range cr.items {
		cl := Client{
			MAC:         strings.ToLower(strings.TrimSpace(rc.MAC)),
			IP:          strings.TrimSpace(rc.IP),
			Hostname:    strings.TrimSpace(rc.Hostname),
			Name:        strings.TrimSpace(rc.Name),
			OUI:         strings.TrimSpace(rc.OUI),
			NetworkID:   rc.NetworkID,
			NetworkName: rc.Network,
			VLAN:        string(rc.VLAN),
			IsWired:     rc.IsWired,
			ESSID:       strings.TrimSpace(rc.ESSID),
			SwitchMAC:   strings.ToLower(strings.TrimSpace(rc.SwMAC)),
			SwitchPort:  rc.SwPort,
			APMAC:       strings.ToLower(strings.TrimSpace(rc.APMAC)),
		}

		// Fill missing network name or VLAN tag from the site's network table.
		if net, ok := netByID[cl.NetworkID]; ok {
			if cl.NetworkName == "" {
				cl.NetworkName = net.Name
			}
			if cl.VLAN == "" {
				cl.VLAN = net.VLAN
			}
		} else if net, ok := netByName[strings.ToLower(cl.NetworkName)]; ok {
			if cl.VLAN == "" {
				cl.VLAN = net.VLAN
			}
		}

		clients = append(clients, cl)
	}

	defaultNetName := defaultLANName(networks)
	devices := make([]Device, 0, len(dr.items))
	for _, rd := range dr.items {
		dev := Device{
			MAC:        strings.ToLower(strings.TrimSpace(rd.MAC)),
			IP:         strings.TrimSpace(rd.IP),
			Name:       strings.TrimSpace(rd.Name),
			Model:      rd.Model,
			Type:       rd.Type,
			Version:    rd.Version,
			Upgradable: rd.Upgradable,
			Ports:      convertSwitchPorts(rd, netByID, defaultNetName),
		}
		if rd.Uplink != nil {
			dev.UplinkMAC = strings.ToLower(strings.TrimSpace(rd.Uplink.UplinkMAC))
			dev.UplinkName = strings.TrimSpace(rd.Uplink.UplinkDeviceName)
			dev.UplinkPort = rd.Uplink.UplinkRemotePort
		}
		devices = append(devices, dev)
	}

	return &Snapshot{
		CollectedAt:    time.Now().UTC(),
		Site:           c.site,
		ControllerType: c.controllerType,
		Clients:        clients,
		Devices:        devices,
		Networks:       networks,
		PortForwards:   convertPortForwards(fr.items),
	}, nil
}

// fetchAllPages walks a paginated Integration v1 list endpoint using offset and
// limit query parameters until all items reported by totalCount are collected.
func fetchAllPages[T any](ctx context.Context, c *Controller, path string) ([]T, error) {
	var all []T
	offset := 0
	for {
		pagePath := fmt.Sprintf("%s?offset=%d&limit=%d", path, offset, integrationPageLimit)
		var page integrationPage[T]
		if err := c.getJSON(ctx, pagePath, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Data...)
		if len(page.Data) == 0 || offset+len(page.Data) >= page.TotalCount {
			break
		}
		offset += len(page.Data)
	}
	return all, nil
}

// defaultLANName returns the site's primary untagged management/LAN network
// name (VLAN empty or "1", corporate/default) used as the fallback native VLAN
// when a UniFi switch port has no explicit native_networkconf_id override.
func defaultLANName(networks []Network) string {
	for _, n := range networks {
		if strings.EqualFold(n.Purpose, "wan") || strings.EqualFold(n.Purpose, "wan2") {
			continue
		}
		if n.VLAN == "" || n.VLAN == "0" || n.VLAN == "1" {
			return n.Name
		}
	}
	if len(networks) > 0 {
		return networks[0].Name
	}
	return "Default"
}

// convertSwitchPorts normalizes a UniFi device's port_table merged with
// port_overrides into sorted SwitchPort entries with resolved native VLAN names.
func convertSwitchPorts(rd rawDevice, netByID map[string]Network, defaultNetName string) []SwitchPort {
	if len(rd.PortTable) == 0 {
		return nil
	}
	ovByIdx := make(map[int]rawPort, len(rd.PortOverrides))
	for _, ov := range rd.PortOverrides {
		if ov.PortIdx > 0 {
			ovByIdx[ov.PortIdx] = ov
		}
	}

	ports := make([]SwitchPort, 0, len(rd.PortTable))
	for _, rp := range rd.PortTable {
		if rp.PortIdx <= 0 {
			continue
		}
		// Merge any explicit port_override fields onto the live port_table record.
		if ov, ok := ovByIdx[rp.PortIdx]; ok {
			if ov.Name != "" {
				rp.Name = ov.Name
			}
			if ov.OpMode != "" {
				rp.OpMode = ov.OpMode
			}
			if ov.Forward != "" {
				rp.Forward = ov.Forward
			}
			if ov.TaggedVLANMgmt != "" {
				rp.TaggedVLANMgmt = ov.TaggedVLANMgmt
			}
			if ov.NativeNetworkConfID != "" {
				rp.NativeNetworkConfID = ov.NativeNetworkConfID
			}
			if ov.PoEMode != "" {
				rp.PoEMode = ov.PoEMode
			}
			if ov.PortSecurityEnabled != nil {
				rp.PortSecurityEnabled = ov.PortSecurityEnabled
			}
			if len(ov.PortSecurityMACs) > 0 {
				rp.PortSecurityMACs = ov.PortSecurityMACs
			}
			if ov.Isolation != nil {
				rp.Isolation = ov.Isolation
			}
		}

		enabled := true
		if rp.Enable != nil {
			enabled = *rp.Enable
		}
		opMode := strings.ToLower(strings.TrimSpace(rp.OpMode))
		fwd := strings.ToLower(strings.TrimSpace(rp.Forward))
		if opMode == "off" || fwd == "disabled" {
			enabled = false
		}

		isWAN := strings.HasPrefix(strings.ToLower(strings.TrimSpace(rp.NetworkName)), "wan")
		nativeName := ""
		if isWAN {
			nativeName = strings.ToUpper(strings.TrimSpace(rp.NetworkName))
		} else if rp.NativeNetworkConfID != "" {
			if n, ok := netByID[rp.NativeNetworkConfID]; ok {
				nativeName = n.Name
			} else {
				nativeName = rp.NativeNetworkConfID
			}
		} else if enabled {
			nativeName = defaultNetName
		}

		tagged := strings.ToLower(strings.TrimSpace(rp.TaggedVLANMgmt))
		if tagged == "" {
			switch fwd {
			case "native":
				tagged = "block_all"
			case "customize":
				tagged = "custom"
			case "disabled":
				tagged = "disabled"
			default:
				if enabled {
					tagged = "auto"
				} else {
					tagged = "disabled"
				}
			}
		}

		psec := rp.PortSecurityEnabled != nil && *rp.PortSecurityEnabled
		iso := rp.Isolation != nil && *rp.Isolation
		var psecMACs []string
		for _, m := range rp.PortSecurityMACs {
			if norm := strings.ToLower(strings.TrimSpace(m)); norm != "" {
				psecMACs = append(psecMACs, norm)
			}
		}

		ports = append(ports, SwitchPort{
			PortIdx:             rp.PortIdx,
			Name:                strings.TrimSpace(rp.Name),
			Enabled:             enabled,
			Up:                  rp.Up,
			Speed:               rp.Speed,
			Media:               strings.TrimSpace(rp.Media),
			IsUplink:            rp.IsUplink,
			IsWAN:               isWAN,
			OpMode:              opMode,
			Forward:             fwd,
			TaggedVLANMgmt:      tagged,
			NativeNetworkID:     rp.NativeNetworkConfID,
			NativeNetworkName:   nativeName,
			PoEEnabled:          rp.PoEEnable,
			PoEMode:             strings.ToLower(strings.TrimSpace(rp.PoEMode)),
			PoEPower:            strings.TrimSpace(string(rp.PoEPower)),
			PortSecurityEnabled: psec,
			PortSecurityMACs:    psecMACs,
			Isolation:           iso,
			MACTableCount:       rp.MACTableCount,
		})
	}
	sort.Slice(ports, func(i, j int) bool {
		return ports[i].PortIdx < ports[j].PortIdx
	})
	return ports
}

// convertPortForwards normalizes wire port-forward rules into domain PortForward values.
func convertPortForwards(raw []rawPortForward) []PortForward {
	forwards := make([]PortForward, 0, len(raw))
	for _, rf := range raw {
		forwards = append(forwards, PortForward{
			ID:      rf.ID,
			Name:    rf.Name,
			Enabled: rf.Enabled,
			Proto:   strings.ToLower(rf.Proto),
			DstPort: string(rf.DstPort),
			FwdIP:   strings.TrimSpace(rf.Fwd),
			FwdPort: string(rf.FwdPort),
			Src:     strings.TrimSpace(rf.Src),
		})
	}
	return forwards
}

// parseNetworkPrefix parses a UniFi gateway CIDR such as "192.168.20.1/24" and
// returns its masked network prefix ("192.168.20.0/24") for containment checks.
func parseNetworkPrefix(cidr string) (netip.Prefix, error) {
	pfx, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil {
		return netip.Prefix{}, err
	}
	return pfx.Masked(), nil
}

// extractIntegrationSubnet returns the CIDR string from an integrationNetwork,
// checking both the direct subnet field and nested ipv4Configuration.
func extractIntegrationSubnet(rn integrationNetwork) string {
	if rn.Subnet != "" {
		return rn.Subnet
	}
	if rn.IPv4Configuration != nil && rn.IPv4Configuration.HostIPAddress != "" && rn.IPv4Configuration.PrefixLength > 0 {
		return fmt.Sprintf("%s/%d", rn.IPv4Configuration.HostIPAddress, rn.IPv4Configuration.PrefixLength)
	}
	return ""
}

// convertIntegrationPolicies normalizes wire Integration v1 firewall policies
// into domain FirewallPolicy values with resolved zone names and explicit
// IP/port filter flags.
func convertIntegrationPolicies(raw []integrationFirewallPolicy, zoneNames map[string]string) []FirewallPolicy {
	out := make([]FirewallPolicy, 0, len(raw))
	for _, rp := range raw {
		origin := ""
		if rp.Metadata != nil {
			origin = rp.Metadata.Origin
		}
		proto := "all"
		if rp.IPProtocolScope != nil && rp.IPProtocolScope.ProtocolFilter != nil {
			pf := rp.IPProtocolScope.ProtocolFilter
			switch {
			case pf.Protocol != nil && pf.Protocol.Name != "":
				proto = strings.ToLower(pf.Protocol.Name)
			case pf.NamedProtocol != "":
				proto = strings.ToLower(pf.NamedProtocol)
			}
		}
		out = append(out, FirewallPolicy{
			ID:             rp.ID,
			Name:           rp.Name,
			Enabled:        rp.Enabled,
			Action:         strings.ToUpper(strings.TrimSpace(rp.Action.Type)),
			Origin:         origin,
			Protocol:       proto,
			Source:         convertPolicyEndpoint(rp.Source, zoneNames),
			Destination:    convertPolicyEndpoint(rp.Destination, zoneNames),
			LoggingEnabled: rp.LoggingEnabled,
		})
	}
	return out
}

// convertPolicyEndpoint extracts zone identity, IP addresses, and port numbers
// from an Integration v1 firewall policy endpoint.
func convertPolicyEndpoint(ep integrationPolicyEndpoint, zoneNames map[string]string) PolicyEndpoint {
	out := PolicyEndpoint{
		ZoneID:    ep.ZoneID,
		ZoneName:  zoneNames[ep.ZoneID],
		AnyTarget: true,
		AnyPort:   true,
	}
	tf := ep.TrafficFilter
	if tf == nil {
		return out
	}

	if tf.IPAddressFilter != nil && len(tf.IPAddressFilter.Items) > 0 {
		out.AnyTarget = false
		for _, item := range tf.IPAddressFilter.Items {
			if v := strings.TrimSpace(string(item.Value)); v != "" {
				out.IPs = append(out.IPs, v)
			}
		}
	}
	if tf.NetworkFilter != nil && len(tf.NetworkFilter.NetworkIDs) > 0 {
		out.AnyTarget = false
	}
	if tf.MACAddressFilter != nil && len(tf.MACAddressFilter.MACAddresses) > 0 {
		out.AnyTarget = false
	}
	if tf.PortFilter != nil && len(tf.PortFilter.Items) > 0 {
		out.AnyPort = false
		for _, item := range tf.PortFilter.Items {
			if item.Start > 0 && item.End >= item.Start && (item.End-item.Start+1) <= 16 {
				for p := item.Start; p <= item.End; p++ {
					out.Ports = append(out.Ports, p)
				}
				continue
			}
			if v := strings.TrimSpace(string(item.Value)); v != "" {
				out.Ports = append(out.Ports, expandPortSpec(v, 16)...)
			}
		}
	}
	return out
}

// enrichIntegrationNetworks fills in missing IPv4 subnets, isolation flags,
// zone IDs, and network purposes on networks returned by the Integration v1
// list endpoint. It concurrently queries each network's detail endpoint over a
// channel and opportunistically pulls legacy rest/networkconf records (returning
// them so switch port native_networkconf_id references resolve cleanly).
func (c *Controller) enrichIntegrationNetworks(ctx context.Context, siteBase string, items []integrationNetwork) []rawNetwork {
	type detailRes struct {
		idx       int
		subnet    string
		isolated  bool
		zoneID    string
		purpose   string
		hasDetail bool
	}

	if len(items) == 0 {
		return nil
	}

	legacyCh := make(chan []rawNetwork, 1)
	go func() {
		var env apiEnvelope[rawNetwork]
		if err := c.getJSON(ctx, c.apiPrefix+fmt.Sprintf("/api/s/%s/rest/networkconf", c.site), &env); err == nil {
			legacyCh <- env.Data
			return
		}
		legacyCh <- nil
	}()

	ch := make(chan detailRes, len(items))
	for i := range items {
		id := items[i].ID
		if id == "" {
			ch <- detailRes{idx: i}
			continue
		}
		go func(idx int, netID string) {
			var detail integrationNetwork
			if err := c.getJSON(ctx, fmt.Sprintf("%s/networks/%s", siteBase, netID), &detail); err == nil {
				ch <- detailRes{
					idx:       idx,
					subnet:    extractIntegrationSubnet(detail),
					isolated:  detail.IsolationEnabled,
					zoneID:    detail.ZoneID,
					purpose:   detail.Purpose,
					hasDetail: true,
				}
				return
			}
			ch <- detailRes{idx: idx}
		}(i, id)
	}
	for range items {
		res := <-ch
		if !res.hasDetail {
			continue
		}
		if res.subnet != "" && extractIntegrationSubnet(items[res.idx]) == "" {
			items[res.idx].Subnet = res.subnet
		}
		if res.isolated {
			items[res.idx].IsolationEnabled = true
		}
		if res.zoneID != "" && items[res.idx].ZoneID == "" {
			items[res.idx].ZoneID = res.zoneID
		}
		if res.purpose != "" && items[res.idx].Purpose == "" {
			items[res.idx].Purpose = res.purpose
		}
	}

	legacyNets := <-legacyCh
	if len(legacyNets) == 0 {
		return nil
	}

	byName := make(map[string]rawNetwork, len(legacyNets))
	byVLAN := make(map[string]rawNetwork, len(legacyNets))
	for _, rn := range legacyNets {
		if rn.Name != "" {
			byName[strings.ToLower(rn.Name)] = rn
		}
		if vlan := string(rn.VLAN); vlan != "" {
			byVLAN[vlan] = rn
		}
	}
	for i := range items {
		rn, ok := byName[strings.ToLower(items[i].Name)]
		if !ok {
			rn, ok = byVLAN[string(items[i].VLANID)]
		}
		if !ok {
			continue
		}
		if extractIntegrationSubnet(items[i]) == "" && rn.IPSubnet != "" {
			items[i].Subnet = rn.IPSubnet
		}
		if items[i].Purpose == "" && rn.Purpose != "" {
			items[i].Purpose = rn.Purpose
		}
		if rn.NetworkIsolationEnabled {
			items[i].IsolationEnabled = true
		}
	}
	return legacyNets
}

// httpStatusError preserves the HTTP status code on failed controller requests
// so callers can distinguish missing endpoints (404) from auth errors (401/403).
type httpStatusError struct {
	path   string
	status int
}

// Error formats a concise description of the non-2xx HTTP status.
func (e *httpStatusError) Error() string {
	return fmt.Sprintf("GET %s returned HTTP %d", e.path, e.status)
}

// getJSON performs a read-only GET request against a full controller path and
// decodes its JSON response into dst.
func (c *Controller) getJSON(ctx context.Context, fullPath string, dst any) error {
	fullURL := c.baseURL + fullPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}
	if c.csrfToken != "" {
		req.Header.Set("X-CSRF-Token", c.csrfToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", fullPath, err)
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
