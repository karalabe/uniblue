// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package unifi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"reflect"
	"strings"
)

// feed keeps successful empty collections distinct from unavailable data.
type feed[T any] struct {
	items []T
	err   error
}

// asyncFeed starts independent requests without blocking a sender on early snapshot failure.
func asyncFeed[T any](fetch func() ([]T, error)) <-chan feed[T] {
	ch := make(chan feed[T], 1)
	go func() { items, err := fetch(); ch <- feed[T]{items, err} }()
	return ch
}

// readControllerBody reads one sentinel byte to distinguish oversized JSON from malformed JSON.
func readControllerBody(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxControllerBodyBytes+1))
	if len(b) > maxControllerBodyBytes {
		return nil, errors.New("controller response exceeds size limit")
	}
	return b, err
}

// getJSONArray requires a bare JSON array, including for a successfully empty table.
func getJSONArray[T any](ctx context.Context, c *Controller, path string) ([]T, error) {
	var rows []T
	if err := c.getJSON(ctx, path, &rows); err != nil {
		return nil, err
	}
	if rows == nil {
		return nil, fmt.Errorf("%s: expected an array", path)
	}
	return rows, nil
}

// getLegacyRows checks the data envelope even for optional inventory.
func getLegacyRows[T any](ctx context.Context, c *Controller, path string) ([]T, error) {
	var env apiEnvelope[T]
	err := c.getJSON(ctx, path, &env)
	return env.Data, err
}

// UnmarshalJSON requires a non-nil legacy data array so missing or malformed
// envelopes fail cleanly; meta.rc errors are checked by the HTTP transport.
func (env *apiEnvelope[T]) UnmarshalJSON(raw []byte) error {
	type plain apiEnvelope[T]
	var value plain
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	if value.Data == nil {
		return errors.New("expected controller data array")
	}
	*env = apiEnvelope[T](value)
	return nil
}

// finishSessionLogin resolves the site's internal routing reference via
// /api/self/sites using a single GET (avoiding recursive loginMu acquisition),
// tolerates permission/404 denials on restricted accounts, and commits the
// active session state and authEpoch under authMu.
func (c *Controller) finishSessionLogin(ctx context.Context, prefix, kind string) error {
	_, wanted := c.sessionPrefixAndSite()
	var env apiEnvelope[struct {
		ID          string `json:"_id"`
		ExternalID  string `json:"external_id"`
		Name        string `json:"name"`
		Description string `json:"desc"`
	}]
	ref := wanted
	err := c.queryJSONOnce(ctx, http.MethodGet, prefix+"/api/self/sites", nil, &env)
	if err == nil && len(env.Data) > 0 {
		var sites []integrationSite
		for _, r := range env.Data {
			id := firstNonEmpty(r.ExternalID, r.ID)
			if wanted != "" && wanted == r.ID {
				wanted = id
			}
			sites = append(sites, integrationSite{ID: id, Name: r.Description, InternalReference: r.Name})
		}
		s, err := resolveIntegrationSite(sites, wanted)
		if err != nil {
			return err
		}
		ref = s.InternalReference
		if ref == "" {
			return errors.New("site listing omitted routing reference")
		}
	} else if err != nil {
		var status *httpStatusError
		var envelope *apiEnvelopeError
		denied := errors.As(err, &status) && (status.status == http.StatusForbidden || status.status == http.StatusUnauthorized || status.status == http.StatusNotFound || status.status == http.StatusMethodNotAllowed)
		if !denied && !(errors.As(err, &envelope) && isPermissionDeniedMsg(envelope.msg)) {
			return fmt.Errorf("resolve session site: %w", err)
		}
	}
	// Restricted accounts and older controllers may only expose site-scoped reads.
	c.authMu.Lock()
	c.apiPrefix, c.controllerType, c.site = prefix, kind, ref
	c.authEpoch++
	c.authMu.Unlock()
	return nil
}

// fetchLogPages retains earlier pages on failure and bounds work for busy controllers.
func fetchLogPages[T any](ctx context.Context, c *Controller, path string, from, to int64) ([]T, error) {
	const pageSize = 50
	const maxPages = 10
	var items []T
	for n := 0; n < maxPages; n++ {
		req := map[string]any{"timestampFrom": from, "timestampTo": to, "pageNumber": n, "pageSize": pageSize}
		var page struct {
			Data   []T  `json:"data"`
			Number *int `json:"page_number"`
			Pages  *int `json:"total_page_count"`
		}
		if err := c.postJSON(ctx, path, req, &page); err != nil {
			return items, err
		}
		if page.Data == nil || (page.Number != nil && *page.Number != n) {
			return items, fmt.Errorf("%s: invalid log page", path)
		}
		items = append(items, page.Data...)
		if page.Pages != nil {
			if *page.Pages < 0 || *page.Pages == 0 && len(page.Data) > 0 {
				return items, fmt.Errorf("%s: invalid log page count", path)
			}
			if n+1 >= *page.Pages {
				return items, nil
			}
		} else if len(page.Data) < pageSize {
			return items, nil
		}
		if len(page.Data) == 0 {
			return items, fmt.Errorf("%s: empty intermediate log page", path)
		}
	}
	return items, nil
}

// signalDBM supports both modern signed signal and older signed RSSI readings.
func signalDBM(signal, rssi int) int {
	for _, v := range []int{signal, rssi} {
		if v >= -127 && v < 0 {
			return v
		}
	}
	return 0
}

// networkAliases maps legacy network _id and external_id references to
// canonical network IDs within the current site, falling back to unambiguous
// name/VLAN matches only when external_id is absent and the hints agree.
func networkAliases(networks []Network, legacy []rawNetwork) aliases {
	a, names, vlans := make(aliases), make(aliases), make(aliases)
	tags := make(map[string]string, len(networks))
	for _, n := range networks {
		a.add(n.ID, n.ID)
		names.add(n.ID, strings.ToLower(n.Name))
		vlans.add(n.ID, n.VLAN)
		tags[n.ID] = n.VLAN
	}
	for _, r := range legacy {
		id := firstNonEmpty(a[r.ExternalID], a[r.ID])
		if id == "" && r.ExternalID == "" {
			// Older Network versions omit external_id. Only join compatible,
			// unique inventory fields; conflicting evidence cannot identify a VLAN.
			name, byName := names[strings.ToLower(r.Name)]
			vlan, byVLAN := vlans[string(r.VLAN)]
			switch {
			case byName && byVLAN && name == vlan:
				id = name
			case byName && !byVLAN && (r.VLAN == "" || tags[name] == "" || string(r.VLAN) == tags[name]):
				id = name
			case byVLAN && !byName:
				id = vlan
			}
		}
		a.add(id, r.ID, r.ExternalID)
	}
	return a
}

// deviceAliases resolves controller device references to physical MAC addresses.
func deviceAliases(devices []integrationDevice, legacy []rawDevice) aliases {
	a := make(aliases)
	for _, d := range devices {
		m := canonicalMAC(d.MACAddress)
		a.add(m, m, d.ID)
	}
	for _, d := range legacy {
		m := canonicalMAC(d.MAC)
		a.add(m, m, d.ID, d.ExternalID, d.DeviceID)
	}
	return a
}

// fixedAliases prefers active DHCP reservations (use_fixedip=true) and falls
// back to an unambiguous historical fixed_ip claim only when no active
// reservation claims that address (even if the active reservation has no name).
func fixedAliases(users []rawHistoricalUser) aliases {
	active := make(aliases)
	activeClaimed := make(map[string]bool)
	fallback := make(aliases)
	for _, u := range users {
		name := strings.TrimSpace(u.Name)
		ip := strings.TrimSpace(u.FixedIP)
		if ip == "" {
			continue
		}
		if u.UseFixedIP {
			activeClaimed[ip] = true
			active.add(name, ip)
		} else if name != "" {
			fallback.add(name, ip)
		}
	}
	for ip, name := range fallback {
		if name == "" || activeClaimed[ip] {
			continue
		}
		active[ip] = name
	}
	return active
}

// assignClientNetwork resolves a controller ID first. A unique name can identify
// the network when either side lacks an ID. Clients without an attachment ID
// can also match the unique longest prefix containing one of their addresses.
func assignClientNetwork(c *Client, id, name string, ids aliases, nets []Network) {
	set := func(n Network) { c.NetworkID, c.NetworkName, c.VLAN = n.ID, n.Name, n.VLAN }
	ref := ids[id]
	var names []Network
	for _, n := range nets {
		if ref != "" && n.ID == ref {
			set(n)
			return
		}
		if (id == "" || n.ID == "") && name != "" && strings.EqualFold(n.Name, name) {
			names = append(names, n)
		}
	}
	if len(names) == 1 {
		set(names[0])
		return
	}
	if id != "" {
		// A reused name or overlapping subnet cannot override a known attachment ID.
		c.NetworkID, c.NetworkName = id, name
		return
	}
	for _, v := range c.AllIPs() {
		addr, err := netip.ParseAddr(v)
		if err != nil {
			continue
		}
		best, bits, tied := -1, -1, false
		for i, n := range nets {
			for _, p := range n.Prefixes() {
				if !p.Contains(addr) {
					continue
				}
				if p.Bits() > bits {
					best, bits, tied = i, p.Bits(), false
				} else if p.Bits() == bits && best != i {
					tied = true
				}
			}
		}
		if best >= 0 && !tied {
			set(nets[best])
			return
		}
	}
}

// aclCoverage summarizes switch ACL completeness as "unavailable", "partial",
// or "complete". Unsupported selectors and duplicate IDs downgrade coverage
// even on disabled rows, while duplicate (RuleType, Index) priorities are
// checked across enabled rules.
func aclCoverage(rows []SwitchACL, err error) *SwitchACLCoverage {
	if err != nil {
		return &SwitchACLCoverage{Status: "unavailable", Reason: shortFetchErr(err)}
	}
	seen := make(map[string]bool)
	type priority struct {
		class string
		index int
	}
	orders := make(map[priority]bool)
	for _, r := range rows {
		if field := firstNonEmpty(r.Source.UnsupportedSelector, r.Destination.UnsupportedSelector); field != "" {
			return &SwitchACLCoverage{Status: "partial", Reason: field}
		}
		if seen[r.ID] {
			return &SwitchACLCoverage{Status: "partial", Reason: "duplicate ACL ID"}
		}
		seen[r.ID] = true
		if r.Enabled {
			order := priority{r.RuleType, r.Index}
			if orders[order] {
				return &SwitchACLCoverage{Status: "partial", Reason: "ambiguous ACL priority"}
			}
			orders[order] = true
		}
	}
	return &SwitchACLCoverage{Status: "complete"}
}

// sessionPolicyFeeds holds concurrent results until network and device inventory is available.
type sessionPolicyFeeds struct {
	zones          <-chan feed[v2Zone]
	policies, acls <-chan feed[json.RawMessage]
	groups         <-chan feed[firewallGroup]
}

// startSessionPolicies queries each capability independently on the detected Network mount.
func startSessionPolicies(ctx context.Context, c *Controller, base, legacy string) sessionPolicyFeeds {
	return sessionPolicyFeeds{
		zones: asyncFeed(func() ([]v2Zone, error) { return getJSONArray[v2Zone](ctx, c, base+"firewall/zone") }),
		policies: asyncFeed(func() ([]json.RawMessage, error) {
			return getJSONArray[json.RawMessage](ctx, c, base+"firewall-policies")
		}),
		acls: asyncFeed(func() ([]json.RawMessage, error) { return getJSONArray[json.RawMessage](ctx, c, base+"acl-rules") }),
		groups: asyncFeed(func() ([]firewallGroup, error) {
			return getLegacyRows[firewallGroup](ctx, c, legacy+"rest/firewallgroup")
		}),
	}
}

// apply resolves policies only after the matching site inventories have been assembled.
func (feeds sessionPolicyFeeds) apply(s *Snapshot, raw []rawNetwork, devices aliases, guest guestRestrictions) groupIndex {
	zr, pr, ar, gr := <-feeds.zones, <-feeds.policies, <-feeds.acls, <-feeds.groups
	nets := networkAliases(s.Networks, raw)
	groups := indexGroups(gr.items)
	zoneIDs := make(aliases)
	zones := make(map[string]FirewallZone)
	byNet := make(aliases)
	for _, z := range zr.items {
		zoneIDs.add(z.ID, z.ID, z.ExternalID)
		f := FirewallZone{ID: z.ID, Name: z.Name, Origin: "USER_DEFINED"}
		if z.Default {
			f.Origin = "SYSTEM_DEFINED"
		}
		for _, n := range z.NetworkIDs {
			if id := nets[n]; id != "" {
				byNet.add(z.ID, id)
				f.NetworkIDs = append(f.NetworkIDs, id)
			}
		}
		s.Zones = append(s.Zones, f)
		zones[z.ID] = f
	}
	for alias, id := range zoneIDs {
		zones[alias] = zones[id]
	}
	for i, n := range raw {
		id := zoneIDs[n.ZoneID]
		if n.ZoneID == "" {
			id = byNet[n.ID]
		} else if member, ok := byNet[n.ID]; ok && member != id {
			// Clear the zone assignment when rest/networkconf and the v2 zone
			// membership list disagree so isolation evaluation reports unknown
			// rather than guessing which zone owns the network.
			id = ""
		}
		s.Networks[i].ZoneID, s.Networks[i].ZoneName = id, zones[id].Name
	}
	for _, row := range pr.items {
		var w v2Policy
		// Retain the zone pair and order of a well-shaped policy even when a
		// new predicate is opaque. An unreadable row invalidates the chain.
		if err := json.Unmarshal(row, &w); err != nil {
			pr.err = err
			s.FirewallPolicies = nil
			break
		}
		fieldErr := checkWireFields(row, reflect.TypeFor[v2Policy](), "policy")
		if w.Enabled == nil || w.Index == nil || *w.Index < 0 || w.ID == "" {
			pr.err = errors.New("missing firewall policy identity, enabled or index")
			s.FirewallPolicies = nil
			break
		}
		policy := w.policy(zones, nets, groups)
		if fieldErr != nil {
			policy.UnsupportedReason = fieldErr.Error()
		}
		s.FirewallPolicies = append(s.FirewallPolicies, policy)
	}
	applyGuestRestrictions(s.FirewallPolicies, guest)
	for _, row := range ar.items {
		s.SwitchACLs = append(s.SwitchACLs, decodeV2ACL(row, nets, devices))
	}
	s.SwitchACLCoverage = aclCoverage(s.SwitchACLs, ar.err)
	s.Visibility.SwitchACLsAvailable = ar.err == nil
	if s.SwitchACLCoverage.Status != "complete" {
		recordMissingFeed(s, "switch-acls ("+s.SwitchACLCoverage.Reason+")")
	}
	s.Visibility.GatewayPoliciesAvailable = zr.err == nil && pr.err == nil
	for _, f := range []struct {
		name string
		err  error
	}{{"firewall-zones", zr.err}, {"firewall-policies", pr.err}, {"firewall-groups", gr.err}} {
		if f.err != nil {
			recordMissingFeed(s, fmt.Sprintf("%s (%s)", f.name, shortFetchErr(f.err)))
		}
	}
	return groups
}

// normalizeNetworkRefs prevents unresolved ID filters from becoming definitive mismatches.
func normalizeNetworkRefs(ep *PolicyEndpoint, nets aliases) {
	if len(ep.NetworkIDs) == 0 {
		return
	}
	if ids, ok := nets.resolveIDs(ep.NetworkIDs); ok {
		ep.NetworkIDs = ids
	} else {
		ep.NetworkIDs = nil
		ep.UnsupportedSelector = "unresolved networkIds"
	}
}

// joinByUniqueField indexes legacy rest/networkconf rows by _id and builds
// unambiguous lowercase-name and VLAN-tag fallback lookup maps only for rows
// that omit external_id.
func joinByUniqueField(legacy []rawNetwork) (map[string]rawNetwork, aliases, aliases) {
	rows := make(map[string]rawNetwork)
	names, vlans := make(aliases), make(aliases)
	for _, r := range legacy {
		rows[r.ID] = r
		if r.ExternalID == "" {
			names.add(r.ID, strings.ToLower(r.Name))
			vlans.add(r.ID, string(r.VLAN))
		}
	}
	return rows, names, vlans
}

// normalizedScope returns a canonical list or an error marker for scoped ACL rules.
func normalizedScope(ids []string, nets aliases) ([]string, string) {
	if len(ids) == 0 {
		return nil, ""
	}
	res, ok := nets.resolveIDs(ids)
	if !ok {
		return nil, "unresolved ACL network scope"
	}
	return res, ""
}

// appendFeedError records optional feed failures without suppressing core inventory.
func appendFeedError(feeds []string, name string, err error) []string {
	if err != nil {
		return append(feeds, fmt.Sprintf("%s (%s)", name, shortFetchErr(err)))
	}
	return feeds
}
