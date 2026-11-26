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
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/karalabe/uniblue/internal/config"
)

// TestV2ACLValidation exercises malformed rows independently of their enabled flag.
func TestV2ACLValidation(t *testing.T) {
	const row = `{"_id":"acl","enabled":true,"acl_index":0,"type":"IPV4","action":"BLOCK","ip_acl_protocol":"TCP_AND_UDP","specific_enforcers":["02:00:00:00:00:01"],"traffic_source":{"type":"NETWORK","network_ids":["object"]},"traffic_destination":{"type":"IP_OR_SUBNET","ips_or_subnets":["192.0.2.0/24"],"ports":[443]}}`
	nets := aliases{"object": "network"}
	dev := aliases{"02:00:00:00:00:01": "02:00:00:00:00:01"}
	good := decodeV2ACL(json.RawMessage(row), nets, dev)
	if aclCoverage([]SwitchACL{good}, nil).Status != "complete" || good.Index != 0 || good.Protocol != "tcp_udp" || !good.Destination.MatchesPort(443) || !slices.Equal(good.Source.NetworkIDs, []string{"network"}) {
		t.Fatalf("unexpected ACL: %+v", good)
	}
	for _, tc := range []struct{ old, new, field string }{
		{`"enabled":true,`, "", "enabled"}, {`"enabled":true`, `"enabled":false,"new_flag":false`, "new_flag"},
		{`"ports":[443]`, `"ports":[443],"new_filter":[]`, "traffic_destination.new_filter"},
		{`"ports":[443]`, `"ports":[65536]`, "ports"},
		{"192.0.2.0/24", "bad address", "ips_or_subnets"},
		{"02:00:00:00:00:01", "02:00:00:00:00:02", "specific_enforcers"},
		{`["object"]`, `["missing"]`, "network_ids"},
		{`"TCP_AND_UDP"`, `"QUIC"`, "ip_acl_protocol"},
		{`"IP_OR_SUBNET"`, `"NEXT_TYPE"`, "traffic_destination"},
		{`"acl_index":0,`, "", "acl_index"},
		{`"type":"NETWORK","network_ids":["object"]`, `"type":"CLIENT_MAC","specific_mac_addresses":["invalid"]`, "traffic_source"},
	} {
		got := decodeV2ACL(json.RawMessage(strings.Replace(row, tc.old, tc.new, 1)), nets, dev)
		cov := aclCoverage([]SwitchACL{got}, nil)
		if cov.Status != "partial" || !strings.Contains(cov.Reason, tc.field) {
			t.Errorf("%s: %+v", tc.field, cov)
		}
	}
	var v1 integrationACLRule
	if err := json.Unmarshal([]byte(`{"id":"acl","type":"IPV4","action":"BLOCK","enabled":false,"index":0,"sourceFilter":{"type":"PORTS","portFilter":[443],"newPredicate":true}}`), &v1); err != nil {
		t.Fatal(err)
	}
	if cov := aclCoverage(convertIntegrationACLs([]integrationACLRule{v1}, dev), nil); cov.Status != "partial" || !strings.Contains(cov.Reason, "sourceFilter.newPredicate") {
		t.Fatal(cov)
	}

	// Explicit JSON null on optional fields, device ID enforcers, disabled
	// index-sharing rules, and extra metadata on zones/groups must decode cleanly.
	var v1Null integrationACLRule
	if err := json.Unmarshal([]byte(`{"id":"acl-null","type":"IPV4","action":"BLOCK","enabled":true,"index":0,"description":null,"protocolFilter":null,"sourceFilter":{"type":"ANY"},"destinationFilter":{"type":"ANY"}}`), &v1Null); err != nil {
		t.Fatal(err)
	}
	if cov := aclCoverage(convertIntegrationACLs([]integrationACLRule{v1Null}, dev), nil); cov.Status != "complete" {
		t.Fatalf("expected v1 ACL with null optional fields to be complete, got %+v", cov)
	}

	devWithID := aliases{"02:00:00:00:00:01": "02:00:00:00:00:01", "sw-oid-1": "02:00:00:00:00:01"}
	v2NullAndID := decodeV2ACL(json.RawMessage(`{"_id":"acl-2","description":null,"predefined_id":"tpl-1","enabled":true,"acl_index":0,"type":"IPV4","action":"BLOCK","ip_acl_protocol":"ALL","specific_enforcers":["sw-oid-1"],"mac_acl_network_id":null,"traffic_source":{"type":"ANY","ports":null},"traffic_destination":{"type":"ANY","ports":null}}`), nets, devWithID)
	v2DisabledSameIdx := decodeV2ACL(json.RawMessage(`{"_id":"acl-3","enabled":false,"acl_index":0,"type":"IPV4","action":"ALLOW","ip_acl_protocol":"ALL","traffic_source":{"type":"ANY"},"traffic_destination":{"type":"ANY"}}`), nets, devWithID)
	if cov := aclCoverage([]SwitchACL{v2NullAndID, v2DisabledSameIdx}, nil); cov.Status != "complete" || !slices.Equal(v2NullAndID.DeviceMACs, []string{"02:00:00:00:00:01"}) {
		t.Fatalf("expected v2 ACL with null optionals, predefined_id, device ID enforcer, and disabled same-index peer to be complete, got cov=%+v acl=%+v", cov, v2NullAndID)
	}

	// Null list elements and mismatched selector types in v1 ACLs must degrade to partial.
	for _, badV1 := range []string{
		`{"id":"acl-null-elem","type":"MAC","action":"BLOCK","enabled":true,"index":0,"networkIds":[null],"sourceFilter":{"type":"ANY"},"destinationFilter":{"type":"ANY"}}`,
		`{"id":"acl-mismatch","type":"IPV4","action":"BLOCK","enabled":true,"index":0,"sourceFilter":{"type":"NETWORKS","ipAddressesOrSubnets":["192.0.2.0/24"]},"destinationFilter":{"type":"ANY"}}`,
	} {
		var bad integrationACLRule
		if err := json.Unmarshal([]byte(badV1), &bad); err != nil {
			t.Fatal(err)
		}
		if cov := aclCoverage(convertIntegrationACLs([]integrationACLRule{bad}, dev), nil); cov.Status != "partial" {
			t.Fatalf("expected partial coverage for malformed v1 ACL %s, got %+v", badV1, cov)
		}
	}

	var zoneWithExtra v2Zone
	if err := json.Unmarshal([]byte(`{"_id":"z1","name":"IoT","network_ids":["n1"],"future_meta":"ignored"}`), &zoneWithExtra); err != nil || zoneWithExtra.Name != "IoT" {
		t.Fatalf("v2Zone should ignore unknown metadata keys: err=%v zone=%+v", err, zoneWithExtra)
	}
	var groupWithExtra firewallGroup
	if err := json.Unmarshal([]byte(`{"_id":"g1","group_type":"port-group","group_members":["443"],"future_meta":true}`), &groupWithExtra); err != nil || len(groupWithExtra.Members) != 1 {
		t.Fatalf("firewallGroup should ignore unknown metadata keys: err=%v group=%+v", err, groupWithExtra)
	}
}

// TestPolicySelectorsAndGuestOverrides checks conditional semantics shared by both APIs.
func TestPolicySelectorsAndGuestOverrides(t *testing.T) {
	nets := aliases{"oid": "net"}
	zones := map[string]FirewallZone{"a": {ID: "a", Name: "Hotspot"}, "b": {ID: "b", Name: "External"}}
	var wireGroup firewallGroup
	if err := json.Unmarshal([]byte(`{"_id":"pg","external_id":"list","name":"Ports","group_type":"port-group","group_members":["443","1000-1100"]}`), &wireGroup); err != nil {
		t.Fatal(err)
	}
	g := indexGroups([]firewallGroup{wireGroup, {ID: "ipg", Type: "address-group", Members: []string{"192.0.2.0/24"}}})
	w := v2Policy{Name: "Post-Authorization Restrictions", Action: "BLOCK", Family: "IPV4", Protocol: "all", StateType: "RESPOND_ONLY", Return: true, IPSecType: "MATCH_IP_SEC", Source: v2Endpoint{Target: "ANY", Zone: "a", PortType: "ANY"}, Destination: v2Endpoint{Target: "ANY", Zone: "b", PortType: "ANY"}}
	on := true
	w.Predefined = &on
	p := w.policy(zones, nets, g)
	if p.UnsupportedReason != "" || p.MatchReturnTraffic || !slices.Equal(p.ConnectionStates, []string{"established", "related"}) {
		t.Fatalf("bad conditional semantics: %+v", p)
	}
	w.IPSec = true
	if w.policy(zones, nets, g).UnsupportedReason == "" {
		t.Fatal("lost IPsec constraint")
	}
	w.IPSec = false
	w.ICMP = "ECHO_REQUEST"
	if w.policy(zones, nets, g).UnsupportedReason == "" {
		t.Fatal("lost ICMP constraint")
	}
	rows := []FirewallPolicy{p}
	applyGuestRestrictions(rows, readGuestRestrictions([]map[string]any{{"key": "guest_access", "restricted_subnet_12": "198.51.100.0/24", "allowed_subnet_1": "192.0.2.0/24"}}))
	if !slices.Equal(rows[0].Destination.IPs, []string{"198.51.100.0/24"}) {
		t.Fatal(rows)
	}
	rows[0] = p
	applyGuestRestrictions(rows, guestRestrictions{})
	if len(rows[0].Destination.IPs) != 3 {
		t.Fatal(rows)
	}
	rows[0] = p
	applyGuestRestrictions(rows, readGuestRestrictions([]map[string]any{{"key": "guest_access", "restricted_subnet_2": "invalid"}}))
	if rows[0].UnsupportedReason == "" {
		t.Fatal("invalid override became default")
	}
	e := v2Endpoint{Zone: "a", Target: "IP", Subtype: "OBJECT", IPGroup: "ipg", MatchMAC: true, MAC: "02:00:00:00:00:01", PortType: "OBJECT", PortGroup: "pg"}
	match := e.policyEndpoint(zones, nets, g)
	if match.UnsupportedSelector != "" || !match.MatchesPort(1050) || len(match.IPs) != 1 || len(match.MACs) != 1 {
		t.Fatal(match)
	}
	e.OppositeIPs = true
	if e.policyEndpoint(zones, nets, g).UnsupportedSelector == "" {
		t.Fatal("lost mixed negation")
	}
	var raw integrationFirewallPolicy
	err := json.Unmarshal([]byte(`{"index":0,"enabled":true,"action":{"type":"BLOCK","allowReturnTraffic":true},"ipsecFilter":"MATCH_ENCRYPTED","ipProtocolScope":{"ipVersion":"IPV4","protocolFilter":{"type":"NAMED_PROTOCOL","protocol":{"name":"icmp","typenameFilter":"ECHO_REQUEST"}}},"source":{"trafficFilter":{"type":"IP_ADDRESS","ipAddressFilter":{"items":[{"type":"IP_ADDRESS","value":"192.0.2.1"},{"type":"IP_ADDRESS_RANGE","start":"192.0.2.2","stop":"192.0.2.9"}]},"portFilter":{"items":[{"type":"PORT_NUMBER_RANGE","start":1000,"stop":1100}]}}}}`), &raw)
	if err != nil {
		t.Fatal(err)
	}
	v := convertIntegrationPolicies([]integrationFirewallPolicy{raw}, nil, nil)[0]
	if v.UnsupportedReason == "" || v.MatchReturnTraffic || v.Index != 0 || !v.Source.MatchesPort(1050) || !slices.Contains(v.Source.IPs, "192.0.2.2-192.0.2.9") {
		t.Fatal(v)
	}
}

// TestSourceTelemetry verifies that stored values do not override active discriminators.
func TestSourceTelemetry(t *testing.T) {
	yes, no := true, false
	r := rawPortForward{Src: "192.0.2.1", SrcLimitingEnabled: &no, DestinationIP: "198.51.100.1"}
	if p := convertPortForwards([]rawPortForward{r}, groupIndex{})[0]; p.IsSourceRestricted() || p.SourceUnknown || p.DestinationIP != r.DestinationIP {
		t.Fatal(p)
	}
	r.SrcLimitingEnabled = &yes
	r.SrcLimitingType = "FIREWALL_GROUP"
	r.SrcGroupID = "group"
	if !convertPortForwards([]rawPortForward{r}, groupIndex{})[0].SourceUnknown {
		t.Fatal("missing group accepted")
	}
	g := indexGroups([]firewallGroup{{ID: "group", Type: "address-group", Members: []string{"192.0.2.0/24"}}})
	if p := convertPortForwards([]rawPortForward{r}, g)[0]; p.SourceUnknown || !p.IsSourceRestricted() {
		t.Fatal(p)
	}
	if signalDBM(-64, 32) != -64 || signalDBM(0, -78) != -78 || signalDBM(0, 32) != 0 {
		t.Fatal("bad radio units")
	}
	f := fixedAliases([]rawHistoricalUser{
		{FixedIP: "192.0.2.1", Name: "unique-inactive"},
		{FixedIP: "192.0.2.2", Name: "stale-loser"},
		{UseFixedIP: true, FixedIP: "192.0.2.2", Name: "active-winner"},
		{FixedIP: "192.0.2.3", Name: "dup-a"},
		{FixedIP: "192.0.2.3", Name: "dup-b"},
		{FixedIP: "192.0.2.4", Name: "stale-should-not-win"},
		{UseFixedIP: true, FixedIP: "192.0.2.4", Name: ""},
	})
	if f["192.0.2.1"] != "unique-inactive" || f["192.0.2.2"] != "active-winner" || f["192.0.2.3"] != "" || f["192.0.2.4"] != "" {
		t.Fatalf("unexpected fixedAliases: %+v", f)
	}
	nets := []Network{{ID: "a", Subnet: "192.0.2.0/24"}, {ID: "b", Subnet: "192.0.2.0/24"}}
	c := Client{IP: "192.0.2.3"}
	assignClientNetwork(&c, "", "", nil, nets)
	if c.NetworkID != "" {
		t.Fatal("ambiguous subnet assigned")
	}
	nets[1].Subnet = "192.0.2.0/28"
	assignClientNetwork(&c, "", "", nil, nets)
	if c.NetworkID != "b" {
		t.Fatal("longest prefix lost")
	}
}

// TestReadContracts validates array and pagination integrity and retains successful log pages.
func TestReadContracts(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/null", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "null") })
	mux.HandleFunc("/object", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "{}") })
	mux.HandleFunc("/array", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "[]") })
	mux.HandleFunc("/stalled", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"offset":0,"count":0,"totalCount":5,"data":[]}`)
	})
	shrinkPage0 := 0
	mux.HandleFunc("/shrinking", func(w http.ResponseWriter, r *http.Request) {
		off := r.URL.Query().Get("offset")
		if off == "0" {
			shrinkPage0++
			if shrinkPage0 == 1 {
				fmt.Fprint(w, `{"offset":0,"count":1,"totalCount":2,"data":[{"id":"a"}]}`)
				return
			}
			fmt.Fprint(w, `{"offset":0,"count":1,"totalCount":1,"data":[{"id":"a"}]}`)
			return
		}
		// Collection shrank below offset=1 mid-traversal -> must retry from page 0.
		fmt.Fprint(w, `{"offset":1,"count":0,"totalCount":0,"data":[]}`)
	})
	mux.HandleFunc("/logs", func(w http.ResponseWriter, r *http.Request) {
		var p struct {
			Page int `json:"pageNumber"`
		}
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			t.Error(err)
		}
		if p.Page == 0 {
			fmt.Fprint(w, `{"data":[1],"page_number":0,"total_page_count":2}`)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c, _ := New(config.UniFiConfig{URL: srv.URL, APIKey: "fixture"})
	ctx := context.Background()
	for _, p := range []string{"/null", "/object"} {
		if _, err := getJSONArray[int](ctx, c, p); err == nil {
			t.Error("accepted", p)
		}
	}
	if v, err := getJSONArray[int](ctx, c, "/array"); err != nil || v == nil {
		t.Fatal(v, err)
	}
	for _, p := range []string{"/stalled", "/object"} {
		if _, err := fetchAllPages[int](ctx, c, p); err == nil {
			t.Error("accepted", p)
		}
	}
	if rows, err := fetchAllPages[struct{ ID string }](ctx, c, "/shrinking"); err != nil || len(rows) != 1 || shrinkPage0 != 2 {
		t.Fatalf("expected shrinking collection to retry and succeed, got rows=%v err=%v page0=%d", rows, err, shrinkPage0)
	}
	items, err := fetchLogPages[int](ctx, c, "/logs", 1, 2)
	var status *httpStatusError
	if !slices.Equal(items, []int{1}) || !errors.As(err, &status) || status.method != http.MethodPost {
		t.Fatal(items, err)
	}
	if _, err := readControllerBody(strings.NewReader(strings.Repeat(" ", maxControllerBodyBytes+1))); err == nil {
		t.Fatal("oversize body accepted")
	}
}
