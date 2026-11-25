// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package unifi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/karalabe/uniblue/internal/config"
)

func TestIntegrationACLRulesInternetToggleDomainAndPostAuthScoping(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/proxy/network/integration/v1/sites":
			_, _ = w.Write([]byte(`{"offset":0,"limit":200,"count":1,"totalCount":1,"data":[{"id":"site-1","name":"Default","internalReference":"default"}]}`))
		case "/proxy/network/integration/v1/sites/site-1/clients":
			_, _ = w.Write([]byte(`{"offset":0,"limit":200,"count":0,"totalCount":0,"data":[]}`))
		case "/proxy/network/integration/v1/sites/site-1/devices":
			_, _ = w.Write([]byte(`{"offset":0,"limit":200,"count":1,"totalCount":1,"data":[{"id":"dev-sw1","macAddress":"aa:bb:cc:dd:ee:01","ipAddress":"10.0.0.2","name":"Main Switch","model":"USW 24 PoE"}]}`))
		case "/proxy/network/integration/v1/sites/site-1/networks":
			_, _ = w.Write([]byte(`{"offset":0,"limit":200,"count":2,"totalCount":2,"data":[
				{"id":"net-iot","name":"Smart Devices","vlanId":99,"zoneId":"z-hot","isolationEnabled":false},
				{"id":"net-guest","name":"Guest Devices","vlanId":100,"zoneId":"z-hot","isolationEnabled":false}
			]}`))
		case "/proxy/network/integration/v1/sites/site-1/networks/net-iot":
			_, _ = w.Write([]byte(`{
				"id":"net-iot","name":"Smart Devices","vlanId":99,"zoneId":"z-hot",
				"isolationEnabled":false,"internetAccessEnabled":false,
				"ipv4Configuration":{"hostIpAddress":"10.99.0.1","prefixLength":16,"dhcpConfiguration":{"mode":"SERVER","domainName":"iot"}}
			}`))
		case "/proxy/network/integration/v1/sites/site-1/networks/net-guest":
			_, _ = w.Write([]byte(`{
				"id":"net-guest","name":"Guest Devices","vlanId":100,"zoneId":"z-hot",
				"isolationEnabled":false,"internetAccessEnabled":true,
				"ipv4Configuration":{"hostIpAddress":"10.100.0.1","prefixLength":16,"dhcpConfiguration":{"mode":"SERVER","domainName":"guest"}}
			}`))
		case "/proxy/network/integration/v1/sites/site-1/firewall/zones":
			_, _ = w.Write([]byte(`{"offset":0,"limit":200,"count":2,"totalCount":2,"data":[
				{"id":"z-hot","name":"Hotspot","networkIds":["net-iot","net-guest"]},
				{"id":"z-ext","name":"External","networkIds":[]}
			]}`))
		case "/proxy/network/integration/v1/sites/site-1/firewall/policies":
			_, _ = w.Write([]byte(`{"offset":0,"limit":200,"count":2,"totalCount":2,"data":[
				{
					"id":"p-postauth","name":"Post-Authorization Restrictions","enabled":true,"index":30002,
					"action":{"type":"BLOCK"},
					"source":{"zoneId":"z-hot"},
					"destination":{"zoneId":"z-ext"},
					"ipProtocolScope":{"ipVersion":"IPV4"},
					"metadata":{"origin":"SYSTEM_DEFINED"}
				},
				{
					"id":"p-protect","name":"Allow UniFi Protect","enabled":true,"index":10002,
					"action":{"type":"ALLOW"},
					"source":{"zoneId":"z-hot"},
					"destination":{
						"zoneId":"z-ext",
						"trafficFilter":{
							"type":"PORT",
							"portFilter":{"type":"TRAFFIC_MATCHING_LIST","matchOpposite":false,"trafficMatchingListId":"tml-protect"}
						}
					},
					"ipProtocolScope":{"ipVersion":"IPV4_AND_IPV6","protocolFilter":{"type":"NAMED_PROTOCOL","protocol":{"name":"TCP"}}}
				}
			]}`))
		case "/proxy/network/integration/v1/sites/site-1/traffic-matching-lists":
			_, _ = w.Write([]byte(`{"offset":0,"limit":200,"count":1,"totalCount":1,"data":[
				{
					"id":"tml-protect","type":"PORTS","name":"UniFi Protect (TCP)",
					"items":[{"type":"PORT_NUMBER","value":7080},{"type":"PORT_NUMBER","value":7442},{"type":"PORT_NUMBER","value":7444}]
				}
			]}`))
		case "/proxy/network/integration/v1/sites/site-1/acl-rules":
			_, _ = w.Write([]byte(`{"offset":0,"limit":200,"count":1,"totalCount":1,"data":[
				{
					"id":"acl-1","type":"IPV4","name":"Block IoT Peers","enabled":true,"index":10000,"action":"BLOCK",
					"protocolFilter":["TCP","UDP"],
					"networkIdFilter":"net-iot",
					"enforcingDeviceFilter":{"type":"DEVICES","deviceIds":["dev-sw1"]},
					"sourceFilter":{"type":"NETWORKS","networkIds":["net-iot"]},
					"destinationFilter":{"type":"NETWORKS","networkIds":["net-iot"],"portFilter":[443]}
				}
			]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	ctrl, err := New(config.UniFiConfig{
		URL:                srv.URL,
		APIKey:             "test-key",
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ctrl.Login(context.Background()); err != nil {
		t.Fatal(err)
	}
	snap, err := ctrl.FetchSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if snap.SwitchACLCoverage == nil || snap.SwitchACLCoverage.Status != "complete" {
		t.Fatalf("expected complete SwitchACLCoverage from /acl-rules, got %+v", snap.SwitchACLCoverage)
	}
	if snap.Visibility == nil || !snap.Visibility.SwitchACLsAvailable {
		t.Fatalf("expected SwitchACLsAvailable=true, got %+v", snap.Visibility)
	}
	if len(snap.SwitchACLs) != 1 || snap.SwitchACLs[0].Action != "BLOCK" || !slices.Equal(snap.SwitchACLs[0].DeviceMACs, []string{"aa:bb:cc:dd:ee:01"}) {
		t.Fatalf("unexpected SwitchACLs: %+v", snap.SwitchACLs)
	}

	byName := make(map[string]Network)
	for _, n := range snap.Networks {
		byName[n.Name] = n
	}
	iot := byName["Smart Devices"]
	if iot.InternetAccessEnabled == nil || *iot.InternetAccessEnabled {
		t.Fatalf("expected Smart Devices InternetAccessEnabled=false, got %v", iot.InternetAccessEnabled)
	}
	if iot.DomainName != "iot" {
		t.Fatalf("expected Smart Devices DomainName=iot, got %q", iot.DomainName)
	}
	guest := byName["Guest Devices"]
	if guest.InternetAccessEnabled == nil || !*guest.InternetAccessEnabled {
		t.Fatalf("expected Guest Devices InternetAccessEnabled=true, got %v", guest.InternetAccessEnabled)
	}
	if guest.DomainName != "guest" {
		t.Fatalf("expected Guest Devices DomainName=guest, got %q", guest.DomainName)
	}

	if len(snap.FirewallPolicies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(snap.FirewallPolicies))
	}
	postAuth := snap.FirewallPolicies[0]
	if postAuth.Destination.AnyTarget || !slices.Equal(postAuth.Destination.IPs, []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}) {
		t.Fatalf("expected SYSTEM_DEFINED Post-Authorization Restrictions on External to be scoped to RFC1918, got %+v", postAuth.Destination)
	}
	prot := snap.FirewallPolicies[1]
	if prot.Destination.UnsupportedSelector != "" || prot.Destination.AnyPort || !slices.Equal(prot.Destination.Ports, []int{7080, 7442, 7444}) {
		t.Fatalf("expected TRAFFIC_MATCHING_LIST port list to resolve cleanly, got %+v", prot.Destination)
	}
}

// TestSwitchACLWirePortAndAddressRestrictions verifies that UniFi Integration
// v1 OpenAPI switch ACL endpoint schemas (PORTS, IP_ADDRESSES_OR_SUBNETS, and
// NETWORKS with portFilter) decode accurately into PolicyEndpoint restrictions.
func TestSwitchACLWirePortAndAddressRestrictions(t *testing.T) {
	for _, tc := range []struct {
		label, wire string
		check       func(PolicyEndpoint) bool
	}{
		{
			label: "ports",
			wire:  `{"type":"PORTS","portFilter":[443]}`,
			check: func(e PolicyEndpoint) bool { return !e.AnyPort && e.MatchesPort(443) && !e.MatchesPort(80) },
		},
		{
			label: "subnet",
			wire:  `{"type":"IP_ADDRESSES_OR_SUBNETS","ipAddressesOrSubnets":["192.0.2.0/24"],"portFilter":[443]}`,
			check: func(e PolicyEndpoint) bool {
				return e.UnsupportedSelector == "" && slices.Contains(e.IPs, "192.0.2.0/24") && !e.AnyPort
			},
		},
		{
			label: "network and port",
			wire:  `{"type":"NETWORKS","networkIds":["9d44c2a7-b959-4e35-8b98-fe2999d87b5b"],"portFilter":[443]}`,
			check: func(e PolicyEndpoint) bool {
				return !e.AnyTarget && !e.AnyPort && e.MatchesPort(443) && !e.MatchesPort(80)
			},
		},
	} {
		t.Run(tc.label, func(t *testing.T) {
			var raw integrationACLRule
			if err := json.Unmarshal([]byte(`{"type":"IPV4","action":"BLOCK","enabled":true,"destinationFilter":`+tc.wire+`}`), &raw); err != nil {
				t.Fatal(err)
			}
			got := convertIntegrationACLs([]integrationACLRule{raw}, nil)[0]
			if !tc.check(got.Destination) {
				t.Fatalf("decoded %+v", got.Destination)
			}
		})
	}
}

// TestDeviceSpecificACLWithMissingInventory verifies that an enforcingDeviceFilter
// referencing an unknown device ID is flagged as unsupported rather than silently
// decoded as an unscoped site-wide ACL rule.
func TestDeviceSpecificACLWithMissingInventory(t *testing.T) {
	var raw integrationACLRule
	if err := json.Unmarshal([]byte(`{"type":"IPV4","action":"BLOCK","enabled":true,"enforcingDeviceFilter":{"type":"DEVICES","deviceIds":["934368d4-4be5-4b9f-b9a0-6db897f785d9"]}}`), &raw); err != nil {
		t.Fatal(err)
	}
	acls := convertIntegrationACLs([]integrationACLRule{raw}, map[string]string{})
	if len(acls) > 0 && len(acls[0].DeviceMACs) == 0 && acls[0].Source.UnsupportedSelector == "" && acls[0].Destination.UnsupportedSelector == "" {
		t.Fatal("unresolved device-specific ACL decoded as unscoped rule")
	}
}
