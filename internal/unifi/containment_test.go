// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package unifi

import (
	"context"
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
			_, _ = w.Write([]byte(`{"offset":0,"limit":200,"count":1,"totalCount":1,"data":[
				{
					"id":"p-postauth","name":"Post-Authorization Restrictions","enabled":true,"index":30002,
					"action":{"type":"BLOCK"},
					"source":{"zoneId":"z-hot"},
					"destination":{"zoneId":"z-ext"},
					"ipProtocolScope":{"ipVersion":"IPV4"},
					"metadata":{"origin":"SYSTEM_DEFINED"}
				}
			]}`))
		case "/proxy/network/integration/v1/sites/site-1/acl-rules":
			_, _ = w.Write([]byte(`{"offset":0,"limit":200,"count":1,"totalCount":1,"data":[
				{
					"id":"acl-1","type":"IPV4","name":"Block IoT Peers","enabled":true,"index":10000,"action":"BLOCK",
					"protocolFilter":["TCP","UDP"],
					"networkIdFilter":"net-iot",
					"enforcingDeviceFilter":{"type":"DEVICE_IDS","deviceIds":["dev-sw1"]},
					"sourceFilter":{"type":"NETWORK","networkIds":["net-iot"]},
					"destinationFilter":{"type":"NETWORK","networkIds":["net-iot"]}
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

	if len(snap.FirewallPolicies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(snap.FirewallPolicies))
	}
	postAuth := snap.FirewallPolicies[0]
	if postAuth.Destination.AnyTarget || !slices.Equal(postAuth.Destination.IPs, []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}) {
		t.Fatalf("expected SYSTEM_DEFINED Post-Authorization Restrictions on External to be scoped to RFC1918, got %+v", postAuth.Destination)
	}
}
