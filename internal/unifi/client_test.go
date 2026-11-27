// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package unifi

import (
	"bufio"
	"bytes"
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/karalabe/uniblue/internal/config"
)

// TestFetchSnapshotUniFiOS verifies UniFi OS cookie login with CSRF propagation
// and legacy REST snapshot assembly under /proxy/network.
func TestFetchSnapshotUniFiOS(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-CSRF-Token", "csrf-123")
		http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: "session-ok"})
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/proxy/network/api/s/default/stat/sta", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-CSRF-Token") != "csrf-123" {
			t.Errorf("missing csrf token header")
		}
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[{"mac":"AA:BB:CC:DD:EE:FF","ip":"192.168.20.42","hostname":"ventilation","oui":"AcmeHVAC","network_id":"net-iot","is_wired":true}]}`))
	})
	mux.HandleFunc("/proxy/network/api/s/default/stat/device", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[{"mac":"11:22:33:44:55:66","ip":"192.168.1.1","name":"UDM-Pro","model":"UDMPRO","type":"udm","version":"4.0.6","upgradable":true}]}`))
	})
	mux.HandleFunc("/proxy/network/api/s/default/rest/networkconf", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[{"_id":"net-iot","name":"IoT","purpose":"corporate","vlan":20,"ip_subnet":"192.168.20.1/24"}]}`))
	})
	mux.HandleFunc("/proxy/network/api/s/default/rest/portforward", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[{"_id":"pf-1","name":"HVAC-Web","enabled":true,"proto":"tcp","dst_port":8080,"fwd":"192.168.20.42","fwd_port":"80","src":"any"}]}`))
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	ctrl, err := New(config.UniFiConfig{
		URL:                srv.URL,
		Site:               "default",
		Username:           "uniblue",
		Password:           "secret",
		InsecureSkipVerify: true,
		Timeout:            5 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	snap, err := ctrl.FetchSnapshot(context.Background())
	if err != nil {
		t.Fatalf("FetchSnapshot: %v", err)
	}
	if snap.ControllerType != controllerUniFiOS {
		t.Fatalf("controller type = %q, want %q", snap.ControllerType, controllerUniFiOS)
	}
	if len(snap.Clients) != 1 {
		t.Fatalf("clients = %d, want 1", len(snap.Clients))
	}
	cl := snap.Clients[0]
	if cl.MAC != "aa:bb:cc:dd:ee:ff" || cl.NetworkName != "IoT" || cl.VLAN != "20" {
		t.Fatalf("unexpected client resolution: %+v", cl)
	}
	if len(snap.PortForwards) != 1 || !snap.PortForwards[0].ExposesPort(80) {
		t.Fatalf("expected port forward to expose port 80: %+v", snap.PortForwards)
	}
}

// TestFetchSnapshotClassicFallback verifies automatic fallback to /api/login
// when /api/auth/login returns 404 on classic controllers.
func TestFetchSnapshotClassicFallback(t *testing.T) {
	mux := http.NewServeMux()
	// Classic Cloud Key returns 404 for /api/auth/login and uses /api/login instead.
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "unifises", Value: "classic-ok"})
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/s/default/stat/sta", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[{"mac":"00:11:22:33:44:55","ip":"192.168.1.50","hostname":"nas","network":"LAN"}]}`))
	})
	mux.HandleFunc("/api/s/default/stat/device", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[]}`))
	})
	mux.HandleFunc("/api/s/default/rest/networkconf", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[{"_id":"n1","name":"LAN","purpose":"corporate","vlan":""}]}`))
	})
	mux.HandleFunc("/api/s/default/rest/portforward", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[]}`))
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	ctrl, err := New(config.UniFiConfig{
		URL:                srv.URL,
		Site:               "default",
		Username:           "admin",
		Password:           "secret",
		InsecureSkipVerify: true,
		Timeout:            5 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	snap, err := ctrl.FetchSnapshot(context.Background())
	if err != nil {
		t.Fatalf("FetchSnapshot: %v", err)
	}
	if snap.ControllerType != controllerClassic {
		t.Fatalf("controller type = %q, want %q", snap.ControllerType, controllerClassic)
	}
	if len(snap.Clients) != 1 || snap.Clients[0].Hostname != "nas" {
		t.Fatalf("unexpected clients: %+v", snap.Clients)
	}
}

// TestFetchSnapshotIntegrationV1 verifies API-key authentication, offset
// pagination, CIDR-based VLAN resolution, and graceful 401 degradation on legacy endpoints.
func TestFetchSnapshotIntegrationV1(t *testing.T) {
	mux := http.NewServeMux()
	checkKey := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("X-API-Key") != "test-api-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return false
		}
		return true
	}

	mux.HandleFunc("/proxy/network/integration/v1/sites", func(w http.ResponseWriter, r *http.Request) {
		if !checkKey(w, r) {
			return
		}
		_, _ = w.Write([]byte(`{"offset":0,"limit":200,"count":1,"totalCount":1,"data":[{"id":"site-uuid-1","name":"Default","internalReference":"default"}]}`))
	})
	mux.HandleFunc("/proxy/network/integration/v1/sites/site-uuid-1/clients", func(w http.ResponseWriter, r *http.Request) {
		if !checkKey(w, r) {
			return
		}
		// Simulate two paginated pages to verify offset pagination.
		if r.URL.Query().Get("offset") == "0" {
			_, _ = w.Write([]byte(`{"offset":0,"limit":200,"count":1,"totalCount":2,"data":[{"id":"c1","name":"ventilation","type":"WIRED","macAddress":"AA:BB:CC:DD:EE:01","ipAddress":"192.168.20.42"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"offset":1,"limit":200,"count":1,"totalCount":2,"data":[{"id":"c2","name":"workstation","type":"WIRELESS","macAddress":"AA:BB:CC:DD:EE:02","ipAddress":"192.168.1.50"}]}`))
	})
	mux.HandleFunc("/proxy/network/integration/v1/sites/site-uuid-1/devices", func(w http.ResponseWriter, r *http.Request) {
		if !checkKey(w, r) {
			return
		}
		_, _ = w.Write([]byte(`{"offset":0,"limit":200,"count":1,"totalCount":1,"data":[{"id":"d1","macAddress":"11:22:33:44:55:66","ipAddress":"192.168.1.1","name":"UDM-Pro","model":"UDMPro","state":"ONLINE","firmwareVersion":"4.1.13","firmwareUpdatable":true}]}`))
	})
	mux.HandleFunc("/proxy/network/integration/v1/sites/site-uuid-1/networks", func(w http.ResponseWriter, r *http.Request) {
		if !checkKey(w, r) {
			return
		}
		_, _ = w.Write([]byte(`{"offset":0,"limit":200,"count":2,"totalCount":2,"data":[
			{"id":"n1","name":"Default","vlanId":1,"management":"GATEWAY","ipv4Configuration":{"hostIpAddress":"192.168.1.1","prefixLength":24}},
			{"id":"n2","name":"IoT","vlanId":20,"management":"GATEWAY","ipv4Configuration":{"hostIpAddress":"192.168.20.1","prefixLength":24}}
		]}`))
	})
	// Legacy portforward endpoint returns 401 for integration-scoped API keys;
	// verify UniBlue degrades gracefully without failing the snapshot.
	mux.HandleFunc("/proxy/network/api/s/default/rest/portforward", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	ctrl, err := New(config.UniFiConfig{
		URL:                srv.URL,
		Site:               "default",
		APIKey:             "test-api-key",
		InsecureSkipVerify: true,
		Timeout:            5 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	snap, err := ctrl.FetchSnapshot(context.Background())
	if err != nil {
		t.Fatalf("FetchSnapshot: %v", err)
	}
	if snap.ControllerType != controllerIntegrationV1 {
		t.Fatalf("controller type = %q, want %q", snap.ControllerType, controllerIntegrationV1)
	}
	if len(snap.Clients) != 2 {
		t.Fatalf("clients = %d, want 2 (paginated)", len(snap.Clients))
	}
	if snap.Clients[0].NetworkName != "IoT" || snap.Clients[0].VLAN != "20" || !snap.Clients[0].IsWired {
		t.Fatalf("expected subnet-resolved IoT VLAN for client 0, got %+v", snap.Clients[0])
	}
	if snap.Clients[1].NetworkName != "Default" || snap.Clients[1].VLAN != "1" || snap.Clients[1].IsWired {
		t.Fatalf("expected subnet-resolved Default VLAN for client 1, got %+v", snap.Clients[1])
	}
	if len(snap.Devices) != 1 || !snap.Devices[0].Upgradable {
		t.Fatalf("unexpected devices: %+v", snap.Devices)
	}
}

// TestPortMatchesSpec verifies single-port, range, and comma-separated UniFi port specs.
func TestPortMatchesSpec(t *testing.T) {
	tests := []struct {
		spec string
		port int
		want bool
	}{
		{"80", 80, true},
		{"80", 443, false},
		{"8000-8010", 8005, true},
		{"8000-8010", 8011, false},
		{"80,443,8080-8082", 8081, true},
	}
	for _, tc := range tests {
		if got := portMatchesSpec(tc.spec, tc.port); got != tc.want {
			t.Errorf("portMatchesSpec(%q, %d) = %v, want %v", tc.spec, tc.port, got, tc.want)
		}
	}
}

// TestFetchSnapshotFirewallVisibilityAndPolicySemantics verifies that HTTP 403
// marks GatewayPoliciesAvailable false while 200 OK preserves rule order, state,
// negation, and unsupported filter markers.
func TestFetchSnapshotFirewallVisibilityAndPolicySemantics(t *testing.T) {
	// Verify Integration v1 HTTP 403 on firewall/policies marks GatewayPoliciesAvailable=false,
	// while a 200 OK response preserves Index, ConnectionStates, MatchReturnTraffic,
	// MatchOpposite negation, and marks unsupported REGION filters instead of AnyTarget=true.
	policiesStatus := http.StatusForbidden
	mux := http.NewServeMux()
	mux.HandleFunc("/proxy/network/integration/v1/sites", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"offset":0,"limit":200,"count":1,"totalCount":1,"data":[{"id":"site-1","name":"Default","internalReference":"default"}]}`))
	})
	mux.HandleFunc("/proxy/network/integration/v1/sites/site-1/clients", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"offset":0,"limit":200,"count":0,"totalCount":0,"data":[]}`))
	})
	mux.HandleFunc("/proxy/network/integration/v1/sites/site-1/devices", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"offset":0,"limit":200,"count":0,"totalCount":0,"data":[]}`))
	})
	mux.HandleFunc("/proxy/network/integration/v1/sites/site-1/networks", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"offset":0,"limit":200,"count":0,"totalCount":0,"data":[]}`))
	})
	mux.HandleFunc("/proxy/network/integration/v1/sites/site-1/firewall/zones", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"offset":0,"limit":200,"count":2,"totalCount":2,"data":[{"id":"z-guest","name":"Hotspot"},{"id":"z-mgmt","name":"Management"}]}`))
	})
	mux.HandleFunc("/proxy/network/integration/v1/sites/site-1/firewall/policies", func(w http.ResponseWriter, r *http.Request) {
		if policiesStatus != http.StatusOK {
			w.WriteHeader(policiesStatus)
			return
		}
		_, _ = w.Write([]byte(`{"offset":0,"limit":200,"count":2,"totalCount":2,"data":[
			{
				"id":"p-neg","name":"Negated IPv6 Allow","enabled":true,"index":10,
				"action":{"type":"ALLOW","allowReturnTraffic":true},
				"connectionStateFilter":["NEW"],
				"ipProtocolScope":{"ipVersion":"IPV6","protocolFilter":{"protocol":{"name":"TCP"}}},
				"source":{"zoneId":"z-guest","trafficFilter":{"type":"IP_ADDRESS","ipAddressFilter":{"matchOpposite":true,"items":[{"value":"2001:db8:50::1"}]}}},
				"destination":{"zoneId":"z-mgmt","trafficFilter":{"type":"REGION"}}
			},
			{
				"id":"p-block","name":"Higher Priority Block","enabled":true,"index":5,
				"action":{"type":"BLOCK"},
				"ipProtocolScope":{"ipVersion":"IPV4","protocolFilter":{"type":"PRESET","preset":"TCP_UDP"}},
				"source":{"zoneId":"z-guest","trafficFilter":{"type":"MAC_ADDRESS","macAddressFilter":"aa:bb:cc:dd:ee:01"}},
				"destination":{"zoneId":"z-mgmt"}
			}
		]}`))
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	ctrl, err := New(config.UniFiConfig{URL: srv.URL, Site: "default", APIKey: "k", InsecureSkipVerify: true, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// 1. HTTP 403 on firewall/policies must mark GatewayPoliciesAvailable false.
	snap403, err := ctrl.FetchSnapshot(context.Background())
	if err != nil {
		t.Fatalf("FetchSnapshot(403): %v", err)
	}
	if snap403.Visibility == nil || snap403.Visibility.GatewayPoliciesAvailable {
		t.Fatalf("expected GatewayPoliciesAvailable=false on HTTP 403, got %+v", snap403.Visibility)
	}

	// 2. HTTP 200 OK must mark GatewayPoliciesAvailable true and preserve wire fields.
	policiesStatus = http.StatusOK
	snapOK, err := ctrl.FetchSnapshot(context.Background())
	if err != nil {
		t.Fatalf("FetchSnapshot(200): %v", err)
	}
	if snapOK.Visibility == nil || !snapOK.Visibility.GatewayPoliciesAvailable {
		t.Fatalf("expected GatewayPoliciesAvailable=true on HTTP 200, got %+v", snapOK.Visibility)
	}
	if len(snapOK.FirewallPolicies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(snapOK.FirewallPolicies))
	}
	p0 := snapOK.FirewallPolicies[0]
	if p0.Index != 10 || !p0.MatchReturnTraffic || len(p0.ConnectionStates) != 1 || p0.ConnectionStates[0] != "new" {
		t.Fatalf("lost policy ordering/state semantics: %+v", p0)
	}
	if !p0.Source.NegateTarget || p0.Destination.AnyTarget || p0.Destination.UnsupportedSelector == "" {
		t.Fatalf("lost negation or unsupported REGION selector: src=%+v dst=%+v", p0.Source, p0.Destination)
	}
	p1 := snapOK.FirewallPolicies[1]
	if len(p1.Source.MACs) != 1 || p1.Source.MACs[0] != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("expected string-valued macAddressFilter to decode cleanly, got %+v", p1.Source)
	}
	if p1.Protocol != "tcp_udp" || p1.UnsupportedReason != "" {
		t.Fatalf("expected PRESET TCP_UDP protocol filter to decode cleanly, got proto=%q unsupported=%q", p1.Protocol, p1.UnsupportedReason)
	}

	// 3. Verify JSON site supplement preserves nested snake_case fields cleanly.
	supPath := filepath.Join(t.TempDir(), "supplement.json")
	supJSON := `{
		"proxy_routes":[{"proxy_ip":"10.0.0.5","hostname":"admin.test","public_exposed":true,"frontend_auth":false,"backend_ip":"10.0.0.6","backend_port":8080,"admin_vhost":true}],
		"dynamic_mappings":[{"protocol":"upnp","transport":"tcp","ext_port":8080,"internal_ip":"10.0.0.9","int_port":8080}]
	}`
	if err := os.WriteFile(supPath, []byte(supJSON), 0o600); err != nil {
		t.Fatalf("write supplement: %v", err)
	}
	if err := ApplySiteSupplement(snapOK, supPath); err != nil {
		t.Fatalf("ApplySiteSupplement: %v", err)
	}
	if len(snapOK.ProxyRoutes) != 1 || !snapOK.ProxyRoutes[0].PublicExposed || snapOK.ProxyRoutes[0].BackendPort != 8080 || snapOK.ProxyRoutes[0].FrontendAuth == nil || *snapOK.ProxyRoutes[0].FrontendAuth {
		t.Fatalf("ApplySiteSupplement dropped ProxyRoute fields: %+v", snapOK.ProxyRoutes)
	}
	if len(snapOK.DynamicMappings) != 1 || snapOK.DynamicMappings[0].InternalIP != "10.0.0.9" || snapOK.DynamicMappings[0].ExtPort != 8080 || snapOK.DynamicMappings[0].IntPort != 8080 {
		t.Fatalf("ApplySiteSupplement dropped DynamicPortMapping fields: %+v", snapOK.DynamicMappings)
	}
}

// TestControllerReloginEnvelopeErrorsAndWSTLS verifies automatic single-flight
// re-login after HTTP 401 or 200 meta.rc=error LoginRequired, rejection of
// non-auth 200 meta.rc=error responses, and WebSocket TLS verification honoring
// insecure_skip_verify=false.
func TestControllerReloginEnvelopeErrorsAndWSTLS(t *testing.T) {
	var logins atomic.Int32
	var expired atomic.Bool
	var returnPermErr atomic.Bool

	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		n := logins.Add(1)
		w.Header().Set("X-CSRF-Token", "csrf-"+string(rune('0'+n)))
		http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: "tok-" + string(rune('0'+n))})
		expired.Store(false)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/proxy/network/api/s/default/stat/sta", func(w http.ResponseWriter, r *http.Request) {
		if expired.Load() {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[{"mac":"02:aa:bb:00:00:01","ip":"192.0.2.50","is_wired":true,"tx_bytes":500,"wired-tx_bytes":500,"rx_bytes":800,"wired-rx_bytes":800,"network_id":"n1"}]}`))
	})
	mux.HandleFunc("/proxy/network/api/s/default/stat/device", func(w http.ResponseWriter, r *http.Request) {
		if expired.Load() {
			_, _ = w.Write([]byte(`{"meta":{"rc":"error","msg":"api.err.LoginRequired"},"data":[]}`))
			return
		}
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[]}`))
	})
	mux.HandleFunc("/proxy/network/api/s/default/rest/networkconf", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[{"_id":"n1","name":"Main","purpose":"corporate","ip_subnet":"192.0.2.1/24","dhcpd_enabled":true,"dhcpd_start":"192.0.2.100","dhcpd_stop":"192.0.2.150"}]}`))
	})
	mux.HandleFunc("/proxy/network/api/s/default/rest/portforward", func(w http.ResponseWriter, r *http.Request) {
		if returnPermErr.Load() {
			_, _ = w.Write([]byte(`{"meta":{"rc":"error","msg":"api.err.NoPermission"},"data":[]}`))
			return
		}
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[]}`))
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	ctrl, err := New(config.UniFiConfig{
		URL:                srv.URL,
		Site:               "default",
		Username:           "admin",
		Password:           "secret",
		InsecureSkipVerify: true,
		Timeout:            5 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	snap1, err := ctrl.FetchSnapshot(context.Background())
	if err != nil {
		t.Fatalf("first FetchSnapshot: %v", err)
	}
	// Static client 192.0.2.50 is outside DHCP pool .100-.150 -> ActiveLeases=0,
	// and wired TxBytes must not double-count tx_bytes + wired-tx_bytes.
	if snap1.Networks[0].ActiveLeases != 0 {
		t.Fatalf("expected 0 DHCP leases for static IP outside pool, got %d", snap1.Networks[0].ActiveLeases)
	}
	if snap1.Clients[0].TxBytes != 500 || snap1.Clients[0].RxBytes != 800 {
		t.Fatalf("expected single wired counter 500/800, got %d/%d", snap1.Clients[0].TxBytes, snap1.Clients[0].RxBytes)
	}

	// Simulate controller reboot invalidating session cookie.
	expired.Store(true)
	if _, err := ctrl.FetchSnapshot(context.Background()); err != nil {
		t.Fatalf("FetchSnapshot after session expiry should auto-relogin: %v", err)
	}
	if logins.Load() < 2 {
		t.Fatalf("expected re-login after expiry, logins=%d", logins.Load())
	}

	// HTTP 200 with meta.rc=error (NoPermission) must return an error, not empty data.
	returnPermErr.Store(true)
	snap, err := ctrl.FetchSnapshot(context.Background())
	if err != nil || snap.Visibility.PortForwardsAvailable || !strings.Contains(strings.Join(snap.Visibility.MissingFeeds, " "), "port-forwards") {
		t.Fatalf("optional feed failure: %v", err)
	}
	var direct apiEnvelope[rawPortForward]
	if err := ctrl.getJSON(context.Background(), "/proxy/network/api/s/default/rest/portforward", &direct); err == nil {
		t.Fatal("expected NoPermission envelope error")
	}

	// WebSocket must reject untrusted self-signed cert when insecure_skip_verify is false.
	strictCtrl, err := New(config.UniFiConfig{
		URL:                srv.URL,
		Site:               "default",
		Username:           "admin",
		Password:           "secret",
		InsecureSkipVerify: false,
		Timeout:            5 * time.Second,
	})
	if err != nil {
		t.Fatalf("New(strict): %v", err)
	}
	strictCtrl.controllerType = controllerUniFiOS
	strictCtrl.apiPrefix = "/proxy/network"
	err = strictCtrl.SubscribeEvents(context.Background(), make(chan Event, 1))
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("expected strict WebSocket TLS error for self-signed cert, got %v", err)
	}
}

// TestPolicyDecodingWideRangesBoundsNegationAndSiteRef verifies wide port
// ranges, MaxInt overflow guards, protocol matchOpposite, reference-only empty
// filters, model-derived device types, display-name site resolution, and
// missing switch-port feed reporting.
func TestPolicyDecodingWideRangesBoundsNegationAndSiteRef(t *testing.T) {
	// Wide port range (>16) and MaxInt overflow bound check.
	ep := convertPolicyEndpoint(integrationPolicyEndpoint{
		ZoneID: "z1",
		TrafficFilter: &integrationTrafficFilter{
			PortFilter: &integrationPortFilter{
				Items: []integrationPortFilterItem{
					{Value: "22"},
					{Start: 400, End: 500},
				},
			},
		},
	}, map[string]string{"z1": "Internal"}, nil)
	if !ep.MatchesPort(22) || !ep.MatchesPort(443) || ep.MatchesPort(80) {
		t.Fatalf("expected wide range 400-500 + 22 to match 22 and 443, got %+v", ep)
	}

	// Overflow / out-of-range port bounds must not loop or produce invalid ports.
	badEp := convertPolicyEndpoint(integrationPolicyEndpoint{
		ZoneID: "z1",
		TrafficFilter: &integrationTrafficFilter{
			IPAddressFilter: &integrationIPAddressFilter{Type: "TRAFFIC_MATCHING_LIST"},
			PortFilter: &integrationPortFilter{
				Items: []integrationPortFilterItem{
					{Start: math.MaxInt - 1, End: math.MaxInt},
				},
			},
		},
	}, map[string]string{"z1": "Internal"}, nil)
	if badEp.UnsupportedSelector == "" {
		t.Fatalf("expected empty reference IPAddressFilter / invalid port range to mark UnsupportedSelector, got %+v", badEp)
	}

	for _, tc := range []struct {
		model string
		want  string
	}{
		{"UXGPRO", "uxg"},
		{"UXG-Lite", "uxg"},
		{"USG-3P", "ugw"},
		{"UGW4", "ugw"},
		{"UDMPRO", "udm"},
		{"Dream Machine Pro", "udm"},
		{"UCG-Ultra", "udm"},
		{"UX", "udm"},
		{"UX7", "udm"},
		{"US8P60", "usw"},
		{"U7-Pro-Max", "uap"},
		{"UCK-G2-Plus", "uck"},
	} {
		if got := inferDeviceTypeFromModel(tc.model); got != tc.want {
			t.Fatalf("inferDeviceTypeFromModel(%q) = %q, want %q", tc.model, got, tc.want)
		}
	}

	// Verify fragmented WebSocket text frame reassembly via readWSFrame.
	var wire bytes.Buffer
	// Fragment 1: fin=0, opcode=1, len=4 ("{\"me")
	wire.Write([]byte{0x01, 0x04})
	wire.WriteString(`{"me`)
	// Fragment 2: fin=1, opcode=0, len=3 ("ta}")
	wire.Write([]byte{0x80, 0x03})
	wire.WriteString(`ta}`)
	br := bufio.NewReader(&wire)
	fin1, op1, p1, err := readWSFrame(br)
	if err != nil || fin1 || op1 != 0x1 || string(p1) != `{"me` {
		t.Fatalf("fragment 1 unexpected: fin=%v op=%d p=%q err=%v", fin1, op1, p1, err)
	}
	fin2, op2, p2, err := readWSFrame(br)
	if err != nil || !fin2 || op2 != 0x0 || string(p2) != `ta}` {
		t.Fatalf("fragment 2 unexpected: fin=%v op=%d p=%q err=%v", fin2, op2, p2, err)
	}

	// Display-name site resolution must update c.site to InternalReference for
	// API path routing while keeping Snapshot.Site at the configured display name
	// and reporting missing switch-ports.
	var routedLegacyDevice atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/proxy/network/integration/v1/sites", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"offset":0,"limit":200,"count":1,"totalCount":1,"data":[{"id":"s-1","name":"Office","internalReference":"office-ref"}]}`))
	})
	mux.HandleFunc("/proxy/network/integration/v1/sites/s-1/clients", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"offset":0,"limit":200,"count":0,"totalCount":0,"data":[]}`))
	})
	mux.HandleFunc("/proxy/network/integration/v1/sites/s-1/devices", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"offset":0,"limit":200,"count":1,"totalCount":1,"data":[{"id":"d1","macAddress":"02:aa:bb:00:00:09","ipAddress":"192.0.2.1","name":"GW","model":"UXGPRO","state":"ONLINE"}]}`))
	})
	mux.HandleFunc("/proxy/network/integration/v1/sites/s-1/networks", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"offset":0,"limit":200,"count":0,"totalCount":0,"data":[]}`))
	})
	mux.HandleFunc("/proxy/network/api/s/office-ref/stat/device", func(w http.ResponseWriter, r *http.Request) {
		routedLegacyDevice.Store(true)
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	ctrl, err := New(config.UniFiConfig{URL: srv.URL, Site: "Office", APIKey: "k", InsecureSkipVerify: true, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	snap, err := ctrl.FetchSnapshot(context.Background())
	if err != nil {
		t.Fatalf("FetchSnapshot(Office): %v", err)
	}
	if _, routedSite := ctrl.sessionPrefixAndSite(); routedSite != "office-ref" || !routedLegacyDevice.Load() {
		t.Fatalf("expected legacy API routing via office-ref (routed=%q hit=%v)", routedSite, routedLegacyDevice.Load())
	}
	if snap.Site != "Office" {
		t.Fatalf("expected Snapshot.Site to preserve configured display name Office, got %q", snap.Site)
	}
	if snap.Devices[0].Type != "uxg" {
		t.Fatalf("expected model-derived uxg type, got %q", snap.Devices[0].Type)
	}
	foundMissingPorts := false
	for _, mf := range snap.Visibility.MissingFeeds {
		if strings.HasPrefix(mf, "switch-ports") {
			foundMissingPorts = true
		}
	}
	if !foundMissingPorts {
		t.Fatalf("expected switch-ports missing feed on stat/device 401, got %v", snap.Visibility.MissingFeeds)
	}
}

// TestFailedReloginCoalescedWithCooldown verifies that concurrent 401 failures
// share a single failed re-login attempt within the cooldown window, avoid
// falling back to /api/login on a known UniFi OS console, and return the real
// login error instead of masking it.
func TestFailedReloginCoalescedWithCooldown(t *testing.T) {
	var uosLogins atomic.Int32
	var classicLogins atomic.Int32
	var rejectAll atomic.Bool

	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		uosLogins.Add(1)
		if rejectAll.Load() {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: "ok"})
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		classicLogins.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/proxy/network/api/s/default/stat/sta", func(w http.ResponseWriter, r *http.Request) {
		if rejectAll.Load() {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[]}`))
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	ctrl, err := New(config.UniFiConfig{
		URL:                srv.URL,
		Site:               "default",
		Username:           "uniblue",
		Password:           "secret",
		InsecureSkipVerify: true,
		Timeout:            5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ctrl.Login(context.Background()); err != nil {
		t.Fatalf("initial Login: %v", err)
	}

	rejectAll.Store(true)
	var wg sync.WaitGroup
	errs := make([]error, 10)
	for i := range errs {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			var out apiEnvelope[rawClient]
			errs[idx] = ctrl.getJSON(context.Background(), "/proxy/network/api/s/default/stat/sta", &out)
		}(i)
	}
	wg.Wait()

	if uosLogins.Load() != 2 {
		t.Fatalf("expected 1 initial + 1 coalesced failed relogin = 2 login POSTs, got %d", uosLogins.Load())
	}
	if classicLogins.Load() != 0 {
		t.Fatalf("expected 0 classic /api/login fallback POSTs on known UniFi OS console, got %d", classicLogins.Load())
	}
	for i, gotErr := range errs {
		if gotErr == nil || !strings.Contains(gotErr.Error(), "unifi-os login failed") {
			t.Fatalf("caller %d expected real login error, got %v", i, gotErr)
		}
	}
}

// TestPostJSON503Then401ReloginExecutesThirdPost verifies that postJSON performs
// the post-relogin request after a 503 retry encounters 401 instead of exiting
// the retry loop with a nil error and undecoded payload.
func TestPostJSON503Then401ReloginExecutesThirdPost(t *testing.T) {
	var posts atomic.Int32
	var logins atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		logins.Add(1)
		http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: "fresh"})
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/proxy/network/v2/api/site/default/system-log/all", func(w http.ResponseWriter, r *http.Request) {
		switch posts.Add(1) {
		case 1:
			w.WriteHeader(http.StatusServiceUnavailable)
		case 2:
			w.WriteHeader(http.StatusUnauthorized)
		default:
			_, _ = w.Write([]byte(`{"data":[{"id":"ev-1","category":"SECURITY","event":"THREAT_BLOCKED"}]}`))
		}
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	ctrl, err := New(config.UniFiConfig{
		URL:                srv.URL,
		Site:               "default",
		Username:           "uniblue",
		Password:           "secret",
		InsecureSkipVerify: true,
		Timeout:            5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ctrl.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}

	var resp struct {
		Data []rawSystemLogEntry `json:"data"`
	}
	if err := ctrl.postJSON(context.Background(), "/proxy/network/v2/api/site/default/system-log/all", map[string]any{"pageSize": 10}, &resp); err != nil {
		t.Fatalf("postJSON: %v", err)
	}
	if posts.Load() != 3 || logins.Load() != 2 || len(resp.Data) != 1 || resp.Data[0].ID != "ev-1" {
		t.Fatalf("expected 3 POSTs, 2 logins, and 1 decoded entry; got posts=%d logins=%d data=%+v", posts.Load(), logins.Load(), resp.Data)
	}
}

// TestPermissionDenied401AndPersistentWSRejectDoNotStormLogins verifies that
// HTTP 401 with NoPermission does not trigger re-login, and persistent bare
// 401/403 rejections on optional REST endpoints or WebSocket upgrades do not
// mint a fresh session on every poll or redial.
func TestPermissionDenied401AndPersistentWSRejectDoNotStormLogins(t *testing.T) {
	var logins atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		logins.Add(1)
		http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: "tok"})
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/proxy/network/api/s/default/stat/noperm", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"meta":{"rc":"error","msg":"api.err.NoPermission"},"data":[]}`))
	})
	mux.HandleFunc("/proxy/network/api/s/default/stat/bare401", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/proxy/network/wss/s/default/events", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	ctrl, err := New(config.UniFiConfig{
		URL:                srv.URL,
		Site:               "default",
		Username:           "uniblue",
		Password:           "secret",
		InsecureSkipVerify: true,
		Timeout:            5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ctrl.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}

	// 1. 401 with NoPermission must trigger 0 re-logins across repeated polls.
	for range 3 {
		var out apiEnvelope[rawClient]
		if err := ctrl.getJSON(context.Background(), "/proxy/network/api/s/default/stat/noperm", &out); err == nil {
			t.Fatal("expected error for NoPermission 401")
		}
	}
	if logins.Load() != 1 {
		t.Fatalf("expected 0 re-logins on 401 NoPermission (total logins=1), got %d", logins.Load())
	}

	// 2. Persistent bare 401 on an optional endpoint triggers at most 1 re-login across 3 polls.
	for range 3 {
		var out apiEnvelope[rawClient]
		if err := ctrl.getJSON(context.Background(), "/proxy/network/api/s/default/stat/bare401", &out); err == nil {
			t.Fatal("expected error for persistent bare 401")
		}
	}
	if logins.Load() != 2 {
		t.Fatalf("expected at most 1 re-login for persistent bare 401 (total logins=2), got %d", logins.Load())
	}

	// 3. Persistent 403 on WebSocket upgrade triggers at most 1 re-login across 3 redials.
	for range 3 {
		if err := ctrl.SubscribeEvents(context.Background(), make(chan Event, 1)); err == nil {
			t.Fatal("expected error for 403 WebSocket rejection")
		}
	}
	if logins.Load() != 3 {
		t.Fatalf("expected at most 1 re-login for persistent 403 WS upgrade (total logins=3), got %d", logins.Load())
	}
}

// TestConvertPolicyEndpointUnrecognizedTypeWithPortSibling verifies that
// unmodeled trafficFilter types (REGION, DOMAIN, APPLICATION) always set
// UnsupportedSelector and AnyTarget=false even when a sibling portFilter decoded.
func TestConvertPolicyEndpointUnrecognizedTypeWithPortSibling(t *testing.T) {
	for _, filterType := range []string{"REGION", "DOMAIN", "APPLICATION"} {
		ep := convertPolicyEndpoint(integrationPolicyEndpoint{
			ZoneID: "z1",
			TrafficFilter: &integrationTrafficFilter{
				Type: filterType,
				PortFilter: &integrationPortFilter{
					Items: []integrationPortFilterItem{{Value: "443"}},
				},
			},
		}, map[string]string{"z1": "Internal"}, nil)
		if ep.UnsupportedSelector == "" || ep.AnyTarget {
			t.Fatalf("filterType=%s with portFilter sibling must mark UnsupportedSelector and AnyTarget=false, got %+v", filterType, ep)
		}
		if !ep.MatchesPort(443) {
			t.Fatalf("filterType=%s should still retain decoded port 443, got %+v", filterType, ep)
		}
	}
}

// TestPortProfilesPrecedenceAndFailureVisibility verifies that setting_preference
// "auto" lets assigned port profiles override stale per-port values, "manual"
// keeps per-port overrides, and failed rest/portconf fetches record
// PortProfilesAvailable=false and a port-profiles MissingFeeds entry.
func TestPortProfilesPrecedenceAndFailureVisibility(t *testing.T) {
	tTrue := true
	tFalse := false
	netByID := map[string]Network{
		"net-lan": {ID: "net-lan", Name: "LAN"},
		"net-iot": {ID: "net-iot", Name: "IoT"},
	}
	portConfs := indexPortConfs([]rawPortConf{
		{
			ID:                  "prof-iot",
			NativeNetworkConfID: "net-iot",
			Forward:             "native",
			PortSecurityEnabled: &tTrue,
			PortSecurityMACs:    []string{"02:aa:bb:cc:dd:ee"},
		},
	})
	rd := rawDevice{
		PortTable: []rawPort{
			{
				PortIdx:             1,
				SettingPreference:   "auto",
				PortConfID:          "prof-iot",
				NativeNetworkConfID: "net-lan",
				Forward:             "all",
				TaggedVLANMgmt:      "auto",
				PortSecurityEnabled: &tFalse,
			},
			{
				PortIdx:             2,
				SettingPreference:   "manual",
				PortConfID:          "prof-iot",
				NativeNetworkConfID: "net-lan",
				Forward:             "all",
				TaggedVLANMgmt:      "auto",
				PortSecurityEnabled: &tFalse,
			},
		},
	}
	ports := convertSwitchPorts(rd, netByID, portConfs, "LAN")
	if len(ports) != 2 {
		t.Fatalf("expected 2 ports, got %d", len(ports))
	}
	if ports[0].NativeNetworkName != "IoT" || ports[0].TaggedVLANMgmt != "block_all" || !ports[0].PortSecurityEnabled {
		t.Fatalf("setting_preference=auto must let port profile override stale per-port values, got %+v", ports[0])
	}
	if ports[1].NativeNetworkName != "LAN" || ports[1].TaggedVLANMgmt != "auto" || ports[1].PortSecurityEnabled {
		t.Fatalf("setting_preference=manual must keep manual per-port values, got %+v", ports[1])
	}

	// Verify rest/portconf failure sets PortProfilesAvailable=false and records MissingFeeds.
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: "tok"})
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/proxy/network/api/s/default/stat/sta", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[]}`))
	})
	mux.HandleFunc("/proxy/network/api/s/default/stat/device", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[]}`))
	})
	mux.HandleFunc("/proxy/network/api/s/default/rest/networkconf", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[{"_id":"n1","name":"LAN","purpose":"corporate"}]}`))
	})
	mux.HandleFunc("/proxy/network/api/s/default/rest/portforward", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[]}`))
	})
	mux.HandleFunc("/proxy/network/api/s/default/rest/portconf", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"meta":{"rc":"error","msg":"api.err.NoPermission"},"data":[]}`))
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	ctrl, err := New(config.UniFiConfig{
		URL:                srv.URL,
		Site:               "default",
		Username:           "uniblue",
		Password:           "secret",
		InsecureSkipVerify: true,
		Timeout:            5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	snap, err := ctrl.FetchSnapshot(context.Background())
	if err != nil {
		t.Fatalf("FetchSnapshot: %v", err)
	}
	if snap.Visibility == nil || snap.Visibility.PortProfilesAvailable {
		t.Fatalf("expected PortProfilesAvailable=false on portconf failure, got %+v", snap.Visibility)
	}
	foundPortConfMissing := false
	for _, mf := range snap.Visibility.MissingFeeds {
		if strings.HasPrefix(mf, "port-profiles") {
			foundPortConfMissing = true
		}
	}
	if !foundPortConfMissing {
		t.Fatalf("expected port-profiles in MissingFeeds, got %v", snap.Visibility.MissingFeeds)
	}
}

// TestInterleavedRESTAndWSAuthRejectDoesNotPingPong verifies that alternating
// persistent bare 401 responses on optional REST paths and persistent 403
// responses on WebSocket upgrades do not invalidate each other's suppression
// and cause continuous re-logins.
func TestInterleavedRESTAndWSAuthRejectDoesNotPingPong(t *testing.T) {
	var logins atomic.Int32
	var allowBare atomic.Bool

	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		logins.Add(1)
		http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: "tok"})
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/proxy/network/api/s/default/stat/opt1", func(w http.ResponseWriter, r *http.Request) {
		if allowBare.Load() {
			_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[]}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/proxy/network/api/s/default/stat/opt2", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/proxy/network/wss/s/default/events", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	ctrl, err := New(config.UniFiConfig{
		URL:                srv.URL,
		Site:               "default",
		Username:           "uniblue",
		Password:           "secret",
		InsecureSkipVerify: true,
		Timeout:            5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ctrl.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}

	// Interleave REST opt1, WS, REST opt2 across 5 rounds. Each distinct source
	// may trigger at most one re-login (1 initial + 3 = 4 total), never ping-ponging.
	for range 5 {
		var out apiEnvelope[rawClient]
		if err := ctrl.getJSON(context.Background(), "/proxy/network/api/s/default/stat/opt1", &out); err == nil {
			t.Fatal("expected error for opt1 bare 401")
		}
		if err := ctrl.SubscribeEvents(context.Background(), make(chan Event, 1)); err == nil {
			t.Fatal("expected error for WS 403")
		}
		if err := ctrl.getJSON(context.Background(), "/proxy/network/api/s/default/stat/opt2", &out); err == nil {
			t.Fatal("expected error for opt2 bare 401")
		}
	}
	if got := logins.Load(); got != 4 {
		t.Fatalf("expected 4 total logins (1 initial + 1 per persistent source), got %d", got)
	}

	// Once opt1 succeeds, its suppression clears so a future genuine 401 can re-login again.
	allowBare.Store(true)
	var out apiEnvelope[rawClient]
	if err := ctrl.getJSON(context.Background(), "/proxy/network/api/s/default/stat/opt1", &out); err != nil {
		t.Fatalf("expected opt1 to succeed after permission granted: %v", err)
	}
	allowBare.Store(false)
	_ = ctrl.getJSON(context.Background(), "/proxy/network/api/s/default/stat/opt1", &out)
	if got := logins.Load(); got != 5 {
		t.Fatalf("expected cleared opt1 to allow one re-login on later expiry (total=5), got %d", got)
	}
}

// TestReloginCooldownIgnoresCallerTimeoutAndTransientErrors verifies that a
// caller timing out or cancelling during re-login (or a transient 503) does not
// activate the 30s auth-failure cooldown and block subsequent healthy callers.
func TestReloginCooldownIgnoresCallerTimeoutAndTransientErrors(t *testing.T) {
	var loginCalls atomic.Int32
	var slowLogin atomic.Bool
	var return503 atomic.Bool
	var expired atomic.Bool

	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		loginCalls.Add(1)
		if slowLogin.Load() {
			select {
			case <-time.After(300 * time.Millisecond):
			case <-r.Context().Done():
				return
			}
		}
		if return503.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		expired.Store(false)
		http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: "fresh"})
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/proxy/network/api/s/default/stat/sta", func(w http.ResponseWriter, r *http.Request) {
		if expired.Load() {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[]}`))
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	ctrl, err := New(config.UniFiConfig{
		URL:                srv.URL,
		Site:               "default",
		Username:           "uniblue",
		Password:           "secret",
		InsecureSkipVerify: true,
		Timeout:            5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctrl.transientReloginCooldown = 60 * time.Millisecond
	if err := ctrl.Login(context.Background()); err != nil {
		t.Fatalf("initial Login: %v", err)
	}

	// 1. Caller with a short deadline times out during relogin.
	expired.Store(true)
	slowLogin.Store(true)
	shortCtx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	var out apiEnvelope[rawClient]
	if err := ctrl.getJSON(shortCtx, "/proxy/network/api/s/default/stat/sta", &out); err == nil {
		t.Fatal("expected timeout error for short-deadline caller")
	}

	// Immediately afterward, a healthy caller must succeed without hitting any cooldown.
	slowLogin.Store(false)
	if err := ctrl.getJSON(context.Background(), "/proxy/network/api/s/default/stat/sta", &out); err != nil {
		t.Fatalf("healthy caller blocked after prior caller timeout: %v", err)
	}

	// 2. Transient HTTP 503 during relogin coalesces a burst of concurrent 401s
	// into one login attempt, then recovers right after the short transient window
	// (without engaging the full 30s credential lockout cooldown).
	expired.Store(true)
	return503.Store(true)
	before503 := loginCalls.Load()
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var tmp apiEnvelope[rawClient]
			_ = ctrl.getJSON(context.Background(), "/proxy/network/api/s/default/stat/sta", &tmp)
		}()
	}
	wg.Wait()
	if delta := loginCalls.Load() - before503; delta != 1 {
		t.Fatalf("expected 6 concurrent 401s on 503 login to coalesce into 1 login attempt, got %d", delta)
	}

	return503.Store(false)
	time.Sleep(80 * time.Millisecond)
	if err := ctrl.getJSON(context.Background(), "/proxy/network/api/s/default/stat/sta", &out); err != nil {
		t.Fatalf("healthy caller blocked after transient 503 burst window expired: %v", err)
	}
}

// TestSnapshotSitePreservesConfiguredDisplayName verifies that Integration v1
// routes legacy endpoints via the site's opaque internalReference while
// reporting the user-configured display site name in Snapshot.Site.
func TestSnapshotSitePreservesConfiguredDisplayName(t *testing.T) {
	var hitOpaqueRef atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/proxy/network/integration/v1/sites", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"offset":0,"limit":200,"count":1,"totalCount":1,"data":[{"id":"site-uuid-office","name":"Office","internalReference":"x8k2j3l1"}]}`))
	})
	mux.HandleFunc("/proxy/network/integration/v1/sites/site-uuid-office/clients", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"offset":0,"limit":200,"count":0,"totalCount":0,"data":[]}`))
	})
	mux.HandleFunc("/proxy/network/integration/v1/sites/site-uuid-office/devices", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"offset":0,"limit":200,"count":0,"totalCount":0,"data":[]}`))
	})
	mux.HandleFunc("/proxy/network/integration/v1/sites/site-uuid-office/networks", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"offset":0,"limit":200,"count":0,"totalCount":0,"data":[]}`))
	})
	mux.HandleFunc("/proxy/network/api/s/x8k2j3l1/rest/portforward", func(w http.ResponseWriter, r *http.Request) {
		hitOpaqueRef.Store(true)
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[]}`))
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	ctrl, err := New(config.UniFiConfig{
		URL:                srv.URL,
		Site:               "Office",
		APIKey:             "test-key",
		InsecureSkipVerify: true,
		Timeout:            5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	snap, err := ctrl.FetchSnapshot(context.Background())
	if err != nil {
		t.Fatalf("FetchSnapshot: %v", err)
	}
	if !hitOpaqueRef.Load() {
		t.Fatal("expected legacy REST call to route via opaque internalReference x8k2j3l1")
	}
	if snap.Site != "Office" {
		t.Fatalf("Snapshot.Site = %q, want Office", snap.Site)
	}
}

// TestFetchRecentLogsInterpolatesAdminTemplateParameters verifies that UniFi
// admin-activity log messages interpolate numeric, string, and object parameter
// values and strip any remaining unpopulated {PLACEHOLDER} tokens cleanly.
func TestFetchRecentLogsInterpolatesAdminTemplateParameters(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/proxy/network/v2/api/site/default/system-log/all", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[]}`))
	})
	mux.HandleFunc("/proxy/network/v2/api/site/default/system-log/admin-activity", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[
			{
				"id":"adm-1",
				"timestamp":1770000002000,
				"key":"ADMIN_SETTINGS_CHANGED",
				"ip":"10.0.0.5",
				"platform":"web",
				"message":"{ADMIN} made {COUNT} changes to {OBJECT} {SECTION} settings",
				"admin":{"name":"Alice"},
				"parameters":{"COUNT":3,"OBJECT":{"name":"UDM Pro"},"SECTION":"Firewall"}
			},
			{
				"id":"adm-2",
				"timestamp":1770000001000,
				"key":"ADMIN_SETTINGS_CHANGED",
				"ip":"10.0.0.5",
				"platform":"web",
				"message":"{ADMIN} made {COUNT} changes to {OBJECT} {SECTION} settings",
				"admin":{"name":"Bob"},
				"parameters":{"SECTION":"Network"}
			}
		]}`))
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	ctrl, err := New(config.UniFiConfig{
		URL:                srv.URL,
		Site:               "default",
		Username:           "viewer",
		Password:           "secret",
		InsecureSkipVerify: true,
		Timeout:            5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	logs, err := ctrl.FetchRecentLogs(context.Background(), time.Unix(1770000000, 0).UTC())
	if err != nil {
		t.Fatalf("FetchRecentLogs: %v", err)
	}
	if len(logs) != 2 {
		t.Fatalf("expected 2 admin log events, got %d (%+v)", len(logs), logs)
	}
	if logs[0].Message != "Alice made 3 changes to UDM Pro Firewall settings" {
		t.Fatalf("unexpected interpolated admin message: %q", logs[0].Message)
	}
	if logs[1].Message != "Bob made changes to Network settings" || strings.Contains(logs[1].Message, "{") {
		t.Fatalf("unexpected fallback admin message with missing params: %q", logs[1].Message)
	}
}

// TestAdoptedSSHPasswordSetting preserves the distinction between false and missing telemetry.
func TestAdoptedSSHPasswordSetting(t *testing.T) {
	for _, tc := range []struct {
		value          any
		enabled, known bool
	}{{nil, false, false}, {"false", false, false}, {false, false, true}, {true, true, true}} {
		row := map[string]any{"key": "mgmt", "x_ssh_enabled": true}
		if tc.value != nil {
			row["x_ssh_auth_password_enabled"] = tc.value
		}
		s := parseSecuritySettings([]map[string]any{row})
		if s.SSHPasswordAuth != tc.enabled || s.SSHPasswordAuthKnown != tc.known {
			t.Fatal(tc, s)
		}
	}
}
