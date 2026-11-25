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
	if _, err := ctrl.FetchSnapshot(context.Background()); err == nil {
		t.Fatal("expected HTTP 200 meta.rc=error NoPermission to fail FetchSnapshot")
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
		TrafficFilter: &struct {
			Type            string `json:"type"`
			IPAddressFilter *struct {
				Type          string `json:"type"`
				MatchOpposite bool   `json:"matchOpposite"`
				Items         []struct {
					Type  string     `json:"type"`
					Value flexString `json:"value"`
				} `json:"items"`
			} `json:"ipAddressFilter"`
			PortFilter *struct {
				Type          string `json:"type"`
				MatchOpposite bool   `json:"matchOpposite"`
				Items         []struct {
					Type  string     `json:"type"`
					Value flexString `json:"value"`
					Start int        `json:"start"`
					End   int        `json:"end"`
				} `json:"items"`
			} `json:"portFilter"`
			NetworkFilter *struct {
				MatchOpposite bool     `json:"matchOpposite"`
				NetworkIDs    []string `json:"networkIds"`
			} `json:"networkFilter"`
			MACAddressFilter *flexMACFilter `json:"macAddressFilter"`
		}{
			PortFilter: &struct {
				Type          string `json:"type"`
				MatchOpposite bool   `json:"matchOpposite"`
				Items         []struct {
					Type  string     `json:"type"`
					Value flexString `json:"value"`
					Start int        `json:"start"`
					End   int        `json:"end"`
				} `json:"items"`
			}{
				Items: []struct {
					Type  string     `json:"type"`
					Value flexString `json:"value"`
					Start int        `json:"start"`
					End   int        `json:"end"`
				}{
					{Value: "22"},
					{Start: 400, End: 500},
				},
			},
		},
	}, map[string]string{"z1": "Internal"})
	if !ep.MatchesPort(22) || !ep.MatchesPort(443) || ep.MatchesPort(80) {
		t.Fatalf("expected wide range 400-500 + 22 to match 22 and 443, got %+v", ep)
	}

	// Overflow / out-of-range port bounds must not loop or produce invalid ports.
	badEp := convertPolicyEndpoint(integrationPolicyEndpoint{
		ZoneID: "z1",
		TrafficFilter: &struct {
			Type            string `json:"type"`
			IPAddressFilter *struct {
				Type          string `json:"type"`
				MatchOpposite bool   `json:"matchOpposite"`
				Items         []struct {
					Type  string     `json:"type"`
					Value flexString `json:"value"`
				} `json:"items"`
			} `json:"ipAddressFilter"`
			PortFilter *struct {
				Type          string `json:"type"`
				MatchOpposite bool   `json:"matchOpposite"`
				Items         []struct {
					Type  string     `json:"type"`
					Value flexString `json:"value"`
					Start int        `json:"start"`
					End   int        `json:"end"`
				} `json:"items"`
			} `json:"portFilter"`
			NetworkFilter *struct {
				MatchOpposite bool     `json:"matchOpposite"`
				NetworkIDs    []string `json:"networkIds"`
			} `json:"networkFilter"`
			MACAddressFilter *flexMACFilter `json:"macAddressFilter"`
		}{
			IPAddressFilter: &struct {
				Type          string `json:"type"`
				MatchOpposite bool   `json:"matchOpposite"`
				Items         []struct {
					Type  string     `json:"type"`
					Value flexString `json:"value"`
				} `json:"items"`
			}{Type: "TRAFFIC_MATCHING_LIST"},
			PortFilter: &struct {
				Type          string `json:"type"`
				MatchOpposite bool   `json:"matchOpposite"`
				Items         []struct {
					Type  string     `json:"type"`
					Value flexString `json:"value"`
					Start int        `json:"start"`
					End   int        `json:"end"`
				} `json:"items"`
			}{
				Items: []struct {
					Type  string     `json:"type"`
					Value flexString `json:"value"`
					Start int        `json:"start"`
					End   int        `json:"end"`
				}{
					{Start: math.MaxInt - 1, End: math.MaxInt},
				},
			},
		},
	}, map[string]string{"z1": "Internal"})
	if badEp.UnsupportedSelector == "" {
		t.Fatalf("expected empty reference IPAddressFilter / invalid port range to mark UnsupportedSelector, got %+v", badEp)
	}

	if got := inferDeviceTypeFromModel("UXGPRO"); got != "ugw" {
		t.Fatalf("inferDeviceTypeFromModel(UXGPRO) = %q, want ugw", got)
	}
	if got := inferDeviceTypeFromModel("US8P60"); got != "usw" {
		t.Fatalf("inferDeviceTypeFromModel(US8P60) = %q, want usw", got)
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

	// Display-name site resolution must update c.site to InternalReference and report missing switch-ports.
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
	if snap.Site != "office-ref" {
		t.Fatalf("expected resolved site internalReference office-ref, got %q", snap.Site)
	}
	if snap.Devices[0].Type != "ugw" {
		t.Fatalf("expected model-derived ugw type, got %q", snap.Devices[0].Type)
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
