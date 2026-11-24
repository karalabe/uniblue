package unifi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/karalabe/uniblue/internal/config"
)

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
