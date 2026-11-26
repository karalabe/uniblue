// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package unifi

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/karalabe/uniblue/internal/config"
)

// TestLoginDiscoveryContracts distinguishes API errors from missing mounts and
// prevents an unsuccessful probe from publishing a controller mode.
func TestLoginDiscoveryContracts(t *testing.T) {
	for _, body := range []string{"<html>login</html>", `{"meta":{"rc":"error","msg":"api.err.NoPermission"}}`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
		c, _ := New(config.UniFiConfig{URL: srv.URL, Username: "reader", Password: "fixture"})
		if err := c.Login(context.Background()); err == nil || c.currentControllerType() != "" {
			t.Error("invalid login accepted")
		}
		srv.Close()
	}
	for _, tc := range []struct {
		status int
		body   string
		probe  bool
	}{{200, "{}", false}, {403, "", false}, {404, "", true}} {
		var touched atomic.Bool
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, integrationV1Prefix) {
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
				return
			}
			touched.Store(true)
			w.WriteHeader(http.StatusForbidden)
		}))
		c, _ := New(config.UniFiConfig{URL: srv.URL, APIKey: "fixture"})
		if err := c.Login(context.Background()); err == nil || c.currentControllerType() != "" || touched.Load() != tc.probe {
			t.Errorf("status %d: mode=%q probes=%v", tc.status, c.currentControllerType(), touched.Load())
		}
		srv.Close()
	}
	var leaked atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Store(true) }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, other.URL, http.StatusFound) }))
	defer srv.Close()
	c, _ := New(config.UniFiConfig{URL: srv.URL, APIKey: "fixture"})
	if err := c.Login(context.Background()); err == nil || leaked.Load() {
		t.Fatal("followed cross-port redirect")
	}
}

// TestWebSocketUpgradeAndCookieScope checks the native site stream's challenge
// and ensures a cookie scoped below the base URL reaches its intended endpoint.
func TestWebSocketUpgradeAndCookieScope(t *testing.T) {
	for _, bad := range []string{"", "Upgrade", "Connection", "Sec-WebSocket-Accept"} {
		t.Run("header-"+bad, func(t *testing.T) {
			const stream = "/proxy/network/wss/s/branch/events"
			mux := http.NewServeMux()
			mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
				http.SetCookie(w, &http.Cookie{Name: "session", Value: "test", Path: "/proxy/network/wss/"})
			})
			mux.HandleFunc(stream, func(w http.ResponseWriter, r *http.Request) {
				if _, err := r.Cookie("session"); err != nil {
					t.Error("missing path-scoped cookie")
				}
				sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
				h := http.Header{"Upgrade": {"websocket"}, "Connection": {"keep-alive, Upgrade"}, "Sec-Websocket-Accept": {base64.StdEncoding.EncodeToString(sum[:])}}
				if bad != "" {
					h.Set(bad, "incorrect")
				}
				conn, rw, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\n")
				h.Write(rw)
				fmt.Fprint(rw, "\r\n")
				rw.Write([]byte{0x88, 0})
				rw.Flush()
			})
			srv := httptest.NewServer(mux)
			defer srv.Close()
			c, _ := New(config.UniFiConfig{URL: srv.URL, Site: "branch", Username: "reader", Password: "fixture"})
			if err := c.Login(context.Background()); err != nil {
				t.Fatal(err)
			}
			err := c.SubscribeEvents(context.Background(), make(chan Event, 1))
			if bad == "" && err != io.EOF || bad != "" && (err == nil || !strings.Contains(err.Error(), "invalid websocket upgrade")) {
				t.Fatalf("header %q: %v", bad, err)
			}
		})
	}
}

// TestFallbackInventoryAndDeniedSiteListing covers older integration and limited session accounts.
func TestFallbackInventoryAndDeniedSiteListing(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/proxy/network/api/self/sites", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) })
	mux.HandleFunc(integrationV1Prefix+"/sites", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"offset":0,"count":1,"totalCount":1,"data":[{"id":"s","internalReference":"east/branch"}]}`)
	})
	for _, path := range []string{"clients", "devices"} {
		mux.HandleFunc(integrationV1Prefix+"/sites/s/"+path, func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `{"offset":0,"count":0,"totalCount":0,"data":[]}`)
		})
	}
	mux.HandleFunc("/proxy/network/api/s/", func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.EscapedPath(), "east%2Fbranch/") {
			t.Errorf("site path %q", r.URL.EscapedPath())
		}
		if strings.HasSuffix(r.URL.Path, "/rest/networkconf") {
			fmt.Fprint(w, `{"data":[{"_id":"oid","external_id":"uuid","name":"Lab","ip_subnet":"192.0.2.1/24"}]}`)
			return
		}
		fmt.Fprint(w, `{"data":[]}`)
	})
	mux.HandleFunc("/proxy/network/v2/api/site/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/vpn/connections") {
			fmt.Fprint(w, "{}")
			return
		}
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	for _, key := range []string{"fixture", ""} {
		c, _ := New(config.UniFiConfig{URL: srv.URL, Site: "east/branch", APIKey: key, Username: "reader", Password: "fixture"})
		s, err := c.FetchSnapshot(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(s.Networks) != 1 || s.Networks[0].Subnet != "192.0.2.1/24" || s.Visibility.VPNAvailable {
			t.Fatalf("bad fallback inventory/visibility: %+v", s.Visibility)
		}
		if _, err := c.FetchRecentLogs(context.Background(), s.CollectedAt); err == nil {
			t.Fatal("two failed log feeds reported success")
		}
	}

	// If v1 /networks returns 404 AND legacy rest/networkconf returns 403,
	// core clients and devices must still be returned while recording the
	// missing network feeds.
	netDeniedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case integrationV1Prefix + "/sites":
			fmt.Fprint(w, `{"offset":0,"count":1,"totalCount":1,"data":[{"id":"s","internalReference":"default"}]}`)
		case integrationV1Prefix + "/sites/s/clients":
			fmt.Fprint(w, `{"offset":0,"count":1,"totalCount":1,"data":[{"id":"c1","name":"Laptop","type":"WIRED","macAddress":"02:00:00:00:00:09","ipAddress":"192.0.2.9"}]}`)
		case integrationV1Prefix + "/sites/s/devices":
			fmt.Fprint(w, `{"offset":0,"count":1,"totalCount":1,"data":[{"id":"d1","name":"Switch","model":"USW","macAddress":"02:00:00:00:00:01","ipAddress":"192.0.2.2"}]}`)
		case "/proxy/network/api/s/default/rest/networkconf":
			w.WriteHeader(http.StatusForbidden)
		default:
			http.NotFound(w, r)
		}
	}))
	defer netDeniedSrv.Close()
	c2, _ := New(config.UniFiConfig{URL: netDeniedSrv.URL, APIKey: "fixture"})
	snap2, err := c2.FetchSnapshot(context.Background())
	if err != nil {
		t.Fatalf("expected 404 v1 /networks + 403 legacy networkconf to preserve core inventory, got: %v", err)
	}
	if len(snap2.Clients) != 1 || len(snap2.Devices) != 1 || len(snap2.Networks) != 0 {
		t.Fatalf("unexpected degraded snapshot inventory: clients=%d devices=%d networks=%d", len(snap2.Clients), len(snap2.Devices), len(snap2.Networks))
	}
}
