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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/karalabe/uniblue/internal/config"
)

func TestReloginSuppressionTTLExpiresAndRecovers(t *testing.T) {
	var loginCalls atomic.Int32
	var rejectData atomic.Bool

	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		loginCalls.Add(1)
		http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: "tok"})
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/proxy/network/api/s/default/stat/sta", func(w http.ResponseWriter, r *http.Request) {
		if rejectData.Load() {
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
	ctrl.reloginSuppressTTL = 60 * time.Millisecond

	if err := ctrl.Login(context.Background()); err != nil {
		t.Fatalf("initial Login: %v", err)
	}

	// Simulate a brief console restart window where login succeeds (200) while
	// the network proxy still returns 401 -> path gets suppressed temporarily.
	rejectData.Store(true)
	var out apiEnvelope[rawClient]
	if err := ctrl.getJSON(context.Background(), "/proxy/network/api/s/default/stat/sta", &out); err == nil {
		t.Fatal("expected 401 while network proxy is restarting")
	}
	callsDuringRestart := loginCalls.Load()
	if !ctrl.isPathUnauthorized("/proxy/network/api/s/default/stat/sta") {
		t.Fatal("expected path to be temporarily suppressed immediately after 401")
	}
	// While within TTL, repeated polls do not spam login.
	_ = ctrl.getJSON(context.Background(), "/proxy/network/api/s/default/stat/sta", &out)
	if loginCalls.Load() != callsDuringRestart {
		t.Fatalf("expected path suppression to prevent login spam within TTL, got %d vs %d", loginCalls.Load(), callsDuringRestart)
	}

	// Once the TTL expires, suppression clears automatically so the controller
	// can re-authenticate and recover without restarting UniBlue.
	time.Sleep(80 * time.Millisecond)
	if ctrl.isPathUnauthorized("/proxy/network/api/s/default/stat/sta") {
		t.Fatal("expected path suppression to expire after TTL")
	}
	// Verify WebSocket suppression also expires after TTL.
	ctrl.markWSReloginSuppressed()
	if ctrl.shouldReloginWS() {
		t.Fatal("expected WS relogin to be suppressed within TTL")
	}
	time.Sleep(80 * time.Millisecond)
	if !ctrl.shouldReloginWS() {
		t.Fatal("expected WS relogin suppression to expire after TTL")
	}
}

func TestDecodeLogParamValueBoundedDepthAndInterpolateLogTemplateSinglePass(t *testing.T) {
	// Deeply nested JSON object must complete instantaneously without quadratic work.
	const depth = 200
	deep := strings.Repeat(`{"value":`, depth) + `"leaf"` + strings.Repeat(`}`, depth)
	start := time.Now()
	_ = decodeLogParamValue(json.RawMessage(deep))
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("deeply nested decodeLogParamValue took %v (expected bounded O(n))", elapsed)
	}

	// Shallow nested value within maxLogParamDecodeDepth resolves cleanly.
	shallow := json.RawMessage(`{"value":{"value":{"name":"Switch-1"}}}`)
	if got := decodeLogParamValue(shallow); got != "Switch-1" {
		t.Fatalf("shallow decodeLogParamValue = %q, want Switch-1", got)
	}

	// Single-pass interpolation must never re-interpolate or strip literal
	// "{...}" substrings inside parameter values, regardless of map iteration order.
	params := map[string]string{
		"ADMIN":  "alice{OBJECT}",
		"OBJECT": "FirewallRule",
	}
	for i := 0; i < 50; i++ {
		got := interpolateLogTemplate("{ADMIN} modified {OBJECT} ({COUNT})", params)
		want := "alice{OBJECT} modified FirewallRule ()"
		if got != want {
			t.Fatalf("run %d: interpolateLogTemplate = %q, want %q", i, got, want)
		}
	}
}
