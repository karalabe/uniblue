// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/karalabe/uniblue/internal/unifi"
	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// TestFingerprintHostAndExclusions verifies open port discovery, exclude_ips
// enforcement, and HTTP landing-page title and header extraction.
func TestFingerprintHostAndExclusions(t *testing.T) {
	// Start a local HTTP listener simulating an embedded ventilation web panel.
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "AirFlow-HTTP/1.0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><head><title>  AirFlow Pro Ventilation  </title></head><body>ok</body></html>`))
	}))
	defer httpSrv.Close()

	_, portStr, err := net.SplitHostPort(httpSrv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	openPort, _ := strconv.Atoi(portStr)

	fp := NewFingerprinter([]int{openPort}, 4, 2*time.Second, map[string]struct{}{
		"127.0.0.2": {},
	})

	clients := []unifi.Client{
		{IP: "127.0.0.1", MAC: "aa:bb:cc:dd:ee:01", Hostname: "hvac"},
		{IP: "127.0.0.2", MAC: "aa:bb:cc:dd:ee:02", Hostname: "excluded"},
	}

	profiles := fp.FingerprintAll(context.Background(), clients)
	if len(profiles) != 1 {
		t.Fatalf("got %d profiles, want 1 (excluded IP should be skipped)", len(profiles))
	}
	if !profiles[0].HasPort(openPort) {
		t.Fatalf("expected port %d to be detected open", openPort)
	}

	// Verify HTTP banner extraction helper directly since httptest picks an
	// ephemeral port outside the fixed well-known HTTP port list.
	banner, ok := fp.fetchHTTPBanner(context.Background(), "http", "127.0.0.1", openPort)
	if !ok {
		t.Fatalf("expected HTTP banner to be fetched")
	}
	if banner.StatusCode != 200 || banner.Server != "AirFlow-HTTP/1.0" || banner.Title != "AirFlow Pro Ventilation" {
		t.Fatalf("unexpected banner: %+v", banner)
	}
}

// TestShouldKeepNervaFindingFiltersSyntheticHTTPAnonAccess verifies that
// Nerva's synthetic HTTP product-detection anon-access notices are dropped while
// real protocol misconfigurations (such as SMBv1) are kept.
func TestShouldKeepNervaFindingFiltersSyntheticHTTPAnonAccess(t *testing.T) {
	// Synthetic HTTP fingerprinter finding emitted on public /api/health or /login must be dropped.
	synthetic := plugins.SecurityFinding{
		ID:       "grafana:10.0.0-anon-access",
		Severity: plugins.SeverityMedium,
		Evidence: "Successfully queried endpoint without credentials",
	}
	if shouldKeepNervaFinding(synthetic) {
		t.Fatal("expected synthetic HTTP *-anon-access finding to be filtered out")
	}

	// Real verified protocol findings must be retained.
	for _, realFinding := range []plugins.SecurityFinding{
		{ID: "smb-v1-enabled", Severity: plugins.SeverityMedium, Evidence: "SMBv1 negotiate response received"},
		{ID: "ftp-anon-access", Severity: plugins.SeverityHigh, Evidence: "230 Anonymous login ok"},
		{ID: "tls-certificate-expired", Severity: plugins.SeverityLow, Evidence: "expired=2023-01-01"},
	} {
		if !shouldKeepNervaFinding(realFinding) {
			t.Fatalf("expected genuine finding %q to be kept", realFinding.ID)
		}
	}
}

// TestFingerprintingReportsPerPortProgress verifies that Nerva service
// identification and alternate-port fallback emit monotonic per-port progress
// updates naming the active host and port.
func TestFingerprintingReportsPerPortProgress(t *testing.T) {
	// Start an alternate-port SSH banner listener so both Nerva FastMode and the
	// unclassified-port fallback run and emit progress updates.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.9\r\n"))
				time.Sleep(50 * time.Millisecond)
			}(conn)
		}
	}()

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	altPort, _ := strconv.Atoi(portStr)

	type progressEvent struct {
		phase string
		done  int
		total int
		host  string
	}
	var (
		mu     sync.Mutex
		events []progressEvent
	)
	fp := NewFingerprinter([]int{altPort}, 4, time.Second, nil)
	fp.SetProgressFunc(func(phase string, done, total int, host string) {
		mu.Lock()
		events = append(events, progressEvent{phase: phase, done: done, total: total, host: host})
		mu.Unlock()
	})

	profiles := fp.FingerprintAll(context.Background(), []unifi.Client{
		{IP: "127.0.0.1", MAC: "aa:bb:cc:dd:ee:09", Name: "Lab Box"},
	})
	if len(profiles) != 1 || !profiles[0].HasPort(altPort) {
		t.Fatalf("expected open port %d on Lab Box, got %+v", altPort, profiles)
	}

	mu.Lock()
	defer mu.Unlock()
	wantHostPort := "Lab Box:" + portStr
	sawFPStart, sawFPComplete, sawFBComplete := false, false, false
	lastDone := make(map[string]int)
	for _, ev := range events {
		if prev, ok := lastDone[ev.phase]; ok && ev.done < prev {
			t.Fatalf("phase %q progress went backwards: %d -> %d (%+v)", ev.phase, prev, ev.done, events)
		}
		lastDone[ev.phase] = ev.done
		switch ev.phase {
		case "fingerprinting":
			if ev.done == 0 && ev.total == 1 {
				sawFPStart = true
			}
			if ev.done == 1 && ev.total == 1 && strings.HasPrefix(ev.host, wantHostPort) {
				sawFPComplete = true
			}
		case "fingerprinting-fallback":
			if ev.done == 1 && ev.total == 1 && strings.HasPrefix(ev.host, wantHostPort) {
				sawFBComplete = true
			}
		}
	}
	if !sawFPStart || !sawFPComplete {
		t.Fatalf("expected fingerprinting start and completion for %q, got %+v", wantHostPort, events)
	}
	if !sawFBComplete {
		t.Fatalf("expected fingerprinting-fallback completion for %q, got %+v", wantHostPort, events)
	}
}
