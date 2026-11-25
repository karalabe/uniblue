// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package oui

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestSyncAndLongestPrefixLookup verifies IEEE CSV syncing, gzipped persistence,
// longest-prefix matching (36-bit MA-S over 28-bit MA-M over 24-bit MA-L),
// built-in virtual MAC detection, and locally-administered bit decoding.
func TestSyncAndLongestPrefixLookup(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oui.csv", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Registry,Assignment,Organization Name,Organization Address\n" +
			"MA-L,001122,Acme Audio Corp.,USA\n" +
			"MA-L,0050C2,IEEE Registration Authority,USA\n"))
	})
	mux.HandleFunc("/mam.csv", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Registry,Assignment,Organization Name,Organization Address\n" +
			"MA-M,AABBCC1,Acme Medium Block Corp,USA\n"))
	})
	mux.HandleFunc("/oui36.csv", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Registry,Assignment,Organization Name,Organization Address\n" +
			"MA-S,0050C2AA1,Acme Sensor GmbH,Germany\n"))
	})
	mux.HandleFunc("/iab.csv", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Registry,Assignment,Organization Name,Organization Address\n"))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	db := New(t.TempDir())
	db.sources = []registrySource{
		{Name: "MA-L", URL: srv.URL + "/oui.csv", Nibbles: 6},
		{Name: "MA-M", URL: srv.URL + "/mam.csv", Nibbles: 7},
		{Name: "MA-S", URL: srv.URL + "/oui36.csv", Nibbles: 9},
		{Name: "IAB", URL: srv.URL + "/iab.csv", Nibbles: 9},
	}

	meta, err := db.Sync(context.Background(), nil)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if meta.MALCount != 2 || meta.MAMCount != 1 || meta.MASCount != 1 {
		t.Fatalf("unexpected meta counts: %+v", meta)
	}

	// Reload from disk into a fresh DB instance to verify gzip persistence.
	reloaded := New(db.Dir())
	if err := reloaded.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// 36-bit MA-S must beat MA-L's "IEEE Registration Authority" placeholder.
	mas := reloaded.Lookup("00:50:c2:aa:10:01")
	if mas.Vendor != "Acme Sensor GmbH" || mas.Registry != "MA-S" {
		t.Fatalf("MA-S lookup = %+v, want Acme Sensor GmbH (MA-S)", mas)
	}

	// 28-bit MA-M lookup.
	mam := reloaded.Lookup("aa:bb:cc:1f:00:01")
	if mam.Vendor != "Acme Medium Block Corp" || mam.Registry != "MA-M" {
		t.Fatalf("MA-M lookup = %+v, want Acme Medium Block Corp (MA-M)", mam)
	}

	// 24-bit MA-L lookup.
	mal := reloaded.Lookup("00:11:22:00:00:42")
	if mal.Vendor != "Acme Audio Corp." || mal.Registry != "MA-L" {
		t.Fatalf("MA-L lookup = %+v, want Acme Audio Corp. (MA-L)", mal)
	}

	// Built-in virtual MAC prefix (QEMU/KVM).
	vm := reloaded.Lookup("52:54:00:12:34:56")
	if !vm.IsVirtual || vm.Vendor != "QEMU/KVM" {
		t.Fatalf("virtual lookup = %+v, want QEMU/KVM virtual", vm)
	}

	// Locally-administered random MAC (bit 1 of first byte set: 0x02 = 0000_0010).
	priv := reloaded.Lookup("02:aa:bb:cc:dd:01")
	if !priv.IsLocallyAdministered || priv.Registry != "local" {
		t.Fatalf("local MAC lookup = %+v, want IsLocallyAdministered=true", priv)
	}
}

// TestFetchCSVHandlesTruncatedBodyWithoutSpinning verifies that fetchCSV
// returns immediately on non-parse read errors (such as io.ErrUnexpectedEOF
// from a truncated download or a canceled context) instead of looping forever,
// while still skipping isolated *csv.ParseError rows.
func TestFetchCSVHandlesTruncatedBodyWithoutSpinning(t *testing.T) {
	t.Run("truncated body returns error promptly", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Advertise a Content-Length larger than what we send and abruptly close
			// the hijacked connection so the client receives io.ErrUnexpectedEOF.
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Error("ResponseWriter does not implement http.Hijacker")
				return
			}
			conn, buf, err := hj.Hijack()
			if err != nil {
				return
			}
			body := "Registry,Assignment,Organization Name,Organization Address\nMA-L,001122,Acme Corp,USA\n"
			_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/csv\r\nContent-Length: 10000\r\n\r\n" + body)
			_ = buf.Flush()
			_ = conn.Close()
		}))
		defer srv.Close()

		db := New(t.TempDir())
		db.sources = []registrySource{
			{Name: "MA-L", URL: srv.URL + "/oui.csv", Nibbles: 6},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		_, err := db.Sync(ctx, nil)
		if err == nil {
			t.Fatal("expected error for truncated CSV body, got nil")
		}
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("expected io.ErrUnexpectedEOF in error chain, got: %v", err)
		}
	})

	t.Run("canceled context exits promptly", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Registry,Assignment,Organization Name,Organization Address\n"))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			cancel()
			_, _ = w.Write([]byte("MA-L,001122,Acme Corp,USA\n"))
		}))
		defer srv.Close()

		db := New(t.TempDir())
		db.sources = []registrySource{
			{Name: "MA-L", URL: srv.URL + "/oui.csv", Nibbles: 6},
		}

		_, err := db.Sync(ctx, nil)
		if err == nil {
			t.Fatal("expected error on canceled context, got nil")
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got: %v", err)
		}
	})

	t.Run("short row is skipped", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("Registry,Assignment,Organization Name,Organization Address\n" +
				"MA-L,001122,Acme Audio Corp.,USA\n" +
				"MA-L,001133\n"))
		}))
		defer srv.Close()

		db := New(t.TempDir())
		db.sources = []registrySource{
			{Name: "MA-L", URL: srv.URL + "/oui.csv", Nibbles: 6},
		}

		meta, err := db.Sync(context.Background(), nil)
		if err != nil {
			t.Fatalf("Sync with short CSV row failed: %v", err)
		}
		if meta.MALCount != 1 {
			t.Fatalf("got MALCount=%d, want 1", meta.MALCount)
		}
	})
}

// TestSyncRejectsInvalidCSVAndPreservesExistingDB verifies that Sync rejects
// HTML captive-portal 200 responses, empty/header-only CSV responses, and
// sources below MinEntries without overwriting an existing valid OUI database.
func TestSyncRejectsInvalidCSVAndPreservesExistingDB(t *testing.T) {
	mode := "valid"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch mode {
		case "valid":
			_, _ = w.Write([]byte("Registry,Assignment,Organization Name,Organization Address\n" +
				"MA-L,001122,Acme Audio Corp.,USA\n" +
				"MA-L,001123,Beta Instruments,USA\n"))
		case "html":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte("<!DOCTYPE html><html><body><h1>Captive Portal Login</h1></body></html>"))
		case "empty":
			_, _ = w.Write([]byte("Registry,Assignment,Organization Name,Organization Address\n"))
		case "too-small":
			_, _ = w.Write([]byte("Registry,Assignment,Organization Name,Organization Address\n" +
				"MA-L,001122,Acme Audio Corp.,USA\n"))
		}
	}))
	defer srv.Close()

	db := New(t.TempDir())
	db.sources = []registrySource{
		{Name: "MA-L", URL: srv.URL + "/oui.csv", Nibbles: 6, MinEntries: 2},
	}

	// 1. Seed a valid database on disk and in memory.
	if _, err := db.Sync(context.Background(), nil); err != nil {
		t.Fatalf("initial valid Sync: %v", err)
	}
	if got := db.Lookup("00:11:22:00:00:01").Vendor; got != "Acme Audio Corp." {
		t.Fatalf("initial lookup = %q, want Acme Audio Corp.", got)
	}

	// 2. HTML captive portal, header-only empty CSV, and sub-threshold CSV must all fail
	// without overwriting the existing database on disk or in memory.
	for _, tc := range []struct {
		name     string
		nextMode string
		wantSub  string
		minRows  int
	}{
		{name: "html captive portal", nextMode: "html", wantSub: "unexpected csv header", minRows: 2},
		{name: "header-only empty csv", nextMode: "empty", wantSub: "zero valid OUI entries", minRows: 0},
		{name: "below minimum row count", nextMode: "too-small", wantSub: "too few entries", minRows: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mode = tc.nextMode
			db.sources[0].MinEntries = tc.minRows
			if _, err := db.Sync(context.Background(), nil); err == nil {
				t.Fatalf("expected Sync(%s) to fail, got nil", tc.name)
			} else if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("Sync(%s) error = %v, want substring %q", tc.name, err, tc.wantSub)
			}

			// Verify in-memory and on-disk caches still hold the previously synced data.
			if got := db.Lookup("00:11:22:00:00:01").Vendor; got != "Acme Audio Corp." {
				t.Fatalf("in-memory DB corrupted after %s: got %q", tc.name, got)
			}
			reloaded := New(db.Dir())
			if err := reloaded.Load(); err != nil {
				t.Fatalf("reload DB after %s: %v", tc.name, err)
			}
			if got := reloaded.Lookup("00:11:22:00:00:01").Vendor; got != "Acme Audio Corp." {
				t.Fatalf("on-disk DB corrupted after %s: got %q", tc.name, got)
			}
		})
	}
}
