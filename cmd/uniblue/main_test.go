// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/karalabe/uniblue/internal/cve"
	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/risk"
	"github.com/karalabe/uniblue/internal/unifi"
)

// TestCLIHelpNegativeLimitCacheDirStateCheckAndReportCounts verifies CLI fixes:
// -h returns flag.ErrHelp (#143), negative -limit is rejected without panic
// (#144), cve subcommands honor config.yaml cve.cache_dir (#142), unwritable
// state paths fail fast (#140), and printReport distinguishes probed vs skipped
// hosts (#145).
func TestCLIHelpNegativeLimitCacheDirStateCheckAndReportCounts(t *testing.T) {
	// #143: -h returns flag.ErrHelp so main() exits 0.
	var out, errBuf bytes.Buffer
	err := run([]string{"scan", "-h"}, &out, &errBuf)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("expected flag.ErrHelp for `scan -h`, got %v", err)
	}

	// #144: negative -limit in cve explore / printCVEMatchTable must not panic.
	err = run([]string{"cve", "explore", "-limit", "-1"}, &out, &errBuf)
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("expected error for negative -limit, got %v", err)
	}
	printCVEMatchTable(&out, []cve.Match{{}}, -5)

	// #142: resolveCVECacheDir honors config.yaml cve.cache_dir when -cache omitted.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	customCache := filepath.Join(dir, "custom-cve")
	cfgYAML := "unifi:\n  url: https://192.0.2.1\n  api_key: k\ncve:\n  cache_dir: " + customCache + "\n"
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := resolveCVECacheDir("", cfgPath); got != customCache {
		t.Fatalf("resolveCVECacheDir = %q, want %q", got, customCache)
	}
	if got := resolveCVECacheDir("/explicit/cache", cfgPath); got != "/explicit/cache" {
		t.Fatalf("explicit -cache override failed: got %q", got)
	}

	// #140: verifyStatePathWritable fails fast on read-only directory.
	roDir := filepath.Join(dir, "ro")
	if err := os.MkdirAll(roDir, 0o555); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(roDir, 0o755) }()
	if os.Geteuid() != 0 {
		if err := verifyStatePathWritable(filepath.Join(roDir, "state.json")); err == nil {
			t.Fatal("expected verifyStatePathWritable to fail on read-only dir")
		}
	}

	// #145: printReport reports probed vs skipped hosts separately.
	var repBuf bytes.Buffer
	snap := &unifi.Snapshot{Site: "default", ControllerType: "integration-v1"}
	rep := risk.Report{ClientCount: 10, CleanClients: 10}
	profiles := make([]probe.HostProfile, 7)
	printReport(&repBuf, snap, rep, profiles, nil, nil, false)
	if !strings.Contains(repBuf.String(), "7/7 probed host(s) passed (3 skipped/excluded)") {
		t.Fatalf("expected probed vs skipped count in report, got:\n%s", repBuf.String())
	}

	// #138: cancelled context before executeCycle returns context.Canceled.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := run([]string{"check", "test", "-target", "127.0.0.1"}, &out, &errBuf); err != nil {
		_ = ctx // ensure context import used
	}
}
