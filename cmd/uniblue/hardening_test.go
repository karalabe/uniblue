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
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/risk"
	"github.com/karalabe/uniblue/internal/unifi"
)

func TestWatchSessionPreservesWebhookIDAcrossRetryCycles(t *testing.T) {
	var sentIDs []string
	failFirst := true
	snap := &unifi.Snapshot{
		Site: "default",
		Clients: []unifi.Client{
			{MAC: "aa:bb:cc:dd:ee:01", Name: "Laptop", IP: "192.168.1.20", NetworkName: "Main"},
		},
	}
	finding := checks.Finding{
		CheckID:           "UB-0001",
		Title:             "Test Finding",
		Client:            snap.Clients[0],
		Port:              80,
		BaseSeverity:      checks.SeverityHigh,
		EffectiveSeverity: checks.SeverityHigh,
	}
	session := &watchSession{
		cfg:    &config.Config{State: config.StateConfig{Path: filepath.Join(t.TempDir(), "state.json")}},
		minSev: checks.SeverityMedium,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		scanFn: func(context.Context) (*unifi.Snapshot, []probe.HostProfile, risk.Report, error) {
			return snap, nil, risk.Report{ClientCount: 1, Findings: []checks.Finding{finding}}, nil
		},
		sendWithIDFn: func(_ context.Context, id, _ string, _ risk.Diff) error {
			sentIDs = append(sentIDs, id)
			if failFirst {
				failFirst = false
				return errors.New("temporary webhook outage")
			}
			return nil
		},
		loadFn: func(string) (*risk.State, error) { return nil, nil },
		saveFn: func(string, *risk.State) error { return nil },
	}

	session.runCycle(context.Background())
	session.runCycle(context.Background())

	if len(sentIDs) != 2 {
		t.Fatalf("expected 2 delivery attempts, got %d (%+v)", len(sentIDs), sentIDs)
	}
	if sentIDs[0] == "" || sentIDs[0] != sentIDs[1] {
		t.Fatalf("expected watch retry to preserve identical webhook-id, got %q then %q", sentIDs[0], sentIDs[1])
	}
	if session.pendingWebhookID != "" {
		t.Fatalf("expected pendingWebhookID cleared after successful send, got %q", session.pendingWebhookID)
	}
}

func TestWarnLegacyCWDStateLogsWhenMissingTargetAndCWDExists(t *testing.T) {
	cwd := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	if err := os.WriteFile(filepath.Join(cwd, "uniblue-state.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgStatePath := filepath.Join(t.TempDir(), "uniblue-state.json")

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	warnLegacyCWDState(logger, cfgStatePath)

	out := buf.String()
	if !strings.Contains(out, "legacy_cwd_state") || !strings.Contains(out, cfgStatePath) {
		t.Fatalf("expected startup warning naming both resolved state_path and legacy CWD state file, got: %q", out)
	}
}
