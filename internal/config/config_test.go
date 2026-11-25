// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadZeroConfigFromEnv verifies that Load builds a valid configuration
// solely from environment variables when config.yaml does not exist.
func TestLoadZeroConfigFromEnv(t *testing.T) {
	t.Setenv("UNIBLUE_UNIFI_URL", "https://10.0.0.1")
	t.Setenv("UNIBLUE_UNIFI_API_KEY", "test-key")

	cfg, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatalf("Load env-only config: %v", err)
	}
	if cfg.UniFi.URL != "https://10.0.0.1" || cfg.UniFi.APIKey != "test-key" {
		t.Fatalf("unexpected UniFi config: %+v", cfg.UniFi)
	}
	if len(cfg.Scan.Ports) != len(DefaultPorts) {
		t.Fatalf("got %d default ports, want %d", len(cfg.Scan.Ports), len(DefaultPorts))
	}
}

// TestLoadInheritsDefaultPortsAndDedupesExtraPorts verifies that omitting scan.ports
// inherits DefaultPorts and merges scan.extra_ports without duplicates.
func TestLoadInheritsDefaultPortsAndDedupesExtraPorts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	raw := `
unifi:
  url: "https://10.0.0.1"
  api_key: "test-key"
scan:
  extra_ports: [8123, 9090, 9090]
`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// 8123 is already in DefaultPorts, 9090 appears twice -> net +1 port.
	if len(cfg.Scan.Ports) != len(DefaultPorts)+1 {
		t.Fatalf("got %d ports (%v), want %d", len(cfg.Scan.Ports), cfg.Scan.Ports, len(DefaultPorts)+1)
	}
}
