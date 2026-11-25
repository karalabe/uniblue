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

// TestLoadStrictUnknownFieldsWebhookURLAndMACNormalization verifies that typos
// in YAML keys fail fast, scheme-less webhook URLs are rejected, configured
// MACs in dash/dot/bare forms are canonicalized, and relative state paths
// resolve relative to the config directory.
func TestLoadStrictUnknownFieldsWebhookURLAndMACNormalization(t *testing.T) {
	dir := t.TempDir()

	// 1. Unknown key (typo exclude_ip instead of exclude_ips) must fail fast.
	badPath := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(badPath, []byte("unifi:\n  url: https://192.0.2.1\n  api_key: k\nnetwork:\n  exclude_ip: ['192.0.2.5']\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(badPath); err == nil {
		t.Fatal("expected unknown field exclude_ip to return an error")
	}

	// 2. Scheme-less webhook_url must fail validation.
	badWH := filepath.Join(dir, "badwh.yaml")
	if err := os.WriteFile(badWH, []byte("unifi:\n  url: https://192.0.2.1\n  api_key: k\nnotify:\n  webhook_url: ntfy.example/topic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(badWH); err == nil {
		t.Fatal("expected scheme-less notify.webhook_url to fail validation")
	}

	// 3. MAC normalization across dash, dot, and bare hex + relative state path.
	goodPath := filepath.Join(dir, "good.yaml")
	goodYAML := `
unifi:
  url: "https://192.0.2.1"
  api_key: "k"
network:
  external_devices: ["AA-BB-CC-DD-EE-01", "Garage Switch"]
  physical_ports:
    - device: "aabb.ccdd.ee02"
      port: 3
      zone: "external"
      allowed_macs: ["11-22-33-44-55-66", "AABBCCDDEEFF"]
notify:
  webhook_url: "https://hooks.example.test/abc"
`
	if err := os.WriteFile(goodPath, []byte(goodYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(goodPath)
	if err != nil {
		t.Fatalf("Load(good): %v", err)
	}
	if cfg.Network.ExternalDevices[0] != "aa:bb:cc:dd:ee:01" || cfg.Network.ExternalDevices[1] != "Garage Switch" {
		t.Fatalf("unexpected external_devices: %+v", cfg.Network.ExternalDevices)
	}
	pr := cfg.Network.PhysicalPorts[0]
	if pr.Device != "aa:bb:cc:dd:ee:02" || pr.AllowedMACs[0] != "11:22:33:44:55:66" || pr.AllowedMACs[1] != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("unexpected normalized physical_ports: %+v", pr)
	}
	if cfg.State.Path != filepath.Join(dir, "uniblue-state.json") {
		t.Fatalf("expected relative state path resolved under config dir, got %q", cfg.State.Path)
	}
}
