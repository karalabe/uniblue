// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package config

import (
	"os"
	"path/filepath"
	"strings"
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

// TestValidateDoesNotEchoWebhookURLSecret verifies that invalid notify.webhook_url
// validation errors never print the raw webhook URL or embedded tokens.
func TestValidateDoesNotEchoWebhookURLSecret(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name      string
		rawURL    string
		forbidden []string
	}{
		{
			name:      "schemeless discord webhook",
			rawURL:    "discord.com/api/webhooks/123456789/SUPER_SECRET_TOKEN_ABC",
			forbidden: []string{"SUPER_SECRET_TOKEN_ABC", "123456789", "discord.com"},
		},
		{
			name:      "unsupported scheme slack webhook",
			rawURL:    "ftp://hooks.slack.com/services/T000/B000/SLACK_SECRET_XYZ",
			forbidden: []string{"SLACK_SECRET_XYZ", "hooks.slack.com"},
		},
		{
			name:      "userinfo secret with missing host",
			rawURL:    "https://bot:MY_PASSWORD_999@",
			forbidden: []string{"MY_PASSWORD_999"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name+".yaml")
			content := "unifi:\n  url: https://192.0.2.1\n  api_key: k\nnotify:\n  webhook_url: " + tc.rawURL + "\n"
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if err == nil {
				t.Fatalf("expected validation error for webhook_url %q", tc.rawURL)
			}
			msg := err.Error()
			for _, secret := range tc.forbidden {
				if strings.Contains(msg, secret) {
					t.Fatalf("validation error leaked secret %q: %s", secret, msg)
				}
			}
		})
	}
}

// TestStatePathPreservesLegacyCWDBaselineOnUpgrade verifies that relative state
// paths resolve next to config.yaml on fresh installs while preserving an
// existing working-directory baseline file across upgrades.
func TestStatePathPreservesLegacyCWDBaselineOnUpgrade(t *testing.T) {
	cfgDir := t.TempDir()
	workDir := t.TempDir()
	cfgPath := filepath.Join(cfgDir, "config.yaml")
	cfgYAML := "unifi:\n  url: https://192.0.2.1\n  api_key: k\n"
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Chdir(workDir)

	// Fresh install: no state file in cfgDir or workDir -> resolve under cfgDir.
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load (fresh): %v", err)
	}
	wantCfgState := filepath.Join(cfgDir, "uniblue-state.json")
	if cfg.State.Path != wantCfgState {
		t.Fatalf("fresh install state.path = %q, want %q", cfg.State.Path, wantCfgState)
	}

	// Upgrade with legacy working-directory state file -> preserve workDir baseline
	// even if config dir is read-only.
	legacyState := filepath.Join(workDir, "uniblue-state.json")
	if err := os.WriteFile(legacyState, []byte(`{"findings":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cfgDir, 0o555); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(cfgDir, 0o755) }()

	cfgUpgrade, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load (upgrade): %v", err)
	}
	gotEval, _ := filepath.EvalSymlinks(cfgUpgrade.State.Path)
	wantEval, _ := filepath.EvalSymlinks(legacyState)
	if gotEval != wantEval {
		t.Fatalf("upgrade state.path = %q (eval %q), want legacy CWD %q (eval %q)",
			cfgUpgrade.State.Path, gotEval, legacyState, wantEval)
	}

	// Once a state file exists in cfgDir, cfgDir takes precedence.
	if err := os.Chmod(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wantCfgState, []byte(`{"findings":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgMigrated, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load (migrated): %v", err)
	}
	if cfgMigrated.State.Path != wantCfgState {
		t.Fatalf("migrated state.path = %q, want %q", cfgMigrated.State.Path, wantCfgState)
	}
}

// TestLoadWebhookSecretFromYAMLAndEnv verifies notify.webhook_secret parsing
// from YAML and UNIBLUE_WEBHOOK_SECRET environment overrides.
func TestLoadWebhookSecretFromYAMLAndEnv(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	raw := `
unifi:
  url: "https://192.0.2.1"
  api_key: "k"
notify:
  webhook_url: "https://hooks.example.test/uniblue"
  webhook_secret: "whsec_eWFtbC1zZWNyZXQ="
`
	if err := os.WriteFile(cfgPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load(yaml): %v", err)
	}
	if cfg.Notify.WebhookSecret != "whsec_eWFtbC1zZWNyZXQ=" {
		t.Fatalf("expected yaml webhook_secret, got %q", cfg.Notify.WebhookSecret)
	}

	t.Setenv("UNIBLUE_WEBHOOK_SECRET", "env-override-secret")
	t.Setenv("UNIBLUE_WEBHOOK_FORMAT", "json")
	t.Setenv("UNIBLUE_WEBHOOK_MIN_SEVERITY", "high")
	cfgEnv, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load(env): %v", err)
	}
	if cfgEnv.Notify.WebhookSecret != "env-override-secret" || cfgEnv.Notify.Format != "json" || cfgEnv.Notify.MinSeverity != "high" {
		t.Fatalf("unexpected env notify config: %+v", cfgEnv.Notify)
	}
}
