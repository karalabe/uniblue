// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
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

// TestControllerTLSDefaults checks the certificate policy for the effective
// controller URL, including an environment override of a local YAML URL.
func TestControllerTLSDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.yaml")
	t.Setenv("UNIBLUE_UNIFI_API_KEY", "test-key")
	for _, tc := range []struct {
		host  string
		local bool
	}{
		{"api.ui.com/v1/connector/consoles/abc", false}, {"unifi.local.example", false},
		{"192.0.2.1", false}, {"[2001:db8::1]", false}, {"100.128.0.1", false},
		{"api。ui。com", false}, {"ai.", false}, {"134744072", false},
		{"192.168.1.1", true}, {"10.0.0.1", true}, {"172.16.0.1", true},
		{"localhost.", true}, {"127.0.0.1", true}, {"100.127.255.254", true}, {"169.254.1.1", true},
		{"[fc00::1]", true}, {"[::1]", true}, {"[fe80::1%25en0]", true},
		{"unifi", true}, {"konzolám", true}, {"unifi.local", true}, {"UNIFI.LAN.:8443", true},
		{"unifi.home", true}, {"unifi.home.arpa", true}, {"unifi.internal", true},
		{"unifi.localdomain", true}, {"unifi.localhost", true},
	} {
		t.Run(tc.host, func(t *testing.T) {
			t.Setenv("UNIBLUE_UNIFI_URL", "https://"+tc.host)
			cfg, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.UniFi.InsecureSkipVerify != tc.local {
				t.Errorf("InsecureSkipVerify = %t, want %t", cfg.UniFi.InsecureSkipVerify, tc.local)
			}
		})
	}
	for _, tc := range []struct {
		host, yamlSetting, envSetting string
		setEnv                        bool
		want                          bool
	}{
		{"api.ui.com", "", "", false, false}, {"api.ui.com", "true", "", false, true}, {"unifi", "false", "", false, false},
		{"api.ui.com", "false", "true", true, true}, {"unifi", "true", "false", true, false},
		{"unifi", "false", "", true, false}, {"api.ui.com", "", "", true, false},
	} {
		t.Run(tc.host+"/"+tc.yamlSetting+"/"+tc.envSetting, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			raw := "unifi:\n  url: https://unifi.lan\n"
			if tc.yamlSetting != "" {
				raw += "  insecure_skip_verify: " + tc.yamlSetting + "\n"
			}
			if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("UNIBLUE_UNIFI_URL", "https://"+tc.host)
			if tc.setEnv {
				t.Setenv("UNIBLUE_UNIFI_INSECURE_SKIP_VERIFY", tc.envSetting)
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.UniFi.InsecureSkipVerify != tc.want {
				t.Errorf("InsecureSkipVerify = %t, want %t", cfg.UniFi.InsecureSkipVerify, tc.want)
			}
		})
	}
	t.Setenv("UNIBLUE_UNIFI_URL", "https://unifi")
	t.Setenv("UNIBLUE_UNIFI_INSECURE_SKIP_VERIFY", "sometimes")
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "UNIBLUE_UNIFI_INSECURE_SKIP_VERIFY") {
		t.Errorf("invalid TLS override: %v", err)
	}
}

// TestControllerRequestDelay checks pacing defaults, precedence, and rejection
// of invalid settings before the controller client is constructed.
func TestControllerRequestDelay(t *testing.T) {
	t.Setenv("UNIBLUE_UNIFI_URL", "https://unifi")
	t.Setenv("UNIBLUE_UNIFI_API_KEY", "test-key")
	for _, tc := range []struct {
		yaml, env, wantErr string
		setEnv             bool
		want               time.Duration
	}{
		{"", "", "", false, 0}, {"500ms", "", "", false, 500 * time.Millisecond},
		{"500ms", "", "", true, 500 * time.Millisecond},
		{"500ms", "2s", "", true, 2 * time.Second}, {"500ms", "0", "", true, 0},
		{"-1s", "", "unifi.request_delay", false, 0}, {"", "-1ms", "unifi.request_delay", true, 0},
		{"", "later", "UNIBLUE_UNIFI_REQUEST_DELAY", true, 0},
	} {
		t.Run(tc.yaml+"/"+tc.env, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if tc.yaml != "" {
				if err := os.WriteFile(path, []byte("unifi:\n  request_delay: "+tc.yaml+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.setEnv {
				t.Setenv("UNIBLUE_UNIFI_REQUEST_DELAY", tc.env)
			}
			cfg, err := Load(path)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Load error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.UniFi.RequestDelay != tc.want {
				t.Errorf("RequestDelay = %s, want %s", cfg.UniFi.RequestDelay, tc.want)
			}
		})
	}
}

// TestAssetOverrides checks the YAML representation and validation of exact
// selectors, including aliases that differ only in MAC address punctuation.
func TestAssetOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assets")
	raw := `
unifi:
  url: https://controller.example
  api_key: test
network:
  assets:
    - mac: "DA-00-00-00-00-01"
      id: Storage-A
      label: Backup NAS
      tier: crown
      consequences: [data, continuity]
      manages: ["0200.0000.0002", Host-B]
      hosts: ["020000000003", Guest-C]
`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []AssetOverride{{
		MAC: "da:00:00:00:00:01", ID: "Storage-A", Label: "Backup NAS", Tier: "crown",
		Consequences: []string{"data", "continuity"},
		Manages:      []string{"02:00:00:00:00:02", "Host-B"}, Hosts: []string{"02:00:00:00:00:03", "Guest-C"},
	}}
	if !reflect.DeepEqual(cfg.Network.Assets, want) {
		t.Fatalf("loaded assets = %+v, want %+v", cfg.Network.Assets, want)
	}
	for _, tc := range []struct {
		name   string
		assets []AssetOverride
	}{
		{"missing selector", []AssetOverride{{Label: "Server"}}},
		{"invalid MAC with valid ID", []AssetOverride{{ID: "A", MAC: "bad"}}},
		{"duplicate MAC", []AssetOverride{{MAC: "da0000000001"}, {MAC: "DA-00-00-00-00-01"}}},
		{"duplicate ID", []AssetOverride{{ID: "A"}, {ID: "A", MAC: "da0000000001"}}},
		{"invalid tier", []AssetOverride{{ID: "A", Tier: "critical"}}},
		{"invalid consequence", []AssetOverride{{ID: "A", Consequences: []string{"data", "damage"}}}},
		{"self manage", []AssetOverride{{MAC: "da0000000001", Manages: []string{"DA00.0000.0001"}}}},
		{"self host", []AssetOverride{{ID: "Guest-A", Hosts: []string{"Guest-A"}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg.Network.Assets = tc.assets
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "network.assets") {
				t.Errorf("Validate() = %v, want an asset configuration error", err)
			}
		})
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

// TestStatePathResolvesRelativeToConfigDirIgnoringCWD verifies that a relative
// state.path in a config file always resolves relative to that config file's
// directory, never falling back to an unrelated ./uniblue-state.json in the
// current working directory.
func TestStatePathResolvesRelativeToConfigDirIgnoringCWD(t *testing.T) {
	siteA := t.TempDir()
	siteB := t.TempDir()

	siteAState := filepath.Join(siteA, "uniblue-state.json")
	const siteAContent = `{"site":"A","findings":{"keep":true}}`
	if err := os.WriteFile(siteAState, []byte(siteAContent), 0o600); err != nil {
		t.Fatal(err)
	}

	siteBConfig := filepath.Join(siteB, "config.yaml")
	cfgYAML := "unifi:\n  url: https://192.0.2.2\n  api_key: k\n"
	if err := os.WriteFile(siteBConfig, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Chdir(siteA)

	cfg, err := Load(siteBConfig)
	if err != nil {
		t.Fatalf("Load(siteB): %v", err)
	}
	wantSiteBState := filepath.Join(siteB, "uniblue-state.json")
	if cfg.State.Path != wantSiteBState {
		t.Fatalf("siteB state.path = %q, want %q (must ignore CWD state file in siteA)", cfg.State.Path, wantSiteBState)
	}

	// Simulate persisting siteB state and verify siteA state stays untouched.
	const siteBContent = `{"site":"B"}`
	if err := os.WriteFile(cfg.State.Path, []byte(siteBContent), 0o600); err != nil {
		t.Fatalf("write siteB state: %v", err)
	}
	gotA, err := os.ReadFile(siteAState)
	if err != nil {
		t.Fatalf("read siteA state: %v", err)
	}
	if string(gotA) != siteAContent {
		t.Fatalf("siteA state was modified: got %q, want %q", string(gotA), siteAContent)
	}
	gotB, err := os.ReadFile(wantSiteBState)
	if err != nil {
		t.Fatalf("read siteB state: %v", err)
	}
	if string(gotB) != siteBContent {
		t.Fatalf("siteB state mismatch: got %q, want %q", string(gotB), siteBContent)
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

// TestSSHProbeDefaults distinguishes omitted audit settings from an explicit opt-out.
func TestSSHProbeDefaults(t *testing.T) {
	for _, tc := range []struct {
		name, settings     string
		authDisabled, keys bool
	}{
		{"default", "", false, false},
		{"configured", "  ssh_key_audit:\n    public_key_files: [audit.pub]\n    usernames: [admin]\n", false, true},
		{"disabled", "  disable_ssh_auth_probe: true\n  ssh_key_audit:\n    enabled: false\n    public_key_files: [audit.pub]\n", true, false},
		{"explicit", "  ssh_key_audit:\n    enabled: true\n    public_key_files: [audit.pub]\n    usernames: [admin]\n", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "settings")
			if err := os.WriteFile(path, []byte("unifi:\n  url: https://controller.test\n  api_key: test\nscan:\n"+tc.settings), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Scan.DisableSSHAuthProbe != tc.authDisabled || cfg.Scan.SSHKeyAudit.Active() != tc.keys {
				t.Fatal("unexpected SSH configuration")
			}
		})
	}
}
