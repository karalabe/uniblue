// Package config loads and validates UniBlue runtime configuration from YAML
// files and environment variable overrides.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultPorts lists the curated set of high-signal service and IoT ports
// checked when no custom port list is supplied in configuration. Keeping the
// default list small avoids overwhelming fragile embedded devices.
var DefaultPorts = []int{22, 23, 80, 443, 502, 554, 1883, 5900, 8080, 8123, 8443, 47808}

// Config is the top-level UniBlue configuration structure.
type Config struct {
	// UniFi controls how UniBlue connects to the local gateway or controller.
	UniFi UniFiConfig `yaml:"unifi"`

	// Network describes VLAN trust tiers and exclusions used for blast-radius
	// scoring and scan scoping.
	Network NetworkConfig `yaml:"network"`

	// Scan tunes how aggressively UniBlue probes hosts on the local network.
	Scan ScanConfig `yaml:"scan"`

	// State configures where scan snapshots are persisted for change detection.
	State StateConfig `yaml:"state"`

	// CVE configures the local NVD/KEV vulnerability cache used by `uniblue cve`.
	CVE CVEConfig `yaml:"cve"`

	// Notify configures optional outbound alerting for `uniblue watch`.
	Notify NotifyConfig `yaml:"notify"`
}

// CVEConfig controls where the local NVD JSON 2.0 and CISA KEV cache is stored.
type CVEConfig struct {
	// CacheDir is the directory storing vendor-sharded CVE indexes and sync metadata.
	// When omitted, UniBlue defaults to ~/.cache/uniblue/cve.
	CacheDir string `yaml:"cache_dir"`
}

// UniFiConfig holds connection and authentication settings for a UniFi OS
// gateway (e.g., UDM Pro) or classic Network controller (e.g., Cloud Key).
type UniFiConfig struct {
	// URL is the base HTTPS address of the UniFi controller (e.g., https://192.168.1.1).
	URL string `yaml:"url"`

	// Site is the UniFi site identifier; most single-site deployments use "default".
	Site string `yaml:"site"`

	// Username is the local UniFi account used for session-based authentication.
	Username string `yaml:"username"`

	// Password is the local UniFi password. Prefer setting UNIBLUE_UNIFI_PASSWORD
	// in the environment rather than storing plaintext secrets on disk.
	Password string `yaml:"password"`

	// APIKey is an optional UniFi local API key sent via the X-API-KEY header.
	// When set, session login with username/password is skipped.
	APIKey string `yaml:"api_key"`

	// InsecureSkipVerify disables TLS certificate verification, which is typically
	// required for local gateways serving self-signed certificates.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`

	// Timeout bounds each HTTP request made to the UniFi controller.
	Timeout time.Duration `yaml:"timeout"`
}

// NetworkConfig defines local network segmentation hints so UniBlue can weigh
// findings by where a device actually lives.
type NetworkConfig struct {
	// TrustedVLANs lists VLAN names (case-insensitive) or numeric VLAN IDs whose
	// hosts have elevated trust. Findings on these networks are escalated.
	TrustedVLANs []string `yaml:"trusted_vlans"`

	// IsolatedVLANs lists VLAN names or numeric VLAN IDs reserved for untrusted
	// IoT gear. Non-WAN findings on these networks are de-escalated because
	// lateral movement is already constrained.
	IsolatedVLANs []string `yaml:"isolated_vlans"`

	// ExcludeIPs lists IP addresses that UniBlue must never actively probe.
	ExcludeIPs []string `yaml:"exclude_ips"`
}

// ScanConfig controls probing concurrency, timeouts, and check loading.
type ScanConfig struct {
	// Concurrency caps how many LAN hosts are fingerprinted or checked in parallel.
	Concurrency int `yaml:"concurrency"`

	// Timeout bounds each individual TCP connect or HTTP probe.
	Timeout time.Duration `yaml:"timeout"`

	// Ports specifies which TCP ports are inspected during host fingerprinting.
	Ports []int `yaml:"ports"`

	// ChecksDir is an optional filesystem directory containing additional YAML
	// checks loaded alongside the embedded built-in checks.
	ChecksDir string `yaml:"checks_dir"`

	// Interval sets the delay between consecutive scans in `uniblue watch`.
	Interval time.Duration `yaml:"interval"`
}

// StateConfig controls local persistence between scans.
type StateConfig struct {
	// Path is the filesystem location of the JSON state file used for diffing.
	Path string `yaml:"path"`
}

// NotifyConfig controls outbound webhook alerts during watch mode.
type NotifyConfig struct {
	// WebhookURL is the HTTP(S) endpoint receiving alert payloads. Leaving it
	// empty disables webhook notifications.
	WebhookURL string `yaml:"webhook_url"`

	// Format selects the payload shape: "json", "discord", "slack", or "ntfy".
	Format string `yaml:"format"`

	// MinSeverity filters out findings below this effective severity level.
	MinSeverity string `yaml:"min_severity"`
}

// Default returns a Config populated with safe, gentle defaults suitable for a
// typical home or small-office UniFi network.
func Default() *Config {
	ports := make([]int, len(DefaultPorts))
	copy(ports, DefaultPorts)

	return &Config{
		UniFi: UniFiConfig{
			Site:               "default",
			InsecureSkipVerify: true,
			Timeout:            10 * time.Second,
		},
		Scan: ScanConfig{
			Concurrency: 8,
			Timeout:     3 * time.Second,
			Ports:       ports,
			Interval:    15 * time.Minute,
		},
		State: StateConfig{
			Path: "uniblue-state.json",
		},
		Notify: NotifyConfig{
			Format:      "json",
			MinSeverity: "medium",
		},
	}
}

// Load reads a YAML configuration file from path, applies defaults for omitted
// fields, merges environment variable overrides, and validates the result.
func Load(path string) (*Config, error) {
	cfg := Default()

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	if err := yaml.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}

	// Overlay secret values from the environment so users can keep config.yaml
	// free of credentials without duplicating the entire file.
	if v := os.Getenv("UNIBLUE_UNIFI_PASSWORD"); v != "" {
		cfg.UniFi.Password = v
	}
	if v := os.Getenv("UNIBLUE_UNIFI_API_KEY"); v != "" {
		cfg.UniFi.APIKey = v
	}
	if v := os.Getenv("UNIBLUE_WEBHOOK_URL"); v != "" {
		cfg.Notify.WebhookURL = v
	}

	// Re-apply safe defaults for zero-valued fields that may have been explicitly
	// left empty in the YAML file.
	if cfg.UniFi.Site == "" {
		cfg.UniFi.Site = "default"
	}
	if cfg.UniFi.Timeout <= 0 {
		cfg.UniFi.Timeout = 10 * time.Second
	}
	if cfg.Scan.Concurrency <= 0 {
		cfg.Scan.Concurrency = 8
	}
	if cfg.Scan.Timeout <= 0 {
		cfg.Scan.Timeout = 3 * time.Second
	}
	if len(cfg.Scan.Ports) == 0 {
		cfg.Scan.Ports = append([]int(nil), DefaultPorts...)
	}
	if cfg.Scan.Interval <= 0 {
		cfg.Scan.Interval = 15 * time.Minute
	}
	if cfg.State.Path == "" {
		cfg.State.Path = "uniblue-state.json"
	}
	if cfg.Notify.Format == "" {
		cfg.Notify.Format = "json"
	}
	if cfg.Notify.MinSeverity == "" {
		cfg.Notify.MinSeverity = "medium"
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate checks that required fields are present and well-formed before any
// network calls are attempted.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.UniFi.URL) == "" {
		return errors.New("config: unifi.url is required")
	}
	parsed, err := url.Parse(c.UniFi.URL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return fmt.Errorf("config: unifi.url %q must be a valid http(s) URL", c.UniFi.URL)
	}
	if c.UniFi.APIKey == "" && (c.UniFi.Username == "" || c.UniFi.Password == "") {
		return errors.New("config: either unifi.api_key or unifi.username + unifi.password is required")
	}
	for _, p := range c.Scan.Ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("config: invalid scan port %d", p)
		}
	}
	switch strings.ToLower(c.Notify.Format) {
	case "json", "discord", "slack", "ntfy":
	default:
		return fmt.Errorf("config: unsupported notify.format %q (want json, discord, slack, or ntfy)", c.Notify.Format)
	}
	return nil
}

// ExcludedSet returns a fast lookup map of excluded IP addresses.
func (n NetworkConfig) ExcludedSet() map[string]struct{} {
	set := make(map[string]struct{}, len(n.ExcludeIPs))
	for _, ip := range n.ExcludeIPs {
		if trimmed := strings.TrimSpace(ip); trimmed != "" {
			set[trimmed] = struct{}{}
		}
	}
	return set
}
