// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package config loads and validates UniBlue runtime configuration from YAML
// files and environment variable overrides.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultPorts lists the curated set of high-signal service, database,
// homelab, and IoT ports checked when no custom port list is supplied. Keeping
// the list focused avoids overwhelming fragile embedded devices while giving
// Nerva broad Shodan-style protocol coverage across the LAN.
var DefaultPorts = []int{
	21, 22, 23, 53, 80, 111, 443, 445,
	502, 554, 623, 631, 1883, 2049, 2375, 3000,
	3306, 3389, 5000, 5052, 5432, 5900, 5901, 6379,
	8006, 8080, 8123, 8443, 8545, 9100, 27017,
}

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

// PhysicalPortRule assigns an explicit physical-security zone and optional MAC
// allowlist to a single switch, gateway, or In-Wall AP port.
type PhysicalPortRule struct {
	// Device matches the UniFi switch/gateway/AP name (case-insensitive) or MAC address.
	Device string `yaml:"device"`

	// Port is the 1-based physical port number (port_idx) on Device.
	Port int `yaml:"port"`

	// Zone classifies the physical exposure of this cable drop:
	// "external" (outside secured perimeter), "internal" (inside secured room),
	// or "unused" (expected unplugged and administratively disabled).
	Zone string `yaml:"zone"`

	// Label is an optional human-readable description (e.g., "Driveway Camera").
	Label string `yaml:"label,omitempty"`

	// AllowedMACs optionally pins expected hardware MAC address(es) on this jack.
	AllowedMACs []string `yaml:"allowed_macs,omitempty"`
}

// NetworkConfig defines local network segmentation hints so UniBlue can weigh
// findings by where a device actually lives.
type NetworkConfig struct {
	// Assets declares the impact and platform relations of individual devices and clients.
	Assets []AssetOverride `yaml:"assets,omitempty"`

	// TrustedVLANs identifies trusted networks for isolation policy evaluation.
	TrustedVLANs []string `yaml:"trusted_vlans"`

	// IsolatedVLANs identifies networks intended to contain untrusted devices.
	IsolatedVLANs []string `yaml:"isolated_vlans"`

	// ExcludeIPs lists IP addresses that UniBlue must never actively probe.
	ExcludeIPs []string `yaml:"exclude_ips"`

	// ExternalDevices lists UniFi switch/AP names (case-insensitive) or MAC
	// addresses physically installed outside the secured perimeter (e.g., a
	// garage, outbuilding, or outdoor PoE switch). Every port on a listed device
	// is treated as "external", and the indoor parent switch port feeding it via
	// LLDP is automatically audited as "external_uplink".
	ExternalDevices []string `yaml:"external_devices,omitempty"`

	// PhysicalPorts assigns explicit physical-perimeter zones ("external",
	// "internal", or "unused") and optional allowed MACs to specific switch ports.
	PhysicalPorts []PhysicalPortRule `yaml:"physical_ports,omitempty"`

	// BridgeInventories lists optional owner-provided read-only bridge, NVR,
	// Zigbee2MQTT, Z-Wave JS, Matter, or BLE proxy inventory files.
	BridgeInventories []BridgeInventoryConfig `yaml:"bridge_inventories,omitempty"`

	// PassiveFlowsPath optionally points to an owner-supplied passive service /
	// flow log file (Zeek known_services, IPFIX summary, or JSON/YAML manifest).
	PassiveFlowsPath string `yaml:"passive_flows_path,omitempty"`

	// SiteSupplementPath optionally points to an owner-supplied YAML/JSON file
	// supplying controller-omitted telemetry (switch ACLs, dynamic NAT leases,
	// reverse proxy routes, published tunnels, and backup freshness).
	SiteSupplementPath string `yaml:"site_supplement_path,omitempty"`

	// IsolationPolicy declares optional site isolation intent and explicitly
	// approved cross-zone workflows (e.g., Guest -> Printer IPPS TCP 631 allowed,
	// Admin Workstation -> BMC allowed) so UniBlue preserves legitimate
	// dependencies and leaves approved paths out of the action queue.
	IsolationPolicy IsolationIntent `yaml:"isolation_policy,omitempty"`
}

// AssetOverride pins the impact and platform relations of a device or client
// identified by its hardware address or stable controller ID.
type AssetOverride struct {
	// MAC identifies the host by its hardware address.
	MAC string `yaml:"mac,omitempty"`
	// ID identifies the host by its case-sensitive controller ID.
	ID string `yaml:"id,omitempty"`
	// Label is an optional reminder of the host's purpose.
	Label string `yaml:"label,omitempty"`
	// Tier replaces the inferred asset value tier when specified.
	Tier string `yaml:"tier,omitempty"`
	// Consequences replaces the inferred dimensions when specified.
	Consequences []string `yaml:"consequences,omitempty"`
	// Manages lists the MACs or IDs of hosts this device controls.
	Manages []string `yaml:"manages,omitempty"`
	// Hosts lists the MACs or IDs of guests running on this device.
	Hosts []string `yaml:"hosts,omitempty"`
}

// BridgeInventoryConfig points to one owner-supplied bridge/recorder inventory file.
type BridgeInventoryConfig struct {
	// Format identifies the bridge inventory schema or parser to use.
	Format string `yaml:"format"`
	// Path is the filesystem path to the read-only inventory file.
	Path string `yaml:"path"`
	// ParentIP optionally identifies the parent bridge, hub, or recorder IP.
	ParentIP string `yaml:"parent_ip,omitempty"`
	// ParentMAC optionally identifies the parent bridge, hub, or recorder MAC.
	ParentMAC string `yaml:"parent_mac,omitempty"`
	// ParentRole optionally describes the parent device's operational role.
	ParentRole string `yaml:"parent_role,omitempty"`
	// ObservedFrom optionally records where or how the inventory export was collected.
	ObservedFrom string `yaml:"observed_from,omitempty"`
}

// ApprovedPath declares one explicitly intended cross-zone service workflow
// (such as Guest -> Printer IPPS on TCP 631 or NVR -> Camera RTSP on TCP 554).
type ApprovedPath struct {
	// Name is the display label shown in reports and BreaksApproved annotations.
	Name string `yaml:"name" json:"name"`
	// SourceZone names the originating firewall zone or network.
	SourceZone string `yaml:"source_zone" json:"source_zone"`
	// DestRole optionally matches destinations by classified role or category.
	DestRole string `yaml:"dest_role,omitempty" json:"dest_role,omitempty"`
	// DestIP optionally restricts the destination to a specific IP address.
	DestIP string `yaml:"dest_ip,omitempty" json:"dest_ip,omitempty"`
	// DestZone optionally names the destination firewall zone or network (e.g., "External").
	DestZone string `yaml:"dest_zone,omitempty" json:"dest_zone,omitempty"`
	// Function labels the approved service workflow (e.g., "ipps-printing", "bmc-admin", "camera-recording").
	Function string `yaml:"function" json:"function"`
	// Transport specifies the layer 4 protocol ("tcp" or "udp").
	Transport string `yaml:"transport" json:"transport"`
	// Port specifies the destination port number (0 acts as a wildcard in some
	// approval lookups, while transit exceptions require a positive port).
	Port int `yaml:"port" json:"port"`
	// IPVersion optionally limits matching to "ipv4", "ipv6", or "both".
	IPVersion string `yaml:"ip_version,omitempty" json:"ip_version,omitempty"`
	// Description optionally documents why this cross-zone path is approved.
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// IsolationIntent captures declared site segmentation goals and approved workflows.
type IsolationIntent struct {
	// ManagementVLANs lists VLAN/network names reserved for OOB/BMC/admin gear.
	ManagementVLANs []string `yaml:"management_vlans,omitempty" json:"management_vlans,omitempty"`

	// CameraVLANs lists VLAN/network names dedicated to IP cameras/NVRs.
	CameraVLANs []string `yaml:"camera_vlans,omitempty" json:"camera_vlans,omitempty"`

	// GuestVLANs lists VLAN/network names reserved for guests/visitors.
	GuestVLANs []string `yaml:"guest_vlans,omitempty" json:"guest_vlans,omitempty"`

	// IoTVLANs lists VLAN/network names reserved for untrusted IoT/smart-home devices.
	IoTVLANs []string `yaml:"iot_vlans,omitempty" json:"iot_vlans,omitempty"`

	// NoInternetVLANs lists VLAN/network names where outbound internet access
	// must stay blocked (flagging any open or leaking VLAN -> External path).
	NoInternetVLANs []string `yaml:"no_internet_vlans,omitempty" json:"no_internet_vlans,omitempty"`

	// StrictInboundVLANs lists VLAN/network names where broad LAN -> VLAN
	// inbound access must stay blocked outside explicitly approved paths.
	StrictInboundVLANs []string `yaml:"strict_inbound_vlans,omitempty" json:"strict_inbound_vlans,omitempty"`

	// ApprovedPaths lists explicitly permitted cross-zone service paths.
	ApprovedPaths []ApprovedPath `yaml:"approved_paths,omitempty" json:"approved_paths,omitempty"`

	// RequireSameVLANIsolation lists network/VLAN names where same-VLAN peer
	// isolation is required by policy (triggering switch ACL / AP isolation checks).
	RequireSameVLANIsolation []string `yaml:"require_same_vlan_isolation,omitempty" json:"require_same_vlan_isolation,omitempty"`
}

// ScanConfig controls probing concurrency, timeouts, and check loading.
type ScanConfig struct {
	// Concurrency caps how many LAN hosts are fingerprinted or checked in parallel.
	Concurrency int `yaml:"concurrency"`

	// Timeout bounds each individual TCP connect or HTTP probe.
	Timeout time.Duration `yaml:"timeout"`

	// Ports optionally replaces DefaultPorts when non-empty. Leave empty to
	// inherit UniBlue's curated DefaultPorts automatically.
	Ports []int `yaml:"ports"`

	// ExtraPorts appends additional TCP ports onto DefaultPorts without
	// replacing the built-in list.
	ExtraPorts []int `yaml:"extra_ports"`

	// ChecksDir is an optional filesystem directory containing additional YAML
	// checks loaded alongside the embedded built-in checks.
	ChecksDir string `yaml:"checks_dir"`

	// Interval sets the delay between consecutive scans in `uniblue watch`.
	Interval time.Duration `yaml:"interval"`

	// DisableSSHAuthProbe skips discovery of the authentication methods offered by SSH servers.
	DisableSSHAuthProbe bool `yaml:"disable_ssh_auth_probe,omitempty"`

	// SSHKeyAudit configures the strictly opt-in, Fail2ban-safe SSH public-key
	// reachability check (RFC 4252 section 7). Disabled by default.
	SSHKeyAudit *SSHKeyAuditConfig `yaml:"ssh_key_audit,omitempty"`
}

// SSHKeyAuditConfig controls opt-in SSH "none" and public-key (PK_OK) checks.
// It accepts only local OpenSSH .pub files, refuses private keys, and caps
// probes per host to stay below Fail2ban and sshd MaxStartups thresholds.
type SSHKeyAuditConfig struct {
	// Enabled overrides the default of auditing when public key files are configured.
	Enabled *bool `yaml:"enabled,omitempty"`

	// PublicKeyFiles lists local OpenSSH .pub file paths to test.
	PublicKeyFiles []string `yaml:"public_key_files,omitempty"`

	// Usernames lists local account names to query with the configured public keys.
	Usernames []string `yaml:"usernames,omitempty"`

	// TargetHosts optionally restricts the audit to specific IPs, MACs, or hostnames.
	TargetHosts []string `yaml:"target_hosts,omitempty"`

	// MaxProbesPerHost caps total SSH auth-attempting connections per host
	// (including the canary check) to stay below Fail2ban and OpenSSH 9.8+
	// PerSourcePenalties thresholds (default 3, hard max 3).
	MaxProbesPerHost int `yaml:"max_probes_per_host,omitempty"`
}

// Active reports whether the operator has configured the public-key audit.
func (c *SSHKeyAuditConfig) Active() bool {
	if c == nil {
		return false
	}
	if c.Enabled != nil {
		return *c.Enabled
	}
	return len(c.PublicKeyFiles) > 0
}

// StateConfig controls where UniBlue persists its baseline scan state.
type StateConfig struct {
	// Path is the filesystem location of the JSON state file used for diffing.
	Path string `yaml:"path"`

	// ExplicitPath reports whether state.path was explicitly configured in YAML
	// rather than falling back to the default state path.
	ExplicitPath bool `yaml:"-" json:"-"`
}

// NotifyConfig controls outbound webhook alerts during watch and serve modes.
type NotifyConfig struct {
	// WebhookURL is the HTTP(S) endpoint receiving alert payloads. Leaving it
	// empty disables webhook notifications.
	WebhookURL string `yaml:"webhook_url"`

	// WebhookSecret optionally signs outbound webhook POSTs using the Standard
	// Webhooks scheme (webhook-id, webhook-timestamp, webhook-signature). Accepts
	// either a raw shared secret or a whsec_<base64> secret. Leave empty to send
	// unsigned webhooks.
	WebhookSecret string `yaml:"webhook_secret"`

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
//
// If path does not exist and UNIBLUE_UNIFI_URL is set in the environment, Load
// constructs a zero-file configuration directly from environment variables.
func Load(path string) (*Config, error) {
	cfg := Default()

	loadedFromFile := false
	raw, err := os.ReadFile(path)
	if err != nil {
		if !(errors.Is(err, os.ErrNotExist) && os.Getenv("UNIBLUE_UNIFI_URL") != "") {
			return nil, fmt.Errorf("read config %q: %w", path, err)
		}
	} else {
		loadedFromFile = true
		// Clear default ports and state path before unmarshaling so we can tell
		// whether the YAML file explicitly set scan.ports or state.path
		// (setting State.ExplicitPath) vs. leaving them omitted.
		cfg.Scan.Ports = nil
		cfg.State.Path = ""
		dec := yaml.NewDecoder(bytes.NewReader(raw))
		dec.KnownFields(true)
		if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("parse config %q: %w", path, err)
		}
		cfg.State.ExplicitPath = cfg.State.Path != ""
	}

	// Overlay connection and secret values from the environment so UniBlue can
	// run with a minimal (or even absent) config.yaml.
	if v := os.Getenv("UNIBLUE_UNIFI_URL"); v != "" {
		cfg.UniFi.URL = v
	}
	if v := os.Getenv("UNIBLUE_UNIFI_SITE"); v != "" {
		cfg.UniFi.Site = v
	}
	if v := os.Getenv("UNIBLUE_UNIFI_USERNAME"); v != "" {
		cfg.UniFi.Username = v
	}
	if v := os.Getenv("UNIBLUE_UNIFI_PASSWORD"); v != "" {
		cfg.UniFi.Password = v
	}
	if v := os.Getenv("UNIBLUE_UNIFI_API_KEY"); v != "" {
		cfg.UniFi.APIKey = v
	}
	if v := os.Getenv("UNIBLUE_WEBHOOK_URL"); v != "" {
		cfg.Notify.WebhookURL = v
	}
	if v := os.Getenv("UNIBLUE_WEBHOOK_SECRET"); v != "" {
		cfg.Notify.WebhookSecret = v
	}
	if v := os.Getenv("UNIBLUE_WEBHOOK_FORMAT"); v != "" {
		cfg.Notify.Format = v
	}
	if v := os.Getenv("UNIBLUE_WEBHOOK_MIN_SEVERITY"); v != "" {
		cfg.Notify.MinSeverity = v
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
	if len(cfg.Scan.ExtraPorts) > 0 {
		cfg.Scan.Ports = dedupeInts(append(cfg.Scan.Ports, cfg.Scan.ExtraPorts...))
	}
	if cfg.Scan.Interval <= 0 {
		cfg.Scan.Interval = 15 * time.Minute
	}
	if cfg.Scan.SSHKeyAudit.Active() && cfg.Scan.SSHKeyAudit.MaxProbesPerHost <= 0 {
		cfg.Scan.SSHKeyAudit.MaxProbesPerHost = 3
	}
	if cfg.State.Path == "" {
		cfg.State.Path = "uniblue-state.json"
	}
	// Anchor relative state paths to the config file's directory when loaded
	// from disk. In zero-file env mode started from "/", redirect to a writable
	// user state/cache directory instead of attempting to write at root.
	if !filepath.IsAbs(cfg.State.Path) {
		if loadedFromFile {
			if cfgDir := filepath.Dir(path); cfgDir != "" && cfgDir != "." {
				cfg.State.Path = filepath.Join(cfgDir, cfg.State.Path)
			}
		} else if cwd, err := os.Getwd(); err == nil && cwd == string(filepath.Separator) {
			cfg.State.Path = defaultFallbackStatePath(cfg.State.Path)
		}
	}
	if cfg.Notify.Format == "" {
		cfg.Notify.Format = "json"
	}
	if cfg.Notify.MinSeverity == "" {
		cfg.Notify.MinSeverity = "medium"
	}

	// Canonicalize configured MAC addresses (supporting dash, dot, and bare hex forms)
	// so comparisons against UniFi colon-form MACs always match reliably.
	for i, dev := range cfg.Network.ExternalDevices {
		if mac, ok := ParseCanonicalMAC(dev); ok {
			cfg.Network.ExternalDevices[i] = mac
		}
	}
	for i := range cfg.Network.PhysicalPorts {
		if mac, ok := ParseCanonicalMAC(cfg.Network.PhysicalPorts[i].Device); ok {
			cfg.Network.PhysicalPorts[i].Device = mac
		}
		for j, m := range cfg.Network.PhysicalPorts[i].AllowedMACs {
			cfg.Network.PhysicalPorts[i].AllowedMACs[j] = CanonicalMAC(m)
		}
	}
	for i := range cfg.Network.BridgeInventories {
		if mac, ok := ParseCanonicalMAC(cfg.Network.BridgeInventories[i].ParentMAC); ok {
			cfg.Network.BridgeInventories[i].ParentMAC = mac
		}
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// ParseCanonicalMAC parses a 48-bit MAC address in colon, dash, Cisco dot, or
// bare 12-hex-digit form and returns lowercase colon-separated aa:bb:cc:dd:ee:ff.
func ParseCanonicalMAC(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", false
	}
	var hexBuf [12]byte
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ':' || c == '-' || c == '.' {
			continue
		}
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
			c += 'a' - 'A'
		default:
			return "", false
		}
		if n >= 12 {
			return "", false
		}
		hexBuf[n] = c
		n++
	}
	if n != 12 {
		return "", false
	}
	return fmt.Sprintf("%s:%s:%s:%s:%s:%s",
		hexBuf[0:2], hexBuf[2:4], hexBuf[4:6], hexBuf[6:8], hexBuf[8:10], hexBuf[10:12]), true
}

// CanonicalMAC returns the canonical lowercase colon-separated MAC when raw is
// a valid 48-bit MAC, or trimmed lowercase raw otherwise.
func CanonicalMAC(raw string) string {
	if mac, ok := ParseCanonicalMAC(raw); ok {
		return mac
	}
	return strings.ToLower(strings.TrimSpace(raw))
}

// defaultFallbackStatePath places baseName under XDG_STATE_HOME (or the user
// cache directory) when running in zero-file environment mode with cwd == "/".
func defaultFallbackStatePath(baseName string) string {
	if stateHome := strings.TrimSpace(os.Getenv("XDG_STATE_HOME")); stateHome != "" {
		return filepath.Join(stateHome, "uniblue", baseName)
	}
	if cacheDir, err := os.UserCacheDir(); err == nil && cacheDir != "" {
		return filepath.Join(cacheDir, "uniblue", baseName)
	}
	return baseName
}

// Validate checks that required fields are present and well-formed before any
// network calls are attempted, and normalizes/canonicalizes c.Network.Assets
// entries in place.
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
	if ka := c.Scan.SSHKeyAudit; ka.Active() {
		if ka.MaxProbesPerHost > 3 {
			return fmt.Errorf("config: scan.ssh_key_audit.max_probes_per_host %d exceeds Fail2ban-safe hard cap 3", ka.MaxProbesPerHost)
		}
		if len(ka.PublicKeyFiles) == 0 {
			return errors.New("config: scan.ssh_key_audit.public_key_files must list at least one .pub file when enabled")
		}
		if len(ka.Usernames) == 0 {
			return errors.New("config: scan.ssh_key_audit.usernames must list at least one username when enabled")
		}
	}
	switch strings.ToLower(c.Notify.Format) {
	case "json", "discord", "slack", "ntfy":
	default:
		return fmt.Errorf("config: unsupported notify.format %q (want json, discord, slack, or ntfy)", c.Notify.Format)
	}
	if wh := strings.TrimSpace(c.Notify.WebhookURL); wh != "" {
		whURL, err := url.Parse(wh)
		if err != nil || (whURL.Scheme != "http" && whURL.Scheme != "https") || whURL.Host == "" {
			return errors.New("config: notify.webhook_url must be a valid http(s) URL")
		}
	}
	for _, pr := range c.Network.PhysicalPorts {
		if strings.TrimSpace(pr.Device) == "" || pr.Port < 1 {
			return fmt.Errorf("config: physical_ports entry requires device and port >= 1 (got device=%q port=%d)", pr.Device, pr.Port)
		}
		switch strings.ToLower(strings.TrimSpace(pr.Zone)) {
		case "external", "internal", "unused":
		default:
			return fmt.Errorf("config: unsupported physical_ports zone %q for %s port %d (want external, internal, or unused)", pr.Zone, pr.Device, pr.Port)
		}
	}
	return validateAssets(c.Network.Assets)
}

// ValidAssetTier reports whether tier names a supported asset value tier.
func ValidAssetTier(tier string) bool {
	switch tier {
	case "crown", "high", "medium", "low", "disposable":
		return true
	}
	return false
}

// ValidConsequence reports whether dimension names a supported kind of impact.
func ValidConsequence(dimension string) bool {
	switch dimension {
	case "control-plane", "data", "identity", "privacy", "physical", "continuity":
		return true
	}
	return false
}

// validateAssets canonicalizes hardware addresses before comparing selectors
// and relations so alternate spellings cannot hide duplicates or self-references.
func validateAssets(assets []AssetOverride) error {
	macs, ids := make(map[string]bool), make(map[string]bool)
	for i := range assets {
		a := &assets[i]
		a.MAC = strings.TrimSpace(a.MAC)
		a.ID = strings.TrimSpace(a.ID)
		if a.MAC == "" && a.ID == "" {
			return fmt.Errorf("config: network.assets[%d] requires a MAC or ID", i)
		}
		if a.MAC != "" {
			mac, ok := ParseCanonicalMAC(a.MAC)
			if !ok {
				return fmt.Errorf("config: network.assets[%d] has invalid MAC %q", i, a.MAC)
			}
			if macs[mac] {
				return fmt.Errorf("config: network.assets[%d] repeats MAC %q", i, mac)
			}
			a.MAC = mac
			macs[mac] = true
		}
		if a.ID != "" {
			if ids[a.ID] {
				return fmt.Errorf("config: network.assets[%d] repeats ID %q", i, a.ID)
			}
			ids[a.ID] = true
		}
		a.Tier = strings.ToLower(strings.TrimSpace(a.Tier))
		if a.Tier != "" && !ValidAssetTier(a.Tier) {
			return fmt.Errorf("config: network.assets[%d] has invalid tier %q", i, a.Tier)
		}
		for j, dim := range a.Consequences {
			dim = strings.ToLower(strings.TrimSpace(dim))
			if !ValidConsequence(dim) {
				return fmt.Errorf("config: network.assets[%d] has invalid consequence %q", i, a.Consequences[j])
			}
			a.Consequences[j] = dim
		}
		for _, targets := range [][]string{a.Manages, a.Hosts} {
			for j, target := range targets {
				target = strings.TrimSpace(target)
				if target == "" {
					return fmt.Errorf("config: network.assets[%d] has an empty target", i)
				}
				mac, isMAC := ParseCanonicalMAC(target)
				if target == a.ID || (isMAC && mac == a.MAC) {
					return fmt.Errorf("config: network.assets[%d] cannot manage or host itself", i)
				}
				if isMAC {
					target = mac
				}
				targets[j] = target
			}
		}
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

// dedupeInts removes duplicate integers from nums while preserving their first
// seen order.
func dedupeInts(nums []int) []int {
	seen := make(map[int]struct{}, len(nums))
	out := make([]int, 0, len(nums))
	for _, n := range nums {
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}
