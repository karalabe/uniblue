// Package checks loads, validates, and safely executes declarative YAML
// security checks against fingerprinted LAN hosts.
package checks

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// maxProbeTimeout bounds how long any single YAML check may specify so a
	// community check cannot stall a scan.
	maxProbeTimeout = 10 * time.Second

	// defaultProbeTimeout is applied when a YAML check omits probe.timeout.
	defaultProbeTimeout = 3 * time.Second
)

// idPattern restricts check identifiers to compact, uppercase alphanumeric IDs
// such as "UB-0001" or "UB-2026-0042".
var idPattern = regexp.MustCompile(`^[A-Z0-9][A-Z0-9_-]{2,48}$`)

// Severity ranks the impact of a security finding from informational to critical.
type Severity int

const (
	// SeverityInfo marks low-risk or already-mitigated observations.
	SeverityInfo Severity = iota
	// SeverityLow marks minor hardening opportunities.
	SeverityLow
	// SeverityMedium marks meaningful LAN exposure worth reviewing.
	SeverityMedium
	// SeverityHigh marks serious unauthenticated access or insecure services.
	SeverityHigh
	// SeverityCritical marks immediate takeover or WAN-exposed risk.
	SeverityCritical
)

// ParseSeverity converts a case-insensitive severity label into a Severity value.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return SeverityInfo, nil
	case "low":
		return SeverityLow, nil
	case "medium":
		return SeverityMedium, nil
	case "high":
		return SeverityHigh, nil
	case "critical":
		return SeverityCritical, nil
	default:
		return SeverityInfo, fmt.Errorf("unknown severity %q", s)
	}
}

// String returns the canonical lowercase label for a Severity level.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "info"
	}
}

// Bump shifts a severity up or down by delta levels, clamping within
// [SeverityInfo, SeverityCritical].
func (s Severity) Bump(delta int) Severity {
	next := int(s) + delta
	if next < int(SeverityInfo) {
		return SeverityInfo
	}
	if next > int(SeverityCritical) {
		return SeverityCritical
	}
	return Severity(next)
}

// MarshalText serializes Severity as its lowercase string in JSON/YAML output.
func (s Severity) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

// UnmarshalText parses a lowercase severity string from JSON/YAML input.
func (s *Severity) UnmarshalText(text []byte) error {
	parsed, err := ParseSeverity(string(text))
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}

// Check defines a single declarative, community-submittable LAN/IoT check.
type Check struct {
	// ID uniquely identifies the check (e.g., "UB-0001" or "UB-2026-0042").
	ID string `yaml:"id"`

	// Title is a short, human-readable summary of the issue detected.
	Title string `yaml:"title"`

	// CVE optionally records an official CVE identifier when one exists.
	CVE string `yaml:"cve"`

	// Category classifies the bug (e.g., "unauth-control", "exposed-protocol").
	Category string `yaml:"category"`

	// Severity is the base impact before UniFi VLAN/WAN blast-radius scoring.
	Severity Severity `yaml:"severity"`

	// Safety declares the probe's operational impact. v0.1 strictly requires
	// "read-only" so community checks cannot alter or reboot fragile devices.
	Safety string `yaml:"safety"`

	// Supersedes optionally lists generic check IDs (e.g., "UB-0001") that
	// should be suppressed on the same (host, port) when this more specific
	// device check confirms a match.
	Supersedes []string `yaml:"supersedes,omitempty"`

	// Metadata holds vendor, product, authorship, and reference links.
	Metadata Metadata `yaml:"metadata"`

	// Preconditions are evaluated cheaply against already-collected host
	// fingerprints; Stage 2 only runs when all specified preconditions pass.
	Preconditions Preconditions `yaml:"preconditions"`

	// Probe defines the bounded, target-only network verification step.
	Probe ProbeSpec `yaml:"probe"`

	// Remediation explains the risk and suggests UniFi-native mitigations.
	Remediation Remediation `yaml:"remediation"`

	// Source records the file path the check was loaded from for diagnostics.
	Source string `yaml:"-"`

	// compiled holds pre-validated regular expressions populated during Validate
	// so checks never pay regex compilation overhead per host.
	compiled compiledPatterns
}

// Metadata describes the target device family and attribution for a Check.
type Metadata struct {
	// Vendor names the hardware or firmware maker (or "Generic").
	Vendor string `yaml:"vendor"`

	// Product names the specific model or service targeted.
	Product string `yaml:"product"`

	// AffectedVersions documents known vulnerable firmware or software ranges.
	AffectedVersions string `yaml:"affected_versions"`

	// Author attributes the contributor who submitted the check.
	Author string `yaml:"author"`

	// References lists advisory URLs, forum posts, or CWE entries.
	References []string `yaml:"references"`
}

// Preconditions gate whether a check's probe is allowed to touch a host.
// All non-empty fields must match (logical AND); values within each slice
// match if any entry matches (logical OR).
type Preconditions struct {
	// PortsAny requires at least one of these TCP ports to be open on the host.
	PortsAny []int `yaml:"ports_any"`

	// MACPrefix requires the client's normalized MAC address to begin with any
	// of these colon-separated prefixes (e.g., "14:4f:d7" for Zehnder). This
	// works reliably even when UniFi Integration v1 omits the OUI vendor string.
	MACPrefix []string `yaml:"mac_prefix"`

	// OUIContains requires the client's MAC OUI/vendor string to contain any
	// of these case-insensitive substrings.
	OUIContains []string `yaml:"oui_contains"`

	// HostnameRegex matches against the client's UniFi name or DHCP hostname.
	HostnameRegex string `yaml:"hostname_regex"`

	// HTTPTitleRegex matches against the HTML <title> collected during fingerprinting.
	HTTPTitleRegex string `yaml:"http_title_regex"`

	// HTTPServerRegex matches against the HTTP Server header collected during fingerprinting.
	HTTPServerRegex string `yaml:"http_server_regex"`

	// HTTPStatusAny requires an open web port to have returned one of these status codes.
	HTTPStatusAny []int `yaml:"http_status_any"`
}

// ProbeSpec defines the target-only verification probe executed when a host
// satisfies a check's Preconditions.
type ProbeSpec struct {
	// Type selects the probe protocol: "tcp", "telnet", "http", "mqtt",
	// "modbus", "rtsp", "vnc", "avr", "comfoconnect", or "eth-rpc".
	Type string `yaml:"type"`

	// Port optionally pins the target port. When 0, the runner tests whichever
	// ports from Preconditions.PortsAny were observed open on the host.
	Port int `yaml:"port"`

	// Scheme optionally forces "http" or "https" for HTTP probes; inferred from
	// the port when left empty.
	Scheme string `yaml:"scheme"`

	// Method sets the HTTP verb for HTTP probes. Only GET, HEAD, and OPTIONS are
	// permitted so community checks remain strictly read-only.
	Method string `yaml:"method"`

	// Path is the relative request path for HTTP probes (must begin with "/").
	Path string `yaml:"path"`

	// Timeout bounds how long the probe waits for a response from the target.
	Timeout time.Duration `yaml:"timeout"`

	// Match configures response matching rules for HTTP and TCP banner probes.
	Match MatchSpec `yaml:"match"`
}

// MatchSpec defines deterministic conditions that confirm a finding.
type MatchSpec struct {
	// Status requires the HTTP response status to match one of these codes.
	Status []int `yaml:"status"`

	// BodyContainsAll requires every substring to appear in the response body.
	BodyContainsAll []string `yaml:"body_contains_all"`

	// BodyContainsAny requires at least one substring to appear in the body.
	BodyContainsAny []string `yaml:"body_contains_any"`

	// BodyRegex matches a regular expression against the response body.
	BodyRegex string `yaml:"body_regex"`

	// HeadersAbsent requires none of these header names to be present.
	HeadersAbsent []string `yaml:"headers_absent"`

	// HeadersPresent requires all of these header names to be present.
	HeadersPresent []string `yaml:"headers_present"`

	// BannerRegex matches against the initial bytes read from a TCP banner probe.
	BannerRegex string `yaml:"banner_regex"`

	// RedactBody ensures raw response content is never copied into evidence strings.
	RedactBody bool `yaml:"redact_body"`
}

// Remediation captures plain-English guidance and suggested UniFi actions.
type Remediation struct {
	// Summary explains what is exposed and how to reduce risk.
	Summary string `yaml:"summary"`

	// UniFiActions lists structured UniFi remediation hints (e.g., move_to_iot_vlan).
	UniFiActions []string `yaml:"unifi_actions"`
}

// compiledPatterns caches compiled regular expressions validated at load time.
type compiledPatterns struct {
	hostname   *regexp.Regexp
	httpTitle  *regexp.Regexp
	httpServer *regexp.Regexp
	body       *regexp.Regexp
	banner     *regexp.Regexp
}

// LoadFromFS walks an embedded or virtual filesystem, parsing and validating
// every .yaml/.yml check file it finds.
func LoadFromFS(fsys fs.FS) ([]*Check, error) {
	var paths []string
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk checks fs: %w", err)
	}
	sort.Strings(paths)

	checks := make([]*Check, 0, len(paths))
	for _, p := range paths {
		raw, err := fs.ReadFile(fsys, p)
		if err != nil {
			return nil, fmt.Errorf("read check %q: %w", p, err)
		}
		chk, err := Parse(raw, p)
		if err != nil {
			return nil, err
		}
		checks = append(checks, chk)
	}
	return checks, nil
}

// LoadFromDir loads and validates all YAML check files beneath a local
// filesystem directory.
func LoadFromDir(dir string) ([]*Check, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("stat checks dir %q: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("checks path %q is not a directory", dir)
	}
	return LoadFromFS(os.DirFS(dir))
}

// Merge combines multiple check slices, rejecting duplicate IDs so community
// overrides or accidental duplicates fail loudly rather than silently masking.
func Merge(groups ...[]*Check) ([]*Check, error) {
	seen := make(map[string]string)
	var merged []*Check
	for _, g := range groups {
		for _, chk := range g {
			if prev, exists := seen[chk.ID]; exists {
				return nil, fmt.Errorf("duplicate check id %q in %q and %q", chk.ID, prev, chk.Source)
			}
			seen[chk.ID] = chk.Source
			merged = append(merged, chk)
		}
	}
	sort.Slice(merged, func(i, j int) bool {
		return merged[i].ID < merged[j].ID
	})
	return merged, nil
}

// Parse decodes a single YAML check definition and enforces all schema and
// safety guardrails.
func Parse(raw []byte, source string) (*Check, error) {
	var chk Check
	if err := yaml.Unmarshal(raw, &chk); err != nil {
		return nil, fmt.Errorf("parse check %q: %w", source, err)
	}
	chk.Source = source
	if err := chk.Validate(); err != nil {
		return nil, fmt.Errorf("invalid check %q: %w", source, err)
	}
	return &chk, nil
}

// Validate enforces schema completeness and safety invariants on a Check and
// pre-compiles all regular expressions.
func (c *Check) Validate() error {
	if !idPattern.MatchString(c.ID) {
		return fmt.Errorf("id %q must match %s", c.ID, idPattern.String())
	}
	if strings.TrimSpace(c.Title) == "" {
		return errors.New("title is required")
	}
	if strings.TrimSpace(c.Safety) != "read-only" {
		return fmt.Errorf("safety must be %q (got %q)", "read-only", c.Safety)
	}
	if len(c.Preconditions.PortsAny) == 0 {
		return errors.New("preconditions.ports_any must specify at least one port")
	}
	for _, p := range c.Preconditions.PortsAny {
		if p < 1 || p > 65535 {
			return fmt.Errorf("invalid precondition port %d", p)
		}
	}

	// Normalize and validate probe settings, enforcing strict read-only and
	// target-only guardrails so community checks cannot exfiltrate LAN data or
	// mutate device state.
	c.Probe.Type = strings.ToLower(strings.TrimSpace(c.Probe.Type))
	switch c.Probe.Type {
	case "tcp", "telnet", "mqtt", "modbus", "rtsp", "vnc", "avr", "comfoconnect", "eth-rpc":
	case "http":
		method := strings.ToUpper(strings.TrimSpace(c.Probe.Method))
		if method == "" {
			method = "GET"
		}
		if method != "GET" && method != "HEAD" && method != "OPTIONS" {
			return fmt.Errorf("http probe method %q is forbidden; only GET, HEAD, and OPTIONS are allowed", method)
		}
		c.Probe.Method = method

		// Paths must be strictly relative so a check can never direct traffic to
		// an external host or trigger an SSRF callback.
		if !strings.HasPrefix(c.Probe.Path, "/") || strings.Contains(c.Probe.Path, "://") || strings.HasPrefix(c.Probe.Path, "//") {
			return fmt.Errorf("http probe path %q must be a relative path starting with /", c.Probe.Path)
		}
		if c.Probe.Scheme != "" && c.Probe.Scheme != "http" && c.Probe.Scheme != "https" {
			return fmt.Errorf("http probe scheme %q must be http or https", c.Probe.Scheme)
		}
	default:
		return fmt.Errorf("unsupported probe.type %q", c.Probe.Type)
	}

	if c.Probe.Port < 0 || c.Probe.Port > 65535 {
		return fmt.Errorf("invalid probe.port %d", c.Probe.Port)
	}
	if c.Probe.Timeout <= 0 {
		c.Probe.Timeout = defaultProbeTimeout
	}
	if c.Probe.Timeout > maxProbeTimeout {
		return fmt.Errorf("probe.timeout %s exceeds safety cap of %s", c.Probe.Timeout, maxProbeTimeout)
	}

	// Pre-compile every optional regex so syntax mistakes fail validation early.
	var err error
	if c.Preconditions.HostnameRegex != "" {
		if c.compiled.hostname, err = regexp.Compile(c.Preconditions.HostnameRegex); err != nil {
			return fmt.Errorf("preconditions.hostname_regex: %w", err)
		}
	}
	if c.Preconditions.HTTPTitleRegex != "" {
		if c.compiled.httpTitle, err = regexp.Compile(c.Preconditions.HTTPTitleRegex); err != nil {
			return fmt.Errorf("preconditions.http_title_regex: %w", err)
		}
	}
	if c.Preconditions.HTTPServerRegex != "" {
		if c.compiled.httpServer, err = regexp.Compile(c.Preconditions.HTTPServerRegex); err != nil {
			return fmt.Errorf("preconditions.http_server_regex: %w", err)
		}
	}
	if c.Probe.Match.BodyRegex != "" {
		if c.compiled.body, err = regexp.Compile(c.Probe.Match.BodyRegex); err != nil {
			return fmt.Errorf("probe.match.body_regex: %w", err)
		}
	}
	if c.Probe.Match.BannerRegex != "" {
		if c.compiled.banner, err = regexp.Compile(c.Probe.Match.BannerRegex); err != nil {
			return fmt.Errorf("probe.match.banner_regex: %w", err)
		}
	}

	return nil
}
