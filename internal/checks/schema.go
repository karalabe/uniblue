// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package checks loads, validates, and safely executes declarative YAML
// security checks against fingerprinted LAN hosts.
package checks

import (
	"bytes"
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

	// maxProbeSteps limits sequential HTTP observations within one probe timeout.
	maxProbeSteps = 4
)

// idPattern restricts check identifiers to compact, uppercase alphanumeric IDs
// such as "UB-0001" or "UB-2026-0042".
var idPattern = regexp.MustCompile(`^[A-Z0-9][A-Z0-9_-]{2,48}$`)

// jsonPathPattern accepts the root, object keys and optional array indices
// supported by evalJSONPath. Wildcards and filters are outside this subset.
var jsonPathPattern = regexp.MustCompile(`^\$(\[[0-9]+\])?(\.[^.\[\]*]+(\[[0-9]+\])?)*$`)

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

// ClaimKind separates what a check or finding actually establishes so pure
// inventory observations never open false security incidents while configured
// paths and confirmed permissions remain clearly distinguished.
type ClaimKind string

const (
	// ClaimAssetIdentity establishes the identity or role of a host or child device.
	ClaimAssetIdentity ClaimKind = "asset-identity"
	// ClaimServiceAdvertised records a service announcement (mDNS/SSDP/WS-D).
	ClaimServiceAdvertised ClaimKind = "service-advertised"
	// ClaimServiceObserved records a protocol-aware observed service endpoint.
	ClaimServiceObserved ClaimKind = "service-observed"
	// ClaimConfiguredAccess records a policy, route, ACL, or NAT configured path.
	ClaimConfiguredAccess ClaimKind = "configured-access"
	// ClaimConfirmedPermission records an evidenced anonymous or excess permission/exposure.
	ClaimConfirmedPermission ClaimKind = "confirmed-permission"
)

// ParseClaimKind validates and normalizes a YAML claim string.
func ParseClaimKind(s string) (ClaimKind, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return "", nil
	case string(ClaimAssetIdentity):
		return ClaimAssetIdentity, nil
	case string(ClaimServiceAdvertised):
		return ClaimServiceAdvertised, nil
	case string(ClaimServiceObserved):
		return ClaimServiceObserved, nil
	case string(ClaimConfiguredAccess):
		return ClaimConfiguredAccess, nil
	case string(ClaimConfirmedPermission):
		return ClaimConfirmedPermission, nil
	default:
		return "", fmt.Errorf("unknown claim %q", s)
	}
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

	// Claim declares the semantic evidence level established when this check
	// matches (asset-identity, service-advertised, service-observed,
	// configured-access, or confirmed-permission).
	Claim ClaimKind `yaml:"claim,omitempty"`

	// Property optionally names the specific security property proven (e.g.,
	// "tls-protocol", "auth-anon", "smb-v1") so independent properties on the
	// same endpoint are never deduplicated against one another.
	Property string `yaml:"property,omitempty"`

	// Severity is the base impact before UniFi VLAN/WAN blast-radius scoring.
	Severity Severity `yaml:"severity"`

	// Safety declares the probe's operational impact. UniBlue strictly requires
	// "read-only" so community checks cannot alter or reboot fragile devices.
	Safety string `yaml:"safety"`

	// Supersedes optionally lists generic check IDs (e.g., "UB-0001") that
	// should be suppressed on the same (host, port) when this more specific
	// device check confirms a match.
	Supersedes []string `yaml:"supersedes,omitempty"`

	// Metadata holds vendor, product, authorship, and reference links.
	Metadata Metadata `yaml:"metadata"`

	// Preconditions are evaluated cheaply against already-collected host
	// fingerprints; the verification probe only runs when all preconditions pass.
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

	// PortsAll requires every listed TCP port to be open on the host (useful for
	// multi-service fingerprints such as iOS lockdownd + SSH on a jailbroken device).
	PortsAll []int `yaml:"ports_all"`

	// MACPrefix requires the client's normalized MAC address to begin with any
	// of these colon-separated OUI prefixes (e.g., "00:11:22"). This works
	// reliably even when UniFi Integration v1 omits the OUI vendor string.
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

	// MDNSTypeAny matches hosts advertising any of these DNS-SD service types
	// (e.g., "_esphomelib._tcp", "_hap._tcp", "_ipp._tcp").
	MDNSTypeAny []string `yaml:"mdns_type_any"`

	// MDNSTXTRegex matches allowlisted DNS-SD TXT key=value pairs on matched services.
	MDNSTXTRegex string `yaml:"mdns_txt_regex"`

	// MDNSTXTNotRegex rejects a matched mDNS service if any allowlisted TXT
	// key=value pair matches this pattern (e.g., excluding encrypted nodes).
	MDNSTXTNotRegex string `yaml:"mdns_txt_not_regex"`

	// UPnPDeviceRegex matches SSDP/UPnP deviceType, ST, manufacturer, model, or Server.
	UPnPDeviceRegex string `yaml:"upnp_device_regex"`

	// UPnPServiceRegex matches advertised UPnP XML serviceType URNs.
	UPnPServiceRegex string `yaml:"upnp_service_regex"`

	// WSTypeRegex matches WS-Discovery Types or Scopes (e.g., "NetworkVideoTransmitter").
	WSTypeRegex string `yaml:"ws_type_regex"`

	// ServiceProtoAny matches Nerva-detected protocol names (e.g., "smb", "mongodb").
	ServiceProtoAny []string `yaml:"service_proto_any"`

	// DiscoveryOnly prevents this check's ports from being added to the global
	// TCP baseline sweep; the check runs only when its port is already open via
	// DefaultPorts, UniFi hints, or per-host LAN discovery.
	DiscoveryOnly bool `yaml:"discovery_only"`
}

// ProbeSpec defines the target-only verification probe executed when a host
// satisfies a check's Preconditions.
type ProbeSpec struct {
	// Type selects the probe protocol: "observe", "tcp", "telnet", "http",
	// "mqtt", "modbus", "rtsp", "vnc", "avr", "comfoconnect", "eth-rpc", "adb",
	// "rdp-nla", "ftp-anon", "esfile", "redis", "snmp", "tls-legacy",
	// "memcached", "rsync", "mpd", "kasa", "coap", "natpmp", or "ipp".
	Type string `yaml:"type"`

	// Port optionally pins the target port. When 0, the runner tests whichever
	// ports from Preconditions were observed open on the host.
	Port int `yaml:"port"`

	// Scheme optionally forces "http" or "https" for HTTP probes; inferred from
	// the port when left empty.
	Scheme string `yaml:"scheme"`

	// HTTPStepSpec holds single-request HTTP fields as well as match rules for
	// non-HTTP probes. It cannot be combined with Steps.
	HTTPStepSpec `yaml:",inline"`

	// Steps defines an ordered sequence of read-only HTTP requests that must
	// all succeed against the same target endpoint within Probe.Timeout.
	Steps []HTTPStepSpec `yaml:"steps,omitempty"`

	// Community sets the single read-only SNMP community string for "snmp" probes.
	Community string `yaml:"community"`

	// Timeout bounds how long the probe waits for a response from the target.
	Timeout time.Duration `yaml:"timeout"`
}

// HTTPStepSpec describes a read-only HTTP request and the evidence it must return.
type HTTPStepSpec struct {
	// Method sets the HTTP verb for HTTP probes. Only GET, HEAD, and OPTIONS are
	// permitted so community checks remain strictly read-only.
	Method string `yaml:"method"`

	// Path is the relative request path for HTTP probes (must begin with "/").
	Path string `yaml:"path"`

	// Paths optionally supplies an ordered list of relative HTTP paths to try
	// sequentially, stopping on the first conclusive match or 401/403 challenge.
	Paths []string `yaml:"paths"`

	// RequestHeaders optionally sets strictly allowlisted read-only HTTP request
	// headers (e.g., Accept). Host, Authorization, Cookie, and forwarding headers
	// are rejected by Validate().
	RequestHeaders map[string]string `yaml:"request_headers"`

	// Match configures response matching rules for HTTP and TCP banner probes.
	Match MatchSpec `yaml:"match"`
}

// JSONPredicate tests a bounded JSONPath field (e.g., "$.auth_en") in a JSON body.
type JSONPredicate struct {
	// Path is a bounded dot/index JSONPath expression starting with "$.".
	Path string `yaml:"path"`

	// Exists asserts whether Path is present (true) or absent (false).
	Exists *bool `yaml:"exists,omitempty"`

	// Equals requires the scalar string representation at Path to equal this value.
	Equals string `yaml:"equals,omitempty"`

	// NotEquals requires the scalar string representation at Path not to equal this value.
	NotEquals string `yaml:"not_equals,omitempty"`

	// Regex matches the scalar string value at Path against a Go RE2 pattern.
	Regex string `yaml:"regex,omitempty"`

	compiled *regexp.Regexp
}

// MatchSpec defines deterministic conditions that confirm a finding.
type MatchSpec struct {
	// Status requires the HTTP response status to match one of these codes.
	Status []int `yaml:"status"`

	// BodyContainsAll requires every substring to appear in the response body.
	BodyContainsAll []string `yaml:"body_contains_all"`

	// BodyContainsAny requires at least one substring to appear in the body.
	BodyContainsAny []string `yaml:"body_contains_any"`

	// BodyNotContains rejects the match if any of these substrings appear in the body.
	BodyNotContains []string `yaml:"body_not_contains"`

	// BodyRegex matches a regular expression against the response body.
	BodyRegex string `yaml:"body_regex"`

	// BodyNotRegex rejects the match if the regular expression matches the response body.
	BodyNotRegex string `yaml:"body_not_regex"`

	// JSONMatch evaluates typed JSONPath predicates against a JSON response body.
	JSONMatch []JSONPredicate `yaml:"json_match"`

	// HeadersAbsent requires none of these header names to be present.
	HeadersAbsent []string `yaml:"headers_absent"`

	// HeadersPresent requires all of these header names to be present.
	HeadersPresent []string `yaml:"headers_present"`

	// HeaderContains requires each named HTTP response header to contain the
	// given case-insensitive substring (e.g., Server: "Microsoft-HTTPAPI").
	HeaderContains map[string]string `yaml:"header_contains"`

	// BannerRegex matches against the initial bytes read from a TCP banner probe.
	BannerRegex string `yaml:"banner_regex"`

	// EvidenceSummary optionally overrides the generic probe evidence string
	// with an exact, factual description of what the check proved.
	EvidenceSummary string `yaml:"evidence_summary"`

	// RedactBody ensures raw response content is never copied into evidence strings.
	RedactBody bool `yaml:"redact_body"`

	// Compiled regular expressions cached during Validate so matching does not
	// recompile patterns per host.
	bodyPattern    *regexp.Regexp
	bodyNotPattern *regexp.Regexp
	bannerPattern  *regexp.Regexp
}

// Remediation captures plain-English guidance and suggested UniFi actions.
type Remediation struct {
	// Summary explains what is exposed and how to reduce risk.
	Summary string `yaml:"summary" json:"summary"`

	// UniFiActions lists structured UniFi remediation hints (e.g., move_to_iot_vlan).
	UniFiActions []string `yaml:"unifi_actions" json:"unifi_actions,omitempty"`
}

// compiledPatterns caches compiled regular expressions validated at load time.
type compiledPatterns struct {
	hostname    *regexp.Regexp
	httpTitle   *regexp.Regexp
	httpServer  *regexp.Regexp
	mdnsTXT     *regexp.Regexp
	mdnsTXTNot  *regexp.Regexp
	upnpDevice  *regexp.Regexp
	upnpService *regexp.Regexp
	wsType      *regexp.Regexp
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
// safety guardrails. Unknown YAML fields are rejected so typos in matchers or
// preconditions fail loudly during validation.
func Parse(raw []byte, source string) (*Check, error) {
	var chk Check
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&chk); err != nil {
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
	if c.Claim != "" {
		parsedClaim, err := ParseClaimKind(string(c.Claim))
		if err != nil {
			return err
		}
		c.Claim = parsedClaim
	} else {
		c.Claim = inferDefaultClaim(c)
	}
	hasSelector := len(c.Preconditions.PortsAny) > 0 ||
		len(c.Preconditions.PortsAll) > 0 ||
		len(c.Preconditions.MDNSTypeAny) > 0 ||
		c.Preconditions.UPnPDeviceRegex != "" ||
		c.Preconditions.UPnPServiceRegex != "" ||
		c.Preconditions.WSTypeRegex != "" ||
		len(c.Preconditions.ServiceProtoAny) > 0
	if !hasSelector {
		return errors.New("preconditions must specify at least one port, mDNS, UPnP, WS-Discovery, or service selector")
	}
	for _, p := range c.Preconditions.PortsAny {
		if p < 1 || p > 65535 {
			return fmt.Errorf("invalid precondition port %d", p)
		}
	}
	for _, p := range c.Preconditions.PortsAll {
		if p < 1 || p > 65535 {
			return fmt.Errorf("invalid precondition ports_all port %d", p)
		}
	}

	// Normalize and validate probe settings, enforcing strict read-only and
	// target-only guardrails so community checks cannot exfiltrate LAN data or
	// mutate device state.
	c.Probe.Type = strings.ToLower(strings.TrimSpace(c.Probe.Type))
	switch c.Probe.Type {
	case "observe", "tcp", "telnet", "mqtt", "modbus", "rtsp", "vnc", "avr",
		"comfoconnect", "eth-rpc", "adb", "rdp-nla", "ftp-anon", "esfile",
		"redis", "snmp", "tls-legacy", "memcached", "rsync", "mpd", "kasa",
		"coap", "natpmp", "ipp", "ipmi",
		"bitcoin-p2p", "bitcoin-rpc", "eth-engine", "nut", "lifx",
		"pjlink", "nbns", "pcp", "dns-recursion", "ntp", "stun":
		if c.Probe.Steps != nil {
			return errors.New("probe.steps requires probe.type http")
		}
	case "http":
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
	if c.Preconditions.MDNSTXTRegex != "" {
		if c.compiled.mdnsTXT, err = regexp.Compile(c.Preconditions.MDNSTXTRegex); err != nil {
			return fmt.Errorf("preconditions.mdns_txt_regex: %w", err)
		}
	}
	if c.Preconditions.MDNSTXTNotRegex != "" {
		if c.compiled.mdnsTXTNot, err = regexp.Compile(c.Preconditions.MDNSTXTNotRegex); err != nil {
			return fmt.Errorf("preconditions.mdns_txt_not_regex: %w", err)
		}
	}
	if c.Preconditions.UPnPDeviceRegex != "" {
		if c.compiled.upnpDevice, err = regexp.Compile(c.Preconditions.UPnPDeviceRegex); err != nil {
			return fmt.Errorf("preconditions.upnp_device_regex: %w", err)
		}
	}
	if c.Preconditions.UPnPServiceRegex != "" {
		if c.compiled.upnpService, err = regexp.Compile(c.Preconditions.UPnPServiceRegex); err != nil {
			return fmt.Errorf("preconditions.upnp_service_regex: %w", err)
		}
	}
	if c.Preconditions.WSTypeRegex != "" {
		if c.compiled.wsType, err = regexp.Compile(c.Preconditions.WSTypeRegex); err != nil {
			return fmt.Errorf("preconditions.ws_type_regex: %w", err)
		}
	}
	if c.Probe.Steps != nil {
		if !c.Probe.HTTPStepSpec.isZero() {
			return errors.New("probe.steps cannot be combined with top-level method, path, paths, request_headers, or match")
		}
		if len(c.Probe.Steps) == 0 || len(c.Probe.Steps) > maxProbeSteps {
			return fmt.Errorf("probe.steps requires between 1 and %d steps", maxProbeSteps)
		}
		for i := range c.Probe.Steps {
			if err := c.Probe.Steps[i].validateHTTP(); err != nil {
				return fmt.Errorf("probe.steps[%d]: %w", i, err)
			}
		}
		return nil
	}
	if c.Probe.Type == "http" {
		return c.Probe.HTTPStepSpec.validateHTTP()
	}
	return c.Probe.Match.compile()
}

// isZero reports whether all top-level HTTP step fields are unset.
func (s HTTPStepSpec) isZero() bool {
	return s.Method == "" &&
		s.Path == "" &&
		len(s.Paths) == 0 &&
		len(s.RequestHeaders) == 0 &&
		s.Match.isZero()
}

// isZero reports whether no match fields were configured on MatchSpec.
func (m MatchSpec) isZero() bool {
	return len(m.Status) == 0 &&
		len(m.BodyContainsAll) == 0 &&
		len(m.BodyContainsAny) == 0 &&
		len(m.BodyNotContains) == 0 &&
		m.BodyRegex == "" &&
		m.BodyNotRegex == "" &&
		len(m.JSONMatch) == 0 &&
		len(m.HeadersAbsent) == 0 &&
		len(m.HeadersPresent) == 0 &&
		len(m.HeaderContains) == 0 &&
		m.BannerRegex == "" &&
		m.EvidenceSummary == "" &&
		!m.RedactBody
}

// validateHTTP applies the same target and response constraints to both YAML forms.
func (s *HTTPStepSpec) validateHTTP() error {
	s.Method = strings.ToUpper(strings.TrimSpace(s.Method))
	switch s.Method {
	case "":
		s.Method = "GET"
	case "GET", "HEAD", "OPTIONS":
	default:
		return fmt.Errorf("http probe method %q is forbidden; only GET, HEAD, and OPTIONS are allowed", s.Method)
	}
	paths := s.httpPaths()
	if len(paths) == 0 {
		return errors.New("http probe requires path or paths")
	}
	for _, path := range paths {
		if !strings.HasPrefix(path, "/") || strings.Contains(path, "://") || strings.HasPrefix(path, "//") {
			return fmt.Errorf("http probe path %q must be a relative path starting with /", path)
		}
	}
	for name := range s.RequestHeaders {
		switch strings.ToLower(name) {
		case "accept", "accept-language", "cache-control":
		default:
			return fmt.Errorf("http probe request header %q is not in the read-only allowlist (Accept, Accept-Language, Cache-Control)", name)
		}
	}
	if !s.Match.hasHTTPMatcher() {
		return errors.New("http probe requires at least one positive response matcher")
	}
	return s.Match.compile()
}

// compile validates response predicates once at load time, including for TCP banners.
func (m *MatchSpec) compile() error {
	var err error
	if m.BodyRegex != "" {
		if m.bodyPattern, err = regexp.Compile(m.BodyRegex); err != nil {
			return fmt.Errorf("match.body_regex: %w", err)
		}
	}
	if m.BodyNotRegex != "" {
		if m.bodyNotPattern, err = regexp.Compile(m.BodyNotRegex); err != nil {
			return fmt.Errorf("match.body_not_regex: %w", err)
		}
	}
	if m.BannerRegex != "" {
		if m.bannerPattern, err = regexp.Compile(m.BannerRegex); err != nil {
			return fmt.Errorf("match.banner_regex: %w", err)
		}
	}
	for i := range m.JSONMatch {
		p := &m.JSONMatch[i]
		if !jsonPathPattern.MatchString(p.Path) {
			return fmt.Errorf("match.json_match[%d]: unsupported JSON path %q", i, p.Path)
		}
		if p.Exists == nil && p.Equals == "" && p.NotEquals == "" && p.Regex == "" {
			return fmt.Errorf("match.json_match[%d]: predicate requires exists, equals, not_equals, or regex", i)
		}
		if p.Regex != "" {
			if p.compiled, err = regexp.Compile(p.Regex); err != nil {
				return fmt.Errorf("match.json_match[%d].regex: %w", i, err)
			}
		}
	}
	return nil
}

// hasHTTPMatcher reports whether MatchSpec defines at least one positive HTTP
// response matching condition. Negative-only matchers (headers_absent,
// body_not_contains, body_not_regex) do not qualify on their own because they
// would match arbitrary 404 or 500 error responses.
func (m *MatchSpec) hasHTTPMatcher() bool {
	for _, p := range m.JSONMatch {
		// A missing JSON field or bare root "$" check alone matches unrelated JSON error pages.
		if (p.Exists != nil && *p.Exists && p.Path != "$") || p.Equals != "" || p.NotEquals != "" || p.Regex != "" {
			return true
		}
	}
	return len(m.Status) > 0 ||
		len(m.BodyContainsAll) > 0 ||
		len(m.BodyContainsAny) > 0 ||
		strings.TrimSpace(m.BodyRegex) != "" ||
		len(m.HeadersPresent) > 0 ||
		len(m.HeaderContains) > 0
}

// httpPaths returns the ordered deduplicated list of non-empty relative paths
// configured on an HTTP step, trying Path before any entries in Paths.
func (s *HTTPStepSpec) httpPaths() []string {
	var out []string
	if s.Path != "" {
		out = append(out, s.Path)
	}
	for _, p := range s.Paths {
		if p != "" && p != s.Path {
			out = append(out, p)
		}
	}
	return out
}

// DefaultTransport returns the L4 transport ("tcp" or "udp") exercised by this check.
func (c *Check) DefaultTransport() string {
	switch strings.ToLower(strings.TrimSpace(c.Probe.Type)) {
	case "snmp", "coap", "natpmp", "ipmi", "lifx", "nbns", "pcp", "dns-recursion", "ntp", "stun":
		return "udp"
	case "observe":
		for _, t := range c.Preconditions.MDNSTypeAny {
			if strings.Contains(strings.ToLower(t), "._udp") || strings.EqualFold(t, "_matter._tcp") {
				return "udp"
			}
		}
		if len(c.Preconditions.PortsAny) == 0 && len(c.Preconditions.PortsAll) == 0 &&
			(c.Preconditions.WSTypeRegex != "" || c.Preconditions.UPnPDeviceRegex != "" || c.Preconditions.UPnPServiceRegex != "") {
			return "udp"
		}
		return "tcp"
	default:
		return "tcp"
	}
}

func inferDefaultClaim(c *Check) ClaimKind {
	cat := strings.ToLower(strings.TrimSpace(c.Category))
	pt := strings.ToLower(strings.TrimSpace(c.Probe.Type))
	switch {
	case pt == "observe":
		// Passive observation checks never execute an active auth/permission
		// transaction, so they establish advertisement or service visibility
		// rather than confirmed control permission.
		if len(c.Preconditions.MDNSTypeAny) > 0 || c.Preconditions.UPnPDeviceRegex != "" || c.Preconditions.UPnPServiceRegex != "" || c.Preconditions.WSTypeRegex != "" {
			return ClaimServiceAdvertised
		}
		if cat == "device-inventory" {
			return ClaimAssetIdentity
		}
		return ClaimServiceObserved
	case cat == "service-inventory" || cat == "device-inventory":
		return ClaimServiceObserved
	case cat == "firewall-policy" || cat == "isolation-policy":
		return ClaimConfiguredAccess
	case pt == "tls-legacy" || pt == "telnet" || pt == "tcp" || pt == "bitcoin-p2p" || pt == "nbns" || pt == "ntp" || pt == "stun" || pt == "lifx" || cat == "oob-bmc":
		return ClaimServiceObserved
	default:
		return ClaimConfirmedPermission
	}
}
