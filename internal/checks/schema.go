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
	"slices"
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

// GrantEffect identifies a capability available through a matched service.
type GrantEffect string

const (
	// GrantRead permits reading service data.
	GrantRead GrantEffect = "read"
	// GrantSecrets permits obtaining credentials or other secret material.
	GrantSecrets GrantEffect = "secrets"
	// GrantControl permits issuing operational commands.
	GrantControl GrantEffect = "control"
	// GrantConfigure permits changing settings or policy.
	GrantConfigure GrantEffect = "configure"
	// GrantPivot permits acting on other systems through this service.
	GrantPivot GrantEffect = "pivot"
	// GrantDisrupt permits interrupting service or device operation.
	GrantDisrupt GrantEffect = "disrupt"
)

// Valid reports whether the capability belongs to the shared check and protocol vocabulary.
func (e GrantEffect) Valid() bool {
	switch e {
	case GrantRead, GrantSecrets, GrantControl, GrantConfigure, GrantPivot, GrantDisrupt:
		return true
	}
	return false
}

// GrantBasis records how directly a probe establishes a capability.
type GrantBasis string

const (
	// BasisProven means the response directly demonstrates the permission.
	BasisProven GrantBasis = "proven"
	// BasisImplied means the observed behavior supports an inference.
	BasisImplied GrantBasis = "implied"
	// BasisConditional depends on an explicit, unverified prerequisite.
	BasisConditional GrantBasis = "conditional"
	// BasisAssumed records a capability based only on an assumption.
	BasisAssumed GrantBasis = "assumed"
)

// strength orders the four bases for comparison with a probe's evidence ceiling.
func (b GrantBasis) strength() int {
	return slices.Index([]GrantBasis{BasisAssumed, BasisConditional, BasisImplied, BasisProven}, b)
}

// GrantSpec declares one capability yielded when a check matches.
type GrantSpec struct {
	// Effect identifies the available operation.
	Effect GrantEffect `yaml:"effect"`
	// Basis qualifies the evidence supporting Effect.
	Basis GrantBasis `yaml:"basis"`
	// WhenField optionally requires a field's presence or its equality to a literal.
	WhenField string `yaml:"when_field,omitempty"`
	// Requires names a prerequisite the probe left unverified.
	Requires string `yaml:"requires,omitempty"`
	// SameNetwork limits a grant to peers on the listener's own network.
	SameNetwork bool `yaml:"same_network,omitempty"`
	// Note describes the scope of the capability.
	Note string `yaml:"note,omitempty"`
}

// ObservationLevel describes the evidence collected by a successful probe.
type ObservationLevel string

const (
	// ObsIdentity identifies an asset from its fingerprint.
	ObsIdentity ObservationLevel = "identity"
	// ObsService establishes service visibility or a protocol response.
	ObsService ObservationLevel = "service"
	// ObsAuthVerified establishes that the service accepted an anonymous session or command.
	ObsAuthVerified ObservationLevel = "auth-verified"
	// ObsPrivilegeVerified establishes a specific operation, such as a successful data read.
	ObsPrivilegeVerified ObservationLevel = "privilege-verified"
)

// Observation carries transient facts from one successful check on one endpoint.
type Observation struct {
	// Level describes the most specific evidence from the match.
	Level ObservationLevel
	// Fields contains matched protocol values and HTTP JSON paths. A bare predicate tests presence.
	Fields map[string]string
}

// ProbeCapability bounds the evidence available to a declarative check.
type ProbeCapability struct {
	// MaxLevel is the strongest observation the probe can make.
	MaxLevel ObservationLevel
	// EmittedFields names protocol fields available to grant predicates.
	EmittedFields []string
	// MaxBasis is the strongest basis a check can declare with this probe.
	MaxBasis GrantBasis
}

// probeCapabilities is also the allowlist of supported probe types. HTTP adds
// only the paths explicitly checked in the successful response to a step.
var probeCapabilities = map[string]ProbeCapability{
	"adb":           {ObsAuthVerified, []string{"command"}, BasisImplied},
	"avr":           {ObsPrivilegeVerified, []string{"power_reply"}, BasisProven},
	"bitcoin-p2p":   {ObsService, []string{"network", "version"}, BasisImplied},
	"bitcoin-rpc":   {ObsPrivilegeVerified, []string{"subversion"}, BasisProven},
	"coap":          {ObsPrivilegeVerified, []string{"response_code"}, BasisProven},
	"comfoconnect":  {ObsService, []string{"discovery_reply"}, BasisImplied},
	"dns-recursion": {ObsPrivilegeVerified, []string{"answers"}, BasisProven},
	"esfile":        {ObsPrivilegeVerified, []string{"model", "sdk"}, BasisProven},
	"eth-engine":    {ObsPrivilegeVerified, []string{"capability_count"}, BasisProven},
	"eth-rpc":       {ObsPrivilegeVerified, []string{"client_version"}, BasisProven},
	"ftp-anon":      {ObsAuthVerified, []string{"login_code"}, BasisImplied},
	"http":          {ObsPrivilegeVerified, []string{"status"}, BasisProven},
	"ipmi":          {ObsService, []string{"anonymous_login", "null_user", "cipher_zero"}, BasisImplied},
	"ipp":           {ObsPrivilegeVerified, []string{"status"}, BasisProven},
	"kasa":          {ObsPrivilegeVerified, []string{"model"}, BasisProven},
	"lifx":          {ObsService, []string{"vendor_id", "product_id"}, BasisImplied},
	"memcached":     {ObsPrivilegeVerified, []string{"version"}, BasisProven},
	"modbus":        {ObsService, []string{"function_code"}, BasisImplied},
	"mpd":           {ObsPrivilegeVerified, []string{"version"}, BasisProven},
	"mqtt":          {ObsAuthVerified, []string{"connack"}, BasisImplied},
	"natpmp":        {ObsPrivilegeVerified, []string{"result_code"}, BasisProven},
	"nbns":          {ObsService, []string{"name_count"}, BasisImplied},
	"ntp":           {ObsService, []string{"stratum"}, BasisImplied},
	"nut":           {ObsService, []string{"listed_ups"}, BasisImplied},
	"observe":       {ObsService, nil, BasisImplied},
	"pcp":           {ObsService, []string{"epoch"}, BasisImplied},
	"pjlink":        {ObsService, []string{"auth_required"}, BasisImplied},
	"rdp-nla":       {ObsService, []string{"selected_protocol"}, BasisImplied},
	"redis":         {ObsAuthVerified, []string{"reply"}, BasisImplied},
	"rsync":         {ObsService, []string{"version"}, BasisImplied},
	"rtsp":          {ObsPrivilegeVerified, []string{"describe_status"}, BasisProven},
	"snmp":          {ObsPrivilegeVerified, []string{"sys_descr"}, BasisProven},
	"stun":          {ObsService, []string{"binding_success"}, BasisImplied},
	"tcp":           {ObsService, []string{"banner_matched"}, BasisImplied},
	"telnet":        {ObsService, []string{"prompt"}, BasisImplied},
	"tls-legacy":    {ObsService, []string{"tls_version"}, BasisImplied},
	"vnc":           {ObsAuthVerified, []string{"security_type", "session_accepted"}, BasisImplied},
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

	// Grants lists the capabilities supported by a successful match.
	Grants []GrantSpec `yaml:"grants,omitempty"`

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
	// Type selects a protocol from the probe capability contract.
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

// Merge combines check groups in ID order, rejecting duplicate IDs,
// self-references or cycles in supersedes chains, and superseding checks that
// would drop or narrow a capability declared by the superseded check.
func Merge(groups ...[]*Check) ([]*Check, error) {
	seen := make(map[string]*Check)
	var merged []*Check
	for _, g := range groups {
		for _, chk := range g {
			if prev, exists := seen[chk.ID]; exists {
				return nil, fmt.Errorf("duplicate check id %q in %q and %q", chk.ID, prev.Source, chk.Source)
			}
			seen[chk.ID] = chk
			merged = append(merged, chk)
		}
	}
	sort.Slice(merged, func(i, j int) bool {
		return merged[i].ID < merged[j].ID
	})
	// Reject self-supersession and cycles so RunHost suppression can never erase
	// every finding in a mutual-supersedes loop.
	state := make(map[string]uint8, len(merged)) // 1=visiting, 2=done
	var checkCycle func(id string) error
	checkCycle = func(id string) error {
		state[id] = 1
		for _, next := range seen[id].Supersedes {
			if next == id {
				return fmt.Errorf("check %s cannot supersede itself", id)
			}
			if seen[next] == nil {
				continue
			}
			if state[next] == 1 {
				return fmt.Errorf("supersedes cycle involving %s and %s", id, next)
			}
			if state[next] == 0 {
				if err := checkCycle(next); err != nil {
					return err
				}
			}
		}
		state[id] = 2
		return nil
	}
	for _, chk := range merged {
		if state[chk.ID] == 0 {
			if err := checkCycle(chk.ID); err != nil {
				return nil, err
			}
		}
		for _, id := range chk.Supersedes {
			prior := seen[id]
			if prior == nil {
				continue
			}
			for _, grant := range prior.Grants {
				covered := slices.ContainsFunc(chk.Grants, func(g GrantSpec) bool {
					return g.Effect == grant.Effect && g.WhenField == "" && (g.Basis != BasisProven || grant.Basis == BasisProven)
				})
				if !covered {
					return nil, fmt.Errorf("check %s supersedes %s but omits unconditional grant effect %q", chk.ID, id, grant.Effect)
				}
			}
		}
	}
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
	if _, ok := probeCapabilities[c.Probe.Type]; !ok {
		return fmt.Errorf("unsupported probe.type %q", c.Probe.Type)
	}
	if c.Probe.Type == "http" {
		if c.Probe.Scheme != "" && c.Probe.Scheme != "http" && c.Probe.Scheme != "https" {
			return fmt.Errorf("http probe scheme %q must be http or https", c.Probe.Scheme)
		}
	} else if c.Probe.Steps != nil {
		return errors.New("probe.steps requires probe.type http")
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
	} else if c.Probe.Type == "http" {
		if err := c.Probe.HTTPStepSpec.validateHTTP(); err != nil {
			return err
		}
	} else if err := c.Probe.Match.compile(); err != nil {
		return err
	}
	return c.validateGrants()
}

// IsInventoryOnly reports whether the check is a pure informational inventory
// observation (matching Finding.IsInventoryOnly) rather than a risk finding.
func (c *Check) IsInventoryOnly() bool {
	return c.Severity == SeverityInfo && (c.Claim == ClaimAssetIdentity || c.Claim == ClaimServiceAdvertised || c.Claim == ClaimServiceObserved)
}

// grantPredicate accepts field presence or equality with one literal token.
// The length limit bounds both parsing work and the size of a literal in YAML.
var grantPredicate = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*|\$(?:\[[0-9]+\])?(?:\.[A-Za-z0-9_-]+(?:\[[0-9]+\])?)*)(?:[ \t]*==[ \t]*([A-Za-z0-9_.*:/+-]+))?$`)

// parseGrantPredicate is shared by validation and evaluation so both interpret literals identically.
func parseGrantPredicate(expr string) (field, value string, ok bool) {
	if len(expr) > 256 {
		return "", "", false
	}
	m := grantPredicate.FindStringSubmatch(strings.TrimSpace(expr))
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

// emitsField reports whether the probe can populate field during execution,
// allowing JSONPath selectors only when a matching HTTP step verifies presence.
func (p *ProbeSpec) emitsField(field string) bool {
	if slices.Contains(probeCapabilities[p.Type].EmittedFields, field) {
		return true
	}
	if p.Type != "http" {
		return false
	}
	for _, step := range p.httpSteps() {
		if step.Match.observesPath(field) {
			return true
		}
	}
	return false
}

// observesPath excludes absence predicates, which cannot supply a value for a grant.
func (m *MatchSpec) observesPath(field string) bool {
	return slices.ContainsFunc(m.JSONMatch, func(p JSONPredicate) bool {
		return p.Path == field && (p.Exists == nil || *p.Exists)
	})
}

// httpSteps presents the single-request and sequential forms in wire order.
func (p *ProbeSpec) httpSteps() []HTTPStepSpec {
	if p.Steps != nil {
		return p.Steps
	}
	return []HTTPStepSpec{p.HTTPStepSpec}
}

// verifiesRead identifies GET payload checks that can demonstrate a successful
// read. The runner uses the actual status when the YAML leaves it open.
func (s HTTPStepSpec) verifiesRead() bool {
	if s.Method != "GET" || (len(s.Match.Status) > 0 && !slices.ContainsFunc(s.Match.Status, func(code int) bool { return code >= 200 && code < 300 })) {
		return false
	}
	return len(s.Match.BodyContainsAll) > 0 || len(s.Match.BodyContainsAny) > 0 || s.Match.BodyRegex != "" ||
		slices.ContainsFunc(s.Match.JSONMatch, func(p JSONPredicate) bool { return p.Exists == nil || *p.Exists })
}

// validateGrants bounds declarations by the operations the runner actually performs.
func (c *Check) validateGrants() error {
	if len(c.Grants) == 0 && !c.IsInventoryOnly() {
		return errors.New("grants required for a non-inventory check")
	}
	capability := probeCapabilities[c.Probe.Type]
	for i, g := range c.Grants {
		strength := g.Basis.strength()
		switch {
		case !g.Effect.Valid():
			return fmt.Errorf("grants[%d]: unknown effect %q", i, g.Effect)
		case strength < 0:
			return fmt.Errorf("grants[%d]: unknown basis %q", i, g.Basis)
		case g.Basis == BasisConditional && strings.TrimSpace(g.Requires) == "":
			return fmt.Errorf("grants[%d]: conditional basis requires a prerequisite in requires", i)
		case strength > capability.MaxBasis.strength():
			return fmt.Errorf("grants[%d]: %s probe supports at most %s basis", i, c.Probe.Type, capability.MaxBasis)
		}
		var field, value string
		if g.WhenField != "" {
			var ok bool
			field, value, ok = parseGrantPredicate(g.WhenField)
			if !ok || !c.Probe.emitsField(field) {
				return fmt.Errorf("grants[%d]: invalid or unemitted when_field %q for %s probe", i, g.WhenField, c.Probe.Type)
			}
		}
		if g.Basis == BasisProven && !c.canProve(g.Effect, field, value) {
			return fmt.Errorf("grants[%d]: %s probe with claim %s cannot prove %s from this response", i, c.Probe.Type, c.Claim, g.Effect)
		}
	}
	return nil
}

// canProve reports whether the check's probe and claim establish a proven grant
// rather than a service banner or error page.
func (c *Check) canProve(effect GrantEffect, field, value string) bool {
	if c.Claim != ClaimConfirmedPermission {
		return false
	}
	if c.Probe.Type != "http" {
		// SNMP can match a response carrying a varbind exception in place of sysDescr.
		return effect == GrantRead && (c.Probe.Type != "snmp" || field == "sys_descr")
	}
	steps := c.Probe.httpSteps()
	if effect == GrantRead {
		return slices.ContainsFunc(steps, HTTPStepSpec.verifiesRead)
	}
	if effect != GrantSecrets && value == "" {
		return false
	}
	// The last step that supplies a field owns its value. In a sequence its
	// successful status must be explicit, since another step can prove a read.
	for i := len(steps) - 1; i >= 0; i-- {
		step := &steps[i]
		if step.Match.observesPath(field) {
			statuses := step.Match.Status
			if len(steps) > 1 && (len(statuses) == 0 || slices.ContainsFunc(statuses, func(code int) bool { return code < 200 || code >= 300 })) {
				return false
			}
			return step.verifiesRead()
		}
	}
	return false
}

// EffectiveGrants returns the grants supported by a matched check and its
// transient fields. Conditional grants retain their external prerequisites.
func EffectiveGrants(chk *Check, obs Observation) []GrantSpec {
	var grants []GrantSpec
	for _, g := range chk.Grants {
		// A matched error response can identify the service without establishing
		// the read permission available on a successful response.
		if g.Basis == BasisProven && obs.Level != "" && obs.Level != ObsPrivilegeVerified {
			continue
		}
		if g.WhenField != "" {
			field, want, valid := parseGrantPredicate(g.WhenField)
			got, present := obs.Fields[field]
			if !valid || !present || (want != "" && got != want) {
				continue
			}
		}
		grants = append(grants, g)
	}
	return grants
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
