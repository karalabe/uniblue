package risk

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/unifi"
	"gopkg.in/yaml.v3"
)

// ExposureRule classifies a WAN port-forwarding rule deterministically into a
// known traffic class (such as expected P2P, public web proxy, or dangerous
// admin/RPC exposure) so operators only get escalated alerts for genuinely
// risky forwards.
type ExposureRule struct {
	// ID uniquely identifies the exposure rule.
	ID string `yaml:"id"`

	// Name is a concise label for the matched traffic class.
	Name string `yaml:"name"`

	// Class groups forwards by operational intent ("expected-p2p",
	// "vpn-entrypoint", "web-entrypoint", "remote-admin", "dangerous-rpc",
	// "dangerous-remote").
	Class string `yaml:"class"`

	// Severity is the baseline severity for this exposure class.
	Severity checks.Severity `yaml:"severity"`

	// Proto optionally restricts matching to a specific protocol ("tcp", "udp").
	Proto string `yaml:"proto"`

	// Ports lists destination or internal ports matched by this rule.
	Ports []int `yaml:"ports"`

	// NameRegex optionally matches the user's UniFi port-forward rule name.
	NameRegex string `yaml:"name_regex"`

	// Summary explains why this exposure class is benign, review-worthy, or dangerous.
	Summary string `yaml:"summary"`

	// Actions suggests concrete remediation or verification steps.
	Actions []string `yaml:"actions"`

	nameRe *regexp.Regexp
}

// ExposureAssessment records the deterministic classification of a single
// enabled UniFi WAN port-forwarding rule.
type ExposureAssessment struct {
	// Forward is the underlying UniFi port-forward rule.
	Forward unifi.PortForward `json:"forward"`

	// Client is the resolved internal host receiving the forwarded traffic.
	Client unifi.Client `json:"client"`

	// Class is the matched category (e.g., "expected-p2p", "web-entrypoint", "dangerous-rpc").
	Class string `json:"class"`

	// RuleName is the human-readable classification label.
	RuleName string `json:"rule_name"`

	// Severity is the effective severity after optional source/VLAN checks.
	Severity checks.Severity `json:"severity"`

	// Summary explains the risk posture of this forward.
	Summary string `json:"summary"`

	// Actions lists recommended follow-up actions.
	Actions []string `json:"actions,omitempty"`
}

// PostureNote captures a deterministic network-wide architectural observation
// (for example, an unused isolated IoT VLAN while vulnerable IoT devices sit
// on a trusted VLAN).
type PostureNote struct {
	// Severity ranks the importance of the architectural observation.
	Severity checks.Severity `json:"severity"`

	// Title summarizes the posture observation.
	Title string `json:"title"`

	// Detail explains the specific UniFi objects involved and how to improve them.
	Detail string `json:"detail"`
}

// ExposureClassifier evaluates UniFi port forwards against a declarative set of
// YAML ExposureRules.
type ExposureClassifier struct {
	rules []*ExposureRule
}

// LoadExposureClassifier reads and compiles all YAML exposure rules from fsys.
func LoadExposureClassifier(fsys fs.FS) (*ExposureClassifier, error) {
	var paths []string
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk exposure rules: %w", err)
	}
	sort.Strings(paths)

	var rules []*ExposureRule
	for _, p := range paths {
		raw, err := fs.ReadFile(fsys, p)
		if err != nil {
			return nil, fmt.Errorf("read exposure rule %q: %w", p, err)
		}
		var batch []*ExposureRule
		if err := yaml.Unmarshal(raw, &batch); err != nil {
			return nil, fmt.Errorf("parse exposure rule %q: %w", p, err)
		}
		for _, r := range batch {
			if r.NameRegex != "" {
				re, err := regexp.Compile(r.NameRegex)
				if err != nil {
					return nil, fmt.Errorf("compile exposure rule %q regex: %w", r.ID, err)
				}
				r.nameRe = re
			}
			rules = append(rules, r)
		}
	}
	return &ExposureClassifier{rules: rules}, nil
}

// Classify matches an enabled UniFi PortForward against the ordered rule list,
// falling back to an unclassified MEDIUM assessment when no rule matches.
func (c *ExposureClassifier) Classify(pf unifi.PortForward, cl unifi.Client) ExposureAssessment {
	if c != nil {
		for _, r := range c.rules {
			if r.matches(pf) {
				return ExposureAssessment{
					Forward:  pf,
					Client:   cl,
					Class:    r.Class,
					RuleName: r.Name,
					Severity: r.Severity,
					Summary:  strings.TrimSpace(r.Summary),
					Actions:  r.Actions,
				}
			}
		}
	}

	return ExposureAssessment{
		Forward:  pf,
		Client:   cl,
		Class:    "unclassified-wan",
		RuleName: "Unclassified WAN Port Forward",
		Severity: checks.SeverityMedium,
		Summary:  "Verify this service truly needs public internet exposure. Prefer WireGuard VPN access or restrict allowed source IPs.",
		Actions:  []string{"review_port_forward", "restrict_wan_source_ip"},
	}
}

// matches evaluates whether a PortForward satisfies an ExposureRule's protocol,
// port list, or optional rule-name regex.
func (r *ExposureRule) matches(pf unifi.PortForward) bool {
	if r.Proto != "" && !strings.Contains(strings.ToLower(pf.Proto), strings.ToLower(r.Proto)) {
		return false
	}

	portHit := false
	for _, p := range r.Ports {
		if pf.ExposesPort(p) || portSpecMatches(pf.DstPort, p) {
			portHit = true
			break
		}
	}

	// For expected-p2p rules that define both ports and a name_regex, require
	// either the port match OR name match only when ports are empty; when both
	// are present on high-risk admin rules, either match catches it; on benign
	// expected-p2p rules, require portHit (and if nameRe is set, confirm intent
	// if ambiguous, or accept well-known port directly).
	if r.Class == "expected-p2p" || r.Class == "vpn-entrypoint" {
		return portHit
	}
	if portHit {
		return true
	}
	if r.nameRe != nil && r.nameRe.MatchString(pf.Name) {
		return true
	}
	return false
}

// portSpecMatches parses a UniFi port specification ("80", "8000-8010", "80,443")
// and checks whether port falls inside it.
func portSpecMatches(spec string, port int) bool {
	for _, token := range strings.Split(spec, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if startStr, endStr, ok := strings.Cut(token, "-"); ok {
			start, err1 := strconv.Atoi(strings.TrimSpace(startStr))
			end, err2 := strconv.Atoi(strings.TrimSpace(endStr))
			if err1 == nil && err2 == nil && port >= start && port <= end {
				return true
			}
			continue
		}
		if single, err := strconv.Atoi(token); err == nil && single == port {
			return true
		}
	}
	return false
}

// AnalyzePosture inspects UniFi VLAN utilization and active findings to emit
// deterministic architectural guidance (such as pointing out an unused IoT
// VLAN when vulnerable appliances sit on a trusted VLAN).
func AnalyzePosture(snap *unifi.Snapshot, findings []checks.Finding, netCfg config.NetworkConfig) []PostureNote {
	if snap == nil {
		return nil
	}
	trustedSet := toLowerSet(netCfg.TrustedVLANs)
	isolatedSet := toLowerSet(netCfg.IsolatedVLANs)

	// Count active clients per network name.
	clientsPerNet := make(map[string]int, len(snap.Networks))
	for _, cl := range snap.Clients {
		if cl.NetworkName != "" {
			clientsPerNet[strings.ToLower(cl.NetworkName)]++
		}
	}

	// Identify isolated/IoT/smart VLANs configured on the gateway that currently
	// hold zero active clients.
	var emptyIoTVLANs []unifi.Network
	for _, n := range snap.Networks {
		lower := strings.ToLower(n.Name)
		_, explicitIsolated := isolatedSet[lower]
		if !explicitIsolated && n.VLAN != "" {
			_, explicitIsolated = isolatedSet[strings.ToLower(n.VLAN)]
		}
		looksLikeIoT := explicitIsolated || strings.Contains(lower, "iot") || strings.Contains(lower, "smart") || strings.Contains(lower, "not")
		if looksLikeIoT && clientsPerNet[lower] == 0 {
			emptyIoTVLANs = append(emptyIoTVLANs, n)
		}
	}

	// Count findings belonging to appliances sitting on trusted VLANs.
	trustedHosts := make(map[string]struct{})
	for _, f := range findings {
		if f.Port > 0 && matchesVLAN(f.Client, trustedSet) {
			trustedHosts[f.Client.DisplayName()] = struct{}{}
		}
	}

	var notes []PostureNote
	if len(emptyIoTVLANs) > 0 && len(trustedHosts) > 0 {
		vlan := emptyIoTVLANs[0]
		names := make([]string, 0, len(trustedHosts))
		for h := range trustedHosts {
			names = append(names, h)
		}
		sort.Strings(names)
		notes = append(notes, PostureNote{
			Severity: checks.SeverityMedium,
			Title:    fmt.Sprintf("Unused IoT VLAN %q (VLAN %s) while exposed devices sit on Trusted LAN", vlan.Name, vlan.VLAN),
			Detail:   fmt.Sprintf("VLAN %q currently has 0 active clients, while %d host(s) with confirmed LAN exposures (%s) share your trusted network. Moving IoT/AV/HVAC appliances onto %q immediately lowers blast radius.", vlan.Name, len(names), strings.Join(names, ", "), vlan.Name),
		})
	}

	// Flag unnamed MAC-only clients that receive active WAN port forwards.
	clientsByIP := make(map[string]unifi.Client, len(snap.Clients))
	for _, cl := range snap.Clients {
		if cl.IP != "" {
			clientsByIP[cl.IP] = cl
		}
	}
	seenUnnamed := make(map[string]struct{})
	for _, pf := range snap.PortForwards {
		if !pf.Enabled {
			continue
		}
		cl, ok := clientsByIP[pf.FwdIP]
		if !ok {
			continue
		}
		if strings.EqualFold(cl.DisplayName(), cl.MAC) {
			if _, dup := seenUnnamed[cl.IP]; dup {
				continue
			}
			seenUnnamed[cl.IP] = struct{}{}
			notes = append(notes, PostureNote{
				Severity: checks.SeverityInfo,
				Title:    fmt.Sprintf("Unnamed WAN-exposed host (%s / %s)", cl.IP, cl.MAC),
				Detail:   fmt.Sprintf("Port forward %q targets %s, which has no friendly alias in UniFi. Naming this host/container in UniFi makes alerts immediately recognizable.", pf.Name, cl.IP),
			})
		}
	}

	return notes
}
