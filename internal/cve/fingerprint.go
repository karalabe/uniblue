// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cve

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/unifi"
	"gopkg.in/yaml.v3"
)

// FingerprintRule maps passive host signals (HTTP headers, SSH banners,
// hostnames, MAC prefixes, or open ports) to canonical NVD vendor/product
// patterns so UniBlue can match devices to cached CVEs deterministically.
type FingerprintRule struct {
	// Name is a readable label displayed in `uniblue cve explore`.
	Name string `yaml:"name"`

	// HostnameRegex matches against the UniFi display name or DHCP hostname.
	HostnameRegex string `yaml:"hostname_regex"`

	// HTTPTitleRegex matches against any fingerprinted HTTP HTML <title>.
	HTTPTitleRegex string `yaml:"http_title_regex"`

	// HTTPServerRegex matches against any fingerprinted HTTP Server header.
	HTTPServerRegex string `yaml:"http_server_regex"`

	// SSHBannerRegex matches against the passive SSH greeting line on port 22.
	SSHBannerRegex string `yaml:"ssh_banner_regex"`

	// MACPrefix matches against colon-separated lowercase MAC prefixes.
	MACPrefix []string `yaml:"mac_prefix"`

	// PortsAny optionally restricts a rule to hosts where at least one listed
	// TCP port was observed open. PortsAny never attributes a vendor on its own
	// without an identity signal (banner, HTTP header/title, hostname, or MAC).
	PortsAny []int `yaml:"ports_any"`

	// Vendors lists one or more NVD CPE vendor shards to query for this product.
	Vendors []string `yaml:"vendors"`

	// Products lists exact CPE product tokens or "*" wildcard patterns (e.g.,
	// "nginx", "nginx_open_source", or "*laserjet*{model}*").
	Products []string `yaml:"products"`

	// VersionGroup optionally selects a regex capture group (1-based) containing
	// the extracted software version string.
	VersionGroup int `yaml:"version_group"`

	// ModelGroup optionally selects a regex capture group (1-based) substituted
	// for "{model}" inside Products patterns (useful for narrowing printer or
	// appliance families to a specific hardware model).
	ModelGroup int `yaml:"model_group"`

	hostnameRe   *regexp.Regexp
	httpTitleRe  *regexp.Regexp
	httpServerRe *regexp.Regexp
	sshBannerRe  *regexp.Regexp
}

// Fingerprinter converts a UniFi Snapshot + probed HostProfiles into canonical
// Products ready for deterministic CVE cache lookup.
type Fingerprinter struct {
	rules []*FingerprintRule
}

// LoadFingerprinter loads and compiles all YAML fingerprint rules from fsys.
func LoadFingerprinter(fsys fs.FS) (*Fingerprinter, error) {
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
		return nil, fmt.Errorf("walk fingerprints fs: %w", err)
	}
	sort.Strings(paths)

	var all []*FingerprintRule
	for _, p := range paths {
		raw, err := fs.ReadFile(fsys, p)
		if err != nil {
			return nil, fmt.Errorf("read fingerprint %q: %w", p, err)
		}
		var batch []*FingerprintRule
		if err := yaml.Unmarshal(raw, &batch); err != nil {
			return nil, fmt.Errorf("parse fingerprint %q: %w", p, err)
		}
		for _, r := range batch {
			if err := r.compile(); err != nil {
				return nil, fmt.Errorf("compile fingerprint %q (%s): %w", r.Name, p, err)
			}
			all = append(all, r)
		}
	}
	return &Fingerprinter{rules: all}, nil
}

// compile pre-compiles optional regular expressions on a FingerprintRule.
func (r *FingerprintRule) compile() error {
	var err error
	if r.HostnameRegex != "" {
		if r.hostnameRe, err = regexp.Compile(r.HostnameRegex); err != nil {
			return err
		}
	}
	if r.HTTPTitleRegex != "" {
		if r.httpTitleRe, err = regexp.Compile(r.HTTPTitleRegex); err != nil {
			return err
		}
	}
	if r.HTTPServerRegex != "" {
		if r.httpServerRe, err = regexp.Compile(r.HTTPServerRegex); err != nil {
			return err
		}
	}
	if r.SSHBannerRegex != "" {
		if r.sshBannerRe, err = regexp.Compile(r.SSHBannerRegex); err != nil {
			return err
		}
	}
	return nil
}

// Identify extracts canonical Products from both UniFi infrastructure devices
// (which already carry exact firmware versions) and fingerprinted LAN hosts.
func (f *Fingerprinter) Identify(snap *unifi.Snapshot, profiles []probe.HostProfile) []Product {
	wanExposedIPs := make(map[string]bool)
	if snap != nil {
		for _, pf := range snap.PortForwards {
			if pf.Enabled && pf.FwdIP != "" {
				wanExposedIPs[pf.FwdIP] = true
			}
		}
	}

	var products []Product
	seenPairs := make(map[string]struct{})
	seenFallback := make(map[string]struct{})
	add := func(p Product) {
		hostKey := strings.ToLower(strings.TrimSpace(p.HostIP))
		if hostKey == "" {
			hostKey = strings.ToLower(strings.TrimSpace(p.HostName))
		}
		verKey := strings.ToLower(strings.TrimSpace(p.Version))

		// Dedupe by host + canonical vendor/product + version rather than display
		// label so a built-in rule and a Nerva CPE never produce duplicate rollups.
		var keys []string
		for _, v := range p.Vendors {
			v = strings.ToLower(strings.TrimSpace(v))
			if v == "" {
				continue
			}
			for _, prod := range p.Products {
				prod = strings.ToLower(strings.TrimSpace(prod))
				if prod == "" {
					continue
				}
				keys = append(keys, fmt.Sprintf("%s|%s|%s|%s", hostKey, v, prod, verKey))
			}
		}
		if len(keys) == 0 {
			fb := fmt.Sprintf("%s|%s|%s", hostKey, strings.ToLower(strings.TrimSpace(p.Label)), verKey)
			if _, dup := seenFallback[fb]; dup {
				return
			}
			seenFallback[fb] = struct{}{}
			products = append(products, p)
			return
		}
		allSeen := true
		for _, k := range keys {
			if _, ok := seenPairs[k]; !ok {
				allSeen = false
				break
			}
		}
		if allSeen {
			return
		}
		for _, k := range keys {
			seenPairs[k] = struct{}{}
		}
		products = append(products, p)
	}

	// 1. Identify UniFi infrastructure gear directly from controller metadata.
	// Emit one Product per UniFi device carrying all applicable CPE tokens so
	// reports stay clean and deduplicated.
	if snap != nil {
		for _, dev := range snap.Devices {
			cpeProducts := mapUniFiDeviceProducts(dev)
			if len(cpeProducts) == 0 {
				continue
			}
			add(Product{
				Label:    fmt.Sprintf("UniFi %s (%s)", dev.Name, dev.Model),
				Vendors:  []string{"ui"},
				Products: cpeProducts,
				Version:  normalizeUniFiFirmwareVersion(dev.Version),
				Source:   "unifi-firmware",
				HostName: dev.Name,
				HostIP:   dev.IP,
				VLAN:     "UniFi Infrastructure",
			})
		}
	}

	// 2. Apply declarative fingerprint rules to every probed LAN host, plus
	// extract exact software versions directly from Nerva's Service discoveries
	// (e.g., "<product>:<version>-<finding>").
	for _, hp := range profiles {
		hostIP := hp.Client.PrimaryIP()
		wan := false
		for _, ip := range hp.Client.AllIPs() {
			if wanExposedIPs[ip] {
				wan = true
				break
			}
		}
		for _, rule := range f.rules {
			for _, hit := range rule.matchAll(hp) {
				label := rule.Name
				if hit.model != "" {
					label = fmt.Sprintf("%s %s", rule.Name, strings.ToUpper(hit.model))
				}
				add(Product{
					Label:      label,
					Vendors:    rule.Vendors,
					Products:   expandProductPatterns(rule.Products, hit.model),
					Version:    hit.version,
					Source:     hit.source,
					HostName:   hp.Client.DisplayName(),
					HostIP:     hostIP,
					VLAN:       hp.Client.NetworkName,
					WANExposed: wan,
				})
			}
		}

		// Extract exact-version products directly from any versioned CPE 2.3
		// identifiers reported by Nerva's protocol fingerprinters.
		for _, svc := range hp.Services {
			for _, rawCPE := range svc.CPEs {
				vendor, product, ver, ok := parseVersionedCPE23(rawCPE)
				if !ok {
					continue
				}
				add(Product{
					Label:      formatProductLabel(product),
					Vendors:    []string{vendor},
					Products:   []string{product},
					Version:    ver,
					Source:     "nerva-cpe",
					HostName:   hp.Client.DisplayName(),
					HostIP:     hostIP,
					VLAN:       hp.Client.NetworkName,
					WANExposed: wan,
				})
			}
		}
	}

	// Also match idle clients without an active IP (e.g., sleeping printers)
	// purely by hostname/MAC so they still appear in `uniblue cve explore`.
	if snap != nil {
		probedMACs := make(map[string]struct{}, len(profiles))
		for _, hp := range profiles {
			probedMACs[hp.Client.MAC] = struct{}{}
		}
		for _, cl := range snap.Clients {
			if _, ok := probedMACs[cl.MAC]; ok {
				continue
			}
			hp := probe.HostProfile{Client: cl}
			for _, rule := range f.rules {
				for _, hit := range rule.matchAll(hp) {
					label := rule.Name
					if hit.model != "" {
						label = fmt.Sprintf("%s %s", rule.Name, strings.ToUpper(hit.model))
					}
					add(Product{
						Label:    label,
						Vendors:  rule.Vendors,
						Products: expandProductPatterns(rule.Products, hit.model),
						Version:  hit.version,
						Source:   hit.source,
						HostName: cl.DisplayName(),
						HostIP:   cl.PrimaryIP(),
						VLAN:     cl.NetworkName,
					})
				}
			}
		}
	}

	// Drop any versionless Product on a host when the same (vendor, product) is
	// already represented by a concrete versioned Product on that host (for
	// example, a versionless HTTP-title rule alongside a versioned Nerva CPE).
	products = dropSupersededVersionlessProducts(products)

	sort.Slice(products, func(i, j int) bool {
		if products[i].HostIP != products[j].HostIP {
			return products[i].HostIP < products[j].HostIP
		}
		if products[i].Label != products[j].Label {
			return products[i].Label < products[j].Label
		}
		return products[i].Version < products[j].Version
	})
	return products
}

// productHostKey returns the canonical lowercase host identifier used to
// group and deduplicate products and CVE matches belonging to the same host.
func productHostKey(p Product) string {
	if ip := strings.ToLower(strings.TrimSpace(p.HostIP)); ip != "" {
		return ip
	}
	return strings.ToLower(strings.TrimSpace(p.HostName))
}

// dropSupersededVersionlessProducts removes versionless Products whose
// (host, vendor, product) is already covered by a versioned Product on the
// same host so one service never emits both Exact and Potential rollups.
func dropSupersededVersionlessProducts(products []Product) []Product {
	type vendorProductPair struct {
		vendor  string
		product string
	}
	versionedByHost := make(map[string][]vendorProductPair)
	for _, p := range products {
		if strings.TrimSpace(p.Version) == "" {
			continue
		}
		hk := productHostKey(p)
		for _, v := range p.Vendors {
			v = strings.ToLower(strings.TrimSpace(v))
			if v == "" {
				continue
			}
			for _, prod := range p.Products {
				prod = strings.ToLower(strings.TrimSpace(prod))
				if prod == "" {
					continue
				}
				versionedByHost[hk] = append(versionedByHost[hk], vendorProductPair{vendor: v, product: prod})
			}
		}
	}
	if len(versionedByHost) == 0 {
		return products
	}
	out := make([]Product, 0, len(products))
	for _, p := range products {
		if strings.TrimSpace(p.Version) != "" {
			out = append(out, p)
			continue
		}
		covered := versionedByHost[productHostKey(p)]
		if len(covered) == 0 {
			out = append(out, p)
			continue
		}
		superseded := false
		for _, v := range p.Vendors {
			v = strings.ToLower(strings.TrimSpace(v))
			if v == "" {
				continue
			}
			for _, c := range covered {
				if c.vendor == v && matchesAnyPattern(p.Products, c.product) {
					superseded = true
					break
				}
			}
			if superseded {
				break
			}
		}
		if !superseded {
			out = append(out, p)
		}
	}
	return out
}

// normalizeUniFiFirmwareVersion strips UniFi's trailing 4th numeric build
// suffix (such as "6.6.55.15189" -> "6.6.55" or "4.4.57.5578372" -> "4.4.57")
// when the version consists of a 3-part major.minor.patch release plus a build
// number >= 1000. This allows UniFi stat/device strings to match 3-part NVD
// inclusive bounds and exact versions without weakening CompareVersions.
func normalizeUniFiFirmwareVersion(raw string) string {
	v := strings.TrimSpace(raw)
	parts := strings.Split(v, ".")
	if len(parts) != 4 {
		return v
	}
	for _, part := range parts {
		if !isASCIIUnsignedInt(part) {
			return v
		}
	}
	build, err := strconv.Atoi(parts[3])
	if err != nil || build < 1000 {
		return v
	}
	return parts[0] + "." + parts[1] + "." + parts[2]
}

func isASCIIUnsignedInt(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// ruleHit records one deterministic match emitted by FingerprintRule.matchAll.
type ruleHit struct {
	version string
	model   string
	source  string
}

// matchAll checks whether any configured identity signal on a FingerprintRule
// matches hp, preferring version-bearing signals (SSH banner, HTTP Server) over
// identity-only signals and iterating HTTP ports in deterministic sorted order.
// PortsAny never produces a match on its own; when set, it acts as a port
// precondition that must hold alongside an identity signal.
func (r *FingerprintRule) matchAll(hp probe.HostProfile) []ruleHit {
	if len(r.PortsAny) > 0 {
		portOK := false
		for _, p := range r.PortsAny {
			if hp.HasPort(p) {
				portOK = true
				break
			}
		}
		if !portOK {
			return nil
		}
	}

	if r.sshBannerRe != nil && hp.SSHBanner != "" {
		if m := r.sshBannerRe.FindStringSubmatch(hp.SSHBanner); m != nil {
			return []ruleHit{{
				version: captureGroup(m, r.VersionGroup),
				model:   captureGroup(m, r.ModelGroup),
				source:  "ssh-banner",
			}}
		}
	}

	var ports []int
	if (r.httpServerRe != nil || r.httpTitleRe != nil) && len(hp.HTTP) > 0 {
		ports = make([]int, 0, len(hp.HTTP))
		for port := range hp.HTTP {
			ports = append(ports, port)
		}
		sort.Ints(ports)
	}

	if r.httpServerRe != nil && len(ports) > 0 {
		if hits := matchHTTPField(ports, hp.HTTP, r.httpServerRe, r.VersionGroup, r.ModelGroup, "http-server", func(b probe.HTTPBanner) string {
			return b.Server
		}); len(hits) > 0 {
			return hits
		}
	}
	if r.httpTitleRe != nil && len(ports) > 0 {
		if hits := matchHTTPField(ports, hp.HTTP, r.httpTitleRe, r.VersionGroup, r.ModelGroup, "http-title", func(b probe.HTTPBanner) string {
			return b.Title
		}); len(hits) > 0 {
			return hits
		}
	}
	if r.hostnameRe != nil {
		for _, candidate := range []string{hp.Client.Name, hp.Client.Hostname} {
			if candidate != "" {
				if m := r.hostnameRe.FindStringSubmatch(candidate); m != nil {
					return []ruleHit{{
						version: captureGroup(m, r.VersionGroup),
						model:   captureGroup(m, r.ModelGroup),
						source:  "hostname",
					}}
				}
			}
		}
	}
	if len(r.MACPrefix) > 0 && hp.Client.MAC != "" {
		macLower := strings.ToLower(hp.Client.MAC)
		for _, pfx := range r.MACPrefix {
			if strings.HasPrefix(macLower, strings.ToLower(pfx)) {
				return []ruleHit{{source: "mac-prefix"}}
			}
		}
	}
	return nil
}

// matchHTTPField scans HTTP banners in ascending port order, preferring banners
// that yield a non-empty version (or model) capture and emitting one hit per
// distinct (version, model) pair so multi-port hosts stay deterministic.
func matchHTTPField(
	ports []int,
	banners map[int]probe.HTTPBanner,
	re *regexp.Regexp,
	verGroup, modelGroup int,
	source string,
	extract func(probe.HTTPBanner) string,
) []ruleHit {
	var versioned []ruleHit
	var fallback *ruleHit
	seen := make(map[string]struct{})

	for _, port := range ports {
		val := extract(banners[port])
		if val == "" {
			continue
		}
		m := re.FindStringSubmatch(val)
		if m == nil {
			continue
		}
		ver := captureGroup(m, verGroup)
		model := captureGroup(m, modelGroup)
		hit := ruleHit{version: ver, model: model, source: source}
		if ver != "" || model != "" {
			k := strings.ToLower(ver) + "|" + strings.ToLower(model)
			if _, dup := seen[k]; !dup {
				seen[k] = struct{}{}
				versioned = append(versioned, hit)
			}
			continue
		}
		if fallback == nil {
			fallback = &hit
		}
	}
	if len(versioned) > 0 {
		return versioned
	}
	if fallback != nil {
		return []ruleHit{*fallback}
	}
	return nil
}

// expandProductPatterns substitutes "{model}" placeholders with the captured
// lowercase hardware model token (or drops the placeholder cleanly when absent).
func expandProductPatterns(patterns []string, model string) []string {
	normModel := strings.ToLower(strings.TrimSpace(model))
	out := make([]string, 0, len(patterns))
	for _, p := range patterns {
		if strings.Contains(p, "{model}") {
			if normModel == "" {
				p = strings.ReplaceAll(p, "{model}", "")
			} else {
				p = strings.ReplaceAll(p, "{model}", normModel)
			}
		}
		out = append(out, p)
	}
	return out
}

// parseVersionedCPE23 parses a CPE 2.3 URI ("cpe:2.3:a:vendor:product:version:update:...")
// and returns (vendor, product, version, true) only when a concrete version
// token (not "*", "-", or empty) is present, folding any non-wildcard update
// component (parts[6]) into version.
func parseVersionedCPE23(raw string) (vendor, product, version string, ok bool) {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(raw)), ":")
	if len(parts) < 6 || parts[0] != "cpe" || parts[1] != "2.3" {
		return "", "", "", false
	}
	vendor = strings.TrimSpace(parts[3])
	product = strings.TrimSpace(parts[4])
	version = strings.TrimSpace(parts[5])
	if vendor == "" || vendor == "*" || vendor == "-" ||
		product == "" || product == "*" || product == "-" ||
		version == "" || version == "*" || version == "-" {
		return "", "", "", false
	}
	if len(parts) > 6 {
		version = joinCPEVersionUpdate(version, parts[6])
	}
	return vendor, product, version, true
}

// formatProductLabel converts a CPE product token such as "grafana" or
// "http_server" into a concise human-readable display label.
func formatProductLabel(cpeProduct string) string {
	words := strings.Fields(strings.NewReplacer("_", " ", "-", " ").Replace(cpeProduct))
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}

// captureGroup safely extracts group idx from a regex submatch slice.
func captureGroup(matches []string, idx int) string {
	if idx <= 0 || idx >= len(matches) {
		return ""
	}
	return strings.TrimSpace(matches[idx])
}

// mapUniFiDeviceProducts maps a UniFi hardware device's Type and Model code to
// the exact NVD CPE product tokens used in Ubiquiti's CVE entries, taking care
// never to inspect user-configured dev.Name strings, never to conflate AP or
// switch "Pro Max" models with UDM Pro Max, and never to fall back to
// unifi_network_application for a device firmware version.
func mapUniFiDeviceProducts(dev unifi.Device) []string {
	typ := strings.ToLower(strings.TrimSpace(dev.Type))
	model := strings.ToLower(strings.TrimSpace(dev.Model))
	compact := strings.NewReplacer("-", "", "_", "", " ", "").Replace(model)

	// 1. Discriminate on unambiguous controller-reported dev.Type values first
	// so APs, switches, UXG gateways, and Cloud Keys are never misclassified by
	// model suffixes like "Pro Max". Do NOT short-circuit "ugw" or "udm" here:
	// integration-only snapshots infer "ugw" for UXG/UX models as well as USG,
	// and "udm" spans several console families.
	switch typ {
	case "uap":
		return []string{"unifi_uap_firmware"}
	case "usw":
		if strings.Contains(compact, "flexmini") || compact == "usmini" {
			// Flex Mini runs an independent 2.x firmware branch and is explicitly
			// excluded from standard 6.x/7.x UniFi Switch advisories.
			return []string{"unifi_switch_flex_mini_firmware"}
		}
		return []string{"unifi_switch_firmware"}
	case "uxg":
		if strings.Contains(compact, "pro") {
			return []string{"unifi_next-generation_gateway_pro_firmware", "unifi_gateway_firmware"}
		}
		return []string{"unifi_gateway_firmware"}
	case "uck":
		return []string{"unifi_cloudkey_firmware", "unifi_cloud_key_plus_firmware"}
	}

	// 2. Discriminate on model codes before falling back to generic "ugw"/"udm"
	// types. Order AP, switch, UXG, and UniFi Express cases before USG/UDM
	// patterns so next-gen gateways never map to legacy USG firmware.
	switch {
	// Access points (UAP, UAL6, U6-*, U7-*, U7 Pro Max, UK-Ultra, etc.).
	case strings.HasPrefix(compact, "uap") ||
		strings.HasPrefix(compact, "ual") ||
		strings.HasPrefix(compact, "u6") ||
		strings.HasPrefix(compact, "u7") ||
		strings.HasPrefix(compact, "uac") ||
		strings.HasPrefix(compact, "ukultra") ||
		strings.Contains(model, "access point"):
		return []string{"unifi_uap_firmware"}

	// Switches (USW-Flex-Mini, USW-*, USW Pro Max, USL16LP, US8P60, etc.).
	case strings.Contains(compact, "flexmini") || compact == "usmini":
		return []string{"unifi_switch_flex_mini_firmware"}
	case strings.HasPrefix(compact, "usw") ||
		strings.HasPrefix(compact, "usl") ||
		strings.HasPrefix(compact, "usf") ||
		strings.HasPrefix(compact, "usagg") ||
		isClassicUniFiSwitchCode(compact) ||
		strings.Contains(model, "switch"):
		return []string{"unifi_switch_firmware"}

	// Standalone next-gen gateways and UniFi Express (UXGPRO, UXG-Lite, UX, UX7).
	case strings.HasPrefix(compact, "uxg"):
		if strings.Contains(compact, "pro") {
			return []string{"unifi_next-generation_gateway_pro_firmware", "unifi_gateway_firmware"}
		}
		return []string{"unifi_gateway_firmware"}
	case compact == "ux" ||
		strings.HasPrefix(compact, "ux7") ||
		strings.HasPrefix(model, "ux-") ||
		strings.HasPrefix(model, "ux ") ||
		strings.Contains(compact, "unifiexpress") ||
		strings.Contains(model, "express"):
		return []string{"unifi_express_firmware", "unifi_gateway_firmware", "unifi_os"}
	case strings.HasPrefix(compact, "ugw") || strings.HasPrefix(compact, "usg"):
		return []string{"unifi_security_gateway_firmware"}

	// UniFi OS consoles (UDM Pro Max, UDM SE / UDMPROSE, UDM Pro, UDM, UDR, UCG, UDW).
	case strings.Contains(compact, "udmpromax") ||
		strings.Contains(compact, "dreammachinepromax") ||
		(typ == "udm" && strings.Contains(compact, "promax")):
		return []string{"unifi_dream_machine_pro_max_firmware", "unifi_os"}
	case strings.Contains(compact, "udmse") ||
		strings.Contains(compact, "udmprose") ||
		strings.Contains(compact, "dreammachinese") ||
		strings.Contains(compact, "specialedition"):
		return []string{"unifi_dream_machine_special_edition_firmware", "unifi_os"}
	case strings.Contains(compact, "udmpro") || strings.Contains(compact, "dreammachinepro"):
		return []string{"unifi_dream_machine_pro_firmware", "unifi_os"}
	case strings.HasPrefix(compact, "udm") || strings.Contains(compact, "dreammachine"):
		return []string{"unifi_dream_machine_firmware", "unifi_os"}
	case strings.HasPrefix(compact, "udr") || strings.Contains(compact, "dreamrouter"):
		return []string{"unifi_dream_router_firmware", "unifi_os"}
	case strings.HasPrefix(compact, "ucg") || strings.Contains(compact, "cloudgateway"):
		return []string{"unifi_cloud_gateway_*_firmware", "unifi_os"}
	case strings.HasPrefix(compact, "udw") || strings.Contains(compact, "dreamwall"):
		return []string{"unifi_dream_wall_firmware", "unifi_os"}
	case strings.HasPrefix(compact, "uck") || strings.Contains(compact, "cloudkey"):
		return []string{"unifi_cloudkey_firmware", "unifi_cloud_key_plus_firmware"}
	case typ == "ugw":
		return []string{"unifi_security_gateway_firmware"}
	case typ == "udm":
		return []string{"unifi_os"}
	default:
		// Never fall back to unifi_network_application with a device firmware version.
		return nil
	}
}

// isClassicUniFiSwitchCode reports whether compact is a classic UniFi switch
// model code consisting of "us" followed by a digit (e.g., "us8p60", "us24p250",
// "us48", "us16xg").
func isClassicUniFiSwitchCode(compact string) bool {
	return len(compact) >= 3 && strings.HasPrefix(compact, "us") && compact[2] >= '0' && compact[2] <= '9'
}
