// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cve

import (
	"cmp"
	"fmt"
	"io/fs"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
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

	// SSHBannerRegex matches the passive SSH greeting on its observed TCP port.
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
	// A host-only observation may use any inventory address. A service observation
	// belongs to the address actually probed and the port that supplied the signal.
	forwards := make(map[string][]unifi.PortForward)
	if snap != nil {
		for _, pf := range snap.PortForwards {
			if pf.Enabled && pf.FwdIP != "" {
				forwards[pf.FwdIP] = append(forwards[pf.FwdIP], pf)
			}
		}
	}
	type hostVersion struct {
		host, version      string
		unbound, ambiguous bool
	}
	groups := make(map[hostVersion][]Product)
	var groupOrder []hostVersion
	hostIPs := make(map[string][]string)
	computeWAN := func(p *Product) {
		p.WANExposed = false
		ips := []string{p.HostIP}
		if len(p.Ports) == 0 && len(hostIPs[p.HostIP]) > 0 {
			ips = hostIPs[p.HostIP]
		}
		for _, ip := range ips {
			for _, pf := range forwards[ip] {
				if len(p.Ports) == 0 || slices.ContainsFunc(p.Ports, func(ep EndpointPort) bool {
					return pf.ExposesEndpoint(ep.Port, ep.Transport)
				}) {
					p.WANExposed = true
					return
				}
			}
		}
	}
	mergeInto := func(groups map[hostVersion][]Product, order *[]hostVersion, k hostVersion, p Product) {
		group, exists := groups[k]
		if !exists {
			*order = append(*order, k)
		}
		for i := len(group) - 1; i >= 0; i-- {
			prev := group[i]
			if !productsOverlapVendorProduct(prev, p) {
				continue
			}
			// Keep the first rule's display label while preserving evidence from
			// every endpoint and CPE alias that identified this version.
			prev.Ports = append(prev.Ports, p.Ports...)
			prev.Vendors = mergeUniqueStringsCI(prev.Vendors, p.Vendors)
			prev.Products = mergeUniqueStringsCI(prev.Products, p.Products)
			prev.HighConfidence = prev.HighConfidence || p.HighConfidence
			prev.VersionAmbiguous = prev.VersionAmbiguous || p.VersionAmbiguous
			prev.WANExposed = prev.WANExposed || p.WANExposed
			p = prev
			group = slices.Delete(group, i, i+1)
		}
		groups[k] = append(group, p)
	}
	add := func(p Product) {
		computeWAN(&p)
		// Keep versionless host-only and distro-ambiguous observations separate
		// until supersession so host-wide WAN exposure and per-port distro flags
		// do not bleed across unrelated listeners.
		k := hostVersion{
			host:      productHostKey(p),
			version:   strings.ToLower(p.Version),
			unbound:   p.Version == "" && len(p.Ports) == 0,
			ambiguous: p.Version == "" && p.VersionAmbiguous,
		}
		mergeInto(groups, &groupOrder, k, p)
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
				Label:          fmt.Sprintf("UniFi %s (%s)", dev.Name, dev.Model),
				Vendors:        []string{"ui"},
				Products:       cpeProducts,
				Version:        strings.TrimSpace(dev.Version),
				Source:         "unifi-firmware",
				HighConfidence: true,
				HostName:       dev.Name,
				HostIP:         dev.IP,
				VLAN:           "UniFi Infrastructure",
			})
		}
	}

	// Unprobed clients, including sleeping devices, can still supply hostname and MAC evidence.
	if snap != nil {
		probed := make(map[string]bool, len(profiles))
		for _, hp := range profiles {
			probed[hp.Client.MAC] = true
		}
		profiles = slices.Clone(profiles)
		for _, cl := range snap.Clients {
			if !probed[cl.MAC] {
				profiles = append(profiles, probe.HostProfile{Client: cl})
			}
		}
	}
	for _, hp := range profiles {
		hostIP := hp.Client.PrimaryIP()
		hostIPs[hostIP] = hp.Client.AllIPs()
		probeIP := cmp.Or(hp.ProbeIP, hostIP)
		for _, rule := range f.rules {
			for _, hit := range rule.matchAll(hp) {
				label := rule.Name
				if hit.model != "" {
					label = fmt.Sprintf("%s %s", rule.Name, strings.ToUpper(hit.model))
				}
				var ports []EndpointPort
				ip := hostIP
				if hit.port > 0 {
					ip = probeIP
					ports = []EndpointPort{{Transport: "tcp", Port: hit.port}}
				}
				add(Product{
					Label:            label,
					Vendors:          rule.Vendors,
					Products:         expandProductPatterns(rule.Products, hit.model),
					Version:          hit.version,
					Source:           hit.source,
					HostName:         hp.Client.DisplayName(),
					HostIP:           ip,
					VLAN:             hp.Client.NetworkName,
					Ports:            ports,
					VersionAmbiguous: hit.ambiguous,
				})
			}
		}

		// Extract exact-version products directly from any versioned CPE 2.3
		// identifiers reported by Nerva's protocol fingerprinters.
		for _, svc := range hp.Services {
			transport := strings.ToLower(strings.TrimSpace(svc.Transport))
			if transport == "" {
				transport = "tcp"
			}
			for _, rawCPE := range svc.CPEs {
				vendor, product, ver, ok := parseVersionedCPE23(rawCPE)
				if !ok {
					continue
				}
				packaged := distroPackage.MatchString(svc.Banner) || distroPackage.MatchString(svc.Version) || distroPackage.MatchString(ver)
				add(Product{
					Label:            formatProductLabel(product),
					HighConfidence:   protocolIdentity(svc),
					Vendors:          []string{vendor},
					Products:         []string{product},
					Version:          upstreamVersion(ver, packaged),
					Source:           "nerva-cpe",
					HostName:         hp.Client.DisplayName(),
					HostIP:           probeIP,
					VLAN:             hp.Client.NetworkName,
					Ports:            []EndpointPort{{Transport: transport, Port: svc.Port}},
					VersionAmbiguous: packaged,
				})
			}
		}
	}

	var products []Product
	for _, k := range groupOrder {
		for _, p := range groups[k] {
			slices.SortFunc(p.Ports, func(a, b EndpointPort) int {
				return cmp.Or(cmp.Compare(a.Transport, b.Transport), cmp.Compare(a.Port, b.Port))
			})
			p.Ports = slices.Compact(p.Ports)
			products = append(products, p)
		}
	}

	products = dropSupersededVersionlessProducts(products, computeWAN)
	// Collapse any surviving versionless products that were kept split only for
	// supersession (e.g., an unbound hostname match and a port-bound HTTP title
	// when no versioned CPE superseded either).
	finalGroups := make(map[hostVersion][]Product, len(products))
	var finalOrder []hostVersion
	for _, p := range products {
		if p.Version == "" {
			p.VersionAmbiguous = false
		}
		mergeInto(finalGroups, &finalOrder, hostVersion{host: productHostKey(p), version: strings.ToLower(p.Version)}, p)
	}
	products = products[:0]
	for _, k := range finalOrder {
		for _, p := range finalGroups[k] {
			slices.SortFunc(p.Ports, func(a, b EndpointPort) int {
				return cmp.Or(cmp.Compare(a.Transport, b.Transport), cmp.Compare(a.Port, b.Port))
			})
			p.Ports = slices.Compact(p.Ports)
			products = append(products, p)
		}
	}

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

// protocolIdentity reserves high confidence for an observed protocol fingerprint.
// A CPE parsed from a self-reported web or SSH banner adds no independent evidence.
func protocolIdentity(svc probe.Service) bool {
	switch strings.ToLower(svc.Protocol) {
	case "", "http", "https", "ssh":
		return false
	default:
		return svc.State == probe.ServiceStateObservedProtocol
	}
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
// (host, vendor, product) is already covered by one or more versioned Products
// on the same host, merging any uncovered vendor and exact product aliases from
// the versionless rule into each matching versioned Product so multi-vendor
// NVD shards (such as nginx alongside f5) still match with the exact version.
func dropSupersededVersionlessProducts(products []Product, recomputeWAN func(*Product)) []Product {
	work := make([]Product, len(products))
	copy(work, products)

	versionedIdxByHost := make(map[string][]int)
	for i, p := range work {
		if strings.TrimSpace(p.Version) == "" {
			continue
		}
		hk := productHostKey(p)
		versionedIdxByHost[hk] = append(versionedIdxByHost[hk], i)
	}
	if len(versionedIdxByHost) == 0 {
		return work
	}

	drop := make([]bool, len(work))
	for i, p := range work {
		if strings.TrimSpace(p.Version) != "" {
			continue
		}
		vIdxs := versionedIdxByHost[productHostKey(p)]
		if len(vIdxs) == 0 {
			continue
		}
		matchedAny := false
		remaining := slices.Clone(p.Ports)
		for _, vi := range vIdxs {
			if !productsOverlapVendorProduct(p, work[vi]) {
				continue
			}
			// A version observed on one listener cannot supersede a versionless
			// fingerprint on another, even when both run the same product.
			if len(p.Ports) > 0 {
				ports := work[vi].Ports
				if !slices.ContainsFunc(p.Ports, func(ep EndpointPort) bool { return slices.Contains(ports, ep) }) {
					continue
				}
				work[vi].VersionAmbiguous = work[vi].VersionAmbiguous || p.VersionAmbiguous
				remaining = slices.DeleteFunc(remaining, func(ep EndpointPort) bool { return slices.Contains(ports, ep) })
			}
			// Preserve host-wide WAN exposure when an unbound host identity is
			// superseded by an overlapping versioned product.
			if len(p.Ports) == 0 {
				work[vi].WANExposed = work[vi].WANExposed || p.WANExposed
			}
			matchedAny = true
			work[vi].Vendors = mergeUniqueStringsCI(work[vi].Vendors, p.Vendors)
			var exactAliases []string
			for _, pat := range p.Products {
				if !strings.Contains(pat, "*") {
					exactAliases = append(exactAliases, pat)
				}
			}
			if len(exactAliases) > 0 {
				work[vi].Products = mergeUniqueStringsCI(work[vi].Products, exactAliases)
			}
		}
		if matchedAny {
			work[i].Ports = remaining
			drop[i] = len(remaining) == 0
			if !drop[i] && recomputeWAN != nil {
				recomputeWAN(&work[i])
			}
		}
	}

	out := make([]Product, 0, len(work))
	for i, p := range work {
		if !drop[i] {
			out = append(out, p)
		}
	}
	return out
}

// productsOverlapVendorProduct recognizes aliases shared by fingerprints on the same host.
func productsOverlapVendorProduct(ruleProd, versionedProd Product) bool {
	for _, rv := range ruleProd.Vendors {
		rv = strings.ToLower(strings.TrimSpace(rv))
		if rv == "" {
			continue
		}
		for _, vv := range versionedProd.Vendors {
			if strings.ToLower(strings.TrimSpace(vv)) != rv {
				continue
			}
			for _, vp := range versionedProd.Products {
				if matchesAnyPattern(ruleProd.Products, vp) {
					return true
				}
			}
			for _, rp := range ruleProd.Products {
				if !strings.Contains(rp, "*") && matchesAnyPattern(versionedProd.Products, rp) {
					return true
				}
			}
		}
	}
	return false
}

// mergeUniqueStringsCI preserves the preferred spelling and order of existing aliases.
func mergeUniqueStringsCI(base, extra []string) []string {
	seen := make(map[string]struct{}, len(base)+len(extra))
	out := make([]string, 0, len(base)+len(extra))
	for _, list := range [][]string{base, extra} {
		for _, raw := range list {
			norm := strings.ToLower(strings.TrimSpace(raw))
			if norm == "" {
				continue
			}
			if _, dup := seen[norm]; dup {
				continue
			}
			seen[norm] = struct{}{}
			out = append(out, raw)
		}
	}
	return out
}

// ruleHit records one deterministic match emitted by FingerprintRule.matchAll.
type ruleHit struct {
	port      int
	ambiguous bool
	version   string
	model     string
	source    string
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

	var hits []ruleHit
	if r.sshBannerRe != nil {
		// Nerva can backfill the host's SSHBanner from a nonstandard port.
		// Prefer its endpoint when it supplied the same greeting.
		located := false
		for _, svc := range hp.Services {
			if svc.Banner == "" || (svc.Transport != "" && !strings.EqualFold(svc.Transport, "tcp")) {
				continue
			}
			if m := r.sshBannerRe.FindStringSubmatch(svc.Banner); m != nil &&
				(strings.EqualFold(svc.Protocol, "ssh") || strings.HasPrefix(svc.Banner, "SSH-")) {
				hits = append(hits, r.serviceHit(m, svc.Banner, "ssh-banner", svc.Port))
				located = located || svc.Banner == hp.SSHBanner
			}
		}
		if !located && hp.SSHBanner != "" {
			if m := r.sshBannerRe.FindStringSubmatch(hp.SSHBanner); m != nil {
				hits = append(hits, r.serviceHit(m, hp.SSHBanner, "ssh-banner", 22))
			}
		}
	}
	var ports []int
	if r.httpServerRe != nil || r.httpTitleRe != nil {
		ports = slices.Sorted(maps.Keys(hp.HTTP))
	}
	for _, port := range ports {
		banner := hp.HTTP[port]
		if r.httpServerRe != nil && banner.Server != "" {
			if m := r.httpServerRe.FindStringSubmatch(banner.Server); m != nil {
				hits = append(hits, r.serviceHit(m, banner.Server, "http-server", port))
				continue
			}
		}
		if r.httpTitleRe != nil && banner.Title != "" {
			if m := r.httpTitleRe.FindStringSubmatch(banner.Title); m != nil {
				hits = append(hits, r.serviceHit(m, banner.Title, "http-title", port))
			}
		}
	}
	if !slices.ContainsFunc(hits, func(h ruleHit) bool { return h.version != "" }) {
		if h, ok := r.matchHostIdentity(hp); ok && (len(hits) == 0 || h.version == "") {
			hits = append(hits, h)
		}
	}
	if r.ModelGroup > 0 {
		// A family-only hit on another port belongs to the same model when
		// the concrete banners agree. Conflicting models cannot refine it.
		model := ""
		for _, h := range hits {
			if h.model == "" {
				continue
			}
			if model != "" && !strings.EqualFold(model, h.model) {
				return slices.DeleteFunc(hits, func(h ruleHit) bool { return h.model == "" })
			}
			model = h.model
		}
		for i := range hits {
			if hits[i].model == "" {
				hits[i].model = model
			}
		}
	}
	return hits
}

// matchHostIdentity prefers a concrete hardware model over a generic family name.
func (r *FingerprintRule) matchHostIdentity(hp probe.HostProfile) (ruleHit, bool) {
	var best ruleHit
	consider := func(re *regexp.Regexp, candidate, source string) {
		if re == nil || candidate == "" {
			return
		}
		if m := re.FindStringSubmatch(candidate); m != nil {
			hit := ruleHit{version: captureGroup(m, r.VersionGroup), model: captureGroup(m, r.ModelGroup), source: source}
			if best.source == "" || (best.model == "" && hit.model != "") {
				best = hit
			}
		}
	}
	consider(r.hostnameRe, hp.Client.Name, "hostname")
	consider(r.hostnameRe, hp.Client.Hostname, "hostname")
	for _, md := range hp.MDNSServices {
		if !hardwarePrinterService(md, hp.HTTP[md.Port]) || md.Withdrawn || (md.Reflected && !md.TrustedReflector) {
			continue
		}
		match := func(value string) {
			consider(r.hostnameRe, value, "mdns")
			consider(r.httpTitleRe, value, "mdns")
		}
		match(md.Instance)
		for _, txt := range md.TXT {
			key, value, _ := strings.Cut(txt, "=")
			switch strings.ToLower(key) {
			case "product", "ty", "usb_mdl":
				match(value)
			}
		}
	}
	if best.source != "" {
		return best, true
	}
	if len(r.MACPrefix) > 0 && hp.Client.MAC != "" {
		macLower := strings.ToLower(hp.Client.MAC)
		for _, pfx := range r.MACPrefix {
			if strings.HasPrefix(macLower, strings.ToLower(pfx)) {
				return ruleHit{source: "mac-prefix"}, true
			}
		}
	}
	return ruleHit{}, false
}

// hardwarePrinterService excludes shared queues whose model describes a remote printer.
func hardwarePrinterService(md probe.MDNSService, banner probe.HTTPBanner) bool {
	switch strings.ToLower(md.Type) {
	case "_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp":
	default:
		return false
	}
	if strings.Contains(md.Instance, " @ ") || strings.HasPrefix(strings.ToLower(banner.Server), "cups/") {
		return false
	}
	for _, txt := range md.TXT {
		value := strings.ToLower(txt)
		if strings.HasPrefix(value, "printer-type=") || strings.HasPrefix(value, "rp=printers/") || strings.Contains(value, "cups") {
			return false
		}
	}
	return true
}

// distroPackage recognizes Linux/BSD distribution names and package revision
// markers in the original banner or version string (such as Debian, Ubuntu,
// RHEL/CentOS/Rocky/AlmaLinux/Fedora/Amazon Linux, Alpine, SUSE, and FreeBSD).
var distroPackage = regexp.MustCompile(`(?i)(?:^|[^a-z])(deb[0-9]+|el[0-9]+|fc[0-9]+|amzn[0-9]+|(?:debian|ubuntu|rhel|red[ -]?hat|centos|rocky|alma(?:linux)?|oracle[ -]?linux|amazon|fedora|alpine|(?:open)?suse|freebsd)(?:[^a-z]|$))`)

// packageRevision separates numeric distribution revisions while preserving upstream prereleases.
var packageRevision = regexp.MustCompile(`[-+~]r?[0-9]`)

// upstreamVersion removes the packaging revision before checking upstream CPE ranges.
func upstreamVersion(version string, packaged bool) string {
	if !packaged {
		return version
	}
	// Debian and RPM revisions follow a hyphen. Attached markers such as
	// ".el9" can also appear directly in the captured version.
	if loc := distroPackage.FindStringSubmatchIndex(version); loc != nil {
		version = strings.TrimRight(version[:loc[2]], ".+~_-")
	}
	if loc := packageRevision.FindStringIndex(version); loc != nil {
		version = version[:loc[0]]
	}
	return version
}

// serviceHit retains the endpoint and packaging evidence that the regex capture omits.
func (r *FingerprintRule) serviceHit(m []string, raw, source string, port int) ruleHit {
	version := captureGroup(m, r.VersionGroup)
	packaged := distroPackage.MatchString(raw)
	return ruleHit{version: upstreamVersion(version, packaged), model: captureGroup(m, r.ModelGroup),
		source: source, port: port, ambiguous: packaged}
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
