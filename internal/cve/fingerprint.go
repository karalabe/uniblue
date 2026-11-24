package cve

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
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

	// SSHBannerRegex matches against the passive SSH greeting line on port 22.
	SSHBannerRegex string `yaml:"ssh_banner_regex"`

	// MACPrefix matches against colon-separated lowercase MAC prefixes.
	MACPrefix []string `yaml:"mac_prefix"`

	// PortsAny matches when any listed TCP port was observed open.
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
	seen := make(map[string]struct{})
	add := func(p Product) {
		key := fmt.Sprintf("%s|%s|%s", p.HostIP, p.Label, p.Version)
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		products = append(products, p)
	}

	// 1. Identify UniFi infrastructure gear directly from controller metadata.
	// Emit one Product per UniFi device carrying all applicable CPE tokens so
	// reports stay clean and deduplicated.
	if snap != nil {
		for _, dev := range snap.Devices {
			add(Product{
				Label:    fmt.Sprintf("UniFi %s (%s)", dev.Name, dev.Model),
				Vendors:  []string{"ui"},
				Products: mapUniFiDeviceProducts(dev),
				Version:  dev.Version,
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
		wan := wanExposedIPs[hp.Client.IP]
		for _, rule := range f.rules {
			ver, model, source, ok := rule.match(hp)
			if !ok {
				continue
			}
			label := rule.Name
			if model != "" {
				label = fmt.Sprintf("%s %s", rule.Name, strings.ToUpper(model))
			}
			add(Product{
				Label:      label,
				Vendors:    rule.Vendors,
				Products:   expandProductPatterns(rule.Products, model),
				Version:    ver,
				Source:     source,
				HostName:   hp.Client.DisplayName(),
				HostIP:     hp.Client.IP,
				VLAN:       hp.Client.NetworkName,
				WANExposed: wan,
			})
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
					HostIP:     hp.Client.IP,
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
				ver, model, source, ok := rule.match(hp)
				if !ok {
					continue
				}
				label := rule.Name
				if model != "" {
					label = fmt.Sprintf("%s %s", rule.Name, strings.ToUpper(model))
				}
				add(Product{
					Label:    label,
					Vendors:  rule.Vendors,
					Products: expandProductPatterns(rule.Products, model),
					Version:  ver,
					Source:   source,
					HostName: cl.DisplayName(),
					HostIP:   cl.IP,
					VLAN:     cl.NetworkName,
				})
			}
		}
	}

	sort.Slice(products, func(i, j int) bool {
		if products[i].HostIP != products[j].HostIP {
			return products[i].HostIP < products[j].HostIP
		}
		return products[i].Label < products[j].Label
	})
	return products
}

// match checks whether any configured signal on a FingerprintRule matches hp,
// preferring version-bearing signals (SSH banner, HTTP Server) over identity-only signals.
func (r *FingerprintRule) match(hp probe.HostProfile) (version, model, source string, ok bool) {
	if r.sshBannerRe != nil && hp.SSHBanner != "" {
		if m := r.sshBannerRe.FindStringSubmatch(hp.SSHBanner); m != nil {
			return captureGroup(m, r.VersionGroup), captureGroup(m, r.ModelGroup), "ssh-banner", true
		}
	}
	if r.httpServerRe != nil {
		for _, b := range hp.HTTP {
			if b.Server != "" {
				if m := r.httpServerRe.FindStringSubmatch(b.Server); m != nil {
					return captureGroup(m, r.VersionGroup), captureGroup(m, r.ModelGroup), "http-server", true
				}
			}
		}
	}
	if r.httpTitleRe != nil {
		for _, b := range hp.HTTP {
			if b.Title != "" {
				if m := r.httpTitleRe.FindStringSubmatch(b.Title); m != nil {
					return captureGroup(m, r.VersionGroup), captureGroup(m, r.ModelGroup), "http-title", true
				}
			}
		}
	}
	if r.hostnameRe != nil {
		for _, candidate := range []string{hp.Client.Name, hp.Client.Hostname} {
			if candidate != "" {
				if m := r.hostnameRe.FindStringSubmatch(candidate); m != nil {
					return captureGroup(m, r.VersionGroup), captureGroup(m, r.ModelGroup), "hostname", true
				}
			}
		}
	}
	if len(r.MACPrefix) > 0 && hp.Client.MAC != "" {
		macLower := strings.ToLower(hp.Client.MAC)
		for _, pfx := range r.MACPrefix {
			if strings.HasPrefix(macLower, strings.ToLower(pfx)) {
				return "", "", "mac-prefix", true
			}
		}
	}
	if len(r.PortsAny) > 0 {
		for _, p := range r.PortsAny {
			if hp.HasPort(p) {
				return "", "", "port", true
			}
		}
	}
	return "", "", "", false
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

// parseVersionedCPE23 parses a CPE 2.3 URI ("cpe:2.3:a:vendor:product:version:...")
// and returns (vendor, product, version, true) only when a concrete version
// token (not "*", "-", or empty) is present.
func parseVersionedCPE23(raw string) (vendor, product, version string, ok bool) {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(raw)), ":")
	if len(parts) < 6 || parts[0] != "cpe" || parts[1] != "2.3" {
		return "", "", "", false
	}
	vendor = parts[3]
	product = parts[4]
	version = parts[5]
	if vendor == "" || vendor == "*" || vendor == "-" ||
		product == "" || product == "*" || product == "-" ||
		version == "" || version == "*" || version == "-" {
		return "", "", "", false
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

// mapUniFiDeviceProducts maps a UniFi hardware model name to the exact NVD CPE
// product tokens used in Ubiquiti's CVE entries, taking care not to mix models
// that use separate firmware version tracks (such as USW Flex Mini's 2.x branch).
func mapUniFiDeviceProducts(dev unifi.Device) []string {
	m := strings.ToLower(dev.Model + " " + dev.Name)
	switch {
	case strings.Contains(m, "pro max"):
		return []string{"unifi_dream_machine_pro_max_firmware", "unifi_os"}
	case strings.Contains(m, "udm se") || strings.Contains(m, "special edition"):
		return []string{"unifi_dream_machine_special_edition_firmware", "unifi_os"}
	case strings.Contains(m, "udm pro") || strings.Contains(m, "dream machine pro"):
		return []string{"unifi_dream_machine_pro_firmware", "unifi_os"}
	case strings.Contains(m, "udm") || strings.Contains(m, "dream machine"):
		return []string{"unifi_dream_machine_firmware", "unifi_os"}
	case strings.Contains(m, "dream router") || strings.Contains(m, "udr"):
		return []string{"unifi_dream_router_firmware", "unifi_os"}
	case strings.Contains(m, "cloud gateway") || strings.Contains(m, "ucg"):
		return []string{"unifi_cloud_gateway_*_firmware", "unifi_os"}
	case strings.Contains(m, "cloud key") || strings.Contains(m, "uck"):
		return []string{"unifi_cloudkey_firmware", "unifi_cloud_key_plus_firmware"}
	case strings.Contains(m, "flex mini") || strings.Contains(m, "flex-mini"):
		// Flex Mini runs an independent 2.x firmware branch and is explicitly
		// excluded from standard 6.x/7.x UniFi Switch advisories.
		return []string{"unifi_switch_flex_mini_firmware"}
	case strings.Contains(m, "usw") || strings.Contains(m, "switch"):
		return []string{"unifi_switch_firmware"}
	case strings.Contains(m, "ap") || strings.Contains(m, "iw ") || strings.Contains(m, "u6") || strings.Contains(m, "u7"):
		return []string{"unifi_uap_firmware"}
	default:
		return []string{"unifi_os", "unifi_network_application"}
	}
}
