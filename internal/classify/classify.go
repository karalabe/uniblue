// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package classify deterministically categorizes LAN hosts into operational
// device classes (server, vm, bmc, netservice, camera, printer, media, iot,
// personal, network) by combining observed protocol/port signals, official IEEE
// OUI lookups, MAC structure, and controller metadata.
package classify

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/karalabe/uniblue/internal/oui"
	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/unifi"
	"gopkg.in/yaml.v3"
)

// Category identifies the high-level operational class of a LAN client.
type Category string

const (
	// CategoryNetwork marks switches, routers, gateways, and wireless APs.
	CategoryNetwork Category = "network"
	// CategoryBMC marks out-of-band server management controllers (IPMI/iKVM/iDRAC/iLO).
	CategoryBMC Category = "bmc"
	// CategoryServer marks compute servers, hypervisors, and NAS storage appliances.
	CategoryServer Category = "server"
	// CategoryVM marks virtual machines and containers with virtual/synthetic MACs.
	CategoryVM Category = "vm"
	// CategoryNetService marks core infrastructure services (DNS resolvers, WAN proxies).
	CategoryNetService Category = "netservice"
	// CategoryCamera marks IP cameras, doorbells, chimes, and NVRs.
	CategoryCamera Category = "camera"
	// CategoryPrinter marks network printers and 3D printers.
	CategoryPrinter Category = "printer"
	// CategoryMedia marks AV receivers, smart TVs, streaming boxes, and consoles.
	CategoryMedia Category = "media"
	// CategoryIoT marks smart-home hubs, HVAC bridges, vacuums, relays, and sensors.
	CategoryIoT Category = "iot"
	// CategoryPersonal marks laptops, desktops, phones, and tablets.
	CategoryPersonal Category = "personal"
	// CategoryUnknown is used when no deterministic signal identifies the device.
	CategoryUnknown Category = "unknown"
)

// Confidence expresses how strongly the available signals determine Category.
type Confidence string

const (
	// ConfidenceHigh indicates direct protocol/port proof or an unambiguous hardware OUI.
	ConfidenceHigh Confidence = "high"
	// ConfidenceMedium indicates classification from hostname, silicon OUI, or MAC bits.
	ConfidenceMedium Confidence = "medium"
	// ConfidenceLow indicates a weak or fallback classification.
	ConfidenceLow Confidence = "low"
)

// Result holds the deterministic classification of a single LAN client along
// with its resolved hardware vendor and the exact evidence signals that fired.
type Result struct {
	// Category is the canonical operational device class.
	Category Category `json:"category"`

	// Role is a concise, human-readable description (e.g., "DNS Server", "3D Printer").
	Role string `json:"role,omitempty"`

	// Vendor is the hardware manufacturer or hypervisor resolved from IEEE OUI or UniFi.
	Vendor string `json:"vendor,omitempty"`

	// Confidence ranks the strength of the classification ("high", "medium", "low").
	Confidence Confidence `json:"confidence"`

	// Signals records the deterministic facts that led to this classification.
	Signals []string `json:"signals,omitempty"`
}

// taxonomyFile mirrors the structure of classify/taxonomy.yaml.
type taxonomyFile struct {
	VendorRules        []vendorRule   `yaml:"vendor_rules"`
	SiliconVendorRules []vendorRule   `yaml:"silicon_vendor_rules"`
	HostnameRules      []hostnameRule `yaml:"hostname_rules"`
}

type vendorRule struct {
	Category    Category `yaml:"category"`
	Role        string   `yaml:"role"`
	VendorRegex string   `yaml:"vendor_regex"`
	re          *regexp.Regexp
}

type hostnameRule struct {
	Category Category `yaml:"category"`
	Role     string   `yaml:"role"`
	Regex    string   `yaml:"regex"`
	re       *regexp.Regexp
}

// Classifier evaluates LAN clients against compiled YAML taxonomy rules, an
// optional local IEEE OUI database, and active host probe results.
type Classifier struct {
	ouiDB        *oui.DB
	vendorRules  []vendorRule
	siliconRules []vendorRule
	hostRules    []hostnameRule
}

// Load reads and compiles all taxonomy YAML files from fsys and attaches ouiDB
// (which may be nil or empty, in which case built-in virtual OUIs and UniFi
// OUI strings are still used).
func Load(fsys fs.FS, ouiDB *oui.DB) (*Classifier, error) {
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
		return nil, fmt.Errorf("walk classify rules: %w", err)
	}
	sort.Strings(paths)

	c := &Classifier{ouiDB: ouiDB}
	for _, p := range paths {
		raw, err := fs.ReadFile(fsys, p)
		if err != nil {
			return nil, fmt.Errorf("read taxonomy %q: %w", p, err)
		}
		var tf taxonomyFile
		if err := yaml.Unmarshal(raw, &tf); err != nil {
			return nil, fmt.Errorf("parse taxonomy %q: %w", p, err)
		}
		for _, r := range tf.VendorRules {
			if r.re, err = regexp.Compile(r.VendorRegex); err != nil {
				return nil, fmt.Errorf("compile vendor rule %q: %w", r.Role, err)
			}
			c.vendorRules = append(c.vendorRules, r)
		}
		for _, r := range tf.SiliconVendorRules {
			if r.re, err = regexp.Compile(r.VendorRegex); err != nil {
				return nil, fmt.Errorf("compile silicon rule %q: %w", r.Role, err)
			}
			c.siliconRules = append(c.siliconRules, r)
		}
		for _, r := range tf.HostnameRules {
			if r.re, err = regexp.Compile(r.Regex); err != nil {
				return nil, fmt.Errorf("compile hostname rule %q: %w", r.Role, err)
			}
			c.hostRules = append(c.hostRules, r)
		}
	}
	return c, nil
}

// ClassifyAll classifies every client in snap (keyed by client IP, falling back
// to MAC), incorporating optional host probe profiles when available.
func (c *Classifier) ClassifyAll(snap *unifi.Snapshot, profiles []probe.HostProfile) map[string]Result {
	if snap == nil {
		return nil
	}
	profileByIP := make(map[string]*probe.HostProfile, len(profiles))
	for i := range profiles {
		if profiles[i].Client.IP != "" {
			profileByIP[profiles[i].Client.IP] = &profiles[i]
		}
	}

	// Track internal IPs that receive active WAN HTTP/HTTPS forwards (80/443).
	wanWebIPs := make(map[string]bool)
	for _, pf := range snap.PortForwards {
		if !pf.Enabled || pf.FwdIP == "" {
			continue
		}
		if pf.ExposesPort(80) || pf.ExposesPort(443) {
			wanWebIPs[pf.FwdIP] = true
		}
	}

	out := make(map[string]Result, len(snap.Clients))
	for _, cl := range snap.Clients {
		key := cl.IP
		if key == "" {
			key = cl.MAC
		}
		out[key] = c.ClassifyClient(cl, profileByIP[cl.IP], wanWebIPs[cl.IP])
	}
	return out
}

// ClassifyClient determines the Category, Role, Vendor, Confidence, and
// supporting Signals for a single UniFi client using an ordered, deterministic
// signal stack:
//  1. Active protocol/port/HTTP banner proof (and WAN HTTP entrypoint role)
//  2. Known virtualization MAC prefixes (QEMU, VMware, Proxmox, Docker, etc.)
//  3. Unambiguous hardware manufacturer OUI (IEEE MA-S -> MA-M -> MA-L)
//  4. DHCP hostname / controller display name patterns
//  5. Generic embedded Wi-Fi/MCU silicon OUIs (e.g., Espressif)
//  6. IEEE locally-administered MAC bit (wired -> virtual NIC, Wi-Fi -> private mobile/laptop)
func (c *Classifier) ClassifyClient(cl unifi.Client, hp *probe.HostProfile, isWANWeb bool) Result {
	ouiRes := c.ouiDB.Lookup(cl.MAC)
	vendor := resolveVendor(ouiRes, cl.OUI)

	// 1. Active protocol, port, banner, and WAN-proxy signals (strongest proof).
	if res, ok := classifyByProtocol(hp, isWANWeb, vendor); ok {
		return res
	}

	// 2. Virtualization MAC prefix (e.g., 52:54:00 QEMU/KVM, 00:50:56 VMware).
	if ouiRes.IsVirtual {
		return Result{
			Category:   CategoryVM,
			Role:       fmt.Sprintf("Virtual Machine (%s)", ouiRes.Vendor),
			Vendor:     vendor,
			Confidence: ConfidenceHigh,
			Signals:    []string{fmt.Sprintf("virtual OUI %s (%s)", ouiRes.Prefix, ouiRes.Vendor)},
		}
	}

	// 3. Unambiguous hardware manufacturer OUI (MA-S / MA-M / MA-L).
	if vendor != "" {
		for _, r := range c.vendorRules {
			if r.re.MatchString(vendor) {
				sig := fmt.Sprintf("vendor %q", vendor)
				if ouiRes.Registry != "" && ouiRes.Prefix != "" {
					sig = fmt.Sprintf("IEEE %s %s (%s)", ouiRes.Registry, ouiRes.Prefix, vendor)
				}
				return Result{
					Category:   r.Category,
					Role:       r.Role,
					Vendor:     vendor,
					Confidence: ConfidenceHigh,
					Signals:    []string{sig},
				}
			}
		}
	}

	// 4. DHCP hostname and UniFi display-name taxonomy rules.
	nameText := strings.TrimSpace(cl.Hostname + " " + cl.Name)
	if nameText != "" {
		for _, r := range c.hostRules {
			if r.re.MatchString(nameText) {
				sig := fmt.Sprintf("hostname/name matched %s", r.Role)
				if cl.Hostname != "" {
					sig = fmt.Sprintf("hostname %q", cl.Hostname)
				}
				return Result{
					Category:   r.Category,
					Role:       r.Role,
					Vendor:     vendor,
					Confidence: ConfidenceMedium,
					Signals:    []string{sig},
				}
			}
		}
	}

	// 5. Generic embedded Wi-Fi / MCU silicon OUIs (evaluated after hostname
	// rules so named ESP32 printers/cameras keep their specific role).
	if vendor != "" {
		for _, r := range c.siliconRules {
			if r.re.MatchString(vendor) {
				return Result{
					Category:   r.Category,
					Role:       r.Role,
					Vendor:     vendor,
					Confidence: ConfidenceMedium,
					Signals:    []string{fmt.Sprintf("embedded silicon OUI (%s)", vendor)},
				}
			}
		}
	}

	// 6. Locally-administered MAC bit (0x02 on first byte): wired synthetic MACs
	// strongly indicate containers/VMs, while wireless private MACs indicate
	// modern phones/tablets/laptops using MAC randomization.
	if ouiRes.IsLocallyAdministered {
		if cl.IsWired {
			return Result{
				Category:   CategoryVM,
				Role:       "Virtual NIC / Container",
				Vendor:     vendor,
				Confidence: ConfidenceMedium,
				Signals:    []string{"wired locally-administered MAC"},
			}
		}
		return Result{
			Category:   CategoryPersonal,
			Role:       "Mobile / Laptop (Private MAC)",
			Vendor:     vendor,
			Confidence: ConfidenceMedium,
			Signals:    []string{"wireless locally-administered private MAC"},
		}
	}

	return Result{
		Category:   CategoryUnknown,
		Role:       "Unclassified Device",
		Vendor:     vendor,
		Confidence: ConfidenceLow,
	}
}

// classifyByProtocol checks observed TCP/UDP service banners, open ports, and
// WAN web-entrypoint routing for high-confidence functional classification.
func classifyByProtocol(hp *probe.HostProfile, isWANWeb bool, vendor string) (Result, bool) {
	if isWANWeb {
		return Result{
			Category:   CategoryNetService,
			Role:       "WAN Web Entrypoint / Reverse Proxy",
			Vendor:     vendor,
			Confidence: ConfidenceHigh,
			Signals:    []string{"receives WAN HTTP/HTTPS port forward"},
		}, true
	}
	if hp == nil {
		return Result{}, false
	}

	titles := collectHTTPTitles(hp)
	titlesLower := strings.ToLower(titles)

	// Out-of-band server BMCs (IPMI port 623 or iKVM/iDRAC/iLO/OpenBMC web UI).
	if hp.HasPort(623) || containsAny(titlesLower, "ikvm", "asmb", "idrac", "ilo ", "openbmc", "ipmi") {
		var sigs []string
		if hp.HasPort(623) {
			sigs = append(sigs, "port 623 (IPMI)")
		}
		if titles != "" {
			sigs = append(sigs, fmt.Sprintf("HTTP title %q", titles))
		}
		return Result{
			Category:   CategoryBMC,
			Role:       "Out-of-Band BMC / IPMI",
			Vendor:     vendor,
			Confidence: ConfidenceHigh,
			Signals:    sigs,
		}, true
	}

	// DNS appliances (Pi-hole, AdGuard, or port 53 resolver).
	if hp.HasPort(53) || containsAny(titlesLower, "pi-hole", "adguard", "technitium") {
		return Result{
			Category:   CategoryNetService,
			Role:       "DNS Server",
			Vendor:     vendor,
			Confidence: ConfidenceHigh,
			Signals:    []string{"port 53 / DNS admin interface"},
		}, true
	}

	// Smart home hubs (Home Assistant :8123, OpenHAB, Hubitat).
	if hp.HasPort(8123) || containsAny(titlesLower, "home assistant", "openhab", "hubitat") {
		return Result{
			Category:   CategoryIoT,
			Role:       "Smart Home Hub",
			Vendor:     vendor,
			Confidence: ConfidenceHigh,
			Signals:    []string{"Home Assistant / smart-home hub interface"},
		}, true
	}

	// Compute servers, hypervisors, and NAS boxes.
	if hp.HasPort(8006) || hp.HasPort(445) || hp.HasPort(2049) || hp.HasPort(5900) ||
		containsAny(titlesLower, "truenas", "unraid", "proxmox", "synology", "diskstation", "qnap") {
		var sigs []string
		for _, p := range []int{445, 2049, 5900, 8006} {
			if hp.HasPort(p) {
				sigs = append(sigs, fmt.Sprintf("port %d", p))
			}
		}
		if len(sigs) == 0 {
			sigs = append(sigs, fmt.Sprintf("HTTP title %q", titles))
		}
		return Result{
			Category:   CategoryServer,
			Role:       "Server / NAS / Hypervisor",
			Vendor:     vendor,
			Confidence: ConfidenceHigh,
			Signals:    sigs,
		}, true
	}

	// Network & 3D printers (JetDirect 9100, IPP 631, Prusa/LaserJet titles).
	if hp.HasPort(9100) || hp.HasPort(631) || containsAny(titlesLower, "laserjet", "prusalink", "octoprint", "bambu") {
		role := "Network Printer"
		if containsAny(titlesLower, "prusa", "octoprint", "bambu") {
			role = "3D Printer"
		}
		return Result{
			Category:   CategoryPrinter,
			Role:       role,
			Vendor:     vendor,
			Confidence: ConfidenceHigh,
			Signals:    []string{"printer protocol / web panel"},
		}, true
	}

	// IP cameras (RTSP 554).
	if hp.HasPort(554) {
		return Result{
			Category:   CategoryCamera,
			Role:       "IP Camera / Stream",
			Vendor:     vendor,
			Confidence: ConfidenceHigh,
			Signals:    []string{"port 554 (RTSP)"},
		}, true
	}

	// Building automation / IoT control protocols.
	if hp.HasPort(502) || hp.HasPort(1883) || hp.HasPort(56747) ||
		containsAny(titlesLower, "tasmota", "shelly", "esphome") {
		return Result{
			Category:   CategoryIoT,
			Role:       "IoT / Building Control",
			Vendor:     vendor,
			Confidence: ConfidenceHigh,
			Signals:    []string{"IoT control protocol / embedded panel"},
		}, true
	}

	return Result{}, false
}

// resolveVendor picks the cleanest non-placeholder vendor name, preferring the
// full synced IEEE OUI database (which resolves 28-bit MA-M and 36-bit MA-S
// blocks) over UniFi's truncated 24-bit OUI string.
func resolveVendor(ouiRes oui.Result, unifiOUI string) string {
	if ouiRes.Vendor != "" {
		return ouiRes.Vendor
	}
	trimmed := strings.TrimSpace(unifiOUI)
	if trimmed == "" || strings.Contains(strings.ToLower(trimmed), "ieee registration authority") {
		return ""
	}
	return trimmed
}

// collectHTTPTitles joins all non-empty HTML titles collected across open web
// ports on hp.
func collectHTTPTitles(hp *probe.HostProfile) string {
	var titles []string
	for _, b := range hp.HTTP {
		if t := strings.TrimSpace(b.Title); t != "" {
			titles = append(titles, t)
		}
	}
	for _, svc := range hp.Services {
		if t := strings.TrimSpace(svc.Title); t != "" {
			titles = append(titles, t)
		}
	}
	return strings.Join(titles, " | ")
}

// containsAny reports whether s contains any of the provided lowercase substrings.
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
