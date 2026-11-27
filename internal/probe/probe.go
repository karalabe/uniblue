// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package probe performs gentle, bounded host fingerprinting across LAN
// clients so declarative checks can match cheap preconditions before sending
// targeted probes.
package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/unifi"
)

const (
	// maxHTTPFingerprintBytes limits how much of a landing page is read when
	// extracting HTML titles so slow or huge responses never stall a scan.
	maxHTTPFingerprintBytes = 64 * 1024

	// perPortPause inserts a brief breather between consecutive port dials on
	// the same host so fragile embedded TCP stacks (HVAC controllers, inverters,
	// older cameras) are never hit with a rapid burst of SYNs.
	perPortPause = 8 * time.Millisecond

	// maxPortDialTimeout caps the initial TCP connect check on a local LAN so
	// sleeping or firewalled hosts never stall a scan across 40+ ports.
	maxPortDialTimeout = 350 * time.Millisecond

	// maxConsecutiveSilentTimeouts stops dialing additional ports on a host that
	// has neither opened a single port nor returned a single TCP RST (e.g., a
	// sleeping phone or stealth-firewalled workstation silently dropping SYNs).
	maxConsecutiveSilentTimeouts = 8

	// vncMaxDisplayPort caps the adaptive sequential VNC display walk (5900..5919)
	// triggered only on hosts that already expose a VNC listener.
	vncMaxDisplayPort = 5919

	// vncWalkMaxConsecutiveMisses stops the adaptive VNC walk once this many
	// consecutive display ports are closed, catching gaps from stopped VMs while
	// keeping hypervisor probing fast.
	vncWalkMaxConsecutiveMisses = 2
)

// titleRegex extracts the text inside an HTML <title>...</title> tag.
var titleRegex = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// HTTPBanner summarizes the lightweight metadata gathered from a single
// read-only GET / request on an open HTTP(S) port.
type HTTPBanner struct {
	// Scheme is "http" or "https".
	Scheme string `json:"scheme"`

	// StatusCode is the HTTP status returned for GET /.
	StatusCode int `json:"status_code"`

	// Server is the raw HTTP Server response header, if present.
	Server string `json:"server,omitempty"`

	// PoweredBy is the raw X-Powered-By response header, if present.
	PoweredBy string `json:"powered_by,omitempty"`

	// Title is the trimmed HTML <title> text extracted from the landing page.
	Title string `json:"title,omitempty"`

	// WWWAuthenticate records the WWW-Authenticate header when the device asks
	// for HTTP authentication.
	WWWAuthenticate string `json:"www_authenticate,omitempty"`

	// TLSSubjectCN is the leaf TLS certificate Common Name observed on HTTPS ports.
	TLSSubjectCN string `json:"tls_subject_cn,omitempty"`

	// TLSSubjectOrg is the leaf TLS certificate Organization observed on HTTPS ports.
	TLSSubjectOrg string `json:"tls_subject_org,omitempty"`

	// TLSVersion records the negotiated TLS protocol version (e.g., "TLS 1.3").
	TLSVersion string `json:"tls_version,omitempty"`

	// TLSNotAfter records the leaf certificate's expiration timestamp, if present.
	TLSNotAfter *time.Time `json:"tls_not_after,omitempty"`

	// TLSExpired reports whether the leaf TLS certificate is past its NotAfter date.
	TLSExpired bool `json:"tls_expired,omitempty"`

	// TLSVerified reports that the scanner verified the certificate chain and the endpoint address.
	TLSVerified bool `json:"tls_verified,omitempty"`

	// TLSSelfSigned reports whether the leaf certificate is cryptographically self-signed.
	TLSSelfSigned bool `json:"tls_self_signed,omitempty"`
}

// Service summarizes one application-layer service identified on an open port
// by UniBlue's embedded Nerva fingerprinter (covering 170+ TCP/UDP protocols).
type Service struct {
	// Port is the open TCP or UDP port where the service responded.
	Port int `json:"port"`

	// Transport is the L4 transport ("tcp", "udp", or "sctp"), defaulting to "tcp".
	Transport string `json:"transport,omitempty"`

	// Protocol is the canonical protocol name detected by Nerva (e.g., "ssh",
	// "smb", "http", "https", "nfs", "dns", "vnc").
	Protocol string `json:"protocol"`

	// State records how this service was established ("observed-protocol",
	// "advertised-service", "owner-declared", "candidate-port", "tls-unknown-app",
	// or "unknown").
	State string `json:"state,omitempty"`

	// AddressFamily records "ipv4" or "ipv6".
	AddressFamily string `json:"address_family,omitempty"`

	// Observer records the observer network or vantage point, when known.
	Observer string `json:"observer,omitempty"`

	// ObservedAt records when this service observation was recorded.
	ObservedAt *time.Time `json:"observed_at,omitempty"`

	// TLS reports whether the service spoke TLS on this port.
	TLS bool `json:"tls,omitempty"`

	// Version is the software version string extracted from the protocol banner
	// or handshake, when advertised (e.g., "nginx/1.24.0", "OpenSSH_9.6p1").
	Version string `json:"version,omitempty"`

	// Title holds an extracted web page title when Protocol is HTTP/HTTPS.
	Title string `json:"title,omitempty"`

	// Banner holds raw service identification text (such as an SSH greeting).
	Banner string `json:"banner,omitempty"`

	// AnonymousAccess indicates Nerva confirmed unauthenticated access to the service.
	AnonymousAccess bool `json:"anonymous_access,omitempty"`

	// CPEs lists any normalized CPE 2.3 identifiers reported by the service plugin.
	CPEs []string `json:"cpes,omitempty"`

	// Findings holds high-signal misconfigurations detected by Nerva after
	// filtering out noisy LAN HTTP header lint warnings.
	Findings []ServiceFinding `json:"findings,omitempty"`
}

// ServiceFinding represents one high-signal protocol misconfiguration surfaced
// by Nerva (such as legacy protocol versions, anonymous access, or an expired TLS cert).
type ServiceFinding struct {
	// ID is Nerva's canonical finding identifier (e.g., "smb-v1-enabled").
	ID string `json:"id"`

	// Severity is the normalized lowercase severity string ("low", "medium", "high", "critical").
	Severity string `json:"severity"`

	// Title is an optional short summary provided by the plugin.
	Title string `json:"title,omitempty"`

	// Description explains the misconfiguration when provided by the plugin.
	Description string `json:"description,omitempty"`

	// Evidence records observable protocol-level proof without leaking secrets.
	Evidence string `json:"evidence,omitempty"`
}

// HostProfile holds everything learned about a single LAN host during the
// lightweight fingerprinting pass.
type HostProfile struct {
	// Client is the UniFi inventory record for this host.
	Client unifi.Client `json:"client"`

	// ProbeIP is the concrete probe-eligible IPv4 or IPv6 address chosen by
	// SelectProbeIP for active probing and checks. When empty (e.g. profiles
	// constructed directly without Fingerprinter), EffectiveProbeIP falls back
	// to SelectProbeIP(Client, nil) so public internet addresses are never dialed.
	ProbeIP string `json:"probe_ip,omitempty"`

	// OpenPorts lists the TCP ports from the scan list that accepted a connection.
	OpenPorts []int `json:"open_ports,omitempty"`

	// HTTP maps open HTTP/HTTPS port numbers to their observed landing-page banner.
	HTTP map[int]HTTPBanner `json:"http,omitempty"`

	// SMB holds server capabilities from one read-only negotiation on TCP 445.
	SMB *SMBInfo `json:"smb,omitempty"`

	// SSH holds the host key, algorithms, and observed authentication posture.
	SSH *SSHInfo `json:"ssh,omitempty"`

	// SSHBanner stores the passive greeting line advertised on port 22 (e.g.,
	// "SSH-2.0-OpenSSH_9.6p1"), read without attempting authentication.
	SSHBanner string `json:"ssh_banner,omitempty"`

	// Services holds structured application-layer services identified on open
	// ports by Nerva's embedded protocol fingerprinters.
	Services []Service `json:"services,omitempty"`

	// MDNSServices lists DNS-SD services advertised by this host on UDP 5353.
	MDNSServices []MDNSService `json:"mdns_services,omitempty"`

	// UPnPDevices lists SSDP/UPnP device descriptions advertised by this host.
	UPnPDevices []UPnPDevice `json:"upnp_devices,omitempty"`

	// WSDiscovery lists WS-Discovery (ONVIF / WSD) announcements from this host.
	WSDiscovery []WSDiscoveryRecord `json:"ws_discovery,omitempty"`

	// Children lists enrolled downstream devices managed by this host when it
	// acts as an NVR, Zigbee/Z-Wave/Matter coordinator, bridge, or BLE proxy.
	Children []ChildDevice `json:"children,omitempty"`

	// OutboundDependencies records observed or configured external internet
	// services used by this host, kept strictly separate from hosted LAN services.
	OutboundDependencies []OutboundDependency `json:"outbound_dependencies,omitempty"`

	// RawPrintPorts lists protected raw print and serial sink ports, including
	// ports learned from discovery before a TCP connection was attempted.
	RawPrintPorts []int `json:"raw_print_ports,omitempty"`

	// ConnectOnlyPorts lists open sink ports where the scanner connected and
	// skipped all application probes.
	ConnectOnlyPorts []int `json:"connect_only_ports,omitempty"`

	// ScannedAt records when fingerprinting finished for this host.
	ScannedAt time.Time `json:"scanned_at"`
}

// cgnatPrefix matches RFC 6598 Carrier-Grade NAT space (100.64.0.0/10),
// commonly used for Tailscale and private lab VLANs.
var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// EffectiveProbeIP returns the validated probe target address for active checks
// on this host: the explicitly authorized ProbeIP selected during fingerprinting,
// or SelectProbeIP(Client, nil) when ProbeIP was not populated. Public internet
// addresses are never returned unless explicitly authorized via SetAllowedSubnets.
func (h HostProfile) EffectiveProbeIP() string {
	if ip := strings.TrimSpace(h.ProbeIP); ip != "" {
		return ip
	}
	return SelectProbeIP(h.Client, nil)
}

// IsRawPrintPort reports whether port on this host is protected by the raw
// print or raw serial sink zero-byte guard. Self-announced sinks are always
// honored. Configured reflectors can identify JetDirect and serial bridge ports.
func (h HostProfile) IsRawPrintPort(port int) bool {
	if port == 9100 || port == 515 {
		return true
	}
	for _, p := range h.RawPrintPorts {
		if p == port {
			return true
		}
	}
	for _, md := range h.MDNSServices {
		if md.Withdrawn || md.Port != port || !isMDNSZeroByteSink(md.Type) {
			continue
		}
		authoritative := !md.Reflected && hostOwnsIP(h.Client, md.ResponderIP)
		if shouldProtectMDNSSinkPort(md.Type, port, authoritative, md.Reflected && md.TrustedReflector) {
			return true
		}
	}
	return false
}

func (h *HostProfile) recordOpenPort(port int) bool {
	h.OpenPorts = append(h.OpenPorts, port)
	if !h.IsRawPrintPort(port) {
		return false
	}
	if !slices.Contains(h.RawPrintPorts, port) {
		h.RawPrintPorts = append(h.RawPrintPorts, port)
		sort.Ints(h.RawPrintPorts)
	}
	h.ConnectOnlyPorts = append(h.ConnectOnlyPorts, port)
	return true
}

func hostOwnsIP(cl unifi.Client, candidate string) bool {
	want := canonicalIPKey(candidate)
	if want == "" {
		return false
	}
	for _, ip := range cl.AllIPs() {
		if canonicalIPKey(ip) == want {
			return true
		}
	}
	return false
}

// Clone returns a deep copy of HostProfile so concurrent enrichment and live
// publishing never mutate or race on shared slices or maps.
func (h HostProfile) Clone() HostProfile {
	cp := h
	if h.SMB != nil {
		info := *h.SMB
		cp.SMB = &info
	}
	if h.SSH != nil {
		info := *h.SSH
		info.AuthMethods = slices.Clone(info.AuthMethods)
		cp.SSH = &info
	}
	cp.ConnectOnlyPorts = slices.Clone(h.ConnectOnlyPorts)
	if len(h.Client.IPv6) > 0 {
		cp.Client.IPv6 = append([]string(nil), h.Client.IPv6...)
	}
	if len(h.OpenPorts) > 0 {
		cp.OpenPorts = append([]int(nil), h.OpenPorts...)
	}
	if len(h.RawPrintPorts) > 0 {
		cp.RawPrintPorts = append([]int(nil), h.RawPrintPorts...)
	}
	if len(h.HTTP) > 0 {
		cp.HTTP = make(map[int]HTTPBanner, len(h.HTTP))
		for k, v := range h.HTTP {
			cp.HTTP[k] = v
		}
	}
	if len(h.Services) > 0 {
		cp.Services = make([]Service, len(h.Services))
		for i, s := range h.Services {
			if len(s.CPEs) > 0 {
				s.CPEs = append([]string(nil), s.CPEs...)
			}
			if len(s.Findings) > 0 {
				s.Findings = append([]ServiceFinding(nil), s.Findings...)
			}
			cp.Services[i] = s
		}
	}
	if len(h.MDNSServices) > 0 {
		cp.MDNSServices = make([]MDNSService, len(h.MDNSServices))
		for i, m := range h.MDNSServices {
			if len(m.TXT) > 0 {
				m.TXT = append([]string(nil), m.TXT...)
			}
			if len(m.TargetIPs) > 0 {
				m.TargetIPs = append([]string(nil), m.TargetIPs...)
			}
			cp.MDNSServices[i] = m
		}
	}
	if len(h.UPnPDevices) > 0 {
		cp.UPnPDevices = append([]UPnPDevice(nil), h.UPnPDevices...)
	}
	if len(h.WSDiscovery) > 0 {
		cp.WSDiscovery = make([]WSDiscoveryRecord, len(h.WSDiscovery))
		for i, w := range h.WSDiscovery {
			if len(w.Types) > 0 {
				w.Types = append([]string(nil), w.Types...)
			}
			if len(w.Scopes) > 0 {
				w.Scopes = append([]string(nil), w.Scopes...)
			}
			if len(w.Ports) > 0 {
				w.Ports = append([]int(nil), w.Ports...)
			}
			cp.WSDiscovery[i] = w
		}
	}
	if len(h.Children) > 0 {
		cp.Children = append([]ChildDevice(nil), h.Children...)
	}
	if len(h.OutboundDependencies) > 0 {
		cp.OutboundDependencies = append([]OutboundDependency(nil), h.OutboundDependencies...)
	}
	return cp
}

// HasPort reports whether port was observed open on the host.
func (h HostProfile) HasPort(port int) bool {
	for _, p := range h.OpenPorts {
		if p == port {
			return true
		}
	}
	return false
}

// Fingerprinter gently inspects a slice of LAN clients using a fixed-size
// channel worker pool.
type Fingerprinter struct {
	infrastructure map[string]bool
	// ports is the curated list of TCP ports checked on each host.
	ports []int

	// concurrency controls how many distinct hosts are probed simultaneously.
	concurrency int

	// timeout bounds each individual TCP dial and HTTP banner request.
	timeout time.Duration

	// excludeIPs contains IP addresses skipped without sending any packets.
	excludeIPs map[string]struct{}

	// allowedSubnets lists explicitly configured site prefixes (in addition to
	// RFC1918/ULA, CGNAT, link-local, and loopback) that are allowed to be probed.
	allowedSubnets []netip.Prefix

	// trustedReflectors lists local gateway/router IP addresses authorized to
	// reflect cross-VLAN mDNS advertisements.
	trustedReflectors []string

	// hostPortHints maps specific client IPs to extra TCP ports discovered from
	// UniFi port forwards, firewall policies, or per-host LAN discovery.
	hostPortHints map[string][]int

	// discovery holds optional LAN-wide multicast observations (mDNS, SSDP,
	// WS-Discovery) collected once per FingerprintAll sweep.
	discovery *LANDiscovery

	// skipDiscovery disables multicast discovery (used by isolated unit tests
	// or when cached discovery is injected via SetCachedDiscovery).
	skipDiscovery bool

	// httpClient is configured with redirects disabled and self-signed TLS
	// accepted so local LAN devices can be fingerprinted without leaking requests
	// to external hosts.
	httpClient *http.Client

	// onProgress receives optional per-host progress updates during FingerprintAll.
	onProgress func(phase string, done, total int, host string)

	// sshKeyAudit holds optional opt-in SSH PK_OK audit settings, loaded keys,
	// prior host-key fingerprints (to refuse auditing on changed keys), and a
	// per-fingerprint result cache so repeated watch/serve scans replay findings
	// without re-probing unchanged hosts.
	sshKeyAudit     *config.SSHKeyAuditConfig
	sshAuditKeys    []SSHPublicKey
	prevSSHHostKeys map[string]string
	auditedSSHHosts *SSHKeyAuditCache
	// DisableSSHAuthProbe disables the credential-free SSH method query.
	DisableSSHAuthProbe bool
}

// SetPreviousSSHHostKeys provides saved host-key fingerprints from the prior
// scan so opt-in SSH key audits refuse to send configured keys to any endpoint
// whose host key changed.
func (f *Fingerprinter) SetPreviousSSHHostKeys(prev map[string]string) {
	f.prevSSHHostKeys = prev
}

// SetAuditedSSHHostKeys provides a caller-owned cache recording SSH key audit
// outcomes and retry cooldowns by host identity, listener IP, and port.
func (f *Fingerprinter) SetAuditedSSHHostKeys(audited *SSHKeyAuditCache) {
	if audited != nil {
		f.auditedSSHHosts = audited
	}
}

// SetSSHKeyAudit enables the strictly opt-in Fail2ban-safe SSH public-key
// reachability check when the configuration enables it. It returns an
// error if any configured file contains a private key or fails to parse.
func (f *Fingerprinter) SetSSHKeyAudit(cfg *config.SSHKeyAuditConfig) error {
	if !cfg.Active() {
		f.sshKeyAudit = nil
		f.sshAuditKeys = nil
		return nil
	}
	keys, err := LoadSSHPublicKeys(cfg.PublicKeyFiles)
	if err != nil {
		return err
	}
	f.sshKeyAudit = cfg
	f.sshAuditKeys = keys
	return nil
}

func (f *Fingerprinter) matchesSSHKeyAuditTarget(h HostProfile) bool {
	if !f.sshKeyAudit.Active() || len(f.sshAuditKeys) == 0 {
		return false
	}
	if len(f.sshKeyAudit.TargetHosts) == 0 {
		return true
	}
	mac := config.CanonicalMAC(h.Client.MAC)
	for _, raw := range f.sshKeyAudit.TargetHosts {
		t := strings.TrimSpace(raw)
		if t == "" {
			continue
		}
		if t == h.ProbeIP || strings.EqualFold(t, h.Client.Hostname) || strings.EqualFold(t, h.Client.Name) || (mac != "" && config.CanonicalMAC(t) == mac) {
			return true
		}
	}
	return false
}

// SetInfrastructure identifies adopted devices whose SSH settings come from the controller.
func (f *Fingerprinter) SetInfrastructure(devices []unifi.Device) {
	f.infrastructure = make(map[string]bool, len(devices)*2)
	for _, d := range devices {
		if d.MAC != "" {
			f.infrastructure[config.CanonicalMAC(d.MAC)] = true
		}
		if d.IP != "" {
			f.infrastructure[d.IP] = true
		}
	}
}

// isInfrastructure also matches the probe address when the client record has no MAC.
func (f *Fingerprinter) isInfrastructure(h HostProfile) bool {
	return f.infrastructure[config.CanonicalMAC(h.Client.MAC)] || f.infrastructure[h.ProbeIP]
}

// SetHostPortHints attaches optional per-host TCP port hints (such as ports
// derived from UniFi port forwards or firewall policies) that are dialed ahead
// of the base scan port list when fingerprinting matching hosts.
func (f *Fingerprinter) SetHostPortHints(hints map[string][]int) {
	f.hostPortHints = hints
}

// SetAllowedSubnets registers explicitly configured site subnets that may be
// probed in addition to private (RFC1918/ULA), CGNAT (100.64.0.0/10),
// link-local unicast, and loopback addresses.
func (f *Fingerprinter) SetAllowedSubnets(prefixes []netip.Prefix) {
	f.allowedSubnets = append([]netip.Prefix(nil), prefixes...)
}

// SetTrustedReflectors registers local gateway/router IP addresses authorized
// to reflect cross-VLAN mDNS advertisements during passive discovery.
func (f *Fingerprinter) SetTrustedReflectors(ips []string) {
	f.trustedReflectors = append([]string(nil), ips...)
}

// SetCachedDiscovery injects a previously collected LANDiscovery snapshot so
// single-host rescans can reuse cached discovery without sending a new
// LAN-wide multicast sweep.
func (f *Fingerprinter) SetCachedDiscovery(d *LANDiscovery) {
	f.discovery = d
	if d != nil {
		f.skipDiscovery = true
	}
}

// Discovery returns the LANDiscovery snapshot collected or injected for this
// Fingerprinter so callers can cache and reuse it across rescans.
func (f *Fingerprinter) Discovery() *LANDiscovery {
	return f.discovery
}

// isAllowedProbeIPWithSubnets enforces that active probing and discovery
// fetches only target private/local LAN ranges or explicitly configured site
// subnets, never arbitrary public internet addresses.
func isAllowedProbeIPWithSubnets(rawIP string, allowedSubnets []netip.Prefix) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(rawIP))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLoopback() || cgnatPrefix.Contains(addr) {
		return true
	}
	for _, pfx := range allowedSubnets {
		if pfx.Contains(addr) {
			return true
		}
	}
	return false
}

// isAllowedProbeIP enforces that active probing only targets private/local LAN
// ranges or explicitly configured site subnets, never arbitrary public IPs.
func (f *Fingerprinter) isAllowedProbeIP(rawIP string) bool {
	return isAllowedProbeIPWithSubnets(rawIP, f.allowedSubnets)
}

// SelectProbeIP picks the preferred probe-eligible IP address for cl given
// allowedSubnets: first an allowed non-link-local IPv4, then an allowed
// non-link-local IPv6, then an allowed link-local IPv4, then an allowed
// link-local IPv6. Returns "" when cl has no probe-eligible address.
func SelectProbeIP(cl unifi.Client, allowedSubnets []netip.Prefix) string {
	var v4LL, v6Global, v6LL string
	for _, raw := range cl.AllIPs() {
		ip := strings.TrimSpace(raw)
		if !isAllowedProbeIPWithSubnets(ip, allowedSubnets) {
			continue
		}
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		if addr.Is4() {
			if !addr.IsLinkLocalUnicast() {
				return ip
			}
			if v4LL == "" {
				v4LL = ip
			}
			continue
		}
		if !addr.IsLinkLocalUnicast() {
			if v6Global == "" {
				v6Global = ip
			}
			continue
		}
		if v6LL == "" {
			v6LL = ip
		}
	}
	if v6Global != "" {
		return v6Global
	}
	if v4LL != "" {
		return v4LL
	}
	return v6LL
}

func (f *Fingerprinter) selectAllowedProbeIP(cl unifi.Client) string {
	return SelectProbeIP(cl, f.allowedSubnets)
}

// SetProgressFunc registers an optional callback invoked on the collector
// goroutine as discovery, per-host port probing, and protocol fingerprinting advance.
func (f *Fingerprinter) SetProgressFunc(fn func(phase string, done, total int, host string)) {
	f.onProgress = fn
}

func (f *Fingerprinter) reportProgress(phase string, done, total int, host string) {
	if f.onProgress != nil {
		f.onProgress(phase, done, total, host)
	}
}

// NewFingerprinter creates a Fingerprinter with safe defaults for zero-valued
// parameters.
func NewFingerprinter(ports []int, concurrency int, timeout time.Duration, excludeIPs map[string]struct{}) *Fingerprinter {
	if concurrency <= 0 {
		concurrency = 8
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	sortedPorts := append([]int(nil), ports...)
	sort.Ints(sortedPorts)

	return &Fingerprinter{
		ports:           sortedPorts,
		auditedSSHHosts: new(SSHKeyAuditCache),
		concurrency:     concurrency,
		timeout:         timeout,
		excludeIPs:      excludeIPs,
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
				DisableKeepAlives: true,
				IdleConnTimeout:   5 * time.Second,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, //nolint:gosec // LAN IoT devices routinely use self-signed certificates
				},
			},
			// Never follow redirects during fingerprinting: a device redirecting
			// to an external domain must never cause UniBlue to contact WAN hosts.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// FingerprintAll profiles every eligible client concurrently using a bounded
// channel worker pool and returns the collected HostProfiles sorted by IP.
func (f *Fingerprinter) FingerprintAll(ctx context.Context, clients []unifi.Client) []HostProfile {
	defer f.httpClient.CloseIdleConnections()

	// Filter down to clients with a valid, non-excluded, probe-eligible LAN IP.
	targets := make([]unifi.Client, 0, len(clients))
	for _, cl := range clients {
		if f.selectAllowedProbeIP(cl) == "" {
			continue
		}
		excluded := false
		for _, ip := range cl.AllIPs() {
			if isExcludedIP(ip, f.excludeIPs) {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}
		targets = append(targets, cl)
	}
	if len(targets) == 0 {
		return nil
	}

	workers := f.concurrency
	if len(targets) < workers {
		workers = len(targets)
	}

	// Run one bounded LAN multicast discovery sweep (mDNS, SSDP/UPnP, WS-Discovery)
	// when profiling non-loopback LAN hosts so per-host port hints and passive
	// service metadata enrich every matching HostProfile with zero blind dials.
	if f.discovery == nil && !f.skipDiscovery && f.hasNonLoopbackTarget(targets) {
		f.reportProgress("discovery", 0, len(targets), "")
		f.discovery = discoverLANWithOptions(ctx, f.httpClient, f.excludeIPs, f.allowedSubnets, f.trustedReflectors)
	}
	return f.collectProfiles(ctx, targets, workers)
}

func (f *Fingerprinter) hasNonLoopbackTarget(targets []unifi.Client) bool {
	for _, cl := range targets {
		ip := net.ParseIP(f.selectAllowedProbeIP(cl))
		if ip != nil && !ip.IsLoopback() {
			return true
		}
	}
	return false
}

// collectProfiles runs the channel pipeline cleanly so the exact number of
// dispatched jobs is always synchronized with result collection.
func (f *Fingerprinter) collectProfiles(ctx context.Context, targets []unifi.Client, workers int) []HostProfile {
	jobs := make(chan unifi.Client)
	results := make(chan HostProfile, workers)
	done := make(chan struct{}, workers)

	for range workers {
		go func() {
			defer func() { done <- struct{}{} }()
			for cl := range jobs {
				results <- f.FingerprintHost(ctx, cl)
			}
		}()
	}

	// Close results once all workers have exited so the collector simply ranges
	// over results until exhausted.
	go func() {
		for range workers {
			<-done
		}
		close(results)
	}()

	// Feed hosts until all are sent or the caller cancels the context.
	go func() {
		defer close(jobs)
		for _, cl := range targets {
			select {
			case <-ctx.Done():
				return
			case jobs <- cl:
			}
		}
	}()

	f.reportProgress("probing", 0, len(targets), "")
	profiles := make([]HostProfile, 0, len(targets))
	for p := range results {
		profiles = append(profiles, p)
		f.reportProgress("probing", len(profiles), len(targets), p.Client.DisplayName())
	}
	sort.Slice(profiles, func(i, j int) bool {
		return profiles[i].Client.PrimaryIP() < profiles[j].Client.PrimaryIP()
	})

	// Enrich every discovered open port using Nerva's FastMode protocol
	// fingerprinters (170+ protocols, MaxHostConn=1 for IoT safety).
	f.enrichWithNerva(ctx, profiles)
	CompareSSHHostKeys(profiles, nil)
	return profiles
}

// FingerprintHost probes a single client's curated ports sequentially (to stay
// gentle on embedded stacks) and grabs lightweight HTTP banners for web ports.
func (f *Fingerprinter) FingerprintHost(ctx context.Context, cl unifi.Client) HostProfile {
	targetIP := f.selectAllowedProbeIP(cl)
	allIPs := cl.AllIPs()
	profile := HostProfile{
		Client:    cl,
		ProbeIP:   targetIP,
		HTTP:      make(map[int]HTTPBanner),
		ScannedAt: time.Now().UTC(),
	}
	if f.discovery != nil {
		rawSeen := make(map[int]struct{})
		mdnsIdx := make(map[string]int)
		upnpSeen := make(map[string]struct{})
		wsdSeen := make(map[string]struct{})
		for _, ip := range allIPs {
			for _, svc := range f.discovery.MDNS[ip] {
				key := strings.ToLower(fmt.Sprintf("%s|%s|%d|%s|%s", svc.ObserverVLAN, svc.Type, svc.Port, svc.Transport, svc.Instance))
				if idx, dup := mdnsIdx[key]; dup {
					// Prefer an authoritative (non-reflected) observation when
					// merging dual-stack addresses for the same service.
					if preferMDNSService(svc, profile.MDNSServices[idx]) {
						profile.MDNSServices[idx] = svc
					}
					continue
				}
				mdnsIdx[key] = len(profile.MDNSServices)
				profile.MDNSServices = append(profile.MDNSServices, svc)
			}
			for _, dev := range f.discovery.UPnP[ip] {
				key := strings.ToLower(fmt.Sprintf("%s|%s|%d|%s|%s|%s|%s", dev.ObserverVLAN, dev.ST, dev.Port, dev.DeviceType, dev.Manufacturer, dev.ModelName, dev.Server))
				if _, dup := upnpSeen[key]; dup {
					continue
				}
				upnpSeen[key] = struct{}{}
				profile.UPnPDevices = append(profile.UPnPDevices, dev)
			}
			for _, rec := range f.discovery.WSDiscovery[ip] {
				key := strings.ToLower(fmt.Sprintf("%s|%s|%s|%v", rec.ObserverVLAN, strings.Join(rec.Types, ","), strings.Join(rec.Scopes, ","), rec.Ports))
				if _, dup := wsdSeen[key]; dup {
					continue
				}
				wsdSeen[key] = struct{}{}
				profile.WSDiscovery = append(profile.WSDiscovery, rec)
			}
			for rp := range f.discovery.RawPrintIPs[ip] {
				if _, dup := rawSeen[rp]; !dup {
					rawSeen[rp] = struct{}{}
					profile.RawPrintPorts = append(profile.RawPrintPorts, rp)
				}
			}
		}
		sort.Ints(profile.RawPrintPorts)
	}
	if targetIP == "" || !f.isAllowedProbeIP(targetIP) {
		return profile
	}

	dialTimeout := f.timeout
	if dialTimeout > maxPortDialTimeout {
		dialTimeout = maxPortDialTimeout
	}
	dialer := net.Dialer{Timeout: dialTimeout}

	priorityPorts, baselinePorts := f.splitPortsForHost(allIPs...)
	priorityCount := len(priorityPorts)
	ports := make([]int, 0, priorityCount+len(baselinePorts))
	ports = append(ports, priorityPorts...)
	ports = append(ports, baselinePorts...)

	consecutiveTimeouts := 0
	for i, port := range ports {
		if ctx.Err() != nil {
			break
		}
		// Pause briefly between ports on the same host to avoid flooding tiny
		// IoT TCP state tables.
		if i > 0 {
			timer := time.NewTimer(perPortPause)
			select {
			case <-ctx.Done():
				timer.Stop()
				return profile
			case <-timer.C:
			}
		}

		addr := net.JoinHostPort(targetIP, strconv.Itoa(port))
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				// Apply the silent-host cutoff only to baseline ports so
				// Windows/macOS stealth firewalls dropping SYNs still have all
				// hinted, forwarded, and discovered priority ports checked.
				if i >= priorityCount {
					consecutiveTimeouts++
					if len(profile.OpenPorts) == 0 && consecutiveTimeouts >= maxConsecutiveSilentTimeouts {
						break
					}
				}
			} else {
				// Received an active TCP RST / ECONNREFUSED: host is awake and reachable.
				consecutiveTimeouts = 0
			}
			continue
		}
		consecutiveTimeouts = 0

		rawPrint := profile.recordOpenPort(port)
		sshPort := profile.sshPort(port)

		if !rawPrint {
			switch {
			case sshPort:
				if !f.isInfrastructure(profile) {
					if obs := observeSSH(conn, port, f.timeout); obs != nil {
						if profile.SSH == nil {
							profile.SSH = obs
							profile.SSHBanner = obs.Banner
						}
						svc := Service{Port: port, Transport: "tcp", Protocol: "ssh", State: ServiceStateObservedProtocol, AddressFamily: ipFamilyOf(targetIP), Banner: obs.Banner}
						if len(obs.WeakKex) > 0 {
							svc.Findings = append(svc.Findings, ServiceFinding{ID: "ssh-weak-kex", Severity: "medium", Evidence: "Weak SSH key exchange offered: " + strings.Join(obs.WeakKex, ", ")})
						}
						if len(obs.WeakCiphers) > 0 {
							svc.Findings = append(svc.Findings, ServiceFinding{ID: "ssh-weak-cipher", Severity: "medium", Evidence: "Weak SSH cipher offered: " + strings.Join(obs.WeakCiphers, ", ")})
						}
						if len(obs.WeakMACs) > 0 {
							svc.Findings = append(svc.Findings, ServiceFinding{ID: "ssh-weak-mac", Severity: "low", Evidence: "Weak SSH MAC offered: " + strings.Join(obs.WeakMACs, ", ")})
						}
						profile.Services = append(profile.Services, svc)
					}
				}
			case port == 445:
				profile.SMB = negotiateSMB(conn, f.timeout)
				// Send one read-only SMBv1 NEGOTIATE on a fresh connection to retain
				// SMBv1 detection without ever sending SESSION_SETUP.
				v1, v1SignEn, v1SignReq := false, false, false
				if c1, err := dialer.DialContext(ctx, "tcp", addr); err == nil {
					v1, v1SignEn, v1SignReq = negotiateSMBv1(c1, f.timeout)
					_ = c1.Close()
				}
				if v1 {
					if profile.SMB == nil {
						profile.SMB = &SMBInfo{Dialect: "1.0", SigningEnabled: v1SignEn, SigningRequired: v1SignReq}
					}
					profile.SMB.SMBv1Enabled = true
				}
				if profile.SMB != nil {
					service := Service{Port: port, Transport: "tcp", Protocol: "smb", State: ServiceStateObservedProtocol, AddressFamily: ipFamilyOf(targetIP)}
					if profile.SMB.SMBv1Enabled {
						service.Findings = append(service.Findings, ServiceFinding{ID: "smb-v1-enabled", Severity: "high", Evidence: "The SMB server accepted legacy SMBv1 (NT LM 0.12) during protocol negotiation."})
					}
					if !profile.SMB.SigningRequired {
						service.Findings = append(service.Findings, ServiceFinding{ID: "smb-signing-not-required", Severity: "medium", Evidence: "The SMB server did not require signing during negotiation."})
					}
					profile.Services = append(profile.Services, service)
				}
			}
		}
		_ = conn.Close()

		// Hard raw-printer zero-byte safety guard: never send HTTP or other
		// application bytes to a raw print sink even if it overlaps a web port.
		if rawPrint || sshPort || port == 445 {
			continue
		}

		// For well-known HTTP/HTTPS ports, grab a single read-only banner so
		// HTTP checks and CVE fingerprinters can match headers, titles, and TLS
		// certificate metadata cheaply.
		if scheme, ok := httpSchemeForPort(port); ok {
			if banner, ok := f.fetchHTTPBanner(ctx, scheme, targetIP, port); ok {
				profile.HTTP[port] = banner
			}
		}
	}

	// Hypervisors (QEMU/KVM, Proxmox, libvirt) assign VNC displays sequentially
	// starting at 5900 (:0, :1, :2...). When a host already exposes a VNC port,
	// adaptively walk upward to discover additional VM displays without sending
	// extra probes to hosts that do not speak VNC.
	if profile.HasPort(5900) || profile.HasPort(5901) {
		f.walkVNCDisplays(ctx, dialer, targetIP, ports, &profile)
	}

	f.auditSSH(ctx, &profile)

	sort.Ints(profile.OpenPorts)
	return profile
}

func isRawPrintSinkPortAny(port int, disc *LANDiscovery, ips []string) bool {
	if isRawPrintSinkPort(port, disc, "") {
		return true
	}
	for _, ip := range ips {
		if isRawPrintSinkPort(port, disc, ip) {
			return true
		}
	}
	return false
}

// splitPortsForHost separates priority ports (UniFi port-forward/firewall hints
// and per-host mDNS/SSDP/WS-Discovery ports) from the baseline scan port list.
// Priority ports are dialed first and exempt from the silent-host timeout cutoff.
func (f *Fingerprinter) splitPortsForHost(ips ...string) (priority, baseline []int) {
	seen := make(map[int]struct{}, len(f.ports)+16)
	addInto := func(dst *[]int, list []int) {
		for _, p := range list {
			if p < 1 || p > 65535 {
				continue
			}
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			*dst = append(*dst, p)
		}
	}
	for _, ip := range ips {
		if ip == "" {
			continue
		}
		addInto(&priority, f.hostPortHints[ip])
		if f.discovery != nil {
			addInto(&priority, f.discovery.PortsByIP[ip])
		}
	}
	sort.Ints(priority)
	addInto(&baseline, f.ports)
	sort.Ints(baseline)
	return priority, baseline
}

// portsForHost returns the deduplicated list of TCP ports to probe on a host,
// with hinted and discovered priority ports first followed by baseline ports.
func (f *Fingerprinter) portsForHost(ips ...string) []int {
	priority, baseline := f.splitPortsForHost(ips...)
	out := make([]int, 0, len(priority)+len(baseline))
	out = append(out, priority...)
	out = append(out, baseline...)
	return out
}

// walkVNCDisplays gently probes sequential RFB/VNC display ports (5901..5919)
// on a host that already responded on a base VNC port, stopping once
// vncWalkMaxConsecutiveMisses consecutive ports are closed.
func (f *Fingerprinter) walkVNCDisplays(ctx context.Context, dialer net.Dialer, ip string, alreadyProbed []int, profile *HostProfile) {
	probed := make(map[int]struct{}, len(alreadyProbed))
	for _, p := range alreadyProbed {
		probed[p] = struct{}{}
	}

	misses := 0
	for port := 5901; port <= vncMaxDisplayPort; port++ {
		if ctx.Err() != nil {
			return
		}
		if _, already := probed[port]; already {
			if profile.HasPort(port) {
				misses = 0
			} else {
				misses++
			}
			continue
		}

		timer := time.NewTimer(perPortPause)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
		if err != nil {
			misses++
			if misses >= vncWalkMaxConsecutiveMisses {
				return
			}
			continue
		}
		_ = conn.Close()
		profile.recordOpenPort(port)
		misses = 0
	}
}

// fetchHTTPBanner performs one bounded GET / request against a local host and
// extracts its status code, Server/X-Powered-By headers, HTML title, and peer
// TLS certificate subject metadata.
func (f *Fingerprinter) fetchHTTPBanner(ctx context.Context, scheme, ip string, port int) (HTTPBanner, bool) {
	targetURL := fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(ip, strconv.Itoa(port)))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return HTTPBanner{}, false
	}
	req.Header.Set("User-Agent", "UniBlue-Fingerprinter/0.1")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return HTTPBanner{}, false
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxHTTPFingerprintBytes))
	banner := HTTPBanner{
		Scheme:          scheme,
		StatusCode:      resp.StatusCode,
		Server:          strings.TrimSpace(resp.Header.Get("Server")),
		PoweredBy:       strings.TrimSpace(resp.Header.Get("X-Powered-By")),
		Title:           extractTitle(string(body)),
		WWWAuthenticate: strings.TrimSpace(resp.Header.Get("WWW-Authenticate")),
	}
	if resp.TLS != nil {
		banner.TLSVersion = tlsVersionString(resp.TLS.Version)
		if len(resp.TLS.PeerCertificates) > 0 {
			cert := resp.TLS.PeerCertificates[0]
			banner.TLSSubjectCN = strings.TrimSpace(cert.Subject.CommonName)
			if len(cert.Subject.Organization) > 0 {
				banner.TLSSubjectOrg = strings.TrimSpace(cert.Subject.Organization[0])
			}
			exp := cert.NotAfter.UTC()
			banner.TLSNotAfter = &exp
			banner.TLSExpired = time.Now().UTC().After(exp)
			banner.TLSSelfSigned = isSelfSignedCert(cert)
			chain := x509.NewCertPool()
			for _, intermediate := range resp.TLS.PeerCertificates[1:] {
				chain.AddCert(intermediate)
			}
			_, err := cert.Verify(x509.VerifyOptions{DNSName: ip, Intermediates: chain})
			banner.TLSVerified = err == nil
		}
	}
	return banner, true
}

// isSelfSignedCert reports whether cert was signed by its own public key.
// Unlike x509.Certificate.CheckSignatureFrom, it does not require CA basic
// constraints so typical self-signed device leaf certificates are recognized.
func isSelfSignedCert(cert *x509.Certificate) bool {
	if cert == nil || len(cert.RawIssuer) == 0 || !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return false
	}
	return cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return ""
	}
}

// extractTitle pulls a compact single-line title from raw HTML, returning an
// empty string if no <title> tag is present.
func extractTitle(html string) string {
	matches := titleRegex.FindStringSubmatch(html)
	if len(matches) < 2 {
		return ""
	}
	// Collapse internal newlines and repeated spaces for clean display and regex matching.
	fields := strings.Fields(matches[1])
	title := strings.Join(fields, " ")
	if len(title) > 160 {
		title = title[:160]
	}
	return title
}

// httpSchemeForPort maps common web ports to their expected HTTP scheme.
func httpSchemeForPort(port int) (string, bool) {
	switch port {
	case 80, 8080, 8000, 8081, 8123:
		return "http", true
	case 443, 8443:
		return "https", true
	default:
		return "", false
	}
}
