// Package probe performs gentle, bounded host fingerprinting across LAN
// clients so declarative checks can match cheap preconditions before sending
// targeted probes.
package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

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

	// TLSSelfSigned reports whether the leaf certificate is cryptographically self-signed.
	TLSSelfSigned bool `json:"tls_self_signed,omitempty"`
}

// Service summarizes one application-layer service identified on an open port
// by UniBlue's embedded Nerva fingerprinter (covering 170+ TCP/UDP protocols).
type Service struct {
	// Port is the open TCP port where the service responded.
	Port int `json:"port"`

	// Protocol is the canonical protocol name detected by Nerva (e.g., "ssh",
	// "smb", "http", "https", "nfs", "dns", "vnc").
	Protocol string `json:"protocol"`

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

	// OpenPorts lists the TCP ports from the scan list that accepted a connection.
	OpenPorts []int `json:"open_ports,omitempty"`

	// HTTP maps open HTTP/HTTPS port numbers to their observed landing-page banner.
	HTTP map[int]HTTPBanner `json:"http,omitempty"`

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

	// ScannedAt records when fingerprinting finished for this host.
	ScannedAt time.Time `json:"scanned_at"`
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
	// ports is the curated list of TCP ports checked on each host.
	ports []int

	// concurrency controls how many distinct hosts are probed simultaneously.
	concurrency int

	// timeout bounds each individual TCP dial and HTTP banner request.
	timeout time.Duration

	// excludeIPs contains IP addresses skipped without sending any packets.
	excludeIPs map[string]struct{}

	// hostPortHints maps specific client IPs to extra TCP ports discovered from
	// UniFi port forwards, firewall policies, or per-host LAN discovery.
	hostPortHints map[string][]int

	// discovery holds optional LAN-wide multicast observations (mDNS, SSDP,
	// WS-Discovery) collected once per FingerprintAll sweep.
	discovery *LANDiscovery

	// skipDiscovery disables multicast discovery (used by isolated unit tests).
	skipDiscovery bool

	// httpClient is configured with redirects disabled and self-signed TLS
	// accepted so local LAN devices can be fingerprinted without leaking requests
	// to external hosts.
	httpClient *http.Client
}

// SetHostPortHints attaches optional per-host TCP port hints (such as ports
// derived from UniFi port forwards or firewall policies) that are merged into
// the base scan port list when fingerprinting matching hosts.
func (f *Fingerprinter) SetHostPortHints(hints map[string][]int) {
	f.hostPortHints = hints
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
		ports:       sortedPorts,
		concurrency: concurrency,
		timeout:     timeout,
		excludeIPs:  excludeIPs,
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{Timeout: timeout}).DialContext,
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
	// Filter down to clients with a valid, non-excluded IP before spawning work.
	targets := make([]unifi.Client, 0, len(clients))
	for _, cl := range clients {
		if cl.IP == "" {
			continue
		}
		if _, skip := f.excludeIPs[cl.IP]; skip {
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
	if !f.skipDiscovery && hasNonLoopbackTarget(targets) {
		f.discovery = DiscoverLAN(ctx, f.httpClient)
	}
	return f.collectProfiles(ctx, targets, workers)
}

func hasNonLoopbackTarget(targets []unifi.Client) bool {
	for _, cl := range targets {
		ip := net.ParseIP(cl.IP)
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

	profiles := make([]HostProfile, 0, len(targets))
	for p := range results {
		profiles = append(profiles, p)
	}
	sort.Slice(profiles, func(i, j int) bool {
		return profiles[i].Client.IP < profiles[j].Client.IP
	})

	// Enrich every discovered open port using Nerva's FastMode protocol
	// fingerprinters (170+ protocols, MaxHostConn=1 for IoT safety).
	f.enrichWithNerva(ctx, profiles)
	return profiles
}

// FingerprintHost probes a single client's curated ports sequentially (to stay
// gentle on embedded stacks) and grabs lightweight HTTP banners for web ports.
func (f *Fingerprinter) FingerprintHost(ctx context.Context, cl unifi.Client) HostProfile {
	profile := HostProfile{
		Client:    cl,
		HTTP:      make(map[int]HTTPBanner),
		ScannedAt: time.Now().UTC(),
	}
	if f.discovery != nil {
		profile.MDNSServices = f.discovery.MDNS[cl.IP]
		profile.UPnPDevices = f.discovery.UPnP[cl.IP]
		profile.WSDiscovery = f.discovery.WSDiscovery[cl.IP]
	}

	dialTimeout := f.timeout
	if dialTimeout > maxPortDialTimeout {
		dialTimeout = maxPortDialTimeout
	}
	dialer := net.Dialer{Timeout: dialTimeout}

	ports := f.portsForHost(cl.IP)
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

		addr := net.JoinHostPort(cl.IP, strconv.Itoa(port))
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				consecutiveTimeouts++
				if len(profile.OpenPorts) == 0 && consecutiveTimeouts >= maxConsecutiveSilentTimeouts {
					break
				}
			} else {
				// Received an active TCP RST / ECONNREFUSED: host is awake and reachable.
				consecutiveTimeouts = 0
			}
			continue
		}
		consecutiveTimeouts = 0

		// On SSH (port 22), passively read the server's initial identification
		// banner before closing so version-based CVE checks have exact OpenSSH
		// or Dropbear versions without sending any auth packets.
		if port == 22 && profile.SSHBanner == "" {
			profile.SSHBanner = readSSHBanner(conn, f.timeout)
		}
		_ = conn.Close()
		profile.OpenPorts = append(profile.OpenPorts, port)

		// For well-known HTTP/HTTPS ports, grab a single read-only banner so
		// HTTP checks and CVE fingerprinters can match headers, titles, and TLS
		// certificate metadata cheaply.
		if scheme, ok := httpSchemeForPort(port); ok {
			if banner, ok := f.fetchHTTPBanner(ctx, scheme, cl.IP, port); ok {
				profile.HTTP[port] = banner
			}
		}
	}

	// Hypervisors (QEMU/KVM, Proxmox, libvirt) assign VNC displays sequentially
	// starting at 5900 (:0, :1, :2...). When a host already exposes a VNC port,
	// adaptively walk upward to discover additional VM displays without sending
	// extra probes to hosts that do not speak VNC.
	if profile.HasPort(5900) || profile.HasPort(5901) {
		f.walkVNCDisplays(ctx, dialer, cl.IP, ports, &profile)
	}

	sort.Ints(profile.OpenPorts)
	return profile
}

// portsForHost returns the deduplicated, sorted list of TCP ports to probe on
// ip, merging UniBlue's base port list with UniFi-derived port hints and
// per-host ports dynamically discovered via mDNS/SSDP/WS-Discovery.
func (f *Fingerprinter) portsForHost(ip string) []int {
	hints := f.hostPortHints[ip]
	var discPorts []int
	if f.discovery != nil {
		discPorts = f.discovery.PortsByIP[ip]
	}
	if len(hints) == 0 && len(discPorts) == 0 {
		return f.ports
	}
	seen := make(map[int]struct{}, len(f.ports)+len(hints)+len(discPorts))
	out := make([]int, 0, len(f.ports)+len(hints)+len(discPorts))
	add := func(list []int) {
		for _, p := range list {
			if p < 1 || p > 65535 {
				continue
			}
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	add(f.ports)
	add(hints)
	add(discPorts)
	sort.Ints(out)
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
		profile.OpenPorts = append(profile.OpenPorts, port)
		misses = 0
	}
}

// readSSHBanner reads a single identification line (e.g., "SSH-2.0-OpenSSH_9.6p1")
// sent by an SSH server immediately upon connection.
func readSSHBanner(conn net.Conn, timeout time.Duration) string {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	line, err := bufio.NewReader(io.LimitReader(conn, 256)).ReadString('\n')
	if err != nil && !strings.HasPrefix(line, "SSH-") {
		return ""
	}
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "SSH-") {
		return ""
	}
	return trimmed
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
			if cert.Subject.String() == cert.Issuer.String() {
				banner.TLSSelfSigned = cert.CheckSignatureFrom(cert) == nil
			}
		}
	}
	return banner, true
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
