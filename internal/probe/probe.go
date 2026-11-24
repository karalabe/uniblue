// Package probe performs gentle, bounded host fingerprinting across LAN
// clients so declarative checks can match cheap preconditions before sending
// targeted probes.
package probe

import (
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
	perPortPause = 25 * time.Millisecond
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

	// Title is the trimmed HTML <title> text extracted from the landing page.
	Title string `json:"title,omitempty"`

	// WWWAuthenticate records the WWW-Authenticate header when the device asks
	// for HTTP authentication.
	WWWAuthenticate string `json:"www_authenticate,omitempty"`
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

	// httpClient is configured with redirects disabled and self-signed TLS
	// accepted so local LAN devices can be fingerprinted without leaking requests
	// to external hosts.
	httpClient *http.Client
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
	return f.collectProfiles(ctx, targets, workers)
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

	dialer := net.Dialer{Timeout: f.timeout}

	for i, port := range f.ports {
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
			continue
		}
		_ = conn.Close()
		profile.OpenPorts = append(profile.OpenPorts, port)

		// For well-known HTTP/HTTPS ports, grab a single read-only banner so
		// HTTP checks can match titles, headers, and status codes cheaply.
		if scheme, ok := httpSchemeForPort(port); ok {
			if banner, ok := f.fetchHTTPBanner(ctx, scheme, cl.IP, port); ok {
				profile.HTTP[port] = banner
			}
		}
	}

	return profile
}

// fetchHTTPBanner performs one bounded GET / request against a local host and
// extracts its status code, Server header, WWW-Authenticate header, and HTML title.
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
	return HTTPBanner{
		Scheme:          scheme,
		StatusCode:      resp.StatusCode,
		Server:          strings.TrimSpace(resp.Header.Get("Server")),
		Title:           extractTitle(string(body)),
		WWWAuthenticate: strings.TrimSpace(resp.Header.Get("WWW-Authenticate")),
	}, true
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
	case 80, 8080, 8000, 8081:
		return "http", true
	case 443, 8443:
		return "https", true
	default:
		return "", false
	}
}
