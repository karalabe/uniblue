// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/scan"
)

// noisyNervaFindings lists low-value web-header and LAN-normative findings
// emitted by Nerva that cause alert fatigue on internal cameras, printers, and
// IoT web panels without representing actionable LAN exposure.
var noisyNervaFindings = map[string]struct{}{
	"http-missing-hsts":                   {},
	"http-missing-csp":                    {},
	"http-missing-x-frame-options":        {},
	"http-missing-x-content-type-options": {},
	"http-cors-wildcard":                  {},
	"http-server-version":                 {},
	"tls-self-signed":                     {},
	// Handled with deeper read-only verification by UniBlue's UB-0001 / UB-2026-0056 checks.
	"telnet-cleartext": {},
}

// nervaMetaSubset extracts common structured fields from Nerva's heterogeneous
// per-protocol Raw metadata JSON without pulling in every plugin struct type.
type nervaMetaSubset struct {
	Title           string              `json:"title"`
	Banner          string              `json:"banner"`
	CPEs            []string            `json:"cpes"`
	StatusCode      int                 `json:"status_code"`
	ResponseHeaders map[string][]string `json:"response_headers"`
}

// enrichWithNerva runs Praetorian's Nerva fingerprinter in FastMode across all
// confirmed-open TCP ports discovered during the gentle port sweep. Using
// FastMode + MaxHostConn=1 ensures Nerva only tests port-relevant protocols
// sequentially per host instead of spraying 170 fallback probes at fragile IoT gear.
func (f *Fingerprinter) enrichWithNerva(ctx context.Context, profiles []HostProfile) {
	if ctx.Err() != nil || len(profiles) == 0 {
		return
	}

	idxByIP := make(map[string]int, len(profiles))
	var targets []plugins.Target
	for i, hp := range profiles {
		targetIP := f.selectAllowedProbeIP(hp.Client)
		if targetIP == "" || len(hp.OpenPorts) == 0 {
			continue
		}
		addr, err := netip.ParseAddr(targetIP)
		if err != nil {
			continue
		}
		canonIP := addr.String()
		idxByIP[targetIP] = i
		idxByIP[canonIP] = i
		allIPs := hp.Client.AllIPs()
		for _, port := range hp.OpenPorts {
			// Hard zero-byte sink safety guard: NEVER send application-layer probe
			// bytes to JetDirect (9100), LPD (515), or any raw print or serial-bridge
			// port (including reflected Zigbee UART coordinators).
			if hp.sshPort(port) || port == 445 || hp.IsRawPrintPort(port) || isRawPrintSinkPortAny(port, f.discovery, allIPs) {
				continue
			}
			targets = append(targets, plugins.Target{
				Address:    netip.AddrPortFrom(addr, uint16(port)),
				Host:       canonIP,
				Misconfigs: true,
			})
		}
	}
	if len(targets) == 0 {
		return
	}

	nervaTimeout := f.timeout
	if nervaTimeout > 2*time.Second {
		nervaTimeout = 2 * time.Second
	}

	// Report live per-port service identification progress as Nerva workers
	// complete each target so startup never appears stalled on large LANs.
	f.reportProgress("fingerprinting", 0, len(targets), "")
	services, err := scan.ScanTargets(ctx, targets, scan.Config{
		DefaultTimeout: nervaTimeout,
		Workers:        f.concurrency,
		MaxHostConn:    1,
		Misconfigs:     true,
		FastMode:       true,
		ScanDepth:      scan.ScanDepthFast,
		OnProgress: func(target plugins.Target, results []plugins.Service, completed int64) {
			hostLabel := target.Host
			if idx, ok := idxByIP[target.Host]; ok {
				hostLabel = profiles[idx].Client.DisplayName()
			}
			label := fmt.Sprintf("%s:%d", hostLabel, target.Address.Port())
			if len(results) > 0 && strings.TrimSpace(results[0].Protocol) != "" {
				label += fmt.Sprintf(" (%s)", strings.ToLower(strings.TrimSpace(results[0].Protocol)))
			}
			// Pass Nerva's absolute atomic completion count directly rather than
			// synthesizing increments on out-of-order worker callbacks; callers
			// discard stale lower counts under their own lock.
			done := min(max(int(completed), 0), len(targets))
			f.reportProgress("fingerprinting", done, len(targets), label)
		},
	})
	if err == nil {
		for _, rawSvc := range services {
			idx, ok := idxByIP[rawSvc.IP]
			if !ok {
				continue
			}
			hp := &profiles[idx]

			svc, meta, proto := convertNervaService(rawSvc, time.Now().UTC())
			hp.Services = append(hp.Services, svc)

			// Backfill SSHBanner and HTTP banners discovered on non-default ports
			// (e.g., web dashboards or APIs on alternate ports) so downstream YAML
			// checks and CVE rules see them uniformly.
			if svc.Banner != "" && strings.HasPrefix(svc.Banner, "SSH-") && hp.SSHBanner == "" {
				hp.SSHBanner = svc.Banner
			}
			if (proto == "http" || proto == "https") && meta.StatusCode > 0 {
				if _, exists := hp.HTTP[svc.Port]; !exists {
					scheme := "http"
					if svc.TLS || proto == "https" {
						scheme = "https"
					}
					serverHdr := firstHeader(meta.ResponseHeaders, "Server")
					if serverHdr == "" && svc.Version != "" {
						serverHdr = svc.Version
					}
					hp.HTTP[svc.Port] = HTTPBanner{
						Scheme:          scheme,
						StatusCode:      meta.StatusCode,
						Server:          serverHdr,
						PoweredBy:       firstHeader(meta.ResponseHeaders, "X-Powered-By"),
						Title:           svc.Title,
						WWWAuthenticate: firstHeader(meta.ResponseHeaders, "WWW-Authenticate"),
					}
				}
			}
		}
	}

	// Alternate-port & TLS fallback: for open non-raw-print TCP ports that Nerva
	// FastMode did not classify (because FastMode prioritizes default ports),
	// reuse observed HTTP/TLS metadata first, then queue remaining ports per host
	// so bounded fallback banner/TLS probes run concurrently across hosts while
	// keeping at most one active connection per host for IoT safety.
	type fallbackHostJob struct {
		idx   int
		ip    string
		name  string
		ports []int
	}
	var fallbackJobs []fallbackHostJob
	totalFallbacks := 0
	for i := range profiles {
		hp := &profiles[i]
		targetIP := f.selectAllowedProbeIP(hp.Client)
		if targetIP == "" || len(hp.OpenPorts) == 0 || ctx.Err() != nil {
			continue
		}
		allIPs := hp.Client.AllIPs()
		covered := make(map[int]bool, len(hp.Services))
		for _, s := range hp.Services {
			if s.Transport == "" || strings.EqualFold(s.Transport, "tcp") {
				covered[s.Port] = true
			}
		}
		var pendingPorts []int
		for _, port := range hp.OpenPorts {
			if hp.sshPort(port) || port == 445 || covered[port] || hp.IsRawPrintPort(port) || isRawPrintSinkPortAny(port, f.discovery, allIPs) {
				continue
			}
			if b, ok := hp.HTTP[port]; ok {
				now := time.Now().UTC()
				proto := "http"
				state := ServiceStateObservedProtocol
				isTLS := b.Scheme == "https" || b.TLSVersion != ""
				if isTLS {
					if b.StatusCode > 0 {
						proto = "https"
					} else {
						proto = "tls"
						state = ServiceStateTLSUnknownApp
					}
				}
				hp.Services = append(hp.Services, Service{
					Port:          port,
					Transport:     "tcp",
					Protocol:      proto,
					State:         state,
					AddressFamily: ipFamilyOf(targetIP),
					ObservedAt:    &now,
					TLS:           isTLS,
					Title:         b.Title,
					Banner:        b.Server,
				})
				continue
			}
			pendingPorts = append(pendingPorts, port)
		}
		if len(pendingPorts) > 0 {
			fallbackJobs = append(fallbackJobs, fallbackHostJob{
				idx:   i,
				ip:    targetIP,
				name:  hp.Client.DisplayName(),
				ports: pendingPorts,
			})
			totalFallbacks += len(pendingPorts)
		}
	}

	if totalFallbacks > 0 && ctx.Err() == nil {
		f.reportProgress("fingerprinting-fallback", 0, totalFallbacks, "")
		workers := max(1, min(f.concurrency, len(fallbackJobs)))
		jobCh := make(chan fallbackHostJob, len(fallbackJobs))
		for _, job := range fallbackJobs {
			jobCh <- job
		}
		close(jobCh)

		var fbDoneMu sync.Mutex
		fbDone := 0
		var wg sync.WaitGroup
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for job := range jobCh {
					hp := &profiles[job.idx]
					for _, port := range job.ports {
						if ctx.Err() != nil {
							return
						}
						label := fmt.Sprintf("%s:%d", job.name, port)
						if svc, ok := probeAlternatePortFallback(ctx, job.ip, port, nervaTimeout); ok {
							// A greeting on an alternate port identifies a listener for the same pre-authentication exchange.
							if svc.Protocol == "ssh" && !f.isInfrastructure(*hp) {
								dialer := net.Dialer{Timeout: nervaTimeout}
								conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(job.ip, strconv.Itoa(port)))
								if err == nil {
									if obs := observeSSH(conn, port, nervaTimeout); obs != nil {
										if hp.SSH == nil {
											hp.SSH = obs
											f.auditSSH(ctx, hp)
										}
										svc.Findings = append(svc.Findings, sshWeakAlgorithmFindings(obs)...)
									}
									conn.Close()
								}
							}
							hp.Services = append(hp.Services, svc)
							if svc.Banner != "" && strings.HasPrefix(svc.Banner, "SSH-") && hp.SSHBanner == "" {
								hp.SSHBanner = svc.Banner
							}
							if svc.Protocol != "" {
								label += fmt.Sprintf(" (%s)", svc.Protocol)
							}
						}
						fbDoneMu.Lock()
						fbDone++
						done := fbDone
						fbDoneMu.Unlock()
						f.reportProgress("fingerprinting-fallback", done, totalFallbacks, label)
					}
				}
			}()
		}
		wg.Wait()
	}

	// Keep each host's Services sorted deterministically by port.
	for i := range profiles {
		sort.Slice(profiles[i].Services, func(a, b int) bool {
			if profiles[i].Services[a].Port != profiles[i].Services[b].Port {
				return profiles[i].Services[a].Port < profiles[i].Services[b].Port
			}
			return profiles[i].Services[a].Transport < profiles[i].Services[b].Transport
		})
	}
}

// convertNervaService translates a raw Nerva plugin detection into UniBlue's
// normalized Service record, preserving Nerva's canonical AnonymousAccess flag
// without false-positiving on TLS cipher findings such as tls-anon-cipher.
func convertNervaService(rawSvc plugins.Service, now time.Time) (Service, nervaMetaSubset, string) {
	var meta nervaMetaSubset
	if len(rawSvc.Raw) > 0 {
		_ = json.Unmarshal(rawSvc.Raw, &meta)
	}

	// Filter out known false-positive classifications (e.g., ASUS ASMB9-iKVM
	// server BMCs matching Oracle OUAF login heuristics).
	proto := strings.ToLower(strings.TrimSpace(rawSvc.Protocol))
	isBMCFalsePositive := proto == "oracle_ouaf" && strings.Contains(strings.ToLower(meta.Title), "ikvm")
	if isBMCFalsePositive {
		proto = "https"
		meta.CPEs = nil
	}

	svcState := ServiceStateObservedProtocol
	switch proto {
	case "", "unknown":
		svcState = ServiceStateUnknown
	case "tls", "ssl", "dtls":
		svcState = ServiceStateTLSUnknownApp
	}
	svc := Service{
		Port:            rawSvc.Port,
		Transport:       "tcp",
		Protocol:        proto,
		State:           svcState,
		AddressFamily:   ipFamilyOf(rawSvc.IP),
		IP:              rawSvc.IP,
		ObservedAt:      &now,
		TLS:             rawSvc.TLS,
		Version:         strings.TrimSpace(rawSvc.Version),
		Title:           strings.TrimSpace(meta.Title),
		Banner:          sanitizeBanner(meta.Banner),
		AnonymousAccess: rawSvc.AnonymousAccess && !isBMCFalsePositive,
		CPEs:            meta.CPEs,
	}

	droppedSyntheticAnon := false
	keptAuthFinding := false
	for _, sf := range rawSvc.SecurityFindings {
		if isBMCFalsePositive && strings.EqualFold(sf.ID, "oracle-ouaf-login-exposed") {
			continue
		}
		if !shouldKeepNervaFinding(sf) {
			if isSyntheticHTTPAnonFinding(sf) {
				droppedSyntheticAnon = true
			}
			continue
		}
		if isNervaAnonAccessFinding(sf.ID) {
			svc.AnonymousAccess = true
			keptAuthFinding = true
		}
		svc.Findings = append(svc.Findings, ServiceFinding{
			ID:          sf.ID,
			Severity:    strings.ToLower(string(sf.Severity)),
			Title:       strings.TrimSpace(sf.Title),
			Description: strings.TrimSpace(sf.Description),
			Evidence:    strings.TrimSpace(sf.Evidence),
		})
	}
	// Clear AnonymousAccess when its only basis was a dropped synthetic HTTP
	// product-detection placeholder, or when Nerva's HTTP plugin set the flag
	// alongside only non-auth findings (such as os-eol or php version checks).
	if !keptAuthFinding {
		if droppedSyntheticAnon || ((proto == "http" || proto == "https") && len(rawSvc.SecurityFindings) > 0) {
			svc.AnonymousAccess = false
		}
	}
	return svc, meta, proto
}

// isNervaAnonAccessFinding reports whether a Nerva finding ID specifically
// denotes unauthenticated or anonymous service access rather than an unrelated
// TLS cipher attribute such as tls-anon-cipher.
func isNervaAnonAccessFinding(rawID string) bool {
	id := strings.ToLower(strings.TrimSpace(rawID))
	if id == "" || strings.HasPrefix(id, "tls-") {
		return false
	}
	switch {
	case strings.HasSuffix(id, "-anon-access"),
		strings.HasSuffix(id, "-anonymous-access"),
		strings.HasSuffix(id, "-anonymous-bind"),
		strings.HasSuffix(id, "-anonymous-login"),
		strings.HasSuffix(id, "-no-auth"),
		strings.HasSuffix(id, "-unauth"),
		strings.Contains(id, "-unauth-"),
		strings.Contains(id, "-unauthenticated"):
		return true
	default:
		return false
	}
}

func isSyntheticHTTPAnonFinding(sf plugins.SecurityFinding) bool {
	id := strings.ToLower(strings.TrimSpace(sf.ID))
	return strings.HasSuffix(id, "-anon-access") &&
		strings.EqualFold(strings.TrimSpace(sf.Evidence), "Successfully queried endpoint without credentials")
}

// maxFallbackBannerBytes caps passive banner reads in probeAlternatePortFallback
// so a hostile device streaming unbounded data without newlines cannot exhaust memory.
const maxFallbackBannerBytes = 256

// sanitizeBanner strips non-printable control characters and truncates banners
// to maxFallbackBannerBytes bytes.
func sanitizeBanner(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(min(len(s), maxFallbackBannerBytes))
	for _, r := range s {
		if r >= 0x20 && r != 0x7f {
			if b.Len()+len(string(r)) > maxFallbackBannerBytes {
				break
			}
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// probeAlternatePortFallback performs a gentle read-only check on an open TCP
// port that Nerva FastMode left unclassified: first listens briefly for a
// server-initiated greeting (SSH, RFB/VNC, SMTP/FTP/Redis), and if the server
// waits for a client, attempts a read-only TLS handshake to identify TLS-wrapped
// services without guessing the inner application protocol.
func probeAlternatePortFallback(ctx context.Context, ip string, port int, timeout time.Duration) (Service, bool) {
	if timeout <= 0 || timeout > 800*time.Millisecond {
		timeout = 500 * time.Millisecond
	}
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	now := time.Now().UTC()

	// 1. Passive greeting read (zero bytes written, bounded to 256 bytes).
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return Service{}, false
	}
	greetTimeout := timeout / 3
	if greetTimeout < 120*time.Millisecond {
		greetTimeout = 120 * time.Millisecond
	}
	_ = conn.SetReadDeadline(time.Now().Add(greetTimeout))
	line, readErr := bufio.NewReaderSize(io.LimitReader(conn, maxFallbackBannerBytes), maxFallbackBannerBytes).ReadString('\n')
	_ = conn.Close()
	if readErr == nil || len(line) > 0 {
		trimmed := sanitizeBanner(line)
		switch {
		case strings.HasPrefix(trimmed, "SSH-"):
			return Service{
				Port:          port,
				Transport:     "tcp",
				Protocol:      "ssh",
				State:         ServiceStateObservedProtocol,
				AddressFamily: ipFamilyOf(ip),
				ObservedAt:    &now,
				Banner:        trimmed,
			}, true
		case strings.HasPrefix(trimmed, "RFB "):
			return Service{
				Port:          port,
				Transport:     "tcp",
				Protocol:      "vnc",
				State:         ServiceStateObservedProtocol,
				AddressFamily: ipFamilyOf(ip),
				ObservedAt:    &now,
				Banner:        trimmed,
			}, true
		}
	}

	// 2. Read-only TLS handshake check: establishes TLS without inventing an app.
	tlsConn, tlsErr := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // read-only LAN fingerprinting
	})
	if tlsErr == nil {
		cs := tlsConn.ConnectionState()
		_ = tlsConn.Close()
		proto := "tls"
		state := ServiceStateTLSUnknownApp
		if alpn := strings.ToLower(strings.TrimSpace(cs.NegotiatedProtocol)); alpn == "h2" || alpn == "http/1.1" {
			proto = "https"
			state = ServiceStateObservedProtocol
		}
		return Service{
			Port:          port,
			Transport:     "tcp",
			Protocol:      proto,
			State:         state,
			AddressFamily: ipFamilyOf(ip),
			ObservedAt:    &now,
			TLS:           true,
		}, true
	}
	return Service{}, false
}

// shouldKeepNervaFinding drops noisy LAN web-header lint findings and Nerva's
// synthetic HTTP product-detection "*-anon-access" placeholders (which fire
// on public /api/health or /login endpoints without verifying authentication),
// while retaining genuine security exposures (SMBv1, weak signing, expired TLS
// certificates, verified unauthenticated protocols, etc.).
func shouldKeepNervaFinding(sf plugins.SecurityFinding) bool {
	id := strings.ToLower(strings.TrimSpace(sf.ID))
	if id == "" {
		return false
	}
	if _, noisy := noisyNervaFindings[id]; noisy {
		return false
	}
	// Nerva's HTTP plugin synthesizes "<tech>-anon-access" with this exact
	// boilerplate evidence whenever an HTTP fingerprinter detects a product via
	// a public health or login endpoint, even when authentication is enforced.
	if strings.HasSuffix(id, "-anon-access") &&
		strings.EqualFold(strings.TrimSpace(sf.Evidence), "Successfully queried endpoint without credentials") {
		return false
	}
	return true
}

// isRawPrintSinkPort returns true for raw printer data-stream ports that must
// remain strictly connect-only (zero application bytes written).
func isRawPrintSinkPort(port int, disc *LANDiscovery, ip string) bool {
	if port == 9100 || port == 515 {
		return true
	}
	if disc != nil {
		if m := disc.RawPrintIPs[ip]; m != nil {
			if _, ok := m[port]; ok {
				return true
			}
		}
	}
	return false
}

// firstHeader looks up a header name case-insensitively in Nerva's response_headers map.
func firstHeader(headers map[string][]string, name string) string {
	for k, vals := range headers {
		if strings.EqualFold(k, name) && len(vals) > 0 {
			return strings.TrimSpace(vals[0])
		}
	}
	return ""
}
