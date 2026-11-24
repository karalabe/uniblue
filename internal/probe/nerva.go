package probe

import (
	"context"
	"encoding/json"
	"net/netip"
	"sort"
	"strings"
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
	"http-server-version":                 {},
	"tls-self-signed":                     {},
	// Handled with deeper read-only verification by UniBlue's UB-0001 / UB-2026-0002 checks.
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
		if hp.Client.IP == "" || len(hp.OpenPorts) == 0 {
			continue
		}
		addr, err := netip.ParseAddr(hp.Client.IP)
		if err != nil {
			continue
		}
		idxByIP[hp.Client.IP] = i
		for _, port := range hp.OpenPorts {
			// Hard raw-printer safety guard: NEVER send application-layer probe
			// bytes to JetDirect (9100), LPD (515), or any port advertised via
			// mDNS _pdl-datastream._tcp, because non-PJL printers can print raw
			// probe bytes onto physical paper.
			if isRawPrintSinkPort(port, f.discovery, hp.Client.IP) {
				continue
			}
			targets = append(targets, plugins.Target{
				Address:    netip.AddrPortFrom(addr, uint16(port)),
				Host:       hp.Client.IP,
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

	services, err := scan.ScanTargets(ctx, targets, scan.Config{
		DefaultTimeout: nervaTimeout,
		Workers:        f.concurrency,
		MaxHostConn:    1,
		Misconfigs:     true,
		FastMode:       true,
		ScanDepth:      scan.ScanDepthFast,
	})
	if err != nil || len(services) == 0 {
		return
	}

	for _, rawSvc := range services {
		idx, ok := idxByIP[rawSvc.IP]
		if !ok {
			continue
		}
		hp := &profiles[idx]

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

		svc := Service{
			Port:     rawSvc.Port,
			Protocol: proto,
			TLS:      rawSvc.TLS,
			Version:  strings.TrimSpace(rawSvc.Version),
			Title:    strings.TrimSpace(meta.Title),
			Banner:   strings.TrimSpace(meta.Banner),
			CPEs:     meta.CPEs,
		}

		for _, sf := range rawSvc.SecurityFindings {
			if isBMCFalsePositive && strings.EqualFold(sf.ID, "oracle-ouaf-login-exposed") {
				continue
			}
			if !shouldKeepNervaFinding(sf) {
				continue
			}
			if strings.Contains(strings.ToLower(sf.ID), "anon") || strings.Contains(strings.ToLower(sf.ID), "no-auth") {
				svc.AnonymousAccess = true
			}
			svc.Findings = append(svc.Findings, ServiceFinding{
				ID:          sf.ID,
				Severity:    strings.ToLower(string(sf.Severity)),
				Title:       strings.TrimSpace(sf.Title),
				Description: strings.TrimSpace(sf.Description),
				Evidence:    strings.TrimSpace(sf.Evidence),
			})
		}

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

	// Keep each host's Services sorted deterministically by port.
	for i := range profiles {
		sort.Slice(profiles[i].Services, func(a, b int) bool {
			return profiles[i].Services[a].Port < profiles[i].Services[b].Port
		})
	}
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
