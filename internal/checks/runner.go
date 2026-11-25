// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checks

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/unifi"
)

const (
	// maxProbeBodyBytes caps HTTP response reads during active probe verification so
	// large pages never consume excessive memory.
	maxProbeBodyBytes = 64 * 1024

	// maxBannerReadBytes caps the initial bytes read from a raw TCP service banner.
	maxBannerReadBytes = 2048
)

// SwitchPortRef identifies a physical socket independently of any attached host.
type SwitchPortRef struct {
	// SwitchMAC is the normalized MAC address of the owning switch.
	SwitchMAC string `json:"switch_mac"`

	// PortIdx is the one-based physical port number on the switch.
	PortIdx int `json:"port_idx"`
}

// Finding records a confirmed security issue discovered on a specific LAN host.
type Finding struct {
	// CheckID is the identifier of the check that triggered (e.g., "UB-0003").
	CheckID string `json:"check_id"`

	// AffectedClientMACs lists concrete client endpoints of permitted peer paths.
	AffectedClientMACs []string `json:"affected_client_macs,omitempty"`

	// AffectedSwitchPorts lists wired sockets with actionable isolation settings.
	AffectedSwitchPorts []SwitchPortRef `json:"affected_switch_ports,omitempty"`

	// Title summarizes the detected exposure or vulnerability.
	Title string `json:"title"`

	// CVE carries an official CVE ID when applicable.
	CVE string `json:"cve,omitempty"`

	// Category groups findings by bug class (e.g., "unauth-control").
	Category string `json:"category"`

	// ClaimKind distinguishes asset identity, advertised service, observed
	// service, configured access, and confirmed permission evidence.
	ClaimKind ClaimKind `json:"claim_kind,omitempty"`

	// Property identifies the specific security property proven (e.g.,
	// "tls-protocol", "tls-cert", "smb-v1", "smb-signing", "auth-anon").
	Property string `json:"property,omitempty"`

	// Transport records the L4 transport ("tcp" or "udp") associated with Port.
	Transport string `json:"transport,omitempty"`

	// ObservedIPs identifies the target addresses supporting this finding.
	// An empty list means unresolved. Older records omit the field entirely.
	ObservedIPs []string `json:"observed_ips,omitzero"`

	// BaseSeverity is the check's intrinsic severity before UniFi topology scoring.
	BaseSeverity Severity `json:"base_severity"`

	// EffectiveSeverity is the final severity after VLAN and WAN adjustments.
	EffectiveSeverity Severity `json:"effective_severity"`

	// RiskReasons lists human-readable explanations for any severity adjustments.
	RiskReasons []string `json:"risk_reasons,omitempty"`

	// Client identifies the affected host from the UniFi snapshot.
	Client unifi.Client `json:"client"`

	// Port is the TCP port where the issue was observed (0 for pure posture findings).
	Port int `json:"port,omitempty"`

	// Evidence summarizes what the probe observed without leaking redacted secrets.
	Evidence string `json:"evidence"`

	// Remediation provides practical guidance and suggested UniFi actions.
	Remediation Remediation `json:"remediation"`
}

// EndpointIPs returns the addresses eligible for correlation with a WAN forward.
// Legacy records can be attributed only when the client has one possible address.
func (f Finding) EndpointIPs() []string {
	if f.ObservedIPs != nil {
		return f.ObservedIPs
	}
	if ips := f.Client.AllIPs(); len(ips) == 1 {
		return ips
	}
	return nil
}

// Key returns a stable deduplication key identifying this finding across scans.
func (f Finding) Key() string {
	hostID := f.Client.MAC
	if hostID == "" {
		hostID = f.Client.IP
	}
	base := fmt.Sprintf("%s|%s|%d", f.CheckID, hostID, f.Port)
	if p := strings.TrimSpace(f.Property); p != "" {
		base += "|" + p
	}
	if t := strings.ToLower(strings.TrimSpace(f.Transport)); t != "" && t != "tcp" {
		base += "|" + t
	}
	return base
}

// EffectiveTransport returns the normalized transport protocol ("tcp" or "udp")
// for this finding, defaulting to "tcp" for legacy records without Transport set.
func (f Finding) EffectiveTransport() string {
	if t := strings.ToLower(strings.TrimSpace(f.Transport)); t != "" {
		return t
	}
	if f.Port == 623 || f.Port == 161 || f.Port == 5351 || f.Port == 5683 {
		return "udp"
	}
	return "tcp"
}

// IsInventoryOnly reports whether this finding establishes only asset identity
// or service visibility at informational severity without asserting a policy
// violation or unauthorized permission.
func (f Finding) IsInventoryOnly() bool {
	if f.BaseSeverity != SeverityInfo {
		return false
	}
	switch f.ClaimKind {
	case ClaimAssetIdentity, ClaimServiceAdvertised, ClaimServiceObserved:
		return true
	default:
		return false
	}
}

// Runner executes validated declarative Checks against HostProfiles using a
// bounded channel worker pool.
type Runner struct {
	// checks is the validated set of checks to evaluate.
	checks []*Check

	// concurrency limits how many hosts are checked simultaneously.
	concurrency int

	// httpClient enforces redirect suppression and local-LAN TLS handling for
	// every HTTP probe.
	httpClient *http.Client

	// onProgress receives optional per-host progress updates during RunAll.
	onProgress func(done, total int, host string)
}

// SetProgressFunc registers an optional callback invoked as each host finishes
// check evaluation inside RunAll.
func (r *Runner) SetProgressFunc(fn func(done, total int, host string)) {
	r.onProgress = fn
}

// NewRunner constructs a Runner for the provided checks and worker count.
func NewRunner(list []*Check, concurrency int) *Runner {
	if concurrency <= 0 {
		concurrency = 8
	}
	return &Runner{
		checks:      list,
		concurrency: concurrency,
		httpClient: &http.Client{
			Transport: &http.Transport{
				DisableKeepAlives: true,
				IdleConnTimeout:   5 * time.Second,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, //nolint:gosec // local LAN appliances routinely use self-signed certificates
					MinVersion:         tls.VersionTLS10,
					CipherSuites:       allLegacyTLSCipherSuites(),
				},
			},
			// Never follow redirects: prevents a hostile or misconfigured device
			// from bouncing a probe off the LAN to an external internet host.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// RunAll evaluates all checks across the provided host profiles concurrently
// via a channel worker pool, returning findings sorted deterministically.
func (r *Runner) RunAll(ctx context.Context, profiles []probe.HostProfile) []Finding {
	defer r.httpClient.CloseIdleConnections()
	if len(profiles) == 0 || len(r.checks) == 0 {
		return nil
	}

	workers := r.concurrency
	if len(profiles) < workers {
		workers = len(profiles)
	}

	type hostResult struct {
		host     string
		findings []Finding
	}
	jobs := make(chan probe.HostProfile)
	results := make(chan hostResult, workers)
	done := make(chan struct{}, workers)

	// Each worker handles one host at a time so probes against a single fragile
	// embedded device remain sequential and gentle.
	for range workers {
		go func() {
			defer func() { done <- struct{}{} }()
			for hp := range jobs {
				results <- hostResult{
					host:     hp.Client.DisplayName(),
					findings: r.RunHost(ctx, hp),
				}
			}
		}()
	}

	go func() {
		for range workers {
			<-done
		}
		close(results)
	}()

	go func() {
		defer close(jobs)
		for _, hp := range profiles {
			select {
			case <-ctx.Done():
				return
			case jobs <- hp:
			}
		}
	}()

	var all []Finding
	completed := 0
	for res := range results {
		completed++
		if len(res.findings) > 0 {
			all = append(all, res.findings...)
		}
		if r.onProgress != nil {
			r.onProgress(completed, len(profiles), res.host)
		}
	}

	sort.Slice(all, func(i, j int) bool {
		if all[i].EffectiveSeverity != all[j].EffectiveSeverity {
			return all[i].EffectiveSeverity > all[j].EffectiveSeverity
		}
		if all[i].Client.IP != all[j].Client.IP {
			return all[i].Client.IP < all[j].Client.IP
		}
		if all[i].CheckID != all[j].CheckID {
			return all[i].CheckID < all[j].CheckID
		}
		return all[i].Port < all[j].Port
	})
	return all
}

// RunHost evaluates all checks whose preconditions match hp and executes
// their verification probes sequentially against that host.
func (r *Runner) RunHost(ctx context.Context, hp probe.HostProfile) []Finding {
	defer r.httpClient.CloseIdleConnections()
	var findings []Finding
	// Track (checkID|port) pairs superseded by more specific device checks on
	// the same host so operators aren't shown redundant generic warnings.
	superseded := make(map[string]struct{})

	for _, chk := range r.checks {
		if ctx.Err() != nil {
			break
		}
		ports, ok := matchPreconditions(chk, hp)
		if !ok {
			continue
		}
		for _, port := range ports {
			if ctx.Err() != nil {
				break
			}
			var evidence string
			var matched bool
			if chk.Probe.Type == "observe" {
				evidence, matched = probeObserve(chk, hp, port)
			} else {
				// Hard raw-printer safety guard: never send active bytes to raw print sinks.
				if hp.IsRawPrintPort(port) {
					continue
				}
				targetIP := hp.EffectiveProbeIP()
				if targetIP == "" {
					continue
				}
				evidence, matched = r.executeProbeProfile(ctx, chk, hp, targetIP, port)
			}
			if matched {
				for _, supID := range chk.Supersedes {
					superseded[fmt.Sprintf("%s|%d", supID, port)] = struct{}{}
				}
				for _, ep := range findingEndpoints(chk, hp, port) {
					findings = append(findings, Finding{
						CheckID:           chk.ID,
						Title:             chk.Title,
						CVE:               chk.CVE,
						Category:          chk.Category,
						ClaimKind:         chk.Claim,
						Property:          chk.Property,
						Transport:         ep.transport,
						ObservedIPs:       ep.ips,
						BaseSeverity:      chk.Severity,
						EffectiveSeverity: chk.Severity,
						Client:            hp.Client,
						Port:              port,
						Evidence:          evidence,
						Remediation:       chk.Remediation,
					})
				}
			}
		}
	}

	if len(superseded) == 0 {
		return findings
	}
	filtered := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if _, drop := superseded[fmt.Sprintf("%s|%d", f.CheckID, f.Port)]; drop {
			continue
		}
		filtered = append(filtered, f)
	}
	return filtered
}

// matchPreconditions evaluates precondition rules against already-fingerprinted host
// metadata without sending any network packets. It returns the target port(s)
// to probe when all preconditions hold.
func matchPreconditions(chk *Check, hp probe.HostProfile) ([]int, bool) {
	allowUDPPortMatch := isNonTCPProbe(chk.Probe.Type) && chk.Probe.Type != "observe"

	// Match open ports first since it is the cheapest filter and also selects
	// which concrete ports the verification probe should target.
	for _, p := range chk.Preconditions.PortsAll {
		if !hostHasObservedPort(hp, p, allowUDPPortMatch) {
			return nil, false
		}
	}
	var matchedPorts []int
	for _, p := range chk.Preconditions.PortsAny {
		if hostHasObservedPort(hp, p, allowUDPPortMatch) {
			matchedPorts = append(matchedPorts, p)
		}
	}
	// For UDP probes that declare both ports_any and service_proto_any (such as
	// STUN/TURN), either an observed port or a matching passive-flow protocol
	// satisfies the trigger so UDP-only servers work without TCP open ports.
	portsOrServiceProto := allowUDPPortMatch && len(chk.Preconditions.PortsAny) > 0 && len(chk.Preconditions.ServiceProtoAny) > 0
	if !portsOrServiceProto && len(chk.Preconditions.PortsAny) > 0 && len(matchedPorts) == 0 {
		return nil, false
	}
	if len(matchedPorts) == 0 && len(chk.Preconditions.PortsAll) > 0 {
		matchedPorts = append(matchedPorts, chk.Preconditions.PortsAll...)
	}

	// Match identity preconditions (MAC prefix, OUI vendor, or hostname). When
	// multiple identity hints are present on a community check, treat MAC prefix
	// or hostname as independent ways to identify the same device when OUI is empty.
	if len(chk.Preconditions.MACPrefix) > 0 || chk.compiled.hostname != nil {
		macMatched := false
		if len(chk.Preconditions.MACPrefix) > 0 && hp.Client.MAC != "" {
			macLower := strings.ToLower(hp.Client.MAC)
			for _, pfx := range chk.Preconditions.MACPrefix {
				if strings.HasPrefix(macLower, strings.ToLower(strings.TrimSpace(pfx))) {
					macMatched = true
					break
				}
			}
		}
		hostMatched := false
		if chk.compiled.hostname != nil {
			hostMatched = chk.compiled.hostname.MatchString(hp.Client.Hostname) || chk.compiled.hostname.MatchString(hp.Client.Name)
		}
		// Require whichever identity matcher(s) were supplied to match (logical OR
		// between MACPrefix and HostnameRegex so a renamed device still matches by
		// MAC OUI, and a single-IP `check test` without MAC still matches by name).
		if !macMatched && !hostMatched {
			return nil, false
		}
	}

	if len(chk.Preconditions.OUIContains) > 0 {
		ouiLower := strings.ToLower(hp.Client.OUI)
		matched := false
		for _, needle := range chk.Preconditions.OUIContains {
			if strings.Contains(ouiLower, strings.ToLower(needle)) {
				matched = true
				break
			}
		}
		if !matched {
			return nil, false
		}
	}

	// HTTP-based preconditions narrow matchedPorts down to only those web ports
	// whose fingerprinted banner actually satisfied the criteria.
	needsHTTP := chk.compiled.httpTitle != nil || chk.compiled.httpServer != nil || len(chk.Preconditions.HTTPStatusAny) > 0
	if needsHTTP {
		var webPorts []int
		for _, p := range matchedPorts {
			banner, ok := hp.HTTP[p]
			if !ok {
				continue
			}
			if chk.compiled.httpTitle != nil && !chk.compiled.httpTitle.MatchString(banner.Title) {
				continue
			}
			if chk.compiled.httpServer != nil && !chk.compiled.httpServer.MatchString(banner.Server) {
				continue
			}
			if len(chk.Preconditions.HTTPStatusAny) > 0 && !intInSlice(banner.StatusCode, chk.Preconditions.HTTPStatusAny) {
				continue
			}
			webPorts = append(webPorts, p)
		}
		if len(webPorts) == 0 {
			return nil, false
		}
		matchedPorts = webPorts
	}

	// Match passive mDNS / DNS-SD service preconditions.
	var discoveredPorts []int
	if len(chk.Preconditions.MDNSTypeAny) > 0 {
		mdnsMatched := false
		for _, svc := range hp.MDNSServices {
			if !matchesMDNSService(chk, svc) {
				continue
			}
			mdnsMatched = true
			if svc.Port > 0 {
				discoveredPorts = append(discoveredPorts, svc.Port)
			}
		}
		if !mdnsMatched {
			return nil, false
		}
	}

	// Match passive SSDP / UPnP device and service preconditions.
	if chk.compiled.upnpDevice != nil || chk.compiled.upnpService != nil {
		upnpMatched := false
		for _, dev := range hp.UPnPDevices {
			if !matchesUPnPDevice(chk, dev) {
				continue
			}
			upnpMatched = true
			if dev.Port > 0 {
				discoveredPorts = append(discoveredPorts, dev.Port)
			}
		}
		if !upnpMatched {
			return nil, false
		}
	}

	// Match passive WS-Discovery (ONVIF / WSD) preconditions.
	if chk.compiled.wsType != nil {
		wsMatched := false
		for _, rec := range hp.WSDiscovery {
			if !matchesWSRecord(chk, rec) {
				continue
			}
			wsMatched = true
			discoveredPorts = append(discoveredPorts, rec.Ports...)
		}
		if !wsMatched {
			return nil, false
		}
	}

	// Match Nerva-detected or passive-flow application-layer protocol names.
	if len(chk.Preconditions.ServiceProtoAny) > 0 {
		svcMatched := false
		for _, svc := range hp.Services {
			for _, want := range chk.Preconditions.ServiceProtoAny {
				if strings.EqualFold(svc.Protocol, want) {
					svcMatched = true
					if svc.Port > 0 {
						discoveredPorts = append(discoveredPorts, svc.Port)
					}
					break
				}
			}
		}
		if !svcMatched && (!portsOrServiceProto || len(matchedPorts) == 0) {
			return nil, false
		}
	}

	if len(matchedPorts) == 0 && len(discoveredPorts) > 0 {
		seen := make(map[int]struct{}, len(discoveredPorts))
		for _, p := range discoveredPorts {
			if _, dup := seen[p]; !dup {
				seen[p] = struct{}{}
				matchedPorts = append(matchedPorts, p)
			}
		}
	}

	// When a host already exposed a base VNC port (5900/5901), also probe any
	// higher display ports (5902..5919) discovered by Fingerprinter.walkVNCDisplays.
	if chk.Probe.Type == "vnc" && len(matchedPorts) > 0 {
		seen := make(map[int]struct{}, len(matchedPorts))
		for _, p := range matchedPorts {
			seen[p] = struct{}{}
		}
		for _, p := range hp.OpenPorts {
			if p >= 5900 && p <= 5919 {
				if _, dup := seen[p]; !dup {
					seen[p] = struct{}{}
					matchedPorts = append(matchedPorts, p)
				}
			}
		}
	}

	// Allow probe.port to pin a single specific port once preconditions pass.
	if chk.Probe.Port > 0 {
		return []int{chk.Probe.Port}, true
	}
	if len(matchedPorts) == 0 && (chk.Probe.Type == "observe" || isNonTCPProbe(chk.Probe.Type)) {
		return []int{0}, true
	}
	if len(matchedPorts) == 0 {
		return nil, false
	}
	return matchedPorts, true
}

// matchesMDNSService reports whether a single passive mDNS service record
// satisfies chk's mDNS type and positive/negative TXT regex preconditions.
// Untrusted third-party reflected advertisements are ignored so a forged mDNS
// packet from another LAN host cannot attach mDNS-gated findings to a victim.
func matchesMDNSService(chk *Check, svc probe.MDNSService) bool {
	if svc.Withdrawn || (svc.Reflected && !svc.TrustedReflector) {
		return false
	}
	typeOK := false
	for _, want := range chk.Preconditions.MDNSTypeAny {
		if strings.EqualFold(svc.Type, want) {
			typeOK = true
			break
		}
	}
	if !typeOK {
		return false
	}
	if chk.compiled.mdnsTXT != nil {
		txtOK := false
		for _, kv := range svc.TXT {
			if chk.compiled.mdnsTXT.MatchString(kv) {
				txtOK = true
				break
			}
		}
		if !txtOK {
			return false
		}
	}
	if chk.compiled.mdnsTXTNot != nil {
		for _, kv := range svc.TXT {
			if chk.compiled.mdnsTXTNot.MatchString(kv) {
				return false
			}
		}
	}
	return true
}

// matchesUPnPDevice reports whether a single UPnP/SSDP device record satisfies
// chk's UPnP device and service regex preconditions.
func matchesUPnPDevice(chk *Check, dev probe.UPnPDevice) bool {
	if chk.compiled.upnpDevice != nil {
		combined := strings.Join([]string{dev.ST, dev.DeviceType, dev.Manufacturer, dev.ModelName, dev.ModelNumber, dev.Server}, " ")
		if !chk.compiled.upnpDevice.MatchString(combined) {
			return false
		}
	}
	if chk.compiled.upnpService != nil {
		svcOK := false
		for _, st := range dev.ServiceTypes {
			if chk.compiled.upnpService.MatchString(st) {
				svcOK = true
				break
			}
		}
		if !svcOK && !chk.compiled.upnpService.MatchString(dev.ST) {
			return false
		}
	}
	return true
}

// matchesWSRecord reports whether a single WS-Discovery record satisfies chk's
// WS-Discovery type/scope regex precondition.
func matchesWSRecord(chk *Check, rec probe.WSDiscoveryRecord) bool {
	if chk.compiled.wsType == nil {
		return true
	}
	combined := strings.Join(append(append([]string(nil), rec.Types...), rec.Scopes...), " ")
	return chk.compiled.wsType.MatchString(combined)
}

// executeProbe runs the verification probe for a single check against ip:port.
func (r *Runner) executeProbe(ctx context.Context, chk *Check, ip string, port int) (string, bool) {
	return r.executeProbeProfile(ctx, chk, probe.HostProfile{}, ip, port)
}

// executeProbeProfile runs the verification probe for a single check against
// ip:port with access to already-fingerprinted host metadata (such as TLS state).
func (r *Runner) executeProbeProfile(ctx context.Context, chk *Check, hp probe.HostProfile, ip string, port int) (string, bool) {
	probeCtx, cancel := context.WithTimeout(ctx, chk.Probe.Timeout)
	defer cancel()

	switch chk.Probe.Type {
	case "tcp":
		return probeTCP(probeCtx, ip, port, chk)
	case "telnet":
		return probeTelnet(probeCtx, ip, port)
	case "http":
		return r.probeHTTP(probeCtx, hp, ip, port, chk)
	case "mqtt":
		return probeMQTT(probeCtx, ip, port)
	case "modbus":
		return probeModbus(probeCtx, ip, port)
	case "rtsp":
		return probeRTSP(probeCtx, ip, port)
	case "vnc":
		return probeVNC(probeCtx, ip, port)
	case "avr":
		return probeDenonMarantzAVR(probeCtx, ip, port)
	case "comfoconnect":
		return probeComfoConnect(probeCtx, ip, port)
	case "eth-rpc":
		return r.probeEthereumRPC(probeCtx, ip, port)
	case "adb":
		return probeADB(probeCtx, ip, port)
	case "rdp-nla":
		return probeRDPNoNLA(probeCtx, ip, port)
	case "ftp-anon":
		return probeFTPAnonymous(probeCtx, ip, port)
	case "esfile":
		return r.probeESFileExplorer(probeCtx, ip, port)
	case "redis":
		return probeRedisUnauth(probeCtx, ip, port)
	case "snmp":
		return probeSNMPReadOnly(probeCtx, ip, port, chk.Probe.Community)
	case "tls-legacy":
		return probeTLSLegacy(probeCtx, ip, port)
	case "memcached":
		return probeMemcached(probeCtx, ip, port)
	case "rsync":
		return probeRsync(probeCtx, ip, port)
	case "mpd":
		return probeMPD(probeCtx, ip, port)
	case "kasa":
		return probeKasa(probeCtx, ip, port)
	case "coap":
		return probeCoAP(probeCtx, ip, port)
	case "natpmp":
		return probeNATPMP(probeCtx, ip, port)
	case "ipp":
		return r.probeIPP(probeCtx, ip, port)
	case "ipmi":
		return probeIPMI(probeCtx, ip, port)
	case "bitcoin-p2p":
		return probeBitcoinP2P(probeCtx, ip, port)
	case "bitcoin-rpc":
		return r.probeBitcoinRPC(probeCtx, ip, port)
	case "eth-engine":
		return r.probeEthEngineAPI(probeCtx, ip, port)
	case "nut":
		return probeNUT(probeCtx, ip, port)
	case "lifx":
		return probeLIFX(probeCtx, ip, port)
	case "pjlink":
		return probePJLink(probeCtx, ip, port)
	case "nbns":
		return probeNBNS(probeCtx, ip, port)
	case "pcp":
		return probePCP(probeCtx, ip, port)
	case "dns-recursion":
		return probeDNSRecursion(probeCtx, ip, port)
	case "ntp":
		return probeNTP(probeCtx, ip, port)
	case "stun":
		return probeSTUN(probeCtx, ip, port)
	default:
		return "", false
	}
}

type findingEndpoint struct {
	transport string
	ips       []string
}

// observationIPs intersects explicit target addresses and family with the
// client inventory. Family alone identifies a target only if exactly one
// client address qualifies.
func observationIPs(cl unifi.Client, family string, targets []string) []string {
	family = strings.ToLower(strings.TrimSpace(family))
	ips := []string{}
	for _, raw := range cl.AllIPs() {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		if (family == "ipv4" && !addr.Is4()) || (family == "ipv6" && !addr.Is6()) {
			continue
		}
		if len(targets) > 0 && !slices.ContainsFunc(targets, func(target string) bool {
			a, err := netip.ParseAddr(target)
			return err == nil && a.Unmap() == addr
		}) {
			continue
		}
		if !slices.Contains(ips, addr.String()) {
			ips = append(ips, addr.String())
		}
	}
	if len(targets) == 0 && len(ips) != 1 {
		return []string{}
	}
	return ips
}

func findingEndpoints(chk *Check, hp probe.HostProfile, port int) []findingEndpoint {
	if chk.Probe.Type != "observe" {
		ips := []string{}
		if addr, err := netip.ParseAddr(hp.EffectiveProbeIP()); err == nil {
			ips = append(ips, addr.Unmap().String())
		}
		return []findingEndpoint{{chk.DefaultTransport(), ips}}
	}
	byTransport := make(map[string][]string)
	add := func(transport, family string, targets []string) {
		if transport == "" {
			transport = chk.DefaultTransport()
		}
		transport = strings.ToLower(transport)
		// Keep an explicitly empty observation when the address is unresolved.
		ips := byTransport[transport]
		if ips == nil {
			ips = []string{}
		}
		for _, ip := range observationIPs(hp.Client, family, targets) {
			if !slices.Contains(ips, ip) {
				ips = append(ips, ip)
			}
		}
		byTransport[transport] = ips
	}
	for _, md := range hp.MDNSServices {
		if md.Port == port && matchesMDNSService(chk, md) {
			targets := md.TargetIPs
			if !md.Reflected && md.ResponderIP != "" && len(targets) == 0 {
				targets = []string{md.ResponderIP}
			}
			add(md.Transport, md.AddressFamily, targets)
		}
	}
	for _, svc := range hp.Services {
		if svc.Port == port && slices.ContainsFunc(chk.Preconditions.ServiceProtoAny, func(want string) bool {
			return strings.EqualFold(want, svc.Protocol)
		}) {
			add(svc.Transport, svc.AddressFamily, nil)
		}
	}
	if chk.compiled.upnpDevice != nil || chk.compiled.upnpService != nil {
		for _, dev := range hp.UPnPDevices {
			if dev.Port == port && matchesUPnPDevice(chk, dev) {
				add("tcp", dev.AddressFamily, nil)
			}
		}
	}
	if chk.compiled.wsType != nil {
		for _, rec := range hp.WSDiscovery {
			if slices.Contains(rec.Ports, port) && matchesWSRecord(chk, rec) {
				add("tcp", rec.AddressFamily, nil)
			}
		}
	}
	if len(byTransport) == 0 {
		ips := []string{}
		if hp.HasPort(port) && (len(chk.Preconditions.PortsAny) > 0 || len(chk.Preconditions.PortsAll) > 0) {
			ips = observationIPs(hp.Client, "", []string{hp.EffectiveProbeIP()})
		}
		byTransport[chk.DefaultTransport()] = ips
	}
	var endpoints []findingEndpoint
	for transport, ips := range byTransport {
		endpoints = append(endpoints, findingEndpoint{transport, ips})
	}
	sort.Slice(endpoints, func(i, j int) bool { return endpoints[i].transport < endpoints[j].transport })
	return endpoints
}

// probeTCP confirms that ip:port accepts a TCP connection and optionally
// verifies a read-only server banner against probe.match.banner_regex.
func probeTCP(ctx context.Context, ip string, port int, chk *Check) (string, bool) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", false
	}
	defer conn.Close()

	if chk.compiled.banner == nil {
		return fmt.Sprintf("TCP port %d accepted connection", port), true
	}

	// Read up to maxBannerReadBytes within a short deadline for banner matching.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetReadDeadline(deadline)
	}
	buf := make([]byte, maxBannerReadBytes)
	n, _ := conn.Read(buf)
	if n == 0 || !chk.compiled.banner.Match(buf[:n]) {
		return "", false
	}
	return fmt.Sprintf("TCP port %d banner matched check signature", port), true
}

// probeHTTP executes strictly read-only, target-IP-only HTTP request(s) across
// Path / Paths and evaluates status, header, body, negative, and JSONPath matchers.
func (r *Runner) probeHTTP(ctx context.Context, hp probe.HostProfile, ip string, port int, chk *Check) (string, bool) {
	scheme := inferHTTPScheme(hp, port, chk)

	for _, path := range chk.httpPaths() {
		if ctx.Err() != nil {
			return "", false
		}
		targetURL := fmt.Sprintf("%s://%s%s", scheme, net.JoinHostPort(ip, strconv.Itoa(port)), path)
		req, err := http.NewRequestWithContext(ctx, chk.Probe.Method, targetURL, nil)
		if err != nil {
			return "", false
		}
		req.Header.Set("User-Agent", "UniBlue-Checker/0.1")
		for hk, hv := range chk.Probe.RequestHeaders {
			req.Header.Set(hk, hv)
		}

		resp, err := r.httpClient.Do(req)
		if err != nil {
			return "", false
		}
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxProbeBodyBytes))
		_ = resp.Body.Close()

		// Stop trying alternate paths if the service explicitly challenged authentication.
		if (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) &&
			!intInSlice(resp.StatusCode, chk.Probe.Match.Status) {
			return "", false
		}
		if !matchHTTPResponse(resp, bodyBytes, chk) {
			continue
		}
		if chk.Probe.Match.EvidenceSummary != "" {
			return fmt.Sprintf("%s (%s %s -> HTTP %d)", chk.Probe.Match.EvidenceSummary, chk.Probe.Method, path, resp.StatusCode), true
		}
		if chk.Claim == ClaimServiceObserved || chk.Claim == ClaimAssetIdentity {
			return fmt.Sprintf("%s %s returned HTTP %d (service observed)", chk.Probe.Method, path, resp.StatusCode), true
		}
		return fmt.Sprintf("%s %s returned HTTP %d without required authentication", chk.Probe.Method, path, resp.StatusCode), true
	}
	return "", false
}

// inferHTTPScheme resolves whether an HTTP probe should speak "http" or "https"
// by honoring explicit probe.scheme first, then fingerprinted HTTP banner or
// Nerva service TLS state, and finally well-known TLS management/web ports.
func inferHTTPScheme(hp probe.HostProfile, port int, chk *Check) string {
	if chk != nil && chk.Probe.Scheme != "" {
		return chk.Probe.Scheme
	}
	if banner, ok := hp.HTTP[port]; ok {
		if s := strings.ToLower(strings.TrimSpace(banner.Scheme)); s == "http" || s == "https" {
			return s
		}
	}
	for _, svc := range hp.Services {
		if svc.Port == port && (svc.TLS || strings.EqualFold(svc.Protocol, "https")) {
			return "https"
		}
	}
	switch port {
	case 443, 636, 993, 995, 5986, 8006, 8007, 8443, 9443, 10443, 16993, 16995:
		return "https"
	default:
		return "http"
	}
}

func matchHTTPResponse(resp *http.Response, bodyBytes []byte, chk *Check) bool {
	body := string(bodyBytes)
	m := chk.Probe.Match

	if len(m.Status) > 0 && !intInSlice(resp.StatusCode, m.Status) {
		return false
	}
	for _, h := range m.HeadersAbsent {
		if resp.Header.Get(h) != "" {
			return false
		}
	}
	for _, h := range m.HeadersPresent {
		if resp.Header.Get(h) == "" {
			return false
		}
	}
	for h, substr := range m.HeaderContains {
		if !strings.Contains(strings.ToLower(resp.Header.Get(h)), strings.ToLower(substr)) {
			return false
		}
	}
	for _, needle := range m.BodyContainsAll {
		if !strings.Contains(body, needle) {
			return false
		}
	}
	if len(m.BodyContainsAny) > 0 {
		found := false
		for _, needle := range m.BodyContainsAny {
			if strings.Contains(body, needle) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	for _, forbid := range m.BodyNotContains {
		if strings.Contains(body, forbid) {
			return false
		}
	}
	if chk.compiled.body != nil && !chk.compiled.body.MatchString(body) {
		return false
	}
	if chk.compiled.bodyNot != nil && chk.compiled.bodyNot.MatchString(body) {
		return false
	}
	if !matchJSONPredicates(bodyBytes, m.JSONMatch) {
		return false
	}
	return true
}

func hostHasObservedPort(hp probe.HostProfile, port int, allowUDP bool) bool {
	if hp.HasPort(port) {
		return true
	}
	if !allowUDP {
		return false
	}
	for _, svc := range hp.Services {
		if svc.Port == port {
			return true
		}
	}
	for _, md := range hp.MDNSServices {
		if !md.Withdrawn && md.Port == port {
			return true
		}
	}
	return false
}

// probeMQTT sends a minimal MQTT 3.1.1 CONNECT packet with no credentials and
// checks whether the broker responds with CONNACK return code 0 (Accepted).
// It immediately sends DISCONNECT to leave the broker in a clean state.
func probeMQTT(ctx context.Context, ip string, port int) (string, bool) {
	conn, err := dialWithContextDeadline(ctx, ip, port)
	if err != nil {
		return "", false
	}
	defer conn.Close()

	// Unique 12-byte ephemeral client ID: "uniblue-" + 4 random hex chars
	// so UniBlue never evicts an active client sharing a static ID.
	clientID := "uniblue-" + randomShortHex()
	remLen := byte(10 + 2 + len(clientID))
	connectPkt := make([]byte, 0, int(remLen)+2)
	connectPkt = append(connectPkt,
		0x10, remLen,
		0x00, 0x04, 'M', 'Q', 'T', 'T',
		0x04,       // Protocol level 3.1.1
		0x02,       // Clean Session, no username/password
		0x00, 0x0A, // Keep alive 10s
		0x00, byte(len(clientID)),
	)
	connectPkt = append(connectPkt, []byte(clientID)...)
	if _, err := conn.Write(connectPkt); err != nil {
		return "", false
	}

	// Read the 4-byte CONNACK packet: [0x20, 0x02, ackFlags, returnCode].
	resp := make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return "", false
	}
	if resp[0] != 0x20 || resp[1] != 0x02 || resp[3] != 0x00 {
		return "", false
	}

	// Gracefully disconnect so the broker does not keep a stale client session.
	_, _ = conn.Write([]byte{0xE0, 0x00})
	return "MQTT broker accepted anonymous CONNECT (CONNACK code 0)", true
}

// probeModbus sends a strictly read-only Modbus TCP "Read Device Identification"
// (FC 43 / MEI 14) request and verifies that the device replies with a valid
// Modbus TCP header (matching transaction ID and protocol ID 0x0000). Even a
// Modbus exception response proves an unauthenticated Modbus slave is active.
func probeModbus(ctx context.Context, ip string, port int) (string, bool) {
	conn, err := dialWithContextDeadline(ctx, ip, port)
	if err != nil {
		return "", false
	}
	defer conn.Close()

	// MBAP header (7 bytes) + Read Device Identification PDU (4 bytes):
	//   Transaction ID: 0x1337
	//   Protocol ID:    0x0000 (Modbus)
	//   Length:         0x0005 (Unit ID + 4-byte PDU)
	//   Unit ID:        0x01
	//   Function Code:  0x2B (43 - Encapsulated Interface Transport)
	//   MEI Type:       0x0E (14 - Read Device Identification)
	//   Read Code:      0x01 (Basic device identification)
	//   Object ID:      0x00 (VendorName)
	req := []byte{
		0x13, 0x37,
		0x00, 0x00,
		0x00, 0x05,
		0x01,
		0x2B, 0x0E, 0x01, 0x00,
	}
	if _, err := conn.Write(req); err != nil {
		return "", false
	}

	// Read the 7-byte MBAP header plus at least 1 function code byte.
	header := make([]byte, 8)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", false
	}
	txID := binary.BigEndian.Uint16(header[0:2])
	protoID := binary.BigEndian.Uint16(header[2:4])
	length := binary.BigEndian.Uint16(header[4:6])
	fc := header[7]

	if txID != 0x1337 || protoID != 0x0000 || length < 2 {
		return "", false
	}
	// Accept either a normal response (0x2B) or a standard Modbus exception
	// (0xAB = 0x2B | 0x80), both of which prove an active unauthenticated slave.
	if fc != 0x2B && fc != 0xAB {
		return "", false
	}
	return fmt.Sprintf("Modbus TCP slave responded without authentication (function code 0x%02X)", fc), true
}

type rtspResponse struct {
	statusCode       int
	hasAuthChallenge bool
	publicHeader     string
	contentType      string
	body             string
}

// probeRTSP sends a read-only RTSP OPTIONS request followed by a read-only
// DESCRIBE request (Accept: application/sdp) and reports an unauthenticated
// media server only when DESCRIBE returns 200 OK with SDP and no
// WWW-Authenticate challenge.
func probeRTSP(ctx context.Context, ip string, port int) (string, bool) {
	conn, err := dialWithContextDeadline(ctx, ip, port)
	if err != nil {
		return "", false
	}
	defer conn.Close()

	hostPort := net.JoinHostPort(ip, strconv.Itoa(port))
	optReq := fmt.Sprintf("OPTIONS rtsp://%s/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: UniBlue/0.1\r\n\r\n", hostPort)
	if _, err := io.WriteString(conn, optReq); err != nil {
		return "", false
	}

	reader := bufio.NewReader(conn)
	optResp, ok := readRTSPResponse(ctx, conn, reader, false)
	if !ok || optResp.statusCode != 200 || optResp.hasAuthChallenge {
		return "", false
	}

	// Many password-protected cameras and RTSP servers answer OPTIONS 200 OK
	// without WWW-Authenticate and only enforce auth on DESCRIBE/SETUP/PLAY.
	descReq := fmt.Sprintf("DESCRIBE rtsp://%s/ RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\nUser-Agent: UniBlue/0.1\r\n\r\n", hostPort)
	descResp, ok := sendRTSPDescribe(ctx, conn, reader, ip, port, descReq)
	if !ok || descResp.statusCode != 200 || descResp.hasAuthChallenge {
		return "", false
	}

	hasSDP := strings.Contains(strings.ToLower(descResp.contentType), "application/sdp") ||
		strings.Contains(descResp.body, "v=0") ||
		strings.Contains(descResp.body, "\nm=") ||
		strings.HasPrefix(descResp.body, "m=")
	if !hasSDP {
		return "", false
	}
	if optResp.publicHeader != "" {
		return fmt.Sprintf("RTSP DESCRIBE returned 200 OK with SDP without authentication (Public: %s)", optResp.publicHeader), true
	}
	return "RTSP DESCRIBE returned 200 OK with SDP without authentication", true
}

func sendRTSPDescribe(ctx context.Context, conn net.Conn, reader *bufio.Reader, ip string, port int, req string) (rtspResponse, bool) {
	if _, err := io.WriteString(conn, req); err == nil {
		if resp, ok := readRTSPResponse(ctx, conn, reader, true); ok {
			return resp, true
		}
	}
	// Some RTSP servers close the TCP connection after OPTIONS; reconnect once
	// for the read-only DESCRIBE probe.
	conn2, err := dialWithContextDeadline(ctx, ip, port)
	if err != nil {
		return rtspResponse{}, false
	}
	defer conn2.Close()
	if _, err := io.WriteString(conn2, req); err != nil {
		return rtspResponse{}, false
	}
	return readRTSPResponse(ctx, conn2, bufio.NewReader(conn2), true)
}

func readRTSPResponse(ctx context.Context, conn net.Conn, reader *bufio.Reader, wantBody bool) (rtspResponse, bool) {
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return rtspResponse{}, false
	}
	statusLine = strings.TrimSpace(statusLine)
	if !strings.HasPrefix(statusLine, "RTSP/1.") {
		return rtspResponse{}, false
	}
	fields := strings.Fields(statusLine)
	if len(fields) < 2 {
		return rtspResponse{}, false
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil {
		return rtspResponse{}, false
	}

	resp := rtspResponse{statusCode: code}
	contentLen := 0
	totalHeaderBytes := len(statusLine)
	for range 64 {
		line, err := reader.ReadString('\n')
		totalHeaderBytes += len(line)
		if totalHeaderBytes > 8192 {
			break
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			break
		}
		lower := strings.ToLower(trimmed)
		switch {
		case strings.HasPrefix(lower, "www-authenticate:"):
			resp.hasAuthChallenge = true
		case strings.HasPrefix(lower, "public:"):
			resp.publicHeader = strings.TrimSpace(trimmed[len("public:"):])
		case strings.HasPrefix(lower, "content-type:"):
			resp.contentType = strings.TrimSpace(trimmed[len("content-type:"):])
		case strings.HasPrefix(lower, "content-length:"):
			if n, convErr := strconv.Atoi(strings.TrimSpace(trimmed[len("content-length:"):])); convErr == nil && n > 0 {
				contentLen = n
			}
		}
		if err != nil {
			break
		}
	}

	if contentLen > 0 {
		toRead := contentLen
		if toRead > 4096 {
			toRead = 4096
		}
		body := make([]byte, toRead)
		n, _ := io.ReadFull(reader, body)
		if wantBody {
			resp.body = string(body[:n])
		}
	} else if wantBody && resp.statusCode == 200 && !strings.Contains(strings.ToLower(resp.contentType), "application/sdp") {
		shortDeadline := time.Now().Add(150 * time.Millisecond)
		if dl, ok := ctx.Deadline(); ok && dl.Before(shortDeadline) {
			shortDeadline = dl
		}
		_ = conn.SetReadDeadline(shortDeadline)
		buf := make([]byte, maxBannerReadBytes)
		n, _ := reader.Read(buf)
		if n > 0 {
			resp.body = string(buf[:n])
		}
	}
	return resp, true
}

// probeTelnet connects to a Telnet service, politely declines IAC option
// negotiations (replying WONT/DONT), and reads the initial banner so operators
// know whether the port exposes a login prompt, an unauthenticated shell, or
// a silent custom protocol instead of a blind "port 23 open" warning.
func probeTelnet(ctx context.Context, ip string, port int) (string, bool) {
	conn, err := dialWithContextDeadline(ctx, ip, port)
	if err != nil {
		return "", false
	}
	defer conn.Close()

	// Give the daemon up to ~1s to send IAC negotiations and a greeting banner
	// without stalling the full probe timeout on silent services.
	shortDeadline := time.Now().Add(1200 * time.Millisecond)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(shortDeadline) {
		shortDeadline = ctxDeadline
	}
	_ = conn.SetReadDeadline(shortDeadline)

	var text bytes.Buffer
	buf := make([]byte, 512)
	for text.Len() < 512 {
		n, readErr := conn.Read(buf)
		if n > 0 {
			reply, cleaned := stripTelnetIAC(buf[:n])
			if len(reply) > 0 {
				_, _ = conn.Write(reply)
			}
			text.Write(cleaned)
			// Stop early once we see a recognizable prompt.
			lower := strings.ToLower(text.String())
			if strings.Contains(lower, "login:") || strings.Contains(lower, "password:") ||
				strings.Contains(lower, "username:") || strings.HasSuffix(strings.TrimSpace(lower), "#") ||
				strings.HasSuffix(strings.TrimSpace(lower), "$") || strings.HasSuffix(strings.TrimSpace(lower), ">") {
				break
			}
		}
		if readErr != nil {
			break
		}
	}

	banner := compactASCII(text.String(), 120)
	lower := strings.ToLower(banner)
	switch {
	case banner == "":
		return "Telnet port 23 accepted connection (silent/no banner; likely custom cleartext control protocol)", true
	case strings.Contains(lower, "login:") || strings.Contains(lower, "username:") || strings.Contains(lower, "password:"):
		return fmt.Sprintf("cleartext Telnet login prompt observed (%q)", banner), true
	case strings.HasSuffix(banner, "#") || strings.HasSuffix(banner, "$") || strings.HasSuffix(banner, ">"):
		return fmt.Sprintf("unauthenticated Telnet command prompt observed without login (%q)", banner), true
	default:
		return fmt.Sprintf("cleartext Telnet banner observed (%q)", banner), true
	}
}

// stripTelnetIAC parses RFC 854 Telnet IAC (0xFF) negotiation triplets,
// generating polite WONT/DONT refusals so standard telnetd proceeds to emit its
// login/shell banner, and returning the remaining printable payload bytes.
func stripTelnetIAC(data []byte) (reply []byte, cleaned []byte) {
	const (
		iac  = 255
		will = 251
		wont = 252
		do   = 253
		dont = 254
		sb   = 250
		se   = 240
	)
	for i := 0; i < len(data); {
		if data[i] != iac {
			cleaned = append(cleaned, data[i])
			i++
			continue
		}
		if i+1 >= len(data) {
			break
		}
		cmd := data[i+1]
		switch cmd {
		case will, wont, do, dont:
			if i+2 >= len(data) {
				return reply, cleaned
			}
			opt := data[i+2]
			if cmd == do {
				reply = append(reply, iac, wont, opt)
			} else if cmd == will {
				reply = append(reply, iac, dont, opt)
			}
			i += 3
		case sb:
			// Skip subnegotiation payload through IAC SE.
			i += 2
			for i+1 < len(data) && !(data[i] == iac && data[i+1] == se) {
				i++
			}
			i += 2
		default:
			i += 2
		}
	}
	return reply, cleaned
}

// probeDenonMarantzAVR sends a strictly read-only status query ("PW?\r",
// Power State query) to a Denon/Marantz AVR Telnet control port. Receiving
// "PWON" or "PWSTANDBY" confirms unauthenticated control access without
// changing power, volume, or input state.
func probeDenonMarantzAVR(ctx context.Context, ip string, port int) (string, bool) {
	conn, err := dialWithContextDeadline(ctx, ip, port)
	if err != nil {
		return "", false
	}
	defer conn.Close()

	if _, err := io.WriteString(conn, "PW?\r"); err != nil {
		return "", false
	}

	buf := make([]byte, 128)
	n, _ := conn.Read(buf)
	if n == 0 {
		return "", false
	}
	resp := compactASCII(string(buf[:n]), 80)
	if strings.Contains(resp, "PWON") || strings.Contains(resp, "PWSTANDBY") {
		return fmt.Sprintf("confirmed unauthenticated AVR control via read-only query PW? -> %q", resp), true
	}
	return "", false
}

// probeComfoConnect sends a strictly read-only 2-byte unicast UDP discovery
// beacon (0x0a 0x00) directly to the target host on port 56747 to verify it is
// an active Zehnder ComfoConnect LAN C bridge without ever attempting app
// registration or disrupting an existing Home Assistant TCP session.
func probeComfoConnect(ctx context.Context, ip string, port int) (string, bool) {
	// First confirm TCP port 56747 is listening.
	tcpConn, err := dialWithContextDeadline(ctx, ip, port)
	if err != nil {
		return "", false
	}
	_ = tcpConn.Close()

	// Send unicast read-only UDP discovery request (protobuf SearchGatewayRequest = 0x0a 0x00).
	udpConn, err := (&net.Dialer{}).DialContext(ctx, "udp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return fmt.Sprintf("TCP port %d accepted connection (ComfoConnect control API)", port), true
	}
	defer udpConn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = udpConn.SetDeadline(deadline)
	}
	if _, err := udpConn.Write([]byte{0x0a, 0x00}); err == nil {
		buf := make([]byte, 256)
		if n, readErr := udpConn.Read(buf); readErr == nil && n >= 8 {
			// Discovery response ends with the bridge UUID/MAC identifier.
			return fmt.Sprintf("confirmed active ComfoConnect LAN C bridge via read-only UDP discovery (%d-byte response) + TCP:%d open", n, port), true
		}
	}
	return fmt.Sprintf("TCP port %d accepted connection (ComfoConnect control API)", port), true
}

// probeVNC completes the read-only RFB initialization handshake when security
// type 1 ("None") is offered: it selects None, confirms SecurityResult == 0
// (authentication genuinely bypassed), sends ClientInit with shared=1 so any
// active viewer is never disconnected, and reads ServerInit to report the exact
// exposed desktop name and framebuffer dimensions, without sending input or
// reading screen pixels.
func probeVNC(ctx context.Context, ip string, port int) (string, bool) {
	conn, err := dialWithContextDeadline(ctx, ip, port)
	if err != nil {
		return "", false
	}
	defer conn.Close()

	// Step 1: Read the 12-byte RFB server version banner (e.g., "RFB 003.008\n").
	version := make([]byte, 12)
	if _, err := io.ReadFull(conn, version); err != nil {
		return "", false
	}
	if !bytes.HasPrefix(version, []byte("RFB ")) || version[11] != '\n' {
		return "", false
	}

	// Negotiate RFB 3.8 if supported, otherwise echo the server's 3.3/3.7 version.
	isRFB33 := bytes.HasPrefix(version, []byte("RFB 003.003"))
	isRFB37 := bytes.HasPrefix(version, []byte("RFB 003.007"))
	clientVer := []byte("RFB 003.008\n")
	if isRFB33 {
		clientVer = []byte("RFB 003.003\n")
	} else if isRFB37 {
		clientVer = []byte("RFB 003.007\n")
	}
	if _, err := conn.Write(clientVer); err != nil {
		return "", false
	}

	// Step 2: Confirm security type 1 ("None") is offered and accepted.
	if isRFB33 {
		sec := make([]byte, 4)
		if _, err := io.ReadFull(conn, sec); err != nil {
			return "", false
		}
		if binary.BigEndian.Uint32(sec) != 1 {
			return "", false
		}
	} else {
		countBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, countBuf); err != nil || countBuf[0] == 0 {
			return "", false
		}
		types := make([]byte, int(countBuf[0]))
		if _, err := io.ReadFull(conn, types); err != nil {
			return "", false
		}
		hasNone := false
		for _, t := range types {
			if t == 1 {
				hasNone = true
				break
			}
		}
		if !hasNone {
			return "", false
		}
		// Select security type 1 (None).
		if _, err := conn.Write([]byte{0x01}); err != nil {
			return "", false
		}
		// RFB 3.8 sends a 4-byte SecurityResult (0 = OK); reject false positives
		// where the server advertised None in its list but fails SecurityResult.
		if !isRFB37 {
			secRes := make([]byte, 4)
			if _, err := io.ReadFull(conn, secRes); err != nil {
				return "", false
			}
			if binary.BigEndian.Uint32(secRes) != 0 {
				return "", false
			}
		}
	}

	// Step 3: Send ClientInit with shared-flag=1 (never kicks off active sessions)
	// and read ServerInit to identify which VM or desktop is actually exposed.
	if _, err := conn.Write([]byte{0x01}); err != nil {
		return "confirmed passwordless VNC access (RFB SecurityResult=OK)", true
	}
	// ServerInit fixed header: 2B width + 2B height + 16B pixel-format + 4B name-length = 24 bytes.
	initHdr := make([]byte, 24)
	if _, err := io.ReadFull(conn, initHdr); err != nil {
		return "confirmed passwordless VNC access (RFB SecurityResult=OK)", true
	}
	width := binary.BigEndian.Uint16(initHdr[0:2])
	height := binary.BigEndian.Uint16(initHdr[2:4])
	nameLen := binary.BigEndian.Uint32(initHdr[20:24])

	var desktopName string
	if nameLen > 0 && nameLen <= 256 {
		nameBuf := make([]byte, nameLen)
		if _, err := io.ReadFull(conn, nameBuf); err == nil {
			desktopName = compactASCII(string(nameBuf), 80)
		}
	}

	if desktopName != "" {
		return fmt.Sprintf("confirmed passwordless VNC session: desktop %q (%dx%d, RFB None)", desktopName, width, height), true
	}
	return fmt.Sprintf("confirmed passwordless VNC session (%dx%d, RFB None)", width, height), true
}

// probeEthereumRPC sends a strictly read-only JSON-RPC "web3_clientVersion"
// query to confirm an unauthenticated Ethereum Execution RPC endpoint and
// identify the exact client software (e.g., Geth, Reth, Nethermind, Besu).
func (r *Runner) probeEthereumRPC(ctx context.Context, ip string, port int) (string, bool) {
	targetURL := fmt.Sprintf("http://%s/", net.JoinHostPort(ip, strconv.Itoa(port)))
	payload := `{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}`

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, strings.NewReader(payload))
	if err != nil {
		return "", false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "UniBlue-Checker/0.1")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var rpcResp struct {
		Result string `json:"result"`
	}
	if err := json.Unmarshal(bodyBytes, &rpcResp); err != nil || strings.TrimSpace(rpcResp.Result) == "" {
		return "", false
	}
	return fmt.Sprintf("confirmed unauthenticated Ethereum JSON-RPC: web3_clientVersion -> %q", compactASCII(rpcResp.Result, 96)), true
}

// probeADB sends a strictly read-only ADB CNXN handshake packet to TCP port
// 5555 and checks whether the target accepts the session directly with CNXN
// (no RSA key authentication required). When the device responds with AUTH,
// the connection is closed immediately without sending any key so no on-screen
// prompt is ever triggered on Android TV / Fire TV devices.
func probeADB(ctx context.Context, ip string, port int) (string, bool) {
	conn, err := dialWithContextDeadline(ctx, ip, port)
	if err != nil {
		return "", false
	}
	defer conn.Close()

	const (
		adbCmdCNXN    uint32 = 0x4E584E43 // "CNXN" in little-endian
		adbVersion    uint32 = 0x01000000
		adbMaxPayload uint32 = 0x00004000
	)
	payload := []byte("host::\x00")
	var checksum uint32
	for _, b := range payload {
		checksum += uint32(b)
	}

	pkt := make([]byte, 24+len(payload))
	binary.LittleEndian.PutUint32(pkt[0:4], adbCmdCNXN)
	binary.LittleEndian.PutUint32(pkt[4:8], adbVersion)
	binary.LittleEndian.PutUint32(pkt[8:12], adbMaxPayload)
	binary.LittleEndian.PutUint32(pkt[12:16], uint32(len(payload)))
	binary.LittleEndian.PutUint32(pkt[16:20], checksum)
	binary.LittleEndian.PutUint32(pkt[20:24], adbCmdCNXN^0xffffffff)
	copy(pkt[24:], payload)

	if _, err := conn.Write(pkt); err != nil {
		return "", false
	}

	hdr := make([]byte, 24)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return "", false
	}
	respCmd := binary.LittleEndian.Uint32(hdr[0:4])
	respLen := binary.LittleEndian.Uint32(hdr[12:16])
	respMagic := binary.LittleEndian.Uint32(hdr[20:24])
	if respMagic != respCmd^0xffffffff || respCmd != adbCmdCNXN {
		return "", false
	}

	// Read the device identity banner (e.g., "device::ro.product.model=...") if present.
	var banner string
	if respLen > 0 && respLen <= 4096 {
		buf := make([]byte, respLen)
		if _, err := io.ReadFull(conn, buf); err == nil {
			banner = compactASCII(string(buf), 100)
		}
	}
	if banner != "" {
		return fmt.Sprintf("confirmed unauthenticated ADB shell access (CNXN accepted without AUTH: %q)", banner), true
	}
	return "confirmed unauthenticated ADB shell access (CNXN accepted without AUTH)", true
}

// probeRDPNoNLA sends a read-only TPKT + X.224 Connection Request with an
// RDP_NEG_REQ offering PROTOCOL_RDP | PROTOCOL_SSL (0x00000001, no CredSSP/NLA).
// Servers enforcing Network Level Authentication reply with TYPE_RDP_NEG_FAILURE
// (0x03) and HYBRID_REQUIRED_BY_SERVER; servers with NLA disabled (including
// TLS-required SecurityLayer=2 servers) accept PROTOCOL_SSL (0x01) or
// PROTOCOL_RDP (0x00). If a legacy server refuses SSL with
// SSL_NOT_ALLOWED_BY_SERVER (0x02) or SSL_CERT_NOT_ON_SERVER (0x03), the probe
// retries once offering only PROTOCOL_RDP (0x00000000).
func probeRDPNoNLA(ctx context.Context, ip string, port int) (string, bool) {
	const (
		rdpProtoRDP               uint32 = 0x00000000
		rdpProtoSSL               uint32 = 0x00000001
		rdpFailSSLRequired        uint32 = 0x00000001
		rdpFailSSLNotAllowed      uint32 = 0x00000002
		rdpFailSSLCertNotOnServer uint32 = 0x00000003
	)

	ev, matched, failCode := probeRDPWithProtocol(ctx, ip, port, rdpProtoSSL)
	if matched {
		return ev, true
	}
	if failCode == rdpFailSSLNotAllowed || failCode == rdpFailSSLCertNotOnServer {
		ev, matched, _ = probeRDPWithProtocol(ctx, ip, port, rdpProtoRDP)
		return ev, matched
	}
	_ = rdpFailSSLRequired
	return "", false
}

func probeRDPWithProtocol(ctx context.Context, ip string, port int, requestedProto uint32) (string, bool, uint32) {
	conn, err := dialWithContextDeadline(ctx, ip, port)
	if err != nil {
		return "", false, 0
	}
	defer conn.Close()

	// 19-byte TPKT + X.224 CR + 8-byte RDP_NEG_REQ.
	req := []byte{
		0x03, 0x00, 0x00, 0x13, // TPKT v3, reserved 0, total length 19
		0x0e,       // X.224 length indicator (14 bytes follow)
		0xe0,       // X.224 Connection Request (CR)
		0x00, 0x00, // DST-REF
		0x00, 0x00, // SRC-REF
		0x00,       // Class 0
		0x01, 0x00, // TYPE_RDP_NEG_REQ (0x01), flags (0x00)
		0x08, 0x00, // length = 8 (little-endian)
		0x00, 0x00, 0x00, 0x00, // requestedProtocols (filled below)
	}
	binary.LittleEndian.PutUint32(req[15:19], requestedProto)
	if _, err := conn.Write(req); err != nil {
		return "", false, 0
	}

	// Read TPKT 4-byte header first, then the remaining payload (bounded to 512B).
	tpkt := make([]byte, 4)
	if _, err := io.ReadFull(conn, tpkt); err != nil {
		return "", false, 0
	}
	if tpkt[0] != 0x03 || tpkt[1] != 0x00 {
		return "", false, 0
	}
	totalLen := int(binary.BigEndian.Uint16(tpkt[2:4]))
	if totalLen < 11 || totalLen > 512 {
		return "", false, 0
	}
	body := make([]byte, totalLen-4)
	if _, err := io.ReadFull(conn, body); err != nil {
		return "", false, 0
	}
	// body[1] must be X.224 Connection Confirm (0xD0).
	if len(body) < 7 || body[1] != 0xd0 {
		return "", false, 0
	}
	// If the server omitted RDP_NEG_RSP entirely, it accepted legacy RDP security.
	if len(body) == 7 {
		return "RDP server accepted legacy PROTOCOL_RDP without Network Level Authentication (no RDP_NEG_RSP)", true, 0
	}
	// Otherwise inspect the 8-byte RDP_NEG_RSP / RDP_NEG_FAILURE block at body[7:].
	if len(body) < 15 {
		return "", false, 0
	}
	negType := body[7]
	if negType == 0x03 { // TYPE_RDP_NEG_FAILURE
		return "", false, binary.LittleEndian.Uint32(body[11:15])
	}
	if negType != 0x02 { // 0x02 = TYPE_RDP_NEG_RSP
		return "", false, 0
	}
	selectedProto := binary.LittleEndian.Uint32(body[11:15])
	switch selectedProto {
	case 0x00000000:
		return "RDP server accepted standard PROTOCOL_RDP with Network Level Authentication (NLA) disabled", true, 0
	case 0x00000001:
		return "RDP server accepted TLS-only PROTOCOL_SSL with Network Level Authentication (NLA) disabled", true, 0
	default:
		return "", false, 0
	}
}

// probeFTPAnonymous checks whether an FTP daemon accepts anonymous login
// ("USER anonymous" / "PASS uniblue@local") and immediately sends QUIT so no
// files are listed or modified.
func probeFTPAnonymous(ctx context.Context, ip string, port int) (string, bool) {
	conn, err := dialWithContextDeadline(ctx, ip, port)
	if err != nil {
		return "", false
	}
	defer conn.Close()

	br := bufio.NewReader(io.LimitReader(conn, 4096))
	code, greeting, ok := readFTPResponse(br)
	if !ok || code != 220 {
		return "", false
	}

	if _, err := io.WriteString(conn, "USER anonymous\r\n"); err != nil {
		return "", false
	}
	code, _, ok = readFTPResponse(br)
	if !ok {
		return "", false
	}
	if code == 331 {
		if _, err := io.WriteString(conn, "PASS uniblue@local\r\n"); err != nil {
			return "", false
		}
		code, _, ok = readFTPResponse(br)
		if !ok {
			return "", false
		}
	}
	if code != 230 {
		return "", false
	}
	_, _ = io.WriteString(conn, "QUIT\r\n")
	return fmt.Sprintf("FTP server accepted anonymous login (230 OK; banner %q)", compactASCII(greeting, 80)), true
}

// readFTPResponse reads a single-line or multi-line RFC 959 FTP reply and
// returns its 3-digit numeric status code and final message text.
func readFTPResponse(br *bufio.Reader) (int, string, bool) {
	for range 16 {
		line, err := br.ReadString('\n')
		if err != nil && len(line) == 0 {
			return 0, "", false
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 3 {
			continue
		}
		code, err := strconv.Atoi(line[:3])
		if err != nil {
			continue
		}
		if len(line) == 3 || line[3] == ' ' {
			return code, strings.TrimSpace(line[3:]), true
		}
	}
	return 0, "", false
}

// probeESFileExplorer sends a strictly read-only {"command":"getDeviceInfo"}
// request to TCP port 59777 to confirm CVE-2019-6447 (ES File Explorer's
// unauthenticated local HTTP server on Android) without listing files or apps.
func (r *Runner) probeESFileExplorer(ctx context.Context, ip string, port int) (string, bool) {
	targetURL := fmt.Sprintf("http://%s/", net.JoinHostPort(ip, strconv.Itoa(port)))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, strings.NewReader(`{"command":"getDeviceInfo"}`))
	if err != nil {
		return "", false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "UniBlue-Checker/0.1")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var info struct {
		Name    string `json:"name"`
		Model   string `json:"model"`
		Version string `json:"version"`
		SDK     string `json:"sdk"`
	}
	if err := json.Unmarshal(bodyBytes, &info); err != nil {
		return "", false
	}
	if info.Model == "" && info.SDK == "" {
		return "", false
	}
	return fmt.Sprintf("confirmed ES File Explorer CVE-2019-6447 unauthenticated HTTP server (model=%q, android=%q)",
		compactASCII(info.Model, 48), compactASCII(info.Version, 16)), true
}

// probeRedisUnauth sends a single read-only RESP "PING\r\n" command and checks
// for "+PONG\r\n", confirming Redis accepts commands without authentication.
func probeRedisUnauth(ctx context.Context, ip string, port int) (string, bool) {
	conn, err := dialWithContextDeadline(ctx, ip, port)
	if err != nil {
		return "", false
	}
	defer conn.Close()

	if _, err := io.WriteString(conn, "PING\r\n"); err != nil {
		return "", false
	}
	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return "", false
	}
	if strings.HasPrefix(string(buf[:n]), "+PONG") {
		return "Redis server replied +PONG to unauthenticated PING (no requirepass/ACL)", true
	}
	return "", false
}

// compactASCII strips control bytes, collapses whitespace, and caps length so
// device banners render cleanly in reports without terminal escape injection.
func compactASCII(s string, maxLen int) string {
	var b strings.Builder
	for _, r := range s {
		if r == '\r' || r == '\n' || r == '\t' {
			b.WriteByte(' ')
		} else if r >= 0x20 && r <= 0x7E {
			b.WriteRune(r)
		}
	}
	clean := strings.Join(strings.Fields(b.String()), " ")
	if len(clean) > maxLen {
		return clean[:maxLen-3] + "..."
	}
	return clean
}

// dialWithContextDeadline dials a TCP address and applies the context's
// deadline to all subsequent reads and writes on the connection.
func dialWithContextDeadline(ctx context.Context, ip string, port int) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	return conn, nil
}

// intInSlice reports whether target is present in values.
func intInSlice(target int, values []int) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}
