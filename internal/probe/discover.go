// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// mdnsMulticastAddr is the IPv4 RFC 6762 mDNS multicast group.
	mdnsMulticastAddr = "224.0.0.251:5353"

	// ssdpMulticastAddr is the IPv4 SSDP/UPnP multicast group.
	ssdpMulticastAddr = "239.255.255.250:1900"

	// wsDiscoveryAddr is the IPv4 WS-Discovery multicast group (ONVIF & WSD).
	wsDiscoveryAddr = "239.255.255.250:3702"

	// maxUPnPDescBytes caps fetched UPnP XML device description documents.
	maxUPnPDescBytes = 64 * 1024

	// discoveryWindow bounds the one-shot multicast collection window per scan.
	discoveryWindow = 1400 * time.Millisecond
)

// mdnsQueryTypes lists high-signal DNS-SD service types queried in a single
// bounded browse pass so UniBlue discovers exact ports, models, and security
// posture across hundreds of smart-home, media, printer, and mobile ecosystems
// without blind port scanning.
var mdnsQueryTypes = []string{
	"_services._dns-sd._udp.local.",
	"_http._tcp.local.",
	"_https._tcp.local.",
	"_ipp._tcp.local.",
	"_ipps._tcp.local.",
	"_uscan._tcp.local.",
	"_uscans._tcp.local.",
	"_pdl-datastream._tcp.local.",
	"_esphomelib._tcp.local.",
	"_home-assistant._tcp.local.",
	"_googlecast._tcp.local.",
	"_airplay._tcp.local.",
	"_raop._tcp.local.",
	"_sonos._tcp.local.",
	"_hap._tcp.local.",
	"_hue._tcp.local.",
	"_wled._tcp.local.",
	"_hwenergy._tcp.local.",
	"_homewizard._tcp.local.",
	"_enphase-envoy._tcp.local.",
	"_octoprint._tcp.local.",
	"_axis-video._tcp.local.",
	"_dkapi._tcp.local.",
	"_soundtouch._tcp.local.",
	"_musc._tcp.local.",
	"_linkplay._tcp.local.",
	"_xbmc-jsonrpc-h._tcp.local.",
	"_plexmediasvr._tcp.local.",
	"_Volumio._tcp.local.",
	"_afpovertcp._tcp.local.",
	"_adisk._tcp.local.",
	"_apple-mobdev2._tcp.local.",
	"_adb-tls-connect._tcp.local.",
	"_adb-tls-pairing._tcp.local.",
	"_zwave-js-server._tcp.local.",
	"_miio._udp.local.",
	"_lifx._udp.local.",
	"_nanoleafapi._tcp.local.",
	"_homeconnect._tcp.local.",
	"_heos-audio._tcp.local.",
	"_viziocast._tcp.local.",
	"_philipstv_rpc._tcp.local.",
	"_androidtvremote2._tcp.local.",
	"_slzb-06._tcp.local.",
	"_uzg-01._tcp.local.",
	"_zigbee-coordinator._tcp.local.",
	"_airgradient._tcp.local.",
	"_rfb._tcp.local.",
	"_smb._tcp.local.",
	// Additional smart-home, media, lighting, energy, and infrastructure DNS-SD types:
	"_matter._tcp.local.",
	"_matterc._udp.local.",
	"_meshcop._udp.local.",
	"_shelly._tcp.local.",
	"_openevse._tcp.local.",
	"_solaredge-modbus._tcp.local.",
	"_lutron._tcp.local.",
	"_powerview._tcp.local.",
	"_powerview-g3._tcp.local.",
	"_nut._tcp.local.",
	"_hap._udp.local.",
	"_homekit._tcp.local.",
	"_printer._tcp.local.",
	"_bond._tcp.local.",
	"_ecobee._tcp.local.",
	"_plugwise._tcp.local.",
	"_mypv._tcp.local.",
	"_nrgkick._tcp.local.",
	"_solarman._tcp.local.",
	"_mass._tcp.local.",
	"_wyoming._tcp.local.",
	"_kizbox._tcp.local.",
	"_deako._tcp.local.",
	"_elg._tcp.local.",
	"_bangolufsen._tcp.local.",
	"_devialet-http._tcp.local.",
	"_stream-magic._tcp.local.",
	"_technove-stations._tcp.local.",
}

// safeMDNSTXTKeys restricts persisted DNS-SD TXT attributes to benign model,
// protocol, and posture keys so room names, SSIDs, or tokens are never stored.
var safeMDNSTXTKeys = map[string]struct{}{
	"md": {}, "ty": {}, "pv": {}, "sf": {}, "rp": {}, "rs": {},
	"api_version": {}, "version": {}, "ver": {}, "fw": {}, "firmware": {},
	"model": {}, "product": {}, "board": {}, "platform": {}, "mac": {}, "macaddress": {},
	"api_encryption": {}, "network": {}, "gen": {}, "auth": {}, "auth_en": {},
	"usb_mfg": {}, "usb_mdl": {}, "pdl": {}, "txtvers": {}, "am": {},
	// Matter, Thread (MeshCoP), IPP/IPPS, Shelly, and NUT allowlisted metadata keys:
	"d": {}, "vp": {}, "cm": {}, "dt": {}, "ph": {}, "pi": {}, "sii": {}, "sai": {}, "t": {},
	"tv": {}, "sb": {}, "at": {}, "pt": {}, "sq": {}, "vn": {}, "mn": {}, "id": {},
	"app": {}, "qtotal": {}, "adminurl": {}, "urf": {}, "color": {}, "duplex": {}, "tls": {},
}

// MDNSService records a single DNS-SD service advertisement observed on the LAN
// along with observer, address-family, target, freshness, and reflection provenance.
type MDNSService struct {
	// Type is the normalized DNS-SD service type (e.g., "_esphomelib._tcp").
	Type string `json:"type"`

	// Instance is the advertised instance label (e.g., "living-room-sensor").
	Instance string `json:"instance,omitempty"`

	// Port is the SRV target port advertised by the service.
	Port int `json:"port,omitempty"`

	// Transport is the real L4 transport ("tcp" or "udp"). Note: Matter operational
	// (_matter._tcp) uses UDP despite its DNS-SD _tcp label.
	Transport string `json:"transport,omitempty"`

	// TargetHost is the SRV target hostname (e.g., "printer.local").
	TargetHost string `json:"target_host,omitempty"`

	// TargetIPs lists resolved IPv4 and/or IPv6 addresses for TargetHost.
	TargetIPs []string `json:"target_ips,omitempty"`

	// ResponderIP is the source IP that sent the multicast/unicast mDNS packet.
	ResponderIP string `json:"responder_ip,omitempty"`

	// Reflected is true when ResponderIP differs from the resolved target host IP,
	// indicating an mDNS proxy/reflector forwarded the advertisement across VLANs.
	Reflected bool `json:"reflected,omitempty"`

	// AddressFamily records "ipv4", "ipv6", or "dual".
	AddressFamily string `json:"address_family,omitempty"`

	// ObserverInterface names the local interface where the record was received.
	ObserverInterface string `json:"observer_interface,omitempty"`

	// ObserverVLAN names the VLAN or zone of the observing interface.
	ObserverVLAN string `json:"observer_vlan,omitempty"`

	// ObservedAt records when this advertisement was last received.
	ObservedAt *time.Time `json:"observed_at,omitempty"`

	// TTLSeconds is the DNS record TTL from the advertisement.
	TTLSeconds uint32 `json:"ttl_seconds,omitempty"`

	// ExpiresAt records when this cached advertisement expires.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`

	// Withdrawn is true when an RFC 6762 TTL=0 goodbye packet revoked this service.
	Withdrawn bool `json:"withdrawn,omitempty"`

	// TXT holds allowlisted key=value metadata pairs (e.g., "sf=1", "api_encryption=Noise_NNpsk0").
	TXT []string `json:"txt,omitempty"`
}

// UPnPDevice records one SSDP / UPnP device advertisement and its validated
// same-host XML device description summary.
type UPnPDevice struct {
	// ST is the SSDP Search Target / Notification Type URN.
	ST string `json:"st,omitempty"`

	// Server is the SSDP SERVER header (e.g., "Linux/4.14 UPnP/1.0 MiniUPnPd/2.3").
	Server string `json:"server,omitempty"`

	// Port is the TCP port extracted from the pinned same-host LOCATION URL.
	Port int `json:"port,omitempty"`

	// DeviceType is the XML <deviceType> URN.
	DeviceType string `json:"device_type,omitempty"`

	// Manufacturer is the XML <manufacturer> string.
	Manufacturer string `json:"manufacturer,omitempty"`

	// ModelName is the XML <modelName> string.
	ModelName string `json:"model_name,omitempty"`

	// ModelNumber is the XML <modelNumber> string.
	ModelNumber string `json:"model_number,omitempty"`

	// ServiceTypes lists normalized XML <serviceType> URNs advertised by the device.
	ServiceTypes []string `json:"service_types,omitempty"`

	// ObserverInterface, ObserverVLAN, AddressFamily, ObservedAt, and ExpiresAt
	// capture where and when this SSDP advertisement was seen.
	ObserverInterface string     `json:"observer_interface,omitempty"`
	ObserverVLAN      string     `json:"observer_vlan,omitempty"`
	AddressFamily     string     `json:"address_family,omitempty"`
	ObservedAt        *time.Time `json:"observed_at,omitempty"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
	Withdrawn         bool       `json:"withdrawn,omitempty"`
}

// WSDiscoveryRecord stores one WS-Discovery ProbeMatch (ONVIF cameras, WSD printers/hosts).
type WSDiscoveryRecord struct {
	// Types lists resolved local-name device types (e.g., "NetworkVideoTransmitter").
	Types []string `json:"types,omitempty"`

	// Scopes lists allowlisted non-sensitive scope tokens (e.g., "onvif://www.onvif.org/type/video_encoder").
	Scopes []string `json:"scopes,omitempty"`

	// Ports lists TCP ports parsed from same-host XAddr HTTP(S) URLs.
	Ports []int `json:"ports,omitempty"`

	// ObserverInterface, ObserverVLAN, AddressFamily, and ObservedAt capture provenance.
	ObserverInterface string     `json:"observer_interface,omitempty"`
	ObserverVLAN      string     `json:"observer_vlan,omitempty"`
	AddressFamily     string     `json:"address_family,omitempty"`
	ObservedAt        *time.Time `json:"observed_at,omitempty"`
}

// LANDiscovery holds all passive/multicast observations indexed by IPv4/IPv6 address.
type LANDiscovery struct {
	MDNS        map[string][]MDNSService
	UPnP        map[string][]UPnPDevice
	WSDiscovery map[string][]WSDiscoveryRecord
	PortsByIP   map[string][]int
	RawPrintIPs map[string]map[int]struct{}
	Unavailable map[string]string // observer VLAN/interface -> reason when discovery was unavailable
}

// DiscoveryCache retains durable, TTL-bounded passive discovery observations
// across full-scan and live recomputations, supporting IPv4/IPv6 AAAA records,
// RFC 6762 TTL=0 goodbye withdrawal, and reflection tracking.
type DiscoveryCache struct {
	mu       sync.RWMutex
	mdnsInst map[string]*cachedMDNSInst
	hostIPs  map[string]map[string]time.Time // hostname -> ip -> expiresAt
	upnp     map[string][]UPnPDevice
	wsd      map[string][]WSDiscoveryRecord
	unavail  map[string]string
}

type cachedMDNSInst struct {
	svc        MDNSService
	targetHost string
}

// NewDiscoveryCache initializes an empty durable DiscoveryCache.
func NewDiscoveryCache() *DiscoveryCache {
	return &DiscoveryCache{
		mdnsInst: make(map[string]*cachedMDNSInst),
		hostIPs:  make(map[string]map[string]time.Time),
		upnp:     make(map[string][]UPnPDevice),
		wsd:      make(map[string][]WSDiscoveryRecord),
		unavail:  make(map[string]string),
	}
}

// MarkUnavailable records that passive discovery could not run on observerVLAN
// (e.g., missing interface attachment or permission error) so callers preserve
// explicit visibility gaps instead of treating silence as absence.
func (c *DiscoveryCache) MarkUnavailable(observerVLAN, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.unavail[observerVLAN] = reason
}

// IngestMDNSPacket decodes one raw mDNS/DNS-SD UDP datagram with full PTR, SRV,
// TXT, A, and AAAA assembly, TTL expiry tracking, RFC 6762 goodbye withdrawal
// (TTL == 0), and mDNS reflector detection.
func (c *DiscoveryCache) IngestMDNSPacket(pkt []byte, responderIP, observerIface, observerVLAN string, now time.Time) {
	recs := parseDNSPacket(pkt)
	if len(recs) == 0 {
		return
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, rr := range recs {
		switch rr.rrType {
		case 1: // A (IPv4)
			if rr.ipv4 != "" {
				host := strings.ToLower(rr.name)
				if rr.ttl == 0 {
					delete(c.hostIPs[host], rr.ipv4)
				} else {
					if c.hostIPs[host] == nil {
						c.hostIPs[host] = make(map[string]time.Time)
					}
					c.hostIPs[host][rr.ipv4] = now.UTC().Add(time.Duration(rr.ttl) * time.Second)
				}
			}
		case 28: // AAAA (IPv6)
			if rr.ipv6 != "" {
				host := strings.ToLower(rr.name)
				if rr.ttl == 0 {
					delete(c.hostIPs[host], rr.ipv6)
				} else {
					if c.hostIPs[host] == nil {
						c.hostIPs[host] = make(map[string]time.Time)
					}
					c.hostIPs[host][rr.ipv6] = now.UTC().Add(time.Duration(rr.ttl) * time.Second)
				}
			}
		case 12: // PTR
			svcType := normalizeMDNSType(rr.name)
			if svcType == "" || strings.HasPrefix(svcType, "_services.") {
				continue
			}
			key := strings.ToLower(observerVLAN + "|" + rr.target)
			inst := c.ensureMDNSInstLocked(key, svcType, extractMDNSInstance(rr.target, svcType), responderIP, observerIface, observerVLAN, now)
			applyMDNSTTL(&inst.svc, rr.ttl, now)
		case 33: // SRV
			svcType := extractMDNSTypeFromFull(rr.name)
			if svcType == "" {
				continue
			}
			key := strings.ToLower(observerVLAN + "|" + rr.name)
			inst := c.ensureMDNSInstLocked(key, svcType, extractMDNSInstance(rr.name, svcType), responderIP, observerIface, observerVLAN, now)
			inst.svc.Port = rr.port
			inst.targetHost = strings.ToLower(rr.target)
			inst.svc.TargetHost = inst.targetHost
			applyMDNSTTL(&inst.svc, rr.ttl, now)
		case 16: // TXT
			svcType := extractMDNSTypeFromFull(rr.name)
			if svcType == "" {
				continue
			}
			key := strings.ToLower(observerVLAN + "|" + rr.name)
			inst := c.ensureMDNSInstLocked(key, svcType, extractMDNSInstance(rr.name, svcType), responderIP, observerIface, observerVLAN, now)
			inst.svc.TXT = mergeSafeTXT(inst.svc.TXT, rr.txt)
			applyMDNSTTL(&inst.svc, rr.ttl, now)
		}
	}
}

func (c *DiscoveryCache) ensureMDNSInstLocked(key, svcType, instance, responderIP, observerIface, observerVLAN string, now time.Time) *cachedMDNSInst {
	inst := c.mdnsInst[key]
	if inst == nil {
		ts := now.UTC()
		inst = &cachedMDNSInst{
			svc: MDNSService{
				Type:              svcType,
				Instance:          instance,
				Transport:         mdnsRealTransport(svcType),
				ResponderIP:       responderIP,
				ObserverInterface: observerIface,
				ObserverVLAN:      observerVLAN,
				ObservedAt:        &ts,
			},
		}
		c.mdnsInst[key] = inst
	} else {
		ts := now.UTC()
		inst.svc.ObservedAt = &ts
		if inst.svc.Type == "" {
			inst.svc.Type = svcType
			inst.svc.Transport = mdnsRealTransport(svcType)
		}
		if inst.svc.Instance == "" {
			inst.svc.Instance = instance
		}
		if responderIP != "" {
			inst.svc.ResponderIP = responderIP
		}
	}
	return inst
}

func applyMDNSTTL(svc *MDNSService, ttl uint32, now time.Time) {
	if ttl == 0 {
		svc.TTLSeconds = 0
		svc.Withdrawn = true
		exp := now.UTC()
		svc.ExpiresAt = &exp
		return
	}
	svc.Withdrawn = false
	svc.TTLSeconds = ttl
	exp := now.UTC().Add(time.Duration(ttl) * time.Second)
	svc.ExpiresAt = &exp
}

// mdnsRealTransport returns the actual L4 transport for a DNS-SD service type.
// Matter operational discovery advertises `_matter._tcp` per spec while using
// UDP for operational MRP sessions, so it MUST NOT be fed to the TCP dialer.
func mdnsRealTransport(svcType string) string {
	low := strings.ToLower(strings.TrimSpace(svcType))
	if low == "_matter._tcp" || strings.HasSuffix(low, "._udp") {
		return "udp"
	}
	return "tcp"
}

// isMDNSRawPrintSink reports whether a DNS-SD type represents a raw print sink
// that must never receive generic application-layer probe bytes.
func isMDNSRawPrintSink(svcType string) bool {
	low := strings.ToLower(strings.TrimSpace(svcType))
	return strings.HasPrefix(low, "_pdl-datastream.") || low == "_printer._tcp"
}

// PruneExpired drops expired or withdrawn mDNS records (including A/AAAA entries) as of now.
func (c *DiscoveryCache) PruneExpired(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, inst := range c.mdnsInst {
		if inst.svc.Withdrawn || (inst.svc.ExpiresAt != nil && now.After(*inst.svc.ExpiresAt)) {
			delete(c.mdnsInst, k)
		}
	}
	for host, ipMap := range c.hostIPs {
		for ip, exp := range ipMap {
			if !exp.IsZero() && now.After(exp) {
				delete(ipMap, ip)
			}
		}
		if len(ipMap) == 0 {
			delete(c.hostIPs, host)
		}
	}
}

// Snapshot builds a point-in-time LANDiscovery view from all non-expired,
// non-withdrawn records in the cache.
func (c *DiscoveryCache) Snapshot(now time.Time) *LANDiscovery {
	c.mu.RLock()
	defer c.mu.RUnlock()

	res := &LANDiscovery{
		MDNS:        make(map[string][]MDNSService),
		UPnP:        make(map[string][]UPnPDevice),
		WSDiscovery: make(map[string][]WSDiscoveryRecord),
		PortsByIP:   make(map[string][]int),
		RawPrintIPs: make(map[string]map[int]struct{}),
		Unavailable: make(map[string]string, len(c.unavail)),
	}
	for k, v := range c.unavail {
		res.Unavailable[k] = v
	}

	portSet := make(map[string]map[int]struct{})
	addPort := func(ip string, port int) {
		if ip == "" || port < 1 || port > 65535 {
			return
		}
		if portSet[ip] == nil {
			portSet[ip] = make(map[int]struct{})
		}
		portSet[ip][port] = struct{}{}
	}

	seen := make(map[string]struct{})
	for _, inst := range c.mdnsInst {
		svc := inst.svc
		if svc.Withdrawn || (svc.ExpiresAt != nil && now.After(*svc.ExpiresAt)) {
			continue
		}
		var ips []string
		if inst.targetHost != "" {
			for ip, exp := range c.hostIPs[inst.targetHost] {
				if !exp.IsZero() && now.After(exp) {
					continue
				}
				ips = append(ips, ip)
			}
			sort.Strings(ips)
			// Never attribute an unresolved SRV target host to ResponderIP as if
			// the reflector hosted that service directly.
			if len(ips) == 0 {
				continue
			}
		} else if svc.ResponderIP != "" {
			ips = []string{svc.ResponderIP}
		}
		if len(ips) == 0 {
			continue
		}
		svc.TargetIPs = ips
		svc.AddressFamily = classifyIPFamily(ips)
		if svc.ResponderIP != "" {
			responderMatchesTarget := false
			for _, tip := range ips {
				if tip == svc.ResponderIP {
					responderMatchesTarget = true
					break
				}
			}
			svc.Reflected = !responderMatchesTarget
		}

		for _, ip := range ips {
			dedup := fmt.Sprintf("%s|%s|%s|%d|%s", ip, svc.ObserverVLAN, svc.Type, svc.Port, svc.Instance)
			if _, dup := seen[dedup]; dup {
				continue
			}
			seen[dedup] = struct{}{}
			res.MDNS[ip] = append(res.MDNS[ip], svc)

			if isMDNSRawPrintSink(svc.Type) {
				if res.RawPrintIPs[ip] == nil {
					res.RawPrintIPs[ip] = make(map[int]struct{})
				}
				if svc.Port > 0 {
					res.RawPrintIPs[ip][svc.Port] = struct{}{}
				}
				continue
			}
			// Never dial Matter operational (_matter._tcp uses UDP) or any UDP service via TCP.
			if svc.Transport == "tcp" && svc.Port > 0 && !svc.Reflected {
				addPort(ip, svc.Port)
			}
		}
	}
	for ip := range res.MDNS {
		sort.Slice(res.MDNS[ip], func(i, j int) bool {
			if res.MDNS[ip][i].Type != res.MDNS[ip][j].Type {
				return res.MDNS[ip][i].Type < res.MDNS[ip][j].Type
			}
			return res.MDNS[ip][i].Port < res.MDNS[ip][j].Port
		})
	}
	for ip, pset := range portSet {
		list := make([]int, 0, len(pset))
		for p := range pset {
			list = append(list, p)
		}
		sort.Ints(list)
		res.PortsByIP[ip] = list
	}
	return res
}

func classifyIPFamily(ips []string) string {
	hasV4, hasV6 := false, false
	for _, s := range ips {
		ip := net.ParseIP(s)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			hasV4 = true
		} else {
			hasV6 = true
		}
	}
	switch {
	case hasV4 && hasV6:
		return "dual"
	case hasV6:
		return "ipv6"
	case hasV4:
		return "ipv4"
	default:
		return ""
	}
}

// DiscoverLAN performs one bounded, read-only multicast discovery sweep across
// mDNS/DNS-SD (UDP 5353), SSDP/UPnP (UDP 1900), and WS-Discovery (UDP 3702).
// Any network permission errors (e.g., in restricted sandboxes) degrade
// gracefully to an empty result so LAN scanning still succeeds.
func DiscoverLAN(ctx context.Context, httpClient *http.Client) *LANDiscovery {
	res := &LANDiscovery{
		MDNS:        make(map[string][]MDNSService),
		UPnP:        make(map[string][]UPnPDevice),
		WSDiscovery: make(map[string][]WSDiscoveryRecord),
		PortsByIP:   make(map[string][]int),
		RawPrintIPs: make(map[string]map[int]struct{}),
	}

	discCtx, cancel := context.WithTimeout(ctx, discoveryWindow+1200*time.Millisecond)
	defer cancel()

	var wg sync.WaitGroup
	var mdnsRes map[string][]MDNSService
	var ssdpHits []ssdpHit
	var ssdpNoLoc map[string][]ssdpHit
	var wsdRes map[string][]WSDiscoveryRecord

	wg.Add(3)
	go func() {
		defer wg.Done()
		mdnsRes = discoverMDNS(discCtx)
	}()
	go func() {
		defer wg.Done()
		ssdpHits, ssdpNoLoc = listenSSDP(discCtx)
	}()
	go func() {
		defer wg.Done()
		wsdRes = discoverWSD(discCtx)
	}()
	wg.Wait()

	portSet := make(map[string]map[int]struct{})
	addPort := func(ip string, port int) {
		if ip == "" || port < 1 || port > 65535 {
			return
		}
		if portSet[ip] == nil {
			portSet[ip] = make(map[int]struct{})
		}
		portSet[ip][port] = struct{}{}
	}

	for ip, svcs := range mdnsRes {
		res.MDNS[ip] = svcs
		for _, s := range svcs {
			if isMDNSRawPrintSink(s.Type) {
				if res.RawPrintIPs[ip] == nil {
					res.RawPrintIPs[ip] = make(map[int]struct{})
				}
				if s.Port > 0 {
					res.RawPrintIPs[ip][s.Port] = struct{}{}
				}
				continue
			}
			// Only feed genuinely TCP SRV ports into the TCP fingerprinter
			// (skip UDP services and Matter operational _matter._tcp which runs UDP).
			if mdnsRealTransport(s.Type) == "tcp" && s.Port > 0 && !s.Reflected {
				addPort(ip, s.Port)
			}
		}
	}

	// Fetch UPnP XML descriptions AFTER collecting mDNS raw-print sink ports so
	// SSDP never writes HTTP bytes to any advertised raw print sink.
	upnpRes := fetchSSDPDescriptions(discCtx, httpClient, ssdpHits, ssdpNoLoc, res.RawPrintIPs)
	for ip, devs := range upnpRes {
		res.UPnP[ip] = devs
		for _, d := range devs {
			if d.Port > 0 && !isRawPrintSinkPort(d.Port, res, ip) {
				addPort(ip, d.Port)
			}
		}
	}
	for ip, recs := range wsdRes {
		res.WSDiscovery[ip] = recs
		for _, r := range recs {
			for _, p := range r.Ports {
				addPort(ip, p)
			}
		}
	}

	for ip, pset := range portSet {
		list := make([]int, 0, len(pset))
		for p := range pset {
			list = append(list, p)
		}
		sort.Ints(list)
		res.PortsByIP[ip] = list
	}
	return res
}

// discoverMDNS sends bounded RFC 6762 DNS-SD PTR queries over IPv4 (224.0.0.251:5353)
// and IPv6 ([ff02::fb]:5353), assembling PTR, SRV, TXT, A, and AAAA records.
func discoverMDNS(ctx context.Context) map[string][]MDNSService {
	cache := NewDiscoveryCache()
	collectMDNSIntoCache(ctx, cache)
	return cache.Snapshot(time.Now().UTC()).MDNS
}

func collectMDNSIntoCache(ctx context.Context, cache *DiscoveryCache) {
	var wg sync.WaitGroup
	// IPv4 mDNS sweep.
	wg.Add(1)
	go func() {
		defer wg.Done()
		collectMDNSFamily(ctx, cache, "udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0}, mdnsMulticastAddr, "mdns-ipv4")
	}()
	// IPv6 mDNS sweep (best-effort; records unavailability if host lacks IPv6 multicast).
	wg.Add(1)
	go func() {
		defer wg.Done()
		collectMDNSFamily(ctx, cache, "udp6", &net.UDPAddr{IP: net.IPv6unspecified, Port: 0}, "[ff02::fb]:5353", "mdns-ipv6")
	}()
	wg.Wait()
}

func collectMDNSFamily(ctx context.Context, cache *DiscoveryCache, network string, local *net.UDPAddr, remoteAddr, label string) {
	conn, err := net.ListenUDP(network, local)
	if err != nil {
		cache.MarkUnavailable(label, err.Error())
		return
	}
	defer conn.Close()

	dst, err := net.ResolveUDPAddr(network, remoteAddr)
	if err != nil {
		cache.MarkUnavailable(label, err.Error())
		return
	}

	sent := false
	for i := 0; i < len(mdnsQueryTypes); i += 10 {
		end := i + 10
		if end > len(mdnsQueryTypes) {
			end = len(mdnsQueryTypes)
		}
		if pkt := buildMDNSQuery(mdnsQueryTypes[i:end]); len(pkt) > 0 {
			if _, werr := conn.WriteToUDP(pkt, dst); werr == nil {
				sent = true
			}
		}
	}
	if !sent {
		cache.MarkUnavailable(label, "multicast send failed")
		return
	}

	deadline := time.Now().Add(discoveryWindow)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetReadDeadline(deadline)

	buf := make([]byte, 8192)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if n < 12 || src == nil || src.IP == nil {
			continue
		}
		cache.IngestMDNSPacket(buf[:n], src.IP.String(), src.Zone, "", time.Now().UTC())
	}
}

// buildMDNSQuery encodes a standard RFC 6762 PTR question packet for names.
func buildMDNSQuery(names []string) []byte {
	var buf bytes.Buffer
	// Header: ID=0, Flags=0 (standard query), QDCOUNT=len(names), AN/NS/AR=0.
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[4:6], uint16(len(names)))
	buf.Write(hdr)
	for _, name := range names {
		for _, lbl := range strings.Split(strings.TrimSuffix(name, "."), ".") {
			if len(lbl) == 0 || len(lbl) > 63 {
				continue
			}
			buf.WriteByte(byte(len(lbl)))
			buf.WriteString(lbl)
		}
		buf.WriteByte(0x00)
		// QTYPE=PTR (12), QCLASS=IN (1) with unicast-response bit (0x8001) so
		// responders can reply directly without flooding the LAN.
		buf.Write([]byte{0x00, 0x0c, 0x80, 0x01})
	}
	return buf.Bytes()
}

type dnsRecord struct {
	name   string
	rrType uint16
	ttl    uint32
	port   int
	target string
	ipv4   string
	ipv6   string
	txt    []string
}

// parseDNSPacket decodes Answer and Additional resource records from a raw
// DNS/mDNS UDP datagram with full RFC 1035 name pointer decompression, TTL,
// IPv4 A, and IPv6 AAAA extraction.
func parseDNSPacket(pkt []byte) []dnsRecord {
	if len(pkt) < 12 {
		return nil
	}
	qdCount := int(binary.BigEndian.Uint16(pkt[4:6]))
	anCount := int(binary.BigEndian.Uint16(pkt[6:8]))
	nsCount := int(binary.BigEndian.Uint16(pkt[8:10]))
	arCount := int(binary.BigEndian.Uint16(pkt[10:12]))

	off := 12
	for range qdCount {
		var ok bool
		_, off, ok = readDNSName(pkt, off)
		if !ok || off+4 > len(pkt) {
			return nil
		}
		off += 4
	}

	totalRR := anCount + nsCount + arCount
	if totalRR > 256 {
		totalRR = 256
	}
	var out []dnsRecord
	for range totalRR {
		name, nextOff, ok := readDNSName(pkt, off)
		if !ok || nextOff+10 > len(pkt) {
			break
		}
		rrType := binary.BigEndian.Uint16(pkt[nextOff : nextOff+2])
		ttl := binary.BigEndian.Uint32(pkt[nextOff+4 : nextOff+8])
		rdLen := int(binary.BigEndian.Uint16(pkt[nextOff+8 : nextOff+10]))
		rdataOff := nextOff + 10
		if rdataOff+rdLen > len(pkt) {
			break
		}
		off = rdataOff + rdLen

		switch rrType {
		case 1: // A
			if rdLen == 4 {
				ip := net.IP(pkt[rdataOff : rdataOff+4]).String()
				out = append(out, dnsRecord{name: name, rrType: 1, ttl: ttl, ipv4: ip})
			}
		case 28: // AAAA
			if rdLen == 16 {
				ip := net.IP(pkt[rdataOff : rdataOff+16]).String()
				out = append(out, dnsRecord{name: name, rrType: 28, ttl: ttl, ipv6: ip})
			}
		case 12: // PTR
			if target, _, ok := readDNSName(pkt, rdataOff); ok {
				out = append(out, dnsRecord{name: name, rrType: 12, ttl: ttl, target: target})
			}
		case 33: // SRV
			if rdLen >= 7 {
				port := int(binary.BigEndian.Uint16(pkt[rdataOff+4 : rdataOff+6]))
				if target, _, ok := readDNSName(pkt, rdataOff+6); ok {
					out = append(out, dnsRecord{name: name, rrType: 33, ttl: ttl, port: port, target: target})
				}
			}
		case 16: // TXT
			var pairs []string
			pos := rdataOff
			end := rdataOff + rdLen
			for pos < end {
				l := int(pkt[pos])
				pos++
				if l == 0 || pos+l > end {
					break
				}
				pairs = append(pairs, string(pkt[pos:pos+l]))
				pos += l
			}
			out = append(out, dnsRecord{name: name, rrType: 16, ttl: ttl, txt: pairs})
		}
	}
	return out
}

// readDNSName reads a compressed RFC 1035 domain name starting at off.
func readDNSName(pkt []byte, off int) (string, int, bool) {
	var labels []string
	jumped := false
	origNext := off
	steps := 0

	for off < len(pkt) {
		steps++
		if steps > 128 {
			return "", 0, false
		}
		b := pkt[off]
		if b == 0 {
			if !jumped {
				origNext = off + 1
			}
			return strings.Join(labels, "."), origNext, true
		}
		if b&0xc0 == 0xc0 {
			if off+1 >= len(pkt) {
				return "", 0, false
			}
			ptr := int(binary.BigEndian.Uint16(pkt[off:off+2]) & 0x3fff)
			if ptr >= len(pkt) {
				return "", 0, false
			}
			if !jumped {
				origNext = off + 2
				jumped = true
			}
			off = ptr
			continue
		}
		if b&0xc0 != 0 {
			return "", 0, false
		}
		lblLen := int(b)
		if off+1+lblLen > len(pkt) {
			return "", 0, false
		}
		labels = append(labels, string(pkt[off+1:off+1+lblLen]))
		off += 1 + lblLen
	}
	return "", 0, false
}

func normalizeMDNSType(name string) string {
	n := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSpace(name), "."), ".local")
	if strings.HasPrefix(n, "_") && (strings.HasSuffix(n, "._tcp") || strings.HasSuffix(n, "._udp")) {
		return n
	}
	return ""
}

func extractMDNSTypeFromFull(full string) string {
	trimmed := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSpace(full), "."), ".local")
	idx := strings.Index(trimmed, "._")
	if idx < 0 {
		return normalizeMDNSType(trimmed)
	}
	// Find the first label beginning with "_" followed by "._tcp" or "._udp".
	parts := strings.Split(trimmed, ".")
	for i := 0; i < len(parts)-1; i++ {
		if strings.HasPrefix(parts[i], "_") && (parts[i+1] == "_tcp" || parts[i+1] == "_udp") {
			return parts[i] + "." + parts[i+1]
		}
	}
	return ""
}

func extractMDNSInstance(full, svcType string) string {
	trimmed := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSpace(full), "."), ".local")
	if svcType != "" {
		trimmed = strings.TrimSuffix(trimmed, "."+svcType)
	}
	if len(trimmed) > 80 {
		trimmed = trimmed[:80]
	}
	return trimmed
}

// mergeSafeTXT updates allowlisted DNS-SD TXT attributes by key so a refreshed
// record (e.g. Matter cm=0 replacing cm=1) never leaves stale values behind.
func mergeSafeTXT(existing, incoming []string) []string {
	byKey := make(map[string]string, len(existing)+len(incoming))
	for _, kv := range existing {
		if k, v, ok := strings.Cut(kv, "="); ok {
			byKey[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	for _, raw := range incoming {
		k, v, ok := strings.Cut(raw, "=")
		if !ok {
			continue
		}
		kLower := strings.ToLower(strings.TrimSpace(k))
		if _, allowed := safeMDNSTXTKeys[kLower]; !allowed {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) > 64 {
			v = v[:64]
		}
		byKey[kLower] = v
	}
	out := make([]string, 0, len(byKey))
	for k, v := range byKey {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

type ssdpHit struct {
	ip       string
	st       string
	server   string
	location string
}

// listenSSDP issues a single bounded SSDP M-SEARCH (MX: 1, ST: ssdp:all) and
// returns passive UDP responses without sending any HTTP requests yet.
func listenSSDP(ctx context.Context) ([]ssdpHit, map[string][]ssdpHit) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, nil
	}
	defer conn.Close()

	dst, err := net.ResolveUDPAddr("udp4", ssdpMulticastAddr)
	if err != nil {
		return nil, nil
	}
	msearch := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 1\r\n" +
		"ST: ssdp:all\r\n\r\n"
	_, _ = conn.WriteToUDP([]byte(msearch), dst)

	deadline := time.Now().Add(discoveryWindow)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetReadDeadline(deadline)

	hitsByLoc := make(map[string]ssdpHit)
	noLocHits := make(map[string][]ssdpHit)

	buf := make([]byte, 4096)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if src == nil || src.IP == nil || n == 0 {
			continue
		}
		ip := src.IP.String()
		hdrs := parseSSDPHeaders(string(buf[:n]))
		st := hdrs["st"]
		if st == "" {
			st = hdrs["nt"]
		}
		loc := hdrs["location"]
		srv := hdrs["server"]
		if loc != "" {
			key := ip + "|" + loc
			if _, exists := hitsByLoc[key]; !exists && len(hitsByLoc) < 128 {
				hitsByLoc[key] = ssdpHit{ip: ip, st: st, server: srv, location: loc}
			}
		} else if st != "" || srv != "" {
			noLocHits[ip] = append(noLocHits[ip], ssdpHit{ip: ip, st: st, server: srv})
		}
	}

	hits := make([]ssdpHit, 0, len(hitsByLoc))
	for _, h := range hitsByLoc {
		hits = append(hits, h)
	}
	return hits, noLocHits
}

// fetchSSDPDescriptions fetches at most one same-host pinned UPnP XML
// description per unique location while enforcing the raw-printer guard across
// both fixed raw print ports (9100/515) and mDNS-advertised raw print sinks.
func fetchSSDPDescriptions(ctx context.Context, httpClient *http.Client, hits []ssdpHit, noLocHits map[string][]ssdpHit, rawPrintIPs map[string]map[int]struct{}) map[string][]UPnPDevice {
	out := make(map[string][]UPnPDevice)
	for ip, list := range noLocHits {
		for _, h := range list {
			out[ip] = append(out[ip], UPnPDevice{ST: h.st, Server: h.server})
		}
	}
	isProtectedRawPrint := func(ip string, port int) bool {
		if port == 9100 || port == 515 {
			return true
		}
		if m := rawPrintIPs[ip]; m != nil {
			_, ok := m[port]
			return ok
		}
		return false
	}

	var mu sync.Mutex
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, hit := range hits {
		h := hit
		port, safeURL, ok := validateSameHostURL(h.location, h.ip)
		if !ok {
			mu.Lock()
			out[h.ip] = append(out[h.ip], UPnPDevice{ST: h.st, Server: h.server})
			mu.Unlock()
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			dev := UPnPDevice{ST: h.st, Server: h.server, Port: port}
			if httpClient != nil && !isProtectedRawPrint(h.ip, port) {
				fetchUPnPXML(ctx, httpClient, safeURL, &dev)
			}
			mu.Lock()
			out[h.ip] = append(out[h.ip], dev)
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out
}

func parseSSDPHeaders(raw string) map[string]string {
	out := make(map[string]string)
	for _, line := range strings.Split(raw, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(k))
		if key != "" && out[key] == "" {
			out[key] = strings.TrimSpace(v)
		}
	}
	return out
}

// validateSameHostURL enforces UniBlue's strict pinning rule: an advertised
// SSDP LOCATION or WS-Discovery XAddr must be HTTP(S), have no userinfo, and
// point strictly to the exact IP address that sent the UDP response.
func validateSameHostURL(rawURL, responderIP string) (int, string, bool) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return 0, "", false
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Host == "" {
		return 0, "", false
	}
	host := u.Hostname()
	if host != responderIP {
		return 0, "", false
	}
	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	if pStr := u.Port(); pStr != "" {
		p, err := strconv.Atoi(pStr)
		if err != nil || p < 1 || p > 65535 {
			return 0, "", false
		}
		port = p
	}
	u.Fragment = ""
	return port, u.String(), true
}

func fetchUPnPXML(ctx context.Context, client *http.Client, targetURL string, dev *UPnPDevice) {
	reqCtx, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, targetURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "UniBlue-Discovery/0.1")
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxUPnPDescBytes))
	if err != nil || len(body) == 0 {
		return
	}
	parseUPnPDescriptionXML(body, dev)
}

// parseUPnPDescriptionXML safely extracts root and embedded UPnP device
// metadata and serviceType URNs without resolving external entities.
func parseUPnPDescriptionXML(raw []byte, dev *UPnPDevice) {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	dec.Strict = false
	svcSeen := make(map[string]struct{})
	var curTag string
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			curTag = strings.ToLower(t.Name.Local)
		case xml.EndElement:
			curTag = ""
		case xml.CharData:
			val := strings.TrimSpace(string(t))
			if val == "" {
				continue
			}
			switch curTag {
			case "devicetype":
				if dev.DeviceType == "" {
					dev.DeviceType = val
				}
			case "manufacturer":
				if dev.Manufacturer == "" {
					dev.Manufacturer = val
				}
			case "modelname":
				if dev.ModelName == "" {
					dev.ModelName = val
				}
			case "modelnumber":
				if dev.ModelNumber == "" {
					dev.ModelNumber = val
				}
			case "servicetype":
				if _, dup := svcSeen[val]; !dup && len(dev.ServiceTypes) < 32 {
					svcSeen[val] = struct{}{}
					dev.ServiceTypes = append(dev.ServiceTypes, val)
				}
			}
		}
	}
	sort.Strings(dev.ServiceTypes)
}

// discoverWSD sends one bounded WS-Discovery SOAP Probe to UDP 3702 to detect
// ONVIF NetworkVideoTransmitter cameras and WSD printers/hosts without probing
// arbitrary ports.
func discoverWSD(ctx context.Context) map[string][]WSDiscoveryRecord {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil
	}
	defer conn.Close()

	dst, err := net.ResolveUDPAddr("udp4", wsDiscoveryAddr)
	if err != nil {
		return nil
	}
	probeXML := `<?xml version="1.0" encoding="utf-8"?>` +
		`<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" ` +
		`xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" ` +
		`xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" ` +
		`xmlns:dn="http://www.onvif.org/ver10/network/wsdl">` +
		`<e:Header><w:MessageID>uuid:uniblue-wsd-probe-0001</w:MessageID>` +
		`<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>` +
		`<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header>` +
		`<e:Body><d:Probe/></e:Body></e:Envelope>`
	_, _ = conn.WriteToUDP([]byte(probeXML), dst)

	deadline := time.Now().Add(discoveryWindow)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetReadDeadline(deadline)

	out := make(map[string][]WSDiscoveryRecord)
	seenIP := make(map[string]struct{})
	buf := make([]byte, 8192)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if src == nil || src.IP == nil || n == 0 {
			continue
		}
		ip := src.IP.String()
		if _, dup := seenIP[ip]; dup {
			continue
		}
		if rec, ok := parseWSDProbeMatch(buf[:n], ip); ok {
			seenIP[ip] = struct{}{}
			out[ip] = append(out[ip], rec)
		}
	}
	return out
}

// parseWSDProbeMatch extracts Types, non-sensitive Scopes, and same-host XAddr
// ports from a WS-Discovery SOAP ProbeMatches datagram.
func parseWSDProbeMatch(raw []byte, responderIP string) (WSDiscoveryRecord, bool) {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	dec.Strict = false
	var rec WSDiscoveryRecord
	var curTag string
	portSeen := make(map[int]struct{})

	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			curTag = strings.ToLower(t.Name.Local)
		case xml.EndElement:
			curTag = ""
		case xml.CharData:
			val := strings.TrimSpace(string(t))
			if val == "" {
				continue
			}
			switch curTag {
			case "types":
				for _, field := range strings.Fields(val) {
					// Strip arbitrary XML namespace prefix (e.g., "dn:NetworkVideoTransmitter" -> "NetworkVideoTransmitter").
					if _, local, ok := strings.Cut(field, ":"); ok {
						field = local
					}
					if field != "" {
						rec.Types = append(rec.Types, field)
					}
				}
			case "scopes":
				for _, sc := range strings.Fields(val) {
					low := strings.ToLower(sc)
					// Keep only standard ONVIF/WSD capability scopes (never room/location/serial names).
					if strings.Contains(low, "onvif.org/type/") || strings.Contains(low, "onvif.org/profile/") || strings.Contains(low, "onvif.org/hardware/") {
						rec.Scopes = append(rec.Scopes, sc)
					}
				}
			case "xaddrs":
				for _, addr := range strings.Fields(val) {
					if port, _, ok := validateSameHostURL(addr, responderIP); ok {
						if _, dup := portSeen[port]; !dup {
							portSeen[port] = struct{}{}
							rec.Ports = append(rec.Ports, port)
						}
					}
				}
			}
		}
	}
	sort.Strings(rec.Types)
	sort.Strings(rec.Scopes)
	sort.Ints(rec.Ports)
	return rec, len(rec.Types) > 0 || len(rec.Scopes) > 0 || len(rec.Ports) > 0
}
