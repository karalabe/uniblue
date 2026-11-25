// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
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

	// ssdpFetchBudget gives UPnP XML description fetches their own short timeout
	// budget independent of the multicast listen deadline.
	ssdpFetchBudget = 2500 * time.Millisecond

	// mDNS anti-DoS memory caps.
	maxDNSNameWireBytes               = 255
	maxDNSQuestionsPerPacket          = 64
	maxDNSRecordsPerPacket            = 128
	maxMDNSTXTEntriesPerRR            = 64
	maxMDNSTXTBytesPerInst            = 512
	maxMDNSServicesPerHost            = 64
	maxMDNSServicesPerResponder       = 512
	maxMDNSHostsPerResponder          = 512
	maxMDNSReflectedPerSenderTarget   = 16
	maxMDNSServicesTotal              = 4096
	maxMDNSHostsTotal                 = 4096
	maxMDNSIPsPerHost                 = 16
	maxMDNSRespondersPerInst          = 8

	// SSDP anti-DoS caps and string length bounds.
	maxSSDPHeaderLen        = 256
	maxSSDPLocationLen      = 512
	maxSSDPLocHitsPerIP     = 8
	maxSSDPIGDLocHitsPerIP  = 2
	maxSSDPLocHitsTotal     = 256
	maxSSDPIGDReservedSlots = 16
	maxSSDPNoLocHitsPerIP   = 8
	maxSSDPNoLocHitsTotal   = 256
	maxSSDPSTsPerLocation   = 16
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
	"_mpd._tcp.local.",
	"_afpovertcp._tcp.local.",
	"_adisk._tcp.local.",
	"_apple-mobdev2._tcp.local.",
	"_adb-tls-connect._tcp.local.",
	"_adb-tls-pairing._tcp.local.",
	"_zwave-js-server._tcp.local.",
	"_miio._udp.local.",
	"_lifx._udp.local.",
	"_coap._udp.local.",
	"_nanoleafapi._tcp.local.",
	"_homeconnect._tcp.local.",
	"_heos-audio._tcp.local.",
	"_viziocast._tcp.local.",
	"_philipstv_rpc._tcp.local.",
	"_philipstv_s_rpc._tcp.local.",
	"_androidtvremote2._tcp.local.",
	"_slzb-06._tcp.local.",
	"_smlight._tcp.local.",
	"_esphome-uart._tcp.local.",
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

	// TrustedReflector is true when Reflected is set and ResponderIP matches a
	// configured local gateway mDNS reflector.
	TrustedReflector bool `json:"trusted_reflector,omitempty"`

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

// senderBuckets tracks per-sender entry counts with O(1) amortized updates and
// O(1) lookup of the heaviest sender so cache eviction never performs full-table
// scans under spoofed multi-source floods.
type senderBuckets struct {
	counts   map[string]int
	byCount  map[int]map[string]struct{}
	maxCount int
}

func newSenderBuckets() *senderBuckets {
	return &senderBuckets{
		counts:  make(map[string]int),
		byCount: make(map[int]map[string]struct{}),
	}
}

func (b *senderBuckets) inc(sender string) {
	if sender == "" {
		return
	}
	old := b.counts[sender]
	if old > 0 {
		if set := b.byCount[old]; set != nil {
			delete(set, sender)
			if len(set) == 0 {
				delete(b.byCount, old)
			}
		}
	}
	next := old + 1
	b.counts[sender] = next
	if b.byCount[next] == nil {
		b.byCount[next] = make(map[string]struct{})
	}
	b.byCount[next][sender] = struct{}{}
	if next > b.maxCount {
		b.maxCount = next
	}
}

func (b *senderBuckets) dec(sender string) {
	if sender == "" {
		return
	}
	old := b.counts[sender]
	if old <= 0 {
		return
	}
	if set := b.byCount[old]; set != nil {
		delete(set, sender)
		if len(set) == 0 {
			delete(b.byCount, old)
		}
	}
	next := old - 1
	if next > 0 {
		b.counts[sender] = next
		if b.byCount[next] == nil {
			b.byCount[next] = make(map[string]struct{})
		}
		b.byCount[next][sender] = struct{}{}
	} else {
		delete(b.counts, sender)
	}
	for b.maxCount > 0 && len(b.byCount[b.maxCount]) == 0 {
		b.maxCount--
	}
}

func (b *senderBuckets) heaviest() (string, int) {
	for b.maxCount > 0 && len(b.byCount[b.maxCount]) == 0 {
		b.maxCount--
	}
	if b.maxCount == 0 {
		return "", 0
	}
	for s := range b.byCount[b.maxCount] {
		return s, b.maxCount
	}
	return "", 0
}

// DiscoveryCache retains durable, TTL-bounded passive discovery observations
// across full-scan and live recomputations, supporting IPv4/IPv6 AAAA records,
// RFC 6762 TTL=0 goodbye withdrawal, and reflection tracking.
type DiscoveryCache struct {
	mu                  sync.RWMutex
	trustedReflectors   map[string]struct{}
	mdnsInst            map[string]*cachedMDNSInst
	respInstCount       map[string]int
	respUnresolvedCount map[string]int
	targetInstCount     map[string]int
	allInstBuckets      *senderBuckets
	reflInstBuckets     *senderBuckets
	respInstKeys        map[string]map[string]struct{}
	respReflNonSinkKeys map[string]map[string]struct{}
	respReflSinkKeys    map[string]map[string]struct{}
	targetReflKeys      map[string]map[string]struct{}
	respTargetInstCount map[string]map[string]int
	hostIPs             map[string]map[string]cachedHostIP // hostname -> ip -> expiry + authority
	hostOwner           map[string]string                  // hostname -> first responderIP that created it
	hostReflected       map[string]bool                    // hostname -> currently indexed as reflected
	respHostCount       map[string]int
	ipHostCount         map[string]int
	allHostBuckets      *senderBuckets
	reflHostBuckets     *senderBuckets
	respHostKeys        map[string]map[string]struct{}
	respReflHostKeys    map[string]map[string]struct{}
	ipReflHosts         map[string]map[string]struct{}
	respIPHostCount     map[string]map[string]int
	upnp                map[string][]UPnPDevice
	wsd                 map[string][]WSDiscoveryRecord
	unavail             map[string]string
}

type cachedHostIP struct {
	expiresAt     time.Time
	authoritative bool
}

type cachedMDNSInst struct {
	svc               MDNSService
	targetHost        string
	createdBy         string
	srvResponder      string
	srvAuthoritative  bool
	reflectedIndexed  bool
	reflectedSink     bool
	countedTargetIPs  []string
	countedUnresolved bool
	responderIPs      map[string]struct{}
}

// NewDiscoveryCache initializes an empty durable DiscoveryCache.
func NewDiscoveryCache() *DiscoveryCache {
	return &DiscoveryCache{
		mdnsInst:            make(map[string]*cachedMDNSInst),
		respInstCount:       make(map[string]int),
		respUnresolvedCount: make(map[string]int),
		targetInstCount:     make(map[string]int),
		allInstBuckets:      newSenderBuckets(),
		reflInstBuckets:     newSenderBuckets(),
		respInstKeys:        make(map[string]map[string]struct{}),
		respReflNonSinkKeys: make(map[string]map[string]struct{}),
		respReflSinkKeys:    make(map[string]map[string]struct{}),
		targetReflKeys:      make(map[string]map[string]struct{}),
		respTargetInstCount: make(map[string]map[string]int),
		hostIPs:             make(map[string]map[string]cachedHostIP),
		hostOwner:           make(map[string]string),
		hostReflected:       make(map[string]bool),
		respHostCount:       make(map[string]int),
		ipHostCount:         make(map[string]int),
		allHostBuckets:      newSenderBuckets(),
		reflHostBuckets:     newSenderBuckets(),
		respHostKeys:        make(map[string]map[string]struct{}),
		respReflHostKeys:    make(map[string]map[string]struct{}),
		ipReflHosts:         make(map[string]map[string]struct{}),
		respIPHostCount:     make(map[string]map[string]int),
		upnp:                make(map[string][]UPnPDevice),
		wsd:                 make(map[string][]WSDiscoveryRecord),
		unavail:             make(map[string]string),
	}
}

// SetTrustedReflectors configures local gateway/router IP addresses that are
// authorized to reflect cross-VLAN mDNS advertisements.
func (c *DiscoveryCache) SetTrustedReflectors(ips []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(ips) == 0 {
		c.trustedReflectors = nil
		return
	}
	set := make(map[string]struct{}, len(ips))
	for _, raw := range ips {
		if norm := canonicalIPKey(raw); norm != "" {
			set[norm] = struct{}{}
		}
	}
	c.trustedReflectors = set
}

func (c *DiscoveryCache) isTrustedReflectorLocked(ip string) bool {
	if ip == "" || len(c.trustedReflectors) == 0 {
		return false
	}
	_, ok := c.trustedReflectors[ip]
	return ok
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
	normResp := canonicalIPKey(responderIP)

	// Pre-scan packet SRV and A/AAAA hints so per-target-IP caps can be applied
	// accurately even when PTR/SRV records precede A/AAAA in the datagram.
	pktHostIPs := make(map[string][]string)
	pktInstHost := make(map[string]string)
	for _, rr := range recs {
		switch rr.rrType {
		case 1:
			if rr.ipv4 != "" && rr.ttl > 0 {
				h := strings.ToLower(rr.name)
				pktHostIPs[h] = appendUniqueString(pktHostIPs[h], canonicalIPKey(rr.ipv4))
			}
		case 28:
			if rr.ipv6 != "" && rr.ttl > 0 {
				h := strings.ToLower(rr.name)
				pktHostIPs[h] = appendUniqueString(pktHostIPs[h], canonicalIPKey(rr.ipv6))
			}
		case 33:
			if rr.target != "" {
				pktInstHost[strings.ToLower(rr.name)] = strings.ToLower(rr.target)
			}
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Pass 1: ingest A and AAAA address records first so target IPs are known
	// when service instances are created below.
	for _, rr := range recs {
		switch rr.rrType {
		case 1: // A (IPv4)
			if rr.ipv4 != "" {
				c.recordHostIPLocked(strings.ToLower(rr.name), canonicalIPKey(rr.ipv4), normResp, rr.ttl, now)
			}
		case 28: // AAAA (IPv6)
			if rr.ipv6 != "" {
				c.recordHostIPLocked(strings.ToLower(rr.name), canonicalIPKey(rr.ipv6), normResp, rr.ttl, now)
			}
		}
	}

	resolveTargetIPs := func(fullInstName, explicitTargetHost string) []string {
		th := explicitTargetHost
		if th == "" {
			th = pktInstHost[strings.ToLower(fullInstName)]
		}
		if th == "" {
			return nil
		}
		var out []string
		for ip, entry := range c.hostIPs[th] {
			if !entry.expiresAt.IsZero() && now.After(entry.expiresAt) {
				continue
			}
			out = appendUniqueString(out, ip)
		}
		for _, ip := range pktHostIPs[th] {
			out = appendUniqueString(out, ip)
		}
		sort.Strings(out)
		return out
	}

	// Pass 2: ingest PTR, SRV, and TXT records.
	for _, rr := range recs {
		switch rr.rrType {
		case 12: // PTR
			svcType := normalizeMDNSType(rr.name)
			if svcType == "" || strings.HasPrefix(strings.ToLower(svcType), "_services.") {
				continue
			}
			// Ignore PTR records whose target instance name embeds a different
			// DNS-SD service type (or omits a valid service type), blocking
			// PTR type-confusion spoofing across unrelated services.
			targetType := extractMDNSTypeFromFull(rr.target)
			if targetType == "" || !strings.EqualFold(targetType, svcType) {
				continue
			}
			key := strings.ToLower(observerVLAN + "|" + rr.target)
			if existing := c.mdnsInst[key]; existing != nil && existing.srvAuthoritative && normResp != "" && !containsString(existing.countedTargetIPs, normResp) {
				// Never let a non-authoritative responder withdraw or tamper
				// with an authoritative instance's TTL.
				continue
			}
			targetIPs := resolveTargetIPs(rr.target, "")
			inst := c.ensureMDNSInstLocked(key, svcType, extractMDNSInstance(rr.target, svcType), normResp, observerIface, observerVLAN, targetIPs, now)
			if inst == nil {
				continue
			}
			applyMDNSTTL(&inst.svc, rr.ttl, now)
		case 33: // SRV
			svcType := extractMDNSTypeFromFull(rr.name)
			if svcType == "" {
				continue
			}
			key := strings.ToLower(observerVLAN + "|" + rr.name)
			targetHost := strings.ToLower(rr.target)
			targetIPs := resolveTargetIPs(rr.name, targetHost)
			srvIsAuth := normResp != "" && containsString(targetIPs, normResp)
			if existing := c.mdnsInst[key]; existing != nil && existing.srvResponder != "" && existing.srvResponder != normResp {
				if existing.srvAuthoritative && !srvIsAuth {
					// Never let a third-party responder rewrite an authoritative
					// instance's SRV port or targetHost (or inherit its authority).
					continue
				}
				if !existing.srvAuthoritative && !srvIsAuth {
					// Never let an unrelated third party overwrite another
					// responder's existing reflected SRV.
					continue
				}
				if !existing.srvAuthoritative && srvIsAuth {
					// Authoritative host claims its own instance: replace the
					// prior reflected entry cleanly so the forger is never merged.
					c.deleteMDNSInstLocked(key)
				}
			}
			inst := c.ensureMDNSInstLocked(key, svcType, extractMDNSInstance(rr.name, svcType), normResp, observerIface, observerVLAN, targetIPs, now)
			if inst == nil {
				continue
			}
			inst.svc.Port = rr.port
			inst.targetHost = targetHost
			inst.svc.TargetHost = inst.targetHost
			inst.srvResponder = normResp
			if srvIsAuth {
				inst.srvAuthoritative = true
				c.unindexReflectedInstLocked(key, inst)
			}
			applyMDNSTTL(&inst.svc, rr.ttl, now)
		case 16: // TXT
			svcType := extractMDNSTypeFromFull(rr.name)
			if svcType == "" {
				continue
			}
			key := strings.ToLower(observerVLAN + "|" + rr.name)
			if existing := c.mdnsInst[key]; existing != nil && existing.srvAuthoritative && normResp != "" && !containsString(existing.countedTargetIPs, normResp) {
				// Never let a non-authoritative responder poison TXT or TTL
				// on an authoritative instance.
				continue
			}
			targetIPs := resolveTargetIPs(rr.name, "")
			inst := c.ensureMDNSInstLocked(key, svcType, extractMDNSInstance(rr.name, svcType), normResp, observerIface, observerVLAN, targetIPs, now)
			if inst == nil {
				continue
			}
			inst.svc.TXT = mergeSafeTXT(inst.svc.TXT, rr.txt)
			applyMDNSTTL(&inst.svc, rr.ttl, now)
		}
	}
}

func appendUniqueString(list []string, v string) []string {
	if v == "" {
		return list
	}
	for _, cur := range list {
		if cur == v {
			return list
		}
	}
	return append(list, v)
}

func decCountMap(m map[string]int, key string) {
	if key == "" {
		return
	}
	if m[key] > 1 {
		m[key]--
	} else {
		delete(m, key)
	}
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func addNestedSet(m map[string]map[string]struct{}, outer, inner string) {
	if outer == "" || inner == "" {
		return
	}
	if m[outer] == nil {
		m[outer] = make(map[string]struct{})
	}
	m[outer][inner] = struct{}{}
}

func delNestedSet(m map[string]map[string]struct{}, outer, inner string) {
	if set := m[outer]; set != nil {
		delete(set, inner)
		if len(set) == 0 {
			delete(m, outer)
		}
	}
}

func incNestedCount(m map[string]map[string]int, outer, inner string) {
	if outer == "" || inner == "" {
		return
	}
	if m[outer] == nil {
		m[outer] = make(map[string]int)
	}
	m[outer][inner]++
}

func decNestedCount(m map[string]map[string]int, outer, inner string) {
	if innerMap := m[outer]; innerMap != nil {
		if innerMap[inner] > 1 {
			innerMap[inner]--
		} else {
			delete(innerMap, inner)
			if len(innerMap) == 0 {
				delete(m, outer)
			}
		}
	}
}

func pickAnyKey(set map[string]struct{}) string {
	for k := range set {
		return k
	}
	return ""
}

func (c *DiscoveryCache) indexReflectedInstLocked(k string, inst *cachedMDNSInst) {
	if inst.reflectedIndexed {
		return
	}
	inst.reflectedIndexed = true
	inst.reflectedSink = isMDNSZeroByteSink(inst.svc.Type)
	if inst.createdBy != "" {
		c.reflInstBuckets.inc(inst.createdBy)
		if inst.reflectedSink {
			addNestedSet(c.respReflSinkKeys, inst.createdBy, k)
		} else {
			addNestedSet(c.respReflNonSinkKeys, inst.createdBy, k)
		}
	}
	for _, tip := range inst.countedTargetIPs {
		addNestedSet(c.targetReflKeys, tip, k)
		incNestedCount(c.respTargetInstCount, inst.createdBy, tip)
	}
}

func (c *DiscoveryCache) unindexReflectedInstLocked(k string, inst *cachedMDNSInst) {
	if !inst.reflectedIndexed {
		return
	}
	inst.reflectedIndexed = false
	if inst.createdBy != "" {
		c.reflInstBuckets.dec(inst.createdBy)
		if inst.reflectedSink {
			delNestedSet(c.respReflSinkKeys, inst.createdBy, k)
		} else {
			delNestedSet(c.respReflNonSinkKeys, inst.createdBy, k)
		}
	}
	for _, tip := range inst.countedTargetIPs {
		delNestedSet(c.targetReflKeys, tip, k)
		decNestedCount(c.respTargetInstCount, inst.createdBy, tip)
	}
}

func (c *DiscoveryCache) deleteHostLocked(host string) {
	ipMap, ok := c.hostIPs[host]
	if !ok {
		return
	}
	owner := c.hostOwner[host]
	for ip, entry := range ipMap {
		decCountMap(c.ipHostCount, ip)
		if !entry.authoritative {
			delNestedSet(c.ipReflHosts, ip, host)
			decNestedCount(c.respIPHostCount, owner, ip)
		}
	}
	delete(c.hostIPs, host)
	if c.hostReflected[host] {
		delete(c.hostReflected, host)
		if owner != "" {
			c.reflHostBuckets.dec(owner)
			delNestedSet(c.respReflHostKeys, owner, host)
		}
	}
	if owner != "" {
		delete(c.hostOwner, host)
		decCountMap(c.respHostCount, owner)
		c.allHostBuckets.dec(owner)
		delNestedSet(c.respHostKeys, owner, host)
	}
}

func (c *DiscoveryCache) deleteMDNSInstLocked(k string) {
	inst, ok := c.mdnsInst[k]
	if !ok {
		return
	}
	c.unindexReflectedInstLocked(k, inst)
	delete(c.mdnsInst, k)
	if inst.createdBy != "" {
		decCountMap(c.respInstCount, inst.createdBy)
		c.allInstBuckets.dec(inst.createdBy)
		delNestedSet(c.respInstKeys, inst.createdBy, k)
	}
	if inst.countedUnresolved {
		decCountMap(c.respUnresolvedCount, inst.createdBy)
	}
	for _, tip := range inst.countedTargetIPs {
		decCountMap(c.targetInstCount, tip)
	}
}

func (c *DiscoveryCache) evictReflectedHostForIPLocked(ip, incomingResp string, incomingIsAuth, incomingIsTrusted bool) bool {
	candidates := c.ipReflHosts[ip]
	if len(candidates) == 0 {
		return false
	}
	incomingPerIP := 0
	if incomingResp != "" {
		incomingPerIP = c.respIPHostCount[incomingResp][ip]
	}
	bestHost := ""
	bestPerIP := -1
	bestGlobal := -1
	for h := range candidates {
		owner := c.hostOwner[h]
		if !incomingIsAuth && c.isTrustedReflectorLocked(owner) {
			continue
		}
		perIP := c.respIPHostCount[owner][ip]
		glob := c.respHostCount[owner]
		if bestHost == "" || perIP > bestPerIP || (perIP == bestPerIP && glob > bestGlobal) {
			bestHost = h
			bestPerIP = perIP
			bestGlobal = glob
		}
	}
	if bestHost == "" {
		return false
	}
	if !incomingIsAuth && !incomingIsTrusted {
		if !(bestPerIP > incomingPerIP+1 || (incomingPerIP == 0 && bestPerIP >= 1)) {
			return false
		}
	}
	owner := c.hostOwner[bestHost]
	delete(c.hostIPs[bestHost], ip)
	decCountMap(c.ipHostCount, ip)
	delNestedSet(c.ipReflHosts, ip, bestHost)
	decNestedCount(c.respIPHostCount, owner, ip)
	if len(c.hostIPs[bestHost]) == 0 {
		c.deleteHostLocked(bestHost)
	}
	return true
}

func (c *DiscoveryCache) evictGlobalHostLocked(incomingResp string, incomingIsAuth, incomingIsTrusted bool) bool {
	// Pass 1 (O(1)): evict from the heaviest reflected/third-party sender.
	if sender, cnt := c.reflHostBuckets.heaviest(); sender != "" && cnt > 0 {
		if cnt > 1 || incomingIsAuth || incomingIsTrusted {
			if h := pickAnyKey(c.respReflHostKeys[sender]); h != "" {
				c.deleteHostLocked(h)
				return true
			}
		}
	}
	// Pass 2 (O(1)): max-min fairness across all senders.
	incomingCount := c.respHostCount[incomingResp]
	sender, maxCount := c.allHostBuckets.heaviest()
	if sender == "" || !(maxCount > incomingCount+1 || (incomingCount == 0 && maxCount > 1)) {
		return false
	}
	if h := pickAnyKey(c.respHostKeys[sender]); h != "" {
		c.deleteHostLocked(h)
		return true
	}
	return false
}

func (c *DiscoveryCache) evictReflectedInstForTargetLocked(targetIP, incomingResp string, incomingIsAuth, incomingIsTrusted, incomingIsSink bool) bool {
	candidates := c.targetReflKeys[targetIP]
	if len(candidates) == 0 {
		return false
	}
	incomingPerTarget := 0
	if incomingResp != "" {
		incomingPerTarget = c.respTargetInstCount[incomingResp][targetIP]
	}
	bestKey := ""
	bestSink := true
	bestPerTarget := -1
	bestGlobal := -1
	for k := range candidates {
		inst := c.mdnsInst[k]
		if inst == nil {
			continue
		}
		if !incomingIsAuth && c.isTrustedReflectorLocked(inst.createdBy) {
			continue
		}
		sink := isMDNSZeroByteSink(inst.svc.Type)
		perTarget := c.respTargetInstCount[inst.createdBy][targetIP]
		glob := c.respInstCount[inst.createdBy]
		if bestKey == "" ||
			(bestSink && !sink) ||
			(sink == bestSink && (perTarget > bestPerTarget || (perTarget == bestPerTarget && glob > bestGlobal))) {
			bestKey = k
			bestSink = sink
			bestPerTarget = perTarget
			bestGlobal = glob
		}
	}
	if bestKey == "" {
		return false
	}
	if !incomingIsAuth && !incomingIsTrusted {
		sinkReplacesNonSink := incomingIsSink && !bestSink
		fair := bestPerTarget > incomingPerTarget+1 || (incomingPerTarget == 0 && bestPerTarget >= 1)
		if !sinkReplacesNonSink && !fair {
			return false
		}
	}
	c.deleteMDNSInstLocked(bestKey)
	return true
}

func (c *DiscoveryCache) evictGlobalMDNSInstLocked(incomingResp string, incomingIsAuth, incomingIsTrusted bool) bool {
	// Pass 1 (O(1)): evict from the heaviest reflected/third-party sender,
	// preferring non-sink entries so zero-byte sink guards survive churn.
	if sender, cnt := c.reflInstBuckets.heaviest(); sender != "" && cnt > 0 {
		if cnt > 1 || incomingIsAuth || incomingIsTrusted {
			k := pickAnyKey(c.respReflNonSinkKeys[sender])
			if k == "" {
				k = pickAnyKey(c.respReflSinkKeys[sender])
			}
			if k != "" {
				c.deleteMDNSInstLocked(k)
				return true
			}
		}
	}
	// Pass 2 (O(1)): max-min fairness across all senders when no reflected entries remain.
	incomingCount := c.respInstCount[incomingResp]
	sender, maxCount := c.allInstBuckets.heaviest()
	if sender == "" || !(maxCount > incomingCount+1 || (incomingCount == 0 && maxCount > 1)) {
		return false
	}
	if k := pickAnyKey(c.respInstKeys[sender]); k != "" {
		c.deleteMDNSInstLocked(k)
		return true
	}
	return false
}

func (c *DiscoveryCache) recordHostIPLocked(host, ip, responderIP string, ttl uint32, now time.Time) {
	if host == "" || ip == "" {
		return
	}
	isAuth := responderIP != "" && responderIP == ip
	isTrusted := c.isTrustedReflectorLocked(responderIP)
	if ttl == 0 {
		if m := c.hostIPs[host]; m != nil {
			if prev, existed := m[ip]; existed {
				if prev.authoritative && !isAuth {
					// Never let a non-authoritative responder withdraw an authoritative host A/AAAA.
					return
				}
				owner := c.hostOwner[host]
				delete(m, ip)
				decCountMap(c.ipHostCount, ip)
				if !prev.authoritative {
					delNestedSet(c.ipReflHosts, ip, host)
					decNestedCount(c.respIPHostCount, owner, ip)
				}
			}
			if len(m) == 0 {
				c.deleteHostLocked(host)
			}
		}
		return
	}
	maxRespHosts := maxMDNSHostsPerResponder
	if isTrusted {
		maxRespHosts = maxMDNSHostsTotal / 2
	}
	if c.hostIPs[host] == nil {
		if responderIP != "" && c.respHostCount[responderIP] >= maxRespHosts {
			return
		}
		if !isAuth && !isTrusted && responderIP != "" && c.respIPHostCount[responderIP][ip] >= maxMDNSReflectedPerSenderTarget {
			return
		}
		if c.ipHostCount[ip] >= maxMDNSServicesPerHost {
			if !c.evictReflectedHostForIPLocked(ip, responderIP, isAuth, isTrusted) {
				return
			}
		}
		if len(c.hostIPs) >= maxMDNSHostsTotal {
			if !c.evictGlobalHostLocked(responderIP, isAuth, isTrusted) {
				return
			}
		}
		c.hostIPs[host] = make(map[string]cachedHostIP)
		if responderIP != "" {
			c.hostOwner[host] = responderIP
			c.respHostCount[responderIP]++
			c.allHostBuckets.inc(responderIP)
			addNestedSet(c.respHostKeys, responderIP, host)
			if !isAuth {
				c.hostReflected[host] = true
				c.reflHostBuckets.inc(responderIP)
				addNestedSet(c.respReflHostKeys, responderIP, host)
			}
		}
	}
	if prev, exists := c.hostIPs[host][ip]; !exists {
		if !isAuth && !isTrusted && responderIP != "" && c.respIPHostCount[responderIP][ip] >= maxMDNSReflectedPerSenderTarget {
			return
		}
		if c.ipHostCount[ip] >= maxMDNSServicesPerHost {
			if !c.evictReflectedHostForIPLocked(ip, responderIP, isAuth, isTrusted) {
				return
			}
		}
		if len(c.hostIPs[host]) >= maxMDNSIPsPerHost {
			evicted := ""
			if isAuth || isTrusted {
				for candIP, candEntry := range c.hostIPs[host] {
					if !candEntry.authoritative && (evicted == "" || candIP > evicted) {
						evicted = candIP
					}
				}
			}
			if evicted == "" {
				return
			}
			owner := c.hostOwner[host]
			delete(c.hostIPs[host], evicted)
			decCountMap(c.ipHostCount, evicted)
			delNestedSet(c.ipReflHosts, evicted, host)
			decNestedCount(c.respIPHostCount, owner, evicted)
		}
		c.ipHostCount[ip]++
		if !isAuth {
			addNestedSet(c.ipReflHosts, ip, host)
			incNestedCount(c.respIPHostCount, c.hostOwner[host], ip)
		}
	} else {
		if prev.authoritative {
			isAuth = true
		} else if isAuth {
			// Promoted from reflected to authoritative for this IP.
			delNestedSet(c.ipReflHosts, ip, host)
			decNestedCount(c.respIPHostCount, c.hostOwner[host], ip)
		}
	}
	if isAuth && c.hostReflected[host] {
		delete(c.hostReflected, host)
		if owner := c.hostOwner[host]; owner != "" {
			c.reflHostBuckets.dec(owner)
			delNestedSet(c.respReflHostKeys, owner, host)
		}
	}
	c.hostIPs[host][ip] = cachedHostIP{
		expiresAt:     now.UTC().Add(time.Duration(ttl) * time.Second),
		authoritative: isAuth,
	}
}

func (c *DiscoveryCache) ensureMDNSInstLocked(key, svcType, instance, responderIP, observerIface, observerVLAN string, targetIPs []string, now time.Time) *cachedMDNSInst {
	inst := c.mdnsInst[key]
	if inst == nil {
		incomingIsTrusted := c.isTrustedReflectorLocked(responderIP)
		maxPerResp := maxMDNSServicesPerResponder
		if incomingIsTrusted {
			maxPerResp = maxMDNSServicesTotal / 2
		}
		if responderIP != "" && c.respInstCount[responderIP] >= maxPerResp {
			return nil
		}
		incomingIsAuth := responderIP != "" && containsString(targetIPs, responderIP)
		incomingIsSink := isMDNSZeroByteSink(svcType)
		if len(targetIPs) == 0 {
			if responderIP != "" && c.respUnresolvedCount[responderIP] >= maxMDNSServicesPerHost {
				return nil
			}
		} else {
			if !incomingIsAuth && !incomingIsTrusted && responderIP != "" {
				allOverSenderTargetCap := true
				for _, tip := range targetIPs {
					if c.respTargetInstCount[responderIP][tip] < maxMDNSReflectedPerSenderTarget {
						allOverSenderTargetCap = false
						break
					}
				}
				if allOverSenderTargetCap {
					return nil
				}
			}
			for _, tip := range targetIPs {
				if c.targetInstCount[tip] >= maxMDNSServicesPerHost {
					c.evictReflectedInstForTargetLocked(tip, responderIP, incomingIsAuth, incomingIsTrusted, incomingIsSink)
				}
			}
			allAtCap := true
			for _, tip := range targetIPs {
				if c.targetInstCount[tip] < maxMDNSServicesPerHost {
					allAtCap = false
					break
				}
			}
			if allAtCap {
				return nil
			}
		}
		if len(c.mdnsInst) >= maxMDNSServicesTotal {
			if !c.evictGlobalMDNSInstLocked(responderIP, incomingIsAuth, incomingIsTrusted) {
				return nil
			}
		}
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
			createdBy:    responderIP,
			responderIPs: make(map[string]struct{}),
		}
		if responderIP != "" {
			inst.responderIPs[responderIP] = struct{}{}
			c.respInstCount[responderIP]++
			c.allInstBuckets.inc(responderIP)
			addNestedSet(c.respInstKeys, responderIP, key)
		}
		if len(targetIPs) == 0 {
			if responderIP != "" {
				inst.countedUnresolved = true
				c.respUnresolvedCount[responderIP]++
			}
		} else {
			inst.countedTargetIPs = append([]string(nil), targetIPs...)
			for _, tip := range targetIPs {
				c.targetInstCount[tip]++
			}
		}
		c.mdnsInst[key] = inst
		if !incomingIsAuth {
			c.indexReflectedInstLocked(key, inst)
		}
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
			if inst.responderIPs == nil {
				inst.responderIPs = make(map[string]struct{})
			}
			if _, exists := inst.responderIPs[responderIP]; !exists && len(inst.responderIPs) < maxMDNSRespondersPerInst {
				inst.responderIPs[responderIP] = struct{}{}
			}
			if inst.svc.ResponderIP == "" {
				inst.svc.ResponderIP = responderIP
			}
			if containsString(inst.countedTargetIPs, responderIP) {
				c.unindexReflectedInstLocked(key, inst)
			}
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
	return low == "_pdl-datastream._tcp" || low == "_pdl-datastream._udp" || low == "_printer._tcp"
}

// isMDNSRawSerialSink reports whether a DNS-SD type represents a raw UART or
// Ethernet Zigbee coordinator serial bridge that must remain connect-only so
// TLS ClientHello or banner probe bytes are never injected into the radio stream.
func isMDNSRawSerialSink(svcType string) bool {
	low := strings.ToLower(strings.TrimSpace(svcType))
	switch low {
	case "_slzb-06._tcp", "_uzg-01._tcp", "_smlight._tcp", "_esphome-uart._tcp", "_zigbee-coordinator._tcp":
		return true
	default:
		return false
	}
}

// isMDNSZeroByteSink reports whether a DNS-SD type requires strict connect-only
// zero-byte probing (raw print sinks and raw serial/Zigbee UART bridges).
func isMDNSZeroByteSink(svcType string) bool {
	return isMDNSRawPrintSink(svcType) || isMDNSRawSerialSink(svcType)
}

// isWellKnownSerialSinkPort reports whether port is a standard Ethernet Zigbee
// or serial-coordinator socket port (SLZB-06 / UZG-01 / ZigStar / ZB-GW03).
func isWellKnownSerialSinkPort(port int) bool {
	switch port {
	case 6638, 6639, 20108:
		return true
	default:
		return false
	}
}

// isKnownNonSerialServicePort lists standard non-serial administrative, database,
// web, remote-desktop, and messaging TCP ports that a reflected serial-bridge
// advertisement must never be allowed to hide from active security checks.
func isKnownNonSerialServicePort(port int) bool {
	if port < 1024 {
		return true
	}
	if port >= 5900 && port <= 5919 {
		return true
	}
	switch port {
	case 1080, 1433, 1521, 1883, 2049, 2181, 2375, 2376, 2379,
		3000, 3128, 3306, 3389, 4444, 5000, 5001, 5432, 5601, 5672,
		5984, 5985, 5986, 6379, 6443, 7001, 8000, 8006, 8008, 8080,
		8081, 8086, 8088, 8123, 8200, 8443, 8883, 9000, 9090,
		9200, 9300, 10000, 10250, 11211, 15672, 27017, 32400:
		return true
	default:
		return false
	}
}

// shouldProtectMDNSSinkPort reports whether an mDNS zero-byte sink (raw print
// or serial/Zigbee UART bridge) should enforce connect-only protection on port.
// Authoritative self-announcements are always honored; reflected announcements
// from a local reflector are honored for JetDirect raw print ports (9100-9107)
// and for serial coordinator ports (6638, 6639, 20108, or custom high ports
// outside well-known non-serial services) so legitimate relayed coordinators
// and printers stay zero-byte protected while forged adverts cannot hide
// Redis, Docker, RDP, VNC, SMB, SSH, or HTTP admin ports.
func shouldProtectMDNSSinkPort(svcType string, port int, authoritative bool, responderIP string) bool {
	if port <= 0 || !isMDNSZeroByteSink(svcType) {
		return false
	}
	if authoritative {
		return true
	}
	if responderIP != "" && !isAllowedProbeIPWithSubnets(responderIP, nil) {
		return false
	}
	if isMDNSRawSerialSink(svcType) {
		return isWellKnownSerialSinkPort(port) || !isKnownNonSerialServicePort(port)
	}
	if isMDNSRawPrintSink(svcType) {
		return port >= 9100 && port <= 9107
	}
	return false
}

// PruneExpired drops expired or withdrawn mDNS records (including A/AAAA entries) as of now.
func (c *DiscoveryCache) PruneExpired(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, inst := range c.mdnsInst {
		if inst.svc.Withdrawn || (inst.svc.ExpiresAt != nil && now.After(*inst.svc.ExpiresAt)) {
			c.deleteMDNSInstLocked(k)
		}
	}
	for host, ipMap := range c.hostIPs {
		owner := c.hostOwner[host]
		for ip, entry := range ipMap {
			if !entry.expiresAt.IsZero() && now.After(entry.expiresAt) {
				delete(ipMap, ip)
				decCountMap(c.ipHostCount, ip)
				if !entry.authoritative {
					delNestedSet(c.ipReflHosts, ip, host)
					decNestedCount(c.respIPHostCount, owner, ip)
				}
			}
		}
		if len(ipMap) == 0 {
			c.deleteHostLocked(host)
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

	type mdnsCandidate struct {
		svc          MDNSService
		directMatch  bool
		noResponders bool
	}
	byIP := make(map[string][]mdnsCandidate)
	seenIdx := make(map[string]int)

	for _, inst := range c.mdnsInst {
		svc := inst.svc
		if svc.Withdrawn || (svc.ExpiresAt != nil && now.After(*svc.ExpiresAt)) {
			continue
		}
		allResponders := make([]string, 0, len(inst.responderIPs))
		for rip := range inst.responderIPs {
			allResponders = append(allResponders, rip)
		}
		sort.Strings(allResponders)

		var ips []string
		if inst.targetHost != "" {
			for ip, entry := range c.hostIPs[inst.targetHost] {
				if !entry.expiresAt.IsZero() && now.After(entry.expiresAt) {
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
		} else if len(allResponders) > 0 {
			ips = allResponders
		} else if svc.ResponderIP != "" {
			ips = []string{svc.ResponderIP}
		}
		if len(ips) == 0 {
			continue
		}
		svc.TargetIPs = ips
		svc.AddressFamily = IPFamily(ips)

		hasResponder := func(ip string) bool {
			if len(inst.responderIPs) == 0 {
				return false
			}
			_, ok := inst.responderIPs[canonicalIPKey(ip)]
			return ok
		}

		// Compute authority strictly per target IP and per SRV responder so a
		// third-party SRV can never inherit another responder's authority.
		for _, ip := range ips {
			svcForIP := svc
			var directMatch bool
			if inst.srvResponder != "" {
				directMatch = inst.srvAuthoritative && inst.srvResponder == canonicalIPKey(ip)
			} else {
				directMatch = hasResponder(ip)
			}
			if len(allResponders) > 0 {
				if directMatch {
					svcForIP.ResponderIP = ip
					svcForIP.Reflected = false
					svcForIP.TrustedReflector = false
				} else {
					if inst.srvResponder != "" {
						svcForIP.ResponderIP = inst.srvResponder
					} else {
						svcForIP.ResponderIP = allResponders[0]
					}
					svcForIP.Reflected = true
					svcForIP.TrustedReflector = c.isTrustedReflectorLocked(svcForIP.ResponderIP)
				}
			}

			dedup := fmt.Sprintf("%s|%s|%s|%d|%s", ip, svcForIP.ObserverVLAN, svcForIP.Type, svcForIP.Port, svcForIP.Instance)
			cand := mdnsCandidate{
				svc:          svcForIP,
				directMatch:  directMatch,
				noResponders: len(allResponders) == 0,
			}
			if idx, dup := seenIdx[dedup]; dup {
				if !byIP[ip][idx].directMatch && cand.directMatch {
					byIP[ip][idx] = cand
				}
				continue
			}
			seenIdx[dedup] = len(byIP[ip])
			byIP[ip] = append(byIP[ip], cand)
		}
	}

	for ip, list := range byIP {
		// Prioritize authoritative services and zero-byte sinks ahead of reflected
		// services before enforcing the per-target-IP cap so spoofed reflected
		// floods cannot evict a host's own announcements or sink protections.
		sort.Slice(list, func(i, j int) bool {
			if list[i].svc.Reflected != list[j].svc.Reflected {
				return !list[i].svc.Reflected
			}
			iSink := isMDNSZeroByteSink(list[i].svc.Type)
			jSink := isMDNSZeroByteSink(list[j].svc.Type)
			if iSink != jSink {
				return iSink
			}
			if list[i].svc.Type != list[j].svc.Type {
				return list[i].svc.Type < list[j].svc.Type
			}
			if list[i].svc.Port != list[j].svc.Port {
				return list[i].svc.Port < list[j].svc.Port
			}
			return list[i].svc.Instance < list[j].svc.Instance
		})
		if len(list) > maxMDNSServicesPerHost {
			list = list[:maxMDNSServicesPerHost]
		}
		for _, cand := range list {
			svcForIP := cand.svc
			res.MDNS[ip] = append(res.MDNS[ip], svcForIP)

			if isMDNSZeroByteSink(svcForIP.Type) {
				isAuthoritative := cand.noResponders || cand.directMatch
				if shouldProtectMDNSSinkPort(svcForIP.Type, svcForIP.Port, isAuthoritative, svcForIP.ResponderIP) {
					if res.RawPrintIPs[ip] == nil {
						res.RawPrintIPs[ip] = make(map[int]struct{})
					}
					res.RawPrintIPs[ip][svcForIP.Port] = struct{}{}
				}
				continue
			}
			// Never dial Matter operational (_matter._tcp uses UDP) or any UDP service via TCP.
			if svcForIP.Transport == "tcp" && svcForIP.Port > 0 && !svcForIP.Reflected {
				addPort(ip, svcForIP.Port)
			}
		}
		sort.Slice(res.MDNS[ip], func(i, j int) bool {
			if res.MDNS[ip][i].Type != res.MDNS[ip][j].Type {
				return res.MDNS[ip][i].Type < res.MDNS[ip][j].Type
			}
			if res.MDNS[ip][i].Port != res.MDNS[ip][j].Port {
				return res.MDNS[ip][i].Port < res.MDNS[ip][j].Port
			}
			return res.MDNS[ip][i].Instance < res.MDNS[ip][j].Instance
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

// IPFamily reports ipv4, ipv6, dual, or an empty string for an unknown family.
func IPFamily(ips []string) string {
	hasV4, hasV6 := false, false
	for _, s := range ips {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		if ip.Unmap().Is4() {
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

func isExcludedIP(ip string, excluded map[string]struct{}) bool {
	if len(excluded) == 0 || ip == "" {
		return false
	}
	if _, ok := excluded[ip]; ok {
		return true
	}
	canon := canonicalIPKey(ip)
	if canon == "" {
		return false
	}
	if _, ok := excluded[canon]; ok {
		return true
	}
	for ex := range excluded {
		if canonicalIPKey(ex) == canon {
			return true
		}
	}
	return false
}

// DiscoverLAN performs one bounded, read-only multicast discovery sweep across
// mDNS/DNS-SD (UDP 5353), SSDP/UPnP (UDP 1900), and WS-Discovery (UDP 3702).
// Any network permission errors (e.g., in restricted sandboxes) degrade
// gracefully to an empty result so LAN scanning still succeeds.
func DiscoverLAN(ctx context.Context, httpClient *http.Client) *LANDiscovery {
	return DiscoverLANWithExclusions(ctx, httpClient, nil)
}

// DiscoverLANWithExclusions performs one bounded, read-only multicast discovery
// sweep while ensuring that any IP in excluded never receives unicast SSDP
// description HTTP GETs or discovery-derived port hints.
func DiscoverLANWithExclusions(ctx context.Context, httpClient *http.Client, excluded map[string]struct{}) *LANDiscovery {
	return discoverLANWithOptions(ctx, httpClient, excluded, nil, nil)
}

func discoverLANWithOptions(ctx context.Context, httpClient *http.Client, excluded map[string]struct{}, allowedSubnets []netip.Prefix, trustedReflectors []string) *LANDiscovery {
	res := &LANDiscovery{
		MDNS:        make(map[string][]MDNSService),
		UPnP:        make(map[string][]UPnPDevice),
		WSDiscovery: make(map[string][]WSDiscoveryRecord),
		PortsByIP:   make(map[string][]int),
		RawPrintIPs: make(map[string]map[int]struct{}),
		Unavailable: make(map[string]string),
	}

	listenCtx, cancelListen := context.WithTimeout(ctx, discoveryWindow+200*time.Millisecond)
	defer cancelListen()

	var wg sync.WaitGroup
	var mdnsSnap *LANDiscovery
	var ssdpHits []ssdpHit
	var ssdpNoLoc map[string][]ssdpHit
	var wsdRes map[string][]WSDiscoveryRecord

	wg.Add(3)
	go func() {
		defer wg.Done()
		mdnsSnap = discoverMDNSSnapshotWithReflectors(listenCtx, trustedReflectors)
	}()
	go func() {
		defer wg.Done()
		ssdpHits, ssdpNoLoc = listenSSDPWithSubnets(listenCtx, allowedSubnets)
	}()
	go func() {
		defer wg.Done()
		wsdRes = discoverWSD(listenCtx)
	}()
	wg.Wait()

	portSet := make(map[string]map[int]struct{})
	addPort := func(ip string, port int) {
		if ip == "" || port < 1 || port > 65535 || isExcludedIP(ip, excluded) {
			return
		}
		if portSet[ip] == nil {
			portSet[ip] = make(map[int]struct{})
		}
		portSet[ip][port] = struct{}{}
	}

	if mdnsSnap != nil {
		for k, v := range mdnsSnap.Unavailable {
			res.Unavailable[k] = v
		}
		for ip, svcs := range mdnsSnap.MDNS {
			if isExcludedIP(ip, excluded) {
				continue
			}
			res.MDNS[ip] = svcs
		}
		for ip, rps := range mdnsSnap.RawPrintIPs {
			if isExcludedIP(ip, excluded) {
				continue
			}
			res.RawPrintIPs[ip] = rps
		}
		for ip, ports := range mdnsSnap.PortsByIP {
			if isExcludedIP(ip, excluded) {
				continue
			}
			for _, p := range ports {
				addPort(ip, p)
			}
		}
	}

	// Fetch UPnP XML descriptions AFTER collecting mDNS zero-byte sink ports so
	// SSDP never writes HTTP bytes to any advertised raw print or serial sink,
	// using a fresh timeout budget derived from parent ctx.
	fetchCtx, cancelFetch := context.WithTimeout(ctx, ssdpFetchBudget)
	defer cancelFetch()

	upnpRes := fetchSSDPDescriptionsWithSubnets(fetchCtx, httpClient, ssdpHits, ssdpNoLoc, res.RawPrintIPs, excluded, allowedSubnets)
	for ip, devs := range upnpRes {
		if isExcludedIP(ip, excluded) {
			continue
		}
		res.UPnP[ip] = devs
		for _, d := range devs {
			if d.Port > 0 && !isRawPrintSinkPort(d.Port, res, ip) {
				addPort(ip, d.Port)
			}
		}
	}
	for ip, recs := range wsdRes {
		if isExcludedIP(ip, excluded) {
			continue
		}
		res.WSDiscovery[ip] = recs
		for _, r := range recs {
			for _, p := range r.Ports {
				if !isRawPrintSinkPort(p, res, ip) {
					addPort(ip, p)
				}
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
	return discoverMDNSSnapshot(ctx).MDNS
}

func discoverMDNSSnapshot(ctx context.Context) *LANDiscovery {
	return discoverMDNSSnapshotWithReflectors(ctx, nil)
}

func discoverMDNSSnapshotWithReflectors(ctx context.Context, trustedReflectors []string) *LANDiscovery {
	cache := NewDiscoveryCache()
	if len(trustedReflectors) > 0 {
		cache.SetTrustedReflectors(trustedReflectors)
	}
	collectMDNSIntoCache(ctx, cache)
	return cache.Snapshot(time.Now().UTC())
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

	if qdCount > maxDNSQuestionsPerPacket {
		return nil
	}
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
	if totalRR > maxDNSRecordsPerPacket {
		totalRR = maxDNSRecordsPerPacket
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
			for pos < end && len(pairs) < maxMDNSTXTEntriesPerRR {
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

// readDNSName reads a compressed RFC 1035 domain name starting at off while
// enforcing the RFC 1035 255-byte maximum decompressed wire length.
func readDNSName(pkt []byte, off int) (string, int, bool) {
	var labels []string
	jumped := false
	origNext := off
	steps := 0
	wireLen := 0

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
		// Account for length octet + label bytes; final root 0x00 octet must still fit in 255 bytes.
		wireLen += 1 + lblLen
		if wireLen >= maxDNSNameWireBytes {
			return "", 0, false
		}
		labels = append(labels, string(pkt[off+1:off+1+lblLen]))
		off += 1 + lblLen
	}
	return "", 0, false
}

func stripLocalSuffix(name string) string {
	trimmed := strings.TrimSuffix(strings.TrimSpace(name), ".")
	if len(trimmed) >= len(".local") && strings.EqualFold(trimmed[len(trimmed)-len(".local"):], ".local") {
		trimmed = trimmed[:len(trimmed)-len(".local")]
	}
	return trimmed
}

func normalizeMDNSType(name string) string {
	n := stripLocalSuffix(name)
	low := strings.ToLower(n)
	if strings.HasPrefix(low, "_") && (strings.HasSuffix(low, "._tcp") || strings.HasSuffix(low, "._udp")) {
		return n
	}
	return ""
}

func extractMDNSTypeFromFull(full string) string {
	trimmed := stripLocalSuffix(full)
	parts := strings.Split(trimmed, ".")
	if len(parts) >= 2 {
		proto := strings.ToLower(parts[len(parts)-1])
		if strings.HasPrefix(parts[len(parts)-2], "_") && (proto == "_tcp" || proto == "_udp") {
			return parts[len(parts)-2] + "." + parts[len(parts)-1]
		}
	}
	return ""
}

func extractMDNSInstance(full, svcType string) string {
	trimmed := stripLocalSuffix(full)
	if svcType != "" {
		suffix := "." + svcType
		if len(trimmed) >= len(suffix) && strings.EqualFold(trimmed[len(trimmed)-len(suffix):], suffix) {
			trimmed = trimmed[:len(trimmed)-len(suffix)]
		}
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
	totalBytes := 0
	kept := out[:0]
	for _, entry := range out {
		if totalBytes+len(entry) > maxMDNSTXTBytesPerInst && len(kept) > 0 {
			break
		}
		totalBytes += len(entry)
		kept = append(kept, entry)
	}
	return kept
}

type ssdpHit struct {
	ip       string
	st       string
	sts      []string
	server   string
	location string
}

type ssdpCollector struct {
	hitsByLoc       map[string]ssdpHit
	locCountByIP    map[string]int
	igdLocCountByIP map[string]int
	noLocHits       map[string][]ssdpHit
	seenNoLoc       map[string]struct{}
	totalNoLoc      int
}

func newSSDPCollector() *ssdpCollector {
	return &ssdpCollector{
		hitsByLoc:       make(map[string]ssdpHit),
		locCountByIP:    make(map[string]int),
		igdLocCountByIP: make(map[string]int),
		noLocHits:       make(map[string][]ssdpHit),
		seenNoLoc:       make(map[string]struct{}),
	}
}

func isSSDPGatewayST(st string) bool {
	low := strings.ToLower(strings.TrimSpace(st))
	return strings.Contains(low, "internetgatewaydevice") ||
		strings.Contains(low, "wanipconnection") ||
		strings.Contains(low, "wanpppconnection") ||
		strings.Contains(low, "wancommoninterfaceconfig")
}

func hitHasGatewayST(h ssdpHit) bool {
	if isSSDPGatewayST(h.st) {
		return true
	}
	for _, s := range h.sts {
		if isSSDPGatewayST(s) {
			return true
		}
	}
	return false
}

// evictForFairness makes room for a new SSDP LOCATION from incomingIP when the
// global table is full. It applies max-min fairness across responder IPs so a
// multi-source flooder holding multiple slots per IP (including forged IGD
// locations) cannot starve new devices or the real gateway's IGD.
func (c *ssdpCollector) evictForFairness(incomingIP string, incomingIsIGD bool) bool {
	incomingCount := c.locCountByIP[incomingIP]
	maxCount := 0
	igdCount := 0
	for _, h := range c.hitsByLoc {
		if hitHasGatewayST(h) {
			igdCount++
			continue
		}
		if cnt := c.locCountByIP[h.ip]; cnt > maxCount {
			maxCount = cnt
		}
	}

	canEvictByFairness := maxCount > 0 && (maxCount > incomingCount+1 || (incomingCount == 0 && maxCount > 1))
	canEvictForIGD := maxCount > 0 && incomingIsIGD && igdCount < maxSSDPIGDReservedSlots
	if canEvictByFairness || canEvictForIGD {
		// Choose a deterministic non-IGD victim from an IP holding maxCount entries.
		victimKey := ""
		for k, h := range c.hitsByLoc {
			if hitHasGatewayST(h) {
				continue
			}
			if c.locCountByIP[h.ip] != maxCount {
				continue
			}
			if victimKey == "" || k > victimKey {
				victimKey = k
			}
		}
		if victimKey != "" {
			victimIP := c.hitsByLoc[victimKey].ip
			delete(c.hitsByLoc, victimKey)
			decCountMap(c.locCountByIP, victimIP)
			return true
		}
	}

	// Fallback: when non-IGD eviction cannot make room (for example, a forged
	// IGD-labelled flood filling the table), evict an excess IGD entry from a
	// sender holding more than one IGD LOCATION.
	incomingIGDCount := c.igdLocCountByIP[incomingIP]
	maxIGDPerIP := 0
	for _, h := range c.hitsByLoc {
		if !hitHasGatewayST(h) {
			continue
		}
		if cnt := c.igdLocCountByIP[h.ip]; cnt > maxIGDPerIP {
			maxIGDPerIP = cnt
		}
	}
	if maxIGDPerIP <= 1 || !(incomingCount == 0 || maxIGDPerIP > incomingIGDCount+1) {
		return false
	}
	victimKey := ""
	victimTotal := 0
	for k, h := range c.hitsByLoc {
		if !hitHasGatewayST(h) || c.igdLocCountByIP[h.ip] != maxIGDPerIP {
			continue
		}
		tot := c.locCountByIP[h.ip]
		if victimKey == "" || tot > victimTotal || (tot == victimTotal && k > victimKey) {
			victimKey = k
			victimTotal = tot
		}
	}
	if victimKey == "" {
		return false
	}
	victimIP := c.hitsByLoc[victimKey].ip
	delete(c.hitsByLoc, victimKey)
	decCountMap(c.locCountByIP, victimIP)
	decCountMap(c.igdLocCountByIP, victimIP)
	return true
}

func (c *ssdpCollector) ingest(ip, raw string) {
	if ip == "" || raw == "" {
		return
	}
	hdrs := parseSSDPHeaders(raw)
	st := hdrs["st"]
	if st == "" {
		st = hdrs["nt"]
	}
	loc := hdrs["location"]
	srv := hdrs["server"]
	if loc != "" {
		key := ip + "|" + loc
		incomingIsIGD := isSSDPGatewayST(st)
		if cur, exists := c.hitsByLoc[key]; exists {
			wasIGD := hitHasGatewayST(cur)
			allowST := st != "" && (wasIGD || !incomingIsIGD || c.igdLocCountByIP[ip] < maxSSDPIGDLocHitsPerIP)
			if allowST && len(cur.sts) < maxSSDPSTsPerLocation {
				dup := false
				for _, prev := range cur.sts {
					if prev == st {
						dup = true
						break
					}
				}
				if !dup {
					cur.sts = append(cur.sts, st)
				}
			}
			if allowST && cur.st == "" {
				cur.st = st
			}
			if !wasIGD && hitHasGatewayST(cur) {
				c.igdLocCountByIP[ip]++
			}
			if cur.server == "" && srv != "" {
				cur.server = srv
			}
			c.hitsByLoc[key] = cur
			return
		}
		if c.locCountByIP[ip] >= maxSSDPLocHitsPerIP {
			return
		}
		if incomingIsIGD && c.igdLocCountByIP[ip] >= maxSSDPIGDLocHitsPerIP {
			return
		}
		if len(c.hitsByLoc) >= maxSSDPLocHitsTotal && !c.evictForFairness(ip, incomingIsIGD) {
			return
		}
		var sts []string
		if st != "" {
			sts = []string{st}
		}
		c.hitsByLoc[key] = ssdpHit{ip: ip, st: st, sts: sts, server: srv, location: loc}
		c.locCountByIP[ip]++
		if incomingIsIGD {
			c.igdLocCountByIP[ip]++
		}
		return
	}
	if st == "" && srv == "" {
		return
	}
	dedupKey := ip + "|" + st + "|" + srv
	if _, dup := c.seenNoLoc[dedupKey]; dup {
		return
	}
	if len(c.noLocHits[ip]) >= maxSSDPNoLocHitsPerIP || c.totalNoLoc >= maxSSDPNoLocHitsTotal {
		return
	}
	c.seenNoLoc[dedupKey] = struct{}{}
	c.noLocHits[ip] = append(c.noLocHits[ip], ssdpHit{ip: ip, st: st, server: srv})
	c.totalNoLoc++
}

func (c *ssdpCollector) result() ([]ssdpHit, map[string][]ssdpHit) {
	hits := make([]ssdpHit, 0, len(c.hitsByLoc))
	for _, h := range c.hitsByLoc {
		hits = append(hits, h)
	}
	// Prioritize InternetGatewayDevice hits first so UPnP IGD descriptions are
	// fetched immediately within the fetch budget ahead of noisy devices.
	sort.Slice(hits, func(i, j int) bool {
		igI := hitHasGatewayST(hits[i])
		igJ := hitHasGatewayST(hits[j])
		if igI != igJ {
			return igI
		}
		if hits[i].ip != hits[j].ip {
			return hits[i].ip < hits[j].ip
		}
		return hits[i].location < hits[j].location
	})
	return hits, c.noLocHits
}

// listenSSDP issues a single bounded SSDP M-SEARCH (MX: 1, ST: ssdp:all) and
// returns passive UDP responses without sending any HTTP requests yet.
func listenSSDP(ctx context.Context) ([]ssdpHit, map[string][]ssdpHit) {
	return listenSSDPWithSubnets(ctx, nil)
}

func listenSSDPWithSubnets(ctx context.Context, allowedSubnets []netip.Prefix) ([]ssdpHit, map[string][]ssdpHit) {
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

	collector := newSSDPCollector()
	buf := make([]byte, 4096)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if src == nil || src.IP == nil || n == 0 {
			continue
		}
		srcIP := src.IP.String()
		if !isAllowedProbeIPWithSubnets(srcIP, allowedSubnets) {
			continue
		}
		collector.ingest(srcIP, string(buf[:n]))
	}
	return collector.result()
}

func mergedSSDPSTs(h ssdpHit) (string, []string) {
	var list []string
	seen := make(map[string]struct{})
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if _, dup := seen[s]; dup {
			return
		}
		seen[s] = struct{}{}
		list = append(list, s)
	}
	add(h.st)
	for _, s := range h.sts {
		add(s)
	}
	if len(list) == 0 {
		return "", nil
	}
	var extraSvcs []string
	for _, s := range list {
		if strings.Contains(strings.ToLower(s), ":service:") {
			extraSvcs = append(extraSvcs, s)
		}
	}
	return strings.Join(list, " "), extraSvcs
}

// fetchSSDPDescriptions fetches at most one same-host pinned UPnP XML
// description per unique location while enforcing excluded IPs, allowed LAN
// subnets, and the zero-byte sink guard across raw print and serial sinks.
func fetchSSDPDescriptions(ctx context.Context, httpClient *http.Client, hits []ssdpHit, noLocHits map[string][]ssdpHit, rawPrintIPs map[string]map[int]struct{}, excluded map[string]struct{}) map[string][]UPnPDevice {
	return fetchSSDPDescriptionsWithSubnets(ctx, httpClient, hits, noLocHits, rawPrintIPs, excluded, nil)
}

func fetchSSDPDescriptionsWithSubnets(ctx context.Context, httpClient *http.Client, hits []ssdpHit, noLocHits map[string][]ssdpHit, rawPrintIPs map[string]map[int]struct{}, excluded map[string]struct{}, allowedSubnets []netip.Prefix) map[string][]UPnPDevice {
	out := make(map[string][]UPnPDevice)
	for ip, list := range noLocHits {
		if isExcludedIP(ip, excluded) || !isAllowedProbeIPWithSubnets(ip, allowedSubnets) {
			continue
		}
		for _, h := range list {
			out[ip] = append(out[ip], UPnPDevice{ST: h.st, Server: h.server, AddressFamily: ipFamilyOf(ip)})
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
		if isExcludedIP(h.ip, excluded) || !isAllowedProbeIPWithSubnets(h.ip, allowedSubnets) {
			continue
		}
		mergedST, stServices := mergedSSDPSTs(h)
		port, safeURL, ok := validateSameHostURL(h.location, h.ip)
		if ok {
			if parsed, perr := url.Parse(safeURL); perr != nil || !isAllowedProbeIPWithSubnets(parsed.Hostname(), allowedSubnets) {
				ok = false
			}
		}
		if !ok {
			mu.Lock()
			out[h.ip] = append(out[h.ip], UPnPDevice{ST: mergedST, Server: h.server, ServiceTypes: stServices, AddressFamily: ipFamilyOf(h.ip)})
			mu.Unlock()
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			dev := UPnPDevice{ST: mergedST, Server: h.server, Port: port, ServiceTypes: stServices, AddressFamily: ipFamilyOf(h.ip)}
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
			val := strings.TrimSpace(v)
			limit := maxSSDPHeaderLen
			if key == "location" {
				limit = maxSSDPLocationLen
			}
			if len(val) > limit {
				val = val[:limit]
			}
			out[key] = val
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
	reqCtx, cancel := context.WithTimeout(ctx, 2000*time.Millisecond)
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
	svcSeen := make(map[string]struct{}, len(dev.ServiceTypes))
	for _, existing := range dev.ServiceTypes {
		svcSeen[existing] = struct{}{}
	}
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

func newRandomUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		binary.BigEndian.PutUint64(b[0:8], uint64(time.Now().UnixNano()))
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func buildWSDProbeXML() string {
	return `<?xml version="1.0" encoding="utf-8"?>` +
		`<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" ` +
		`xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" ` +
		`xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" ` +
		`xmlns:dn="http://www.onvif.org/ver10/network/wsdl">` +
		`<e:Header><w:MessageID>uuid:` + newRandomUUID() + `</w:MessageID>` +
		`<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>` +
		`<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header>` +
		`<e:Body><d:Probe/></e:Body></e:Envelope>`
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
	_, _ = conn.WriteToUDP([]byte(buildWSDProbeXML()), dst)

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
			rec.AddressFamily = ipFamilyOf(ip)
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
