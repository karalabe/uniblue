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
}

// safeMDNSTXTKeys restricts persisted DNS-SD TXT attributes to benign model,
// protocol, and posture keys so room names, SSIDs, or tokens are never stored.
var safeMDNSTXTKeys = map[string]struct{}{
	"md": {}, "ty": {}, "pv": {}, "sf": {}, "rp": {}, "rs": {},
	"api_version": {}, "version": {}, "ver": {}, "fw": {}, "firmware": {},
	"model": {}, "product": {}, "board": {}, "platform": {}, "mac": {},
	"api_encryption": {}, "network": {}, "gen": {}, "auth": {}, "auth_en": {},
	"usb_mfg": {}, "usb_mdl": {}, "pdl": {}, "txtvers": {}, "am": {},
}

// MDNSService records a single DNS-SD service advertisement observed on the LAN.
type MDNSService struct {
	// Type is the normalized DNS-SD service type (e.g., "_esphomelib._tcp").
	Type string `json:"type"`

	// Instance is the advertised instance label (e.g., "living-room-sensor").
	Instance string `json:"instance,omitempty"`

	// Port is the SRV target port advertised by the service.
	Port int `json:"port,omitempty"`

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
}

// WSDiscoveryRecord stores one WS-Discovery ProbeMatch (ONVIF cameras, WSD printers/hosts).
type WSDiscoveryRecord struct {
	// Types lists resolved local-name device types (e.g., "NetworkVideoTransmitter").
	Types []string `json:"types,omitempty"`

	// Scopes lists allowlisted non-sensitive scope tokens (e.g., "onvif://www.onvif.org/type/video_encoder").
	Scopes []string `json:"scopes,omitempty"`

	// Ports lists TCP ports parsed from same-host XAddr HTTP(S) URLs.
	Ports []int `json:"ports,omitempty"`
}

// LANDiscovery holds all passive/multicast observations indexed by IPv4 address.
type LANDiscovery struct {
	MDNS        map[string][]MDNSService
	UPnP        map[string][]UPnPDevice
	WSDiscovery map[string][]WSDiscoveryRecord
	PortsByIP   map[string][]int
	RawPrintIPs map[string]map[int]struct{}
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
	var upnpRes map[string][]UPnPDevice
	var wsdRes map[string][]WSDiscoveryRecord

	wg.Add(3)
	go func() {
		defer wg.Done()
		mdnsRes = discoverMDNS(discCtx)
	}()
	go func() {
		defer wg.Done()
		upnpRes = discoverSSDP(discCtx, httpClient)
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
			if strings.HasPrefix(strings.ToLower(s.Type), "_pdl-datastream.") {
				if res.RawPrintIPs[ip] == nil {
					res.RawPrintIPs[ip] = make(map[int]struct{})
				}
				if s.Port > 0 {
					res.RawPrintIPs[ip][s.Port] = struct{}{}
				}
				continue
			}
			// Only feed TCP SRV ports into the TCP fingerprinter.
			if strings.Contains(strings.ToLower(s.Type), "._tcp") && s.Port > 0 {
				addPort(ip, s.Port)
			}
		}
	}
	for ip, devs := range upnpRes {
		res.UPnP[ip] = devs
		for _, d := range devs {
			if d.Port > 0 {
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

// discoverMDNS sends bounded RFC 6762 DNS-SD PTR queries to 224.0.0.251:5353
// and collects PTR, SRV, TXT, and A responses over discoveryWindow.
func discoverMDNS(ctx context.Context) map[string][]MDNSService {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil
	}
	defer conn.Close()

	dst, err := net.ResolveUDPAddr("udp4", mdnsMulticastAddr)
	if err != nil {
		return nil
	}

	// Batch DNS-SD PTR questions into compact <= 1200-byte packets to stay well
	// under standard 1500-byte Ethernet MTU.
	for i := 0; i < len(mdnsQueryTypes); i += 10 {
		end := i + 10
		if end > len(mdnsQueryTypes) {
			end = len(mdnsQueryTypes)
		}
		if pkt := buildMDNSQuery(mdnsQueryTypes[i:end]); len(pkt) > 0 {
			_, _ = conn.WriteToUDP(pkt, dst)
		}
	}

	deadline := time.Now().Add(discoveryWindow)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetReadDeadline(deadline)

	type pendingInst struct {
		svcType  string
		instance string
		port     int
		target   string
		txt      []string
		srcIP    string
	}
	instByFull := make(map[string]*pendingInst)
	ipByHost := make(map[string]string)

	buf := make([]byte, 8192)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if n < 12 || src == nil || src.IP == nil {
			continue
		}
		srcIP := src.IP.String()
		recs := parseDNSPacket(buf[:n])
		for _, rr := range recs {
			switch rr.rrType {
			case 1: // A
				if rr.ipv4 != "" {
					ipByHost[strings.ToLower(rr.name)] = rr.ipv4
				}
			case 12: // PTR
				svcType := normalizeMDNSType(rr.name)
				if svcType == "" || strings.HasPrefix(svcType, "_services.") {
					continue
				}
				key := strings.ToLower(rr.target)
				inst := instByFull[key]
				if inst == nil {
					inst = &pendingInst{srcIP: srcIP}
					instByFull[key] = inst
				}
				inst.svcType = svcType
				inst.instance = extractMDNSInstance(rr.target, svcType)
			case 33: // SRV
				key := strings.ToLower(rr.name)
				inst := instByFull[key]
				if inst == nil {
					inst = &pendingInst{srcIP: srcIP}
					instByFull[key] = inst
				}
				if inst.svcType == "" {
					inst.svcType = extractMDNSTypeFromFull(rr.name)
				}
				if inst.instance == "" {
					inst.instance = extractMDNSInstance(rr.name, inst.svcType)
				}
				inst.port = rr.port
				inst.target = strings.ToLower(rr.target)
			case 16: // TXT
				key := strings.ToLower(rr.name)
				inst := instByFull[key]
				if inst == nil {
					inst = &pendingInst{srcIP: srcIP}
					instByFull[key] = inst
				}
				if inst.svcType == "" {
					inst.svcType = extractMDNSTypeFromFull(rr.name)
				}
				inst.txt = mergeSafeTXT(inst.txt, rr.txt)
			}
		}
	}

	out := make(map[string][]MDNSService)
	seen := make(map[string]struct{})
	for _, inst := range instByFull {
		if inst.svcType == "" {
			continue
		}
		ip := inst.srcIP
		if inst.target != "" {
			if resolved, ok := ipByHost[inst.target]; ok && resolved != "" {
				ip = resolved
			}
		}
		if ip == "" {
			continue
		}
		dedupKey := fmt.Sprintf("%s|%s|%d|%s", ip, inst.svcType, inst.port, inst.instance)
		if _, dup := seen[dedupKey]; dup {
			continue
		}
		seen[dedupKey] = struct{}{}
		out[ip] = append(out[ip], MDNSService{
			Type:     inst.svcType,
			Instance: inst.instance,
			Port:     inst.port,
			TXT:      inst.txt,
		})
	}
	for ip := range out {
		sort.Slice(out[ip], func(i, j int) bool {
			if out[ip][i].Type != out[ip][j].Type {
				return out[ip][i].Type < out[ip][j].Type
			}
			return out[ip][i].Port < out[ip][j].Port
		})
	}
	return out
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
	port   int
	target string
	ipv4   string
	txt    []string
}

// parseDNSPacket decodes Answer and Additional resource records from a raw
// DNS/mDNS UDP datagram with full RFC 1035 name pointer decompression.
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
				out = append(out, dnsRecord{name: name, rrType: 1, ipv4: ip})
			}
		case 12: // PTR
			if target, _, ok := readDNSName(pkt, rdataOff); ok {
				out = append(out, dnsRecord{name: name, rrType: 12, target: target})
			}
		case 33: // SRV
			if rdLen >= 7 {
				port := int(binary.BigEndian.Uint16(pkt[rdataOff+4 : rdataOff+6]))
				if target, _, ok := readDNSName(pkt, rdataOff+6); ok {
					out = append(out, dnsRecord{name: name, rrType: 33, port: port, target: target})
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
			out = append(out, dnsRecord{name: name, rrType: 16, txt: pairs})
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

func mergeSafeTXT(existing, incoming []string) []string {
	seen := make(map[string]struct{}, len(existing))
	out := append([]string(nil), existing...)
	for _, kv := range existing {
		seen[kv] = struct{}{}
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
		entry := kLower + "=" + v
		if _, dup := seen[entry]; !dup {
			seen[entry] = struct{}{}
			out = append(out, entry)
		}
	}
	sort.Strings(out)
	return out
}

// discoverSSDP issues a single bounded SSDP M-SEARCH (MX: 1, ST: ssdp:all) and
// fetches at most one same-host pinned UPnP XML description per unique location.
func discoverSSDP(ctx context.Context, httpClient *http.Client) map[string][]UPnPDevice {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil
	}
	defer conn.Close()

	dst, err := net.ResolveUDPAddr("udp4", ssdpMulticastAddr)
	if err != nil {
		return nil
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

	type ssdpHit struct {
		ip       string
		st       string
		server   string
		location string
	}
	hitsByLoc := make(map[string]*ssdpHit)
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
				hitsByLoc[key] = &ssdpHit{ip: ip, st: st, server: srv, location: loc}
			}
		} else if st != "" || srv != "" {
			noLocHits[ip] = append(noLocHits[ip], ssdpHit{ip: ip, st: st, server: srv})
		}
	}

	out := make(map[string][]UPnPDevice)
	for ip, list := range noLocHits {
		for _, h := range list {
			out[ip] = append(out[ip], UPnPDevice{ST: h.st, Server: h.server})
		}
	}

	// Fetch pinned same-host XML descriptions concurrently (bounded to 8 workers).
	var mu sync.Mutex
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, hit := range hitsByLoc {
		h := hit
		port, safeURL, ok := validateSameHostURL(h.location, h.ip)
		if !ok {
			// Retain passive SSDP headers without dialing cross-host/invalid URLs.
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
			if httpClient != nil {
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
