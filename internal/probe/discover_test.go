// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestMDNSPacketParseAndTXTAllowlist(t *testing.T) {
	// Build a minimal DNS response packet containing PTR, SRV, TXT, and A records
	// with RFC 1035 name compression and verify unsafe TXT keys are dropped.
	var pkt bytes.Buffer
	// Header: ID=0, Flags=0x8400 (response), QD=0, AN=4, NS=0, AR=0
	pkt.Write([]byte{0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00})

	writeName := func(buf *bytes.Buffer, name string) {
		for _, lbl := range bytes.Split([]byte(name), []byte(".")) {
			if len(lbl) == 0 {
				continue
			}
			buf.WriteByte(byte(len(lbl)))
			buf.Write(lbl)
		}
		buf.WriteByte(0)
	}

	// 1. PTR: _hap._tcp.local -> lock._hap._tcp.local
	writeName(&pkt, "_hap._tcp.local")
	var ptrTarget bytes.Buffer
	writeName(&ptrTarget, "lock._hap._tcp.local")
	_ = binary.Write(&pkt, binary.BigEndian, uint16(12)) // PTR
	_ = binary.Write(&pkt, binary.BigEndian, uint16(1))
	_ = binary.Write(&pkt, binary.BigEndian, uint32(120))
	_ = binary.Write(&pkt, binary.BigEndian, uint16(ptrTarget.Len()))
	pkt.Write(ptrTarget.Bytes())

	// 2. SRV: lock._hap._tcp.local -> port 51826, target lock.local
	writeName(&pkt, "lock._hap._tcp.local")
	var srvData bytes.Buffer
	_ = binary.Write(&srvData, binary.BigEndian, uint16(0))     // prio
	_ = binary.Write(&srvData, binary.BigEndian, uint16(0))     // weight
	_ = binary.Write(&srvData, binary.BigEndian, uint16(51826)) // port
	writeName(&srvData, "lock.local")
	_ = binary.Write(&pkt, binary.BigEndian, uint16(33)) // SRV
	_ = binary.Write(&pkt, binary.BigEndian, uint16(1))
	_ = binary.Write(&pkt, binary.BigEndian, uint32(120))
	_ = binary.Write(&pkt, binary.BigEndian, uint16(srvData.Len()))
	pkt.Write(srvData.Bytes())

	// 3. TXT: includes safe "sf=1" and "md=SmartLock" plus sensitive "room=Bedroom" & "token=secret".
	writeName(&pkt, "lock._hap._tcp.local")
	var txtData bytes.Buffer
	for _, s := range []string{"sf=1", "md=SmartLock", "room=Bedroom", "token=secret"} {
		txtData.WriteByte(byte(len(s)))
		txtData.WriteString(s)
	}
	_ = binary.Write(&pkt, binary.BigEndian, uint16(16)) // TXT
	_ = binary.Write(&pkt, binary.BigEndian, uint16(1))
	_ = binary.Write(&pkt, binary.BigEndian, uint32(120))
	_ = binary.Write(&pkt, binary.BigEndian, uint16(txtData.Len()))
	pkt.Write(txtData.Bytes())

	// 4. A: lock.local -> 192.0.2.44
	writeName(&pkt, "lock.local")
	_ = binary.Write(&pkt, binary.BigEndian, uint16(1)) // A
	_ = binary.Write(&pkt, binary.BigEndian, uint16(1))
	_ = binary.Write(&pkt, binary.BigEndian, uint32(120))
	_ = binary.Write(&pkt, binary.BigEndian, uint16(4))
	pkt.Write([]byte{192, 0, 2, 44})

	recs := parseDNSPacket(pkt.Bytes())
	if len(recs) != 4 {
		t.Fatalf("expected 4 DNS records, got %d", len(recs))
	}
	var gotTXT []string
	for _, r := range recs {
		if r.rrType == 16 {
			gotTXT = mergeSafeTXT(nil, r.txt)
		}
	}
	if len(gotTXT) != 2 || gotTXT[0] != "md=SmartLock" || gotTXT[1] != "sf=1" {
		t.Fatalf("unexpected filtered TXT keys: %v (sensitive keys must be stripped)", gotTXT)
	}
}

func TestValidateSameHostURLPinning(t *testing.T) {
	if port, u, ok := validateSameHostURL("http://192.0.2.10:49000/tr64desc.xml", "192.0.2.10"); !ok || port != 49000 || u == "" {
		t.Fatalf("expected same-host UPnP URL to pass, got ok=%v port=%d u=%q", ok, port, u)
	}
	// Cross-host SSRF URL must be rejected.
	if _, _, ok := validateSameHostURL("http://192.0.2.99:49000/tr64desc.xml", "192.0.2.10"); ok {
		t.Fatal("cross-host LOCATION URL must be rejected")
	}
	// Userinfo URL must be rejected.
	if _, _, ok := validateSameHostURL("http://admin:pass@192.0.2.10/desc.xml", "192.0.2.10"); ok {
		t.Fatal("URL with userinfo must be rejected")
	}
	// Non-HTTP scheme must be rejected.
	if _, _, ok := validateSameHostURL("file:///etc/passwd", "192.0.2.10"); ok {
		t.Fatal("non-http scheme must be rejected")
	}
}

func TestUPnPAndWSDParsers(t *testing.T) {
	upnpXML := `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <manufacturer>ExampleNet</manufacturer>
    <modelName>HomeRouter 3000</modelName>
    <serviceList>
      <service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType></service>
    </serviceList>
  </device>
</root>`
	var dev UPnPDevice
	parseUPnPDescriptionXML([]byte(upnpXML), &dev)
	if dev.Manufacturer != "ExampleNet" || dev.ModelName != "HomeRouter 3000" {
		t.Fatalf("unexpected UPnP device metadata: %+v", dev)
	}
	if len(dev.ServiceTypes) != 1 || dev.ServiceTypes[0] != "urn:schemas-upnp-org:service:WANIPConnection:1" {
		t.Fatalf("unexpected UPnP service types: %+v", dev.ServiceTypes)
	}

	wsdXML := `<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
  <e:Body><d:ProbeMatches><d:ProbeMatch>
    <d:Types>dn:NetworkVideoTransmitter tds:Device</d:Types>
    <d:Scopes>onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/name/FrontDoor</d:Scopes>
    <d:XAddrs>http://192.0.2.20:8000/onvif/device_service http://192.0.2.99:9999/evil</d:XAddrs>
  </d:ProbeMatch></d:ProbeMatches></e:Body></e:Envelope>`
	rec, ok := parseWSDProbeMatch([]byte(wsdXML), "192.0.2.20")
	if !ok {
		t.Fatal("expected WS-Discovery ProbeMatch to parse")
	}
	if len(rec.Types) != 2 || rec.Types[1] != "NetworkVideoTransmitter" {
		t.Fatalf("unexpected WSD types: %v", rec.Types)
	}
	if len(rec.Scopes) != 1 {
		t.Fatalf("expected only allowlisted ONVIF type scope (no room/name), got %v", rec.Scopes)
	}
	if len(rec.Ports) != 1 || rec.Ports[0] != 8000 {
		t.Fatalf("expected only same-host port [8000], got %v", rec.Ports)
	}
}

func TestRawPrintSinkGuard(t *testing.T) {
	disc := &LANDiscovery{
		RawPrintIPs: map[string]map[int]struct{}{
			"192.0.2.50": {9101: {}},
		},
	}
	if !isRawPrintSinkPort(9100, nil, "192.0.2.50") {
		t.Fatal("TCP 9100 must always be protected as a raw print sink")
	}
	if !isRawPrintSinkPort(515, nil, "192.0.2.50") {
		t.Fatal("TCP 515 (LPD) must always be protected as a raw print sink")
	}
	if !isRawPrintSinkPort(9101, disc, "192.0.2.50") {
		t.Fatal("mDNS _pdl-datastream advertised port must be protected as a raw print sink")
	}
	if isRawPrintSinkPort(631, disc, "192.0.2.50") {
		t.Fatal("IPP port 631 should not be blocked by raw print sink guard")
	}
}
