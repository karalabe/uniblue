// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package blast

import (
	"cmp"
	"encoding/json"
	"slices"
	"strings"

	"github.com/karalabe/uniblue/internal/classify"
	"github.com/karalabe/uniblue/internal/probe"
)

// TransportVerdict assesses one property of traffic on a single directed leg.
type TransportVerdict uint8

const (
	unverified TransportVerdict = iota
	exposed
	conditional
	resilient
)

// String returns the scope of the verdict in everyday language.
func (v TransportVerdict) String() string {
	switch v {
	case exposed:
		return "exposed"
	case conditional:
		return "conditional"
	case resilient:
		return "resilient (observed inbound surfaces)"
	default:
		return "unknown"
	}
}

// BlindSpots returns a fresh disclosure for every resilience assessment.
func (v TransportVerdict) BlindSpots() []string {
	if v != resilient {
		return nil
	}
	return []string{
		"Outbound traffic and unsigned firmware or software updates were outside this assessment.",
		"The scan cannot tell whether clients actually check TLS certificates.",
		"The first SSH connection depends on someone verifying the server's host key (trust on first use).",
		"False DHCP, DNS, or NTP replies can redirect clients. DHCP option 121 can change VPN routes (TunnelVision).",
		"Unscanned ports, UDP services, and IPv6 endpoints may behave differently.",
		"Someone with a shared WPA2-PSK passphrase can capture peer traffic and decrypt it with the handshake. WPA3-SAE protects against this.",
	}
}

// MarshalJSON keeps the scope and its mandatory disclosure together in every serialized report.
func (v TransportVerdict) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Verdict    string   `json:"verdict"`
		BlindSpots []string `json:"blind_spots,omitempty"`
	}{v.String(), v.BlindSpots()})
}

// TransportSurvival describes what happens to one listener's traffic when it crosses the selected device.
type TransportSurvival struct {
	// From names the sending side of the assessed leg.
	From string `json:"from"`
	// To names the receiving device.
	To string `json:"to"`
	// Path describes how traffic encounters the compromised equipment.
	Path string `json:"path"`
	// Address identifies the observed listener.
	Address string `json:"address"`
	// Port is the listener's port number.
	Port int `json:"port"`
	// Transport is the listener's network transport, such as TCP or UDP.
	Transport string `json:"transport"`
	// Protocol is the application protocol identified at this endpoint.
	Protocol string `json:"protocol"`
	// Class describes the protection seen on this leg.
	Class string `json:"class"`
	// Reachability reports whether the modeled source can initiate a connection.
	Reachability string `json:"reachability"`
	// Confidentiality assesses whether the device can read the payload.
	Confidentiality TransportVerdict `json:"confidentiality"`
	// Integrity assesses whether the device can alter the payload undetected.
	Integrity TransportVerdict `json:"integrity"`
	// Availability assesses whether the device can interrupt delivery.
	Availability TransportVerdict `json:"availability"`
	// Wireless describes peer capture separately from application protection.
	Wireless string `json:"wireless,omitempty"`
	// Note explains evidence and conditions specific to this leg.
	Note string `json:"note"`
}

// inboundSurfaces combines observations only when they identify the same address, port and transport.
func inboundSurfaces(hp probe.HostProfile) []TransportSurvival {
	type endpoint struct {
		ip, transport string
		port          int
	}
	services := make(map[endpoint]probe.Service)
	ip := hp.EffectiveProbeIP()
	for _, port := range hp.OpenPorts {
		services[endpoint{ip, "tcp", port}] = probe.Service{}
	}
	for _, svc := range hp.Services {
		addr := hp.ServiceIP(svc)
		if addr == "" {
			continue
		}
		k := endpoint{addr, cmp.Or(svc.Transport, "tcp"), svc.Port}
		// A candidate port alone cannot establish encryption or authentication.
		if svc.State != "" && svc.State != probe.ServiceStateObservedProtocol && svc.State != probe.ServiceStateTLSUnknownApp && svc.State != probe.ServiceStateOwnerDeclared && svc.State != probe.ServiceStateAdvertisedService {
			if _, ok := services[k]; !ok {
				services[k] = probe.Service{}
			}
			continue
		}
		services[k] = svc
	}
	for port, banner := range hp.HTTP {
		if banner.Scheme == "http" || banner.Scheme == "https" {
			k := endpoint{ip, "tcp", port}
			s := services[k]
			s.Protocol, s.TLS = banner.Scheme, banner.Scheme == "https"
			services[k] = s
		}
	}
	if hp.SSH != nil {
		services[endpoint{ip, "tcp", hp.SSH.Port}] = probe.Service{Protocol: "ssh"}
	}
	if hp.SMB != nil {
		services[endpoint{ip, "tcp", 445}] = probe.Service{Protocol: "smb"}
	}
	// A service advertisement describes an expected protocol. It does not verify
	// a pairing or handshake, even when the advertised TCP port is also open.
	for _, md := range hp.MDNSServices {
		if md.Reflected && !md.TrustedReflector {
			continue
		}
		proto, transport := "", cmp.Or(md.Transport, "tcp")
		switch md.Type {
		case "_hap._tcp":
			proto = "hap"
		case "_matter._tcp":
			proto, transport = "matter", "udp"
		case "_esphomelib._tcp":
			for _, txt := range md.TXT {
				if strings.HasPrefix(strings.ToLower(txt), "api_encryption=noise_") {
					proto = "esphome-noise"
				}
			}
		}
		if proto == "" {
			continue
		}
		for _, addr := range md.TargetIPs {
			k := endpoint{addr, transport, md.Port}
			if !slices.Contains(hp.Client.AllIPs(), addr) {
				continue
			}
			previous := services[k].Protocol
			if previous == "" || previous == "unknown" || proto == "esphome-noise" && previous == "esphome" {
				services[k] = probe.Service{Protocol: proto, State: probe.ServiceStateAdvertisedService}
			}
		}
	}
	var out []TransportSurvival
	for k, svc := range services {
		if k.ip == "" || k.port <= 0 {
			continue
		}
		var banner probe.HTTPBanner
		if k.ip == ip && k.transport == "tcp" {
			banner = hp.HTTP[k.port]
		}
		leg := assessTransport(svc, banner)
		leg.Address, leg.Transport, leg.Port = k.ip, k.transport, k.port
		if svc.Protocol == "smb" && hp.SMB != nil && k.ip == ip && k.port == 445 && k.transport == "tcp" {
			leg.Note = "SMB negotiation shows server capabilities. Encryption on this share is unknown."
			if hp.SMB.SigningRequired {
				leg.Integrity = conditional
				leg.Note += " The server requires signing for signed-in sessions."
			}
		}
		out = append(out, leg)
	}
	return out
}

// assessTransport evaluates confidentiality and integrity independently of an on-path device's ability to drop traffic.
func assessTransport(svc probe.Service, b probe.HTTPBanner) TransportSurvival {
	proto := strings.ToLower(svc.Protocol)
	trait, _ := classify.LookupProtocol(proto)
	class := string(trait.TransportClass)
	if proto == "esphome-noise" {
		class = "e2e"
	}
	if svc.TLS || class == "tls" || proto == "tls" || proto == "dtls" || proto == "quic" {
		class = "tls-unverifiable"
		if b.TLSVerified && !b.TLSExpired && !b.TLSSelfSigned {
			class = "tls-ca"
		}
	}
	if class == "cleartext-auth" && svc.AnonymousAccess {
		class = "cleartext-noauth"
	}
	leg := TransportSurvival{Protocol: cmp.Or(proto, "unknown"), Class: cmp.Or(class, "unknown"), Availability: exposed}
	var protection TransportVerdict
	switch leg.Class {
	case "e2e":
		protection = resilient
		leg.Note = "Paired or authenticated endpoints protect the application data as it crosses this device."
		if svc.State == probe.ServiceStateAdvertisedService || svc.State == probe.ServiceStateOwnerDeclared {
			protection = conditional
			leg.Note = "The service is listed as encrypted. The scan did not verify its pairing or session settings."
		} else if proto == "ssh" {
			protection = conditional
			leg.Note = "SSH protects data when the client checks the server key. First-time trust or an ignored key change can expose this connection."
		}
	case "tls-ca":
		protection = resilient
		leg.Note = "The scanner verified the certificate for this endpoint. Protection depends on the client checking it too."
	case "tls-unverifiable":
		protection = conditional
		leg.Note = "The scan could not verify this certificate for the endpoint. A client with a trusted pin or its own certificate authority may still identify the server."
	case "cleartext-auth", "cleartext-noauth":
		protection = exposed
		leg.Note = "A device carrying this traffic can read or change the unencrypted messages."
	default:
		leg.Note = "The available evidence does not establish how this connection protects its data."
	}
	leg.Confidentiality, leg.Integrity = protection, protection
	return leg
}
