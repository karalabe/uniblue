// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package server

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	builtinchecks "github.com/karalabe/uniblue/checks"
	classifydata "github.com/karalabe/uniblue/classify"
	"github.com/karalabe/uniblue/internal/blast"
	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/classify"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/cve"
	"github.com/karalabe/uniblue/internal/oui"
	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/risk"
	"github.com/karalabe/uniblue/internal/topology"
	"github.com/karalabe/uniblue/internal/unifi"
)

// NewDemoEngine builds an offline, zero-network Engine seeded with a realistic
// synthetic home and homelab UniFi network. Every view, badge, port cutaway,
// isolation boundary, CVE rollup, and drawer is generated through UniBlue's
// real classification, risk, topology, and presentation pipeline.
func NewDemoEngine(opts Options) (*Engine, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	now := time.Now().UTC().Truncate(time.Minute)

	ouiDB := oui.New("")
	classifier, err := classify.Load(classifydata.BuiltinFS, ouiDB)
	if err != nil {
		return nil, fmt.Errorf("load demo classifier: %w", err)
	}

	snap, netCfg, profiles, rawFindings, demoCVEMatches, events := buildDemoDataset(now)
	var exactCVEs, potentialCVEs []cve.ProductSummary
	for _, s := range cve.RollupMatches(demoCVEMatches) {
		if s.Confidence == cve.ConfidenceExact {
			exactCVEs = append(exactCVEs, s)
		} else {
			potentialCVEs = append(potentialCVEs, s)
		}
	}

	// Merge synthetic Nerva protocol findings using the real deduplication path.
	nervaFindings := checks.FindingsFromProfiles(profiles, rawFindings)
	allRaw := append(rawFindings, nervaFindings...)

	report := risk.Evaluate(snap, allRaw, netCfg, profiles...)
	classes := classifier.ClassifyAll(snap, profiles)
	topo := topology.Build(snap, classes, netCfg)

	// Build ClientView rows matching Engine.recomputeAndPublish.
	findingsByIP := make(map[string][]checks.Finding)
	for _, f := range report.Findings {
		if f.Client.IP != "" {
			findingsByIP[f.Client.IP] = append(findingsByIP[f.Client.IP], f)
		}
	}
	profByIP := make(map[string]probe.HostProfile, len(profiles))
	for _, p := range profiles {
		profByIP[p.Client.IP] = p
	}
	clientViews := make([]ClientView, 0, len(snap.Clients))
	for _, cl := range snap.Clients {
		var openPorts []int
		var lastScanned *time.Time
		if p, ok := profByIP[cl.IP]; ok {
			openPorts = append([]int(nil), p.OpenPorts...)
			t := p.ScannedAt
			lastScanned = &t
		}
		fs := findingsByIP[cl.IP]
		maxSev := "clean"
		var best checks.Severity
		activeCount := 0
		for _, f := range fs {
			if f.IsInventoryOnly() {
				continue
			}
			activeCount++
			if activeCount == 1 || f.EffectiveSeverity > best {
				best = f.EffectiveSeverity
				maxSev = best.String()
			}
		}
		cls := classes[cl.IP]
		if cls.Category == "" {
			cls = classes[cl.MAC]
		}
		clientViews = append(clientViews, ClientView{
			Client:        cl,
			Class:         cls,
			OpenPorts:     openPorts,
			FindingCount:  activeCount,
			MaxSeverity:   maxSev,
			LastScannedAt: lastScanned,
		})
	}
	sort.Slice(clientViews, func(i, j int) bool {
		if clientViews[i].FindingCount != clientViews[j].FindingCount {
			return clientViews[i].FindingCount > clientViews[j].FindingCount
		}
		return strings.ToLower(clientViews[i].Client.DisplayName()) < strings.ToLower(clientViews[j].Client.DisplayName())
	})

	view := BuildPresentationModel(snap, report, topo, clientViews, exactCVEs, potentialCVEs, profiles)
	demoChecks, _ := checks.LoadFromFS(builtinchecks.BuiltinFS)
	var demoSignals []blast.TargetSignal
	for _, cl := range snap.Clients {
		low := strings.ToLower(cl.Name + " " + cl.Hostname)
		switch {
		case strings.Contains(low, "caddy") || strings.Contains(low, "nginx"):
			demoSignals = append(demoSignals, blast.TargetSignal{
				Asset:    config.CanonicalMAC(cl.MAC),
				Proto:    "tcp",
				Port:     443,
				Product:  cl.DisplayName(),
				Velocity: cve.TargetVelocity{Class: cve.VelocityHighProfile, KEVCount: 2, LatestKEV: "2025-11-10"},
			})
		case strings.Contains(low, "homeassistant") || strings.Contains(low, "home assistant") || strings.Contains(low, "plex"):
			demoSignals = append(demoSignals, blast.TargetSignal{
				Asset:    config.CanonicalMAC(cl.MAC),
				Product:  cl.DisplayName(),
				Velocity: cve.TargetVelocity{Class: cve.VelocityHighProfile, KEVCount: 2, LatestKEV: "2025-11-10"},
			})
		}
	}
	blastRep, infraReps := EvaluateSiteBlast(snap, profiles, allRaw, report, netCfg, demoChecks, demoCVEMatches, demoSignals, "192.168.1.1")
	AttachBlast(view, blastRep, infraReps)

	eng := &Engine{
		cfg:           &config.Config{Network: netCfg},
		opts:          opts,
		demoMode:      true,
		classifier:    classifier,
		logger:        opts.Logger,
		startedAt:     now.Add(-4 * time.Minute),
		eventMode:     "demo",
		snap:          snap,
		profilesByMAC: make(map[string]probe.HostProfile, len(profiles)),
		findingsByMAC: make(map[string][]checks.Finding),
		events:        events,
		fullRescanCh:  make(chan string, 1),
		hostScanCh:    make(chan hostScanTask, 8),
		subscribers:   make(map[chan LiveEvent]struct{}),
		current: StateSnapshot{
			StartedAt:      now.Add(-4 * time.Minute),
			UpdatedAt:      now,
			LastFullScanAt: now.Add(-12 * time.Second),
			EventMode:      "demo",
			Scanning:       false,
			Site:           snap.Site,
			ControllerType: snap.ControllerType,
			CVELoaded:      true,
			Report:         report,
			ExactCVEs:      exactCVEs,
			PotentialCVEs:  potentialCVEs,
			Topology:       topo,
			Clients:        clientViews,
			Events:         events,
			View:           view,
		},
	}
	eng.eventSeq.Store(int64(len(events)))
	for _, p := range profiles {
		eng.profilesByMAC[p.Client.MAC] = p
	}
	return eng, nil
}

// buildDemoDataset assembles a cohesive, anonymized home and homelab topology
// using RFC 1918 and RFC 5737 documentation addresses so every UI tab and
// slide-out drawer displays clean, realistic, balanced security insights.
func buildDemoDataset(now time.Time) (
	*unifi.Snapshot,
	config.NetworkConfig,
	[]probe.HostProfile,
	[]checks.Finding,
	[]cve.Match,
	[]LiveEvent,
) {
	const (
		macUDM    = "02:aa:bb:00:00:01"
		macCoreSW = "02:aa:bb:00:00:02"
		macWallAP = "02:aa:bb:00:00:03"
		macShedSW = "02:aa:bb:00:00:04"
	)

	netCfg := config.NetworkConfig{
		ExternalDevices: []string{"Detached Shed Switch"},
		IsolationPolicy: config.IsolationIntent{
			GuestVLANs: []string{"Guest Wi-Fi"},
			ApprovedPaths: []config.ApprovedPath{
				{
					Name:       "Guest IPPS Printing",
					SourceZone: "Hotspot",
					DestIP:     "192.168.1.40",
					Function:   "printing",
					Transport:  "tcp",
					Port:       631,
					IPVersion:  "ipv4",
				},
			},
		},
	}

	// Build switch port tables for all four UniFi devices.
	udmPorts := make([]unifi.SwitchPort, 0, 11)
	for i := 1; i <= 11; i++ {
		p := unifi.SwitchPort{
			PortIdx:           i,
			Name:              fmt.Sprintf("Port %d", i),
			Enabled:           true,
			Media:             "GE",
			OpMode:            "switch",
			Forward:           "native",
			TaggedVLANMgmt:    "block_all",
			NativeNetworkID:   "net-home",
			NativeNetworkName: "Home LAN",
		}
		if i == 9 {
			p.Name = "WAN 1"
			p.IsWAN = true
			p.Up = true
			p.Speed = 1000
		}
		if i == 10 || i == 11 {
			p.Media = "SFP+"
		}
		if i == 11 {
			p.Name = "Office Switch Uplink"
			p.Up = true
			p.Speed = 10000
			p.Forward = "all"
			p.TaggedVLANMgmt = "auto"
		}
		udmPorts = append(udmPorts, p)
	}

	corePorts := make([]unifi.SwitchPort, 0, 26)
	for i := 1; i <= 26; i++ {
		p := unifi.SwitchPort{
			PortIdx:           i,
			Name:              fmt.Sprintf("Port %d", i),
			Enabled:           true,
			Media:             "GE",
			OpMode:            "switch",
			Forward:           "native",
			TaggedVLANMgmt:    "block_all",
			NativeNetworkID:   "net-home",
			NativeNetworkName: "Home LAN",
		}
		if i >= 25 {
			p.Media = "SFP+"
		}
		switch i {
		case 1:
			p.Name = "Front Gate Camera"
			p.Up = true
			p.Speed = 100
			p.PoEEnabled = true
			p.PoEPower = "7.40"
			p.PoEPowerWatts = 7.40
			p.Forward = "all"
			p.TaggedVLANMgmt = "auto"
			p.MACTableCount = 1
		case 2:
			p.Name = "Patio Camera"
			p.Up = true
			p.Speed = 100
			p.PoEEnabled = true
			p.PoEPower = "6.85"
			p.PoEPowerWatts = 6.85
			p.NativeNetworkID = "net-iot"
			p.NativeNetworkName = "Smart Home"
			p.TaggedVLANMgmt = "block_all"
			p.PortSecurityEnabled = true
			p.PortSecurityMACs = []string{"02:11:22:00:02:02"}
			p.MACTableCount = 1
		case 6:
			p.Name = "Shed Switch Feeder"
			p.Up = true
			p.Speed = 1000
			p.PoEEnabled = true
			p.PoEPower = "3.20"
			p.PoEPowerWatts = 3.20
			p.Forward = "all"
			p.TaggedVLANMgmt = "auto"
			p.MACTableCount = 2
		case 9:
			p.Name = "Hallway AP"
			p.Up = true
			p.Speed = 1000
			p.PoEEnabled = true
			p.PoEPower = "5.40"
			p.PoEPowerWatts = 5.40
			p.Forward = "all"
			p.TaggedVLANMgmt = "auto"
		case 12, 14, 22, 24:
			p.Up = true
			p.Speed = 1000
			p.MACTableCount = 1
		case 16, 17, 18, 19, 20, 21:
			p.Up = true
			p.Speed = 1000
			p.NativeNetworkID = "net-srv"
			p.NativeNetworkName = "Lab & Storage"
			p.MACTableCount = 1
		case 26:
			p.Name = "Gateway Uplink"
			p.IsUplink = true
			p.Up = true
			p.Speed = 10000
			p.Forward = "all"
			p.TaggedVLANMgmt = "auto"
		}
		corePorts = append(corePorts, p)
	}

	wallPorts := make([]unifi.SwitchPort, 0, 5)
	for i := 1; i <= 5; i++ {
		p := unifi.SwitchPort{
			PortIdx:           i,
			Name:              fmt.Sprintf("Port %d", i),
			Enabled:           true,
			Media:             "GE",
			OpMode:            "switch",
			Forward:           "native",
			TaggedVLANMgmt:    "block_all",
			NativeNetworkID:   "net-home",
			NativeNetworkName: "Home LAN",
		}
		if i == 5 {
			p.IsUplink = true
			p.Up = true
			p.Speed = 1000
			p.Forward = "all"
			p.TaggedVLANMgmt = "auto"
		}
		wallPorts = append(wallPorts, p)
	}

	shedPorts := []unifi.SwitchPort{
		{
			PortIdx:           1,
			Name:              "House Uplink",
			Enabled:           true,
			Up:                true,
			Speed:             1000,
			Media:             "GE",
			IsUplink:          true,
			OpMode:            "switch",
			Forward:           "all",
			TaggedVLANMgmt:    "auto",
			NativeNetworkID:   "net-home",
			NativeNetworkName: "Home LAN",
		},
		{
			PortIdx:             2,
			Name:                "Garden Irrigation Hub",
			Enabled:             true,
			Up:                  true,
			Speed:               100,
			Media:               "GE",
			OpMode:              "switch",
			Forward:             "native",
			TaggedVLANMgmt:      "block_all",
			NativeNetworkID:     "net-iot",
			NativeNetworkName:   "Smart Home",
			PortSecurityEnabled: true,
			PortSecurityMACs:    []string{"02:11:22:00:20:40"},
			MACTableCount:       1,
		},
		{
			PortIdx:           3,
			Name:              "Port 3",
			Enabled:           false,
			Media:             "GE",
			OpMode:            "off",
			Forward:           "disabled",
			TaggedVLANMgmt:    "block_all",
			NativeNetworkID:   "net-iot",
			NativeNetworkName: "Smart Home",
		},
		{
			PortIdx:           4,
			Name:              "Port 4",
			Enabled:           true,
			Up:                false,
			Media:             "GE",
			OpMode:            "switch",
			Forward:           "native",
			TaggedVLANMgmt:    "block_all",
			NativeNetworkID:   "net-iot",
			NativeNetworkName: "Smart Home",
		},
		{
			PortIdx:           5,
			Name:              "Port 5",
			Enabled:           false,
			Media:             "GE",
			OpMode:            "off",
			Forward:           "disabled",
			TaggedVLANMgmt:    "block_all",
			NativeNetworkID:   "net-iot",
			NativeNetworkName: "Smart Home",
		},
	}

	clBMC := unifi.Client{
		MAC: "02:11:22:00:10:05", IP: "192.168.10.5", IPv6: []string{"fd00:10::5"},
		Hostname: "rack-idrac", Name: "Rack Server iDRAC", OUI: "Dell Inc.",
		NetworkID: "net-srv", NetworkName: "Lab & Storage", VLAN: "10",
		IsWired: true, SwitchMAC: macCoreSW, SwitchPort: 17,
	}
	clRack := unifi.Client{
		MAC: "02:11:22:00:10:06", IP: "192.168.10.6",
		Hostname: "pve-rack", Name: "Rack Virtualization Server", OUI: "Dell Inc.",
		NetworkID: "net-srv", NetworkName: "Lab & Storage", VLAN: "10",
		IsWired: true, SwitchMAC: macCoreSW, SwitchPort: 21,
	}
	// The management card controls the physical host even when its hypervisor
	// requires an authenticated login on the network.
	netCfg.Assets = []config.AssetOverride{
		{MAC: clBMC.MAC, Manages: []string{clRack.MAC}},
		{MAC: clRack.MAC, Tier: "high", Label: clRack.Name},
	}
	clLab := unifi.Client{
		MAC: "02:11:22:00:10:10", IP: "192.168.10.10", IPv6: []string{"fd00:10::10"},
		Hostname: "homelab-01", Name: "Ubuntu Lab & AI Host", OUI: "Lenovo",
		NetworkID: "net-srv", NetworkName: "Lab & Storage", VLAN: "10",
		IsWired: true, SwitchMAC: macCoreSW, SwitchPort: 16,
	}
	clNAS := unifi.Client{
		MAC: "02:11:22:00:10:12", IP: "192.168.10.12",
		Hostname: "backup-nas", Name: "TrueNAS Backup Box", OUI: "iXsystems, Inc.",
		NetworkID: "net-srv", NetworkName: "Lab & Storage", VLAN: "10",
		IsWired: true, SwitchMAC: macCoreSW, SwitchPort: 18,
	}
	clProxy := unifi.Client{
		MAC: "02:11:22:00:10:20", IP: "192.168.10.20",
		Hostname: "caddy-edge", Name: "Caddy Reverse Proxy", OUI: "QEMU/KVM",
		NetworkID: "net-srv", NetworkName: "Lab & Storage", VLAN: "10",
		IsWired: true, SwitchMAC: macCoreSW, SwitchPort: 19,
	}
	clNVR := unifi.Client{
		MAC: "02:11:22:00:10:30", IP: "192.168.10.30",
		Hostname: "security-nvr", Name: "Reolink Security NVR", OUI: "Reolink Innovation",
		NetworkID: "net-srv", NetworkName: "Lab & Storage", VLAN: "10",
		IsWired: true, SwitchMAC: macCoreSW, SwitchPort: 20,
	}
	clCamFront := unifi.Client{
		MAC: "02:11:22:00:02:01", IP: "192.168.1.18",
		Hostname: "cam-gate", Name: "Front Gate Camera", OUI: "Ubiquiti Inc.",
		NetworkID: "net-home", NetworkName: "Home LAN", VLAN: "1",
		IsWired: true, SwitchMAC: macCoreSW, SwitchPort: 1,
	}
	clCamPatio := unifi.Client{
		MAC: "02:11:22:00:02:02", IP: "192.168.20.18",
		Hostname: "cam-patio", Name: "Patio Camera", OUI: "Ubiquiti Inc.",
		NetworkID: "net-iot", NetworkName: "Smart Home", VLAN: "20",
		IsWired: true, SwitchMAC: macCoreSW, SwitchPort: 2,
	}
	clHA := unifi.Client{
		MAC: "02:11:22:00:01:25", IP: "192.168.1.25",
		Hostname: "ha-green", Name: "Home Assistant Green", OUI: "Nabu Casa, Inc.",
		NetworkID: "net-home", NetworkName: "Home LAN", VLAN: "1",
		IsWired: true, SwitchMAC: macCoreSW, SwitchPort: 12,
	}
	clOcto := unifi.Client{
		MAC: "02:11:22:00:01:32", IP: "192.168.1.32",
		Hostname: "octopi", Name: "Workshop 3D Printer (OctoPrint)", OUI: "Raspberry Pi Trading Ltd",
		NetworkID: "net-home", NetworkName: "Home LAN", VLAN: "1",
		IsWired: true, SwitchMAC: macCoreSW, SwitchPort: 14,
	}
	clPrinter := unifi.Client{
		MAC: "02:11:22:00:01:40", IP: "192.168.1.40",
		Hostname: "brother-mfc", Name: "Brother Office Printer", OUI: "Brother Industries, LTD.",
		NetworkID: "net-home", NetworkName: "Home LAN", VLAN: "1",
		IsWired: true, SwitchMAC: macCoreSW, SwitchPort: 22,
	}
	clRoku := unifi.Client{
		MAC: "02:11:22:00:01:45", IP: "192.168.1.45",
		Hostname: "roku-living", Name: "Living Room Roku Ultra", OUI: "Roku, Inc.",
		NetworkID: "net-home", NetworkName: "Home LAN", VLAN: "1",
		IsWired: true, SwitchMAC: macCoreSW, SwitchPort: 24,
	}
	clLaptop := unifi.Client{
		MAC: "02:11:22:00:01:50", IP: "192.168.1.50",
		Hostname: "studio-laptop", Name: "Studio MacBook Pro", OUI: "Apple, Inc.",
		NetworkID: "net-home", NetworkName: "Home LAN", VLAN: "1",
		IsWired: false, ESSID: "CedarHome", APMAC: macWallAP,
	}
	clPhone := unifi.Client{
		MAC: "02:11:22:00:01:51", IP: "192.168.1.51",
		Hostname: "pixel-9", Name: "Family Pixel Phone", OUI: "Google, Inc.",
		NetworkID: "net-home", NetworkName: "Home LAN", VLAN: "1",
		IsWired: false, ESSID: "CedarHome", APMAC: macWallAP,
	}
	clIrrigation := unifi.Client{
		MAC: "02:11:22:00:20:40", IP: "192.168.20.40",
		Hostname: "garden-hub", Name: "Garden Irrigation Hub", OUI: "Rachio Inc.",
		NetworkID: "net-iot", NetworkName: "Smart Home", VLAN: "20",
		IsWired: true, SwitchMAC: macShedSW, SwitchPort: 2,
	}
	clThermostat := unifi.Client{
		MAC: "02:11:22:00:20:41", IP: "192.168.20.41",
		Hostname: "ecobee-hall", Name: "Hallway Smart Thermostat", OUI: "ecobee inc",
		NetworkID: "net-iot", NetworkName: "Smart Home", VLAN: "20",
		IsWired: false, ESSID: "CedarIoT", APMAC: macWallAP,
	}
	clShelly := unifi.Client{
		MAC: "02:11:22:00:20:42", IP: "192.168.20.42",
		Hostname: "shelly-patio", Name: "Patio Lighting Relay", OUI: "Shelly Europe Ltd.",
		NetworkID: "net-iot", NetworkName: "Smart Home", VLAN: "20",
		IsWired: false, ESSID: "CedarIoT", APMAC: macWallAP,
	}
	clGuestPhone := unifi.Client{
		MAC: "02:11:22:00:50:10", IP: "192.168.50.10",
		Hostname: "guest-phone", Name: "Visitor Phone", OUI: "Samsung Electronics",
		NetworkID: "net-guest", NetworkName: "Guest Wi-Fi", VLAN: "50",
		IsWired: false, ESSID: "CedarGuest", APMAC: macWallAP,
	}
	clGuestLaptop := unifi.Client{
		MAC: "02:11:22:00:50:11", IP: "192.168.50.11",
		Hostname: "guest-laptop", Name: "Visitor Laptop", OUI: "Intel Corporate",
		NetworkID: "net-guest", NetworkName: "Guest Wi-Fi", VLAN: "50",
		IsWired: false, ESSID: "CedarGuest", APMAC: macWallAP,
	}

	snap := &unifi.Snapshot{
		CollectedAt:    now,
		Site:           "cedar-home",
		ControllerType: "integration-v1",
		Visibility: &unifi.SiteVisibility{
			ControllerVersion:        "9.1.120",
			APIMode:                  "integration-v1",
			GatewayPoliciesAvailable: true,
			PortForwardsAvailable:    true,
			SwitchACLsAvailable:      true,
			WLANsAvailable:           true,
			SettingsAvailable:        true,
			DHCPAvailable:            true,
			MDNSReflectorKnown:       true,
		},
		SwitchACLCoverage: &unifi.SwitchACLCoverage{
			Status: "complete",
		},
		Devices: []unifi.Device{
			{
				Name: "Dream Machine SE", Model: "UDM SE", Type: "udm",
				MAC: macUDM, IP: "192.168.1.1", Version: "4.1.13",
				Ports: udmPorts,
			},
			{
				Name: "Office 24 PoE Switch", Model: "USW 24 PoE", Type: "usw",
				MAC: macCoreSW, IP: "192.168.1.2", Version: "7.1.26",
				UplinkMAC: macUDM, UplinkName: "Dream Machine SE", UplinkPort: 11,
				Ports: corePorts,
			},
			{
				Name: "Hallway In-Wall AP", Model: "U6-IW", Type: "uap",
				MAC: macWallAP, IP: "192.168.1.3", Version: "6.6.77",
				UplinkMAC: macCoreSW, UplinkName: "Office 24 PoE Switch", UplinkPort: 9,
				Ports: wallPorts,
			},
			{
				Name: "Detached Shed Switch", Model: "USW Flex Mini", Type: "usw",
				MAC: macShedSW, IP: "192.168.1.4", Version: "2.0.9",
				UplinkMAC: macCoreSW, UplinkName: "Office 24 PoE Switch", UplinkPort: 6,
				Ports: shedPorts,
			},
		},
		Networks: []unifi.Network{
			{ID: "net-home", Name: "Home LAN", VLAN: "1", Subnet: "192.168.1.1/24", Purpose: "corporate", ZoneID: "z-int", ZoneName: "Internal", DHCPStart: "192.168.1.50", DHCPEnd: "192.168.1.220", ActiveLeases: 12},
			{ID: "net-srv", Name: "Lab & Storage", VLAN: "10", Subnet: "192.168.10.1/24", IPv6Subnet: "fd00:10::/64", Purpose: "corporate", ZoneID: "z-int", ZoneName: "Internal", DHCPStart: "192.168.10.50", DHCPEnd: "192.168.10.200", ActiveLeases: 5},
			{ID: "net-iot", Name: "Smart Home", VLAN: "20", Subnet: "192.168.20.1/24", IPv6Subnet: "fd00:20::/64", Purpose: "corporate", ZoneID: "z-iot", ZoneName: "IoT", IsolationEnabled: true, DHCPStart: "192.168.20.20", DHCPEnd: "192.168.20.200", ActiveLeases: 4},
			{ID: "net-guest", Name: "Guest Wi-Fi", VLAN: "50", Subnet: "192.168.50.1/24", IPv6Subnet: "fd00:50::/64", Purpose: "guest", ZoneID: "z-guest", ZoneName: "Hotspot", IsolationEnabled: true, DHCPStart: "192.168.50.10", DHCPEnd: "192.168.50.200", ActiveLeases: 2},
		},
		Zones: []unifi.FirewallZone{
			{ID: "z-int", Name: "Internal", Origin: "SYSTEM_DEFINED", NetworkIDs: []string{"net-home", "net-srv"}},
			{ID: "z-iot", Name: "IoT", Origin: "USER_DEFINED", NetworkIDs: []string{"net-iot"}},
			{ID: "z-guest", Name: "Hotspot", Origin: "SYSTEM_DEFINED", NetworkIDs: []string{"net-guest"}},
			{ID: "z-gw", Name: "Gateway", Origin: "SYSTEM_DEFINED"},
			{ID: "z-ext", Name: "External", Origin: "SYSTEM_DEFINED"},
		},
		FirewallPolicies: []unifi.FirewallPolicy{
			{
				ID: "fp-guest-print", Name: "Allow Guest IPPS Printing", Enabled: true, Action: "ALLOW", Origin: "USER_DEFINED", Index: 1,
				IPVersion: "ipv4", Protocol: "tcp", MatchReturnTraffic: true,
				Source:      unifi.PolicyEndpoint{ZoneID: "z-guest", ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneID: "z-int", ZoneName: "Internal", IPs: []string{"192.168.1.40"}, Ports: []int{631}},
			},
			{
				ID: "fp-ipv6-leak", Name: "Legacy IPv6 Admin Rule", Enabled: true, Action: "ALLOW", Origin: "USER_DEFINED", Index: 2,
				IPVersion: "ipv6", Protocol: "udp", MatchReturnTraffic: true,
				Source:      unifi.PolicyEndpoint{ZoneID: "z-guest", ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneID: "z-int", ZoneName: "Internal", IPs: []string{"fd00:10::5"}, Ports: []int{623}},
			},
			{
				ID: "fp-block-guest-int", Name: "Block Guest to Internal", Enabled: true, Action: "BLOCK", Origin: "SYSTEM_DEFINED", Index: 10,
				IPVersion: "both", Protocol: "all",
				Source:      unifi.PolicyEndpoint{ZoneID: "z-guest", ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneID: "z-int", ZoneName: "Internal", AnyTarget: true, AnyPort: true},
			},
			{
				ID: "fp-block-iot-int", Name: "Block Smart Home to Internal", Enabled: true, Action: "BLOCK", Origin: "USER_DEFINED", Index: 11,
				IPVersion: "both", Protocol: "all",
				Source:      unifi.PolicyEndpoint{ZoneID: "z-iot", ZoneName: "IoT", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneID: "z-int", ZoneName: "Internal", AnyTarget: true, AnyPort: true},
			},
			{
				ID: "fp-gw-dns-guest", Name: "Allow Gateway DNS (Guest)", Enabled: true, Action: "ALLOW", Origin: "SYSTEM_DEFINED", Index: 20,
				IPVersion: "ipv4", Protocol: "udp",
				Source:      unifi.PolicyEndpoint{ZoneID: "z-guest", ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneID: "z-gw", ZoneName: "Gateway", AnyTarget: true, Ports: []int{53}},
			},
			{
				ID: "fp-gw-dhcp-guest", Name: "Allow Gateway DHCP (Guest)", Enabled: true, Action: "ALLOW", Origin: "SYSTEM_DEFINED", Index: 21,
				IPVersion: "ipv4", Protocol: "udp",
				Source:      unifi.PolicyEndpoint{ZoneID: "z-guest", ZoneName: "Hotspot", AnyTarget: true, Ports: []int{68}},
				Destination: unifi.PolicyEndpoint{ZoneID: "z-gw", ZoneName: "Gateway", AnyTarget: true, Ports: []int{67}},
			},
			{
				ID: "fp-gw-dns-iot", Name: "Allow Gateway DNS (Smart Home)", Enabled: true, Action: "ALLOW", Origin: "SYSTEM_DEFINED", Index: 22,
				IPVersion: "ipv4", Protocol: "udp",
				Source:      unifi.PolicyEndpoint{ZoneID: "z-iot", ZoneName: "IoT", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneID: "z-gw", ZoneName: "Gateway", AnyTarget: true, Ports: []int{53}},
			},
			{
				ID: "fp-gw-dhcp-iot", Name: "Allow Gateway DHCP (Smart Home)", Enabled: true, Action: "ALLOW", Origin: "SYSTEM_DEFINED", Index: 23,
				IPVersion: "ipv4", Protocol: "udp",
				Source:      unifi.PolicyEndpoint{ZoneID: "z-iot", ZoneName: "IoT", AnyTarget: true, Ports: []int{68}},
				Destination: unifi.PolicyEndpoint{ZoneID: "z-gw", ZoneName: "Gateway", AnyTarget: true, Ports: []int{67}},
			},
			{
				ID: "fp-gw-block-guest", Name: "Block Guest to Gateway Admin", Enabled: true, Action: "BLOCK", Origin: "SYSTEM_DEFINED", Index: 30,
				IPVersion: "both", Protocol: "all",
				Source:      unifi.PolicyEndpoint{ZoneID: "z-guest", ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneID: "z-gw", ZoneName: "Gateway", AnyTarget: true, AnyPort: true},
			},
			{
				ID: "fp-gw-block-iot", Name: "Block Smart Home to Gateway Admin", Enabled: true, Action: "BLOCK", Origin: "SYSTEM_DEFINED", Index: 31,
				IPVersion: "both", Protocol: "all",
				Source:      unifi.PolicyEndpoint{ZoneID: "z-iot", ZoneName: "IoT", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneID: "z-gw", ZoneName: "Gateway", AnyTarget: true, AnyPort: true},
			},
		},
		PortForwards: []unifi.PortForward{
			{ID: "pf-https", Name: "Caddy Nextcloud HTTPS", Enabled: true, Proto: "tcp", DstPort: "443", FwdIP: "192.168.10.20", FwdPort: "443", Src: "any"},
			{ID: "pf-wg", Name: "WireGuard Home VPN", Enabled: true, Proto: "udp", DstPort: "51820", FwdIP: "192.168.10.10", FwdPort: "51820", Src: "any"},
		},
		WLANs: []unifi.WLANConfig{
			{Name: "CedarHome", Enabled: true, Security: "wpapsk", WPA3Support: true, PMFMode: "optional", NetworkName: "Home LAN"},
			{Name: "CedarIoT", Enabled: true, Security: "wpapsk", L2Isolation: true, NetworkName: "Smart Home"},
			{Name: "CedarGuest", Enabled: true, Security: "wpapsk", L2Isolation: true, IsGuest: true, NetworkName: "Guest Wi-Fi"},
		},
		RogueAPs: []unifi.RogueAP{
			{ESSID: "Neighbor-5G", BSSID: "dc:9f:db:11:22:33", Channel: 36, RSSI: -74},
			{ESSID: "FiberBox-8821", BSSID: "dc:9f:db:44:55:66", Channel: 11, RSSI: -81},
		},
		SecuritySettings: &unifi.SiteSecuritySettings{
			SSHEnabled:           true,
			SSHPasswordAuth:      true,
			SSHPasswordAuthKnown: true,
			UPnPEnabled:          false,
			IPSMode:              "ips",
			HoneypotEnabled:      true,
			HoneypotIPs:          []string{"192.168.1.254", "192.168.10.254"},
			DNSFiltering:         true,
			DoHState:             "auto",
			TeleportEnabled:      true,
		},
		Health: &unifi.SystemHealth{
			WANStatus:      "ok",
			WANIP:          "198.51.100.42",
			ActiveVPNUsers: 1,
			VPNConnections: []unifi.VPNConnection{
				{Name: "WireGuard Home VPN", User: "Alex (Travel Laptop)", Type: "wireguard", RemoteIP: "203.0.113.19", LocalIP: "192.168.250.2"},
			},
		},
		Clients: []unifi.Client{
			clBMC, clRack, clLab, clNAS, clProxy, clNVR,
			clCamFront, clCamPatio, clHA, clOcto, clPrinter, clRoku, clLaptop, clPhone,
			clIrrigation, clThermostat, clShelly,
			clGuestPhone, clGuestLaptop,
		},
		RecentLogs: []unifi.ControllerLogEvent{
			{ID: "log-1", Timestamp: now.Add(-18 * time.Minute), Category: "SECURITY", Event: "THREAT_BLOCKED", Severity: "high", Message: "A network intrusion attempt from 203.0.113.77 to 192.168.10.20 has been detected and blocked.", SrcIP: "203.0.113.77", DstIP: "192.168.10.20"},
			{ID: "log-2", Timestamp: now.Add(-47 * time.Minute), Category: "NETWORK", Event: "VPN_CONNECTED", Severity: "info", Message: "WireGuard VPN session connected for Alex (Travel Laptop) from 203.0.113.19.", SrcIP: "203.0.113.19"},
			{ID: "log-3", Timestamp: now.Add(-95 * time.Minute), Category: "ADMIN", Event: "ADMIN_ACCESS", Severity: "info", Message: "Alex accessed UniFi Network using the WEB. Source IP: 192.168.1.50", SrcIP: "192.168.1.50", Admin: "Alex"},
			{ID: "log-4", Timestamp: now.Add(-3 * time.Hour), Category: "SECURITY", Event: "THREAT_BLOCKED", Severity: "high", Message: "A network intrusion attempt from 198.51.100.211 to 192.168.10.20 has been detected and blocked.", SrcIP: "198.51.100.211", DstIP: "192.168.10.20"},
		},
	}

	profiles := []probe.HostProfile{
		{
			Client:    clBMC,
			OpenPorts: []int{22, 443},
			SSHBanner: "SSH-2.0-OpenSSH_7.4p1",
			Services: []probe.Service{
				{Port: 22, Transport: "tcp", Protocol: "ssh", State: probe.ServiceStateObservedProtocol, Version: "OpenSSH_7.4p1"},
				{Port: 443, Transport: "tcp", Protocol: "https", State: probe.ServiceStateObservedProtocol, TLS: true, Title: "Dell iDRAC9 Management"},
				{Port: 623, Transport: "udp", Protocol: "ipmi", State: probe.ServiceStateObservedProtocol},
			},
			ScannedAt: now,
		},
		{
			Client:    clRack,
			OpenPorts: []int{8006},
			Services: []probe.Service{
				{Port: 8006, Transport: "tcp", Protocol: "https", State: probe.ServiceStateObservedProtocol, TLS: true, Title: "Proxmox Virtual Environment"},
			},
			ScannedAt: now,
		},
		{
			Client:    clLab,
			OpenPorts: []int{22, 3000, 11434},
			SSHBanner: "SSH-2.0-OpenSSH_8.9p1",
			Services: []probe.Service{
				{Port: 22, Transport: "tcp", Protocol: "ssh", State: probe.ServiceStateObservedProtocol, Version: "OpenSSH_8.9p1"},
				{Port: 3000, Transport: "tcp", Protocol: "http", State: probe.ServiceStateObservedProtocol, Title: "Grafana"},
				{Port: 11434, Transport: "tcp", Protocol: "http", State: probe.ServiceStateObservedProtocol, Title: "Ollama"},
			},
			ScannedAt: now,
		},
		{
			Client:    clNAS,
			OpenPorts: []int{443, 445},
			Services: []probe.Service{
				{
					Port: 445, Transport: "tcp", Protocol: "smb", State: probe.ServiceStateObservedProtocol,
					Findings: []probe.ServiceFinding{
						{ID: "smb-v1-enabled", Severity: "high", Evidence: "SMBv1 dialect negotiated during protocol handshake"},
					},
				},
				{
					Port: 443, Transport: "tcp", Protocol: "https", State: probe.ServiceStateObservedProtocol, TLS: true, Title: "TrueNAS SCALE",
					Findings: []probe.ServiceFinding{
						{ID: "tls-certificate-expired", Severity: "medium", Evidence: "Leaf TLS certificate expired 19 days ago"},
					},
				},
			},
			ScannedAt: now,
		},
		{
			Client:    clProxy,
			OpenPorts: []int{443},
			Services: []probe.Service{
				{Port: 443, Transport: "tcp", Protocol: "https", State: probe.ServiceStateObservedProtocol, TLS: true, Version: "Caddy/2.8.4"},
			},
			ScannedAt: now,
		},
		{
			Client:    clNVR,
			OpenPorts: []int{443, 554},
			Services: []probe.Service{
				{Port: 443, Transport: "tcp", Protocol: "https", State: probe.ServiceStateObservedProtocol, TLS: true, Title: "Reolink NVR Console"},
				{Port: 554, Transport: "tcp", Protocol: "rtsp", State: probe.ServiceStateObservedProtocol},
			},
			Children: []probe.ChildDevice{
				{ID: "nvr-ch1", Name: "Front Walk Camera", ParentIP: clNVR.IP, ParentMAC: clNVR.MAC, ParentRole: "nvr", Category: "camera", Role: "PoE Security Camera", Vendor: "Reolink", Model: "RLC-810A", Firmware: "v3.1.0.2356", IdentitySource: "recorder-inventory", DirectLANReachability: "unknown", PrivateAddress: "172.16.25.11"},
				{ID: "nvr-ch2", Name: "Side Yard Camera", ParentIP: clNVR.IP, ParentMAC: clNVR.MAC, ParentRole: "nvr", Category: "camera", Role: "PoE Security Camera", Vendor: "Reolink", Model: "RLC-820A", Firmware: "v3.1.0.2356", IdentitySource: "recorder-inventory", DirectLANReachability: "unknown", PrivateAddress: "172.16.25.12"},
				{ID: "nvr-ch3", Name: "Driveway Camera", ParentIP: clNVR.IP, ParentMAC: clNVR.MAC, ParentRole: "nvr", Category: "camera", Role: "PoE Security Camera", Vendor: "Reolink", Model: "RLC-811A", Firmware: "v3.1.0.2356", IdentitySource: "recorder-inventory", DirectLANReachability: "unknown", PrivateAddress: "172.16.25.13"},
			},
			ScannedAt: now,
		},
		{
			Client:    clHA,
			OpenPorts: []int{8123},
			Services: []probe.Service{
				{Port: 8123, Transport: "tcp", Protocol: "http", State: probe.ServiceStateObservedProtocol, Title: "Home Assistant"},
			},
			MDNSServices: []probe.MDNSService{
				{Type: "_home-assistant._tcp", Instance: "Cedar Home", Port: 8123, Transport: "tcp", AddressFamily: "ipv4", ObservedAt: &now},
			},
			ScannedAt: now,
		},
		{
			Client:    clOcto,
			OpenPorts: []int{5000},
			Services: []probe.Service{
				{Port: 5000, Transport: "tcp", Protocol: "http", State: probe.ServiceStateObservedProtocol, Title: "OctoPrint"},
			},
			MDNSServices: []probe.MDNSService{
				{Type: "_octoprint._tcp", Instance: "Workshop Printer", Port: 5000, Transport: "tcp", AddressFamily: "ipv4", ObservedAt: &now},
			},
			ScannedAt: now,
		},
		{
			Client:    clPrinter,
			OpenPorts: []int{80, 443, 631},
			Services: []probe.Service{
				{Port: 631, Transport: "tcp", Protocol: "ipp", State: probe.ServiceStateObservedProtocol},
				{Port: 443, Transport: "tcp", Protocol: "https", State: probe.ServiceStateObservedProtocol, TLS: true, Title: "Brother MFC-L3770CDW"},
			},
			MDNSServices: []probe.MDNSService{
				{Type: "_ipps._tcp", Instance: "Brother Office Printer", Port: 631, Transport: "tcp", AddressFamily: "ipv4", ObservedAt: &now},
			},
			ScannedAt: now,
		},
		{
			Client:    clRoku,
			OpenPorts: []int{8060},
			Services: []probe.Service{
				{Port: 8060, Transport: "tcp", Protocol: "http", State: probe.ServiceStateObservedProtocol, Title: "Roku ECP"},
			},
			OutboundDependencies: []probe.OutboundDependency{
				{Category: "vendor-control", ServiceName: "Roku Streaming Services", DestinationHost: "api.roku.com", Port: 443, Transport: "tcp", AddressFamily: "ipv4", AttributionLevel: probe.AttributionGatewayOrDNS, Source: "unifi-flows", ObservedAt: &now},
			},
			ScannedAt: now,
		},
		{Client: clCamFront, OpenPorts: []int{443}, Services: []probe.Service{{Port: 443, Transport: "tcp", Protocol: "https", State: probe.ServiceStateObservedProtocol, TLS: true}}, ScannedAt: now},
		{Client: clCamPatio, OpenPorts: []int{443}, Services: []probe.Service{{Port: 443, Transport: "tcp", Protocol: "https", State: probe.ServiceStateObservedProtocol, TLS: true}}, ScannedAt: now},
		{Client: clLaptop, ScannedAt: now},
		{Client: clPhone, ScannedAt: now},
		{
			Client:    clIrrigation,
			OpenPorts: []int{8443},
			Services: []probe.Service{
				{Port: 8443, Transport: "tcp", Protocol: "tls", State: probe.ServiceStateTLSUnknownApp, TLS: true},
			},
			OutboundDependencies: []probe.OutboundDependency{
				{Category: "shared-cdn", ServiceName: "CloudFront CDN", DestinationIP: "198.51.100.88", Port: 443, Transport: "tcp", AddressFamily: "ipv4", AttributionLevel: probe.AttributionHostingRangeOnly, Source: "unifi-flows", ObservedAt: &now},
			},
			ScannedAt: now,
		},
		{
			Client:    clThermostat,
			OpenPorts: []int{8089},
			MDNSServices: []probe.MDNSService{
				{Type: "_hap._tcp", Instance: "Hallway Thermostat", Port: 8089, Transport: "tcp", AddressFamily: "ipv4", ObservedAt: &now},
			},
			ScannedAt: now,
		},
		{
			Client:    clShelly,
			OpenPorts: []int{80},
			MDNSServices: []probe.MDNSService{
				{Type: "_shelly._tcp", Instance: "shellyplus1pm-patio", Port: 80, Transport: "tcp", AddressFamily: "ipv4", ObservedAt: &now},
			},
			ScannedAt: now,
		},
		{Client: clGuestPhone, ScannedAt: now},
		{Client: clGuestLaptop, ScannedAt: now},
	}

	rawFindings := []checks.Finding{
		{
			CheckID: "UB-0019", Title: "Out-of-Band BMC IPMI (RMCP/RMCP+)", Category: "oob-bmc",
			ClaimKind: checks.ClaimConfirmedPermission, Property: "bmc-ipmi", Transport: "udp",
			BaseSeverity: checks.SeverityHigh, EffectiveSeverity: checks.SeverityHigh,
			Client: clBMC, Port: 623,
			Evidence: "IPMI v2.0 RMCP+ active (vendor=Dell iDRAC, auth=RAKP-HMAC-SHA1)",
			Remediation: checks.Remediation{
				Summary:      "Move BMCs onto a dedicated, firewall-isolated Out-of-Band Management VLAN, disable IPMI-over-LAN if unused, and update iDRAC firmware.",
				UniFiActions: []string{"move_to_oob_management_vlan", "restrict_bmc_access_to_admin_ips"},
			},
		},
		{
			CheckID: "UB-0020", Title: "Out-of-Band BMC Redfish Service Root Discovered", Category: "oob-bmc",
			ClaimKind: checks.ClaimServiceObserved, Property: "service-identity", Transport: "tcp",
			BaseSeverity: checks.SeverityInfo, EffectiveSeverity: checks.SeverityInfo,
			Client: clBMC, Port: 443,
			Evidence: "Redfish BMC service root discovered (public metadata endpoint; verify OOB VLAN isolation)",
			Remediation: checks.Remediation{
				Summary: "Place BMC interfaces on an isolated Out-of-Band Management VLAN reachable only from an admin workstation or VPN.",
			},
		},
		{
			CheckID: "UB-0030", Title: "Unauthenticated Grafana Organization API", Category: "unauth-control",
			ClaimKind: checks.ClaimConfirmedPermission, Property: "auth-anon", Transport: "tcp",
			BaseSeverity: checks.SeverityHigh, EffectiveSeverity: checks.SeverityHigh,
			Client: clLab, Port: 3000,
			Evidence: "GET /api/org returned HTTP 200 without credentials (GF_AUTH_ANONYMOUS_ENABLED=true)",
			Remediation: checks.Remediation{
				Summary:      "Disable anonymous authentication in grafana.ini unless dashboards are intentionally public on the LAN.",
				UniFiActions: []string{"disable_anonymous_auth"},
			},
		},
		{
			CheckID: "UB-0032", Title: "Unauthenticated Ollama Local LLM API", Category: "unauth-control",
			ClaimKind: checks.ClaimConfirmedPermission, Property: "auth-anon", Transport: "tcp",
			BaseSeverity: checks.SeverityMedium, EffectiveSeverity: checks.SeverityMedium,
			Client: clLab, Port: 11434,
			Evidence: "Ollama /api/tags responded on LAN port 11434 without authentication",
			Remediation: checks.Remediation{
				Summary:      "Bind OLLAMA_HOST to 127.0.0.1 or place it behind an authenticated reverse proxy.",
				UniFiActions: []string{"bind_localhost"},
			},
		},
		{
			CheckID: "UB-2026-0055", Title: "Unauthenticated OctoPrint 3D Printer Control API", Category: "unauth-control",
			ClaimKind: checks.ClaimConfirmedPermission, Property: "auth-anon", Transport: "tcp",
			BaseSeverity: checks.SeverityHigh, EffectiveSeverity: checks.SeverityHigh,
			Client: clOcto, Port: 5000,
			Evidence: "GET /api/settings returned full printer configuration without an API key or session cookie",
			Remediation: checks.Remediation{
				Summary:      "Enable Access Control in OctoPrint settings and move the 3D printer onto your isolated Smart Home VLAN.",
				UniFiActions: []string{"move_to_iot_vlan"},
			},
		},
		{
			CheckID: "UB-2026-0063", Title: "Unauthenticated Roku External Control Protocol (ECP)", Category: "unauth-control",
			ClaimKind: checks.ClaimConfirmedPermission, Property: "auth-anon", Transport: "tcp",
			BaseSeverity: checks.SeverityMedium, EffectiveSeverity: checks.SeverityMedium,
			Client: clRoku, Port: 8060,
			Evidence: "GET /query/device-info returned Roku Ultra metadata over unauthenticated ECP",
			Remediation: checks.Remediation{
				Summary:      "Set Control by mobile apps to Limited or Disabled in Roku Settings and move the streaming box to your Smart Home VLAN.",
				UniFiActions: []string{"move_to_iot_vlan"},
			},
		},
	}

	for i := range rawFindings {
		if len(rawFindings[i].ObservedIPs) == 0 {
			rawFindings[i].ObservedIPs = rawFindings[i].Client.AllIPs()
		}
	}

	// Build realistic endpoint-bound CVE matches so both the rolled-up CVE cards
	// and the counterfactual action queue derive from the exact same matches.
	prodBMCSSH := cve.Product{
		Label: "OpenSSH", Vendors: []string{"openbsd"}, Products: []string{"openssh"},
		Version: "7.4p1", Source: "ssh-banner", HighConfidence: true,
		Ports:    []cve.EndpointPort{{Transport: "tcp", Port: 22}},
		HostName: clBMC.Name, HostIP: clBMC.IP, VLAN: clBMC.NetworkName,
	}
	prodLabSSH := cve.Product{
		Label: "OpenSSH", Vendors: []string{"openbsd"}, Products: []string{"openssh"},
		Version: "8.9p1", Source: "ssh-banner", HighConfidence: true,
		Ports:    []cve.EndpointPort{{Transport: "tcp", Port: 22}},
		HostName: clLab.Name, HostIP: clLab.IP, VLAN: clLab.NetworkName,
	}
	demoCVEMatches := []cve.Match{
		{
			Confidence: cve.ConfidenceExact, Product: prodBMCSSH,
			MatchedCPE: cve.CPEMatch{Vendor: "openbsd", Product: "openssh", EndExcl: "9.8p1"},
			Record:     cve.Record{ID: "CVE-2024-6387", Severity: checks.SeverityCritical, CVSS: 9.8, AttackVector: "N", KEV: true, Description: "OpenSSH regreSSHion signal handler race condition"},
		},
		{
			Confidence: cve.ConfidenceExact, Product: prodBMCSSH,
			MatchedCPE: cve.CPEMatch{Vendor: "openbsd", Product: "openssh", EndExcl: "9.3p2"},
			Record:     cve.Record{ID: "CVE-2023-38408", Severity: checks.SeverityHigh, CVSS: 8.8, AttackVector: "N", Description: "OpenSSH forwarded ssh-agent PKCS#11 remote code execution"},
		},
		{
			Confidence: cve.ConfidenceExact, Product: prodBMCSSH,
			MatchedCPE: cve.CPEMatch{Vendor: "openbsd", Product: "openssh", EndExcl: "8.8p1"},
			Record:     cve.Record{ID: "CVE-2021-41617", Severity: checks.SeverityHigh, CVSS: 7.0, AttackVector: "N", PrivilegesRequired: "L", Description: "OpenSSH AuthorizedKeysCommand supplemental groups privilege escalation"},
		},
		{
			Confidence: cve.ConfidenceExact, Product: prodLabSSH,
			MatchedCPE: cve.CPEMatch{Vendor: "openbsd", Product: "openssh", EndExcl: "9.8p1"},
			Record:     cve.Record{ID: "CVE-2024-6387", Severity: checks.SeverityCritical, CVSS: 9.8, AttackVector: "N", KEV: true, Description: "OpenSSH regreSSHion signal handler race condition"},
		},
		{
			Confidence: cve.ConfidenceExact, Product: prodLabSSH,
			MatchedCPE: cve.CPEMatch{Vendor: "openbsd", Product: "openssh", EndExcl: "9.6p1"},
			Record:     cve.Record{ID: "CVE-2023-48795", Severity: checks.SeverityHigh, CVSS: 7.4, AttackVector: "N", Description: "SSH Terrapin prefix truncation attack"},
		},
	}

	events := []LiveEvent{
		{ID: 6, Time: now.Add(-12 * time.Second), Type: "scan_complete", Severity: "info", Summary: "Full scan complete (demo baseline): 18 clients, 3 NVR child cameras, 2 exact CVE rollups"},
		{ID: 5, Time: now.Add(-20 * time.Second), Type: "finding_new", Severity: "high", Host: clOcto.Name, IP: clOcto.IP, SubjectID: hostEntityID(clOcto), Summary: "New [HIGH] UB-2026-0055: Unauthenticated OctoPrint 3D Printer Control API (port 5000)"},
		{ID: 4, Time: now.Add(-21 * time.Second), Type: "finding_new", Severity: "high", Host: clBMC.Name, IP: clBMC.IP, SubjectID: hostEntityID(clBMC), Summary: "New [HIGH] UB-UNIFI-ISO-BMC-IPV6: Guest Wi-Fi IPv6 rule reaches Rack Server iDRAC"},
		{ID: 3, Time: now.Add(-22 * time.Second), Type: "finding_new", Severity: "high", Host: clLab.Name, IP: clLab.IP, SubjectID: hostEntityID(clLab), Summary: "New [HIGH] UB-0030: Unauthenticated Grafana Organization API (port 3000)"},
		{ID: 2, Time: now.Add(-2 * time.Minute), Type: "client_joined", Severity: "info", Host: clGuestLaptop.Name, IP: clGuestLaptop.IP, SubjectID: hostEntityID(clGuestLaptop), Summary: "Visitor Laptop (192.168.50.11) joined Guest Wi-Fi"},
		{ID: 1, Time: now.Add(-4 * time.Minute), Type: "startup", Severity: "info", Summary: "UniBlue demo mode started (simulated UniFi home network, zero packets sent)"},
	}

	return snap, netCfg, profiles, rawFindings, demoCVEMatches, events
}
