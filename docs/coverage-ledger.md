# UniBlue Coverage Ledger

Baseline: `50547fc` (plus UI redesign `1c8fdf7`) · Updated against [coverage-expansion-report.md](coverage-expansion-report.md), [discovery-coverage-index.md](discovery-coverage-index.md), and [uniblue-coverage-research.md](uniblue-coverage-research.md).

## Separate Coverage Counts

| Metric | Count | Supporting Code / Verification |
|---|---:|---|
| Embedded YAML checks validated | **122** (30 generic + 92 community, incl. 11 wire protocol probes) | `uniblue check validate`, `checks/generic/`, `checks/community/` |
| Explicit DNS-SD browse types in UniBlue | **77** (up from 49; +28 high-value types from HA index) | [internal/probe/discover.go](../internal/probe/discover.go) |
| Device families in report | **26** (`15` implemented-verified, `7` already-works, `3` partial, `1` requires-input) | Table 1 below |
| Service families in report | **27** (`19` implemented-verified, `5` already-works, `3` partial, `0` requires-input) | Table 2 below |
| Pinned Nerva v1.84.6 service recognizers | **161 packages** / **189 registry names** (153 TCP/TLS-capable, 28 UDP-only, 8 SCTP-only) | [internal/probe/nerva_matrix.go](../internal/probe/nerva_matrix.go) |
| Read-only wire protocol probes in UniBlue | **33** (+11 added: Bitcoin P2P/RPC, Eth Engine API, NUT, LIFX, PJLink, NBNS, PCP, DNS recursion, NTP, STUN) | [internal/checks/probes_protocols.go](../internal/checks/probes_protocols.go) |
| Network & isolation checks in report | **50** (`23` implemented-verified, `7` already-works, `10` partial, `10` requires-input) | Table 3 below |
| End-to-end acceptance cases verified | **5 / 5** | [internal/server/isolation_and_exposure_test.go](../internal/server/isolation_and_exposure_test.go) |

Status key:
- `already-works`: shipped before this expansion and verified intact.
- `implemented-verified`: implemented or corrected in this expansion with automated positive + negative fixture tests.
- `partial`: core identity, inventory, or rule path shipped; deeper vendor/protocol or controller fields still pending.
- `requires-input`: depends on unavailable hardware, controller API fields, or external owner feeds (exact missing input documented).

---

## 1. IoT & LAN Device Families (26 Rows)

| # | Device Family | Status | Supporting Rule / Code / Fixture | Grouped Index Domains / Notes |
|---:|---|---|---|---|
| 1 | Matter accessories & bridges | `implemented-verified` | `UB-2026-0066`, `UB-2026-0067`, `DiscoveryCache` (`_matter._tcp` UDP exception + IPv6 AAAA + `cm=1/2` vs `cm=0`), `ParseBridgeInventory("matter")` | `matter`; zero TCP dials scheduled for `_matter._tcp`. |
| 2 | Thread border routers & sleepy endpoints | `implemented-verified` | `UB-2026-0068`, `_meshcop._udp`, `classifyByDiscovery`, `ChildDevice.Sleeping` | `thread`, `otbr`. |
| 3 | Zigbee & Z-Wave coordinators & children | `implemented-verified` | `UB-2026-0036`, `UB-2026-0038`, `ParseBridgeInventory("zigbee2mqtt" / "zwave-js")` | `zha`, `zwave_js`, `deconz`, `smlight`, `tradfri`, `hue` (grouped via coordinator inventories). |
| 4 | Bluetooth sensors, beacons & proxies | `partial` | `ParseBridgeInventory("ble")` (`DirectLANReachability: "non-ip-radio"`) | 60 BLE domains in index require owner-supplied BLE proxy export (no direct radio capture in UniBlue). |
| 5 | HomeKit accessories & IP automation hubs | `already-works` | `UB-2026-0035`, `UB-2026-0010`, `_hap._tcp`, `_hap._udp`, `_homekit._tcp`, `_home-assistant._tcp` | `homekit_controller`, `homekit`, `hass`, `openhab`, `homebridge`, `nodered`. |
| 6 | Lighting, relays, outlets & dimmers | `implemented-verified` | `UB-2026-0005`..`0009`, `UB-2026-0039`, `UB-2026-0071` (Lutron), `UB-2026-0073` (Shelly mDNS), `_lutron._tcp`, `_shelly._tcp`, `_lifx._udp`, `_nanoleafapi._tcp`, `_deako._tcp`, `_elg._tcp` | `shelly`, `wled`, `tasmota`, `esphome`, `tplink`, `hue`, `lifx`, `nanoleaf`, `lutron_caseta`, `elgato`, `deako`. |
| 7 | Blinds, shades & garage controllers | `implemented-verified` | `UB-2026-0072` (PowerView), `UB-2026-0078` (Bond/Overkiz), `_powerview._tcp`, `_powerview-g3._tcp`, `_kizbox._tcp`, `_bond._tcp` | `hunterdouglas_powerview`, `overkiz`, `bond`, `somfy_mylink`, `gogogate2`. |
| 8 | Door locks, alarm panels & intercoms | `implemented-verified` | `UB-2026-0076` (DoorBird `_axis-video._tcp` + `1ccae3` TXT guard preventing Axis false positive), `classify/taxonomy.yaml` | `doorbird`, `nuki`, `elkm1`, `envisalink`, `loqed`. Permission claims require owner panel/lock policy. |
| 9 | Cameras, NVRs, doorbells & baby monitors | `implemented-verified` | `UB-2026-0042` (corrected to `asset-identity` Info), `UB-2026-0011`, `UB-2026-0012`, `UB-2026-0016`, `UB-2026-0017`, `UB-2026-0033`, `UB-2026-0045`, `ParseBridgeInventory("nvr")` (Acceptance Case 4) | `onvif`, `axis`, `reolink`, `hikvision`, `unifiprotect`, `frigate`, `zoneminder`, `amcrest`. |
| 10 | Smart speakers, AVRs & casting | `already-works` | `UB-2026-0002`, `UB-2026-0026`..`0028`, `UB-2026-0049`..`0052`, `_bangolufsen._tcp`, `_devialet-http._tcp`, `_stream-magic._tcp`, `_mass._tcp` | `cast`, `sonos`, `heos`, `denonavr`, `yamaha_musiccast`, `soundtouch`, `bluesound`, `wiim`, `linkplay`, `volumio`, `airplay`. |
| 11 | TVs, set-top boxes, tuners & signage | `already-works` | `UB-2026-0025`, `UB-2026-0029`, `UB-2026-0030`, `UB-2026-0047`, `UB-2026-0048`, `UB-2026-0051` | `roku`, `samsungtv`, `webostv`, `braviatv`, `philips_js`, `vizio`, `kodi`, `plex`, `androidtv_remote`, `apple_tv`. |
| 12 | Printers, scanners & USB print bridges | `implemented-verified` | `UB-2026-0069` (IPP/IPPS inventory), `UB-0010`, `UB-2026-0013`, `UB-2026-0043`, raw-print socket guard verified 0 bytes (`TestRawPrinterReceivesZeroApplicationBytesAtSocketBoundary`), Acceptance Case 1 | `ipp`, `brother`, `syncthru`, `hp_printer`. |
| 13 | 3D printers, CNC & workshop gateways | `already-works` | `UB-2026-0014` (Moonraker/Klipper), `UB-2026-0015` (OctoPrint), `classify/taxonomy.yaml` | `octoprint`, `prusalink`, `bambu`, `klipper`. |
| 14 | Thermostats, heat pumps, AC & HVAC | `implemented-verified` | `UB-2026-0001` (Zehnder), `UB-2026-0019` (Daikin), `UB-2026-0054` (Venstar), `UB-2026-0078` (ecobee/Plugwise), `UB-2026-0081` (KNX/BACnet) | `ecobee`, `daikin`, `plugwise`, `comfoconnect`, `venstar`, `knx`, `tado`. |
| 15 | Solar inverters, batteries & energy gateways | `implemented-verified` | `UB-2026-0023` (Fronius), `UB-2026-0055` (OpenDTU), `UB-2026-0074` (Enphase/SolarEdge/Solarman/my-PV), `UB-2026-0075` (Victron GX SSDP), `ParseBridgeInventory("energy")` | `enphase_envoy`, `solaredge_modbus`, `victron_gx`, `fronius`, `solarman`, `my_pv`, `powerwall`. |
| 16 | EV charging & OCPP systems | `implemented-verified` | `UB-2026-0020` (go-e), `UB-2026-0021` (OpenEVSE), `UB-2026-0057` (Tesla Wall Connector), `UB-2026-0077` (EV charger DNS-SD) | `openevse`, `nrgkick`, `technove`, `tesla_wall_connector`. OCPP backend profile requires owner CSMS export. |
| 17 | Smart meters & utility pulse readers | `already-works` | `UB-2026-0024` (HomeWizard), `_hwenergy._tcp`, `_homewizard._tcp`, `classify/taxonomy.yaml` | `homewizard`, `dsmr`, `dsmr_reader`, `iometer`. |
| 18 | UPSs, PDUs & rack power monitors | `implemented-verified` | `UB-2026-0070` (NUT `_nut._tcp` inventory), `classifyByDiscovery` | `nut`, `apcupsd`. Shutdown vs read-only permissions require owner `upsd.users` policy. |
| 19 | Irrigation, pools, hot tubs & water valves | `partial` | `classify/taxonomy.yaml` (Rachio) + DNS-SD / DHCP host rules | `rainmachine`, `rachio`, `screenlogic`, `guardian`, `droplet` (need hardware fixtures for active API checks). |
| 20 | Weather, air-quality & specialist sensors | `already-works` | `UB-2026-0056` (AirGradient), `_airgradient._tcp`, `ApplyPassiveFlows` (egress attribution) | `airgradient`, `ecowitt`, `ruuvi_gateway`, `airq`, `awair`. |
| 21 | Appliances, robot vacuums & wellness | `partial` | `UB-2026-0022` (Valetudo), `_homeconnect._tcp`, `classify/taxonomy.yaml` | `home_connect` (cloud API), `roomba`, `roborock`, `miele`, `whirlpool`. |
| 22 | Network appliances, ISP gateways & mesh | `already-works` | `UB-2026-0018`, `UB-2026-0040` (UPnP IGD), `UB-2026-0041` (FRITZ!Box TR-064), UniFi adoption + LLDP | `upnp`, `fritz`, `mikrotik`, `openwrt`, `unifi_discovery`. |
| 23 | NAS, backup appliances, hypervisors & BMCs | `implemented-verified` | `UB-0030` (IPMI), `UB-2026-0061` (Redfish corrected to `service-observed` Info), `UB-2026-0062`..`0065`, `UB-UNIFI-BMC-SHARED-VLAN`, `UB-UNIFI-ISO-BMC-IPV6` (Acceptance Case 2) | `synology_dsm`, `qnap`, `proxmoxve`, `hp_ilo`, IPMI/Redfish/iDRAC/ASMB. |
| 24 | Phones, tablets, workstations & IP phones | `implemented-verified` | `UB-0009` (legacy TCP ADB), `UB-2026-0032`, `UB-2026-0034`, `UB-2026-0046` (corrected to `service-advertised` Info), private-MAC guard in `classify.go` | `androidtv`, `apple_tv`, mobile randomized-MAC handling. |
| 25 | Building & industrial OT systems | `implemented-verified` | `UB-0003` (Modbus), `UB-2026-0081` (BACnet/KNX/OPC UA/S7/EtherNet/IP/DNP3/IEC104 inventory via passive/Nerva) | Requires owner OT engineering inventory for actuation vs discovery policy. |
| 26 | Medical, life-safety & sensitive embedded | `requires-input` | `config.Network.ExcludeIPs` + `BridgeInventorySpec` | Requires biomedical/facilities asset inventory; operators must list sensitive hosts in `network.exclude_ips` to prevent active TCP probing. |

---

## 2. Internet & LAN Service Families (27 Rows)

| # | Service Family | Status | Supporting Code / Recognizer / Fixture |
|---:|---|---|---|
| 1 | Web front ends, reverse proxies & APIs | `implemented-verified` | Nerva `http`/`https`, `fetchHTTPBanner`, `UB-UNIFI-PROXY-ADMIN-PUBLIC`, `ProxyRoute` |
| 2 | TLS, DTLS, QUIC & app encryption | `implemented-verified` | `UB-0020`, Nerva TLS cert checks, `ServiceStateTLSUnknownApp` preserved on raw TLS & QUIC (`TestNervaMatrixAudit_AlternatePorts_AndTLSUnknownApp`) |
| 3 | Authoritative/recursive DNS, DoT & DoH | `implemented-verified` | Nerva `dns`, `ApplyPassiveFlows` (UDP 53), UniFi DoH setting audit |
| 4 | DHCPv4, DHCPv6, RA & network boot | `partial` | UniFi DHCP pool/config checks; rogue DHCPv4/v6 & RA require link-local passive collector or switch snooping telemetry |
| 5 | Time & discovery infrastructure | `implemented-verified` | `DiscoveryCache` (mDNS/SSDP/WS-D with TTL/expiry/reflection), `UB-0029` (CoAP), `ApplyPassiveFlows` (UDP NTP) |
| 6 | Mail transport, submission & retrieval | `implemented-verified` | Nerva `smtp`, `imap`, `pop3`, `managesieve` (TCP/TLS active-capable) + `UB-2026-0059` (MailHog/Mailpit) |
| 7 | Directory, authentication & PKI | `implemented-verified` | Nerva `ldap`, `kerberos` (TCP/TLS active-capable); RADIUS/TACACS+ via passive flow ingestion |
| 8 | Interactive remote administration | `already-works` | `UB-0001` (Telnet), `UB-0005` (VNC), `UB-0013` (RDP), `UB-0016` (WinRM), Nerva `ssh` (tested on alternate port!) |
| 9 | Network management (SNMP/NETCONF/gNMI) | `implemented-verified` | `UB-0021` (SNMP), Nerva `mikrotikwinbox`, `grpc`, UniFi SSH audit |
| 10 | VPNs, overlays & publishing tunnels | `implemented-verified` | UniFi VPN health, `rules/wan_exposure.yaml` (WireGuard), `UB-UNIFI-TUNNEL-ADMIN-PUBLIC` (`PublishedTunnel`) |
| 11 | Voice, intercom & real-time media | `implemented-verified` | `UB-0004` (RTSP), Nerva `sip`, `h323`, `rtsp`, `rtmp`; STUN/TURN via passive UDP flows |
| 12 | File transfer & file sharing | `already-works` | `UB-0014` (FTP), `UB-0024` (rsync), `UB-2026-0053` (AFP), Nerva `smb` (SMBv1 + signing property-keyed), `nfs` |
| 13 | Object, block & cluster storage | `partial` | Nerva HTTP/MinIO product detection; bucket/iSCSI/Ceph ACLs require owner storage policy export |
| 14 | SQL databases & analytical stores | `implemented-verified` | `UB-2026-0079` + Nerva `postgresql`, `mysql`, `mssql`, `oracledb`, `clickhouse`, `db2`, `firebird` |
| 15 | Document, graph, KV, search & vector stores | `implemented-verified` | `UB-0015` (Redis), `UB-0023` (Memcached), `UB-0025` (Elasticsearch), `UB-2026-0079`, Nerva `mongodb`, `neo4j`, `qdrant`, `milvus`, `influxdb` |
| 16 | Message brokers, queues & event streams | `implemented-verified` | `UB-0002` (MQTT), `UB-2026-0080` + Nerva `amqp`, `kafka`, `nats`, `pulsar`, `activemq` |
| 17 | Container runtimes & orchestration | `already-works` | `UB-0008` (Docker), `UB-0026` (etcd), Nerva `docker`; K8s RBAC requires owner cluster policy |
| 18 | Hypervisors, backup & BMCs | `implemented-verified` | `UB-0030` (IPMI), `UB-2026-0061`..`0065`, Nerva `vmware`, `classify.go` (Proxmox/NAS) |
| 19 | Observability, collectors & monitoring | `already-works` | `UB-0007` (Grafana), Nerva `zabbix`, `nrpe`; syslog/IPFIX via passive UDP flows |
| 20 | Developer & AI services | `already-works` | `UB-0012` (Ollama), `UB-0017` (Chrome DevTools), `UB-0018` (Jupyter), `UB-0019` (Python HTTP), `UB-0027` (Node Inspector), `UB-0028` (Vite), `UB-2026-0058` (ComfyUI) |
| 21 | Source control, CI/CD & registries | `partial` | Nerva `git`, `svn`, `sonarqube`; runner/push ACLs require owner forge export |
| 22 | HTTP/SOCKS proxies, gateways & LBs | `implemented-verified` | `UB-0011` (Traefik), Nerva `socks4`/`socks5`, `ProxyRoute` frontend/backend check |
| 23 | IoT messaging & building control | `implemented-verified` | `UB-0002` (MQTT), `UB-0003` (Modbus), `UB-0029` (CoAP), `UB-2026-0081` (BACnet/KNX/OPC UA) |
| 24 | Industrial, telecom & routing control | `implemented-verified` | `UB-2026-0081` + Nerva `bgp`, `s7comm`, `ethernetip`, `dnp3`, `iec104`, `hartip`, `diameter` (passive/inventory packs) |
| 25 | Collaboration, streaming & gaming | `implemented-verified` | `UB-2026-0030` (Kodi), `UB-2026-0031` (Transmission), `UB-2026-0060` (qBittorrent), Nerva `irc`, `xmpp`, `rtmp`, transport-aware UDP game forwards (Acceptance Case 3) |
| 26 | Peer-to-peer & blockchain | `implemented-verified` | `UB-2026-0003` (Eth RPC), `UB-2026-0004` (Beacon), `UB-2026-0082` (Bitcoin P2P), `UB-2026-0083` (Bitcoin RPC), `UB-2026-0084` (Eth Engine API), `rules/wan_exposure.yaml` |
| 27 | Proprietary, cloud-only & unidentified | `implemented-verified` | `ServiceStateUnknown`, `ServiceStateTLSUnknownApp`, `OutboundDependency` (`AttributionHostingRangeOnly`, `AttributionOpaqueEncrypted`) |

---

## 3. Network & Isolation Checks (50 Rows)

| Group | # | Check | Status | Supporting Implementation / Missing Input |
|---|---:|---|---|---|
| Gateway & External | 1 | Effective guest/IoT/camera/DMZ -> trusted access | `implemented-verified` | `EvaluateIsolation` + `evaluateGatewayPolicies` (ordered rules, new vs established, IPv4/IPv6) |
| Gateway & External | 2 | Untrusted access to gateway itself | `implemented-verified` | `UB-UNIFI-ISO-GW-ADMIN` (separates gateway admin from DHCP/DNS) |
| Gateway & External | 3 | IPv4 and IPv6 policy parity | `implemented-verified` | `EvaluateIsolation` evaluates IPv4 & IPv6 independently (`UB-UNIFI-ISO-BMC-IPV6`, Acceptance Case 2) |
| Gateway & External | 4 | NAT/forward translates to wrong service/transport | `implemented-verified` | `PortForward.ExposesEndpoint(port, transport)` (Acceptance Case 3) |
| Gateway & External | 5 | Stale forward after DHCP lease reuse | `partial` | `AnalyzePosture` flags unnamed/unknown forward targets; longitudinal lease-change tracking needs historical DHCP lease feed |
| Gateway & External | 6 | External reachability overstated behind upstream NAT | `implemented-verified` | `AnalyzeExtendedNetworkChecks` CGNAT/RFC1918 WAN IP disclaimer |
| Gateway & External | 7 | UPnP, NAT-PMP or PCP dynamic mapping drift | `implemented-verified` | `UB-UNIFI-UPNP-ENABLED` + `UB-UNIFI-DYNAMIC-NAT-MAPPING` (third-party escalation) |
| Gateway & External | 8 | Public proxy vs direct backend control mismatch | `implemented-verified` | `UB-UNIFI-PROXY-ADMIN-PUBLIC` + unauthenticated backend note (`ProxyRoute`) |
| Gateway & External | 9 | Outbound tunnel publishes internal app | `implemented-verified` | `UB-UNIFI-TUNNEL-ADMIN-PUBLIC` (`PublishedTunnel`) |
| Gateway & External | 10 | Site-to-site / remote / overlay VPN trust crossing | `partial` | UniFi VPN session tracking + `UB-UNIFI-FW-*`; overlay ACL graphs (Tailscale/WireGuard peers) require owner policy export |
| Gateway & External | 11 | Failover sends traffic over unintended WAN | `requires-input` | `IsolationIntent.VPNOnlyVLANs` modeled; requires UniFi PBR/failover event telemetry |
| Gateway & External | 12 | Overlapping site/VPN subnets or asymmetric routing | `implemented-verified` | `UB-UNIFI-OVERLAPPING-SUBNETS` in `AnalyzeExtendedNetworkChecks` |
| Switching & Wi-Fi | 13 | Native VLAN mismatch across link | `implemented-verified` | `UB-UNIFI-NATIVE-VLAN-MISMATCH` across LLDP parent/child ports |
| Switching & Wi-Fi | 14 | Required tagged VLAN missing on trunk | `partial` | `SwitchPort.TaggedVLANMgmt` audited; per-VLAN custom trunk allowlist array requires UniFi port profile expansion |
| Switching & Wi-Fi | 15 | Unnecessary tagged VLAN on exposed edge/feeder | `already-works` | `UB-UNIFI-PORT-EXT-UPLINK`, `UB-UNIFI-PORT-EXT-OPEN`, `UB-UNIFI-PORT-EXT-UNUSED-OPEN` |
| Switching & Wi-Fi | 16 | Switch-routed traffic bypasses gateway-only ACL | `implemented-verified` | `evaluateRoutedPath` (`RouterDeviceMAC` + `SwitchACLCoverage`, Acceptance Case 5) |
| Switching & Wi-Fi | 17 | Same-VLAN Wi-Fi peer isolation (same-AP vs cross-AP) | `implemented-verified` | `evaluateSameVLANPeerIsolation` + `UB-UNIFI-WIFI-NO-L2-ISOLATION` |
| Switching & Wi-Fi | 18 | Same-VLAN wired & mixed wired/Wi-Fi peers | `implemented-verified` | `evaluateSameVLANPeerIsolation` (`wired-same-vlan` checks port isolation / switch ACL or marks `unknown`) |
| Switching & Wi-Fi | 19 | SSID association gives wrong effective VLAN | `already-works` | `UB-UNIFI-WIFI-IOT-ON-TRUSTED` (PPSK/RADIUS per-key mapping requires UniFi PPSK table) |
| Switching & Wi-Fi | 20 | Wired NAC / MAC-based VLAN fallback too trusted | `requires-input` | Requires UniFi 802.1X/RADIUS port-fallback telemetry not in standard `stat/device` |
| Switching & Wi-Fi | 21 | Guest portal & pre-authentication access | `partial` | Guest zone policies audited; hotspot pre-auth walled-garden list requires portal config feed |
| Switching & Wi-Fi | 22 | Rogue or duplicate SSID confidence | `already-works` | `UB-UNIFI-WIFI-EVIL-TWIN`, `UB-UNIFI-WIFI-ROGUE-WIRED-AP` (filters owned UniFi virtual BSSIDs) |
| Switching & Wi-Fi | 23 | STP root or topology changes unexpectedly | `already-works` | Live STP blocking/churn anomaly tracker in `internal/server/anomalies.go` |
| Switching & Wi-Fi | 24 | LAG, redundant uplinks & inferred loops | `partial` | `SwitchPort.OpMode == "aggregate"` & STP state tracked; multi-port LAG peer validation needs LACP telemetry |
| Switching & Wi-Fi | 25 | Physical jack or power role changes | `already-works` | PoE drop cable-swap & MAC-surge tracker in `internal/server/anomalies.go` |
| Switching & Wi-Fi | 26 | Controller/AP/switch/BMC management on user path | `implemented-verified` | `UB-UNIFI-BMC-SHARED-VLAN`, `UB-UNIFI-ISO-BMC-PATH`, `UB-UNIFI-ISO-BMC-IPV6`, `UB-UNIFI-SSH-PASSWORD` |
| Local Infra & Drift | 27 | Unapproved DHCPv4 server or conflicting lease | `requires-input` | `IsolationIntent.ApprovedDHCPServers` modeled; requires link-local DHCPv4 offer observer or switch DHCP-guard logs |
| Local Infra & Drift | 28 | Unapproved IPv6 RA / prefix / DNS / DHCPv6 | `requires-input` | Requires link-local ICMPv6 RA / DHCPv6 passive observer |
| Local Infra & Drift | 29 | Duplicate or overlapping LAN address pools | `implemented-verified` | `UB-UNIFI-OVERLAPPING-SUBNETS` |
| Local Infra & Drift | 30 | IPv6 broken by blanket ICMPv6 blocking | `implemented-verified` | `UB-UNIFI-IPV6-BLANKET-ICMPV6-BLOCK` |
| Local Infra & Drift | 31 | DNS/NTP/boot dependencies accidentally denied | `implemented-verified` | `IsolationBrokenDependency` in `EvaluateIsolation` |
| Local Infra & Drift | 32 | DNS or egress bypass of restricted segment | `partial` | `ApplyPassiveFlows` + `Network.DNSServers` modeled; requires live gateway flow/DNS telemetry |
| Local Infra & Drift | 33 | mDNS reflector leaks service names | `implemented-verified` | `MDNSService.Reflected` + `ObserverVLAN` tracked distinctly from service access (`DiscoveryCache`) |
| Local Infra & Drift | 34 | Authorized discovery works but app path fails | `implemented-verified` | `IsolationBrokenDependency` on approved guest IPPS printing when blocked |
| Local Infra & Drift | 35 | Camera/BMC/backup/facilities excessive lateral access | `implemented-verified` | `EvaluateIsolation` directed zone/function checks + `UB-UNIFI-FW-ISO-LEAK` |
| Local Infra & Drift | 36 | Device egress departs from verified MUD policy | `requires-input` | `OutboundDependency` foundation shipped; signed RFC 8520 MUD profile verifier not yet integrated |
| Local Infra & Drift | 37 | Device attached to multiple trust zones | `partial` | Wired-vs-Wi-Fi medium swap tracked in `anomalies.go`; cross-VLAN forwarding proof requires host/flow telemetry |
| Local Infra & Drift | 38 | Firmware lifecycle, advisory or unsupported gear | `already-works` | Local NVD+KEV exact vs potential CVE rollup (`internal/cve`) + `UB-UNIFI-FIRMWARE` |
| Local Infra & Drift | 39 | New asset, service or rule broadening after change | `already-works` | `risk.ComputeDiff` + live SSE policy/forward/client delta engine |
| Local Infra & Drift | 40 | Incomplete site visibility | `implemented-verified` | `SiteVisibility`, `SwitchACLCoverage`, `DiscoveryCache.MarkUnavailable`, `AnalyzeExtendedNetworkChecks` |
| Health & Recovery | 41 | DHCP pool approaching exhaustion | `implemented-verified` | `AnalyzeExtendedNetworkChecks` (>= 85% usable pool utilization) |
| Health & Recovery | 42 | Internal DNS sends client to wrong service | `requires-input` | Requires per-VLAN DNS query vantage or UniFi local DNS record export |
| Health & Recovery | 43 | Cert rotation breaks enterprise Wi-Fi (EAP-TLS) | `requires-input` | Requires owner RADIUS server cert & managed client trust store input |
| Health & Recovery | 44 | AP channel & airtime congestion | `requires-input` | Requires sustained multi-window radio utilization/retry telemetry |
| Health & Recovery | 45 | Unintended wireless mesh hop | `requires-input` | Requires expected-wired vs actual wireless-uplink history in `stat/device` |
| Health & Recovery | 46 | Underperforming or flapping Ethernet uplink | `partial` | `SwitchPort.Speed`, `RXErrors`, `TXErrors`, `STPStateChanges` collected; sustained peer-capability baseline pending |
| Health & Recovery | 47 | PoE shortfall affecting cameras/phones/APs | `partial` | Live `PoEPowerWatts` & PoE-drop anomalies tracked; switch total PoE budget ceiling requires device capability table |
| Health & Recovery | 48 | Multicast loss or flooding on AV/IoT | `partial` | `Network.IGMPSnooping` modeled; querier election requires switch IGMP snooping table |
| Health & Recovery | 49 | WAN failover misreports outage | `requires-input` | Requires multi-WAN SLA target & probe metric export |
| Health & Recovery | 50 | Critical network config lacks recoverable backup | `implemented-verified` | `BackupStatus` freshness & restore-test age check in `AnalyzeExtendedNetworkChecks` |
