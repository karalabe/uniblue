# UniBlue discovery coverage index

Companion to the [coverage plan](coverage-expansion-report.md). This index gives maintainers a named candidate for each reference integration or protocol package, plus the source of its identifying evidence. Inclusion means there is an upstream lead to investigate. Shipping support requires a UniBlue fixture and an observable result.

## Device integration candidates

Home Assistant Core 2026.11.3 contains 1,562 component manifests. The six generated discovery files below reference **344 distinct integration domains** including HomeKit model mapping and serial port selection. Of these, **252** have a DNS-SD matcher, HomeKit model mapper, SSDP matcher, or DHCP hint that can apply to a previously unknown asset. Some identify a platform or application. Some merely suggest a cloud integration for a LAN device. The remaining 92 need another observation channel or a prior registration under this counting method. A single integration can represent thousands of supported products. [Component manifests](https://github.com/home-assistant/core/tree/92da9f154079459b9e547126f9bd9fce726de16a/homeassistant/components) · [Generated discovery registries](https://github.com/home-assistant/core/tree/92da9f154079459b9e547126f9bd9fce726de16a/homeassistant/generated)

| Signal | Distinct domains | What UniBlue can learn |
|---|---:|---|
| DNS-SD | 122 | A typed service advertisement. Preserve model, instance and property predicates from the upstream matcher. |
| HAP model | 21 | A model mapping on an Apple HomeKit accessory advertisement. Treat as a family hint. |
| SSDP | 44 | An advertised device or service description. Manufacturer and type constraints often matter jointly. |
| DHCP hint | 105 | A hostname or hardware address pattern eligible for a new observation. Corroborate the identity. |
| DHCP known | 42 | An upstream matcher restricted to already registered devices. Reconcile an existing identity. |
| BLE | 60 | An advertisement from an authorized Bluetooth observer within radio range. |
| MQTT | 10 | Device discovery information on an owner-authorized broker. Retain identity fields only. |
| USB | 9 | An authorized host can identify the attached adapter. Child endpoints require their own inventory. |
| serial | 19 | An integration accepts operator-selected serial equipment. Selection alone supplies no remote device identity. |

Each row uses the first category in the upstream manifest for navigation. The interaction column describes how Home Assistant normally communicates after discovery. A cloud integration can have a local discovery signal.

### AI and voice

| Upstream name | Integration | Signals | Interaction |
|---|---|---|---|
| Wyoming Protocol | `wyoming` | DNS-SD | local push |

### Appliances and cleaning

| Upstream name | Integration | Signals | Interaction |
|---|---|---|---|
| Acaia | `acaia` | BLE | local push |
| Chef iQ | `chef_iq` | BLE | local push |
| Fjäråskupan | `fjaraskupan` | BLE | local polling |
| Home Connect | `home_connect` | DNS-SD, DHCP hint | cloud push |
| iRobot Roomba and Braava | `roomba` | DNS-SD, DHCP hint, DHCP known | local push |
| Kegtron | `kegtron` | BLE | local push |
| La Marzocco | `lamarzocco` | DHCP hint, DHCP known, BLE | cloud push |
| LG ThinQ | `lg_thinq` | DHCP hint | cloud push |
| Liebherr | `liebherr` | DNS-SD | cloud push |
| Miele | `miele` | DNS-SD | cloud push |
| Probe Plus | `probe_plus` | BLE | local push |
| RAPT Bluetooth | `rapt_ble` | BLE | local push |
| Roborock | `roborock` | DHCP hint | local polling |
| ROMY Vacuum Cleaner | `romy` | DNS-SD | local polling |
| Tilt Hydrometer BLE | `tilt_ble` | BLE | local push |
| ToGrill | `togrill` | BLE | local push |
| Whirlpool Appliances | `whirlpool` | DHCP hint | cloud push |

### Blinds and curtains

| Upstream name | Integration | Signals | Interaction |
|---|---|---|---|
| Aladdin Connect | `aladdin_connect` | DHCP hint | cloud polling |
| Gogogate2 and ismartgate | `gogogate2` | HAP model, DHCP hint | local polling |
| Hunter Douglas PowerView | `hunterdouglas_powerview` | DNS-SD, HAP model, DHCP hint, DHCP known | local polling |
| Motionblinds | `motion_blinds` | DHCP hint, DHCP known | local push |
| Motionblinds Bluetooth | `motionblinds_ble` | BLE | assumed state |
| Slide Local | `slide_local` | DNS-SD, HAP model | local polling |
| Somfy MyLink | `somfy_mylink` | DHCP hint | assumed state |
| Tailwind | `tailwind` | DNS-SD, DHCP known | local polling |
| Velux | `velux` | DNS-SD, DHCP hint | local polling |
| WMS WebControl pro | `wmspro` | DHCP hint, DHCP known | local polling |

### Buttons and remotes

| Upstream name | Integration | Signals | Interaction |
|---|---|---|---|
| Broadlink | `broadlink` | DHCP hint, DHCP known | local polling |
| Flic | `flic_button` | BLE | local push |
| Keymitt MicroBot Push | `keymitt_ble` | BLE | assumed state |
| Knocki | `knocki` | DHCP hint | cloud push |
| Logitech Harmony Hub | `harmony` | SSDP | local push |
| LOOKin | `lookin` | DNS-SD | local push |

### Climate

| Upstream name | Integration | Signals | Interaction |
|---|---|---|---|
| Actron Air | `actron_air` | DHCP hint | cloud push |
| aerosmart | `aerosmart` | serial | local polling |
| Airobot | `airobot` | DHCP hint | local polling |
| Airzone | `airzone` | DHCP hint | local polling |
| AriaQ | `flow_it` | DNS-SD | local push |
| Big Ass Fans | `baf` | DNS-SD | local push |
| Bond | `bond` | DNS-SD, DHCP hint | local push |
| BSB-LAN | `bsblan` | DNS-SD | local polling |
| Daikin AC | `daikin` | DNS-SD | local polling |
| Duco | `duco` | DNS-SD, DHCP hint | local polling |
| ecobee | `ecobee` | DNS-SD, HAP model | cloud polling |
| Electra Smart | `electrasmart` | DHCP hint | cloud polling |
| eQ-3 Bluetooth Smart Thermostats | `eq3btsmart` | BLE | local polling |
| Escea | `escea` | HAP model | local push |
| Eurotronic Comet Blue | `eurotronic_cometblue` | BLE | local polling |
| Flexit | `flexit` | serial | local polling |
| Fumis | `fumis` | DHCP hint | cloud polling |
| Google Nest | `nest` | DHCP hint | cloud push |
| Guntamatic | `guntamatic` | DHCP hint | local polling |
| Hive | `hive` | HAP model | cloud polling |
| Honeywell Lyric | `lyric` | DHCP hint | cloud polling |
| IntelliFire | `intellifire` | DHCP hint | local polling |
| Intergas gateway | `incomfort` | DHCP hint, DHCP known | local polling |
| iZone | `izone` | HAP model | local polling |
| Midea | `midea` | DHCP known | local polling |
| Mitsubishi Comfort | `mitsubishi_comfort` | DHCP known | local polling |
| Modern Forms | `modern_forms` | DNS-SD | local polling |
| Netatmo | `netatmo` | HAP model | cloud polling |
| Nexia/American Standard/Trane | `nexia` | DHCP hint | cloud polling |
| Nobø Ecohub | `nobo_hub` | DHCP hint, DHCP known | local push |
| NuHeat | `nuheat` | DHCP hint | cloud polling |
| Palazzetti | `palazzetti` | DHCP hint, DHCP known | local polling |
| Plugwise | `plugwise` | DNS-SD | local polling |
| Prana | `prana` | DNS-SD | local polling |
| Qube heat pump | `hr_energy_qube` | DNS-SD | local polling |
| Rabbit Air | `rabbitair` | DNS-SD | local polling |
| Radio Thermostat | `radiotherm` | DHCP hint, DHCP known | local polling |
| Sensibo | `sensibo` | HAP model, DHCP hint | cloud polling |
| STIEBEL ELTRON | `stiebel_eltron` | DHCP hint | local polling |
| Tado | `tado` | HAP model, DHCP hint | cloud polling |
| Toon | `toon` | DHCP hint | cloud push |
| VeSync | `vesync` | DHCP hint | cloud polling |
| Viessmann ViCare | `vicare` | DHCP hint | cloud polling |

### Computers and networking

| Upstream name | Integration | Signals | Interaction |
|---|---|---|---|
| Brother Printer | `brother` | DNS-SD | local polling |
| devolo Home Network | `devolo_home_network` | DNS-SD | local polling |
| Freebox | `freebox` | DNS-SD | local polling |
| FRITZ!Box Tools | `fritz` | SSDP | local polling |
| Fully Kiosk Browser | `fully_kiosk` | DHCP known, MQTT | local polling |
| Huawei LTE | `huawei_lte` | SSDP | local polling |
| Internet Printing Protocol (IPP) | `ipp` | DNS-SD | local polling |
| Keenetic NDMS2 Router | `keenetic_ndms2` | SSDP | local polling |
| NETGEAR | `netgear` | SSDP | local polling |
| OctoPrint | `octoprint` | DNS-SD, SSDP | local polling |
| PrusaLink | `prusalink` | DHCP hint | local polling |
| QNAP QSW | `qnap_qsw` | DHCP hint | local polling |
| Samsung SyncThru Printer | `syncthru` | SSDP | local polling |
| Synology DSM | `synology_dsm` | DNS-SD, SSDP | local polling |
| System Bridge | `system_bridge` | DNS-SD | local push |
| Teltonika | `teltonika` | DHCP hint | local polling |
| Ubiquiti airOS | `airos` | DHCP known | local polling |
| UPnP/IGD | `upnp` | SSDP | local polling |

### DIY and maker equipment

| Upstream name | Integration | Signals | Interaction |
|---|---|---|---|
| 1-Wire | `onewire` | DNS-SD | local polling |
| ESPHome | `esphome` | DNS-SD, DHCP known, MQTT | local push |
| Improv via BLE | `improv_ble` | BLE | local polling |
| INDI Allsky | `indi_allsky` | DNS-SD | local push |
| IronOS | `iron_os` | BLE | local polling |
| OpenDisplay | `opendisplay` | BLE | local push |
| Tasmota | `tasmota` | MQTT | local push |

### Energy

| Upstream name | Integration | Signals | Interaction |
|---|---|---|---|
| Besen | `besen` | BLE | local push |
| Bitvis Power Hub | `bitvis` | DNS-SD | local push |
| DSMR Reader | `dsmr_reader` | MQTT | local push |
| DSMR Smart Meter | `dsmr` | serial | local push |
| EARN-E P1 Meter | `earn_e_p1` | DHCP hint, DHCP known | local push |
| EDL21 | `edl21` | serial | local push |
| energieleser | `energieleser` | DNS-SD | local polling |
| Enphase Envoy | `enphase_envoy` | DNS-SD | local polling |
| Fronius | `fronius` | DHCP hint | local polling |
| Goal Zero Yeti | `goalzero` | DHCP hint, DHCP known | local polling |
| Greencell | `greencell` | MQTT | local push |
| Homevolt | `homevolt` | DNS-SD | local polling |
| HomeWizard | `homewizard` | DNS-SD, DHCP known | local polling |
| Imeon Inverter | `imeon_inverter` | SSDP | local polling |
| Indevolt | `indevolt` | DNS-SD, DHCP known | local polling |
| IOmeter | `iometer` | DNS-SD | local push |
| KACO RS485 | `kaco_rs485` | serial | local polling |
| Landis+Gyr Heat Meter | `landisgyr_heat_meter` | serial | local polling |
| Lektrico Charging Station | `lektrico` | DNS-SD | local polling |
| Mopeka | `mopeka` | BLE | local push |
| my-PV | `my_pv` | DNS-SD, DHCP hint, DHCP known | local polling |
| Network UPS Tools (NUT) | `nut` | DNS-SD | local polling |
| NRGkick | `nrgkick` | DNS-SD | local polling |
| OpenEVSE | `openevse` | DNS-SD | local push |
| Peblar | `peblar` | DNS-SD | local polling |
| Powerfox Cloud | `powerfox` | DNS-SD | cloud polling |
| Powerfox Local | `powerfox_local` | DNS-SD | local polling |
| Pure Energie | `pure_energie` | DNS-SD | local polling |
| Rainforest Eagle | `rainforest_eagle` | DHCP hint | local polling |
| Rainforest RAVEn | `rainforest_raven` | USB | local polling |
| Rehlko | `rehlko` | DHCP hint | cloud polling |
| Sense | `sense` | DHCP hint | cloud polling |
| Silla Prism | `silla_prism` | MQTT | local push |
| SiteSage Emonitor | `emonitor` | DHCP hint, DHCP known | local polling |
| SMA Solar | `sma` | DHCP hint, DHCP known | local polling |
| Smappee | `smappee` | DNS-SD | cloud polling |
| Sofar | `sofar` | serial | local polling |
| SolarEdge | `solaredge` | DHCP hint | cloud polling |
| SolarEdge Modbus | `solaredge_modbus` | DNS-SD, serial | local polling |
| Solarman | `solarman` | DNS-SD | local polling |
| Spin EV Charger | `exicom_spin_ble` | BLE | local polling |
| TechnoVE | `technove` | DNS-SD | local polling |
| Tesla Powerwall | `powerwall` | DHCP hint | local polling |
| Tesla Wall Connector | `tesla_wall_connector` | DHCP hint | local polling |
| Victron BLE | `victron_ble` | BLE | local push |
| Victron GX | `victron_gx` | SSDP | local push |
| WattWächter | `wattwaechter` | DNS-SD | local polling |

### Gardens and plants

| Upstream name | Integration | Signals | Interaction |
|---|---|---|---|
| FYTA | `fyta` | DHCP hint | cloud polling |
| Gardena Bluetooth | `gardena_bluetooth` | BLE | local polling |
| Husqvarna Automower BLE | `husqvarna_automower_ble` | BLE | local polling |
| Melnor Bluetooth | `melnor` | BLE | local polling |
| Rachio | `rachio` | DNS-SD, HAP model, DHCP hint | cloud push |
| RainMachine | `rainmachine` | DNS-SD, HAP model | local polling |
| Vegetronix VegeHub | `vegehub` | DNS-SD | local push |

### Health and wellbeing

| Upstream name | Integration | Signals | Interaction |
|---|---|---|---|
| EufyLife | `eufylife_ble` | BLE | local push |
| Harbor Sleep | `harbor` | DHCP hint | local push |
| IKEA Idasen Desk | `idasen_desk` | BLE | local push |
| OKOK Scale | `okok_scale` | BLE | local push |
| Oral-B | `oralb` | BLE | local push |
| SleepIQ | `sleepiq` | DHCP hint | cloud polling |
| Snooz | `snooz` | BLE | local push |
| Withings | `withings` | DHCP hint | cloud push |

### Hubs and protocols

| Upstream name | Integration | Signals | Interaction |
|---|---|---|---|
| Bosch SHC | `bosch_shc` | DNS-SD | local push |
| Control4 | `control4` | SSDP | local polling |
| deCONZ | `deconz` | SSDP | local push |
| devolo Home Control | `devolo_home_control` | DNS-SD | local push |
| EnOcean | `enocean` | USB | local push |
| FRITZ!SmartHome | `fritzbox` | SSDP | local polling |
| Home Assistant Connect ZBT-1 | `homeassistant_sky_connect` | USB | unspecified |
| Home Assistant Connect ZBT-2 | `homeassistant_connect_zbt2` | USB | unspecified |
| Homee | `homee` | DNS-SD | local push |
| HomeKit Device | `homekit_controller` | DNS-SD, BLE | local push |
| IKEA TRÅDFRI | `tradfri` | HAP model | local polling |
| iNELS | `inels` | MQTT | local push |
| Insteon | `insteon` | DHCP hint, DHCP known, USB | local push |
| Matter | `matter` | DNS-SD | local push |
| Overkiz | `overkiz` | DNS-SD, DHCP hint | local polling |
| Qbus | `qbus` | MQTT | local push |
| SmartThings | `smartthings` | DHCP hint | cloud push |
| SMLIGHT SLZB | `smlight` | DNS-SD, DHCP known | local push |
| Thread | `thread` | DNS-SD | local polling |
| Tuya | `tuya` | DHCP hint | cloud push |
| Universal Devices ISY/IoX | `isy994` | SSDP, DHCP hint, DHCP known | local push |
| Velbus | `velbus` | USB, serial | local push |
| Xiaomi Gateway (Aqara) | `xiaomi_aqara` | DNS-SD | local push |
| Xiaomi Home | `xiaomi_miio` | DNS-SD | local polling |
| Z-Wave | `zwave_js` | DNS-SD, USB | local push |
| Z-Wave.Me | `zwave_me` | DNS-SD | local push |
| Zigbee Home Automation | `zha` | DNS-SD, USB, serial | local polling |

### Lighting

| Upstream name | Integration | Signals | Interaction |
|---|---|---|---|
| AiDot | `aidot` | DHCP hint | local polling |
| Casper Glow | `casper_glow` | BLE | local polling |
| Elgato Avea | `avea` | BLE | local polling |
| Elgato Light | `elgato` | DNS-SD, DHCP known | local polling |
| Hyperion | `hyperion` | SSDP | local push |
| Kuler Sky | `kulersky` | BLE | local polling |
| LED BLE | `led_ble` | BLE | local polling |
| LIFX | `lifx` | DNS-SD, HAP model, DHCP hint, DHCP known | local polling |
| Lunatone | `lunatone` | DNS-SD | local polling |
| Lutron Caséta | `lutron_caseta` | DNS-SD, HAP model | local push |
| Magic Home | `flux_led` | DHCP hint, DHCP known | local push |
| Nanoleaf | `nanoleaf` | DNS-SD, HAP model, SSDP | local push |
| Philips Hue | `hue` | DNS-SD, HAP model | local push |
| Philips Hue BLE | `hue_ble` | BLE | local push |
| Sunricher DALI | `sunricher_dali` | DHCP known | local push |
| Twinkly | `twinkly` | DHCP hint | local polling |
| Universal Powerline Bus (UPB) | `upb` | serial | local push |
| WiZ | `wiz` | DHCP hint, DHCP known | local push |
| WLED | `wled` | DNS-SD | local push |
| Yeelight | `yeelight` | DNS-SD, HAP model, DHCP hint | local push |

### Media and entertainment

| Upstream name | Integration | Signals | Interaction |
|---|---|---|---|
| Android TV Remote | `androidtv_remote` | DNS-SD | local push |
| Apple TV | `apple_tv` | DNS-SD | local push |
| Arcam FMJ Receivers | `arcam_fmj` | SSDP | local polling |
| Bang & Olufsen | `bang_olufsen` | DNS-SD | local push |
| Bluesound | `bluesound` | DNS-SD | local polling |
| Bose SoundTouch | `soundtouch` | DNS-SD | local polling |
| Cambridge Audio | `cambridge_audio` | DNS-SD | local push |
| Denon AVR Network Receivers | `denonavr` | SSDP | local push |
| Denon HEOS | `heos` | DNS-SD, SSDP | local push |
| Denon RS-232 | `denon_rs232` | serial | local push |
| Devialet | `devialet` | DNS-SD | local polling |
| DirecTV | `directv` | SSDP | local polling |
| DLNA Digital Media Renderer | `dlna_dmr` | SSDP | local push |
| DLNA Digital Media Server | `dlna_dms` | SSDP | local polling |
| Frontier Silicon | `frontier_silicon` | SSDP | local polling |
| Google Cast | `cast` | DNS-SD | local polling |
| Harman Luxury Audio | `harman_luxury` | SSDP | local polling |
| HDFury | `hdfury` | DNS-SD | local polling |
| Hegel Amplifier | `hegel` | SSDP | local push |
| Kaleidescape | `kaleidescape` | SSDP | local push |
| Kodi | `kodi` | DNS-SD | local push |
| LG TV via Serial | `lg_tv_rs232` | serial | local polling |
| LG webOS TV | `webostv` | SSDP | local push |
| LibreSync | `libresync` | SSDP | local push |
| LinkPlay | `linkplay` | DNS-SD | local polling |
| Linn / OpenHome | `openhome` | SSDP | local polling |
| Lyngdorf | `lyngdorf` | SSDP | local push |
| Marantz RS-232 | `marantz_rs232` | serial | local push |
| Monoprice 6-Zone Amplifier | `monoprice` | serial | local polling |
| Music Assistant | `music_assistant` | DNS-SD | local push |
| MusicCast | `yamaha_musiccast` | SSDP | local push |
| Onkyo | `onkyo` | SSDP | local push |
| OwnTone | `forked_daapd` | DNS-SD | local push |
| Philips TV | `philips_js` | DNS-SD | local polling |
| PlayStation Network | `playstation_network` | DHCP hint | cloud polling |
| Plex Media Server | `plex` | DNS-SD | local push |
| Roku | `roku` | HAP model, SSDP | local polling |
| Russound RIO | `russound_rio` | DNS-SD, serial | local push |
| Samsung Smart TV | `samsungtv` | DNS-SD, SSDP, DHCP hint, DHCP known | local push |
| Samsung TV via ExLink | `samsung_exlink` | serial | local polling |
| Sonos | `sonos` | DNS-SD, SSDP | local push |
| Sony Bravia TV | `braviatv` | SSDP | local polling |
| Sony Songpal | `songpal` | SSDP | local push |
| Squeezebox (Lyrion Music Server) | `squeezebox` | DHCP hint | local polling |
| SteamVR Base Station | `steamvr_base_station` | BLE | local push |
| Tonewinner | `tonewinner` | serial | local push |
| VIZIO SmartCast | `vizio` | DNS-SD | local polling |
| Vogel's MotionMount | `motionmount` | DNS-SD | local push |
| Volumio | `volumio` | DNS-SD | local polling |
| WiiM | `wiim` | DNS-SD | local push |
| Xbox | `xbox` | SSDP, DHCP hint | cloud polling |
| Yoto | `yoto` | DHCP hint | cloud push |

### Messaging and notifications

| Upstream name | Integration | Signals | Interaction |
|---|---|---|---|
| LaMetric | `lametric` | SSDP, DHCP known | local polling |
| Obihai | `obihai` | DHCP hint | local polling |
| Phone Modem | `modem_callerid` | USB | local polling |

### Other

| Upstream name | Integration | Signals | Interaction |
|---|---|---|---|
| UniFi Discovery | `unifi_discovery` | SSDP, DHCP hint | local polling |

### Other ecosystems

| Upstream name | Integration | Signals | Interaction |
|---|---|---|---|
| HomeKit Bridge | `homekit` | DNS-SD | local push |

### Pets

| Upstream name | Integration | Signals | Interaction |
|---|---|---|---|
| EHEIM Digital | `eheimdigital` | DNS-SD | local polling |
| Whisker | `litterrobot` | DHCP hint | cloud push |

### Plugs and switches

| Upstream name | Integration | Signals | Interaction |
|---|---|---|---|
| Belkin WeMo | `wemo` | HAP model, SSDP | local push |
| BleBox devices | `blebox` | DNS-SD, DHCP hint | local polling |
| D-Link Wi-Fi Smart Plugs | `dlink` | DHCP hint | local polling |
| Deako | `deako` | DNS-SD | local polling |
| myStrom | `mystrom` | DHCP hint, DHCP known | local polling |
| PG LAB Electronics | `pglab` | MQTT | local push |
| Shelly | `shelly` | DNS-SD, BLE | local push |
| System Nexa 2 | `systemnexa2` | DNS-SD | local push |
| TP-Link Smart Home | `tplink` | DHCP hint, DHCP known | local polling |
| WiLight | `wilight` | SSDP | local polling |

### Presence and location

| Upstream name | Integration | Signals | Interaction |
|---|---|---|---|
| iBeacon Tracker | `ibeacon` | BLE | local push |
| Kiosker | `kiosker` | DNS-SD | local polling |

### Productivity and information

| Upstream name | Integration | Signals | Interaction |
|---|---|---|---|
| TRMNL | `trmnl` | DHCP hint | cloud polling |

### Security and safety

| Upstream name | Integration | Signals | Interaction |
|---|---|---|---|
| Abode | `abode` | HAP model | cloud push |
| August | `august` | DHCP hint | cloud push |
| Axis | `axis` | DNS-SD, SSDP, DHCP hint, DHCP known | local push |
| Blink | `blink` | DHCP hint | cloud polling |
| Bosch Alarm | `bosch_alarm` | DHCP hint | local push |
| DoorBird | `doorbird` | DNS-SD | local push |
| Dormakaba dKey | `dormakaba_dkey` | BLE | local polling |
| Elk-M1 Control | `elkm1` | DHCP hint, DHCP known | local push |
| Elmax | `elmax` | DNS-SD | cloud polling |
| Grandstream Home | `grandstream_home` | DNS-SD | local polling |
| Imou | `imou` | DHCP hint | cloud polling |
| ISEO Argo BLE Lock | `iseo_argo_ble` | BLE | local polling |
| LOQED Touch Smart Lock | `loqed` | DNS-SD | local push |
| Nuki Bridge | `nuki` | DHCP hint | local polling |
| ONVIF | `onvif` | DHCP known | local push |
| Reolink | `reolink` | DHCP hint, DHCP known | local push |
| Ring | `ring` | DHCP hint | cloud polling |
| SimpliSafe | `simplisafe` | DHCP hint | cloud polling |
| Verisure | `verisure` | DHCP hint | cloud polling |
| Yale Access Bluetooth | `yalexs_ble` | BLE | local push |
| Yale Home | `yale` | DHCP hint | cloud push |

### Sensors

| Upstream name | Integration | Signals | Interaction |
|---|---|---|---|
| air-Q | `airq` | DNS-SD | local polling |
| AirGradient | `airgradient` | DNS-SD | local polling |
| Airthings | `airthings` | DHCP hint | cloud polling |
| Airthings BLE | `airthings_ble` | BLE | local polling |
| Altruist | `altruist` | DNS-SD | local polling |
| Aranet | `aranet` | BLE | local push |
| Awair | `awair` | DNS-SD | local polling |
| BlueMaestro | `bluemaestro` | BLE | local push |
| BTHome | `bthome` | BLE | local push |
| Govee Bluetooth | `govee_ble` | BLE | local push |
| HAVEN IAQ | `haven_iaq` | DNS-SD | local polling |
| INKBIRD | `inkbird` | BLE | local push |
| LD2410 BLE | `ld2410_ble` | BLE | local push |
| Medcom Bluetooth | `medcom_ble` | BLE | local polling |
| Moat | `moat` | BLE | local push |
| Nettigo Air Monitor | `nam` | DNS-SD | local polling |
| Qingping | `qingping` | BLE | local push |
| Ruuvi BLE | `ruuvitag_ble` | BLE | local push |
| Ruuvi Gateway | `ruuvi_gateway` | DHCP hint | local polling |
| Sensirion BLE | `sensirion_ble` | BLE | local push |
| SensorPro | `sensorpro` | BLE | local push |
| SensorPush | `sensorpush` | BLE | local push |
| SwitchBot Bluetooth | `switchbot` | BLE | local push |
| ThermoBeacon | `thermobeacon` | BLE | local push |
| ThermoPro | `thermopro` | BLE | local push |
| Xiaomi BLE | `xiaomi_ble` | BLE | local push |

### Vehicles and transport

| Upstream name | Integration | Signals | Interaction |
|---|---|---|---|
| Specialized Turbo | `specialized_turbo` | BLE | local push |

### Water

| Upstream name | Integration | Signals | Interaction |
|---|---|---|---|
| Balboa Spa Client | `balboa` | DHCP hint, DHCP known | local push |
| DROP | `drop_connect` | MQTT | local push |
| Droplet | `droplet` | DNS-SD | local push |
| Elexa Guardian | `guardian` | DNS-SD, DHCP hint | local polling |
| Flume | `flume` | DHCP hint | cloud polling |
| Hot Spring | `hotspring` | DNS-SD | local polling |
| Jandy iAquaLink | `iaqualink` | DHCP hint | cloud polling |
| NeoPool | `neopool` | serial | local polling |
| Pentair ScreenLogic | `screenlogic` | DHCP hint, DHCP known | local push |
| SEKO PoolDose | `pooldose` | DHCP hint | local polling |
| Steamist | `steamist` | DHCP hint, DHCP known | local polling |
| TOLO Sauna | `tolo` | DHCP hint | local polling |
| Vistapool | `vistapool` | DHCP hint | cloud push |

## Local network integrations without a listed discovery matcher

An additional **304 domains** declare local push or polling and the `network` connectivity class, but appear in none of the discovery tables above. Examples in this set may need a user-supplied address, an existing controller or application-specific metadata. Treat these as a second review queue. Other local integrations use serial, fieldbus, software-only inputs, or unspecified connectivity. [Pinned manifests](https://github.com/home-assistant/core/tree/92da9f154079459b9e547126f9bd9fce726de16a/homeassistant/components)

| Category | Local network integrations |
|---|---|
| AI and voice | DOODS - Dedicated Open Object Detection Service (`doods`), llama.cpp (`llama_cpp`), MaryTTS (`marytts`), Model Context Protocol Client (`mcp`), Ollama (`ollama`) |
|  | Rhasspy (`rhasspy`) |
| Appliances and cleaning | Samsung Family Hub (`familyhub`), Thinking Cleaner (`thinkingcleaner`), Tilt Pi (`tilt_pi`) |
| Blinds and curtains | OpenGarage (`opengarage`), Rollease Acmeda Automate (`acmeda`), Soma Connect (`soma`) |
| Buttons and remotes | Flic (legacy) (`flic`) |
| Climate | Adax (`adax`), Advantage Air (`advantage_air`), AirTouch 4 (`airtouch4`), AirTouch 5 (`airtouch5`), AprilAire (`aprilaire`) |
|  | Atag (`atag`), CoolMasterNet (`coolmaster`), Danfoss Air (`danfoss_air`), ebusd (`ebusd`), Ecoforest (`ecoforest`) |
|  | eQ-3 MAX! (`maxcube`), eSterownik eCoal.pl Boiler (`ecoal_boiler`), Flexit Nordic (BACnet) (`flexit_bacnet`), Genius Hub (`geniushub`), Gree Climate (`gree`) |
|  | Hase iQ (`hase_iq`), Heatmiser (`heatmiser`), Helty Flow (`helty`), Hisense AEH-W4A1 (`hisense_aehw4a1`), KWB Easyfire (`kwb`) |
|  | Midea ccm15 AC Controller (`ccm15`), Mill (`mill`), Möhlenhoff Alpha 2 (`moehlenhoff_alpha2`), Nibe Heat Pump (`nibe_heatpump`), OpenEnergyMonitor WiFi Thermostat (`oem`) |
|  | OpenTherm Gateway (`opentherm_gw`), Ouman EH-800 (`ouman_eh_800`), Proliphix (`proliphix`), Renson (`renson`), Roth Touchline (`touchline`) |
|  | Trane Local (`trane`), Vallox (`vallox`), Venstar (`venstar`), Zehnder ComfoAir Q (`comfoconnect`), ZhongHong (`zhong_hong`) |
| Computers and networking | Actiontec (`actiontec`), AdGuard Home (`adguard`), Arris TG2492LG (`arris_tg2492lg`), Aruba (`aruba`), ASUSWRT (`asuswrt`) |
|  | Bbox (`bbox`), Datadog (`datadog`), DD-WRT (`ddwrt`), Deluge (`deluge`), Dremel 3D Printer (`dremel_3d_printer`) |
|  | FortiOS (`fortios`), Gatus (`gatus`), Glances (`glances`), Google Wifi (`google_wifi`), hddtemp (`hddtemp`) |
|  | HP Integrated Lights-Out (ILO) (`hp_ilo`), HP Printer (`hp_printer`), Iperf3 (`iperf3`), Libre Hardware Monitor (`libre_hardware_monitor`), LibreNMS (`librenms`) |
|  | MikroTik (`mikrotik`), mutesync (`mutesync`), Netdata (`netdata`), NETGEAR LTE (`netgear_lte`), NZBGet (`nzbget`) |
|  | Open Hardware Monitor (`openhardwaremonitor`), Pi-hole (`pi_hole`), Portainer (`portainer`), Proxmox VE (`proxmoxve`), pyLoad (`pyload`) |
|  | qBittorrent (`qbittorrent`), QNAP (`qnap`), RainbowMiner (`rainbowminer`), Repetier-Server (`repetier`), rTorrent (`rtorrent`) |
|  | Ruckus (`ruckus_unleashed`), SABnzbd (`sabnzbd`), Seafile (`seafile`), SFR Box (`sfr_box`), SFTP Storage (`sftp_storage`) |
|  | SNMP (`snmp`), Starlink (`starlink`), Supervisord (`supervisord`), Syncthing (`syncthing`), Synology SRM (`synology_srm`) |
|  | TP-Link Omada (`tplink_omada`), Transmission (`transmission`), UniFi Network (`unifi`), Vilfo Router (`vilfo`), Vodafone Station (`vodafone_station`) |
|  | Wake on LAN (`wake_on_lan`), Webmin (`webmin`), Zabbix (`zabbix`) |
| DIY and maker equipment | Apache Kafka (`apache_kafka`), aREST (`arest`), Global Caché GC-100 (`gc100`), Graphite (`graphite`), InfluxDB (`influxdb`) |
|  | MySensors (`mysensors`), Pencom (`pencom`), ProgettiHWSW Automation (`progettihwsw`), Raspberry Pi Remote GPIO (`remote_rpi_gpio`), RESTful (`rest`) |
|  | RESTful Command (`rest_command`), Splunk (`splunk`), SQL (`sql`), StatsD (`statsd`), TCP (`tcp`) |
|  | Telnet (`telnet`) |
| Energy | APC UPS Daemon (`apcupsd`), APsystems (`apsystems`), eGauge (`egauge`), Emoncms (`emoncms`), Emoncms History (`emoncms_history`) |
|  | ENVERTECH EVT800 (`envertech_evt800`), GoodWe Inverter (`goodwe`), GreenEye Monitor (GEM) (`greeneye_monitor`), IamMeter (`iammeter`), IoTaWatt (`iotawatt`) |
|  | iskra (`iskra`), Keba Charging Station (`keba`), Kostal Plenticore Solar Inverter (`kostal_plenticore`), P1 Monitor (`p1_monitor`), SAJ Solar Inverter (`saj`) |
|  | Solar-Log (`solarlog`), SolaX Power (`solax`), The Energy Detective TED5000 (`ted5000`), Theben Conexa Smart Meter Gateway (`theben_conexa`), V2C (`v2c`) |
|  | Volkszaehler (`volkszaehler`), YouLess (`youless`), Zeversolar (`zeversolar`) |
| Finance | Firefly III (`firefly_iii`) |
| Gardens and plants | Rain Bird (`rainbird`), Worx Landroid (`worxlandroid`), Yardian (`yardian`) |
| Health and wellbeing | Sleep as Android (`sleep_as_android`) |
| Hubs and protocols | ADS (`ads`), ChirpStack (`chirpstack`), Comelit SimpleHome (`comelit`), Duotecno (`duotecno`), EZcontrol XS1 (`xs1`) |
|  | Homematic (`homematic`), IHC Controller (`ihc`), LCN (`lcn`), LIVISI Smart Home (`livisi`), NASweb (`nasweb`) |
|  | Niko Home Control (`niko_home_control`), OpenThread Border Router (`otbr`), SwitchBee (`switchbee`) |
| Lighting | EufyHome (`eufy`), EverLights (`everlights`), Evil Genius Labs (`evil_genius_labs`), Govee lights local (`govee_light_local`), iGlo (`iglo`) |
|  | LAGUTE LW-12 (`lw12wifi`), Lutron (`lutron`), Lutron Homeworks (`homeworks`), OpenRGB (`openrgb`), Opple (`opple`) |
|  | Philips Dynalite (`dynalite`), Yeelight Sunflower (`yeelightsunflower`) |
| Media and entertainment | Android Debug Bridge (`androidtv`), Anthem A/V Receivers (`anthemav`), Apple iTunes (`itunes`), Channels (`channels`), cmus (`cmus`) |
|  | Denon Network Receivers (`denon`), Dune HD (`dunehd`), Emby (`emby`), Enigma2 (OpenWebif) (`enigma2`), Epson (`epson`) |
|  | FiveM (`fivem`), Harman Kardon AVR (`harman_kardon_avr`), HDMI-CEC (`hdmi_cec`), Jellyfin (`jellyfin`), JVC Projector (`jvc_projector`) |
|  | KEF (`kef`), LG Netcast (`lg_netcast`), LG Soundbars (`lg_soundbar`), Lidarr (`lidarr`), madVR Envy (`madvr`) |
|  | Mediaroom (`mediaroom`), Minecraft Server (`minecraft_server`), Monoprice Blackbird Matrix Switch (`blackbird`), Music Player Daemon (MPD) (`mpd`), NAD (`nad`) |
|  | Ombi (`ombi`), Panasonic Blu-Ray Player (`panasonic_bluray`), Panasonic Viera (`panasonic_viera`), Pioneer (`pioneer`), PJLink (`pjlink`) |
|  | Pterodactyl (`pterodactyl`), PulseAudio Loopback (`pulseaudio_loopback`), Radarr (`radarr`), RoonLabs music player (`roon`), Russound RNET (`russound_rnet`) |
|  | Seerr (`overseerr`), Sharp Aquos TV (`aquostv`), Sisyphus (`sisyphus`), SlimProto (Squeezebox players) (`slimproto`), Snapcast (`snapcast`) |
|  | Sonarr (`sonarr`), Sony PlayStation 4 (`ps4`), Sony Projector (`sony_projector`), Soundavo WS66i 6-Zone Amplifier (`ws66i`), Tautulli (`tautulli`) |
|  | Unitymedia Horizon HD Recorder (`horizon`), VLC media player via Telnet (`vlc_telnet`), Yamaha Network Receivers (`yamaha`), Ziggo Mediabox XL (`ziggo_mediabox_xl`) |
| Messaging and notifications | FRITZ!Box Call Monitor (`fritzbox_callmonitor`), Notifications for Android TV / Fire TV (`nfandroidtv`) |
| Plugs and switches | Anel NET-PwrCtrl (`anel_pwrctrl`), Ankuoo REC Switch (`recswitch`), Edimax (`edimax`), Hi-Link HLK-SW16 (`hlk_sw16`), Kankun (`kankun`) |
|  | KMtronic (`kmtronic`), Netio (`netio`), Orvibo (`orvibo`), P5 FutureNow (`futurenow`), QwikSwitch QSUSB (`qwikswitch`) |
|  | Refoss (`refoss`), Switcher (`switcher_kis`), Ubiquiti mFi mPort (`mfi`), zimi (`zimi`) |
| Presence and location | Aruba ClearPass (`cppm_tracker`), BT Home Hub 5 (`bt_home_hub_5`), BT Smart Hub (`bt_smarthub`), Cisco IOS (`cisco_ios`), Cisco Mobility Express (`cisco_mobility_express`) |
|  | Fing (`fing`), GPSD (`gpsd`), Linksys Smart Wi-Fi (`linksys_smart`), Locative (`locative`), Nmap Tracker (`nmap_tracker`) |
|  | OpenWrt (luci) (`luci`), OpenWrt (ubus) (`ubus`), OPNsense (`opnsense`), OwnTracks (`owntracks`), Quantum Gateway (`quantum_gateway`) |
|  | Rogers Hitron CODA (`hitron_coda`), Sky Hub (`sky_hub`), Swisscom Internet-Box (`swisscom`), Thomson (`thomson`), Tomato (`tomato`) |
|  | Traccar Server (`traccar_server`), UniFi AP (`unifi_direct`), UPC Connect Box (`upc_connect`) |
| Productivity and information | Immich (`immich`), Karakeep (`karakeep`), Mealie (`mealie`), Paperless-ngx (`paperless_ngx`) |
| Security and safety | Agent DVR (`agent_dvr`), AlarmDecoder (`alarmdecoder`), Amcrest (`amcrest`), Android IP Webcam (`android_ip_webcam`), Antifurto365 iAlarm (`ialarm`) |
|  | Concord232 (`concord232`), Egardia (`egardia`), ekey bionyx (`ekeybionyx`), Envisalink (`envisalink`), Foscam (`foscam`) |
|  | Generic Camera (`generic`), Hikvision (`hikvisioncam`), Hikvision (`hikvision`), IDTECK Proximity Reader (`idteck_prox`), Lupus Electronics LUPUSEC (`lupusec`) |
|  | MJPEG IP Camera (`mjpeg`), motionEye (`motioneye`), Ness Alarm (`ness_alarm`), NX584 (`nx584`), Push (`push`) |
|  | QVR Pro (`qvr_pro`), Risco (`risco`), Satel Integra (`satel_integra`), SIA Alarm Systems (`sia`), Tedee (`tedee`) |
|  | Ubiquiti UniFi Video (`uvc`), UniFi Access (`unifi_access`), UniFi Protect (`unifiprotect`), Vanderbilt SPC (`spc`), VIVOTEK (`vivotek`) |
|  | Xeoma (`xeoma`), Xiaomi (`xiaomi`), Yi Home Cameras (`yi`), ZoneMinder (`zoneminder`) |
| Sensors | AirVisual Pro (`airvisual_pro`), Ecowitt (`ecowitt`), VersaSense (`versasense`), Wiffi (`wiffi`) |
| Vehicles and transport | Torque (`torque`) |
| Water | AquaLogic (`aqualogic`), Watergate (`watergate`) |
| Weather alerts | WeatherFlow (`weatherflow`) |

## DNS-SD service types

Case-folded DNS-SD type keys from the pinned Home Assistant registry compared with the explicit browse list in UniBlue. The shared count measures names requested. Devices can advertise unsolicited records, use a shared type with product-specific properties, or be discovered by another method. [Upstream type table](https://github.com/home-assistant/core/blob/92da9f154079459b9e547126f9bd9fce726de16a/homeassistant/generated/zeroconf.py) · [UniBlue discovery](../internal/probe/discover.go)

### Shared by both lists

- `_airgradient._tcp`, `_airplay._tcp`, `_androidtvremote2._tcp`, `_axis-video._tcp`, `_dkapi._tcp`, `_enphase-envoy._tcp`, `_esphomelib._tcp`, `_googlecast._tcp`
- `_hap._tcp`, `_heos-audio._tcp`, `_homeconnect._tcp`, `_homewizard._tcp`, `_http._tcp`, `_https._tcp`, `_hue._tcp`, `_hwenergy._tcp`
- `_ipp._tcp`, `_ipps._tcp`, `_lifx._udp`, `_linkplay._tcp`, `_miio._udp`, `_musc._tcp`, `_nanoleafapi._tcp`, `_octoprint._tcp`
- `_philipstv_rpc._tcp`, `_plexmediasvr._tcp`, `_raop._tcp`, `_slzb-06._tcp`, `_sonos._tcp`, `_soundtouch._tcp`, `_uzg-01._tcp`, `_viziocast._tcp`
- `_volumio._tcp`, `_wled._tcp`, `_xbmc-jsonrpc-h._tcp`, `_zigbee-coordinator._tcp`, `_zwave-js-server._tcp`

### Upstream types absent from the UniBlue browse list

- `_aicu-http._tcp`, `_airport._tcp`, `_altruist._tcp`, `_amzn-alexa._tcp`, `_api._tcp`, `_api._udp`, `_appletv-v2._tcp`, `_bangolufsen._tcp`
- `_bbxsrv._tcp`, `_bond._tcp`, `_companion-link._tcp`, `_czc._tcp`, `_daap._tcp`, `_deako._tcp`, `_devialet-http._tcp`, `_droplet._tcp`
- `_dvl-deviceapi._tcp`, `_easylink._tcp`, `_ecobee._tcp`, `_elg._tcp`, `_elmax-ssl._tcp`, `_fbx-api._tcp`, `_gasleser._tcp`, `_gaspulse._tcp`
- `_hap._udp`, `_haven._tcp`, `_homekit._tcp`, `_hscp._tcp`, `_indi-allsky._tcp`, `_iometer._tcp`, `_kiosker._tcp`, `_kizbox._tcp`
- `_kizboxdev._tcp`, `_lookin._tcp`, `_lutron._tcp`, `_mass._tcp`, `_matter._tcp`, `_matterc._udp`, `_mediaremotetv._tcp`, `_meshcop._udp`
- `_mieleathome._tcp`, `_mypv._tcp`, `_nanoleafms._tcp`, `_nrgkick._tcp`, `_nut._tcp`, `_openevse._tcp`, `_owserver._tcp`, `_philipstv_s_rpc._tcp`
- `_plugwise._tcp`, `_powerhub._udp`, `_powerview-g3._tcp`, `_powerview._tcp`, `_prana._tcp`, `_printer._tcp`, `_rabbitair._udp`, `_rio._tcp`
- `_shelly._tcp`, `_sideplay._tcp`, `_sleep-proxy._udp`, `_smoip._tcp`, `_solaredge-modbus._tcp`, `_solarman._tcp`, `_ssh._tcp`, `_stream-magic._tcp`
- `_stromleser._tcp`, `_system-bridge._tcp`, `_systemnexa2._tcp`, `_tbk_vmc._tcp`, `_technove-stations._tcp`, `_touch-able._tcp`, `_tvm._tcp`, `_vege._tcp`
- `_waermeleser._tcp`, `_wasserleser._tcp`, `_wattwaechter._tcp`, `_workstation._tcp`, `_ws._tcp`, `_wyoming._tcp`, `_xzg._tcp`, `_zigate-zigbee-gateway._tcp`
- `_zigstar_gw._tcp`

### UniBlue browse names outside the upstream table

- `_adb-tls-connect._tcp`, `_adb-tls-pairing._tcp`, `_adisk._tcp`, `_afpovertcp._tcp`, `_apple-mobdev2._tcp`, `_home-assistant._tcp`, `_pdl-datastream._tcp`, `_rfb._tcp`
- `_services._dns-sd._udp`, `_smb._tcp`, `_uscan._tcp`, `_uscans._tcp`

## Service recognition supplied by Nerva

The pinned Go import list registers **161 distinct service package paths**, plus the HTTP fingerprinter package. This is an index of reusable upstream recognizers. Some packages contain multiple protocol or TLS variants, others cover proprietary software. Some need UDP or SCTP, or equipment outside UniBlue’s normal scope. Verify recognizers with representative fixtures through the UniBlue scan entry point before counting working coverage. [Pinned import list](https://github.com/praetorian-inc/nerva/blob/v1.84.6/pkg/scan/plugin_list.go) · [Upstream protocol and HTTP product catalog](https://github.com/praetorian-inc/nerva/tree/v1.84.6#supported-protocols) · [UniBlue adapter](../internal/probe/nerva.go)

**126 packages declare a TCP or TLS-over-TCP plugin type. The other 35 declare only UDP (27) or SCTP (8).** This describes upstream transport eligibility. UniBlue’s own UDP checks can cover a particular protocol independently. Application-level upgrades to TLS can also occur inside a TCP recognizer.

| Upstream plugin types | Packages | Package names |
|---|---:|---|
| TCP | 70 | `ajp`, `atg`, `bgp`, `cassandra`, `citrixica`, `codesys`, `crimsonv3`, `db2` |
|  |  | `diameter`, `dnp3`, `echo`, `ethernetip`, `firebird`, `fox`, `ftp`, `gesrtp` |
|  |  | `git`, `grpc`, `h323`, `hartip`, `iec104`, `influxdb`, `javarmi`, `jdwp` |
|  |  | `jetdirect`, `kerberos`, `linuxrpc`, `managesieve`, `melsecq`, `memcached`, `mikrotikwinbox`, `milvus` |
|  |  | `modbus`, `mongodb`, `msrpc`, `mssql`, `mysql`, `mysqlx`, `opcua`, `oracledb` |
|  |  | `pcworx`, `postgresql`, `pptp`, `proconos`, `profinet`, `qdrant`, `redissentinel`, `rsync` |
|  |  | `rtmp`, `rtsp`, `s7comm`, `sccp`, `smartinstall`, `smb`, `smpp`, `snpp` |
|  |  | `socks4`, `socks5`, `sonarqube`, `ssh`, `svn`, `sybase`, `teamviewer`, `telnet` |
|  |  | `unitronics`, `vnc`, `x11`, `xmpp`, `zabbix`, `zookeeper` |
| TCP, TLS over TCP | 46 | `activemq`, `amqp`, `clickhouse`, `cups`, `docker`, `glassfish`, `http`, `imap` |
|  |  | `ipp`, `irc`, `kafka/kafkaNew`, `kafka/kafkaOld`, `ldap`, `librechat`, `mqtt/mqtt3`, `mqtt/mqtt5` |
|  |  | `nats`, `neo4j`, `nrpe`, `oracleagile`, `oracledirectory`, `oracleebs`, `oracleem`, `oracleformsreports` |
|  |  | `oraclegoldengate`, `oraclehttp`, `oraclehyperion`, `oracleidentity`, `oracleinfra`, `oraclejdesiebel`, `oraclemft`, `oracleobiee` |
|  |  | `oracleords`, `oracleouaf`, `oracleprotocoldb`, `oraclesbc`, `oraclesoa`, `oraclespatialstudio`, `peoplesoft`, `pop3` |
|  |  | `pulsar`, `rdp`, `redis`, `smtp`, `webcenter`, `weblogic` |
| UDP | 27 | `bacnet`, `coap`, `dhcp`, `ethercat`, `gtpc`, `gtpprime`, `gtpu`, `iax2` |
|  |  | `ikev2`, `ipmi`, `ipsec`, `knxip`, `l2tp`, `lwm2m`, `megaco`, `mgcp` |
|  |  | `netbios`, `ntp`, `pfcp`, `quic`, `rdpeudp`, `smbudp`, `snmp`, `stun` |
|  |  | `tftp`, `turn`, `wireguard` |
| SCTP | 8 | `diametersctp`, `iua`, `m2pa`, `m2ua`, `m3ua`, `sgsap`, `sua`, `x2ap` |
| TCP, UDP | 6 | `dns`, `nfs`, `omronfins`, `openvpn`, `pcanywhere`, `rat` |
| TLS over TCP | 3 | `anydesk`, `sstp`, `vmware` |
| TCP, TLS over TCP, UDP | 1 | `sip` |

## Reproducing the counts

Use the Home Assistant commit linked above. Read the static assignments in `zeroconf.py` (including HOMEKIT), `ssdp.py`, `dhcp.py`, `bluetooth.py`, `mqtt.py`, and `usb.py` (including the serial selector). Collect the integration domain from each matcher, deduplicate per signal, and join to each component manifest by domain. Classify DHCP items marked `registered_devices` separately. For the second queue, filter the remaining manifests by local push or local polling and explicit network connectivity. Compare DNS-SD names case-insensitively after removing the local domain and trailing dot. Count Nerva paths beneath `pkg/plugins/services/` imported by `pkg/scan/plugin_list.go` at v1.84.6.

The IANA registry download on 25 November 2026 contained **7,336 distinct nonempty service names** after trimming and case-folding, including registrations without an assigned port. Multiple transport rows or aliases do not establish that many identifiable applications. CSV SHA-256 `79efcd64d4c5f86fdf9020f7d3fd40bd21711e11db4a45f54cd2da0ca6d89659`. [IANA registry and current downloads](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)
