// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package classify

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"

	classifydata "github.com/karalabe/uniblue/classify"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/oui"
	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/unifi"
)

// AssetTier describes how much the loss or compromise of a host would matter.
type AssetTier string

const (
	// TierCrown identifies assets that control or restore other critical systems.
	TierCrown AssetTier = "crown"
	// TierHigh identifies assets with important data or shared responsibilities.
	TierHigh AssetTier = "high"
	// TierMedium identifies assets with moderate or as yet unknown impact.
	TierMedium AssetTier = "medium"
	// TierLow identifies assets with limited impact on other systems.
	TierLow AssetTier = "low"
	// TierDisposable identifies assets the owner considers expendable.
	TierDisposable AssetTier = "disposable"
)

// Valid reports whether the tier is a recognized asset value.
func (t AssetTier) Valid() bool { return config.ValidAssetTier(string(t)) }

// Consequence identifies one kind of harm the loss or compromise of a host can cause.
type Consequence string

const (
	// ConsequenceControlPlane covers control over networks and other hosts.
	ConsequenceControlPlane Consequence = "control-plane"
	// ConsequenceData covers the disclosure, alteration, or loss of stored data.
	ConsequenceData Consequence = "data"
	// ConsequenceIdentity covers credentials and access to user accounts.
	ConsequenceIdentity Consequence = "identity"
	// ConsequencePrivacy covers exposure of personal activity and surroundings.
	ConsequencePrivacy Consequence = "privacy"
	// ConsequencePhysical covers changes to equipment or the physical environment.
	ConsequencePhysical Consequence = "physical"
	// ConsequenceContinuity covers interruption of services and loss of recovery options.
	ConsequenceContinuity Consequence = "continuity"
)

// Valid reports whether the dimension is a recognized consequence.
func (c Consequence) Valid() bool { return config.ValidConsequence(string(c)) }

// AssetProfile summarizes a host's inferred or owner-declared impact tier,
// consequence dimensions, and platform ownership relations.
type AssetProfile struct {
	// Tier is the host's effective asset value.
	Tier AssetTier `json:"tier"`
	// Unclassified indicates that Tier is the fallback for an unidentified host.
	Unclassified bool `json:"unclassified,omitempty"`
	// Consequences lists the kinds of harm associated with this host.
	Consequences []Consequence `json:"consequences,omitempty"`
	// Manages identifies the hosts this device controls.
	Manages []string `json:"manages,omitempty"`
	// Hosts identifies the guests running on this device.
	Hosts []string `json:"hosts,omitempty"`
	// Override reports whether an owner declaration matched the host.
	Override bool `json:"override,omitempty"`
	// Reason explains the effective tier in plain language.
	Reason string `json:"reason,omitempty"`
}

// DeviceInfo is the existing client classification used to infer asset impact.
type DeviceInfo = Result

// assetTerms matches complete role or hostname terms, including numbered
// hosts such as pve01, without matching unrelated names such as appvendor.
func assetTerms(pattern string) *regexp.Regexp {
	return regexp.MustCompile("(?i)(^|[^a-z0-9])(" + pattern + ")[0-9]*($|[^a-z0-9])")
}

var (
	coreSwitch  = assetTerms("core|aggregation|agg|usl8a|usaggpro|usw[ _-]pro[ _-]aggregation|usw[ _-]aggregation|usxg16|usw[ _-]pro[ _-]xg[ _-]aggregation")
	hypervisor  = assetTerms("hypervisor|proxmox|pve|esxi")
	backup      = assetTerms("backups?|pbs|veeam|urbackup")
	recorder    = assetTerms("unvr|nvr|video[ _-]recorder|protect[ _-]console")
	homeHub     = assetTerms("hub|home[ _-]?assistant|node[ _-]?red|hubitat|openhab|homebridge|zigbee2mqtt|(zigbee|z[ _-]?wave|hue|lighting)[ _-]bridge|thread[ _-]border[ _-]router")
	energy      = assetTerms("energy|solar|inverter|evse|openevse|charger|wallbox|hvac|thermostat|ventilation|daikin|fronius|enphase|homewizard|comfoconnect|go[ _-]?echarger")
	vacuum      = assetTerms("vacuum|roomba|roborock|irobot|valetudo|ecovacs|dreame")
	backupPower = assetTerms("ups|sump[ _-]?pump")
)

// inferred records the impact of a recognized device role.
func inferred(tier AssetTier, reason string, dims ...Consequence) AssetProfile {
	return AssetProfile{Tier: tier, Consequences: dims, Reason: reason}
}

// unclassifiedAsset keeps unidentified hosts visible until the owner identifies them.
func unclassifiedAsset() AssetProfile {
	return AssetProfile{Tier: TierMedium, Unclassified: true, Reason: "Unclassified device (defaulting to medium until identified)"}
}

// InferDeviceAsset estimates the impact of a UniFi infrastructure device.
func InferDeviceAsset(dev unifi.Device) AssetProfile {
	kind := strings.ToLower(strings.TrimSpace(dev.Type))
	switch kind {
	case "unvr", "nvr":
		return recordingAsset()
	case "uck", "controller", "console", "cloud key":
		// UniFi also reports stand-alone Protect recorders as Cloud Keys.
		if recorder.MatchString(dev.Model) {
			return recordingAsset()
		}
		return inferred(TierCrown, "This controller manages the network configuration.", ConsequenceControlPlane, ConsequenceContinuity)
	case "udm", "udr", "udw", "ucg", "uxg", "ugw", "usg", "gateway", "router":
		return inferred(TierCrown, "The network relies on this gateway for routing and access.", ConsequenceControlPlane, ConsequenceContinuity)
	case "usw", "switch", "core switch", "core-switch", "edge switch", "edge-switch":
		if coreSwitch.MatchString(kind + " " + dev.Name + " " + dev.Model) {
			return inferred(TierCrown, "This core switch connects major parts of the network.", ConsequenceControlPlane, ConsequenceContinuity)
		}
		return inferred(TierHigh, "Devices depend on this switch for network access.", ConsequenceControlPlane, ConsequenceContinuity)
	case "uap", "ap", "access point", "access-point":
		return inferred(TierHigh, "Wireless devices depend on this access point.", ConsequenceControlPlane, ConsequenceContinuity)
	}
	return unclassifiedAsset()
}

// recordingAsset accounts for the footage a recorder retains from multiple cameras.
func recordingAsset() AssetProfile {
	return inferred(TierHigh, "This recorder stores private camera footage.", ConsequencePrivacy, ConsequenceData)
}

// InferClientAsset estimates a LAN client's impact from its classification and
// any more specific role identified by its hostname or controller display name.
func InferClientAsset(cl unifi.Client, info DeviceInfo) AssetProfile {
	evidence := cl.Hostname + " " + cl.Name
	// These taxonomy roles describe several possible products. Only a more
	// specific role or device name distinguishes a recorder or hypervisor.
	switch info.Role {
	case "Server / NAS / Hypervisor", "IP Camera / NVR", "ONVIF IP Camera / NVR":
	default:
		evidence += " " + info.Role
	}
	switch info.Category {
	case CategoryBMC:
		return inferred(TierCrown, "This management controller can operate its host's console and power.", ConsequenceControlPlane, ConsequenceContinuity)
	case CategoryNetwork, CategoryNetService:
		return inferred(TierHigh, "Other devices depend on this host for network services.", ConsequenceControlPlane, ConsequenceContinuity)
	case CategoryServer:
		// Proxmox Backup Server shares the hypervisor's brand. A specific
		// hypervisor role from a probe takes precedence over a backup hostname.
		isBackup := backup.MatchString(evidence)
		switch {
		case strings.EqualFold(info.Role, "Hypervisor") || (!isBackup && hypervisor.MatchString(evidence)):
			return inferred(TierCrown, "This host controls the virtual machines running on it.", ConsequenceData, ConsequenceContinuity, ConsequenceControlPlane)
		case isBackup:
			return inferred(TierCrown, "This server holds backups needed to recover other systems.", ConsequenceData, ConsequenceContinuity)
		default:
			return inferred(TierHigh, "This server stores data or runs services for other devices.", ConsequenceData, ConsequenceContinuity)
		}
	case CategoryVM:
		return inferred(TierMedium, "This virtual machine may hold application data.", ConsequenceData)
	case CategoryPersonal:
		return inferred(TierHigh, "A personal device can hold private files and access signed-in accounts.", ConsequenceData, ConsequenceIdentity, ConsequencePrivacy)
	case CategoryCamera:
		if recorder.MatchString(evidence) || strings.EqualFold(cl.Name, "UniFi Protect") || strings.EqualFold(info.Role, "UniFi Protect") {
			return recordingAsset()
		}
		return inferred(TierMedium, "This camera can reveal activity in its surroundings.", ConsequencePrivacy)
	case CategoryIoT:
		evidence += " " + info.Vendor
		switch {
		case homeHub.MatchString(evidence):
			return inferred(TierHigh, "This home automation hub can control devices and observe activity.", ConsequenceControlPlane, ConsequencePhysical, ConsequencePrivacy)
		case backupPower.MatchString(evidence):
			return inferred(TierMedium, "This equipment helps keep essential systems operating.", ConsequencePhysical, ConsequenceContinuity)
		case energy.MatchString(evidence):
			return inferred(TierMedium, "This device controls energy or building equipment.", ConsequencePhysical)
		case vacuum.MatchString(evidence):
			return inferred(TierLow, "This appliance moves through the home and may store a map of it.", ConsequencePhysical, ConsequencePrivacy)
		}
		return inferred(TierLow, "This device monitors or controls physical equipment.", ConsequencePhysical)
	case CategoryPrinter:
		if containsAny(strings.ToLower(evidence), "3d print", "3d-print", "prusa", "bambu", "octoprint", "klipper") {
			return inferred(TierLow, "This 3D printer operates moving and heated parts.", ConsequencePhysical)
		}
		return inferred(TierLow, "This printer handles the contents of print jobs.", ConsequenceData)
	case CategoryMedia:
		return inferred(TierLow, "This media device can reveal viewing or listening activity.", ConsequencePrivacy)
	}
	return unclassifiedAsset()
}

// Share the embedded taxonomy and the optional local IEEE vendor table across scans.
var assetClassifier = sync.OnceValue(func() *Classifier {
	db := oui.New("")
	_ = db.Load()
	c, err := Load(classifydata.BuiltinFS, db)
	if err != nil {
		panic(err)
	}
	return c
})

// ClientRoles resolves the operational role of each client, keyed like ResolveAssets.
func ClientRoles(snap *unifi.Snapshot, profiles []probe.HostProfile) map[string]Result {
	roles := make(map[string]Result)
	if snap == nil {
		return roles
	}
	assetClassifier().classifyClients(snap, profiles, func(cl unifi.Client, info Result) {
		roles[cmp.Or(config.CanonicalMAC(cl.MAC), cl.ID, cl.PrimaryIP())] = info
	})
	return roles
}

// assetIndex keeps one profile per host while allowing either selector to find it.
type assetIndex struct {
	profiles map[string]AssetProfile
	byMAC    map[string]string
	byID     map[string]string
	macOf    map[string]string
	applied  map[string]string
}

// add prefers a canonical MAC as the profile key, falling back to the ID on
// feeds that omit the hardware address. IP addresses can be shared or reassigned.
func (a *assetIndex) add(rawMAC, id string, profile AssetProfile) {
	mac, _ := config.ParseCanonicalMAC(rawMAC)
	id = strings.TrimSpace(id)
	key := cmp.Or(mac, id)
	if key == "" {
		return
	}
	a.profiles[key] = profile
	if mac != "" {
		a.byMAC[mac] = key
		a.macOf[key] = mac
	}
	if id != "" {
		a.byID[id] = key
	}
}

// ResolveAssets infers asset profiles for a scan and applies validated owner
// overrides. Each profile is keyed by canonical MAC, or by ID if it has no MAC.
// Warnings identify declarations that could not be reconciled with the scan.
func ResolveAssets(snap *unifi.Snapshot, profiles []probe.HostProfile, overrides []config.AssetOverride) (map[string]AssetProfile, []string) {
	index := assetIndex{
		profiles: make(map[string]AssetProfile),
		byMAC:    make(map[string]string),
		byID:     make(map[string]string),
		macOf:    make(map[string]string),
		applied:  make(map[string]string),
	}
	if snap != nil {
		assetClassifier().classifyClients(snap, profiles, func(cl unifi.Client, info Result) {
			index.add(cl.MAC, cl.ID, InferClientAsset(cl, info))
		})
		// If a managed device also appears on the client list, its infrastructure
		// role provides stronger evidence of impact than its LAN services.
		for _, dev := range snap.Devices {
			index.add(dev.MAC, dev.ID, InferDeviceAsset(dev))
		}
	}
	var warnings []string
	for _, override := range overrides {
		warnings = append(warnings, index.apply(override)...)
	}
	return index.profiles, warnings
}

// apply uses either identifier to find the asset, skipping the override if the
// configured MAC and ID disagree on the matched host or if an earlier override
// already matched the same device.
func (a *assetIndex) apply(o config.AssetOverride) []string {
	var warnings []string
	mac, _ := config.ParseCanonicalMAC(o.MAC)
	id := strings.TrimSpace(o.ID)
	selector := cmp.Or(mac, id)
	// These four low nibbles mark a locally administered unicast address.
	if mac != "" && strings.ContainsRune("26ae", rune(mac[1])) {
		warnings = append(warnings, fmt.Sprintf("Asset override for %s uses a randomized (locally administered) MAC address and may stop matching after a reconnect", mac))
	}
	byMAC, byID := a.byMAC[mac], a.byID[id]
	key := cmp.Or(byMAC, byID)
	switch {
	case key == "":
		warnings = append(warnings, fmt.Sprintf("Asset override for %s did not match any device or client in the current scan", selector))
	case byMAC != "" && byID != "" && byMAC != byID:
		warnings = append(warnings, fmt.Sprintf("Asset override for %s was skipped because ID %s belongs to a different device or client", mac, id))
		key = ""
	case mac != "" && byMAC == "" && byID != "" && a.macOf[byID] != "" && a.macOf[byID] != mac:
		warnings = append(warnings, fmt.Sprintf("Asset override for %s was skipped because ID %s belongs to a different device or client (%s)", mac, id, a.macOf[byID]))
		key = ""
	case a.applied[key] != "":
		warnings = append(warnings, fmt.Sprintf("Asset override for %s was skipped because the same device already matched an earlier override (%s)", selector, a.applied[key]))
		key = ""
	}
	if key == "" {
		return warnings
	}
	a.applied[key] = selector
	profile := a.profiles[key]
	if o.Manages != nil {
		profile.Manages = a.targets(key, selector, "manages", o.Manages, &warnings)
	}
	if o.Hosts != nil {
		profile.Hosts = a.targets(key, selector, "hosts", o.Hosts, &warnings)
	}
	if o.Tier != "" {
		tier := strings.ToLower(strings.TrimSpace(o.Tier))
		profile.Tier = AssetTier(tier)
		profile.Unclassified = false
		profile.Reason = fmt.Sprintf("You set the asset tier for %s to %s.", cmp.Or(o.Label, selector), tier)
	}
	if o.Consequences != nil {
		profile.Consequences = nil
		for _, raw := range o.Consequences {
			if dim := Consequence(strings.ToLower(strings.TrimSpace(raw))); !slices.Contains(profile.Consequences, dim) {
				profile.Consequences = append(profile.Consequences, dim)
			}
		}
	}
	profile.Override = true
	a.profiles[key] = profile
	return warnings
}

// targets resolves live relations to profile keys. An offline target keeps
// its declared identifier so the owner's relation survives an incomplete scan.
func (a *assetIndex) targets(ownerKey, selector, relation string, targets []string, warnings *[]string) []string {
	var result []string
	for _, target := range targets {
		target = strings.TrimSpace(target)
		key := a.byID[target]
		if mac, ok := config.ParseCanonicalMAC(target); ok {
			target = mac
			key = a.byMAC[mac]
		}
		switch {
		case key == "":
			*warnings = append(*warnings, fmt.Sprintf("Asset override for %s lists %s under %s, but that target did not match any device or client in the current scan", selector, target, relation))
		case key == ownerKey:
			*warnings = append(*warnings, fmt.Sprintf("Asset override for %s lists itself under %s, so this relation was skipped", selector, relation))
			continue
		default:
			target = key
		}
		if !slices.Contains(result, target) {
			result = append(result, target)
		}
	}
	return result
}
