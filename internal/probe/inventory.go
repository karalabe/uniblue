// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/karalabe/uniblue/internal/unifi"
	"gopkg.in/yaml.v3"
)

// ChildDevice represents an enrolled downstream asset owned by a LAN bridge,
// NVR PoE switch, Zigbee/Z-Wave/Matter coordinator, lighting/shade hub, energy
// gateway, or BLE proxy whose individual hardware is not directly visible in
// UniFi's client table.
type ChildDevice struct {
	// ID is a stable identifier scoped beneath the parent bridge/recorder.
	ID string `json:"id" yaml:"id"`

	// Name is an optional human-readable label supplied by the parent inventory.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`

	// ParentIP links this child to the LAN IP of its owning bridge/NVR.
	ParentIP string `json:"parent_ip,omitempty" yaml:"parent_ip,omitempty"`

	// ParentMAC links this child to the normalized MAC of its owning bridge/NVR.
	ParentMAC string `json:"parent_mac,omitempty" yaml:"parent_mac,omitempty"`

	// ParentRole describes the parent gateway kind ("nvr", "zigbee-coordinator",
	// "zwave-controller", "matter-fabric", "lutron-bridge", "powerview-hub",
	// "energy-gateway", "ble-proxy").
	ParentRole string `json:"parent_role,omitempty" yaml:"parent_role,omitempty"`

	// Category classifies the child ("camera", "iot", "lighting", "lock",
	// "sensor", "energy", "shade", "media", etc.).
	Category string `json:"category,omitempty" yaml:"category,omitempty"`

	// Role is a concise functional label (e.g., "PoE Security Camera", "Zigbee Motion Sensor").
	Role string `json:"role,omitempty" yaml:"role,omitempty"`

	// Vendor is the hardware manufacturer reported by the parent inventory.
	Vendor string `json:"vendor,omitempty" yaml:"vendor,omitempty"`

	// Model is the exact model identifier reported by the parent inventory.
	Model string `json:"model,omitempty" yaml:"model,omitempty"`

	// Firmware is the software/firmware version reported by the parent inventory.
	Firmware string `json:"firmware,omitempty" yaml:"firmware,omitempty"`

	// IdentitySource records which authoritative inventory supplied this record
	// (e.g., "recorder-inventory", "zigbee2mqtt", "zwave-js", "matter-fabric", "ble-proxy").
	IdentitySource string `json:"identity_source" yaml:"identity_source"`

	// DirectLANReachability explicitly tracks whether the reporting LAN can
	// directly reach this child ("unknown", "non-ip-radio", "routed").
	// Cameras behind an NVR's private PoE switch default to "unknown" so UniBlue
	// never claims direct LAN exposure without corroborating path evidence.
	DirectLANReachability string `json:"direct_lan_reachability" yaml:"direct_lan_reachability"`

	// PrivateAddress optionally records an internal/private address (e.g. NVR PoE
	// subnet IP or IEEE radio address) for operator cross-reference.
	PrivateAddress string `json:"private_address,omitempty" yaml:"private_address,omitempty"`

	// ObservedFrom names the observer network or radio reception zone.
	ObservedFrom string `json:"observed_from,omitempty" yaml:"observed_from,omitempty"`

	// LastSeen records when the parent bridge last heard from this child.
	LastSeen *time.Time `json:"last_seen,omitempty" yaml:"last_seen,omitempty"`

	// InterviewComplete reports whether protocol discovery/interview finished
	// (nil when not applicable).
	InterviewComplete *bool `json:"interview_complete,omitempty" yaml:"interview_complete,omitempty"`

	// Sleeping reports whether this child is a battery/sleepy endpoint that must
	// not be actively probed.
	Sleeping bool `json:"sleeping,omitempty" yaml:"sleeping,omitempty"`

	// Capabilities lists allowlisted role capabilities (e.g., "video", "ptz", "lock", "dimmer").
	Capabilities []string `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`
}

// BridgeInventorySpec describes an owner-provided read-only inventory file for
// a bridge, NVR, coordinator, or BLE proxy.
type BridgeInventorySpec struct {
	Format       string `json:"format" yaml:"format"` // "generic" | "nvr" | "zigbee2mqtt" | "zwave-js" | "matter" | "ble" | "energy"
	Path         string `json:"path" yaml:"path"`
	ParentIP     string `json:"parent_ip,omitempty" yaml:"parent_ip,omitempty"`
	ParentMAC    string `json:"parent_mac,omitempty" yaml:"parent_mac,omitempty"`
	ParentRole   string `json:"parent_role,omitempty" yaml:"parent_role,omitempty"`
	ObservedFrom string `json:"observed_from,omitempty" yaml:"observed_from,omitempty"`
}

// LoadBridgeInventory reads and normalizes an owner-provided bridge/NVR/coordinator
// inventory file into ChildDevice records without sending any network packets.
func LoadBridgeInventory(spec BridgeInventorySpec) ([]ChildDevice, error) {
	raw, err := os.ReadFile(spec.Path)
	if err != nil {
		return nil, fmt.Errorf("read bridge inventory %q: %w", spec.Path, err)
	}
	return ParseBridgeInventory(raw, spec)
}

// ParseBridgeInventory parses raw JSON or YAML bridge/NVR/coordinator export bytes
// into normalized ChildDevice records.
func ParseBridgeInventory(raw []byte, spec BridgeInventorySpec) ([]ChildDevice, error) {
	format := strings.ToLower(strings.TrimSpace(spec.Format))
	switch format {
	case "", "generic", "nvr", "matter", "ble", "energy", "bridge":
		return parseGenericBridgeInventory(raw, spec, format)
	case "zigbee2mqtt":
		return parseZigbee2MQTTInventory(raw, spec)
	case "zwave-js", "zwave_js":
		return parseZWaveJSInventory(raw, spec)
	default:
		return nil, fmt.Errorf("unsupported bridge inventory format %q", spec.Format)
	}
}

func parseGenericBridgeInventory(raw []byte, spec BridgeInventorySpec, format string) ([]ChildDevice, error) {
	var wrapper struct {
		ParentIP     string        `json:"parent_ip" yaml:"parent_ip"`
		ParentMAC    string        `json:"parent_mac" yaml:"parent_mac"`
		ParentRole   string        `json:"parent_role" yaml:"parent_role"`
		ObservedFrom string        `json:"observed_from" yaml:"observed_from"`
		Devices      []ChildDevice `json:"devices" yaml:"devices"`
		Children     []ChildDevice `json:"children" yaml:"children"`
	}
	var list []ChildDevice
	if err := yaml.Unmarshal(raw, &wrapper); err == nil && (len(wrapper.Devices) > 0 || len(wrapper.Children) > 0) {
		list = append(wrapper.Devices, wrapper.Children...)
	} else if err := yaml.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("parse %s bridge inventory: %w", format, err)
	}

	parentIP := firstNonEmpty(spec.ParentIP, wrapper.ParentIP)
	parentMAC := strings.ToLower(strings.TrimSpace(firstNonEmpty(spec.ParentMAC, wrapper.ParentMAC)))
	parentRole := firstNonEmpty(spec.ParentRole, wrapper.ParentRole)
	if parentRole == "" {
		switch format {
		case "nvr":
			parentRole = "nvr"
		case "matter":
			parentRole = "matter-fabric"
		case "ble":
			parentRole = "ble-proxy"
		case "energy":
			parentRole = "energy-gateway"
		default:
			parentRole = "bridge"
		}
	}
	source := "bridge-inventory"
	switch format {
	case "nvr":
		source = "recorder-inventory"
	case "matter":
		source = "matter-fabric"
	case "ble":
		source = "ble-proxy"
	case "energy":
		source = "energy-gateway"
	}

	out := make([]ChildDevice, 0, len(list))
	seenIDs := make(map[string]struct{}, len(list))
	for i, c := range list {
		c.ParentIP = firstNonEmpty(c.ParentIP, parentIP)
		c.ParentMAC = strings.ToLower(strings.TrimSpace(firstNonEmpty(c.ParentMAC, parentMAC)))
		c.ParentRole = firstNonEmpty(c.ParentRole, parentRole)
		c.IdentitySource = firstNonEmpty(c.IdentitySource, source)
		c.ObservedFrom = firstNonEmpty(c.ObservedFrom, spec.ObservedFrom, wrapper.ObservedFrom)
		if strings.TrimSpace(c.ID) == "" {
			basis := firstNonEmpty(c.PrivateAddress, c.Name, c.Model)
			slug := sanitizeChildIDSlug(basis)
			var candidate string
			if basis == "" || slug == "unknown" {
				candidate = fmt.Sprintf("%s:item-%d", c.IdentitySource, i+1)
			} else {
				candidate = fmt.Sprintf("%s:%s", c.IdentitySource, slug)
			}
			c.ID = uniqueChildID(candidate, i+1, seenIDs)
		} else {
			seenIDs[c.ID] = struct{}{}
		}
		if c.DirectLANReachability == "" {
			if format == "ble" {
				c.DirectLANReachability = "non-ip-radio"
			} else {
				// Private PoE cameras and bridged accessories default to "unknown"
				// until a direct LAN path is independently evidenced.
				c.DirectLANReachability = "unknown"
			}
		}
		if c.Category == "" && format == "nvr" {
			c.Category = "camera"
		}
		if c.Role == "" && format == "nvr" {
			c.Role = "Recorder-Managed Camera"
		}
		out = append(out, c)
	}
	return out, nil
}

func uniqueChildID(base string, itemNum int, seen map[string]struct{}) string {
	if _, dup := seen[base]; !dup {
		seen[base] = struct{}{}
		return base
	}
	candidate := fmt.Sprintf("%s-%d", base, itemNum)
	for suffix := 2; ; suffix++ {
		if _, dup := seen[candidate]; !dup {
			seen[candidate] = struct{}{}
			return candidate
		}
		candidate = fmt.Sprintf("%s-%d-%d", base, itemNum, suffix)
	}
}

// parseZigbee2MQTTInventory parses a standard Zigbee2MQTT `bridge/devices` JSON array.
func parseZigbee2MQTTInventory(raw []byte, spec BridgeInventorySpec) ([]ChildDevice, error) {
	var rawNodes []struct {
		IEEEAddress        string `json:"ieee_address"`
		Type               string `json:"type"`
		FriendlyName       string `json:"friendly_name"`
		Manufacturer       string `json:"manufacturer"`
		ModelID            string `json:"model_id"`
		SoftwareBuildID    string `json:"software_build_id"`
		PowerSource        string `json:"power_source"`
		InterviewCompleted bool   `json:"interview_completed"`
		Definition         *struct {
			Model       string `json:"model"`
			Vendor      string `json:"vendor"`
			Description string `json:"description"`
		} `json:"definition"`
	}
	if err := json.Unmarshal(raw, &rawNodes); err != nil {
		return nil, fmt.Errorf("parse zigbee2mqtt inventory: %w", err)
	}
	var out []ChildDevice
	seenIDs := make(map[string]struct{}, len(rawNodes))
	for i, n := range rawNodes {
		if strings.EqualFold(n.Type, "Coordinator") {
			continue
		}
		vendor := n.Manufacturer
		model := n.ModelID
		role := "Zigbee Device"
		if n.Definition != nil {
			vendor = firstNonEmpty(n.Definition.Vendor, vendor)
			model = firstNonEmpty(n.Definition.Model, model)
			if n.Definition.Description != "" {
				role = n.Definition.Description
			}
		}
		iv := n.InterviewCompleted
		sleeping := strings.EqualFold(n.PowerSource, "Battery") || strings.EqualFold(n.Type, "EndDevice")
		id := firstNonEmpty(n.IEEEAddress, n.FriendlyName)
		if id == "" {
			id = fmt.Sprintf("zigbee2mqtt:item-%d", i+1)
		}
		id = uniqueChildID(id, i+1, seenIDs)
		out = append(out, ChildDevice{
			ID:                    id,
			Name:                  firstNonEmpty(n.FriendlyName, model, n.IEEEAddress),
			ParentIP:              spec.ParentIP,
			ParentMAC:             strings.ToLower(strings.TrimSpace(spec.ParentMAC)),
			ParentRole:            firstNonEmpty(spec.ParentRole, "zigbee-coordinator"),
			Category:              "iot",
			Role:                  role,
			Vendor:                vendor,
			Model:                 model,
			Firmware:              n.SoftwareBuildID,
			IdentitySource:        "zigbee2mqtt",
			DirectLANReachability: "non-ip-radio",
			PrivateAddress:        n.IEEEAddress,
			ObservedFrom:          spec.ObservedFrom,
			InterviewComplete:     &iv,
			Sleeping:              sleeping,
		})
	}
	return out, nil
}

// parseZWaveJSInventory parses a Z-Wave JS controller nodes JSON export.
func parseZWaveJSInventory(raw []byte, spec BridgeInventorySpec) ([]ChildDevice, error) {
	var rawNodes []struct {
		NodeID          int    `json:"nodeId"`
		Name            string `json:"name"`
		Ready           bool   `json:"ready"`
		IsListening     bool   `json:"isListening"`
		FirmwareVersion string `json:"firmwareVersion"`
		DeviceConfig    *struct {
			Manufacturer string `json:"manufacturer"`
			Label        string `json:"label"`
			Description  string `json:"description"`
		} `json:"deviceConfig"`
	}
	if err := json.Unmarshal(raw, &rawNodes); err != nil {
		return nil, fmt.Errorf("parse zwave-js inventory: %w", err)
	}
	var out []ChildDevice
	for _, n := range rawNodes {
		if n.NodeID <= 1 {
			continue // controller node itself
		}
		var vendor, model, role string
		if n.DeviceConfig != nil {
			vendor = n.DeviceConfig.Manufacturer
			model = n.DeviceConfig.Label
			role = n.DeviceConfig.Description
		}
		iv := n.Ready
		out = append(out, ChildDevice{
			ID:                    fmt.Sprintf("zwave-%d", n.NodeID),
			Name:                  firstNonEmpty(n.Name, model, fmt.Sprintf("Z-Wave Node %d", n.NodeID)),
			ParentIP:              spec.ParentIP,
			ParentMAC:             strings.ToLower(strings.TrimSpace(spec.ParentMAC)),
			ParentRole:            firstNonEmpty(spec.ParentRole, "zwave-controller"),
			Category:              "iot",
			Role:                  firstNonEmpty(role, "Z-Wave Device"),
			Vendor:                vendor,
			Model:                 model,
			Firmware:              n.FirmwareVersion,
			IdentitySource:        "zwave-js",
			DirectLANReachability: "non-ip-radio",
			ObservedFrom:          spec.ObservedFrom,
			InterviewComplete:     &iv,
			Sleeping:              !n.IsListening,
		})
	}
	return out, nil
}

// AttachBridgeChildren merges normalized child devices onto their matching
// parent HostProfiles (by ParentMAC or any IPv4/IPv6 ParentIP) without mutating
// unrelated hosts.
func AttachBridgeChildren(profiles []HostProfile, children []ChildDevice) {
	if len(profiles) == 0 || len(children) == 0 {
		return
	}
	byMAC := make(map[string]int, len(profiles))
	byIP := make(map[string]int, len(profiles)*2)
	for i, hp := range profiles {
		if m := strings.ToLower(strings.TrimSpace(hp.Client.MAC)); m != "" {
			byMAC[m] = i
		}
		for _, ip := range hp.Client.AllIPs() {
			if k := canonicalIPKey(ip); k != "" {
				byIP[k] = i
			}
		}
	}
	for _, ch := range children {
		idx := -1
		if m := strings.ToLower(strings.TrimSpace(ch.ParentMAC)); m != "" {
			// When ParentMAC is explicitly supplied, require a MAC match so DHCP
			// lease reuse on ParentIP can never attach children to the wrong device.
			if i, ok := byMAC[m]; ok {
				idx = i
			}
		} else if ch.ParentIP != "" {
			if i, ok := byIP[canonicalIPKey(ch.ParentIP)]; ok {
				idx = i
			}
		}
		if idx < 0 {
			continue
		}
		// Deduplicate by child ID.
		dup := false
		for _, existing := range profiles[idx].Children {
			if existing.ID == ch.ID {
				dup = true
				break
			}
		}
		if !dup {
			profiles[idx].Children = append(profiles[idx].Children, ch)
		}
	}
	for i := range profiles {
		sort.Slice(profiles[i].Children, func(a, b int) bool {
			return profiles[i].Children[a].ID < profiles[i].Children[b].ID
		})
	}
}

// MatchDeviceBridgeChildren matches bridge/NVR child devices whose parent is a
// UniFi infrastructure device (e.g., a UDM Pro or UNVR running UniFi Protect)
// rather than a regular client HostProfile, returning children keyed by
// normalized lowercase UniFi device MAC.
func MatchDeviceBridgeChildren(devices []unifi.Device, children []ChildDevice) map[string][]ChildDevice {
	if len(devices) == 0 || len(children) == 0 {
		return nil
	}
	byMAC := make(map[string]string, len(devices))
	byIP := make(map[string]string, len(devices))
	for _, d := range devices {
		m := strings.ToLower(strings.TrimSpace(d.MAC))
		if m == "" {
			continue
		}
		byMAC[m] = m
		if k := canonicalIPKey(d.IP); k != "" {
			byIP[k] = m
		}
	}
	out := make(map[string][]ChildDevice)
	for _, ch := range children {
		devMAC := ""
		if m := strings.ToLower(strings.TrimSpace(ch.ParentMAC)); m != "" {
			devMAC = byMAC[m]
		} else if ch.ParentIP != "" {
			devMAC = byIP[canonicalIPKey(ch.ParentIP)]
		}
		if devMAC == "" {
			continue
		}
		dup := false
		for _, ex := range out[devMAC] {
			if ex.ID == ch.ID {
				dup = true
				break
			}
		}
		if !dup {
			out[devMAC] = append(out[devMAC], ch)
		}
	}
	for m := range out {
		sort.Slice(out[m], func(a, b int) bool {
			return out[m][a].ID < out[m][b].ID
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

func sanitizeChildIDSlug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == ':' {
			b.WriteRune(r)
		} else if r == ' ' || r == '/' || r == '.' {
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}
