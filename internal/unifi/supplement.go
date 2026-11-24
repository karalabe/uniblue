// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package unifi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// SiteSupplement captures optional owner-provided telemetry that the UniFi
// controller API does not expose directly (switch ACL tables, active dynamic
// NAT mappings, reverse proxy routes, outbound tunnels, and backup status).
type SiteSupplement struct {
	SwitchACLs        []SwitchACL          `json:"switch_acls,omitempty" yaml:"switch_acls,omitempty"`
	SwitchACLCoverage *SwitchACLCoverage   `json:"switch_acl_coverage,omitempty" yaml:"switch_acl_coverage,omitempty"`
	DynamicMappings   []DynamicPortMapping `json:"dynamic_mappings,omitempty" yaml:"dynamic_mappings,omitempty"`
	PublishedTunnels  []PublishedTunnel    `json:"published_tunnels,omitempty" yaml:"published_tunnels,omitempty"`
	ProxyRoutes       []ProxyRoute         `json:"proxy_routes,omitempty" yaml:"proxy_routes,omitempty"`
	BackupStatus      *BackupStatus        `json:"backup_status,omitempty" yaml:"backup_status,omitempty"`
}

// ApplySiteSupplement reads an optional owner-provided YAML/JSON supplement
// file and merges its telemetry into snap. Missing or unreadable files return
// an error AND record the failure in snap.Visibility.MissingFeeds so operators
// never receive silent empty results.
func ApplySiteSupplement(snap *Snapshot, path string) error {
	if snap == nil || strings.TrimSpace(path) == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		recordMissingFeed(snap, fmt.Sprintf("site-supplement (%s: %v)", path, err))
		return fmt.Errorf("read site supplement %q: %w", path, err)
	}
	var sup SiteSupplement
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		if err := json.Unmarshal(trimmed, &sup); err != nil {
			recordMissingFeed(snap, fmt.Sprintf("site-supplement (%s: parse error)", path))
			return fmt.Errorf("parse site supplement %q: %w", path, err)
		}
	} else if err := yaml.Unmarshal(raw, &sup); err != nil {
		recordMissingFeed(snap, fmt.Sprintf("site-supplement (%s: parse error)", path))
		return fmt.Errorf("parse site supplement %q: %w", path, err)
	}
	if len(sup.SwitchACLs) > 0 {
		snap.SwitchACLs = append([]SwitchACL(nil), sup.SwitchACLs...)
	}
	if sup.SwitchACLCoverage != nil {
		cp := *sup.SwitchACLCoverage
		snap.SwitchACLCoverage = &cp
	} else if len(sup.SwitchACLs) > 0 {
		snap.SwitchACLCoverage = &SwitchACLCoverage{Status: "complete"}
	}
	if snap.SwitchACLCoverage != nil && strings.EqualFold(snap.SwitchACLCoverage.Status, "complete") {
		if snap.Visibility != nil {
			snap.Visibility.SwitchACLsAvailable = true
			filtered := snap.Visibility.MissingFeeds[:0]
			for _, f := range snap.Visibility.MissingFeeds {
				if !strings.HasPrefix(strings.ToLower(f), "switch-acls") {
					filtered = append(filtered, f)
				}
			}
			snap.Visibility.MissingFeeds = filtered
		}
	}
	if len(sup.DynamicMappings) > 0 {
		snap.DynamicMappings = append([]DynamicPortMapping(nil), sup.DynamicMappings...)
	}
	if len(sup.PublishedTunnels) > 0 {
		snap.PublishedTunnels = append([]PublishedTunnel(nil), sup.PublishedTunnels...)
	}
	if len(sup.ProxyRoutes) > 0 {
		snap.ProxyRoutes = append([]ProxyRoute(nil), sup.ProxyRoutes...)
	}
	if sup.BackupStatus != nil {
		cp := *sup.BackupStatus
		snap.BackupStatus = &cp
	}
	return nil
}

// RecordMissingFeed appends a human-readable unavailable telemetry note to
// snap.Visibility.MissingFeeds (deduplicated).
func RecordMissingFeed(snap *Snapshot, feed string) {
	recordMissingFeed(snap, feed)
}

func recordMissingFeed(snap *Snapshot, feed string) {
	if snap == nil || strings.TrimSpace(feed) == "" {
		return
	}
	if snap.Visibility == nil {
		snap.Visibility = &SiteVisibility{}
	}
	for _, existing := range snap.Visibility.MissingFeeds {
		if existing == feed {
			return
		}
	}
	snap.Visibility.MissingFeeds = append(snap.Visibility.MissingFeeds, feed)
}
