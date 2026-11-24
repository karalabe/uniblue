// Package fingerprints embeds declarative fingerprint rules that map passive
// LAN/UniFi signals (banners, titles, hostnames, MAC prefixes, TLS subjects)
// to canonical NVD vendor/product identifiers.
package fingerprints

import "embed"

// BuiltinFS contains the built-in YAML fingerprint definitions shipped with UniBlue.
//
//go:embed *.yaml
var BuiltinFS embed.FS
