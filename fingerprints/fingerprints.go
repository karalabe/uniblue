// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package fingerprints embeds declarative fingerprint rules that map passive
// LAN/UniFi signals (banners, titles, hostnames, MAC prefixes, TLS subjects)
// to canonical NVD vendor/product identifiers.
package fingerprints

import "embed"

// BuiltinFS contains the built-in YAML fingerprint definitions shipped with UniBlue.
//
//go:embed *.yaml
var BuiltinFS embed.FS
