// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package rules embeds declarative exposure classification rules used by
// UniBlue's risk engine to distinguish expected WAN listeners (e.g., WireGuard,
// Ethereum DevP2P/LibP2P) from risky public web proxies or dangerous admin/RPC
// ports (e.g., Ethereum JSON-RPC, databases, VNC, RDP).
package rules

import "embed"

// BuiltinFS contains the built-in YAML exposure classification rules shipped
// with UniBlue.
//
//go:embed *.yaml
var BuiltinFS embed.FS
