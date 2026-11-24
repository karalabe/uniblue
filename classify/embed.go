// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package classifydata embeds UniBlue's built-in declarative device-taxonomy
// YAML rules directly into the compiled binary.
package classifydata

import "embed"

// BuiltinFS contains all embedded device classification rules.
//
//go:embed *.yaml
var BuiltinFS embed.FS
