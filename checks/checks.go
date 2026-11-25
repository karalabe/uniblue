// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package checks embeds the built-in declarative security checks shipped with
// UniBlue so the binary works out of the box without requiring external files.
package checks

import "embed"

// BuiltinFS contains all built-in YAML check definitions grouped under generic/
// and community/.
//
//go:embed generic community
var BuiltinFS embed.FS
