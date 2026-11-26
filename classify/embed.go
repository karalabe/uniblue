// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package classifydata embeds UniBlue's device taxonomy and protocol traits.
package classifydata

import "embed"

// BuiltinFS contains the device taxonomy and the protocol trait catalog.
//
//go:embed *.yaml
var BuiltinFS embed.FS
