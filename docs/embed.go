// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package docs embeds UniBlue's SVG brand assets so the built-in web UI can
// serve theme-aware logos directly from the compiled static binary.
package docs

import "embed"

// LogoFS contains the UniBlue SVG brand logos and favicon icon.
//
//go:embed logo-header-light.svg logo-header-dark.svg logo-light.svg
var LogoFS embed.FS
