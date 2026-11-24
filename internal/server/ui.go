// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package server

import _ "embed"

// dashboardHTML is the self-contained, zero-dependency live web dashboard
// served at GET / by `uniblue serve`. It adapts automatically to light and dark
// OS color schemes and updates in real time via Server-Sent Events (/api/events).
//
//go:embed index.html
var dashboardHTML []byte
