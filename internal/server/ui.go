package server

import _ "embed"

// dashboardHTML is the self-contained, zero-dependency live web dashboard
// served at GET / by `uniblue serve`. It adapts automatically to light and dark
// OS color schemes and updates in real time via Server-Sent Events (/api/events).
//
//go:embed index.html
var dashboardHTML []byte
