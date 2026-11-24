// Package checks embeds the built-in declarative security checks shipped with
// UniBlue so the binary works out of the box without requiring external files.
package checks

import "embed"

// BuiltinFS contains all built-in YAML check definitions grouped under generic/
// and community/.
//
//go:embed generic/*.yaml community/*.yaml
var BuiltinFS embed.FS
