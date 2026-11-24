// Package classifydata embeds UniBlue's built-in declarative device-taxonomy
// YAML rules directly into the compiled binary.
package classifydata

import "embed"

// BuiltinFS contains all embedded device classification rules.
//
//go:embed *.yaml
var BuiltinFS embed.FS
