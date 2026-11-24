// Package docs embeds UniBlue's SVG brand assets so the built-in web UI can
// serve theme-aware logos directly from the compiled static binary.
package docs

import "embed"

// LogoFS contains the horizontal light and dark UniBlue SVG logos.
//
//go:embed logo-horizontal-light.svg logo-horizontal-dark.svg
var LogoFS embed.FS
