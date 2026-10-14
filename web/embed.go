// Package web holds the embedded frontend: templates, stylesheet, fonts and
// the compiled TypeScript.
package web

import "embed"

// FS contains templates/ and static/.
//
//go:embed templates static
var FS embed.FS
