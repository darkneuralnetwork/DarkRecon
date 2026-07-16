// Package ui embeds the Dark-Recon web UI (HTML templates + static assets)
// so the compiled binary is self-contained and needs no external file
// directories at runtime. On-disk paths (used during development) are still
// preferred by the API layer when present; these embedded assets are the
// fallback for the installed/packaged binary.
package ui

import (
	"embed"
	"io/fs"
)

// embedded holds the templates/ and static/ directories relative to this
// source file. Go's //go:embed directive is path-relative and does not allow
// "..", which is why this file lives inside dark_recon/ui/.
//
//go:embed templates static
var embedded embed.FS

// TemplatesFS returns the embedded HTML templates as an fs.FS rooted at the
// templates directory (e.g. ReadFile("dashboard.html")).
func TemplatesFS() fs.FS {
	sub, err := fs.Sub(embedded, "templates")
	if err != nil { // cannot fail: "templates" is a valid embedded subdir
		panic(err)
	}
	return sub
}

// StaticFS returns the embedded static assets as an fs.FS rooted at the
// static directory (e.g. ReadFile("app.js")).
func StaticFS() fs.FS {
	sub, err := fs.Sub(embedded, "static")
	if err != nil {
		panic(err)
	}
	return sub
}

// ReadTemplate returns the bytes of a template file by name (e.g.
// "dashboard.html"). Used by the API layer's embedded-template handler.
func ReadTemplate(name string) ([]byte, error) {
	return embedded.ReadFile("templates/" + name)
}
