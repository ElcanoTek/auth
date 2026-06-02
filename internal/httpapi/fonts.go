package httpapi

import (
	"embed"
	"io/fs"
	"net/http"
)

// Dubai is the Elcano "flag" design-system UI font (regular 400 + bold 700).
// We self-host the woff2 from the binary rather than pulling Google Fonts /
// a CDN — AGENT_GUIDE forbids external font dependencies for core UI, and a
// self-contained binary is the whole deploy model here. The files are served
// at /fonts/ and referenced by the @font-face rules in templates.go.
//
//go:embed fonts/DubaiW23-Regular.woff2 fonts/DubaiW23-Bold.woff2
var fontFS embed.FS

// fontHandler serves the embedded woff2 files at /fonts/<name>. The filenames
// are version-pinned and the bytes never change, so we cache them hard.
func fontHandler() http.Handler {
	sub, err := fs.Sub(fontFS, "fonts")
	if err != nil {
		// The embed path is a compile-time constant — this can't fail at
		// runtime — but fail loudly rather than serve a broken /fonts/.
		panic(err)
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.StripPrefix("/fonts/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Pre-set both headers: http.ServeContent only fills Content-Type
		// when unset, and woff2 isn't reliably in the stdlib mime table.
		w.Header().Set("Content-Type", "font/woff2")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		fileServer.ServeHTTP(w, r)
	}))
}
