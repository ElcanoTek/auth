package httpapi

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// Nebula Sans is the Elcano "flag" design-system UI font — the ONE brand face
// for UI, body and headings across every product (see flag/design-system/
// fonts/fonts.css). It replaced Dubai, which was proprietary (© 2017 Dubai
// Executive Council, distributed by Monotype) and could not legally ship in a
// repo; Nebula Sans is SIL OFL 1.1, so the binary is now redistributable.
//
// We embed only the two weights this surface actually renders — 400 for body
// copy and 700 for the headings/labels/button — deliberately skipping flag's
// 500/600 and the true italics. Nothing on the login or "check your inbox"
// page uses them, and this is a lean single-page service where every embedded
// byte ships in the binary. Flag's second face (Hack, for code/monospace) is
// likewise not embedded: neither page renders a single monospace glyph, so
// shipping ~215 KB of it would be dead weight. Add a face here only when a
// page actually renders it.
//
// Self-hosted from the binary rather than Google Fonts / a CDN: external font
// dependencies are forbidden for core UI, and a self-contained binary is the
// whole deploy model here. The files are served at /fonts/ and referenced by
// the @font-face rules in templates.go.
//
// OFL.txt rides along — the licence requires the licence text to travel with
// the font binaries, so it is embedded and served at /fonts/OFL.txt too.
//
//go:embed fonts/NebulaSans-400.woff2 fonts/NebulaSans-700.woff2 fonts/OFL.txt
var fontFS embed.FS

// fontHandler serves the embedded font files at /fonts/<name>. The filenames
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
		// Pre-set the type: http.ServeContent only fills Content-Type when
		// unset, and woff2 isn't reliably in the stdlib mime table. Anything
		// else here is the licence text, which the stdlib sniffs correctly.
		if strings.HasSuffix(r.URL.Path, ".woff2") {
			w.Header().Set("Content-Type", "font/woff2")
		}
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		fileServer.ServeHTTP(w, r)
	}))
}
