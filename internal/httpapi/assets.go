package httpapi

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"path"
	"sort"
	"time"
)

// The page templates and every file they load ship inside the binary, so a
// deployed auth-server can never render a page against a stylesheet or
// script from another release, and nothing on disk is read per request.
//
// templates/  html/template pages (one file per page plus _partials.html).
// static/     the files those pages load, served at /assets/<version>/:
//
//	auth.css, admin.js, admin-noscript.css  Auth's own styles and script.
//	flag/                                   vendored from the Flag design
//	                                        system (ElcanoTek/flag), pinned
//	                                        by flag.lock. Never edit these:
//	                                        run scripts/flag-sync.sh sync.
//
// No page carries inline <style>, <script>, style="" or on*= handlers; the
// page CSP (see renderStatus) refuses all of them.

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// assetVersion is a content hash of the whole static tree. Asset URLs embed
// it (/assets/<version>/auth.css), so a release that changes any file changes
// every URL and the long-lived cache can never serve a stale mix.
var assetVersion = hashStatic()

// assetTypes is the closed list of file types /assets/ serves. Anything else
// in the tree is a 404 rather than a guess by content sniffing.
var assetTypes = map[string]string{
	".css":   "text/css; charset=utf-8",
	".js":    "text/javascript; charset=utf-8",
	".svg":   "image/svg+xml",
	".woff2": "font/woff2",
	".woff":  "font/woff",
	".txt":   "text/plain; charset=utf-8",
	".md":    "text/plain; charset=utf-8",
}

// immutableCache is for URLs whose bytes can never change: the version
// segment (or the brand CSS hash) changes whenever the content does.
const immutableCache = "public, max-age=31536000, immutable"

func hashStatic() string {
	var files []string
	if err := fs.WalkDir(staticFS, "static", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			files = append(files, p)
		}
		return nil
	}); err != nil {
		panic(fmt.Sprintf("walk embedded static tree: %v", err))
	}
	sort.Strings(files)
	h := sha256.New()
	for _, p := range files {
		b, err := staticFS.ReadFile(p)
		if err != nil {
			panic(fmt.Sprintf("read embedded %s: %v", p, err))
		}
		_, _ = fmt.Fprintf(h, "%s\x00%d\x00", p, len(b)) // hash.Hash writes never fail
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// assetURL is the template function {{asset "auth.css"}}. It fails the
// render (rather than emitting a dead link) when the file is not embedded.
func assetURL(name string) (string, error) {
	if !fs.ValidPath(name) {
		return "", fmt.Errorf("asset %q: invalid path", name)
	}
	if info, err := fs.Stat(staticFS, "static/"+name); err != nil || info.IsDir() {
		return "", fmt.Errorf("asset %q is not embedded", name)
	}
	return "/assets/" + assetVersion + "/" + name, nil
}

func parseTemplates() *template.Template {
	return template.Must(template.New("").Funcs(template.FuncMap{"asset": assetURL}).ParseFS(templateFS, "templates/*.html"))
}

// handleAsset serves GET/HEAD /assets/{version}/{path...} from the embedded
// static tree. A stale or unknown version is a 404 rather than today's bytes,
// so an old URL can never pin new content into a year-long cache. Directory
// listings and unknown file types are 404s.
func handleAsset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		serveImmutable(w, r, "", nil) // 405
		return
	}
	name := r.PathValue("path")
	ctype, known := assetTypes[path.Ext(name)]
	if r.PathValue("version") != assetVersion || !known || !fs.ValidPath(name) {
		http.NotFound(w, r)
		return
	}
	b, err := staticFS.ReadFile("static/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	serveImmutable(w, r, ctype, b)
}

// serveImmutable writes bytes whose URL is content-addressed. It overrides
// the middleware's no-store; every other security header stays.
func serveImmutable(w http.ResponseWriter, r *http.Request, ctype string, b []byte) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Cache-Control", immutableCache)
	w.Header().Del("Pragma")
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(b))
}

// brandCSSPath is the content-addressed URL of the client bundle's palette
// overrides ("" without a bundle or palette). The CSS is generated and
// validated once at startup by the branding package.
func brandCSSPath(css string) string {
	if css == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(css))
	return "/brand/theme-" + hex.EncodeToString(sum[:])[:16] + ".css"
}

// brandLogoVersion is the content hash pages put in the logo URL.
func brandLogoVersion(logo []byte) string {
	sum := sha256.Sum256(logo)
	return hex.EncodeToString(sum[:])[:16]
}

// brandCSSHandler serves the bundle's palette overrides as a stylesheet so
// pages need no inline <style>.
func brandCSSHandler(css string) http.HandlerFunc {
	b := []byte(css)
	return func(w http.ResponseWriter, r *http.Request) {
		serveImmutable(w, r, "text/css; charset=utf-8", b)
	}
}
