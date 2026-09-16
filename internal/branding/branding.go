// Package branding reads the client bundle's `branding:` block so an Auth
// deployment wears the client's name, mark and colours instead of Elcano's.
//
// The bundle is the same repository Fleet consumes (FLEET_CLIENT_CONFIG_DIR):
// one edit to manifest.yaml re-brands both services. Auth reads ONLY the
// branding block and ignores every other key, so Fleet's schema may grow
// without ever breaking Auth. Fields Auth has no surface for (share card,
// navigation-rail tokens) are ignored too.
//
// Everything that reaches a page is validated here first: colour values must
// match a small grammar before they are turned into CSS declarations (the
// page's <style> is nonce-blessed, so raw YAML must never flow into it), and
// the logo path must stay inside the bundle after symlink resolution.
package branding

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"
)

// Brand is the loaded, validated result. A nil *Brand means "no bundle":
// callers fall back to their built-in defaults.
type Brand struct {
	Dir string
	// AppName is the wordmark: the small caps line above each card and the
	// tab title. Prose keeps AUTH_BRAND_NAME (Omnicom writes "OMNICOM" as a
	// wordmark and "Omnicom" in sentences; Fleet makes the same split).
	AppName      string
	LoginTitle   string
	LoginTagline string
	// LogoPath is the absolute, containment-checked path of the mark, or ""
	// when the bundle declares none; Logo holds its bytes as read at load.
	// Serving the snapshot rather than re-reading the path means a later
	// bundle pull cannot swap in a symlink to something the service can
	// read; a re-theme is a restart away, like every other setting.
	LogoPath        string
	LogoContentType string
	Logo            []byte
	// CSS is the generated override block (":root{...}" and the light-mode
	// selector), or "" when the bundle sets no colours.
	CSS string
}

const (
	// MaxLogoBytes bounds the mark both at load and at serve time.
	MaxLogoBytes     = 512 * 1024
	maxManifestBytes = 1 << 20
)

type manifest struct {
	Branding struct {
		AppName      string `yaml:"app_name"`
		LoginTitle   string `yaml:"login_title"`
		LoginTagline string `yaml:"login_tagline"`
		Logo         string `yaml:"logo"`
		Colors       struct {
			Light map[string]string `yaml:"light"`
			Dark  map[string]string `yaml:"dark"`
		} `yaml:"colors"`
	} `yaml:"branding"`
}

// Load reads <dir>/manifest.yaml. dir == "" means no bundle (nil, nil). A
// configured directory that is missing, unreadable, unparseable, or that
// declares a logo failing validation is an error: a client deployment must
// not silently ship the default look because of a typo.
func Load(dir string) (*Brand, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, nil
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("AUTH_CLIENT_CONFIG_DIR: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("AUTH_CLIENT_CONFIG_DIR: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("AUTH_CLIENT_CONFIG_DIR: %s is not a directory", abs)
	}
	raw, err := os.ReadFile(filepath.Join(abs, "manifest.yaml"))
	if err != nil {
		return nil, fmt.Errorf("AUTH_CLIENT_CONFIG_DIR: %w", err)
	}
	if len(raw) > maxManifestBytes {
		return nil, errors.New("AUTH_CLIENT_CONFIG_DIR: manifest.yaml is larger than 1 MiB")
	}
	var m manifest
	// Unknown keys are the rest of Fleet's schema; they are expected.
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("AUTH_CLIENT_CONFIG_DIR: manifest.yaml: %w", err)
	}
	b := &Brand{
		Dir:          abs,
		AppName:      oneLine(m.Branding.AppName, 64),
		LoginTitle:   oneLine(m.Branding.LoginTitle, 120),
		LoginTagline: oneLine(m.Branding.LoginTagline, 240),
	}
	if logo := strings.TrimSpace(m.Branding.Logo); logo != "" {
		path, ctype, validated, err := validateLogo(abs, logo)
		if err != nil {
			return nil, fmt.Errorf("AUTH_CLIENT_CONFIG_DIR: branding.logo: %w", err)
		}
		data, err := readBounded(path, validated, MaxLogoBytes)
		if err != nil {
			return nil, fmt.Errorf("AUTH_CLIENT_CONFIG_DIR: branding.logo: %w", err)
		}
		b.LogoPath, b.LogoContentType, b.Logo = path, ctype, data
	}
	b.CSS = generateCSS(m.Branding.Colors.Dark, m.Branding.Colors.Light)
	return b, nil
}

// readBounded reads the file validateLogo just examined and refuses to read
// anything else: the open uses O_NOFOLLOW for the final component, and the
// opened descriptor must be the very inode validation saw (os.SameFile), so a
// swap of the file OR of any ancestor directory for a symlink between the
// check and this read yields an error instead of another file's bytes.
func readBounded(path string, validated os.FileInfo, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(validated, info) {
		return nil, fmt.Errorf("%s changed between validation and read", path)
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("%s is not a regular file of at most %d bytes", path, limit)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s grew past %d bytes while being read", path, limit)
	}
	return data, nil
}

// oneLine keeps copy to a single bounded line: control characters are the
// only thing that could surprise the (auto-escaping) template, and a
// paragraph-length "app name" is a mistake, not a brand. The bound counts
// runes so a multibyte name is never cut into invalid UTF-8.
func oneLine(s string, maxRunes int) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	n := 0
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		if n == maxRunes {
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

var logoContentTypes = map[string]string{
	".svg": "image/svg+xml", ".png": "image/png", ".webp": "image/webp",
	".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".ico": "image/x-icon",
}

// validateLogo applies the same rules Fleet does: a relative path with no
// ".." element, resolving (through symlinks) to a regular file inside the
// bundle, with an extension the HTTP layer knows a content type for, and a
// bounded size.
func validateLogo(bundle, rel string) (string, string, os.FileInfo, error) {
	if filepath.IsAbs(rel) || strings.Contains(rel, "\\") {
		return "", "", nil, fmt.Errorf("%q must be a relative path inside the bundle", rel)
	}
	clean := filepath.Clean(rel)
	for _, part := range strings.Split(clean, string(filepath.Separator)) {
		if part == ".." {
			return "", "", nil, fmt.Errorf("%q escapes the bundle", rel)
		}
	}
	ctype, ok := logoContentTypes[strings.ToLower(filepath.Ext(clean))]
	if !ok {
		return "", "", nil, fmt.Errorf("%q: extension must be one of .svg .png .webp .jpg .jpeg .ico", rel)
	}
	bundleReal, err := filepath.EvalSymlinks(bundle)
	if err != nil {
		return "", "", nil, err
	}
	real, err := filepath.EvalSymlinks(filepath.Join(bundle, clean))
	if err != nil {
		return "", "", nil, err
	}
	if real != bundleReal && !strings.HasPrefix(real, bundleReal+string(filepath.Separator)) {
		return "", "", nil, fmt.Errorf("%q resolves outside the bundle", rel)
	}
	info, err := os.Stat(real)
	if err != nil {
		return "", "", nil, err
	}
	if !info.Mode().IsRegular() {
		return "", "", nil, fmt.Errorf("%q is not a regular file", rel)
	}
	if info.Size() > MaxLogoBytes {
		return "", "", nil, fmt.Errorf("%q is %d bytes; the limit is %d", rel, info.Size(), MaxLogoBytes)
	}
	return real, ctype, info, nil
}

// colorValue mirrors Fleet's grammar: hex, or rgb()/rgba()/hsl()/hsla()
// whose arguments are digits, letters (units such as deg), dots, commas,
// percent signs, slashes, hyphens and spaces. No nested parentheses, so
// url(), var() and calc() cannot appear, and no semicolons or braces, so a
// value cannot end the declaration or the block.
var colorValue = regexp.MustCompile(`^(?:#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})|(?:rgb|rgba|hsl|hsla)\([0-9a-zA-Z.,%/\s-]+\))$`)

// tokens maps the bundle's colour names onto the custom properties Auth's
// stylesheet already uses. Names Auth has no surface for (rail, overlays,
// surface_2, text_disabled) are simply not listed, so they are dropped.
var tokens = map[string]string{
	"primary":        "--color-primary",
	"primary_hover":  "--color-primary-hover",
	"on_primary":     "--color-on-primary",
	"accent":         "--color-accent",
	"background":     "--color-bg",
	"surface_1":      "--color-surface-1",
	"text_primary":   "--color-text-primary",
	"text_secondary": "--color-text-secondary",
	"text_muted":     "--color-text-muted",
	"border":         "--color-border",
	"border_strong":  "--color-border-strong",
}

// ValidColor reports whether v may be emitted into the stylesheet.
func ValidColor(v string) bool {
	return colorValue.MatchString(strings.TrimSpace(v))
}

// modeDefaults are the values Auth's own stylesheet paints with, per mode,
// for the inputs the gradients are derived from. A bundle that sets only
// some of them still gets brand gradients, computed from its values plus
// these defaults, so a partial palette never keeps the stock purple glow
// beside a client colour.
var modeDefaults = map[bool]map[string]string{
	false: {"primary": "#7272ab", "primary_hover": "#8686c4", "accent": "#9da7ef", "background": "#1a0b1e", "surface_1": "#241b31"},
	true:  {"primary": "#7272ab", "primary_hover": "#5f5f97", "accent": "#9da7ef", "background": "#f4f6fb", "surface_1": "#ffffff"},
}

// declarations turns one mode's map into sorted CSS declarations, dropping
// unknown names and invalid values individually. It returns the plain token
// declarations and, separately, the gradient declarations that use
// color-mix(), so the caller can guard those behind @supports: a browser
// without color-mix() would otherwise accept the custom property and then
// paint nothing for the background that consumes it.
func declarations(mode map[string]string, light bool) (plain, mixed []string) {
	valid := map[string]string{}
	for name, value := range mode {
		prop, known := tokens[name]
		if !known || !ValidColor(value) {
			continue
		}
		v := strings.TrimSpace(value)
		valid[name] = v
		plain = append(plain, prop+": "+v+";")
	}
	if len(valid) == 0 {
		return nil, nil
	}
	pick := func(name string) string {
		if v, ok := valid[name]; ok {
			return v
		}
		return modeDefaults[light][name]
	}
	_, hasPrimary := valid["primary"]
	_, hasHover := valid["primary_hover"]
	_, hasAccent := valid["accent"]
	_, hasBackground := valid["background"]
	_, hasSurface := valid["surface_1"]
	if hasPrimary || hasHover || hasAccent || hasBackground || hasSurface {
		primary, hover, accent, bg, surface := pick("primary"), pick("primary_hover"), pick("accent"), pick("background"), pick("surface_1")
		plain = append(plain, "--gradient-action-primary: linear-gradient(140deg, "+primary+", "+hover+");")
		mixed = append(mixed,
			"--gradient-bg-home-signature: radial-gradient(circle at 8% -4%, color-mix(in srgb, "+primary+" 34%, transparent), transparent 34%), "+
				"radial-gradient(circle at 92% 2%, color-mix(in srgb, "+accent+" 22%, transparent), transparent 32%), "+
				"linear-gradient(150deg, "+bg+" 0%, "+bg+" 100%);",
			"--gradient-surface-card: linear-gradient(145deg, "+surface+", color-mix(in srgb, "+surface+" 88%, "+bg+"));")
	}
	sort.Strings(plain)
	sort.Strings(mixed)
	return plain, mixed
}

// generateCSS renders the override block appended to Auth's own tokens. Dark
// is the base (:root) and light overrides it, matching the stylesheet. The
// color-mix() gradients sit behind an @supports guard so an older browser
// keeps the stock gradients instead of an unpainted background.
func generateCSS(dark, light map[string]string) string {
	var b strings.Builder
	block := func(selector string, decls []string) {
		if len(decls) > 0 {
			b.WriteString(selector + " {\n  " + strings.Join(decls, "\n  ") + "\n}\n")
		}
	}
	darkPlain, darkMixed := declarations(dark, false)
	lightPlain, lightMixed := declarations(light, true)
	block(":root", darkPlain)
	block(`:root[data-theme="light"]`, lightPlain)
	if len(darkMixed)+len(lightMixed) > 0 {
		b.WriteString("@supports (color: color-mix(in srgb, red, blue)) {\n")
		block(":root", darkMixed)
		block(`:root[data-theme="light"]`, lightMixed)
		b.WriteString("}\n")
	}
	return b.String()
}
