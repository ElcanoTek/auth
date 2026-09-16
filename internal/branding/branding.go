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
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

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
	// when the bundle declares none. LogoContentType matches its extension.
	LogoPath        string
	LogoContentType string
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
		path, ctype, err := validateLogo(abs, logo)
		if err != nil {
			return nil, fmt.Errorf("AUTH_CLIENT_CONFIG_DIR: branding.logo: %w", err)
		}
		b.LogoPath, b.LogoContentType = path, ctype
	}
	b.CSS = generateCSS(m.Branding.Colors.Dark, m.Branding.Colors.Light)
	return b, nil
}

// oneLine keeps copy to a single bounded line: control characters are the
// only thing that could surprise the (auto-escaping) template, and a
// paragraph-length "app name" is a mistake, not a brand.
func oneLine(s string, max int) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	out := b.String()
	if len(out) > max {
		out = out[:max]
	}
	return out
}

var logoContentTypes = map[string]string{
	".svg": "image/svg+xml", ".png": "image/png", ".webp": "image/webp",
	".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".ico": "image/x-icon",
}

// validateLogo applies the same rules Fleet does: a relative path with no
// ".." element, resolving (through symlinks) to a regular file inside the
// bundle, with an extension the HTTP layer knows a content type for, and a
// bounded size.
func validateLogo(bundle, rel string) (string, string, error) {
	if filepath.IsAbs(rel) || strings.Contains(rel, "\\") {
		return "", "", fmt.Errorf("%q must be a relative path inside the bundle", rel)
	}
	clean := filepath.Clean(rel)
	for _, part := range strings.Split(clean, string(filepath.Separator)) {
		if part == ".." {
			return "", "", fmt.Errorf("%q escapes the bundle", rel)
		}
	}
	ctype, ok := logoContentTypes[strings.ToLower(filepath.Ext(clean))]
	if !ok {
		return "", "", fmt.Errorf("%q: extension must be one of .svg .png .webp .jpg .jpeg .ico", rel)
	}
	bundleReal, err := filepath.EvalSymlinks(bundle)
	if err != nil {
		return "", "", err
	}
	real, err := filepath.EvalSymlinks(filepath.Join(bundle, clean))
	if err != nil {
		return "", "", err
	}
	if real != bundleReal && !strings.HasPrefix(real, bundleReal+string(filepath.Separator)) {
		return "", "", fmt.Errorf("%q resolves outside the bundle", rel)
	}
	info, err := os.Stat(real)
	if err != nil {
		return "", "", err
	}
	if !info.Mode().IsRegular() {
		return "", "", fmt.Errorf("%q is not a regular file", rel)
	}
	if info.Size() > MaxLogoBytes {
		return "", "", fmt.Errorf("%q is %d bytes; the limit is %d", rel, info.Size(), MaxLogoBytes)
	}
	return real, ctype, nil
}

// colorValue is Fleet's grammar: hex, or rgb()/rgba()/hsl()/hsla() with only
// digits, dots, commas, percent signs, slashes and spaces inside. Nothing
// else (no url(), no var(), no semicolons or braces) can reach the stylesheet.
var colorValue = regexp.MustCompile(`^(?:#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})|(?:rgb|rgba|hsl|hsla)\([0-9.,%/\s]+\))$`)

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

// declarations turns one mode's map into sorted CSS declarations, dropping
// unknown names and invalid values individually, and derives the three
// gradients Auth paints with from the brand's own colours so the page does
// not keep the default purple glow beside a client palette.
func declarations(mode map[string]string) []string {
	var out []string
	valid := map[string]string{}
	for name, value := range mode {
		prop, known := tokens[name]
		if !known || !ValidColor(value) {
			continue
		}
		v := strings.TrimSpace(value)
		valid[name] = v
		out = append(out, prop+": "+v+";")
	}
	if len(valid) == 0 {
		return nil
	}
	if primary, ok := valid["primary"]; ok {
		accent := primary
		if a, ok := valid["accent"]; ok {
			accent = a
		}
		hover := primary
		if h, ok := valid["primary_hover"]; ok {
			hover = h
		}
		out = append(out, "--gradient-action-primary: linear-gradient(140deg, "+primary+", "+hover+");")
		if bg, ok := valid["background"]; ok {
			out = append(out,
				"--gradient-bg-home-signature: radial-gradient(circle at 8% -4%, color-mix(in srgb, "+primary+" 34%, transparent), transparent 34%), "+
					"radial-gradient(circle at 92% 2%, color-mix(in srgb, "+accent+" 22%, transparent), transparent 32%), "+
					"linear-gradient(150deg, "+bg+" 0%, "+bg+" 100%);")
			if surface, ok := valid["surface_1"]; ok {
				out = append(out, "--gradient-surface-card: linear-gradient(145deg, "+surface+", color-mix(in srgb, "+surface+" 88%, "+bg+"));")
			}
		}
	}
	sort.Strings(out)
	return out
}

// generateCSS renders the override block appended to Auth's own tokens. Dark
// is the base (:root) and light overrides it, matching the stylesheet.
func generateCSS(dark, light map[string]string) string {
	var b strings.Builder
	if decls := declarations(dark); len(decls) > 0 {
		b.WriteString(":root {\n  " + strings.Join(decls, "\n  ") + "\n}\n")
	}
	if decls := declarations(light); len(decls) > 0 {
		b.WriteString(`:root[data-theme="light"] {` + "\n  " + strings.Join(decls, "\n  ") + "\n}\n")
	}
	return b.String()
}
