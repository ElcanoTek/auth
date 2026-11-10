package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"html"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLanguagePreferencePrecedence(t *testing.T) {
	tests := []struct{ name, query, cookie, accept, want string }{
		{"default", "", "", "", "en"},
		{"regional browser", "", "", "pt-BR,es;q=0.8", "pt"},
		{"quality", "", "", "pt;q=0.2,es-MX;q=0.9,en;q=0.5", "es"},
		{"rejected quality", "", "", "pt;q=0,es;q=broken,en;q=0.5", "en"},
		{"saved", "", "es", "pt-PT", "es"},
		{"explicit English", "lang=en", "es", "pt", "en"},
		{"query region", "lang=PT-br", "es", "en", "pt"},
		{"unsupported query", "lang=de", "es", "pt", "es"},
		{"OIDC list", "ui_locales=fr+es-ES+pt", "pt", "en", "es"},
		{"query before OIDC", "lang=pt&ui_locales=es", "es", "en", "pt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "http://auth.example/?"+tt.query, nil)
			r.Header.Set("Accept-Language", tt.accept)
			if tt.cookie != "" {
				r.AddCookie(&http.Cookie{Name: "elcano_language", Value: tt.cookie})
			}
			if got := requestLanguage(r); got != tt.want {
				t.Fatalf("language=%q; want %q", got, tt.want)
			}
		})
	}
}

func TestLanguageCatalogsPreserveParameters(t *testing.T) {
	numbered := regexp.MustCompile(`\{[0-9]+\}`)
	printf := regexp.MustCompile(`%[sdq]`)
	for lang, catalog := range languageCatalogs {
		if lang == "en" {
			continue
		}
		for source, target := range catalog {
			if target == "" {
				t.Errorf("%s: empty translation for %q", lang, source)
			}
			before, after := numbered.FindAllString(source, -1), numbered.FindAllString(target, -1)
			slices.Sort(before)
			slices.Sort(after)
			if !slices.Equal(before, after) || !slices.Equal(printf.FindAllString(source, -1), printf.FindAllString(target, -1)) {
				t.Errorf("%s: parameters changed for %q", lang, source)
			}
		}
	}
	// A supplied value is data, even when it resembles another message slot.
	if got := translate("es", "QR code for {0}: {1}", "{1}", "actual"); got != "Código QR de {1}: actual" {
		t.Fatalf("value reinterpreted: %q", got)
	}
}

func TestStaticTemplateMessagesHaveTranslations(t *testing.T) {
	literal := regexp.MustCompile(`\btr\s+("(?:\\.|[^"\\])*")`)
	err := fs.WalkDir(templateFS, "templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		raw, err := templateFS.ReadFile(path)
		if err != nil {
			return err
		}
		for _, match := range literal.FindAllStringSubmatch(string(raw), -1) {
			source, err := strconv.Unquote(match[1])
			if err != nil {
				return err
			}
			for _, lang := range []string{"es", "pt"} {
				if _, ok := languageCatalogs[lang][source]; !ok {
					t.Errorf("%s: %s missing %q", path, lang, source)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestLocalizedSignInAccountAdminAndRecovery(t *testing.T) {
	for _, lang := range []string{"es", "pt"} {
		t.Run(lang, func(t *testing.T) {
			ts, st, cfg, plain := adminFixture(t)
			grantAccess(t, st, "alice@example.com", "fleet")
			b := newBrowser(t, ts)
			resp, page := b.get("/?lang=" + lang)
			if resp.Header.Get("Content-Language") != lang || !strings.Contains(page, `<html lang="`+lang+`"`) {
				t.Fatalf("wrong page language: %s", page)
			}
			cookie := b.cookies["elcano_language"]
			if cookie == nil || cookie.Domain != "" || cookie.Path != "/" || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode {
				t.Fatalf("language cookie not host-only and protected: %#v", cookie)
			}
			if !strings.Contains(page, translate(lang, "Enter your work email and password.")) {
				t.Fatal("login copy not localized")
			}
			resp, _ = b.login("alice@example.com", plain)
			if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/account" {
				t.Fatalf("localized login failed: %d %s", resp.StatusCode, resp.Header.Get("Location"))
			}
			for _, route := range []struct{ path, heading string }{{"/account", "Your apps"}, {"/admin", "Admin Portal"}, {"/account/security", "Security"}, {"/change-password", "Change password"}} {
				resp, page = b.get(route.path)
				if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Language") != lang || !strings.Contains(page, translate(lang, route.heading)) {
					t.Fatalf("%s did not retain %s", route.path, lang)
				}
			}
			resp, page = b.post("/account/security", url.Values{"action": {"start"}})
			if resp.StatusCode != http.StatusOK || !strings.Contains(page, translate(lang, "Code from the app")) {
				t.Fatal("enrollment not localized")
			}
			secret := extractSecret(t, page)
			resp, page = b.post("/account/security", url.Values{"action": {"confirm"}, "code": {codeFor(t, secret, time.Now())}})
			if resp.StatusCode != http.StatusOK || !strings.Contains(page, translate(lang, "Authenticator set up")) {
				t.Fatalf("localized enrollment failed: %s", page)
			}
			if len(extractRecoveryCodes(t, page)) != 10 || strings.Contains(page, "data-language-choice") {
				t.Fatal("one-time recovery page must preserve its codes without offering a GET replay")
			}
			if resp.Header.Get("Cache-Control") != "no-store" || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "'nonce-") {
				t.Fatal("localized recovery page lost its security headers")
			}
			q := url.Values{"client_id": {"fleet"}, "response_type": {"code"}, "redirect_uri": {"https://fleet.client.example/api/auth/oidc/callback"}, "scope": {"openid email"}, "state": {"unchanged-state-+-"}, "nonce": {"unchanged-nonce"}, "code_challenge": {pkceChallenge(strings.Repeat("a", 43))}, "code_challenge_method": {"S256"}, "ui_locales": {lang}}
			resp, _ = b.get("/authorize?" + q.Encode())
			dest, err := url.Parse(resp.Header.Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusSeeOther || dest.Host != "fleet.client.example" || dest.Path != "/api/auth/oidc/callback" || dest.Query().Get("state") != "unchanged-state-+-" || dest.Query().Get("code") == "" || dest.Query().Has("lang") || dest.Query().Has("ui_locales") {
				t.Fatalf("language changed OAuth callback: %d %s", resp.StatusCode, dest)
			}
			if !b.has(cfg.PasswordCookieName) {
				t.Fatal("language selection changed the authentication session")
			}
		})
	}
}

func TestLocalizedPublicPagesAndSafeLanguageNavigation(t *testing.T) {
	ts, _, cfg, _ := newPasswordTestServer(t, false)
	enableLinks(cfg)
	for _, lang := range []string{"es", "pt"} {
		for _, page := range []struct{ path, key string }{{"/help/authenticator", "Three steps, about five minutes."}, {"/set-password", "Opening your link…"}, {"/?err=invalid_credentials", "Invalid email or password."}} {
			separator := "?"
			if strings.Contains(page.path, "?") {
				separator = "&"
			}
			resp, body := get(t, ts.URL+page.path+separator+"lang="+lang)
			if resp.StatusCode != http.StatusOK || !strings.Contains(html.UnescapeString(string(body)), translate(lang, page.key)) {
				t.Fatalf("%s missing %s translation", page.path, lang)
			}
		}
	}
	magic, _, _, _ := newTestServer(t)
	resp, body := get(t, magic.URL+"/sent?lang=pt&return_to=https%3A%2F%2Fevil.invalid%2F&err=call-this-number&email=alex%40example.com")
	if resp.StatusCode != http.StatusOK || strings.Contains(string(body), "evil.invalid") || strings.Contains(string(body), "call-this-number") || !strings.Contains(string(body), "alex@example.com") {
		t.Fatal("language navigation reflected rejected navigation state or changed user data")
	}
	_, body = get(t, magic.URL+"/?lang=es&err=call-this-number")
	if strings.Contains(string(body), "call-this-number") {
		t.Fatal("language form echoed a free-text error")
	}
}

func TestLocalizedValuesRemainEscapedAndUntranslated(t *testing.T) {
	ts, _, cfg, _ := newPasswordTestServer(t, false)
	cfg.BrandName = `Sign in <script>alert(1)</script> {0}`
	_, body := get(t, ts.URL+"/?lang=es")
	if strings.Contains(string(body), "<script>alert") || !strings.Contains(string(body), `<div class="brand">`+html.EscapeString(cfg.BrandName)+`</div>`) {
		t.Fatal("brand data was translated, interpreted, or rendered unescaped")
	}
	for _, lang := range []string{"es", "pt"} {
		text := renderTextEmail("Example", "https://auth.example/link", "123456", 15*time.Minute, lang)
		if !strings.Contains(text, "123456") || !strings.Contains(text, "https://auth.example/link") || !strings.Contains(text, translate(lang, "Your sign-in code:")) {
			t.Fatal("localized email changed the sign-in credential or link")
		}
	}
}

func TestStaticGoMessagesHaveTranslations(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		tree, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(tree, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) < 2 {
				return true
			}
			name, ok := call.Fun.(*ast.Ident)
			if !ok || name.Name != "translate" {
				return true
			}
			literal, ok := call.Args[1].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			source, err := strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatal(err)
			}
			for _, lang := range []string{"es", "pt"} {
				if _, ok := languageCatalogs[lang][source]; !ok {
					t.Errorf("%s: %s missing %q", path, lang, source)
				}
			}
			return true
		})
	}
}

func TestLanguageBrowserPreferenceScript(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node is a development-only runner for the browser preference test")
	}
	if out, err := exec.Command(node, "--test", "../../scripts/test/language_test.cjs").CombinedOutput(); err != nil {
		t.Fatalf("language preference script: %v\n%s", err, out)
	}
}

func TestLanguageNavigationKeepsRecoveryMode(t *testing.T) {
	_, st, cfg, _ := newPasswordTestServer(t, false)
	server := New(cfg, st, &captureSender{})
	r := httptest.NewRequest(http.MethodGet, "https://auth.example/login/verify?mode=recovery&lang=pt", nil)
	if query := server.languageQuery(r); query.Get("mode") != "recovery" || query.Has("lang") {
		t.Fatalf("recovery mode lost: %v", query)
	}
}

func TestLocalizedDatesAndCountsLeaveOpaqueValuesUntouched(t *testing.T) {
	date := time.Date(2026, 11, 11, 23, 45, 0, 0, time.FixedZone("example", 3600))
	if got := displayDate(date, "pt", true); got != "11/11/2026 22:45" {
		t.Fatal(got)
	}
	if got := displayDate(date, "en", false); got != "2026-11-11" {
		t.Fatal(got)
	}
	for _, test := range []struct {
		value          any
		language, want string
	}{
		{12345, "en", "12,345"}, {12345, "es", "12.345"}, {12345, "pt", "12\u00a0345"},
		{1234, "es", "1234"}, {-12345, "pt", "-12\u00a0345"}, {"123456", "es", "123456"},
	} {
		if got := displayNumber(test.value, test.language); got != test.want {
			t.Fatalf("%v %s: %q", test.value, test.language, got)
		}
	}
}

func TestChangingLanguagePreservesPendingSecurityAction(t *testing.T) {
	ts, _, _, plain := newPasswordTestServer(t, false)
	b := newBrowser(t, ts)
	b.login("alice@example.com", plain)
	for _, action := range []string{"start", "regenerate", "disable"} {
		_, page := b.get("/account/security/verify?action=" + action + "&return_to=%2Fadmin&lang=es")
		form := regexp.MustCompile(`(?s)<form class="language-choice".*?</form>`).FindString(page)
		query := url.Values{"lang": {"pt"}}
		for _, field := range regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`).FindAllStringSubmatch(form, -1) {
			query.Add(html.UnescapeString(field[1]), html.UnescapeString(field[2]))
		}
		if query.Get("action") != action || query.Get("return_to") != "/admin" {
			t.Fatalf("language form lost pending action: %s", form)
		}
		resp, page := b.get("/account/security/verify?" + query.Encode())
		if resp.StatusCode != http.StatusOK || !strings.Contains(page, `name="action" value="`+action+`"`) {
			t.Fatal("reauth lost pending action after language change")
		}
		resp, _ = b.post("/account/security/verify", url.Values{"action": {action}, "return_to": {"/admin"}, "password": {plain}})
		destination, _ := url.Parse(resp.Header.Get("Location"))
		if destination.Path != "/account/security" || destination.Query().Get("action") != action {
			t.Fatalf("pending action abandoned: %s", destination)
		}
	}
}
