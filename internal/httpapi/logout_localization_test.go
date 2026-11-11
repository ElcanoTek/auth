package httpapi

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Follow the redirect without sending any cookies: the URL must carry the
// preference even when both localStorage and the language cookie are denied.
func assertLogoutLandingLanguage(t *testing.T, ts *httptest.Server, resp *http.Response, location, lang string) {
	t.Helper()
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != location {
		t.Fatalf("logout = %d %q, want 303 %q", resp.StatusCode, resp.Header.Get("Location"), location)
	}
	landing, body := get(t, ts.URL+location)
	if landing.StatusCode != http.StatusOK || landing.Header.Get("Content-Language") != lang || !strings.Contains(string(body), `<html lang="`+lang+`"`) {
		t.Fatalf("landing = %d, language %q, want %q", landing.StatusCode, landing.Header.Get("Content-Language"), lang)
	}
}

func TestRPLogoutLanguageWithoutStorage(t *testing.T) {
	ts, st, _, _ := newPasswordTestServer(t, false)
	if _, err := st.CreateApplication(t.Context(), "pages", "Pages", "https://pages.example.com/auth/callback", "https://pages.example.com/signed-out", hashSecret("test-client-secret"), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ query, suffix, language string }{
		{"lang=en", "&lang=en", "en"},
		{"lang=es-MX", "&lang=es", "es"},
		{"lang=PT-br", "&lang=pt", "pt"},
		{"ui_locales=fr+pt-PT+es", "&lang=pt", "pt"},
		{"lang=en&ui_locales=es", "&lang=en", "en"},
		{"lang=fr", "", "en"},
		{"lang=%2F%2Fevil.invalid%2F%3Fx%3D1", "", "en"},
		{"lang=es-%0d%0aLocation%3Ahttps%3A%2F%2Fevil.invalid", "&lang=es", "es"},
	} {
		t.Run(tt.query, func(t *testing.T) {
			resp, err := noFollowClient().Get(ts.URL + "/logout?client_id=pages&" + tt.query + "&return_to=https%3A%2F%2Fevil.invalid&post_logout_redirect_uri=https%3A%2F%2Fevil.invalid")
			if err != nil {
				t.Fatal(err)
			}
			assertLogoutLandingLanguage(t, ts, resp, "/?notice=signed_out"+tt.suffix, tt.language)
		})
	}
	resp, err := noFollowClient().Get(ts.URL + "/logout?client_id=unknown&lang=es")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
		t.Fatalf("unknown client accepted: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestMagicLogoutLanguageWithoutStorage(t *testing.T) {
	ts, _, _, _ := newTestServer(t)
	for _, lang := range []string{"en", "es", "pt"} {
		t.Run(lang, func(t *testing.T) {
			resp, err := noFollowClient().Get(ts.URL + "/logout?lang=" + lang)
			if err != nil {
				t.Fatal(err)
			}
			assertLogoutLandingLanguage(t, ts, resp, "/?lang="+lang, lang)
		})
	}
	resp, err := noFollowClient().Post(ts.URL+"/logout?lang=pt", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent || resp.Header.Get("Location") != "" {
		t.Fatalf("API logout changed: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestPasswordLogoutFormsCarryLanguageAndPreserveCSRF(t *testing.T) {
	for _, lang := range []string{"en", "es", "pt"} {
		t.Run(lang, func(t *testing.T) {
			ts, st, cfg, plain := newPasswordTestServer(t, false)
			login, session, csrf := passwordLogin(t, ts, cfg, "alice@example.com", plain)
			_ = login.Body.Close()
			b := newBrowser(t, ts)
			b.cookies[session.Name], b.cookies[csrf.Name] = session, csrf
			_, body := b.get("/account?lang=" + lang)
			// The plain account form and its confirmation dialog both work
			// without JavaScript or the display preference cookie.
			if strings.Count(body, `action="/logout?lang=`+lang+`"`) != 2 {
				t.Fatal("both account logout forms must carry the current language")
			}
			stale := postPasswordForm(t, ts.URL+"/logout?lang="+lang, url.Values{"csrf_token": {"stale"}, "redirect_to": {"/?notice=signed_out"}}, session, csrf)
			_ = stale.Body.Close()
			if stale.StatusCode != http.StatusSeeOther || stale.Header.Get("Location") != "/account?lang="+lang {
				t.Fatalf("stale form lost language: %d %q", stale.StatusCode, stale.Header.Get("Location"))
			}
			account, err := st.PasswordAccountByEmail(t.Context(), "alice@example.com")
			if err != nil {
				t.Fatal(err)
			}
			if count, err := st.CountActiveAuthSessions(t.Context(), account.ID, time.Now().Unix()); err != nil || count != 1 {
				t.Fatalf("stale form revoked session: count=%d, error=%v", count, err)
			}
			resp := postPasswordForm(t, ts.URL+"/logout?lang="+lang, url.Values{"csrf_token": {csrf.Value}, "redirect_to": {"/?notice=signed_out"}}, session, csrf)
			assertLogoutLandingLanguage(t, ts, resp, "/?notice=signed_out&lang="+lang, lang)
			if count, err := st.CountActiveAuthSessions(t.Context(), account.ID, time.Now().Unix()); err != nil || count != 0 {
				t.Fatalf("logout failed to revoke session: count=%d, error=%v", count, err)
			}
		})
	}
}

func TestLogoutLanguageKeepsReturnValidationAndApplicationURLs(t *testing.T) {
	for _, tt := range []struct{ destination, want string }{
		{"https://pages.example.com/signed-out?state=opaque%2Bvalue", "https://pages.example.com/signed-out?state=opaque%2Bvalue"},
		{"/callback?state=opaque%2Bvalue", "/callback?state=opaque%2Bvalue"},
		{"https://evil.invalid/", "/?lang=pt"},
		{`/\evil.invalid/`, "/?lang=pt"},
		{"//evil.invalid/", "/?lang=pt"},
		{"", ""},
	} {
		t.Run(tt.destination, func(t *testing.T) {
			ts, _, cfg, plain := newPasswordTestServer(t, false)
			login, session, csrf := passwordLogin(t, ts, cfg, "alice@example.com", plain)
			_ = login.Body.Close()
			resp := postPasswordForm(t, ts.URL+"/logout?lang=pt", url.Values{"csrf_token": {csrf.Value}, "redirect_to": {tt.destination}}, session, csrf)
			_ = resp.Body.Close()
			status := http.StatusSeeOther
			if tt.destination == "" {
				status = http.StatusNoContent
			}
			if resp.StatusCode != status || resp.Header.Get("Location") != tt.want {
				t.Fatalf("logout destination changed: %d %q, want %d %q", resp.StatusCode, resp.Header.Get("Location"), status, tt.want)
			}
		})
	}
}
