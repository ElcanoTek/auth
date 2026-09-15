package httpapi

import (
	"testing"

	"github.com/elcanotek/auth/internal/config"
)

// TestResolveReturnTo locks down the open-redirect defenses on
// ?return_to=. An attacker who can craft a /magic POST gets to embed a
// return_to into the signed magic link; if /callback honored arbitrary
// URLs, that's a phishing pivot once they're authenticated. Allowlist
// is "the cookie domain + its subdomains" by default; explicit list
// can override.
func TestResolveReturnTo(t *testing.T) {
	s := &Server{cfg: &config.Config{
		ReturnToHosts: []string{".example.com", "specific.other.com"},
	}}

	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"relative", "/me", "/me"},
		{"protocol-relative attack", "//evil.com/", ""},
		{"allowed subdomain", "https://chat.example.com/x", "https://chat.example.com/x"},
		{"allowed exact host", "https://specific.other.com/x", "https://specific.other.com/x"},
		{"foreign host", "https://evil.com/steal", ""},
		{"suffix-confusion attack", "https://example.com.evil.com/", ""},
		{"javascript: scheme", "javascript:alert(1)", ""},
		{"malformed", "::::not a url", ""},
		{"http allowed too", "http://chat.example.com/x", "http://chat.example.com/x"},
		{"bare cookie domain", "https://example.com/x", "https://example.com/x"},
		// Browsers parse "\" as "/", so these are scheme-relative to evil.com
		// even though url.Parse sees a path.
		{"backslash scheme-relative attack", `/\evil.com/`, ""},
		{"backslash after slash-dot", `/.\evil.com`, ""},
		{"backslash inside allowed host", `https://chat.example.com\@evil.com/`, ""},
		{"userinfo confusion", "https://chat.example.com@evil.com/", ""},
		{"userinfo on allowed host", "https://evil.com@chat.example.com/", ""},
		{"header injection", "/me\r\nSet-Cookie: x=y", ""},
		{"tab before protocol-relative", "/\t//evil.com", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := s.resolveReturnTo(tc.in)
			if got != tc.want {
				t.Errorf("resolveReturnTo(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestDefaultDest covers the post-login landing fallback: a configured
// default (home.<cookie-domain>) is used when it passes the allowlist,
// dev/localhost with no default falls back to /me, and a default that
// fails the allowlist can never become an open redirect.
func TestDefaultDest(t *testing.T) {
	t.Run("configured home default", func(t *testing.T) {
		s := &Server{cfg: &config.Config{
			DefaultReturnTo: "https://home.example.com",
			ReturnToHosts:   []string{".example.com"},
		}}
		if got := s.defaultDest(); got != "https://home.example.com" {
			t.Errorf("defaultDest() = %q, want https://home.example.com", got)
		}
	})
	t.Run("no default falls back to /me", func(t *testing.T) {
		s := &Server{cfg: &config.Config{}}
		if got := s.defaultDest(); got != "/me" {
			t.Errorf("defaultDest() = %q, want /me", got)
		}
	})
	t.Run("off-allowlist default cannot become an open redirect", func(t *testing.T) {
		s := &Server{cfg: &config.Config{
			DefaultReturnTo: "https://evil.com",
			ReturnToHosts:   []string{".example.com"},
		}}
		if got := s.defaultDest(); got != "/me" {
			t.Errorf("defaultDest() = %q, want /me (rejected)", got)
		}
	})
}

func TestHostMatches(t *testing.T) {
	cases := []struct {
		host, pattern string
		want          bool
	}{
		{"example.com", ".example.com", true},
		{"chat.example.com", ".example.com", true},
		{"deep.chat.example.com", ".example.com", true},
		{"example.com.evil.com", ".example.com", false},
		{"notexample.com", ".example.com", false},
		{"example.com", "example.com", true},
		{"chat.example.com", "example.com", false},
		{"Example.COM", "example.com", true},
	}
	for _, tc := range cases {
		if got := hostMatches(tc.host, tc.pattern); got != tc.want {
			t.Errorf("hostMatches(%q, %q) = %v, want %v",
				tc.host, tc.pattern, got, tc.want)
		}
	}
}
