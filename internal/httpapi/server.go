// Package httpapi wires the auth-server's HTTP surface.
//
// Routes:
//
//   GET  /           — login form (HTML)
//   POST /magic      — issue + email a magic link (form post or JSON)
//   GET  /sent       — "check your inbox" confirmation page
//   GET  /callback   — verify magic token, set session cookie, redirect
//   POST /logout     — clear cookie, render goodbye
//   GET  /verify     — Caddy forward_auth target. 200 + X-User-Email
//                       and X-User-Tenant on success, 401 otherwise.
//   GET  /me         — JSON view of current session. Convenience for
//                       downstream services that don't want to parse the
//                       token themselves.
//   GET  /healthz    — for orchestration probes.
//
// The HTTP server itself is plain net/http. No middleware library, no
// router — chi/mux/gorilla are wonderful but overkill for ~8 routes.
package httpapi

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/elcanotek/auth/internal/config"
	"github.com/elcanotek/auth/internal/email"
	"github.com/elcanotek/auth/internal/store"
	"github.com/elcanotek/auth/internal/token"
)

type Server struct {
	cfg    *config.Config
	store  *store.Store
	sender email.Sender
	tmpl   *template.Template
}

func New(cfg *config.Config, st *store.Store, sender email.Sender) *Server {
	return &Server{cfg: cfg, store: st, sender: sender, tmpl: parseTemplates()}
}

// Handler wires the routes and returns an http.Handler. Mounted by
// cmd/auth-server/main.go on cfg.Addr.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/magic", s.handleMagic)
	mux.HandleFunc("/sent", s.handleSent)
	mux.HandleFunc("/callback", s.handleCallback)
	mux.HandleFunc("/logout", s.handleLogout)
	mux.HandleFunc("/verify", s.handleVerify)
	mux.HandleFunc("/me", s.handleMe)
	mux.HandleFunc("/healthz", s.handleHealth)
	return logRequests(mux)
}

// ── login UI ─────────────────────────────────────────────────────────

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// If they're already signed in, skip the form. Bounce to ?return_to=
	// or AUTH_DEFAULT_RETURN_TO. The "already logged in" case is common
	// when an operator clicks the auth URL directly from an existing
	// chat tab; sending them back to where they came from is sleeker
	// than re-asking for an email.
	if sess := s.currentSession(r); sess != nil {
		dest := s.resolveReturnTo(r.URL.Query().Get("return_to"))
		if dest == "" {
			dest = "/me"
		}
		http.Redirect(w, r, dest, http.StatusSeeOther)
		return
	}

	if err := s.tmpl.ExecuteTemplate(w, "login.html", map[string]any{
		"Brand":    s.cfg.BrandName,
		"ReturnTo": r.URL.Query().Get("return_to"),
		"Error":    r.URL.Query().Get("err"),
	}); err != nil {
		log.Printf("render login: %v", err)
	}
}

func (s *Server) handleSent(w http.ResponseWriter, r *http.Request) {
	if err := s.tmpl.ExecuteTemplate(w, "sent.html", map[string]any{
		"Brand": s.cfg.BrandName,
		"Email": r.URL.Query().Get("email"),
	}); err != nil {
		log.Printf("render sent: %v", err)
	}
}

// ── /magic — issue + email ───────────────────────────────────────────

func (s *Server) handleMagic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	rawEmail := strings.TrimSpace(r.FormValue("email"))
	email := strings.ToLower(rawEmail)
	if !looksLikeEmail(email) {
		s.bounceWithErr(w, r, "Please enter a valid email address.")
		return
	}
	// DB is the source of truth at runtime — env AUTH_ALLOWED_DOMAINS
	// is seeded into the DB at startup, and `auth domain add` updates
	// the DB. We don't AND against cfg.AllowedDomains here because that
	// would make runtime additions ineffective until the operator also
	// restarted with the new env value. The startup seed gives the
	// same UX with one source of truth.
	//
	// Don't leak whether the domain is allowed — that would turn the
	// allowlist into an enumeration oracle. Same "we sent a link"
	// response regardless.
	if ok, err := s.store.DomainAllowed(r.Context(), email); err != nil {
		log.Printf("domain check: %v", err)
		s.bounceWithErr(w, r, "Something went wrong. Try again.")
		return
	} else if !ok {
		s.fakeSentResponse(w, r, email)
		return
	}

	returnTo := s.resolveReturnTo(r.FormValue("return_to"))

	nonce, err := token.NewNonce()
	if err != nil {
		log.Printf("nonce: %v", err)
		s.bounceWithErr(w, r, "Something went wrong. Try again.")
		return
	}
	now := time.Now()
	exp := now.Add(s.cfg.MagicTTL)
	if err := s.store.IssueMagic(r.Context(), nonce, email, exp.Unix()); err != nil {
		log.Printf("issue magic: %v", err)
		s.bounceWithErr(w, r, "Something went wrong. Try again.")
		return
	}

	tok, err := token.Sign(s.cfg.SigningKey, token.Magic{
		Email:    email,
		Nonce:    nonce,
		ReturnTo: returnTo,
		IAT:      now.Unix(),
		Exp:      exp.Unix(),
	})
	if err != nil {
		log.Printf("sign magic: %v", err)
		s.bounceWithErr(w, r, "Something went wrong. Try again.")
		return
	}

	link := s.absoluteURL(r, "/callback") + "?token=" + tok
	subject := "Your " + s.cfg.BrandName + " sign-in link"
	text := renderTextEmail(s.cfg.BrandName, link, s.cfg.MagicTTL)
	html := renderHTMLEmail(s.cfg.BrandName, link, s.cfg.MagicTTL)

	// Send happens asynchronously so a slow provider can't slow the
	// user's "check your inbox" page. We log the error if it fails —
	// the user will just see their inbox stay empty, which matches
	// real email behavior anyway.
	go func(to, subj, t, h string) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.sender.Send(ctx, to, subj, t, h); err != nil {
			log.Printf("send magic email to %s: %v", to, err)
		}
	}(email, subject, text, html)

	dest := "/sent?email=" + url.QueryEscape(email)
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// fakeSentResponse exits the magic flow with a "check your inbox" page
// even though we sent nothing. Used when the email's domain isn't on
// the allowlist; reveals nothing to a curious enumerator.
func (s *Server) fakeSentResponse(w http.ResponseWriter, r *http.Request, email string) {
	http.Redirect(w, r, "/sent?email="+url.QueryEscape(email), http.StatusSeeOther)
}

func (s *Server) bounceWithErr(w http.ResponseWriter, r *http.Request, msg string) {
	q := url.Values{"err": []string{msg}}
	if rt := r.FormValue("return_to"); rt != "" {
		q.Set("return_to", rt)
	}
	http.Redirect(w, r, "/?"+q.Encode(), http.StatusSeeOther)
}

// ── /callback — verify magic, set cookie ─────────────────────────────

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("token")
	if raw == "" {
		s.bounceWithErr(w, r, "Missing sign-in token.")
		return
	}
	m, err := token.VerifyMagic(s.cfg.PublicKey, raw)
	if err != nil {
		s.bounceWithErr(w, r, "Invalid sign-in link. Request a fresh one.")
		return
	}
	if m.Exp <= time.Now().Unix() {
		s.bounceWithErr(w, r, "That link expired. Request a fresh one.")
		return
	}

	// Single-use: consume the nonce. Any error here (already-used,
	// expired in DB, never issued) becomes the same "invalid" message
	// — keeping the failure modes indistinguishable from the outside.
	if _, err := s.store.ConsumeMagic(r.Context(), m.Nonce, time.Now().Unix()); err != nil {
		if errors.Is(err, store.ErrConsumed) {
			s.bounceWithErr(w, r, "That link has already been used. Request a fresh one.")
			return
		}
		s.bounceWithErr(w, r, "Invalid sign-in link. Request a fresh one.")
		return
	}

	tenant := emailTenant(m.Email)
	now := time.Now()
	sessTok, err := token.Sign(s.cfg.SigningKey, token.Session{
		Email:  m.Email,
		Tenant: tenant,
		IAT:    now.Unix(),
		Exp:    now.Add(s.cfg.SessionTTL).Unix(),
	})
	if err != nil {
		log.Printf("sign session: %v", err)
		s.bounceWithErr(w, r, "Something went wrong. Try again.")
		return
	}

	if err := s.store.RecordLogin(r.Context(), m.Email, tenant, now.Unix()); err != nil {
		// Audit log failure shouldn't block login — log + continue.
		log.Printf("record login: %v", err)
	}

	s.setSessionCookie(w, sessTok)

	dest := s.resolveReturnTo(m.ReturnTo)
	if dest == "" {
		dest = s.resolveReturnTo(s.cfg.DefaultReturnTo)
	}
	if dest == "" {
		dest = "/me"
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// ── /logout ──────────────────────────────────────────────────────────

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.clearSessionCookie(w)
	if r.Method == http.MethodPost {
		// XHR-style logout from a downstream service.
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ── /verify — Caddy forward_auth target ──────────────────────────────

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	sess := s.currentSession(r)
	if sess == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// These are picked up by Caddy's `copy_headers` directive and
	// forwarded to the upstream service so the app code can read who
	// the user is without parsing the cookie itself.
	w.Header().Set("X-User-Email", sess.Email)
	w.Header().Set("X-User-Tenant", sess.Tenant)
	w.WriteHeader(http.StatusOK)
}

// ── /me — JSON view of current session ───────────────────────────────

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	sess := s.currentSession(r)
	w.Header().Set("Content-Type", "application/json")
	if sess == nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"authenticated":false}`)
		return
	}
	fmt.Fprintf(w, `{"authenticated":true,"email":%q,"tenant":%q,"exp":%d}`,
		sess.Email, sess.Tenant, sess.Exp)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("ok\n"))
}

// ── cookie helpers ───────────────────────────────────────────────────

func (s *Server) setSessionCookie(w http.ResponseWriter, tok string) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.CookieName,
		Value:    tok,
		Path:     "/",
		Domain:   s.cfg.CookieDomain,
		MaxAge:   int(s.cfg.SessionTTL.Seconds()),
		Secure:   s.cfg.CookieSecure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.CookieName,
		Value:    "",
		Path:     "/",
		Domain:   s.cfg.CookieDomain,
		MaxAge:   -1,
		Secure:   s.cfg.CookieSecure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) currentSession(r *http.Request) *token.Session {
	c, err := r.Cookie(s.cfg.CookieName)
	if err != nil {
		return nil
	}
	sess, err := token.VerifySession(s.cfg.PublicKey, c.Value)
	if err != nil {
		return nil
	}
	return sess
}

// ── helpers ──────────────────────────────────────────────────────────

// resolveReturnTo validates a candidate post-login URL against the
// configured allowlist. Returns "" for anything not allowed; the
// caller picks a safe default.
//
// Accepts absolute URLs (must match an allowed host) and absolute paths
// (those serve from the auth host itself, so they're always safe).
func (s *Server) resolveReturnTo(raw string) string {
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
		// Relative URL pointing at the auth host. Allowed.
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return ""
	}
	for _, h := range s.cfg.ReturnToHosts {
		if hostMatches(u.Host, h) {
			return u.String()
		}
	}
	return ""
}

// hostMatches supports exact-host entries and ".example.com" wildcard
// suffix entries (matches example.com and any subdomain).
func hostMatches(host, pattern string) bool {
	host = strings.ToLower(host)
	pattern = strings.ToLower(pattern)
	if strings.HasPrefix(pattern, ".") {
		bare := pattern[1:]
		return host == bare || strings.HasSuffix(host, "."+bare)
	}
	return host == pattern
}

func (s *Server) absoluteURL(r *http.Request, path string) string {
	scheme := "https"
	if !s.cfg.CookieSecure {
		scheme = "http"
	}
	host := r.Host
	if s.cfg.Hostname != "" && s.cfg.Hostname != "localhost" {
		host = s.cfg.Hostname
	}
	return scheme + "://" + host + path
}

func emailTenant(email string) string {
	at := strings.LastIndexByte(email, '@')
	if at < 0 {
		return ""
	}
	return strings.ToLower(email[at+1:])
}

func looksLikeEmail(s string) bool {
	at := strings.LastIndexByte(s, '@')
	return at > 0 && at < len(s)-3 && !strings.ContainsAny(s, " \t\r\n")
}

// logRequests is the only middleware: status + duration + remote addr +
// method + path. Avoids dragging in a real logger; structured logging
// can come later if any operator asks for it.
func logRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, status: 200}
		h.ServeHTTP(rw, r)
		log.Printf("%s %s %s %d %s",
			r.RemoteAddr, r.Method, r.URL.Path, rw.status, time.Since(start))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(c int) {
	s.status = c
	s.ResponseWriter.WriteHeader(c)
}
