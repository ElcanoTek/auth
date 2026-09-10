// Package httpapi wires the auth-server's HTTP surface.
//
// Routes:
//
//	GET  /           — login form (HTML)
//	POST /login      — password-mode login
//	GET|POST /change-password — password-mode forced replacement
//	GET  /account    — password-mode signed-in page with the logout form
//	POST /magic      — issue + email a magic link (form post or JSON)
//	GET  /sent       — "check your inbox" confirmation page
//	GET  /callback   — verify magic token, set session cookie, redirect
//	POST /logout     — clear cookie, render goodbye
//	GET  /verify     — Caddy forward_auth target. 200 + X-User-Email
//	                    and X-User-Tenant on success, 401 otherwise.
//	GET  /me         — JSON view of current session. Convenience for
//	                    downstream services that don't want to parse the
//	                    token themselves.
//	GET  /healthz    — for orchestration probes.
//
// The HTTP server itself is plain net/http. No middleware library, no
// router — chi/mux/gorilla are wonderful but overkill for this small surface.
package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/elcanotek/auth/internal/config"
	"github.com/elcanotek/auth/internal/email"
	passwordauth "github.com/elcanotek/auth/internal/password"
	"github.com/elcanotek/auth/internal/store"
	"github.com/elcanotek/auth/internal/token"
)

type Server struct {
	cfg               *config.Config
	store             *store.Store
	sender            email.Sender
	tmpl              *template.Template
	dummyPasswordHash string
	passwordSlots     chan struct{} // bounds concurrent Argon2 computations
	attemptGate       chan struct{} // 1-slot gate around limit-check + attempt-reserve

	// sends tracks in-flight magic-link email goroutines so graceful
	// shutdown can drain them instead of dropping mid-flight emails.
	sends sync.WaitGroup
}

func New(cfg *config.Config, st *store.Store, sender email.Sender) *Server {
	s := &Server{
		cfg: cfg, store: st, sender: sender, tmpl: parseTemplates(),
		passwordSlots: make(chan struct{}, 2),
		attemptGate:   make(chan struct{}, 1),
	}
	if cfg.LoginMode == "password" {
		s.dummyPasswordHash = passwordauth.DummyHash()
	}
	return s
}

// WaitSends blocks until every in-flight magic-link email send has finished,
// or ctx is done — whichever comes first. /magic dispatches email in a
// detached goroutine so a slow provider can't stall the response; this lets
// graceful shutdown wait for those sends to land instead of dropping them.
// It's bounded by ctx so a stuck send (despite the per-send deadline) can't
// hang shutdown forever. Call it only after the HTTP server has stopped
// accepting requests, so no new send can begin while we wait.
func (s *Server) WaitSends(ctx context.Context) {
	done := make(chan struct{})
	go func() {
		s.sends.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// Handler wires the routes and returns an http.Handler. Mounted by
// cmd/auth-server/main.go on cfg.Addr.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/magic", s.handleMagic)
	mux.HandleFunc("/login", s.handlePasswordLogin)
	mux.HandleFunc("/change-password", s.handleChangePassword)
	mux.HandleFunc("/account", s.handleAccount)
	mux.HandleFunc("/sent", s.handleSent)
	mux.HandleFunc("/callback", s.handleCallback)
	mux.HandleFunc("/logout", s.handleLogout)
	mux.HandleFunc("/verify", s.handleVerify)
	mux.HandleFunc("/me", s.handleMe)
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.Handle("/fonts/", fontHandler()) // self-hosted Nebula Sans woff2 for the login UI
	return logRequests(securityHeaders(mux))
}

// ── login UI ─────────────────────────────────────────────────────────

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	if s.passwordMode() {
		s.handlePasswordRoot(w, r)
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
			dest = s.defaultDest()
		}
		http.Redirect(w, r, dest, http.StatusSeeOther)
		return
	}

	if err := s.tmpl.ExecuteTemplate(w, "login.html", map[string]any{
		"Brand":    s.cfg.BrandName,
		"ReturnTo": r.URL.Query().Get("return_to"),
		"Error":    errorMessage(r.URL.Query().Get("err")),
	}); err != nil {
		log.Printf("render login: %v", err)
	}
}

func (s *Server) handlePasswordRoot(w http.ResponseWriter, r *http.Request) {
	if identity := s.currentPasswordSession(r); identity != nil {
		if identity.Account.MustChangePassword {
			http.Redirect(w, r, "/change-password", http.StatusSeeOther)
			return
		}
		dest := s.resolveReturnTo(r.URL.Query().Get("return_to"))
		if dest == "" {
			dest = s.defaultDest()
		}
		http.Redirect(w, r, dest, http.StatusSeeOther)
		return
	}
	csrf, err := s.ensureCSRFCookie(w, r)
	if err != nil {
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}
	if err := s.tmpl.ExecuteTemplate(w, "login.html", map[string]any{
		"Brand":        s.cfg.BrandName,
		"PasswordMode": true,
		"ReturnTo":     r.URL.Query().Get("return_to"),
		"Error":        errorMessage(r.URL.Query().Get("err")),
		"CSRF":         csrf,
	}); err != nil {
		log.Printf("render password login: %v", err)
	}
}

func (s *Server) handleSent(w http.ResponseWriter, r *http.Request) {
	if s.passwordMode() {
		http.NotFound(w, r)
		return
	}
	if err := s.tmpl.ExecuteTemplate(w, "sent.html", map[string]any{
		"Brand": s.cfg.BrandName,
		"Email": r.URL.Query().Get("email"),
	}); err != nil {
		log.Printf("render sent: %v", err)
	}
}

// ── /magic — issue + email ───────────────────────────────────────────

// Rolling windows for the POST /magic abuse limits. The per-window caps
// live in config (cfg.MagicRatePerEmail / cfg.MagicGlobalLimit; 0 disables
// a limit); these fix the window each cap is measured over.
const (
	magicRateWindow   = 15 * time.Minute // per-email issuance window
	magicGlobalWindow = 60 * time.Minute // stack-wide issuance window
)

func (s *Server) handleMagic(w http.ResponseWriter, r *http.Request) {
	if s.passwordMode() {
		http.NotFound(w, r)
		return
	}
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
		s.bounceWithErr(w, r, errInvalidEmail)
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
		s.bounceWithErr(w, r, errInternal)
		return
	} else if !ok {
		s.fakeSentResponse(w, r, email)
		return
	}

	// Abuse limits on this email-sending endpoint. We count links already
	// issued (a) to this address in the last magicRateWindow and (b)
	// stack-wide in the last magicGlobalWindow. On a hit we return the same
	// "check your inbox" page as a disallowed domain — never revealing the
	// limit or whether the address exists — and log a domain-only warning so
	// an operator can see an attack in progress. A cap of 0 disables it.
	//
	// Two deliberate limits of this approach: (1) the count and the issuance
	// aren't a single transaction, so a concurrent burst can overshoot a cap
	// by roughly the in-flight request count — acceptable for a spam throttle
	// (the single-use + collapse-to-newest guarantees stay transactional).
	// (2) one client can still spend the whole global budget; a per-IP limit
	// / CAPTCHA in front of /magic is the intended next layer.
	now := time.Now()
	if s.cfg.MagicRatePerEmail > 0 {
		n, err := s.store.CountRecentByEmail(r.Context(), email, now.Add(-magicRateWindow).Unix())
		if err != nil {
			log.Printf("rate count (per-email): %v", err)
			s.bounceWithErr(w, r, errInternal)
			return
		}
		if n >= s.cfg.MagicRatePerEmail {
			log.Printf("magic rate limit hit (per-email): tenant=%s", emailTenant(email))
			s.fakeSentResponse(w, r, email)
			return
		}
	}
	if s.cfg.MagicGlobalLimit > 0 {
		n, err := s.store.CountRecentTotal(r.Context(), now.Add(-magicGlobalWindow).Unix())
		if err != nil {
			log.Printf("rate count (global): %v", err)
			s.bounceWithErr(w, r, errInternal)
			return
		}
		if n >= s.cfg.MagicGlobalLimit {
			log.Printf("magic rate limit hit (global)")
			s.fakeSentResponse(w, r, email)
			return
		}
	}

	returnTo := s.resolveReturnTo(r.FormValue("return_to"))

	nonce, err := token.NewNonce()
	if err != nil {
		log.Printf("nonce: %v", err)
		s.bounceWithErr(w, r, errInternal)
		return
	}
	exp := now.Add(s.cfg.MagicTTL)
	if err := s.store.IssueMagic(r.Context(), nonce, email, now.Unix(), exp.Unix()); err != nil {
		log.Printf("issue magic: %v", err)
		s.bounceWithErr(w, r, errInternal)
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
		s.bounceWithErr(w, r, errInternal)
		return
	}

	link := s.absoluteURL(r, "/callback") + "?token=" + tok
	subject := "Your " + s.cfg.BrandName + " sign-in link"
	text := renderTextEmail(s.cfg.BrandName, link, s.cfg.MagicTTL)
	html := renderHTMLEmail(s.cfg.BrandName, link, s.cfg.MagicTTL)

	// Send happens asynchronously so a slow provider can't slow the
	// user's "check your inbox" page. We log the error if it fails —
	// the user will just see their inbox stay empty, which matches
	// real email behavior anyway. Tracked in s.sends so graceful shutdown
	// can drain it (WaitSends). NOTE: this goroutine may outlive shutdown
	// (drained best-effort), so it must NOT touch s.store — the DB may
	// already be closed by then. It only calls s.sender.Send.
	s.sends.Add(1)
	go func(to, subj, t, h string) {
		defer s.sends.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.sender.Send(ctx, to, subj, t, h); err != nil {
			// Log the tenant (domain) only — the full recipient address is
			// PII we don't want persisted in the journal.
			log.Printf("send magic email failed (tenant=%s): %v", emailTenant(to), err)
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

// Login-page error codes. The page only ever renders one of these fixed
// strings; the ?err= query value is a code, never free text, so nobody can
// craft a link that puts their own words on the sign-in page.
const (
	errInvalidEmail       = "invalid_email"
	errInternal           = "internal"
	errMissingToken       = "missing_token"
	errInvalidLink        = "invalid_link"
	errExpiredLink        = "expired_link"
	errUsedLink           = "used_link"
	errInvalidCredentials = "invalid_credentials"
)

var errorMessages = map[string]string{
	errInvalidEmail:       "Please enter a valid email address.",
	errInternal:           "Something went wrong. Try again.",
	errMissingToken:       "Missing sign-in token.",
	errInvalidLink:        "Invalid sign-in link. Request a fresh one.",
	errExpiredLink:        "That link expired. Request a fresh one.",
	errUsedLink:           "That link has already been used. Request a fresh one.",
	errInvalidCredentials: "Invalid email or password.",
}

// errorMessage maps an ?err= code to its display text; unknown codes render
// nothing rather than echoing the input.
func errorMessage(code string) string {
	return errorMessages[code]
}

// bounceWithErr redirects to the login page carrying an error code.
func (s *Server) bounceWithErr(w http.ResponseWriter, r *http.Request, code string) {
	q := url.Values{"err": []string{code}}
	if rt := r.FormValue("return_to"); rt != "" {
		q.Set("return_to", rt)
	}
	http.Redirect(w, r, "/?"+q.Encode(), http.StatusSeeOther)
}

// ── password login ──────────────────────────────────────────────────

const passwordRateWindow = 15 * time.Minute

func (s *Server) handlePasswordLogin(w http.ResponseWriter, r *http.Request) {
	if !s.passwordMode() {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !s.validCSRF(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	plain := r.FormValue("password")
	now := time.Now()
	ipRateKey := rateKey("ip", clientIP(r))
	account, valid, err := s.authenticatePassword(r.Context(), email, plain, ipRateKey, now, "login")
	if err != nil {
		log.Printf("password authentication: %v", err)
		s.passwordLoginFailure(w, r)
		return
	}
	if !valid {
		s.passwordLoginFailure(w, r)
		return
	}
	_ = s.store.RecordAudit(r.Context(), "login.succeeded", account.ID, ipRateKey, now.Unix())
	if err := s.issuePasswordSession(w, r, account, now); err != nil {
		log.Printf("issue password session: %v", err)
		s.passwordLoginFailure(w, r)
		return
	}
	if account.MustChangePassword {
		http.Redirect(w, r, "/change-password", http.StatusSeeOther)
		return
	}
	dest := s.resolveReturnTo(r.FormValue("return_to"))
	if dest == "" {
		dest = s.defaultDest()
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// authenticatePassword checks the persistent failure limits, verifies the
// credential, and records the attempt. The limit check and the attempt
// record happen together under attemptGate so a burst of parallel requests
// cannot all observe the same pre-failure count; the attempt is reserved as
// a failure BEFORE the expensive Argon2 work and settled to a success only
// after the credential verifies. That keeps the gate cheap (two SQLite
// statements) while Argon2 runs in parallel under passwordSlots. A request
// that is cancelled mid-verify keeps its reserved failure: fail closed.
//
// auditPrefix names the flow ("login" or "password_change") so audit events
// distinguish a sign-in from a current-password check.
func (s *Server) authenticatePassword(ctx context.Context, email, plain, ipRateKey string, now time.Time, auditPrefix string) (store.Account, bool, error) {
	emailRateKey := rateKey("email", email)
	account, lookupErr := s.store.PasswordAccountByEmail(ctx, email)
	auditUser := ""
	if lookupErr == nil {
		auditUser = account.ID
	}

	attempts, limited, err := s.reserveLoginAttempt(ctx, emailRateKey, ipRateKey, now)
	if err != nil {
		return store.Account{}, false, err
	}
	if limited {
		_ = s.store.RecordAudit(ctx, auditPrefix+".rate_limited", auditUser, ipRateKey, now.Unix())
		return store.Account{}, false, nil
	}

	encoded := s.dummyPasswordHash
	if lookupErr == nil {
		encoded = account.PasswordHash
	}
	ok, _, verifyErr := s.verifyPassword(ctx, encoded, plain)
	valid := lookupErr == nil && verifyErr == nil && ok && account.DisabledAt == nil
	if !valid {
		_ = s.store.RecordAudit(ctx, auditPrefix+".failed", auditUser, ipRateKey, now.Unix())
		if lookupErr == nil && verifyErr != nil {
			// A stored hash that no longer parses is an operator problem,
			// not a bad password; surface it in the log.
			return store.Account{}, false, fmt.Errorf("verify stored credential: %w", verifyErr)
		}
		return store.Account{}, false, nil
	}
	// The email reservation becomes the success marker that resets that
	// account's failure count; the IP reservation is discarded so successful
	// sign-ins never count against a shared address.
	if err := s.store.SettleLoginAttemptSuccess(ctx, attempts[0], attempts[1]); err != nil {
		return store.Account{}, false, err
	}
	return account, true, nil
}

// reserveLoginAttempt is the short critical section: check both limits and,
// if neither is exhausted, insert one provisional failure per key.
func (s *Server) reserveLoginAttempt(ctx context.Context, emailKey, ipKey string, now time.Time) ([]int64, bool, error) {
	if err := acquire(ctx, s.attemptGate); err != nil {
		return nil, false, err
	}
	defer release(s.attemptGate)
	limited, err := s.passwordRateLimited(ctx, emailKey, ipKey, now)
	if err != nil || limited {
		return nil, limited, err
	}
	ids, err := s.store.ReserveLoginAttempts(ctx, now.Unix(), emailKey, ipKey)
	if err != nil {
		return nil, false, err
	}
	return ids, false, nil
}

func (s *Server) passwordRateLimited(ctx context.Context, emailKey, ipKey string, now time.Time) (bool, error) {
	since := now.Add(-passwordRateWindow).Unix()
	if s.cfg.PasswordRatePerEmail > 0 {
		n, err := s.store.CountFailedLoginAttempts(ctx, emailKey, since)
		if err != nil || n >= s.cfg.PasswordRatePerEmail {
			return n >= s.cfg.PasswordRatePerEmail, err
		}
	}
	if s.cfg.PasswordRatePerIP > 0 {
		n, err := s.store.CountFailedLoginAttempts(ctx, ipKey, since)
		if err != nil || n >= s.cfg.PasswordRatePerIP {
			return n >= s.cfg.PasswordRatePerIP, err
		}
	}
	return false, nil
}

func (s *Server) passwordLoginFailure(w http.ResponseWriter, r *http.Request) {
	q := url.Values{"err": []string{errInvalidCredentials}}
	if rt := r.FormValue("return_to"); rt != "" {
		q.Set("return_to", rt)
	}
	http.Redirect(w, r, "/?"+q.Encode(), http.StatusSeeOther)
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if !s.passwordMode() {
		http.NotFound(w, r)
		return
	}
	identity := s.currentPasswordSession(r)
	if identity == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	csrf, err := s.ensureCSRFCookie(w, r)
	if err != nil {
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}
	if r.Method == http.MethodGet {
		s.renderChangePassword(w, "", csrf)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !s.validCSRF(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	current, next, confirm := r.FormValue("current_password"), r.FormValue("new_password"), r.FormValue("confirm_password")
	now := time.Now()
	ipRateKey := rateKey("ip", clientIP(r))
	account, valid, authErr := s.authenticatePassword(r.Context(), identity.Account.NormalizedEmail, current, ipRateKey, now, "password_change")
	if authErr != nil || !valid || account.ID != identity.Account.ID {
		if authErr != nil {
			log.Printf("password change authentication: %v", authErr)
		}
		s.renderChangePassword(w, "Current password is incorrect.", csrf)
		return
	}
	if next != confirm {
		s.renderChangePassword(w, "New passwords do not match.", csrf)
		return
	}
	// The current password just verified, so a byte-equal replacement is the
	// same credential. Rejecting it is what makes a forced change a change:
	// the administrator who issued the temporary password must not keep
	// knowing the live one.
	if subtle.ConstantTimeCompare([]byte(next), []byte(current)) == 1 {
		s.renderChangePassword(w, "New password must be different from the current password.", csrf)
		return
	}
	encoded, err := s.hashPassword(r.Context(), next)
	if err != nil {
		s.renderChangePassword(w, err.Error(), csrf)
		return
	}
	if err := s.store.SetPassword(r.Context(), identity.Account.Email, encoded, false, now.Unix()); err != nil {
		log.Printf("replace password: %v", err)
		s.renderChangePassword(w, "Something went wrong. Try again.", csrf)
		return
	}
	updated, err := s.store.PasswordAccountByID(r.Context(), identity.Account.ID)
	if err != nil || s.issuePasswordSession(w, r, updated, now) != nil {
		s.clearPasswordCookies(w)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, s.defaultDest(), http.StatusSeeOther)
}

func (s *Server) renderChangePassword(w http.ResponseWriter, errText, csrf string) {
	if err := s.tmpl.ExecuteTemplate(w, "change-password.html", map[string]any{
		"Brand": s.cfg.BrandName, "Error": errText, "CSRF": csrf,
	}); err != nil {
		log.Printf("render change password: %v", err)
	}
}

// handleAccount is the signed-in landing page on the auth host: it shows who
// is signed in and carries the only same-origin logout form, which is the
// one place a password-mode user can end their central session on demand.
func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	if !s.passwordMode() {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	identity := s.currentPasswordSession(r)
	if identity == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if identity.Account.MustChangePassword {
		http.Redirect(w, r, "/change-password", http.StatusSeeOther)
		return
	}
	csrf, err := s.ensureCSRFCookie(w, r)
	if err != nil {
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}
	if err := s.tmpl.ExecuteTemplate(w, "account.html", map[string]any{
		"Brand": s.cfg.BrandName, "Email": identity.Account.Email, "CSRF": csrf,
	}); err != nil {
		log.Printf("render account: %v", err)
	}
}

// verifyPassword and hashPassword bound concurrent Argon2 work to
// passwordSlots (each computation pins 64 MiB). The wait honours the request
// context so a flood queues briefly and then sheds load instead of piling
// up goroutines behind an uncancellable lock.
func (s *Server) verifyPassword(ctx context.Context, encoded, plain string) (bool, bool, error) {
	if err := acquire(ctx, s.passwordSlots); err != nil {
		return false, false, err
	}
	defer release(s.passwordSlots)
	return passwordauth.Verify(encoded, plain)
}

func (s *Server) hashPassword(ctx context.Context, plain string) (string, error) {
	if err := acquire(ctx, s.passwordSlots); err != nil {
		return "", err
	}
	defer release(s.passwordSlots)
	return passwordauth.Hash(plain)
}

func acquire(ctx context.Context, slots chan struct{}) error {
	select {
	case slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func release(slots chan struct{}) { <-slots }

// ── /callback — verify magic, set cookie ─────────────────────────────

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	if s.passwordMode() {
		http.NotFound(w, r)
		return
	}
	raw := r.URL.Query().Get("token")
	if raw == "" {
		s.bounceWithErr(w, r, errMissingToken)
		return
	}
	m, err := token.VerifyMagic(s.cfg.PublicKey, raw)
	if err != nil {
		s.bounceWithErr(w, r, errInvalidLink)
		return
	}
	if m.Exp <= time.Now().Unix() {
		s.bounceWithErr(w, r, errExpiredLink)
		return
	}

	// Single-use: consume the nonce. Any error here (already-used,
	// expired in DB, never issued) becomes the same "invalid" message
	// — keeping the failure modes indistinguishable from the outside.
	if _, err := s.store.ConsumeMagic(r.Context(), m.Nonce, time.Now().Unix()); err != nil {
		if errors.Is(err, store.ErrConsumed) {
			s.bounceWithErr(w, r, errUsedLink)
			return
		}
		s.bounceWithErr(w, r, errInvalidLink)
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
		s.bounceWithErr(w, r, errInternal)
		return
	}

	if err := s.store.RecordLogin(r.Context(), m.Email, tenant, now.Unix()); err != nil {
		// Audit log failure shouldn't block login — log + continue.
		log.Printf("record login: %v", err)
	}

	s.setSessionCookie(w, sessTok)

	dest := s.resolveReturnTo(m.ReturnTo)
	if dest == "" {
		dest = s.defaultDest()
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// ── /logout ──────────────────────────────────────────────────────────

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if s.passwordMode() {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil || !s.validCSRF(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		userID := ""
		if identity := s.currentPasswordSession(r); identity != nil {
			userID = identity.Account.ID
		}
		if c, err := r.Cookie(s.cfg.PasswordCookieName); err == nil {
			_, _ = s.store.RevokeAuthSession(r.Context(), hashSecret(c.Value), time.Now().Unix(), "logout")
		}
		_ = s.store.RecordAudit(r.Context(), "session.logged_out", userID, rateKey("ip", clientIP(r)), time.Now().Unix())
		s.clearPasswordCookies(w)
		// A browser form (the /account page) asks for a redirect; API-style
		// callers omit redirect_to and get the bare 204.
		if rt := r.FormValue("redirect_to"); rt != "" {
			dest := s.resolveReturnTo(rt)
			if dest == "" {
				dest = "/"
			}
			http.Redirect(w, r, dest, http.StatusSeeOther)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
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
	if s.passwordMode() {
		identity := s.currentPasswordSession(r)
		if identity == nil || identity.Account.MustChangePassword {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("X-User-ID", identity.Account.ID)
		w.Header().Set("X-User-Email", identity.Account.Email)
		w.Header().Set("X-User-Tenant", emailTenant(identity.Account.Email))
		w.WriteHeader(http.StatusOK)
		return
	}
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
	if s.passwordMode() {
		identity := s.currentPasswordSession(r)
		w.Header().Set("Content-Type", "application/json")
		if identity == nil {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = fmt.Fprint(w, `{"authenticated":false}`)
			return
		}
		_, _ = fmt.Fprintf(w, `{"authenticated":true,"sub":%q,"email":%q,"must_change_password":%t,"exp":%d}`,
			identity.Account.ID, identity.Account.Email, identity.Account.MustChangePassword, identity.Session.AbsoluteExpiresAt.Unix())
		return
	}
	sess := s.currentSession(r)
	w.Header().Set("Content-Type", "application/json")
	if sess == nil {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprint(w, `{"authenticated":false}`)
		return
	}
	_, _ = fmt.Fprintf(w, `{"authenticated":true,"email":%q,"tenant":%q,"exp":%d}`,
		sess.Email, sess.Tenant, sess.Exp)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("ok\n"))
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

type passwordIdentity struct {
	Account store.Account
	Session store.AuthSession
}

func (s *Server) passwordMode() bool { return s.cfg.LoginMode == "password" }

func (s *Server) issuePasswordSession(w http.ResponseWriter, r *http.Request, account store.Account, now time.Time) error {
	raw, err := randomSecret(32)
	if err != nil {
		return err
	}
	csrf, err := randomSecret(32)
	if err != nil {
		return err
	}
	idle := now.Add(s.cfg.PasswordIdleTTL)
	absolute := now.Add(s.cfg.PasswordAbsoluteTTL)
	if idle.After(absolute) {
		idle = absolute
	}
	if err := s.store.CreateAuthSession(r.Context(), hashSecret(raw), account.ID,
		now.Unix(), idle.Unix(), absolute.Unix()); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name: s.cfg.PasswordCookieName, Value: raw, Path: "/",
		MaxAge: int(s.cfg.PasswordAbsoluteTTL.Seconds()), Expires: absolute,
		Secure: s.cfg.CookieSecure, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	s.setCSRFCookie(w, csrf)
	return nil
}

func (s *Server) currentPasswordSession(r *http.Request) *passwordIdentity {
	c, err := r.Cookie(s.cfg.PasswordCookieName)
	if err != nil || c.Value == "" {
		return nil
	}
	a, sess, err := s.store.ValidateAuthSession(r.Context(), hashSecret(c.Value), time.Now().Unix(),
		s.cfg.PasswordIdleTTL, 5*time.Minute)
	if err != nil {
		return nil
	}
	return &passwordIdentity{Account: a, Session: sess}
}

const csrfCookieName = "__Host-auth_csrf"

func (s *Server) effectiveCSRFCookieName() string {
	if s.cfg.CookieSecure {
		return csrfCookieName
	}
	return "auth_csrf"
}

func (s *Server) ensureCSRFCookie(w http.ResponseWriter, r *http.Request) (string, error) {
	if c, err := r.Cookie(s.effectiveCSRFCookieName()); err == nil && len(c.Value) >= 32 {
		return c.Value, nil
	}
	return s.rotateCSRFCookie(w)
}

func (s *Server) rotateCSRFCookie(w http.ResponseWriter) (string, error) {
	raw, err := randomSecret(32)
	if err != nil {
		return "", err
	}
	s.setCSRFCookie(w, raw)
	return raw, nil
}

func (s *Server) setCSRFCookie(w http.ResponseWriter, raw string) {
	http.SetCookie(w, &http.Cookie{
		Name: s.effectiveCSRFCookieName(), Value: raw, Path: "/",
		MaxAge: int(s.cfg.PasswordAbsoluteTTL.Seconds()), Secure: s.cfg.CookieSecure,
		HttpOnly: false, SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) validCSRF(r *http.Request) bool {
	c, err := r.Cookie(s.effectiveCSRFCookieName())
	if err != nil || c.Value == "" {
		return false
	}
	submitted := r.FormValue("csrf_token")
	return len(submitted) == len(c.Value) && subtle.ConstantTimeCompare([]byte(submitted), []byte(c.Value)) == 1
}

func (s *Server) clearPasswordCookies(w http.ResponseWriter) {
	for _, cookie := range []http.Cookie{
		{Name: s.cfg.PasswordCookieName, HttpOnly: true},
		{Name: s.effectiveCSRFCookieName(), HttpOnly: false},
	} {
		cookie.Value = ""
		cookie.Path = "/"
		cookie.MaxAge = -1
		cookie.Expires = time.Unix(1, 0)
		cookie.Secure = s.cfg.CookieSecure
		cookie.SameSite = http.SameSiteLaxMode
		http.SetCookie(w, &cookie)
	}
}

func randomSecret(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashSecret(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func rateKey(kind, value string) string {
	return hashSecret(kind + "\x00" + strings.ToLower(strings.TrimSpace(value)))
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	// The production listener is loopback-only behind Caddy. Trust its
	// forwarded client address only when the immediate peer is loopback;
	// a mistakenly public listener must not permit rate-limit spoofing.
	//
	// Use the LAST hop, not the first: a reverse proxy appends the address
	// it actually saw, while any earlier entries arrived from the client and
	// are attacker-controlled. Caddy strips untrusted X-Forwarded-For by
	// default, but the limiter must not depend on that setting staying put.
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			hops := strings.Split(forwarded, ",")
			if last := strings.TrimSpace(hops[len(hops)-1]); last != "" {
				return last
			}
		}
	}
	return host
}

// ── helpers ──────────────────────────────────────────────────────────

// defaultDest is where we send a user when no valid return_to was given:
// the configured AUTH_DEFAULT_RETURN_TO (which defaults to the stack's
// home service, home.<cookie-domain>) if it passes the allowlist, else
// the local /me JSON view. Re-validating through resolveReturnTo means a
// misconfigured default can never become an open redirect.
func (s *Server) defaultDest() string {
	if d := s.resolveReturnTo(s.cfg.DefaultReturnTo); d != "" {
		return d
	}
	if s.passwordMode() {
		return "/account"
	}
	return "/me"
}

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

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		h.ServeHTTP(w, r)
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
