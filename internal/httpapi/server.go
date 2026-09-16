// Package httpapi wires the auth-server's HTTP surface.
//
// Routes:
//
//	GET  /           — login form (HTML)
//	POST /login      — password-mode login
//	GET|POST /change-password — password-mode forced replacement
//	GET  /account    — password-mode signed-in page with the logout form
//	GET  /authorize  — password-mode application authorization request
//	POST /token      — confidential-client authorization-code exchange
//	GET  /.well-known/openid-configuration — application handoff discovery
//	GET  /jwks.json  — current and overlapping identity signing keys
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
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
	rateKeyMAC        []byte        // per-deployment HMAC key for rate-limit and audit hashes
	started           time.Time     // Last-Modified for assets snapshotted at startup (the brand logo)

	// sends tracks in-flight magic-link email goroutines so graceful
	// shutdown can drain them instead of dropping mid-flight emails.
	sends sync.WaitGroup
}

func New(cfg *config.Config, st *store.Store, sender email.Sender) *Server {
	s := &Server{
		cfg: cfg, store: st, sender: sender, tmpl: parseTemplates(), started: time.Now(),
		passwordSlots: make(chan struct{}, 2),
		attemptGate:   make(chan struct{}, 1),
	}
	if cfg.LoginMode == "password" {
		s.dummyPasswordHash = passwordauth.DummyHash()
	}
	// Rate-limit and audit rows store hashes of emails and client IPs. A
	// plain SHA-256 of an IPv4 address falls to a 4-billion-entry dictionary
	// after a database leak, so key the hash with a secret derived from the
	// deployment's Ed25519 private key (itself derived from the
	// AUTH_SIGNING_KEY seed). HKDF with a fixed label keeps this key
	// independent of the signing use of the same material.
	mac, err := hkdf.Key(sha256.New, []byte(cfg.SigningKey), nil, "elcano-auth/rate-key/v1", 32)
	if err != nil {
		panic(fmt.Sprintf("derive rate-key MAC: %v", err))
	}
	s.rateKeyMAC = mac
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
	mux.HandleFunc("/authorize", s.handleAuthorize)
	mux.HandleFunc("/token", s.handleToken)
	mux.HandleFunc("/.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("/jwks.json", s.handleJWKS)
	mux.HandleFunc("/sent", s.handleSent)
	mux.HandleFunc("/callback", s.handleCallback)
	mux.HandleFunc("/logout", s.handleLogout)
	mux.HandleFunc("/verify", s.handleVerify)
	mux.HandleFunc("/me", s.handleMe)
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.Handle("/fonts/", fontHandler()) // self-hosted Nebula Sans woff2 for the login UI
	mux.HandleFunc("/brand/logo", s.handleBrandLogo)
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

	if err := s.render(w, "login.html", map[string]any{
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
			dest := s.resolveReturnTo(r.URL.Query().Get("return_to"))
			location := "/change-password"
			if dest != "" {
				location += "?return_to=" + url.QueryEscape(dest)
			}
			http.Redirect(w, r, location, http.StatusSeeOther)
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
	if err := s.render(w, "login.html", map[string]any{
		"Brand":        s.cfg.BrandName,
		"PasswordMode": true,
		"ReturnTo":     r.URL.Query().Get("return_to"),
		"Error":        errorMessage(r.URL.Query().Get("err")),
		"Notice":       s.noticeMessage(r.URL.Query().Get("notice")),
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
	if err := s.render(w, "sent.html", map[string]any{
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

// noticeMessage maps a ?notice= code on the login page to neutral text; an
// unknown code renders nothing, so the query can never inject content.
func (s *Server) noticeMessage(code string) string {
	if code == "signed_out" {
		// Sign-out of the other apps is delivered over the back-channel
		// (immediately, then a 2-second poll), so it is complete within
		// seconds rather than at the instant this page renders.
		return "You are signed out of " + s.cfg.BrandName + ". Any " + s.cfg.BrandName + " app still open is being signed out too."
	}
	return ""
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
	ipRateKey := s.rateKey("ip", clientIP(r))
	account, valid, err := s.authenticatePassword(r.Context(), email, plain, ipRateKey, now, "login")
	if err != nil {
		logUnlessCancelled("password authentication", err)
		s.passwordLoginFailure(w, r)
		return
	}
	if !valid {
		s.passwordLoginFailure(w, r)
		return
	}
	if err := s.issuePasswordSession(w, r, account, now); err != nil {
		// Includes the credential having been replaced between verify and
		// issue: the password was right a moment ago, but no session exists,
		// so this is not a successful login.
		logUnlessCancelled("issue password session", err)
		_ = s.store.RecordAudit(r.Context(), "login.session_refused", account.ID, ipRateKey, now.Unix())
		s.passwordLoginFailure(w, r)
		return
	}
	// Recorded only once a session actually exists.
	_ = s.store.RecordAudit(r.Context(), "login.succeeded", account.ID, ipRateKey, now.Unix())
	if account.MustChangePassword {
		location := "/change-password"
		if dest := s.resolveReturnTo(r.FormValue("return_to")); dest != "" {
			location += "?return_to=" + url.QueryEscape(dest)
		}
		http.Redirect(w, r, location, http.StatusSeeOther)
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
// The account lookup happens only after the attempt is permitted, so a
// rate-limited request costs the same regardless of whether the email
// exists and its audit row is anonymous. Rate-limited audit rows are
// coalesced per source per window; the attacker already tripped the limit,
// and one row per window records that without letting them grow the table.
//
// On success the returned Account carries the exact hash that verified;
// callers pass it to CreateAuthSession so the session is bound to that
// credential and cannot be issued after a concurrent replacement.
//
// auditPrefix names the flow ("login" or "password_change") so audit events
// distinguish a sign-in from a current-password check.
func (s *Server) authenticatePassword(ctx context.Context, email, plain, ipRateKey string, now time.Time, auditPrefix string) (store.Account, bool, error) {
	emailRateKey := s.rateKey("email", email)

	attempts, limited, err := s.reserveLoginAttempt(ctx, emailRateKey, ipRateKey, now)
	if err != nil {
		return store.Account{}, false, err
	}
	if limited {
		_, _ = s.store.RecordAuditIfAbsent(ctx, auditPrefix+".rate_limited", "", ipRateKey,
			now.Unix(), now.Add(-passwordRateWindow).Unix())
		return store.Account{}, false, nil
	}

	account, lookupErr := s.store.PasswordAccountByEmail(ctx, email)
	auditUser := ""
	encoded := s.dummyPasswordHash
	if lookupErr == nil {
		auditUser = account.ID
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
		s.renderChangePassword(w, "", csrf, s.resolveReturnTo(r.URL.Query().Get("return_to")))
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
	ipRateKey := s.rateKey("ip", clientIP(r))
	account, valid, authErr := s.authenticatePassword(r.Context(), identity.Account.NormalizedEmail, current, ipRateKey, now, "password_change")
	if authErr != nil || !valid || account.ID != identity.Account.ID {
		if authErr != nil {
			logUnlessCancelled("password change authentication", authErr)
		}
		s.renderChangePassword(w, "Current password is incorrect.", csrf, s.resolveReturnTo(r.FormValue("return_to")))
		return
	}
	if next != confirm {
		s.renderChangePassword(w, "New passwords do not match.", csrf, s.resolveReturnTo(r.FormValue("return_to")))
		return
	}
	// The current password just verified, so a byte-equal replacement is the
	// same credential. Rejecting it is what makes a forced change a change:
	// the administrator who issued the temporary password must not keep
	// knowing the live one.
	if subtle.ConstantTimeCompare([]byte(next), []byte(current)) == 1 {
		s.renderChangePassword(w, "New password must be different from the current password.", csrf, s.resolveReturnTo(r.FormValue("return_to")))
		return
	}
	// Policy first, with what we know about this user and deployment, so a
	// password built from the email or the organisation's name is refused
	// before any Argon2 work. Hash re-runs the static checks without context.
	if err := passwordauth.Validate(next, s.passwordContext(identity.Account.Email)...); err != nil {
		s.renderChangePassword(w, passwordauth.UserMessage(err), csrf, s.resolveReturnTo(r.FormValue("return_to")))
		return
	}
	encoded, err := s.hashPassword(r.Context(), next)
	if err != nil {
		s.renderChangePassword(w, passwordauth.UserMessage(err), csrf, s.resolveReturnTo(r.FormValue("return_to")))
		return
	}
	// Compare-and-swap against the hash that just verified: if an
	// administrator replaced the password (or disabled the account) in the
	// meantime, this must not overwrite their change. Their replacement
	// already revoked this session, so send the user back to sign in.
	err = s.store.ReplacePasswordIfCurrent(r.Context(), account.ID, account.PasswordHash, encoded, now.Unix())
	if errors.Is(err, store.ErrCredentialChanged) {
		s.clearPasswordCookies(w)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if err != nil {
		log.Printf("replace password: %v", err)
		s.renderChangePassword(w, "Something went wrong. Try again.", csrf, s.resolveReturnTo(r.FormValue("return_to")))
		return
	}
	updated, err := s.store.PasswordAccountByID(r.Context(), identity.Account.ID)
	if err != nil || s.issuePasswordSession(w, r, updated, now) != nil {
		s.clearPasswordCookies(w)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	dest := s.resolveReturnTo(r.FormValue("return_to"))
	if dest == "" {
		dest = s.defaultDest()
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

func (s *Server) renderChangePassword(w http.ResponseWriter, errText, csrf, returnTo string) {
	if err := s.render(w, "change-password.html", map[string]any{
		"Brand": s.cfg.BrandName, "Error": errText, "CSRF": csrf, "ReturnTo": returnTo,
	}); err != nil {
		log.Printf("render change password: %v", err)
	}
}

// ── application authorization-code handoff ──────────────────────────

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if !s.passwordMode() {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	q := r.URL.Query()
	clientID, redirectURI := q.Get("client_id"), q.Get("redirect_uri")
	state, nonce := q.Get("state"), q.Get("nonce")
	challenge := q.Get("code_challenge")
	// prompt=none (OIDC Core 3.1.2.1) is a silent check: "sign this browser
	// in if it already has a central session, otherwise tell me, never show a
	// form". Applications use it to auto-start SSO on an anonymous visit and
	// fall back to their own login page when the answer is no.
	prompt := q.Get("prompt")
	app, err := s.store.ApplicationByID(r.Context(), clientID)
	if err != nil || app.DisabledAt != nil || redirectURI != app.RedirectURI || !validApplicationRedirect(app.RedirectURI) ||
		q.Get("response_type") != "code" || !validAuthorizationScope(q.Get("scope")) ||
		q.Get("code_challenge_method") != "S256" || !validCodeChallenge(challenge) ||
		!validProtocolValue(state, 512) || !validProtocolValue(nonce, 512) || (prompt != "" && prompt != "none") {
		http.Error(w, "invalid authorization request", http.StatusBadRequest)
		return
	}
	identity := s.currentPasswordSession(r)
	if prompt == "none" && (identity == nil || identity.Account.MustChangePassword) {
		// The redirect target was validated against the registration above,
		// so an error response may go back to it (OIDC Core 3.1.2.6). No
		// code, no identity: only the fact that a silent sign-in is not
		// possible right now. interaction_required means "signed in, but
		// must finish the forced password change first".
		code := "login_required"
		if identity != nil {
			code = "interaction_required"
		}
		s.redirectAuthorizeError(w, r, redirectURI, state, code)
		return
	}
	if identity == nil {
		http.Redirect(w, r, "/?return_to="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return
	}
	if identity.Account.MustChangePassword {
		http.Redirect(w, r, "/change-password?return_to="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return
	}
	rawCode, err := randomSecret(32)
	if err != nil {
		http.Error(w, "authorization failed", http.StatusInternalServerError)
		return
	}
	now := time.Now()
	codeTTL := s.cfg.CodeTTL
	if codeTTL <= 0 {
		codeTTL = 60 * time.Second
	}
	grant := store.AuthorizationGrant{
		ClientID: clientID, UserID: identity.Account.ID, SessionTokenHash: identity.Session.TokenHash,
		RedirectURI: redirectURI, Nonce: nonce, CodeChallenge: challenge,
		AuthTime: identity.Session.CreatedAt.Unix(),
	}
	if err := s.store.IssueAuthorizationCode(r.Context(), hashSecret(rawCode), grant, now.Unix(), now.Add(codeTTL).Unix()); err != nil {
		log.Printf("issue authorization code: %v", err)
		http.Error(w, "authorization failed", http.StatusInternalServerError)
		return
	}
	dest, _ := url.Parse(redirectURI)
	callbackQuery := dest.Query()
	callbackQuery.Set("code", rawCode)
	callbackQuery.Set("state", state)
	// RFC 9207: name the issuer on the response so a client that ever talks
	// to more than one authorization server can detect a mix-up. Explorer
	// ignores it today; it costs nothing and the callback signature is
	// forward-compatible.
	callbackQuery.Set("iss", s.issuerURL())
	dest.RawQuery = callbackQuery.Encode()
	http.Redirect(w, r, dest.String(), http.StatusSeeOther)
}

// redirectAuthorizeError sends the browser back to a validated redirect URI
// with an OAuth error, the caller's state, and the issuer (RFC 9207).
func (s *Server) redirectAuthorizeError(w http.ResponseWriter, r *http.Request, redirectURI, state, code string) {
	dest, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid authorization request", http.StatusBadRequest)
		return
	}
	callbackQuery := dest.Query()
	callbackQuery.Set("error", code)
	callbackQuery.Set("state", state)
	callbackQuery.Set("iss", s.issuerURL())
	dest.RawQuery = callbackQuery.Encode()
	http.Redirect(w, r, dest.String(), http.StatusSeeOther)
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if !s.passwordMode() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if r.Method != http.MethodPost {
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request")
		return
	}
	if mediaType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])); mediaType != "application/x-www-form-urlencoded" {
		writeOAuthError(w, http.StatusUnsupportedMediaType, "invalid_request")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	now := time.Now()
	ipRateKey := s.rateKey("ip", clientIP(r))
	// Token-endpoint refusals are the signal for a stolen or brute-forced
	// client secret and for code replay. Coalesced per source per window, the
	// same way rate-limit events are, so a flood cannot grow the audit table.
	auditRefusal := func(event string) {
		_, _ = s.store.RecordAuditIfAbsent(r.Context(), event, "", ipRateKey, now.Unix(), now.Add(-passwordRateWindow).Unix())
	}
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok || clientID == "" || clientID != r.FormValue("client_id") {
		auditRefusal("token.invalid_client")
		writeInvalidClient(w)
		return
	}
	app, err := s.store.ApplicationByID(r.Context(), clientID)
	providedSecretHash := hashSecret(clientSecret)
	if err != nil || app.DisabledAt != nil || len(app.ClientSecretHash) != len(providedSecretHash) ||
		subtle.ConstantTimeCompare([]byte(app.ClientSecretHash), []byte(providedSecretHash)) != 1 {
		auditRefusal("token.invalid_client")
		writeInvalidClient(w)
		return
	}
	code, redirectURI, verifier := r.FormValue("code"), r.FormValue("redirect_uri"), r.FormValue("code_verifier")
	if r.FormValue("grant_type") != "authorization_code" || code == "" || redirectURI != app.RedirectURI || !validCodeVerifier(verifier) {
		auditRefusal("token.invalid_grant")
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	challenge := pkceChallenge(verifier)
	codeHash := hashSecret(code)
	grant, err := s.store.ConsumeAuthorizationCode(r.Context(), codeHash, clientID, redirectURI, challenge, now.Unix())
	if err != nil {
		if !errors.Is(err, store.ErrInvalidGrant) {
			log.Printf("consume authorization code: %v", err)
		}
		// OAuth 2.1 §4.1.2: a code presented twice is evidence it leaked, so
		// revoke what the first exchange produced. The application session
		// is what that produced; a back-channel logout for this user at this
		// client ends it. Only codes that were actually exchanged carry
		// consumed_at, so a superseded second-tab code never trips this.
		if userID, codeClient, replayed, lookupErr := s.store.ReplayedAuthorizationCode(r.Context(), codeHash); lookupErr != nil {
			log.Printf("replay lookup: %v", lookupErr)
		} else if replayed {
			if _, err := s.store.EnqueueClientLogout(r.Context(), userID, codeClient, "code_replayed", now.Unix()); err != nil {
				log.Printf("revoke after code replay: %v", err)
			}
		}
		auditRefusal("token.invalid_grant")
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	assertionTTL := s.cfg.AssertionTTL
	if assertionTTL <= 0 {
		assertionTTL = 5 * time.Minute
	}
	claims := token.IdentityClaims{
		Issuer: s.issuerURL(), Subject: grant.UserID, Audience: grant.ClientID, Email: grant.Email,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(assertionTTL).Unix(), Nonce: grant.Nonce,
		AuthTime: grant.AuthTime, AMR: []string{"pwd"}, ACR: "urn:elcanotek:loa:1",
	}
	idToken, err := token.SignIdentity(s.cfg.SigningKey, claims)
	if err != nil {
		log.Printf("sign identity assertion: %v", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error")
		return
	}
	// No access_token, token_type, or expires_in in this response, on purpose.
	//
	// An OAuth access token is a credential a client presents to some OTHER
	// service (a resource server) on the user's behalf, and that service must
	// be able to verify it. Auth has no resource server: applications receive
	// the identity claims here, apply their own membership rules, and mint
	// their own sessions. Nothing anywhere accepts an Auth access token, so
	// issuing one would hand clients a bearer credential that nothing checks.
	// An earlier revision returned 32 random, unstored bytes purely to match
	// the textbook OAuth response shape; that is a credential-shaped value
	// with no verifier behind it, which is exactly the kind of thing that
	// gets trusted by mistake later. Every credential Auth mints must be
	// verifiable by something, so the field is gone rather than fake.
	//
	// Note that this is unrelated to MFA or upstream Google/Microsoft login:
	// MFA lands in the id_token's amr/acr claims and the reserved
	// authenticators tables; upstream login makes Auth an OAuth CLIENT of
	// Google, consuming Google's tokens inside Auth and still minting only an
	// id_token downstream. Neither needs an Auth-issued access token.
	//
	// Add access_token back when, and only when, an API exists that a client
	// should call as the signed-in user: for example a shared profile or team
	// membership endpoint at Auth, or one application calling another's API
	// on the user's behalf. Doing it properly means: store the token's hash
	// with user, client, scopes, and expiry; give the API a way to verify it
	// (an introspection endpoint here, or a signed JWT whose aud names that
	// API, never the client); define the scopes; sweep expired rows; rate
	// limit and audit the verifying endpoint; and return token_type "Bearer"
	// plus expires_in alongside it. Until then, generic OIDC client
	// libraries that insist on access_token are not supported; every current
	// consumer reads the claims and id_token only.
	writeJSON(w, http.StatusOK, map[string]any{
		"iss": claims.Issuer, "sub": claims.Subject, "aud": claims.Audience, "email": claims.Email,
		"iat": claims.IssuedAt, "exp": claims.ExpiresAt, "nonce": claims.Nonce, "auth_time": claims.AuthTime,
		"amr": claims.AMR, "acr": claims.ACR, "id_token": idToken,
	})
}

func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	if !s.passwordMode() {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	issuer := s.issuerURL()
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token",
		"jwks_uri": issuer + "/jwks.json", "response_types_supported": []string{"code"},
		"grant_types_supported": []string{"authorization_code"}, "subject_types_supported": []string{"public"},
		"id_token_signing_alg_values_supported": []string{"EdDSA"}, "token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
		"code_challenge_methods_supported": []string{"S256"}, "scopes_supported": []string{"openid", "email"},
		"prompt_values_supported":      []string{"none"},
		"backchannel_logout_supported": true, "backchannel_logout_session_supported": false,
	})
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if !s.passwordMode() {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	publicKeys := append([]ed25519.PublicKey{s.cfg.PublicKey}, s.cfg.PreviousPublicKeys...)
	keys := make([]map[string]string, 0, len(publicKeys))
	seen := map[string]bool{}
	for _, publicKey := range publicKeys {
		if len(publicKey) != ed25519.PublicKeySize {
			continue
		}
		kid := token.KeyID(publicKey)
		if seen[kid] {
			continue
		}
		seen[kid] = true
		keys = append(keys, map[string]string{
			"kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA", "kid": kid,
			"x": base64.RawURLEncoding.EncodeToString(publicKey),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

func (s *Server) issuerURL() string {
	if issuer := strings.TrimRight(s.cfg.IssuerURL, "/"); issuer != "" {
		return issuer
	}
	scheme := "https"
	if !s.cfg.CookieSecure {
		scheme = "http"
	}
	return scheme + "://" + s.cfg.Hostname
}

func validAuthorizationScope(scope string) bool {
	return scope == "email" || scope == "openid email" || scope == "email openid"
}

func validApplicationRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.Path == "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return u.Scheme == "https" || (u.Scheme == "http" && (host == "localhost" || host == "127.0.0.1" || host == "::1"))
}

func validProtocolValue(raw string, max int) bool {
	return raw != "" && len(raw) <= max && !strings.ContainsAny(raw, "\x00\r\n")
}

func validCodeChallenge(raw string) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	return err == nil && len(raw) == 43 && len(decoded) == sha256.Size
}

func validCodeVerifier(raw string) bool {
	if len(raw) < 43 || len(raw) > 128 {
		return false
	}
	for _, c := range []byte(raw) {
		if !isASCIIAlphaNumeric(c) && !strings.ContainsRune("-._~", rune(c)) {
			return false
		}
	}
	return true
}

func isASCIIAlphaNumeric(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func writeOAuthError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func writeInvalidClient(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
	writeOAuthError(w, http.StatusUnauthorized, "invalid_client")
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
	// The quick links are a convenience on a page whose job is the account
	// itself, so a registry read failure greys every tile out rather than
	// turning the page into a 500.
	apps, err := s.store.ListApplications(r.Context())
	if err != nil {
		log.Printf("account: list applications: %v", err)
		apps = nil
	}
	if err := s.render(w, "account.html", map[string]any{
		"Brand": s.cfg.BrandName, "Email": identity.Account.Email, "CSRF": csrf,
		"Links": quickLinksFor(apps),
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

// passwordContext lists the words a new password for email may not be built
// from: the address itself, the brand, this host's name and issuer, and the
// operator's AUTH_PASSWORD_BLOCKED_TERMS (typically the client's name).
func (s *Server) passwordContext(email string) []string {
	return passwordauth.ContextTerms(email, s.cfg.BrandName, s.cfg.Hostname, s.cfg.IssuerURL,
		strings.Join(s.cfg.PasswordBlockedTerms, ","))
}

func (s *Server) hashPassword(ctx context.Context, plain string) (string, error) {
	if err := acquire(ctx, s.passwordSlots); err != nil {
		return "", err
	}
	defer release(s.passwordSlots)
	return passwordauth.Hash(plain)
}

// logUnlessCancelled keeps client disconnects out of the error log: a
// request abandoned while waiting on a gate is not a server fault, and under
// a flood those lines would bury the ones that matter.
func logUnlessCancelled(what string, err error) {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return
	}
	log.Printf("%s: %v", what, err)
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
		s.handlePasswordLogout(w, r)
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

// handlePasswordLogout is "sign out of every Elcano app". Two entry points
// share it:
//
//   - POST with the CSRF token: the form on /account.
//   - GET /logout?client_id=<registered app>: RP-initiated logout (OpenID
//     Connect RP-Initiated Logout 1.0, without id_token_hint). Explorer, Lens
//     and Fleet send the browser here after ending their own session.
//
// Either way every central session of the signed-in account is revoked and a
// back-channel logout is queued to every registered application in the same
// transaction (RevokeAllAuthSessions), so an application session cannot
// outlive the logout and an application that signs in silently (prompt=none)
// cannot sign the user straight back in. The browser lands on this host's
// login page with a notice.
//
// The GET form can be triggered by a hostile page navigating the browser
// here. That is a forced sign-out, not access; RP-initiated logout permits GET
// and we accept the nuisance rather than add a confirmation click. Only a
// registered client_id is honoured; application ids are public anyway, so
// this is hygiene, not a secret.
func (s *Server) handlePasswordLogout(w http.ResponseWriter, r *http.Request) {
	redirectTo := ""
	switch r.Method {
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil || !s.validCSRF(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		redirectTo = r.FormValue("redirect_to")
	case http.MethodGet:
		// Any registered application may start a logout, disabled ones
		// included: their users still hold sessions that should end (and the
		// fan-out below reaches disabled apps too). A database error is a
		// 500, never folded into "unknown client".
		if _, err := s.store.ApplicationByID(r.Context(), r.URL.Query().Get("client_id")); err != nil {
			if errors.Is(err, store.ErrApplicationNotFound) {
				http.Error(w, "invalid logout request", http.StatusBadRequest)
				return
			}
			log.Printf("logout client lookup: %v", err)
			http.Error(w, "sign-out failed, please try again", http.StatusInternalServerError)
			return
		}
		redirectTo = "/?notice=signed_out"
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	now := time.Now()
	if c, err := r.Cookie(s.cfg.PasswordCookieName); err == nil && c.Value != "" {
		userID, err := s.store.RevokeAllAuthSessionsByToken(r.Context(), hashSecret(c.Value), now.Unix(), "user_logout")
		if err != nil {
			// Fail closed: keep the cookie so the user can retry, and do not
			// claim a sign-out the database did not record. A stolen copy of
			// this session would otherwise stay valid while the user believes
			// it is gone.
			log.Printf("logout revoke: %v", err)
			http.Error(w, "sign-out failed, please try again", http.StatusInternalServerError)
			return
		}
		if userID != "" {
			_ = s.store.RecordAudit(r.Context(), "session.logged_out", userID, s.rateKey("ip", clientIP(r)), now.Unix())
		}
	}
	s.clearPasswordCookies(w)
	if redirectTo == "" {
		// API-style callers omit redirect_to and get the bare 204.
		w.WriteHeader(http.StatusNoContent)
		return
	}
	dest := s.resolveReturnTo(redirectTo)
	if dest == "" {
		dest = "/"
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
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
		if identity == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"authenticated": false})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated":        true,
			"sub":                  identity.Account.ID,
			"email":                identity.Account.Email,
			"must_change_password": identity.Account.MustChangePassword,
			"exp":                  identity.Session.AbsoluteExpiresAt.Unix(),
		})
		return
	}
	sess := s.currentSession(r)
	if sess == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"authenticated": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"email":         sess.Email,
		"tenant":        sess.Tenant,
		"exp":           sess.Exp,
	})
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
	if err := s.store.CreateAuthSession(r.Context(), hashSecret(raw), account.ID, account.PasswordHash,
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
		s.cfg.PasswordIdleTTL, sessionTouchInterval)
	if err != nil {
		return nil
	}
	return &passwordIdentity{Account: a, Session: sess}
}

// sessionTouchInterval bounds how often a validated session writes its
// last-seen and idle-expiry columns. Every request reads the session; only a
// request more than this long after the previous touch writes. The idle
// timeout therefore behaves as "idle limit minus at most one interval", never
// longer, and a burst of requests from one page load costs one write.
//
// Convention for every Elcano service that keeps its own sessions (Auth,
// Explorer, Lens, and anything built later): one minute. It is short enough
// that the stated idle limit stays accurate to the minute, and long enough to
// collapse a page's burst of requests into a single write. Do not make it
// configurable; it is a property of the storage pattern, not a policy knob.
const sessionTouchInterval = time.Minute

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
		// The token reaches the browser inside the rendered form, so script
		// never needs to read this cookie. HttpOnly keeps it out of reach
		// of any script that does run on the page.
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
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
		{Name: s.effectiveCSRFCookieName(), HttpOnly: true},
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

// rateKey derives the stored key for a rate-limit bucket or audit source.
// It is an HMAC under a per-deployment secret, so a leaked database does not
// let anyone recover client IPs (or confirm email guesses) by hashing a
// dictionary. Session tokens use plain hashSecret instead: they are already
// 256 random bits and gain nothing from a key.
func (s *Server) rateKey(kind, value string) string {
	m := hmac.New(sha256.New, s.rateKeyMAC)
	m.Write([]byte(kind))
	m.Write([]byte{0})
	m.Write([]byte(strings.ToLower(strings.TrimSpace(value))))
	return hex.EncodeToString(m.Sum(nil))
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
	// Browsers follow the WHATWG URL parser, which treats a backslash like a
	// forward slash: a Location of "/\evil.com" is scheme-relative and lands
	// on evil.com even though Go's url.Parse (and the "//" check below) sees a
	// plain path. Control characters have no place in a redirect target
	// either. Reject both up front so every later check reasons about the
	// same URL the browser will.
	for i := 0; i < len(raw); i++ {
		if c := raw[i]; c == '\\' || c < 0x20 || c == 0x7f {
			return ""
		}
	}
	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
		// Relative URL pointing at the auth host. Allowed.
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		// Userinfo ("https://allowed.example.com@evil.com/") only exists to
		// confuse allowlists; no Elcano service is addressed that way.
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

// render executes an HTML page with a per-response CSP nonce. The pages carry
// one inline <style> and one inline <script> (the theme toggle); the nonce
// lets exactly those run while the policy refuses every other script,
// style, or resource origin. No form-action directive: browsers apply it to
// the redirect that follows a form post, which would break the post-login
// bounce to a client application host.
func (s *Server) render(w http.ResponseWriter, name string, data map[string]any) error {
	nonce, err := randomSecret(16)
	if err != nil {
		return err
	}
	s.decorate(data)
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'nonce-"+nonce+"'; "+
			"font-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data["Nonce"] = nonce
	return s.tmpl.ExecuteTemplate(w, name, data)
}

// decorate adds the branding fields every page template reads. Without a
// bundle the wordmark is the prose brand name and the rest is empty, which
// renders exactly the pre-bundle pages. BrandCSS is template.CSS because the
// branding package has already validated every value against a strict
// grammar; nothing else may be marked that way.
func (s *Server) decorate(data map[string]any) {
	data["Wordmark"] = s.cfg.BrandName
	data["LogoURL"] = ""
	data["BrandCSS"] = template.CSS("")
	data["LoginTitle"] = ""
	data["LoginTagline"] = ""
	b := s.cfg.Brand
	if b == nil {
		return
	}
	if b.AppName != "" {
		data["Wordmark"] = b.AppName
	}
	if len(b.Logo) > 0 {
		data["LogoURL"] = "/brand/logo"
	}
	data["BrandCSS"] = template.CSS(b.CSS)
	data["LoginTitle"] = b.LoginTitle
	data["LoginTagline"] = b.LoginTagline
}

// handleBrandLogo serves the bundle's mark from the bytes captured at load
// (containment- and size-checked then), so nothing on disk is consulted per
// request and a later bundle change cannot redirect this route to another
// file. SVG can carry script, so the response is sandboxed in case someone
// opens it directly rather than as an <img>.
func (s *Server) handleBrandLogo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	b := s.cfg.Brand
	if b == nil || len(b.Logo) == 0 {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", b.LogoContentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
	// A re-theme is a restart away; five minutes keeps every page load from
	// re-fetching while letting a new mark show up promptly.
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Del("Pragma")
	http.ServeContent(w, r, "", s.started, bytes.NewReader(b.Logo))
}

// writeJSON encodes v with encoding/json so every string is escaped by JSON
// rules. fmt's %q is Go-syntax quoting and can emit \a or \xNN, which a
// JSON parser rejects.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		// Pages replace this with a nonce policy in render(); JSON,
		// redirects, and errors keep the closed default.
		w.Header().Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'")
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
