package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/elcanotek/auth/internal/mfa"
	passwordauth "github.com/elcanotek/auth/internal/password"
	"github.com/elcanotek/auth/internal/store"
)

// Second-factor flows. Three surfaces share the pieces below:
//
//   - The incomplete login. When the password verifies but the account has
//     a factor, or policy requires one, no session is minted. A login
//     transaction (store.AuthTransaction) is opened instead, its token in a
//     host-only cookie, and the browser walks the stages that remain:
//     factor (/login/verify), forced password change (/change-password) and
//     enrolment (/login/enroll). The last stage completes the transaction
//     and mints the session in one store transaction, so a password alone
//     never produces a session for such an account.
//   - Account → Security (/account/security): set up, replace or turn off an
//     authenticator and regenerate recovery codes, behind a fresh
//     re-verification (/account/security/verify).
//   - The assurance gate (assuredIdentity) every signed-in page and the
//     authorization handoff ask before treating a session as sufficient.
//
// Codes and secrets travel only in POST bodies and rendered pages marked
// no-store; they never appear in URLs, logs or audit rows.

const (
	stageFactor         = "factor"
	stagePasswordChange = "password_change"
	stageEnroll         = "enroll"
	stageComplete       = "complete" // a password change with nothing left after it

	challengeTTL = 5 * time.Minute  // factor step, password change
	enrollTTL    = 10 * time.Minute // enrolment: scanning a QR takes longer
	reauthWindow = 5 * time.Minute  // how long a fresh password check is honoured

	errMFALocked   = "mfa_locked"
	errMFAExpired  = "mfa_expired"
	noticeMFAReset = "mfa_reset"

	// Separate ceilings (issue #48 §7), all on the shared 15-minute window
	// and all temporary cooldowns, never permanent lockouts:
	//   - mfaGlobalLimit: factor attempts across every account, so one
	//     deployment-wide flood cannot spend everybody's per-account budget
	//     unnoticed (the per-account and per-address limits still apply).
	//   - mfaEnrolLimit: fresh enrolment secrets generated per account.
	//   - mfaResetLimit: administrator resets per acting administrator.
	mfaGlobalLimit = 1000
	mfaEnrolLimit  = 5
	mfaResetLimit  = 10
)

// errEnrolLimited: too many fresh enrolment secrets for one account in the
// window; the person waits rather than being locked out.
var errEnrolLimited = errors.New("too many enrolment attempts")

type loginTxMeta struct {
	ReturnTo string `json:"return_to,omitempty"`
}

func (s *Server) loginTxCookieName() string {
	if s.cfg.CookieSecure {
		return "__Host-auth_login"
	}
	return "auth_login"
}

// mfaAvailable: the deployment has an encryption key, so factors can be
// sealed. Without one every 2FA surface says so instead of failing.
func (s *Server) mfaAvailable() bool { return s.cfg.MFAKeyring != nil }

func (s *Server) mfaPolicy(r *http.Request) store.MFAPolicy {
	policy, err := s.store.MFAPolicy(r.Context())
	if err != nil {
		// Fail closed: an unreadable policy is treated as the strictest one.
		logUnlessCancelled("mfa policy", err)
		return store.MFAPolicy{Mode: mfa.ModeEveryone}
	}
	return policy
}

// factorNeeded: the account has a factor, or something requires one.
func factorNeeded(a store.Account, mode mfa.Mode) bool {
	return a.MFAEnrolled || mfa.Required(mode, a.IsAdmin, a.MFARequired)
}

// firstStage is where an incomplete login starts: an existing factor is
// proven first, then the forced password change, then enrolment.
func firstStage(a store.Account) string {
	switch {
	case a.MFAEnrolled:
		return stageFactor
	case a.MustChangePassword:
		return stagePasswordChange
	default:
		return stageEnroll
	}
}

// nextStage is what follows the stage just finished, or "" when the login
// can complete.
func nextStage(done string, a store.Account, mode mfa.Mode) string {
	mustEnroll := !a.MFAEnrolled && mfa.Required(mode, a.IsAdmin, a.MFARequired)
	switch done {
	case stageFactor:
		if a.MustChangePassword {
			return stagePasswordChange
		}
		if mustEnroll {
			return stageEnroll
		}
	case stagePasswordChange:
		if mustEnroll {
			return stageEnroll
		}
	}
	return ""
}

func stagePath(stage string) string {
	switch stage {
	case stageFactor:
		return "/login/verify"
	case stagePasswordChange:
		return "/change-password"
	case stageEnroll:
		return "/login/enroll"
	}
	return "/"
}

func stageTTL(stage string) time.Duration {
	if stage == stageEnroll {
		return enrollTTL
	}
	return challengeTTL
}

// beginLoginTransaction replaces session issuance for an account that needs
// more than a password. It records where the person was going and sends
// them to the first outstanding stage.
func (s *Server) beginLoginTransaction(w http.ResponseWriter, r *http.Request, account store.Account, policy store.MFAPolicy, dest string, now time.Time) error {
	raw, err := randomSecret(32)
	if err != nil {
		return err
	}
	id, err := randomSecret(16)
	if err != nil {
		return err
	}
	stage := firstStage(account)
	meta, _ := json.Marshal(loginTxMeta{ReturnTo: dest})
	tr := store.AuthTransaction{
		ID: id, UserID: account.ID, Purpose: "login", Stage: stage, StateHash: hashSecret(raw), Metadata: string(meta),
		CredentialHash: account.PasswordHash, SecurityVersion: account.SecurityVersion, PolicyRevision: policy.Revision,
		MaxAttempts: 5, ExpiresAt: now.Add(stageTTL(stage)),
	}
	if err := s.store.CreateAuthTransaction(r.Context(), tr, now.Unix()); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name: s.loginTxCookieName(), Value: raw, Path: "/", MaxAge: int(enrollTTL.Seconds()),
		Secure: s.cfg.CookieSecure, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, stagePath(stage), http.StatusSeeOther)
	return nil
}

func (s *Server) clearLoginTxCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: s.loginTxCookieName(), Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(1, 0),
		Secure: s.cfg.CookieSecure, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

// currentLoginTransaction loads the browser's incomplete login and the
// account it belongs to. Any problem (no cookie, expired, stale after a
// password reset or factor change) reads as "start over".
func (s *Server) currentLoginTransaction(r *http.Request) (store.AuthTransaction, store.Account, bool) {
	c, err := r.Cookie(s.loginTxCookieName())
	if err != nil || c.Value == "" {
		return store.AuthTransaction{}, store.Account{}, false
	}
	tr, err := s.store.AuthTransactionByState(r.Context(), hashSecret(c.Value), time.Now().Unix())
	if err != nil {
		return store.AuthTransaction{}, store.Account{}, false
	}
	account, err := s.store.PasswordAccountByID(r.Context(), tr.UserID)
	if err != nil || account.DisabledAt != nil {
		return store.AuthTransaction{}, store.Account{}, false
	}
	return tr, account, true
}

func (s *Server) loginTxDest(tr store.AuthTransaction) string {
	var meta loginTxMeta
	_ = json.Unmarshal([]byte(tr.Metadata), &meta)
	dest := s.resolveReturnTo(meta.ReturnTo)
	if dest == "" {
		dest = s.defaultDest()
	}
	return dest
}

// restartLogin abandons the incomplete login and sends the browser back to
// the sign-in page with a reason.
func (s *Server) restartLogin(w http.ResponseWriter, r *http.Request, tr store.AuthTransaction, code string) {
	if tr.ID != "" {
		_ = s.store.AbandonAuthTransaction(r.Context(), tr.ID)
	}
	s.clearLoginTxCookie(w)
	q := url.Values{}
	if code != "" {
		q.Set("err", code)
	}
	if tr.ID != "" {
		if dest := s.loginTxDest(tr); dest != s.defaultDest() {
			q.Set("return_to", dest)
		}
	}
	location := "/"
	if len(q) > 0 {
		location += "?" + q.Encode()
	}
	http.Redirect(w, r, location, http.StatusSeeOther)
}

// setSessionCookies is the browser half of session issuance, shared by the
// password-only path and every login completion.
func (s *Server) setSessionCookies(w http.ResponseWriter, rawSession, csrf string, absolute time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name: s.cfg.PasswordCookieName, Value: rawSession, Path: "/",
		MaxAge: int(s.cfg.PasswordAbsoluteTTL.Seconds()), Expires: absolute,
		Secure: s.cfg.CookieSecure, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	s.setCSRFCookie(w, csrf)
}

func (s *Server) sessionWindow(now time.Time) (idle, absolute time.Time) {
	idle = now.Add(s.cfg.PasswordIdleTTL)
	absolute = now.Add(s.cfg.PasswordAbsoluteTTL)
	if idle.After(absolute) {
		idle = absolute
	}
	return idle, absolute
}

// completeLogin finishes an incomplete login with the given proof: the store
// consumes the transaction and mints the session in one transaction, then
// the browser gets its cookies and goes where it was headed.
func (s *Server) completeLogin(w http.ResponseWriter, r *http.Request, tr store.AuthTransaction, account store.Account, proof store.LoginProof, now time.Time) error {
	raw, err := randomSecret(32)
	if err != nil {
		return err
	}
	csrf, err := randomSecret(32)
	if err != nil {
		return err
	}
	idle, absolute := s.sessionWindow(now)
	if _, err := s.store.CompleteLogin(r.Context(), tr.ID, tr.Stage, hashSecret(raw), proof, now.Unix(), idle.Unix(), absolute.Unix()); err != nil {
		return err
	}
	s.setSessionCookies(w, raw, csrf, absolute)
	s.clearLoginTxCookie(w)
	_ = s.store.RecordAudit(r.Context(), "login.succeeded", account.ID, s.rateKey("ip", clientIP(r)), now.Unix())
	http.Redirect(w, r, s.loginTxDest(tr), http.StatusSeeOther)
	return nil
}

// ── sealing helpers ─────────────────────────────────────────────────

func (s *Server) sealSecret(authenticatorID, userID string, secret []byte) ([]byte, error) {
	return s.cfg.MFAKeyring.Seal(secret, mfa.AAD(authenticatorID, userID, store.AuthenticatorTOTP))
}

// openSecret decrypts a factor's secret and reports whether it should be
// re-sealed under the active key (rewrapped bytes are returned for the
// store to write alongside the next accepted step).
func (s *Server) openSecret(f store.Authenticator) (secret, rewrapped []byte, keyID string, err error) {
	secret, usedKey, err := s.cfg.MFAKeyring.Open(f.Ciphertext, mfa.AAD(f.ID, f.UserID, store.AuthenticatorTOTP))
	if err != nil {
		return nil, nil, "", err
	}
	if s.cfg.MFAKeyring.NeedsRewrap(usedKey) {
		if rewrapped, err = s.sealSecret(f.ID, f.UserID, secret); err != nil {
			return nil, nil, "", err
		}
		keyID = s.cfg.MFAKeyring.ActiveID()
	}
	return secret, rewrapped, keyID, nil
}

// factorProof turns what the person typed into a store proof against the
// account's active factor: a TOTP code (with the replay guard's step) or a
// recovery code. ok is false when neither verifies. The TOTP check happens
// here; its single-use recording happens in the store transaction that
// consumes the proof.
func (s *Server) factorProof(r *http.Request, account store.Account, code, recovery string, now time.Time) (store.LoginProof, bool) {
	if recovery = mfa.NormalizeRecoveryCode(recovery); recovery != "" {
		return store.LoginProof{Kind: store.ProofRecovery, RecoveryCodeHash: mfa.HashRecoveryCode(recovery)}, true
	}
	f, err := s.store.ActiveAuthenticator(r.Context(), account.ID)
	if err != nil {
		return store.LoginProof{}, false
	}
	secret, rewrapped, keyID, err := s.openSecret(f)
	if err != nil {
		// A secret that cannot be opened (missing key, corrupt ciphertext)
		// fails closed; the operator sees why in the log, the user sees a
		// generic refusal.
		log.Printf("mfa: open secret for %s: %v", f.ID, err)
		return store.LoginProof{}, false
	}
	step, ok := mfa.Verify(secret, code, now, f.LastAcceptedStep)
	if !ok {
		return store.LoginProof{}, false
	}
	return store.LoginProof{Kind: store.ProofTOTP, AuthenticatorID: f.ID, Step: step, Rewrapped: rewrapped, KeyID: keyID}, true
}

// mfaAttempt reserves one failure across the account and the address the
// way password attempts do (the same limits apply), returning the
// reservation ids to settle on success. limited means the caller must refuse
// without checking anything.
func (s *Server) mfaAttempt(r *http.Request, userID string, now time.Time) (ids []int64, ipKey string, limited bool, err error) {
	ipKey = s.rateKey("ip", clientIP(r))
	// The deployment-wide ceiling is checked first and never settled, so
	// every attempt counts toward it whatever its outcome.
	globalLimited, err := s.reserveCounted(r.Context(), s.rateKey("mfa-global", "all"), mfaGlobalLimit, now)
	if err != nil || globalLimited {
		return nil, ipKey, globalLimited, err
	}
	ids, limited, err = s.reserveLoginAttempt(r.Context(), s.rateKey("mfa-user", userID), ipKey, now)
	return ids, ipKey, limited, err
}

// reserveCounted is a plain counter on the login_attempts table for the
// separate MFA ceilings: it reports whether key has reached max in the
// window and, if not, records one more occurrence. Rows are never settled,
// so the count is of occurrences, not failures, and it persists across
// restarts like every other limit here.
func (s *Server) reserveCounted(ctx context.Context, key string, max int, now time.Time) (bool, error) {
	if err := acquire(ctx, s.attemptGate); err != nil {
		return false, err
	}
	defer release(s.attemptGate)
	n, err := s.store.CountFailedLoginAttempts(ctx, key, now.Add(-passwordRateWindow).Unix())
	if err != nil {
		return false, err
	}
	if n >= max {
		return true, nil
	}
	_, err = s.store.ReserveLoginAttempts(ctx, now.Unix(), key)
	return false, err
}

// ── /login/verify ───────────────────────────────────────────────────

func (s *Server) handleLoginVerify(w http.ResponseWriter, r *http.Request) {
	if !s.passwordMode() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	tr, account, ok := s.currentLoginTransaction(r)
	if !ok || tr.Stage != stageFactor {
		s.restartLogin(w, r, store.AuthTransaction{}, errMFAExpired)
		return
	}
	csrf, err := s.ensureCSRFCookie(w, r)
	if err != nil {
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}
	remaining, _ := s.store.RecoveryCodesRemaining(r.Context(), account.ID)
	render := func(errText string) {
		if err := s.render(w, "mfa-verify.html", map[string]any{
			"Brand": s.cfg.BrandName, "Email": account.Email, "CSRF": csrf, "Error": errText,
			"HasRecovery": remaining > 0, "Recovery": r.URL.Query().Get("mode") == "recovery" || r.FormValue("mode") == "recovery",
		}); err != nil {
			log.Printf("render mfa verify: %v", err)
		}
	}
	switch r.Method {
	case http.MethodGet:
		render("")
		return
	case http.MethodPost:
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !s.validCSRF(r) {
		render(staleFormMessage)
		return
	}
	if r.FormValue("cancel") != "" {
		s.restartLogin(w, r, tr, "")
		return
	}
	now := time.Now()
	left, err := s.store.RecordTransactionAttempt(r.Context(), tr.ID)
	if errors.Is(err, store.ErrTooManyAttempts) {
		_ = s.store.RecordAudit(r.Context(), "login.mfa_locked", account.ID, s.rateKey("ip", clientIP(r)), now.Unix())
		s.restartLogin(w, r, tr, errMFALocked)
		return
	}
	if err != nil {
		logUnlessCancelled("mfa attempt", err)
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}
	ids, ipKey, limited, err := s.mfaAttempt(r, account.ID, now)
	if err != nil {
		logUnlessCancelled("mfa rate limit", err)
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}
	if limited {
		_, _ = s.store.RecordAuditIfAbsent(r.Context(), "login.mfa_rate_limited", account.ID, ipKey, now.Unix(), now.Add(-passwordRateWindow).Unix())
		render("Too many attempts. Wait a few minutes and try again.")
		return
	}
	proof, verified := s.factorProof(r, account, r.FormValue("code"), r.FormValue("recovery_code"), now)
	fail := func() {
		_ = s.store.RecordAudit(r.Context(), "login.mfa_failed", account.ID, ipKey, now.Unix())
		if left <= 0 {
			_ = s.store.AbandonAuthTransaction(r.Context(), tr.ID)
			_ = s.store.RecordAudit(r.Context(), "login.mfa_locked", account.ID, ipKey, now.Unix())
			s.restartLogin(w, r, store.AuthTransaction{}, errMFALocked)
			return
		}
		render("That code did not work. Check the time on your phone and try the current code.")
	}
	if !verified {
		fail()
		return
	}
	policy := s.mfaPolicy(r)
	next := nextStage(stageFactor, account, policy.Mode)
	if next == "" {
		err = s.completeLogin(w, r, tr, account, proof, now)
	} else {
		err = s.store.RecordFactorForTransaction(r.Context(), tr.ID, stageFactor, next, proof, now.Unix(), now.Add(stageTTL(next)).Unix())
	}
	switch {
	case errors.Is(err, store.ErrInvalidProof):
		fail()
		return
	case errors.Is(err, store.ErrTransactionNotFound), errors.Is(err, store.ErrStaleTransaction), errors.Is(err, store.ErrInvalidSession):
		s.restartLogin(w, r, store.AuthTransaction{}, errMFAExpired)
		return
	case err != nil:
		logUnlessCancelled("mfa completion", err)
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}
	_ = s.store.SettleLoginAttemptSuccess(r.Context(), ids[0], ids[1])
	if proof.Kind == store.ProofRecovery {
		_ = s.store.RecordAudit(r.Context(), "login.recovery_code_used", account.ID, ipKey, now.Unix())
		s.notify(account.Email, "A recovery code was used to sign in", "A recovery code signed in to your "+s.cfg.BrandName+" account. If this was not you, contact your administrator; if you lost your authenticator, set up a new one from Security.")
	}
	if next != "" {
		http.Redirect(w, r, stagePath(next), http.StatusSeeOther)
	}
}

// ── enrolment (shared by /login/enroll and Account → Security) ─────

// enrolmentView prepares the QR and manual key for the account's pending
// enrolment, creating one when none is live. The secret is generated here,
// sealed, and only ever rendered into this response.
func (s *Server) enrolmentView(r *http.Request, account store.Account, now time.Time) (map[string]any, error) {
	pending, err := s.store.PendingAuthenticator(r.Context(), account.ID, now.Unix())
	var secret []byte
	if errors.Is(err, store.ErrPendingNotFound) {
		// Generating a secret is cheap for us and free for an attacker to
		// trigger, so fresh secrets per account are capped separately.
		limited, err := s.reserveCounted(r.Context(), s.rateKey("mfa-enroll", account.ID), mfaEnrolLimit, now)
		if err != nil {
			return nil, err
		}
		if limited {
			return nil, errEnrolLimited
		}
		secret, err = mfa.NewSecret()
		if err != nil {
			return nil, err
		}
		id, err := randomSecret(16)
		if err != nil {
			return nil, err
		}
		sealed, err := s.sealSecret(id, account.ID, secret)
		if err != nil {
			return nil, err
		}
		if err := s.store.CreatePendingAuthenticator(r.Context(), id, account.ID, "", sealed, s.cfg.MFAKeyring.ActiveID(), now.Unix(), now.Add(enrollTTL).Unix()); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else {
		secret, _, _, err = s.openSecret(pending)
		if err != nil {
			return nil, err
		}
	}
	key, err := mfa.Key(s.cfg.MFAIssuer, account.Email, secret)
	if err != nil {
		return nil, err
	}
	png, err := mfa.QRPNG(key, 220)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		// template.URL: the PNG bytes came from our own encoder and the CSP
		// already permits img-src data:. Nothing else on the page is marked.
		"QR":        template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png)),
		"ManualKey": groupSecret(mfa.Base32Secret(secret)),
		"Issuer":    s.cfg.MFAIssuer,
		"Email":     account.Email,
	}, nil
}

// groupSecret spaces the manual key in fours so it can be read aloud or
// typed; authenticator apps ignore the spaces.
func groupSecret(b32 string) string {
	var b strings.Builder
	for i, r := range b32 {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// confirmEnrolment checks the first code against the pending secret and
// returns the pending row and matched step for activation.
func (s *Server) confirmEnrolment(r *http.Request, account store.Account, code string, now time.Time) (store.Authenticator, int64, bool) {
	pending, err := s.store.PendingAuthenticator(r.Context(), account.ID, now.Unix())
	if err != nil {
		return store.Authenticator{}, 0, false
	}
	secret, _, _, err := s.openSecret(pending)
	if err != nil {
		log.Printf("mfa: open pending secret for %s: %v", pending.ID, err)
		return store.Authenticator{}, 0, false
	}
	step, ok := mfa.Verify(secret, code, now, -1)
	if !ok {
		return store.Authenticator{}, 0, false
	}
	return pending, step, true
}

func newRecoverySet() ([]string, []string, string, error) {
	codes, err := mfa.GenerateRecoveryCodes()
	if err != nil {
		return nil, nil, "", err
	}
	hashes := make([]string, 0, len(codes))
	for _, c := range codes {
		hashes = append(hashes, mfa.HashRecoveryCode(mfa.NormalizeRecoveryCode(c)))
	}
	setID, err := randomSecret(8)
	if err != nil {
		return nil, nil, "", err
	}
	return codes, hashes, setID, nil
}

func (s *Server) renderRecoveryCodes(w http.ResponseWriter, codes []string, continueTo, title string) {
	w.Header().Set("Cache-Control", "no-store")
	if err := s.render(w, "recovery-codes.html", map[string]any{
		"Brand": s.cfg.BrandName, "Codes": codes, "ContinueTo": continueTo, "Title": title,
	}); err != nil {
		log.Printf("render recovery codes: %v", err)
	}
}

// ── /login/enroll ───────────────────────────────────────────────────

func (s *Server) handleLoginEnroll(w http.ResponseWriter, r *http.Request) {
	if !s.passwordMode() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	tr, account, ok := s.currentLoginTransaction(r)
	if !ok || tr.Stage != stageEnroll {
		s.restartLogin(w, r, store.AuthTransaction{}, errMFAExpired)
		return
	}
	if !s.mfaAvailable() {
		// Policy demands a factor the server cannot store. Say so instead of
		// looping; the operator has to set AUTH_MFA_KEY.
		_ = s.store.AbandonAuthTransaction(r.Context(), tr.ID)
		s.clearLoginTxCookie(w)
		if err := s.renderStatus(w, http.StatusServiceUnavailable, "status.html", map[string]any{
			"Brand": s.cfg.BrandName, "Title": "Two-factor sign-in is not set up on this server",
			"Message": "Your account requires an authenticator app, but this server has no key configured to store one. Ask your administrator to configure AUTH_MFA_KEY.",
		}); err != nil {
			log.Printf("render mfa unavailable: %v", err)
		}
		return
	}
	csrf, err := s.ensureCSRFCookie(w, r)
	if err != nil {
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}
	now := time.Now()
	render := func(errText string) {
		view, err := s.enrolmentView(r, account, now)
		if errors.Is(err, errEnrolLimited) {
			s.restartLogin(w, r, tr, errMFALocked)
			return
		}
		if err != nil {
			log.Printf("mfa enrolment view: %v", err)
			http.Error(w, "something went wrong", http.StatusInternalServerError)
			return
		}
		view["Brand"], view["CSRF"], view["Error"], view["Action"], view["Required"] = s.cfg.BrandName, csrf, errText, "/login/enroll", true
		if err := s.render(w, "mfa-enroll.html", view); err != nil {
			log.Printf("render mfa enroll: %v", err)
		}
	}
	switch r.Method {
	case http.MethodGet:
		render("")
		return
	case http.MethodPost:
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !s.validCSRF(r) {
		render(staleFormMessage)
		return
	}
	if r.FormValue("cancel") != "" {
		s.restartLogin(w, r, tr, "")
		return
	}
	left, err := s.store.RecordTransactionAttempt(r.Context(), tr.ID)
	if err != nil {
		if errors.Is(err, store.ErrTooManyAttempts) {
			s.restartLogin(w, r, tr, errMFALocked)
			return
		}
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}
	ids, ipKey, limited, err := s.mfaAttempt(r, account.ID, now)
	if err != nil {
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}
	if limited {
		_, _ = s.store.RecordAuditIfAbsent(r.Context(), "login.mfa_rate_limited", account.ID, ipKey, now.Unix(), now.Add(-passwordRateWindow).Unix())
		render("Too many attempts. Wait a few minutes and try again.")
		return
	}
	pending, step, verified := s.confirmEnrolment(r, account, r.FormValue("code"), now)
	if !verified {
		_ = s.store.RecordAudit(r.Context(), "login.mfa_failed", account.ID, ipKey, now.Unix())
		if left <= 0 {
			_ = s.store.AbandonAuthTransaction(r.Context(), tr.ID)
			s.restartLogin(w, r, store.AuthTransaction{}, errMFALocked)
			return
		}
		render("That code did not match. Scan the QR code again if you need to, then enter the current code.")
		return
	}
	_ = s.store.SettleLoginAttemptSuccess(r.Context(), ids[0], ids[1])
	codes, hashes, setID, err := newRecoverySet()
	if err != nil {
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}
	raw, err := randomSecret(32)
	if err != nil {
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}
	csrfNew, err := randomSecret(32)
	if err != nil {
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}
	idle, absolute := s.sessionWindow(now)
	completion := &store.LoginCompletion{TransactionID: tr.ID, Stage: stageEnroll, TokenHash: hashSecret(raw), IdleExpiresAt: idle.Unix(), AbsoluteAt: absolute.Unix()}
	if _, err := s.store.ActivateAuthenticator(r.Context(), pending.ID, account.ID, step, hashes, setID, "", completion, now.Unix()); err != nil {
		if errors.Is(err, store.ErrTransactionNotFound) || errors.Is(err, store.ErrStaleTransaction) || errors.Is(err, store.ErrPendingNotFound) {
			s.restartLogin(w, r, store.AuthTransaction{}, errMFAExpired)
			return
		}
		logUnlessCancelled("activate authenticator", err)
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}
	s.setSessionCookies(w, raw, csrfNew, absolute)
	s.clearLoginTxCookie(w)
	_ = s.store.RecordAudit(r.Context(), "login.succeeded", account.ID, s.rateKey("ip", clientIP(r)), now.Unix())
	s.notify(account.Email, "Two-factor sign-in turned on", "An authenticator app was set up on your "+s.cfg.BrandName+" account and every other session was signed out. If this was not you, contact your administrator.")
	s.renderRecoveryCodes(w, codes, s.loginTxDest(tr), "Authenticator set up")
}

// handleLoginCancel lets a person abandon an incomplete login.
func (s *Server) handleLoginCancel(w http.ResponseWriter, r *http.Request) {
	if !s.passwordMode() || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil || !s.validCSRF(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	tr, account, ok := s.currentLoginTransaction(r)
	if ok {
		// A cancelled enrolment leaves no half-generated secret behind.
		_ = s.store.AbandonPendingAuthenticator(r.Context(), account.ID)
	}
	s.restartLogin(w, r, tr, "")
}

// ── the assurance gate ──────────────────────────────────────────────

// assuredIdentity returns the signed-in identity when its session carries
// the evidence the account's policy demands, and otherwise sends the browser
// where it has to go: sign-in, the forced password change, enrolment, or (a
// session that predates a factor change) sign-in after clearing the
// cookies. allowEnrollment lets the Security page itself serve an account
// that still has to enrol. The caller returns as soon as nil comes back.
func (s *Server) assuredIdentity(w http.ResponseWriter, r *http.Request, allowEnrollment bool) *passwordIdentity {
	identity := s.currentPasswordSession(r)
	if identity == nil {
		http.Redirect(w, r, "/?return_to="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return nil
	}
	switch store.Assess(identity.Account, identity.Session, s.mfaPolicy(r).Mode) {
	case store.AssuranceOK:
		return identity
	case store.AssuranceMustChangePassword:
		http.Redirect(w, r, "/change-password?return_to="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
	case store.AssuranceEnrollmentRequired:
		if allowEnrollment {
			return identity
		}
		http.Redirect(w, r, "/account/security?return_to="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
	default:
		// The session never proved a factor the account now has (or it
		// predates a factor change). Nothing a page can offer fixes that:
		// sign in again.
		s.clearPasswordCookies(w)
		http.Redirect(w, r, "/?return_to="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
	}
	return nil
}

// ── Account → Security ──────────────────────────────────────────────

// recentlyVerified: the session was created, or re-verified, within the
// re-authentication window, so a sensitive action may proceed.
func recentlyVerified(sess store.AuthSession, now time.Time, window time.Duration) bool {
	if now.Sub(sess.CreatedAt) <= window {
		return true
	}
	return sess.ReauthAt != nil && now.Sub(*sess.ReauthAt) <= window
}

// reauthWindow is five minutes unless the configuration says otherwise
// (tests shrink it to force the step-up).
func (s *Server) reauthWindow() time.Duration {
	if s.cfg.MFAReauthWindow > 0 {
		return s.cfg.MFAReauthWindow
	}
	return reauthWindow
}

// notify sends a short email about a security change when the deployment
// has a real email driver. Best effort: a failure is logged by tenant only,
// never blocks the change, and the message never carries codes or secrets.
// Password-mode boxes usually have no driver, in which case nothing is sent
// and the audit log remains the record.
func (s *Server) notify(to, subject, body string) {
	if s.sender == nil || s.cfg.EmailDriver == "" || s.cfg.EmailDriver == "stdout" {
		return
	}
	s.sends.Add(1)
	go func(to, subject, text string) {
		defer s.sends.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		html := "<!doctype html><html><body style=\"font:16px/1.5 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;color:#1a1a1a;padding:24px\"><p>" + template.HTMLEscapeString(text) + "</p></body></html>"
		if err := s.sender.Send(ctx, to, subject, text, html); err != nil {
			log.Printf("send security notice failed (tenant=%s): %v", emailTenant(to), err)
		}
	}(to, subject, body)
}

var securityActions = map[string]bool{"start": true, "confirm": true, "regenerate": true, "disable": true}

func (s *Server) handleAccountSecurity(w http.ResponseWriter, r *http.Request) {
	if !s.passwordMode() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	identity := s.assuredIdentity(w, r, true)
	if identity == nil {
		return
	}
	account := identity.Account
	policy := s.mfaPolicy(r)
	required := mfa.Required(policy.Mode, account.IsAdmin, account.MFARequired)
	csrf, err := s.ensureCSRFCookie(w, r)
	if err != nil {
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}
	now := time.Now()
	returnTo := s.resolveReturnTo(r.URL.Query().Get("return_to"))
	if returnTo == "" {
		returnTo = s.resolveReturnTo(r.FormValue("return_to"))
	}
	renderPage := func(notice, errText string) {
		remaining, _ := s.store.RecoveryCodesRemaining(r.Context(), account.ID)
		data := map[string]any{
			"Brand": s.cfg.BrandName, "Email": account.Email, "CSRF": csrf, "Notice": notice, "Error": errText,
			"Enrolled": account.MFAEnrolled, "Required": required, "Available": s.mfaAvailable(),
			"Status": string(mfa.StatusFor(required, account.MFAEnrolled)), "Remaining": remaining,
			"UsedRecovery": hasMethod(identity.Session.AMR, "mfa"), "ReturnTo": returnTo, "IsAdmin": account.IsAdmin,
		}
		if err := s.render(w, "security.html", data); err != nil {
			log.Printf("render security: %v", err)
		}
	}
	if r.Method == http.MethodGet {
		notice := ""
		if r.URL.Query().Get("verified") == "1" {
			notice = "Verified. You can make changes for the next five minutes."
		}
		renderPage(notice, "")
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
		renderPage("", staleFormMessage)
		return
	}
	action := r.FormValue("action")
	if !securityActions[action] {
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}
	if !s.mfaAvailable() {
		renderPage("", "Two-factor sign-in is not set up on this server. Ask your administrator to configure AUTH_MFA_KEY.")
		return
	}
	// Every action is sensitive: it needs a fresh password (and factor).
	if !recentlyVerified(identity.Session, now, s.reauthWindow()) {
		q := url.Values{"action": {action}}
		if returnTo != "" {
			q.Set("return_to", returnTo)
		}
		http.Redirect(w, r, "/account/security/verify?"+q.Encode(), http.StatusSeeOther)
		return
	}
	switch action {
	case "start":
		view, err := s.enrolmentView(r, account, now)
		if errors.Is(err, errEnrolLimited) {
			renderPage("", "Too many set-up attempts. Wait a few minutes and try again.")
			return
		}
		if err != nil {
			log.Printf("mfa enrolment view: %v", err)
			http.Error(w, "something went wrong", http.StatusInternalServerError)
			return
		}
		view["Brand"], view["CSRF"], view["Action"], view["Required"], view["ReturnTo"] = s.cfg.BrandName, csrf, "/account/security", required, returnTo
		view["Replace"] = account.MFAEnrolled
		if err := s.render(w, "mfa-enroll.html", view); err != nil {
			log.Printf("render mfa enroll: %v", err)
		}
	case "confirm":
		pending, step, verified := s.confirmEnrolment(r, account, r.FormValue("code"), now)
		if !verified {
			view, err := s.enrolmentView(r, account, now)
			if err != nil {
				http.Error(w, "something went wrong", http.StatusInternalServerError)
				return
			}
			view["Brand"], view["CSRF"], view["Action"], view["Required"], view["ReturnTo"] = s.cfg.BrandName, csrf, "/account/security", required, returnTo
			view["Replace"], view["Error"] = account.MFAEnrolled, "That code did not match. Enter the current code from your authenticator app."
			if err := s.render(w, "mfa-enroll.html", view); err != nil {
				log.Printf("render mfa enroll: %v", err)
			}
			return
		}
		codes, hashes, setID, err := newRecoverySet()
		if err != nil {
			http.Error(w, "something went wrong", http.StatusInternalServerError)
			return
		}
		if _, err := s.store.ActivateAuthenticator(r.Context(), pending.ID, account.ID, step, hashes, setID, identity.Session.TokenHash, nil, now.Unix()); err != nil {
			if errors.Is(err, store.ErrInvalidSession) {
				s.clearPasswordCookies(w)
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
			logUnlessCancelled("activate authenticator", err)
			http.Error(w, "something went wrong", http.StatusInternalServerError)
			return
		}
		dest := returnTo
		if dest == "" {
			dest = "/account/security"
		}
		title := "Authenticator set up"
		if account.MFAEnrolled {
			title = "Authenticator replaced"
			s.notify(account.Email, "Authenticator replaced", "The authenticator app on your "+s.cfg.BrandName+" account was replaced and every other session was signed out. If this was not you, contact your administrator.")
		} else {
			s.notify(account.Email, "Two-factor sign-in turned on", "An authenticator app was set up on your "+s.cfg.BrandName+" account and every other session was signed out. If this was not you, contact your administrator.")
		}
		s.renderRecoveryCodes(w, codes, dest, title)
	case "regenerate":
		codes, hashes, setID, err := newRecoverySet()
		if err != nil {
			http.Error(w, "something went wrong", http.StatusInternalServerError)
			return
		}
		if err := s.store.ReplaceRecoveryCodes(r.Context(), account.ID, hashes, setID, now.Unix()); err != nil {
			if errors.Is(err, store.ErrNoAuthenticator) {
				renderPage("", "Set up an authenticator first.")
				return
			}
			logUnlessCancelled("regenerate recovery codes", err)
			http.Error(w, "something went wrong", http.StatusInternalServerError)
			return
		}
		s.notify(account.Email, "New recovery codes", "New recovery codes were generated for your "+s.cfg.BrandName+" account; the old ones no longer work. If this was not you, contact your administrator.")
		s.renderRecoveryCodes(w, codes, "/account/security", "New recovery codes")
	case "disable":
		err := s.store.DisableAuthenticator(r.Context(), account.ID, identity.Session.TokenHash, now.Unix())
		switch {
		case errors.Is(err, store.ErrFactorRequired):
			renderPage("", "Your account is required to keep two-factor sign-in on. You can replace the authenticator instead.")
		case errors.Is(err, store.ErrNoAuthenticator):
			renderPage("", "There is no authenticator to turn off.")
		case errors.Is(err, store.ErrInvalidSession):
			s.clearPasswordCookies(w)
			http.Redirect(w, r, "/", http.StatusSeeOther)
		case err != nil:
			logUnlessCancelled("disable authenticator", err)
			http.Error(w, "something went wrong", http.StatusInternalServerError)
		default:
			s.notify(account.Email, "Two-factor sign-in turned off", "Two-factor sign-in was turned off on your "+s.cfg.BrandName+" account and every other session was signed out. If this was not you, contact your administrator.")
			http.Redirect(w, r, "/account/security?off=1", http.StatusSeeOther)
		}
	}
}

func hasMethod(amr []string, method string) bool {
	for _, m := range amr {
		if m == method {
			return true
		}
	}
	return false
}

// handleAccountSecurityVerify is the step-up page: the current password, and
// the authenticator code when one is enrolled, stamp the session as freshly
// verified for the re-authentication window.
func (s *Server) handleAccountSecurityVerify(w http.ResponseWriter, r *http.Request) {
	if !s.passwordMode() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	identity := s.assuredIdentity(w, r, true)
	if identity == nil {
		return
	}
	account := identity.Account
	csrf, err := s.ensureCSRFCookie(w, r)
	if err != nil {
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}
	action := r.URL.Query().Get("action")
	if action == "" {
		action = r.FormValue("action")
	}
	if !securityActions[action] {
		action = ""
	}
	returnTo := s.resolveReturnTo(r.URL.Query().Get("return_to"))
	if returnTo == "" {
		returnTo = s.resolveReturnTo(r.FormValue("return_to"))
	}
	render := func(errText string) {
		if err := s.render(w, "reauth.html", map[string]any{
			"Brand": s.cfg.BrandName, "Email": account.Email, "CSRF": csrf, "Error": errText,
			"Enrolled": account.MFAEnrolled, "Action": action, "ReturnTo": returnTo,
		}); err != nil {
			log.Printf("render reauth: %v", err)
		}
	}
	if r.Method == http.MethodGet {
		render("")
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
		render(staleFormMessage)
		return
	}
	now := time.Now()
	ipKey := s.rateKey("ip", clientIP(r))
	verified, valid, err := s.authenticatePassword(r.Context(), account.NormalizedEmail, r.FormValue("password"), ipKey, now, "reauth")
	if err != nil || !valid || verified.ID != account.ID {
		if err != nil {
			logUnlessCancelled("reauth password", err)
		}
		render("Password is incorrect.")
		return
	}
	if account.MFAEnrolled {
		// The same persistent limits as a login: a valid password must not
		// buy unlimited code guesses.
		ids, _, limited, err := s.mfaAttempt(r, account.ID, now)
		if err != nil {
			http.Error(w, "something went wrong", http.StatusInternalServerError)
			return
		}
		if limited {
			_, _ = s.store.RecordAuditIfAbsent(r.Context(), "reauth.mfa_rate_limited", account.ID, ipKey, now.Unix(), now.Add(-passwordRateWindow).Unix())
			render("Too many attempts. Wait a few minutes and try again.")
			return
		}
		proof, ok := s.factorProof(r, account, r.FormValue("code"), "", now)
		if !ok || proof.Kind != store.ProofTOTP {
			_ = s.store.RecordAudit(r.Context(), "reauth.mfa_failed", account.ID, ipKey, now.Unix())
			render("That code did not work. Enter the current code from your authenticator app.")
			return
		}
		// Replay guard and evidence upgrade in one store transaction, on the
		// account's active authenticator: a factor disabled meanwhile
		// refuses the proof instead of being papered over.
		err = s.store.VerifyFactorAndStampReauth(r.Context(), identity.Session.TokenHash, proof.AuthenticatorID, proof.Step, proof.Rewrapped, proof.KeyID, now.Unix())
		switch {
		case errors.Is(err, store.ErrInvalidProof):
			render("That code was already used. Wait for the next one.")
			return
		case errors.Is(err, store.ErrInvalidSession):
			s.clearPasswordCookies(w)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		case err != nil:
			logUnlessCancelled("step-up", err)
			http.Error(w, "something went wrong", http.StatusInternalServerError)
			return
		}
		_ = s.store.SettleLoginAttemptSuccess(r.Context(), ids[0], ids[1])
	} else if err := s.store.StampSessionReauth(r.Context(), identity.Session.TokenHash, now.Unix()); err != nil {
		s.clearPasswordCookies(w)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	// With no Security action pending, a caller such as the admin console
	// gets the browser back (the target was validated by resolveReturnTo).
	if action == "" && returnTo != "" {
		http.Redirect(w, r, returnTo, http.StatusSeeOther)
		return
	}
	// Back to the Security page; the action the person wanted is offered
	// again there (it is a POST, so it cannot be replayed from a link).
	q := url.Values{"verified": {"1"}}
	if action != "" {
		q.Set("action", action)
	}
	if returnTo != "" {
		q.Set("return_to", returnTo)
	}
	http.Redirect(w, r, "/account/security?"+q.Encode(), http.StatusSeeOther)
}

// amrClaims turns the session's stored method list into the id_token claim;
// a pre-v6 session recorded nothing and means password only.
func amrClaims(stored string) []string {
	if fields := strings.Fields(stored); len(fields) > 0 {
		return fields
	}
	return []string{"pwd"}
}

// acrFor names the assurance level: loa:1 is a password, loa:2 a password
// plus a second factor proven for this session.
func acrFor(mfaVerifiedAt int64) string {
	if mfaVerifiedAt > 0 {
		return "urn:elcanotek:loa:2"
	}
	return "urn:elcanotek:loa:1"
}

// changePasswordUnderTransaction is the forced first-login password change
// for an account whose login runs through a transaction (a factor was just
// proven, or one must be enrolled next). It mirrors handleChangePassword's
// checks, replaces the credential and re-binds the transaction to the new
// hash in one store transaction, then either continues to enrolment or
// completes the login with whatever factor evidence the transaction
// recorded.
func (s *Server) changePasswordUnderTransaction(w http.ResponseWriter, r *http.Request, tr store.AuthTransaction, account store.Account) {
	w.Header().Set("Cache-Control", "no-store")
	csrf, err := s.ensureCSRFCookie(w, r)
	if err != nil {
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}
	dest := s.loginTxDest(tr)
	if r.Method == http.MethodGet {
		s.renderChangePassword(w, "", csrf, dest)
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
		s.renderChangePassword(w, staleFormMessage, csrf, dest)
		return
	}
	current, next, confirm := r.FormValue("current_password"), r.FormValue("new_password"), r.FormValue("confirm_password")
	now := time.Now()
	ipRateKey := s.rateKey("ip", clientIP(r))
	verified, valid, authErr := s.authenticatePassword(r.Context(), account.NormalizedEmail, current, ipRateKey, now, "password_change")
	if authErr != nil || !valid || verified.ID != account.ID {
		if authErr != nil {
			logUnlessCancelled("password change authentication", authErr)
		}
		s.renderChangePassword(w, "Current password is incorrect.", csrf, dest)
		return
	}
	if next != confirm {
		s.renderChangePassword(w, "New passwords do not match.", csrf, dest)
		return
	}
	if subtle.ConstantTimeCompare([]byte(next), []byte(current)) == 1 {
		s.renderChangePassword(w, "New password must be different from the current password.", csrf, dest)
		return
	}
	if err := passwordauth.Validate(next, s.passwordContext(account.Email)...); err != nil {
		s.renderChangePassword(w, passwordauth.UserMessage(err), csrf, dest)
		return
	}
	encoded, err := s.hashPassword(r.Context(), next)
	if err != nil {
		s.renderChangePassword(w, passwordauth.UserMessage(err), csrf, dest)
		return
	}
	// What follows the change: enrolment when policy requires a factor the
	// account lacks, otherwise completion. The account is re-read after the
	// change below, but the requirement does not depend on the password.
	policy := s.mfaPolicy(r)
	after := account
	after.MustChangePassword = false
	following := nextStage(stagePasswordChange, after, policy.Mode)
	toStage := following
	if toStage == "" {
		toStage = stageComplete
	}
	err = s.store.ReplacePasswordUnderTransaction(r.Context(), tr.ID, stagePasswordChange, toStage, account.ID, verified.PasswordHash, encoded, now.Unix(), now.Add(stageTTL(toStage)).Unix())
	switch {
	case errors.Is(err, store.ErrCredentialChanged), errors.Is(err, store.ErrTransactionNotFound):
		s.restartLogin(w, r, store.AuthTransaction{}, errMFAExpired)
		return
	case err != nil:
		log.Printf("replace password under transaction: %v", err)
		s.renderChangePassword(w, "Something went wrong. Try again.", csrf, dest)
		return
	}
	if following != "" {
		http.Redirect(w, r, stagePath(following), http.StatusSeeOther)
		return
	}
	tr.Stage = stageComplete
	if err := s.completeLogin(w, r, tr, after, store.LoginProof{Kind: store.ProofRecorded}, now); err != nil {
		if errors.Is(err, store.ErrFactorRequired) || errors.Is(err, store.ErrTransactionNotFound) || errors.Is(err, store.ErrStaleTransaction) || errors.Is(err, store.ErrInvalidSession) {
			s.restartLogin(w, r, store.AuthTransaction{}, errMFAExpired)
			return
		}
		logUnlessCancelled("complete login after password change", err)
		http.Error(w, "something went wrong", http.StatusInternalServerError)
	}
}
