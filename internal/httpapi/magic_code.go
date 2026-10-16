package httpapi

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/elcanotek/auth/internal/store"
	"github.com/elcanotek/auth/internal/token"
)

// ── magic-link sign-in codes ─────────────────────────────────────────
//
// Every magic link also carries a six-digit code that signs in the browser
// that asked for it, typed on the "check your inbox" page. A link opens in
// the device's default browser, which is not always the one waiting:
//   - A Home Screen web app on iOS keeps its own cookie jar, so a link tapped
//     in Mail signs in Safari and leaves the app on the sign-in page.
//   - A sign-in started on a laptop and read on a phone signs in the phone.
// The code is bound to the requesting browser by a transaction cookie, so it
// is useless anywhere else. Link and code consume the same single-use nonce.
//
// The limits below are constants on purpose. They are security properties of
// a 10^6 code space, not operator policy:
//   - magicCodeMaxAttempts wrong tries kill a code (its link still works).
//   - magicCodeDailyFailures wrong codes per mailbox per magicCodeWindow
//     close code entry for that mailbox (links still work). Successes never
//     reset this budget, so a guesser gets at most that many tries a day
//     however many links they request: a 1-in-100,000 chance per day.

const (
	magicCodeDigits        = 6
	magicCodeMaxAttempts   = 5
	magicCodeDailyFailures = 10
	magicCodeWindow        = 24 * time.Hour
)

// errInvalidCode is the ONE error a code attempt ever reports. A wrong code,
// an expired or used one, a locked one, a mailbox over its daily budget, and
// a decoy cookie from the no-leak "sent" path all read the same, so code
// entry cannot reveal whether an address is allowed or a limit was hit.
const errInvalidCode = "invalid_code"

func (s *Server) magicTxCookieName() string {
	if s.cfg.CookieSecure {
		return "__Host-auth_magic_tx"
	}
	return "auth_magic_tx"
}

// setMagicTxCookie binds a code to this browser. It carries an explicit
// Max-Age equal to the link lifetime and must never be a session cookie: iOS
// can terminate a Home Screen web app while the person is reading Mail, and
// a session cookie would die with it, leaving the code unusable on return.
func (s *Server) setMagicTxCookie(w http.ResponseWriter, raw string) {
	http.SetCookie(w, &http.Cookie{
		Name: s.magicTxCookieName(), Value: raw, Path: "/",
		MaxAge: int(s.cfg.MagicTTL.Seconds()),
		Secure: s.cfg.CookieSecure, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearMagicTxCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: s.magicTxCookieName(), Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(1, 0),
		Secure: s.cfg.CookieSecure, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

// newMagicCode returns a uniformly random six-digit code. rand.Int draws
// without modulo bias.
func newMagicCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// magicCodeMAC keys the stored form of a code to this deployment and to its
// link's nonce, so a leaked database cannot be reversed by hashing all 10^6
// codes, and equal codes on different links never share a stored value.
func (s *Server) magicCodeMAC(nonce, code string) string {
	m := hmac.New(sha256.New, s.magicCodeKey)
	m.Write([]byte(nonce))
	m.Write([]byte{0})
	m.Write([]byte(code))
	return hex.EncodeToString(m.Sum(nil))
}

// normalizeMagicCode strips the spaces and dashes people type or paste and
// returns the six digits, or "" when the input is not a six-digit code.
func normalizeMagicCode(raw string) string {
	var b strings.Builder
	for _, r := range raw {
		switch {
		case r == ' ' || r == '-' || r == '\t':
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			return ""
		}
		if b.Len() > magicCodeDigits {
			return ""
		}
	}
	if b.Len() != magicCodeDigits {
		return ""
	}
	return b.String()
}

// sentLocation is the "check your inbox" page for email, optionally carrying
// an error code. Every outcome of POST /magic and every failed code attempt
// from that page lands here, so the page and its form stay in front of the
// person. returnTo must already have passed resolveReturnTo (or be ""); it
// rides along so "try again" can send the person back to the app that
// started the sign-in.
func sentLocation(email, errCode, returnTo string) string {
	q := url.Values{"email": {email}}
	if errCode != "" {
		q.Set("err", errCode)
	}
	if returnTo != "" {
		q.Set("return_to", returnTo)
	}
	return "/sent?" + q.Encode()
}

// loginLocation is the sign-in page with an error code and an already
// validated returnTo. A failed code typed on the sign-in page itself lands
// here; the transaction cookie is still set, so the page shows the code
// form again.
func loginLocation(errCode, returnTo string) string {
	q := url.Values{}
	if errCode != "" {
		q.Set("err", errCode)
	}
	if returnTo != "" {
		q.Set("return_to", returnTo)
	}
	if len(q) == 0 {
		return "/"
	}
	return "/?" + q.Encode()
}

// hasMagicTx reports whether this browser holds a magic transaction cookie.
// It is a presence check only and never consults the database: a decoy
// cookie from the no-leak path must look exactly like a real one, so the
// sign-in page cannot tell an enumerator which addresses got a code.
func (s *Server) hasMagicTx(r *http.Request) bool {
	c, err := r.Cookie(s.magicTxCookieName())
	return err == nil && c.Value != ""
}

// ── POST /magic/code ─────────────────────────────────────────────────

func (s *Server) handleMagicCode(w http.ResponseWriter, r *http.Request) {
	if s.passwordMode() {
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
	// The address only re-labels the "sent" page on failure, and return_to
	// only says where a failure goes back to; identity and the post-login
	// destination come from the stored code, never from the form. The form
	// on the sign-in page (shown after an app relaunch) has no address, so
	// its failures return to the sign-in page, which shows the code form
	// again while the transaction cookie lives.
	email := strings.TrimSpace(r.FormValue("email"))
	returnTo := s.resolveReturnTo(r.FormValue("return_to"))
	fail := func() {
		dest := loginLocation(errInvalidCode, returnTo)
		if email != "" {
			dest = sentLocation(email, errInvalidCode, returnTo)
		}
		http.Redirect(w, r, dest, http.StatusSeeOther)
	}

	// The transaction cookie is the login-CSRF defense as well as the
	// binding: SameSite=Lax keeps it off cross-site POSTs, and the __Host-
	// prefix keeps a sibling subdomain from planting one.
	c, err := r.Cookie(s.magicTxCookieName())
	if err != nil || c.Value == "" {
		fail()
		return
	}
	code := normalizeMagicCode(r.FormValue("code"))
	if code == "" {
		// Not a code at all: nothing to check, nothing counted.
		fail()
		return
	}
	txHash := hashSecret(c.Value)
	ctx := r.Context()
	ref, err := s.store.MagicCodeByTx(ctx, txHash)
	if errors.Is(err, store.ErrMagicCodeNotFound) {
		fail()
		return
	}
	if err != nil {
		logUnlessCancelled("magic code lookup", err)
		s.bounceWithErr(w, r, errInternal)
		return
	}

	// Reserve one failure against the mailbox's daily budget before the
	// code is compared, under the same one-slot gate the password limits
	// use, so parallel guesses cannot all slip in under the cap.
	now := time.Now()
	key := s.rateKey("magic-code", ref.CanonicalEmail)
	reserved, limited, err := s.reserveMagicCodeAttempt(r, key, now)
	if err != nil {
		logUnlessCancelled("magic code rate limit", err)
		s.bounceWithErr(w, r, errInternal)
		return
	}
	if limited {
		log.Printf("magic code daily limit hit: tenant=%s", emailTenant(ref.CanonicalEmail))
		fail()
		return
	}

	grant, err := s.store.RedeemMagicCode(ctx, txHash, ref.Nonce, s.magicCodeMAC(ref.Nonce, code), magicCodeMaxAttempts, now.Unix())
	switch {
	case err == nil:
	case errors.Is(err, store.ErrMagicCodeMismatch), errors.Is(err, store.ErrMagicCodeNotFound),
		errors.Is(err, store.ErrConsumed), errors.Is(err, store.ErrExpired), errors.Is(err, store.ErrTooManyAttempts):
		// The reserved row stays: it is the failure being counted.
		fail()
		return
	default:
		logUnlessCancelled("magic code redeem", err)
		s.bounceWithErr(w, r, errInternal)
		return
	}
	if err := s.store.DeleteLoginAttempts(ctx, reserved); err != nil {
		// Leaving it costs the person one try of their daily budget; it
		// must not cost them the sign-in that just succeeded.
		logUnlessCancelled("magic code attempt release", err)
	}
	s.clearMagicTxCookie(w)
	s.completeMagicSignIn(w, r, grant.Email, grant.ReturnTo, now)
}

// reserveMagicCodeAttempt checks the mailbox's failure budget and, when it
// has room, records one provisional failure, all under attemptGate. limited
// means the budget is spent and nothing was recorded. Only failures ever
// land under this key (a success deletes its reservation), so the count is
// of wrong codes, never reset by a later success.
func (s *Server) reserveMagicCodeAttempt(r *http.Request, key string, now time.Time) (id int64, limited bool, err error) {
	ctx := r.Context()
	if err := acquire(ctx, s.attemptGate); err != nil {
		return 0, false, err
	}
	defer release(s.attemptGate)
	n, err := s.store.CountFailedLoginAttempts(ctx, key, now.Add(-magicCodeWindow).Unix())
	if err != nil {
		return 0, false, err
	}
	if n >= magicCodeDailyFailures {
		return 0, true, nil
	}
	ids, err := s.store.ReserveLoginAttempts(ctx, now.Unix(), key)
	if err != nil {
		return 0, false, err
	}
	return ids[0], false, nil
}

// completeMagicSignIn is the shared end of a magic-mode sign-in, by link or
// by code: mint the shared session cookie, record the login, and send the
// browser to its re-validated destination.
func (s *Server) completeMagicSignIn(w http.ResponseWriter, r *http.Request, email, returnTo string, now time.Time) {
	tenant := emailTenant(email)
	sessTok, err := token.Sign(s.cfg.SigningKey, token.Session{
		Email:  email,
		Tenant: tenant,
		IAT:    now.Unix(),
		Exp:    now.Add(s.cfg.SessionTTL).Unix(),
	})
	if err != nil {
		log.Printf("sign session: %v", err)
		s.bounceWithErr(w, r, errInternal)
		return
	}
	if err := s.store.RecordLogin(r.Context(), email, tenant, now.Unix()); err != nil {
		// Audit log failure shouldn't block login — log + continue.
		log.Printf("record login: %v", err)
	}
	s.setSessionCookie(w, sessTok)
	dest := s.resolveReturnTo(returnTo)
	if dest == "" {
		dest = s.defaultDest()
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}
