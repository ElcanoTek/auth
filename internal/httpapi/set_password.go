package httpapi

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	passwordauth "github.com/elcanotek/auth/internal/password"
	"github.com/elcanotek/auth/internal/passwordlinks"
	"github.com/elcanotek/auth/internal/store"
)

// /set-password is where an emailed password link (store/password_links.go)
// lands. The link is <issuer>/set-password#<token>: the token is in the
// fragment, which a browser never sends, so it reaches no access log (ours
// or the proxy's), no Referer and no mail scanner that fetches the page. The
// page's script moves the token into a form post and removes it from the
// address bar and history. Opening the link only shows the form: the link is
// used up when a password is saved through it, so a scanner that runs the
// script and posts the form cannot spend it.
//
// Saving signs the account out everywhere and sends the browser to sign in
// with the new password, where the usual rules (two-factor included) apply.

const (
	setPasswordOpen    = "open"    // the script reads the fragment and posts it
	setPasswordForm    = "form"    // choose a password
	setPasswordInvalid = "invalid" // the link cannot set a password
	setPasswordLimited = "limited" // too many failed attempts from here
)

func (s *Server) handleSetPassword(w http.ResponseWriter, r *http.Request) {
	if !s.passwordMode() || !s.cfg.PasswordLinksEnabled() {
		http.NotFound(w, r)
		return
	}
	csrf, err := s.ensureCSRFCookie(w, r)
	if err != nil {
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}
	page := map[string]any{"Stage": setPasswordOpen, "CSRF": csrf}
	if r.Method == http.MethodGet {
		s.renderSetPassword(w, 0, page)
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
		// A stale copy of the page; nothing is read from it. Opening the
		// link again starts over with a live token.
		page["Error"] = "That page had expired, so nothing was saved. Open the link from your email again."
		s.renderSetPassword(w, 0, page)
		return
	}
	ctx := r.Context()
	now := time.Now()
	token := r.PostFormValue("token")
	ipRateKey := s.rateKey("link-ip", clientIP(r))
	attempt, limited, err := s.reserveLinkAttempt(ctx, ipRateKey, now)
	if err != nil {
		logUnlessCancelled("reserve link attempt", err)
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}
	if limited {
		_, _ = s.store.RecordAuditIfAbsent(ctx, "password_link.rate_limited", "", ipRateKey, now.Unix(), now.Add(-passwordRateWindow).Unix())
		page["Stage"] = setPasswordLimited
		s.renderSetPassword(w, http.StatusTooManyRequests, page)
		return
	}
	var account store.Account
	var purpose string
	err = store.ErrLinkInvalid
	if passwordlinks.ValidTokenShape(token) {
		account, purpose, err = s.store.PasswordLinkAccount(ctx, store.HashLinkToken(token), now.Unix())
	}
	if errors.Is(err, store.ErrLinkInvalid) {
		_ = s.store.RecordAudit(ctx, "password_link.invalid", "", ipRateKey, now.Unix())
		page["Stage"] = setPasswordInvalid
		s.renderSetPassword(w, http.StatusGone, page)
		return
	}
	if err != nil {
		logUnlessCancelled("password link lookup", err)
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}
	// A valid link is not a failed attempt, so its provisional failure goes;
	// it is not recorded as a success either, which would clear this
	// source's earlier failures (anyone holding one live link could then
	// keep guessing).
	if err := s.store.DeleteLoginAttempts(ctx, attempt); err != nil {
		logUnlessCancelled("drop link attempt", err)
	}
	page["Stage"], page["Token"], page["Email"], page["Reset"] = setPasswordForm, token, account.Email, purpose == store.LinkReset
	if r.PostFormValue("step") != "set" {
		s.renderSetPassword(w, 0, page)
		return
	}
	next, confirm := r.PostFormValue("new_password"), r.PostFormValue("confirm_password")
	if next != confirm {
		page["Error"] = "The passwords do not match."
		s.renderSetPassword(w, 0, page)
		return
	}
	if err := passwordauth.Validate(next, s.passwordContext(account.Email)...); err != nil {
		page["Error"] = passwordauth.UserMessage(err)
		s.renderSetPassword(w, 0, page)
		return
	}
	encoded, err := s.hashPassword(ctx, next)
	if err != nil {
		page["Error"] = passwordauth.UserMessage(err)
		s.renderSetPassword(w, 0, page)
		return
	}
	if beforeLinkUse != nil {
		beforeLinkUse()
	}
	// The link is checked again in the transaction that uses it: it may
	// have been used, replaced or withdrawn while the password was hashed.
	if _, _, err := s.store.UsePasswordLink(ctx, store.HashLinkToken(token), encoded, ipRateKey, now.Unix()); err != nil {
		if errors.Is(err, store.ErrLinkInvalid) {
			// A second submit of the same form (a double click) loses the
			// race to the first, which set this very password: say so,
			// rather than that the link no longer works.
			if current, err := s.store.PasswordAccountByID(ctx, account.ID); err == nil {
				if ok, _, err := s.verifyPassword(ctx, current.PasswordHash, next); err == nil && ok {
					http.Redirect(w, r, "/?notice=password_set", http.StatusSeeOther)
					return
				}
			}
			page["Stage"] = setPasswordInvalid
			s.renderSetPassword(w, http.StatusGone, page)
			return
		}
		logUnlessCancelled("use password link", err)
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/?notice=password_set", http.StatusSeeOther)
}

// beforeLinkUse is a test seam: it runs just before the link is used, where
// a concurrent submit of the same form could get there first.
var beforeLinkUse func()

// reserveLinkAttempt records a link attempt from this source as a failure
// until a valid link settles it, and refuses once the source has as many
// recent failures as a password sign-in may (AUTH_PASSWORD_RATE_PER_IP).
// Tokens carry 256 bits, so this is not what keeps them from being guessed;
// it keeps a client from using the page to hammer the database.
func (s *Server) reserveLinkAttempt(ctx context.Context, ipKey string, now time.Time) (int64, bool, error) {
	if err := acquire(ctx, s.attemptGate); err != nil {
		return 0, false, err
	}
	defer release(s.attemptGate)
	if limit := s.cfg.PasswordRatePerIP; limit > 0 {
		n, err := s.store.CountFailedLoginAttempts(ctx, ipKey, now.Add(-passwordRateWindow).Unix())
		if err != nil || n >= limit {
			return 0, n >= limit, err
		}
	}
	ids, err := s.store.ReserveLoginAttempts(ctx, now.Unix(), ipKey)
	if err != nil {
		return 0, false, err
	}
	return ids[0], false, nil
}

func (s *Server) renderSetPassword(w http.ResponseWriter, status int, data map[string]any) {
	if err := s.renderStatus(w, status, "set-password.html", data); err != nil {
		log.Printf("render set password: %v", err)
	}
}
