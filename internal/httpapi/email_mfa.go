package httpapi

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/elcanotek/auth/internal/mfa"
	"github.com/elcanotek/auth/internal/store"
)

const (
	mfaEmailSendLimit       = 5
	mfaEmailCooldown        = 60 * time.Second
	emailCodeFormatMessage  = "Enter the six-digit code we sent to your email."
	emailCodeMismatchNotice = "That code did not match or has expired. Enter the latest six-digit code from your email."
)

// emailMFAAvailable reports whether accounts may enroll an email second
// factor: a deployment with 2FA and outbound email enabled.
func (s *Server) emailMFAAvailable() bool {
	return s.mfaAvailable() && s.sender != nil && s.cfg.PasswordLinksEnabled()
}

// mfaEmailCodeMAC computes the keyed MAC of a 6-digit email 2FA code bound to
// (nonce, userID, purpose, scopeID).
func (s *Server) mfaEmailCodeMAC(nonce, userID, purpose, scopeID, code string) string {
	key, err := hkdf.Key(sha256.New, []byte(s.cfg.SigningKey), nil, "elcano-auth/mfa-email-code/v1", 32)
	if err != nil {
		panic("hkdf: " + err.Error())
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(nonce))
	mac.Write([]byte{0})
	mac.Write([]byte(userID))
	mac.Write([]byte{0})
	mac.Write([]byte(purpose))
	mac.Write([]byte{0})
	mac.Write([]byte(scopeID))
	mac.Write([]byte{0})
	mac.Write([]byte(code))
	return hex.EncodeToString(mac.Sum(nil))
}

// sendMFAEmailChallenge issues and emails a 6-digit verification code for
// (account, purpose, scopeID). When forceResend is false and an unexpired,
// unexhausted challenge already exists for this scopeID, nothing is sent.
func (s *Server) sendMFAEmailChallenge(r *http.Request, account store.Account, purpose, scopeID string, ttl time.Duration, forceResend bool, now time.Time) error {
	if !forceResend {
		live, err := s.store.HasLiveMFAEmailChallenge(r.Context(), account.ID, purpose, scopeID, now.Unix())
		if err != nil {
			return err
		}
		if live {
			return nil
		}
	}
	cooldownSec := int64(mfaEmailCooldown / time.Second)
	inCooldown, err := s.store.CheckMFAEmailCooldown(r.Context(), account.ID, purpose, scopeID, cooldownSec, now.Unix())
	if err != nil {
		return err
	}
	if inCooldown {
		return store.ErrEmailCooldown
	}
	limited, err := s.reserveCounted(r.Context(), s.rateKey("mfa-email-send", account.ID), mfaEmailSendLimit, now)
	if err != nil {
		return err
	}
	if limited {
		return errEnrollLimited
	}
	code, err := newMagicCode()
	if err != nil {
		return err
	}
	nonce, err := randomSecret(16)
	if err != nil {
		return err
	}
	mac := s.mfaEmailCodeMAC(nonce, account.ID, purpose, scopeID, code)
	if err := s.store.IssueMFAEmailChallenge(r.Context(), account.ID, purpose, scopeID, nonce, mac, cooldownSec, now.Unix(), now.Add(ttl).Unix()); err != nil {
		return err
	}
	s.sendMFAEmail(account.Email, code, ttl, requestLanguage(r))
	return nil
}

func (s *Server) sendMFAEmail(to, code string, ttl time.Duration, lang string) {
	if s.sender == nil {
		return
	}
	subject := translate(lang, "Your {0} verification code", s.cfg.BrandName)
	text := renderMFAEmailText(s.cfg.BrandName, code, ttl, lang)
	htmlBody := renderMFAEmailHTML(s.cfg.BrandName, code, ttl, lang)
	s.sends.Add(1)
	go func(to, subj, t, h string) {
		defer s.sends.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.sender.Send(ctx, to, subj, t, h); err != nil {
			log.Printf("send mfa verification email failed (tenant=%s): %s", emailTenant(to), redactedError(err))
		}
	}(to, subject, text, htmlBody)
}

// verifySessionEmailCode checks an emailed step-up code for the signed-in
// session. stampReauth is for the Security page's step-up, which also
// checked the password; the console's code-only step-up passes false, so an
// emailed code alone never counts as "password re-entered".
func (s *Server) verifySessionEmailCode(r *http.Request, identity *passwordIdentity, code string, now time.Time, stampReauth bool) (refusal string, err error) {
	account := identity.Account
	ids, ipKey, limited, err := s.mfaAttempt(r, account.ID, now)
	if err != nil {
		return "", err
	}
	if limited {
		_, _ = s.store.RecordAuditIfAbsent(r.Context(), "reauth.mfa_rate_limited", account.ID, ipKey, now.Unix(), now.Add(-passwordRateWindow).Unix())
		return translate(requestLanguage(r), "Too many attempts. Wait a few minutes and try again."), nil
	}
	normalized := mfa.NormalizeCode(code)
	if normalized == "" {
		_ = s.store.RecordAudit(r.Context(), "reauth.mfa_failed", account.ID, ipKey, now.Unix())
		return translate(requestLanguage(r), emailCodeFormatMessage), nil
	}
	scopeID := identity.Session.TokenHash
	verify := s.store.VerifyEmailFactorOnSession
	if stampReauth {
		verify = s.store.VerifyEmailFactorAndStampReauth
	}
	err = verify(r.Context(), scopeID, func(nonce string) string {
		return s.mfaEmailCodeMAC(nonce, account.ID, store.EmailPurposeStepUp, scopeID, normalized)
	}, now.Unix())
	if errors.Is(err, store.ErrInvalidProof) || errors.Is(err, store.ErrTooManyAttempts) {
		_ = s.store.RecordAudit(r.Context(), "reauth.mfa_failed", account.ID, ipKey, now.Unix())
		return translate(requestLanguage(r), emailCodeMismatchNotice), nil
	}
	if err != nil {
		return "", err
	}
	_ = s.store.SettleLoginAttemptSuccess(r.Context(), ids[0], ids[1])
	return "", nil
}
