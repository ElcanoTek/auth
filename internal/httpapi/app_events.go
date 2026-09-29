package httpapi

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/elcanotek/auth/internal/mfa"
	"github.com/elcanotek/auth/internal/store"
)

// POST /apps/{client_id}/events receives an application's signed account
// reports (docs/INTEGRATION.md, "Receiving application account reports").
// There is no browser session and no CSRF token: the request is
// server-to-server and authenticated by an HMAC over the exact body under
// the application's events secret, with the timestamp bound into the MAC.
//
// Status codes: 404 unknown, disabled or unconfigured application (and in
// magic mode); 405 not POST; 413 body over appEventMaxBody; 401 missing or
// wrong signature or a timestamp outside appEventMaxSkew; 400 malformed
// report; 204 once accepted, INCLUDING reports Auth deliberately ignores, so
// the sender stops retrying them; 500 when the database write failed and a
// retry may succeed.

const (
	appEventMaxBody     = 16 << 10
	appEventMaxSkew     = 5 * time.Minute
	appEventSigVersion  = "v1="
	appEventSigHeader   = "X-Fleet-Signature"
	appEventTimeHeader  = "X-Fleet-Timestamp"
	appEventMaxIDLength = 255
)

type appEventBody struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	OccurredAt int64  `json:"occurred_at"`
	Sequence   int64  `json:"sequence"`
	Source     string `json:"source"`
	Actor      string `json:"actor"`
	User       struct {
		Email    string `json:"email"`
		Enabled  bool   `json:"enabled"`
		ChatRole string `json:"chat_role"`
		OpsRole  string `json:"ops_role"`
	} `json:"user"`
}

func (s *Server) handleAppEvents(w http.ResponseWriter, r *http.Request) {
	if !s.passwordMode() {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	clientID := r.PathValue("client_id")
	app, err := s.store.ApplicationByID(r.Context(), clientID)
	if err != nil || app.DisabledAt != nil {
		if err != nil && !errors.Is(err, store.ErrApplicationNotFound) {
			logUnlessCancelled("app events lookup", err)
		}
		http.NotFound(w, r)
		return
	}
	sealed, err := s.store.ApplicationEventsSecret(r.Context(), app.ID)
	if err != nil {
		logUnlessCancelled("app events secret", err)
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}
	if sealed == nil {
		http.NotFound(w, r)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, appEventMaxBody))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	now := time.Now()
	if !s.appEventSignatureValid(r, app.ID, sealed, body, now) {
		_, _ = s.store.RecordAuditIfAbsent(r.Context(), "app_events.invalid_signature", "", s.rateKey("ip", clientIP(r)), now.Unix(), now.Add(-passwordRateWindow).Unix())
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	report, ok := parseAppEvent(body, now)
	if !ok {
		http.Error(w, "invalid report", http.StatusBadRequest)
		return
	}
	decision, err := s.store.ApplyAppReport(r.Context(), app.ID, report, now.Unix())
	if err != nil {
		logUnlessCancelled("apply app report", err)
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}
	// No email in the log line: the audit trail names the account.
	outcome := string(decision.Action)
	if decision.Reason != "" {
		outcome += " (" + decision.Reason + ")"
	}
	log.Printf("app report %s %s: %s", app.ID, logSafeID(report.EventID), outcome)
	w.WriteHeader(http.StatusNoContent)
}

// appEventSignatureValid checks X-Fleet-Timestamp / X-Fleet-Signature the
// way docs/WEBHOOK-SIGNING.md (Fleet) defines them: HMAC-SHA256 keyed by the
// secret string, over "<timestamp>.<raw body>", lowercase hex after "v1=".
func (s *Server) appEventSignatureValid(r *http.Request, appID string, sealed, body []byte, now time.Time) bool {
	rawTS := r.Header.Get(appEventTimeHeader)
	if rawTS == "" || len(rawTS) > 12 || strings.TrimLeft(rawTS, "0123456789") != "" {
		return false
	}
	ts, err := strconv.ParseInt(rawTS, 10, 64)
	if err != nil {
		return false
	}
	if skew := now.Sub(time.Unix(ts, 0)); skew > appEventMaxSkew || skew < -appEventMaxSkew {
		return false
	}
	sig, found := strings.CutPrefix(r.Header.Get(appEventSigHeader), appEventSigVersion)
	provided, err := hex.DecodeString(sig)
	if !found || err != nil || len(provided) != sha256.Size {
		return false
	}
	secret, err := s.openEventsSecret(r, appID, sealed)
	if err != nil {
		// A sealed secret the key cannot open is a deployment fault (the
		// server refuses to start without AUTH_MFA_KEY when one exists).
		log.Printf("app events: cannot open events secret for %s: %v", appID, err)
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(rawTS))
	mac.Write([]byte{'.'})
	mac.Write(body)
	return subtle.ConstantTimeCompare(mac.Sum(nil), provided) == 1
}

// openEventsSecret opens the sealed secret and, when it was sealed under a
// previous AUTH_MFA_KEY, re-seals it under the active one (best effort).
func (s *Server) openEventsSecret(r *http.Request, appID string, sealed []byte) ([]byte, error) {
	aad := mfa.ApplicationSecretAAD(appID)
	secret, usedKey, err := s.cfg.MFAKeyring.Open(sealed, aad)
	if err != nil {
		return nil, err
	}
	if s.cfg.MFAKeyring.NeedsRewrap(usedKey) {
		if rewrapped, err := s.cfg.MFAKeyring.Seal(secret, aad); err == nil {
			if err := s.store.RewrapApplicationEventsSecret(r.Context(), appID, sealed, rewrapped); err != nil {
				logUnlessCancelled("rewrap events secret", err)
			}
		}
	}
	return secret, nil
}

// parseAppEvent validates the body against the v1 contract. Unknown fields
// are allowed so a sender can add information without breaking receivers.
func parseAppEvent(body []byte, now time.Time) (store.AppReport, bool) {
	var ev appEventBody
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&ev); err != nil || dec.More() {
		return store.AppReport{}, false
	}
	if ev.ID == "" || len(ev.ID) > appEventMaxIDLength || !printableASCII(ev.ID) {
		return store.AppReport{}, false
	}
	if ev.OccurredAt <= 0 || time.Unix(ev.OccurredAt, 0).After(now.Add(appEventMaxSkew)) {
		return store.AppReport{}, false
	}
	switch ev.Source {
	case "admin_ui", "cli", "system", "resync", store.AppReportSourceIdentityProvider:
	default:
		return store.AppReport{}, false
	}
	email := strings.TrimSpace(ev.User.Email)
	if len(email) > 254 || !looksLikeEmail(email) || len(ev.Actor) > 254 || strings.ContainsAny(ev.Actor, "\r\n\t") {
		return store.AppReport{}, false
	}
	switch ev.Type {
	case store.AppReportAccessChanged:
		switch ev.User.ChatRole {
		case "viewer", "member", "admin":
		default:
			return store.AppReport{}, false
		}
		switch ev.User.OpsRole {
		case "none", "readonly", "client", "admin":
		default:
			return store.AppReport{}, false
		}
	case store.AppReportDeleted:
		if ev.User.Enabled || ev.User.ChatRole != "" || ev.User.OpsRole != "" {
			return store.AppReport{}, false
		}
	default:
		return store.AppReport{}, false
	}
	return store.AppReport{
		EventID: ev.ID, Type: ev.Type, OccurredAt: ev.OccurredAt, Source: ev.Source,
		Actor: strings.TrimSpace(ev.Actor), Email: email, Enabled: ev.User.Enabled,
		ChatRole: ev.User.ChatRole, OpsRole: ev.User.OpsRole,
	}, true
}

func printableASCII(v string) bool {
	for i := 0; i < len(v); i++ {
		if v[i] < 0x21 || v[i] > 0x7e {
			return false
		}
	}
	return true
}

// logSafeID bounds an already-validated event id for a log line.
func logSafeID(id string) string {
	if len(id) > 64 {
		return id[:64] + "..."
	}
	return id
}
