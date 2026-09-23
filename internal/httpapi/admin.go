package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elcanotek/auth/internal/mfa"
	passwordauth "github.com/elcanotek/auth/internal/password"
	"github.com/elcanotek/auth/internal/store"
)

// The admin console: accounts and per-application access for administrators
// of a password-mode deployment. Everything here is server-rendered forms;
// the page's CSP allows only the nonce'd theme script and that stays so.
// Magic-mode deployments have no accounts, no applications and no
// administrators, so the route is a 404 there.

const adminAccountsTab = "accounts"

type adminTab struct {
	ID     string
	Label  string
	URL    string
	Active bool
}

type adminAppChoice struct {
	ID      string
	Name    string
	Granted bool
}

type adminAccountRow struct {
	Email       string
	Status      string // Active | Disabled | Must change password
	StatusClass string // ok | off | warn
	IsAdmin     bool
	Team        string
	Created     string
	Sessions    int
	Apps        []adminAppChoice
	GrantedApps int
	Self        bool
	CanDisable  bool // not self and not the last enabled admin
	CanDemote   bool
	// Second factor: the console shows the status the issue names and lets
	// an administrator require it per account or reset a lost one.
	MFAStatus      string // Enabled | Enrollment required | Not enrolled
	MFAClass       string // ok | warn | off
	MFAEnrolled    bool
	MFARequired    bool // the per-user flag
	MFAPolicyBound bool // the deployment policy already requires it (pill locked)
}

// adminMFAOption is one deployment-policy choice with what it would do.
type adminMFAOption struct {
	Mode     string
	Label    string
	Describe string // one-line explanation shown in the policy popup
	Current  bool
	ToEnroll int64 // enabled accounts that would have to enroll
}

type adminSignInRow struct {
	Email    string
	Count    int
	Last     string
	Disabled bool
}

type adminAppView struct {
	ID          string
	Name        string
	Disabled    bool
	Callback    string
	Logout      string
	Backchannel string
	Created     string
	SignIns     []adminSignInRow
	Granted     int
}

// adminResult is what one POST leaves for the re-rendered page. Status is
// non-zero when the action must not render the page at all: an unexpected
// failure (500, so an uncertain outcome is never dressed up as "nothing
// changed") or a request the UI never sends (400). Reopen names the popover
// the page should show again (the Add user form after a rejected entry) so
// the administrator's input is not lost behind a closed dialog.
type adminResult struct {
	Notice   string
	Error    string
	Secret   string // temporary password, shown once
	ForEmail string
	Tab      string
	Status   int
	Reopen   string
	Redirect string // send the browser here instead of rendering (own sign-out)
	// NeedVerify: the action is sensitive and the administrator's sign-in is
	// older than the re-verification window; the page offers the step-up.
	NeedVerify bool
	// NeedEnroll: the action is sensitive and the administrator has no
	// authenticator yet; the page points at Security.
	NeedEnroll bool
}

// sensitiveActions are the console actions that lock people out, take over
// an account, create one, or change what an account may reach. They need
// the acting administrator's own authenticator code, entered within the
// re-verification window: a stolen admin browser session must not be enough
// to disable accounts, reset passwords, mint an account with a known
// password, grant applications or change who is an administrator. Team
// tags are the one console write that is not gated.
var sensitiveActions = map[string]string{
	"create":           "creating an account",
	"set-access":       "changing application access or administrator status",
	"disable":          "disabling an account",
	"enable":           "enabling an account",
	"reset-password":   "resetting a password",
	"revoke-sessions":  "signing someone out everywhere",
	"grant-admin":      "changing who is an administrator",
	"revoke-admin":     "changing who is an administrator",
	"reset-mfa":        "resetting someone's two-factor sign-in",
	"set-policy":       "changing the two-factor policy",
	"set-mfa-required": "changing a two-factor requirement",
	"disable-app":      "disabling an application",
	"enable-app":       "enabling an application",
}

// failed logs an unexpected error and marks the result as a 500.
func (res adminResult) failed(what string, err error) adminResult {
	logUnlessCancelled("admin "+what, err)
	res.Status = http.StatusInternalServerError
	return res
}

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if !s.passwordMode() {
		http.NotFound(w, r)
		return
	}
	// The request body is read before the session is judged, so a slow
	// upload cannot pass the gate and land after the session was revoked.
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
	}
	// The console needs a fully assured session: forced change done, and the
	// factor proven when the account has or must have one.
	identity := s.assuredIdentity(w, r, false)
	if identity == nil {
		return
	}
	if !identity.Account.IsAdmin {
		// The console is invisible to everyone else, like its greyed tile.
		http.NotFound(w, r)
		return
	}
	csrf, err := s.ensureCSRFCookie(w, r)
	if err != nil {
		http.Error(w, "something went wrong", http.StatusInternalServerError)
		return
	}
	var result adminResult
	switch r.Method {
	case http.MethodGet:
		result.Tab = r.URL.Query().Get("tab")
	case http.MethodPost:
		if !s.validCSRF(r) {
			// Stale console page (left open across a re-login): nothing
			// runs; the page re-renders with the live token and says so.
			result = adminResult{Error: staleFormMessage, Tab: r.FormValue("tab")}
			break
		}
		result = s.adminAction(r, identity)
		if result.Redirect != "" {
			s.clearPasswordCookies(w)
			http.Redirect(w, r, result.Redirect, http.StatusSeeOther)
			return
		}
		switch result.Status {
		case 0:
		case http.StatusBadRequest:
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		default:
			http.Error(w, "something went wrong", result.Status)
			return
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.renderAdmin(w, r, identity, csrf, result)
}

// adminAction performs one console action and reports the outcome for the
// page. Expected conflicts (unknown email, duplicate account, last admin,
// self-target) are inline messages the administrator can act on; unexpected
// failures are a 500 and requests the UI never sends are a 400, via Status.
func (s *Server) adminAction(r *http.Request, identity *passwordIdentity) adminResult {
	actor := identity.Account
	ctx := r.Context()
	now := time.Now()
	action := r.FormValue("action")
	tab := r.FormValue("tab")
	res := adminResult{Tab: tab}
	ipHash := s.rateKey("ip", clientIP(r))
	// Sensitive actions (see sensitiveActions) need the administrator's own
	// authenticator code entered within the re-verification window: a
	// sign-in that used the code counts, a step-up on the verify page
	// counts, a recovery-code sign-in or a password-only re-verification
	// does not. An administrator without an authenticator is sent to set
	// one up first.
	fresh := actor.MFAEnrolled && recentlyVerified(identity.Session, now, s.reauthWindow()) && hasMethod(identity.Session.AMR, "otp")
	// The same facts, re-checked inside the store transactions that accept
	// an actor proof.
	proof := &store.ActorProof{SessionHash: identity.Session.TokenHash, FreshAfter: now.Add(-s.reauthWindow()).Unix(), RequireFactor: true}
	needVerify := func() adminResult {
		res.Tab = adminAccountsTab
		res.NeedVerify = true
		res.Error = "Confirm it is you before making that change."
		return res
	}
	// gate returns the page to show instead of performing a sensitive
	// action, or ok=true when the administrator may proceed.
	gate := func(what string) (adminResult, bool) {
		if !s.mfaAvailable() {
			res.Tab = adminAccountsTab
			res.Error = "Two-factor sign-in is not set up on this server (AUTH_MFA_KEY is unset), so " + what + " is not possible from the console; use the auth CLI on the server."
			return res, false
		}
		if !actor.MFAEnrolled {
			res.Tab = adminAccountsTab
			res.NeedEnroll = true
			res.Error = "Set up two-factor sign-in on your own account before " + what + "."
			return res, false
		}
		if !fresh {
			r := needVerify()
			r.Error = "Confirm it is you before " + what + "."
			return r, false
		}
		return res, true
	}
	if what, sensitive := sensitiveActions[action]; sensitive && action != "revoke-sessions" {
		// revoke-sessions is gated below, once the target is resolved by
		// account ID: signing yourself out is not a takeover of anyone, and
		// "yourself" must be decided by identity, not by comparing the typed
		// address (two distinct addresses can compare equal under case
		// folding).
		if r, ok := gate(what); !ok {
			return r
		}
	}
	// Attribution is written after the mutation commits, on a context that
	// survives the client hanging up, so a disconnect right after a
	// successful change does not lose who made it.
	audit := func(event, targetID, appID string) {
		auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := s.store.RecordAdminAction(auditCtx, event, actor.ID, targetID, appID, ipHash, now.Unix()); err != nil {
			log.Printf("admin audit %s by %s on target=%q app=%q: %v", event, actor.ID, targetID, appID, err)
		}
	}

	// Application actions live on that application's tab.
	switch action {
	case "disable-app", "enable-app":
		appID := strings.TrimSpace(r.FormValue("app"))
		app, err := s.store.ApplicationByID(ctx, appID)
		if errors.Is(err, store.ErrApplicationNotFound) {
			res.Error = "No application with that ID."
			return res
		}
		if err != nil {
			return res.failed("application lookup", err)
		}
		res.Tab = app.ID
		disable := action == "disable-app"
		err = s.store.SetApplicationDisabledBy(ctx, app.ID, disable, actor.ID, proof, now.Unix())
		if errors.Is(err, store.ErrActorNotFresh) {
			return needVerify()
		}
		if err != nil {
			return res.failed(action, err)
		}
		if disable {
			audit("admin.application_disabled", "", app.ID)
			res.Notice = fmt.Sprintf("%s is disabled. Nobody can sign in to it until it is enabled again.", app.Name)
		} else {
			audit("admin.application_enabled", "", app.ID)
			res.Notice = fmt.Sprintf("%s is enabled.", app.Name)
		}
		return res
	}

	if action == "set-policy" {
		res.Tab = adminAccountsTab
		mode, err := mfa.ParseMode(r.FormValue("mode"))
		if err != nil {
			res.Status = http.StatusBadRequest
			return res
		}
		revision, err := strconv.ParseInt(r.FormValue("revision"), 10, 64)
		if err != nil || revision < 0 {
			// The form always carries the revision it was rendered from; a
			// missing one is not a request the console sends.
			res.Status = http.StatusBadRequest
			return res
		}
		policy, signedOut, err := s.store.SetMFAPolicyBy(ctx, mode, revision, actor.ID, proof, now.Unix())
		if errors.Is(err, store.ErrActorNotFresh) {
			return needVerify()
		}
		if errors.Is(err, store.ErrStalePolicy) {
			res.Error = "The two-factor policy was changed by someone else meanwhile. Review it and try again."
			return res
		}
		if err != nil {
			return res.failed("set mfa policy", err)
		}
		audit("admin.mfa_policy_changed", "", "")
		// The acting administrator may have just required a factor of
		// themself without having one: their session is gone, so say so and
		// send them to sign in (and enroll) rather than render a page that
		// bounces on the next click.
		if mfa.Required(policy.Mode, actor.IsAdmin, actor.MFARequired) && !actor.MFAEnrolled {
			res.Redirect = "/?notice=mfa_required"
			return res
		}
		switch signedOut {
		case 0:
			res.Notice = fmt.Sprintf("Two-factor policy is now %s.", strings.ToLower(policy.Mode.Label()))
		case 1:
			res.Notice = fmt.Sprintf("Two-factor policy is now %s. One account without an authenticator was signed out and will enroll at its next sign-in.", strings.ToLower(policy.Mode.Label()))
		default:
			res.Notice = fmt.Sprintf("Two-factor policy is now %s. %d accounts without an authenticator were signed out and will enroll at their next sign-in.", strings.ToLower(policy.Mode.Label()), signedOut)
		}
		return res
	}

	if action == "batch" {
		return s.adminBatch(r, actor, res, gate, proof, audit, now)
	}

	res.Tab = adminAccountsTab
	email, ok := validAdminEmail(r.FormValue("email"))
	if !ok {
		res.Error = "Enter a valid email address."
		return res
	}
	res.ForEmail = email

	if action == "create" {
		res.Reopen = "add-user"
		team, err := store.NormalizeTeam(r.FormValue("team"))
		if err != nil {
			res.Error = "Team must be at most 40 characters."
			return res
		}
		// The administrator may type the temporary password or leave it blank
		// to have one generated. Either way it is validated against the same
		// policy the change-password form applies, with the new account's
		// email as context, and set must-change. A typed value is used
		// byte-for-byte (spaces included), exactly as the change-password form
		// treats a password, so what the administrator shares is what works.
		plain, typed := r.FormValue("password"), false
		if plain != "" {
			typed = true
			if err := passwordauth.Validate(plain, s.passwordContext(email)...); err != nil {
				res.Error = "Temporary password: " + passwordauth.UserMessage(err)
				return res
			}
		} else {
			plain, err = passwordauth.Generate(s.passwordContext(email)...)
			if err != nil {
				return res.failed("generate password", err)
			}
		}
		encoded, err := s.hashPassword(ctx, plain)
		if err != nil {
			return res.failed("hash password", err)
		}
		account, err := s.store.CreatePasswordAccount(ctx, email, encoded, true, now.Unix())
		if errors.Is(err, store.ErrAccountExists) {
			res.Error = "An account with that email already exists."
			return res
		}
		if err != nil {
			return res.failed("create account", err)
		}
		res.Reopen = ""
		audit("admin.user_created", account.ID, "")
		if r.FormValue("admin") == "on" {
			if err := s.store.SetAccountAdmin(ctx, account.Email, true, now.Unix()); err != nil {
				logUnlessCancelled("admin initial admin", err)
				res.Error = "The account was created, but its Admin permission could not be saved. Set it from Access."
			} else {
				audit("admin.admin_granted", account.ID, "")
			}
		}
		if team != "" {
			if err := s.store.SetAccountTeam(ctx, account.Email, team, now.Unix()); err != nil {
				logUnlessCancelled("admin initial team", err)
				res.Error = "The account was created, but its team could not be saved. Set it from Settings."
			}
		}
		if _, _, err := s.store.SetApplicationAccess(ctx, account.ID, r.Form["apps"], now.Unix()); err != nil {
			// The account exists and its password is in hand, so this is
			// reported on the page rather than as a 500 that would hide
			// the one-time password of a committed create.
			logUnlessCancelled("admin initial access", err)
			res.Error = "The account was created, but its application access could not be saved. Set it from the account's row."
		} else {
			for _, id := range r.Form["apps"] {
				audit("admin.access_granted", account.ID, strings.TrimSpace(id))
			}
			if typed {
				res.Notice = fmt.Sprintf("Created %s with the password you entered; they must change it at first sign-in.", account.Email)
			} else {
				res.Notice = fmt.Sprintf("Created %s. Share the temporary password below; they must change it at first sign-in.", account.Email)
			}
		}
		if !typed {
			res.Secret = plain
		}
		return res
	}

	target, err := s.store.PasswordAccountByEmail(ctx, email)
	if errors.Is(err, store.ErrAccountNotFound) {
		res.Error = "No account with that email."
		return res
	}
	if err != nil {
		return res.failed("lookup", err)
	}
	self := target.ID == actor.ID
	switch action {
	case "reset-password":
		if self {
			res.Error = "Use Change password for your own account."
			return res
		}
		plain, err := passwordauth.Generate(s.passwordContext(target.Email)...)
		if err == nil {
			var encoded string
			encoded, err = s.hashPassword(ctx, plain)
			if err == nil {
				err = s.store.SetPassword(ctx, target.Email, encoded, true, now.Unix())
			}
		}
		if err != nil {
			return res.failed("reset password", err)
		}
		audit("admin.password_reset", target.ID, "")
		res.Notice = fmt.Sprintf("Reset the password for %s and signed them out everywhere. Share the temporary password below.", target.Email)
		res.Secret = plain
	case "revoke-sessions":
		// Allowed on one's own row too: it is "sign out everywhere", which
		// ends this session as well, so the browser goes to the sign-in page.
		// Anyone else's sessions are a sensitive change.
		if !self {
			if r, ok := gate(sensitiveActions[action]); !ok {
				return r
			}
		}
		n, err := s.store.RevokeAllAuthSessions(ctx, target.ID, now.Unix(), "admin_revoked")
		if err != nil {
			return res.failed("revoke sessions", err)
		}
		audit("admin.sessions_revoked", target.ID, "")
		if self {
			res.Redirect = "/?notice=signed_out"
			return res
		}
		res.Notice = fmt.Sprintf("Signed %s out of %d session(s) and every application.", target.Email, n)
	case "disable", "enable":
		disable := action == "disable"
		if self && disable {
			res.Error = "You cannot disable your own account."
			return res
		}
		err := s.store.SetAccountDisabled(ctx, target.Email, disable, now.Unix())
		if errors.Is(err, store.ErrLastAdmin) {
			res.Error = "That is the last enabled administrator. Make someone else an admin first."
			return res
		}
		if err != nil {
			return res.failed(action, err)
		}
		if disable {
			audit("admin.account_disabled", target.ID, "")
			res.Notice = fmt.Sprintf("Disabled %s and signed them out everywhere.", target.Email)
		} else {
			audit("admin.account_enabled", target.ID, "")
			res.Notice = fmt.Sprintf("Enabled %s.", target.Email)
		}
	case "grant-admin", "revoke-admin":
		grant := action == "grant-admin"
		if self && !grant {
			res.Error = "You cannot remove your own administrator access."
			return res
		}
		err := s.store.SetAccountAdmin(ctx, target.Email, grant, now.Unix())
		if errors.Is(err, store.ErrLastAdmin) {
			res.Error = "That is the last enabled administrator. Make someone else an admin first."
			return res
		}
		if err != nil {
			return res.failed(action, err)
		}
		if grant {
			audit("admin.admin_granted", target.ID, "")
			res.Notice = fmt.Sprintf("%s can now open this console.", target.Email)
		} else {
			audit("admin.admin_revoked", target.ID, "")
			res.Notice = fmt.Sprintf("%s is no longer an administrator.", target.Email)
		}
	case "reset-mfa":
		// A lost authenticator. The issue's rules: not for one's own row
		// (Security replaces it), the acting administrator proves their own
		// factor freshly, a reason is recorded, and the account lands in
		// "enrollment required" rather than back at password-only.
		if self {
			res.Error = "Replace your own authenticator from Security."
			return res
		}
		reason, err := store.NormalizeReason(r.FormValue("reason"))
		if err != nil {
			res.Error = "Give a short reason for the reset (how you verified it was them), up to 200 characters."
			return res
		}
		if limited, err := s.reserveCounted(ctx, s.rateKey("mfa-reset", actor.ID), mfaResetLimit, now); err != nil {
			return res.failed("reset limiter", err)
		} else if limited {
			_, _ = s.store.RecordAuditIfAbsent(ctx, "admin.mfa_reset_rate_limited", actor.ID, ipHash, now.Unix(), now.Add(-passwordRateWindow).Unix())
			res.Error = "Too many resets in a short time. Wait a few minutes and try again."
			return res
		}
		err = s.store.ResetMFABy(ctx, target.ID, actor.ID, reason, proof, now.Unix())
		if errors.Is(err, store.ErrActorNotFresh) {
			return needVerify()
		}
		if errors.Is(err, store.ErrNoAuthenticator) {
			res.Error = fmt.Sprintf("%s has no authenticator to reset. Use Require two-factor in Settings if they should set one up.", target.Email)
			return res
		}
		if err != nil {
			return res.failed("reset mfa", err)
		}
		audit("admin.mfa_reset", target.ID, "")
		s.notify(target.Email, "Two-factor sign-in was reset on your account",
			"An administrator reset the authenticator on your "+s.cfg.BrandName+" account. You were signed out everywhere and will set up a new authenticator at your next sign-in. If you did not expect this, contact your administrator.")
		res.Notice = fmt.Sprintf("Reset two-factor for %s and signed them out everywhere. They set up a new authenticator at their next sign-in.", target.Email)
	case "set-team":
		team, err := store.NormalizeTeam(r.FormValue("team"))
		if err != nil {
			res.Error = "Team must be at most 40 characters."
			return res
		}
		if err := s.store.SetAccountTeam(ctx, target.Email, team, now.Unix()); err != nil {
			return res.failed("set team", err)
		}
		audit("admin.team_set", target.ID, "")
		if team == "" {
			res.Notice = fmt.Sprintf("Removed %s's team tag.", target.Email)
		} else {
			res.Notice = fmt.Sprintf("%s is tagged %s.", target.Email, team)
		}
	case "set-mfa-required":
		// Settings: require (or stop requiring) two-factor sign-in of one
		// account. The store re-checks the actor proof in its transaction.
		want := r.FormValue("required") == "on"
		policy := s.mfaPolicy(r)
		if want && mfa.Required(policy.Mode, target.IsAdmin, false) {
			res.Error = fmt.Sprintf("The deployment policy already requires two-factor sign-in of %s.", target.Email)
			return res
		}
		if want == target.MFARequired {
			res.Notice = fmt.Sprintf("No change: two-factor sign-in is %s for %s.", map[bool]string{true: "already required", false: "not required"}[want], target.Email)
			return res
		}
		if _, err := s.store.SetAccountMFARequiredBy(ctx, target.Email, want, actor.ID, proof, now.Unix()); err != nil {
			if errors.Is(err, store.ErrActorNotFresh) {
				return needVerify()
			}
			return res.failed("set mfa required", err)
		}
		if want {
			audit("admin.mfa_required_set", target.ID, "")
			if self && !actor.MFAEnrolled {
				res.Redirect = "/?notice=mfa_required"
				return res
			}
			if target.MFAEnrolled {
				res.Notice = fmt.Sprintf("Two-factor sign-in is now required for %s; they can no longer turn it off.", target.Email)
			} else {
				res.Notice = fmt.Sprintf("Two-factor sign-in is now required for %s. They were signed out and set up an authenticator at their next sign-in.", target.Email)
			}
		} else {
			audit("admin.mfa_required_cleared", target.ID, "")
			res.Notice = fmt.Sprintf("Two-factor sign-in is no longer required for %s.", target.Email)
		}
	case "set-access":
		// The Access popup saves applications and the Admin flag in one store
		// transaction: a refusal of any part changes nothing. Console-level
		// rules that the store does not know (self-demotion, a server without
		// an MFA key) are checked first, so no write is even attempted. Every
		// Access save is a sensitive action (gate above): applications are
		// what an account may reach.
		wantAdmin := r.FormValue("admin") == "on"
		adminChange := wantAdmin != target.IsAdmin
		policy := s.mfaPolicy(r)
		promotionNeedsFactor := adminChange && wantAdmin && !target.MFAEnrolled && policy.Mode == mfa.ModeAdmins
		if adminChange && self && !wantAdmin {
			res.Error = "You cannot remove your own administrator access."
			return res
		}
		if promotionNeedsFactor && !s.mfaAvailable() {
			res.Error = "Two-factor sign-in is not set up on this server (AUTH_MFA_KEY is unset), so nothing can be required of anyone yet."
			return res
		}
		// An empty selection is a real instruction ("no applications"), not
		// "leave as is": the popup always posts the full set.
		apps := r.Form["apps"]
		if apps == nil {
			apps = []string{}
		}
		save := store.AccessSave{Applications: apps}
		var saveProof *store.ActorProof
		if adminChange {
			save.Admin = &wantAdmin
			saveProof = proof
		}
		outcome, err := s.store.SaveAccountAccess(ctx, target.Email, save, actor.ID, saveProof, now.Unix())
		switch {
		case errors.Is(err, store.ErrApplicationNotFound):
			res.Error = "One of those applications is not registered."
			return res
		case errors.Is(err, store.ErrLastAdmin):
			res.Error = "That is the last enabled administrator. Make someone else an admin first."
			return res
		case errors.Is(err, store.ErrActorNotFresh):
			return needVerify()
		case err != nil:
			return res.failed("save access", err)
		}
		for _, id := range outcome.Added {
			audit("admin.access_granted", target.ID, id)
		}
		for _, id := range outcome.Removed {
			audit("admin.access_revoked", target.ID, id)
		}
		adminNote, mfaNote := "", ""
		if outcome.AdminChanged {
			if wantAdmin {
				audit("admin.admin_granted", target.ID, "")
				adminNote = " Admin console granted."
			} else {
				audit("admin.admin_revoked", target.ID, "")
				adminNote = " Admin console removed."
			}
			if promotionNeedsFactor {
				mfaNote = " Administrators must use two-factor sign-in here, so they were signed out and set up an authenticator at their next sign-in."
			}
		}
		added, removed := outcome.Added, outcome.Removed
		switch {
		case len(added) == 0 && len(removed) == 0:
			res.Notice = fmt.Sprintf("No change to %s's applications.%s%s", target.Email, adminNote, mfaNote)
		case len(removed) == 0:
			res.Notice = fmt.Sprintf("%s can now sign in to %s.%s%s", target.Email, strings.Join(added, ", "), adminNote, mfaNote)
		case len(added) == 0:
			res.Notice = fmt.Sprintf("%s was signed out of and can no longer sign in to %s.%s%s", target.Email, strings.Join(removed, ", "), adminNote, mfaNote)
		default:
			res.Notice = fmt.Sprintf("%s: added %s; removed %s (and signed out of it).%s%s", target.Email, strings.Join(added, ", "), strings.Join(removed, ", "), adminNote, mfaNote)
		}
	default:
		res.Status = http.StatusBadRequest
	}
	return res
}

// adminBatch applies one operation to every selected account: a team tag,
// sign out everywhere, or requiring (or no longer requiring) two-factor
// sign-in. Each account is its own store transaction; the notice reports
// what was done and what was skipped and why. Sign-out and the two-factor
// requirement are sensitive actions (gate); tagging is not.
func (s *Server) adminBatch(r *http.Request, actor store.Account, res adminResult, gate func(string) (adminResult, bool), proof *store.ActorProof, audit func(event, targetID, appID string), now time.Time) adminResult {
	ctx := r.Context()
	res.Tab = adminAccountsTab
	emails := r.Form["emails"]
	if len(emails) == 0 {
		res.Error = "Select at least one account first (the boxes on the left)."
		return res
	}
	if len(emails) > 200 {
		res.Status = http.StatusBadRequest
		return res
	}
	op := r.FormValue("op")
	var team string
	switch op {
	case "team":
		var err error
		if team, err = store.NormalizeTeam(r.FormValue("team")); err != nil {
			res.Error = "Team must be at most 40 characters."
			return res
		}
	case "signout":
		if r, ok := gate("signing accounts out everywhere"); !ok {
			return r
		}
	case "require-mfa", "unrequire-mfa":
		if r, ok := gate("changing two-factor requirements"); !ok {
			return r
		}
	default:
		res.Status = http.StatusBadRequest
		return res
	}
	policy := s.mfaPolicy(r)
	var done, skipped []string
	skip := func(email, why string) { skipped = append(skipped, email+" ("+why+")") }
	// Each account commits on its own, so a failure part-way is reported
	// with what already changed rather than as a bare error page: the
	// administrator must not repeat sign-outs and audits blindly.
	stopped := func(email, what string, err error) adminResult {
		logUnlessCancelled("batch "+what, err)
		res.Error = fmt.Sprintf("Stopped at %s: something went wrong. Already done before that: %s. Skipped: %s. Review the table before repeating.", email, orNone(done), orNone(skipped))
		return res
	}
	for _, raw := range emails {
		email, ok := validAdminEmail(raw)
		if !ok {
			continue
		}
		target, err := s.store.PasswordAccountByEmail(ctx, email)
		if errors.Is(err, store.ErrAccountNotFound) {
			skip(email, "no such account")
			continue
		}
		if err != nil {
			return stopped(email, "lookup", err)
		}
		switch op {
		case "team":
			if err := s.store.SetAccountTeam(ctx, target.Email, team, now.Unix()); err != nil {
				return stopped(target.Email, "team", err)
			}
			audit("admin.team_set", target.ID, "")
			done = append(done, target.Email)
		case "signout":
			if target.ID == actor.ID {
				skip(target.Email, "you; use your own row to sign yourself out")
				continue
			}
			if _, err := s.store.RevokeAllAuthSessions(ctx, target.ID, now.Unix(), "admin_revoked"); err != nil {
				return stopped(target.Email, "revoke", err)
			}
			audit("admin.sessions_revoked", target.ID, "")
			done = append(done, target.Email)
		case "require-mfa", "unrequire-mfa":
			want := op == "require-mfa"
			if target.ID == actor.ID {
				skip(target.Email, "you; set yours up from Security")
				continue
			}
			if want && mfa.Required(policy.Mode, target.IsAdmin, false) {
				skip(target.Email, "already required by the policy")
				continue
			}
			if want == target.MFARequired {
				skip(target.Email, "no change")
				continue
			}
			if _, err := s.store.SetAccountMFARequiredBy(ctx, target.Email, want, actor.ID, proof, now.Unix()); err != nil {
				if errors.Is(err, store.ErrActorNotFresh) {
					res.NeedVerify = true
					res.Error = fmt.Sprintf("Confirm it is you before changing two-factor requirements. Already done: %s.", orNone(done))
					return res
				}
				return stopped(target.Email, "mfa required", err)
			}
			if want {
				audit("admin.mfa_required_set", target.ID, "")
			} else {
				audit("admin.mfa_required_cleared", target.ID, "")
			}
			done = append(done, target.Email)
		}
	}
	var what string
	switch op {
	case "team":
		if team == "" {
			what = "Removed the team tag from"
		} else {
			what = "Tagged " + team + ":"
		}
	case "signout":
		what = "Signed out everywhere:"
	case "require-mfa":
		what = "Two-factor sign-in now required (unenrolled accounts were signed out and set up an authenticator at their next sign-in):"
	case "unrequire-mfa":
		what = "Two-factor sign-in no longer required:"
	}
	switch {
	case len(done) == 0:
		res.Error = "Nothing changed. Skipped: " + strings.Join(skipped, "; ") + "."
	default:
		res.Notice = fmt.Sprintf("%s %s (%d).", what, strings.Join(done, ", "), len(done))
		if len(skipped) > 0 {
			res.Notice += " Skipped: " + strings.Join(skipped, "; ") + "."
		}
	}
	return res
}

// renderAdmin builds the whole page for the chosen tab. Read failures fall
// back to a visible error line with whatever did load, since the page is
// where an administrator would go to fix things.
func (s *Server) renderAdmin(w http.ResponseWriter, r *http.Request, identity *passwordIdentity, csrf string, result adminResult) {
	actor := identity.Account
	ctx := r.Context()
	now := time.Now()
	policy := s.mfaPolicy(r)
	apps, err := s.store.ListApplications(ctx)
	if err != nil {
		logUnlessCancelled("admin list applications", err)
		result.Error = joinMessages(result.Error, "Applications could not be loaded.")
	}
	appByID := map[string]store.Application{}
	tabs := []adminTab{{ID: adminAccountsTab, Label: "Accounts", URL: "/admin"}}
	for _, app := range apps {
		appByID[app.ID] = app
		tabs = append(tabs, adminTab{ID: app.ID, Label: app.Name, URL: "/admin?tab=" + url.QueryEscape(app.ID)})
	}
	tab := result.Tab
	if _, known := appByID[tab]; !known {
		tab = adminAccountsTab
	}
	for i := range tabs {
		tabs[i].Active = tabs[i].ID == tab
	}

	data := map[string]any{
		"Brand": s.cfg.BrandName, "Email": actor.Email, "CSRF": csrf,
		"Tabs": tabs, "Tab": tab, "Notice": result.Notice, "Error": result.Error,
		"Secret": result.Secret, "SecretFor": result.ForEmail, "Reopen": result.Reopen,
		"NeedVerify": result.NeedVerify, "NeedEnroll": result.NeedEnroll, "MFAAvailable": s.mfaAvailable(),
		"ActorEnrolled": actor.MFAEnrolled, "ActorFresh": actor.MFAEnrolled && recentlyVerified(identity.Session, now, s.reauthWindow()) && hasMethod(identity.Session.AMR, "otp"),
		"MFAPolicy": policy.Mode.Label(), "MFARevision": policy.Revision,
	}

	if tab == adminAccountsTab {
		accounts, err := s.store.ListPasswordAccounts(ctx)
		if err != nil {
			logUnlessCancelled("admin list accounts", err)
			data["Error"] = joinMessages(result.Error, "Accounts could not be loaded.")
		}
		access, err := s.store.AllApplicationAccess(ctx)
		if err != nil {
			logUnlessCancelled("admin list access", err)
			data["Error"] = joinMessages(result.Error, "Application access could not be loaded.")
		}
		enabledAdmins := 0
		for _, a := range accounts {
			if a.IsAdmin && a.DisabledAt == nil {
				enabledAdmins++
			}
		}
		sessions, err := s.store.ActiveSessionCounts(ctx, now.Unix())
		if err != nil {
			logUnlessCancelled("admin count sessions", err)
			data["Error"] = joinMessages(result.Error, "Session counts could not be loaded.")
		}
		rows := make([]adminAccountRow, 0, len(accounts))
		for _, a := range accounts {
			row := adminAccountRow{
				Email: a.Email, IsAdmin: a.IsAdmin, Team: a.Team, Created: a.CreatedAt.UTC().Format("2006-01-02"),
				Sessions: sessions[a.ID], Self: a.ID == actor.ID,
			}
			switch {
			case a.DisabledAt != nil:
				row.Status, row.StatusClass = "Disabled", "off"
			case a.MustChangePassword:
				row.Status, row.StatusClass = "Must change password", "warn"
			default:
				row.Status, row.StatusClass = "Active", "ok"
			}
			lastAdmin := a.IsAdmin && a.DisabledAt == nil && enabledAdmins == 1
			row.CanDisable = !row.Self && !lastAdmin
			row.CanDemote = !row.Self && !lastAdmin
			row.MFAEnrolled, row.MFARequired = a.MFAEnrolled, a.MFARequired
			row.MFAPolicyBound = mfa.Required(policy.Mode, a.IsAdmin, false)
			switch mfa.StatusFor(mfa.Required(policy.Mode, a.IsAdmin, a.MFARequired), a.MFAEnrolled) {
			case mfa.StatusEnabled:
				row.MFAStatus, row.MFAClass = string(mfa.StatusEnabled), "ok"
			case mfa.StatusEnrollmentRequired:
				row.MFAStatus, row.MFAClass = string(mfa.StatusEnrollmentRequired), "warn"
			default:
				row.MFAStatus, row.MFAClass = string(mfa.StatusNotEnrolled), "off"
			}
			granted := accessSet(access[a.ID])
			for _, app := range apps {
				row.Apps = append(row.Apps, adminAppChoice{ID: app.ID, Name: app.Name, Granted: granted[app.ID]})
				if granted[app.ID] {
					row.GrantedApps++
				}
			}
			rows = append(rows, row)
		}
		choices := make([]adminAppChoice, 0, len(apps))
		for _, app := range apps {
			choices = append(choices, adminAppChoice{ID: app.ID, Name: app.Name, Granted: app.DisabledAt == nil})
		}
		teamSet := map[string]bool{}
		var teams []string
		for _, a := range accounts {
			if a.Team != "" && !teamSet[a.Team] {
				teamSet[a.Team] = true
				teams = append(teams, a.Team)
			}
		}
		sort.Strings(teams)
		data["Accounts"] = rows
		data["AppChoices"] = choices
		data["Teams"] = teams
		// The policy popup shows, for each choice, how many enabled accounts
		// would have to enroll (and be signed out now) if it were chosen.
		var options []adminMFAOption
		for _, mode := range []mfa.Mode{mfa.ModeOptional, mfa.ModeAdmins, mfa.ModeEveryone} {
			n, err := s.store.CountNewlyRequiredWithoutFactor(ctx, mode)
			if err != nil {
				logUnlessCancelled("admin mfa counts", err)
				// Never show "nobody is affected" for a count that failed:
				// the popup says so and withholds Save.
				data["MFACountError"] = true
			}
			options = append(options, adminMFAOption{Mode: string(mode), Label: mode.Label(), Describe: mfaModeDescription(mode), Current: mode == policy.Mode, ToEnroll: n})
		}
		data["MFAOptions"] = options
	} else {
		app := appByID[tab]
		view := adminAppView{
			ID: app.ID, Name: app.Name, Disabled: app.DisabledAt != nil,
			Callback: app.RedirectURI, Logout: app.LogoutURI, Backchannel: app.BackchannelLogoutURI,
			Created: app.CreatedAt.UTC().Format("2006-01-02"),
		}
		signIns, err := s.store.ApplicationSignIns(ctx, app.ID, 200)
		if err != nil {
			logUnlessCancelled("admin sign-ins", err)
			data["Error"] = joinMessages(result.Error, "Sign-in history could not be loaded.")
		}
		for _, si := range signIns {
			view.SignIns = append(view.SignIns, adminSignInRow{Email: si.Email, Count: si.Count, Last: si.LastAt.UTC().Format("2006-01-02 15:04 UTC"), Disabled: si.Disabled})
		}
		access, err := s.store.AllApplicationAccess(ctx)
		if err == nil {
			for _, ids := range access {
				for _, id := range ids {
					if id == app.ID {
						view.Granted++
					}
				}
			}
		}
		data["App"] = view
	}
	if err := s.render(w, "admin.html", data); err != nil {
		log.Printf("render admin: %v", err)
	}
}

// orNone joins a list for a notice, or says "none".
func orNone(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	return strings.Join(items, ", ")
}

// mfaModeDescription is the console's one-line explanation of each policy.
func mfaModeDescription(mode mfa.Mode) string {
	switch mode {
	case mfa.ModeAdmins:
		return "Everyone who can open this console must sign in with an authenticator app; other accounts may set one up but are not made to."
	case mfa.ModeEveryone:
		return "Every account must sign in with an authenticator app."
	default:
		return "Nobody is made to. Anyone may set up an authenticator from their Security page, and once they have, they always use it."
	}
}

// validAdminEmail accepts one plain address (no display name, no angle
// brackets) and returns it lowercased, the form every store lookup uses.
func validAdminEmail(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 254 || strings.ContainsAny(raw, " <>\"\\\x00\r\n") {
		return "", false
	}
	addr, err := mail.ParseAddress(raw)
	if err != nil || addr.Address != raw {
		return "", false
	}
	return strings.ToLower(raw), true
}

func joinMessages(parts ...string) string {
	var kept []string
	for _, p := range parts {
		if p != "" {
			kept = append(kept, p)
		}
	}
	sort.Strings(kept)
	return strings.Join(kept, " ")
}
