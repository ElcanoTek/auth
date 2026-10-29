package httpapi

import (
	"context"
	"encoding/json"
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
	Email         string
	Status        string // Active | Disabled | Must change password
	StatusClass   string // ok | off | warn
	IsAdmin       bool
	Team          string
	Created       string
	Sessions      int
	Apps          []adminAppChoice
	GrantedApps   int
	Self          bool
	CanDisable    bool // not self and not the last enabled admin
	CanDemote     bool
	FleetGranted  bool
	FleetAdmin    bool
	FleetChatRole string
	FleetOpsRole  string
	// Second factor: the console shows the status the issue names and lets
	// an administrator require it per account or reset a lost one.
	MFAStatus      string // Enabled | Enrollment required | Not enrolled
	MFAClass       string // ok | warn | off
	MFAEnrolled    bool
	MFARequired    bool // the per-user flag
	MFAPolicyBound bool // the deployment policy already requires it (pill locked)
}

type fleetAccessSettings struct {
	ChatRole string `json:"chat_role"`
	OpsRole  string `json:"ops_role"`
}

func fleetSettingsFromForm(r *http.Request, apps []string) (map[string]string, error) {
	hasFleet := false
	for _, id := range apps {
		if strings.TrimSpace(id) == "fleet" {
			hasFleet = true
			break
		}
	}
	if !hasFleet {
		return nil, nil
	}
	settings := fleetAccessSettings{ChatRole: r.FormValue("fleet_chat_role"), OpsRole: r.FormValue("fleet_ops_role")}
	if r.FormValue("fleet_admin") == "on" {
		settings.ChatRole, settings.OpsRole = "admin", "admin"
	} else {
		if settings.ChatRole == "" {
			settings.ChatRole = "member"
		}
		if settings.OpsRole == "" {
			settings.OpsRole = "none"
		}
		if settings.ChatRole != "member" && settings.ChatRole != "viewer" {
			return nil, errors.New("invalid Fleet Chat role")
		}
		if settings.OpsRole != "none" && settings.OpsRole != "readonly" && settings.OpsRole != "client" {
			return nil, errors.New("invalid Fleet Ops role")
		}
	}
	raw, err := json.Marshal(settings)
	if err != nil {
		return nil, err
	}
	return map[string]string{"fleet": string(raw)}, nil
}

func decodeFleetSettings(raw string) fleetAccessSettings {
	settings := fleetAccessSettings{ChatRole: "member", OpsRole: "none"}
	var stored fleetAccessSettings
	if json.Unmarshal([]byte(raw), &stored) == nil {
		if stored.ChatRole == "admin" && stored.OpsRole == "admin" {
			return stored
		}
		if stored.ChatRole == "member" || stored.ChatRole == "viewer" {
			settings.ChatRole = stored.ChatRole
		}
		if stored.OpsRole == "none" || stored.OpsRole == "readonly" || stored.OpsRole == "client" {
			settings.OpsRole = stored.OpsRole
		}
	}
	return settings
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
	ID       string
	Name     string
	Disabled bool
	Created  string
	SignIns  []adminSignInRow
	Granted  int
}

// adminResult is what one POST leaves for the re-rendered page. Status is
// non-zero when the action must not render the page at all: an unexpected
// failure (500, so an uncertain outcome is never dressed up as "nothing
// changed") or a request the UI never sends (400). Reopen names the dialog
// the page should show again (the Add user form after a rejected entry) so
// the administrator's input is not lost behind a closed dialog.
type adminResult struct {
	Notice string
	Error  string
	Secret string // temporary password, shown once in its own popup
	// SecretTitle heads that popup ("Password reset", "Account created").
	SecretTitle string
	ForEmail    string
	Tab         string
	Status      int
	Reopen      string
	Redirect    string // send the browser here instead of rendering (own sign-out)
	// Pending is a gated change refused only because the administrator's
	// code is not fresh: the code popup carries it, and once the code is
	// accepted the confirm popup offers to repeat it.
	Pending *pendingChange
	// NeedEnroll: the action is sensitive and the administrator has no
	// authenticator yet; the page points at Security.
	NeedEnroll bool
	// Draft is what was typed into Add user, carried through a refusal (a
	// rejected entry, or the code popup) so the dialog reopens filled in.
	Draft *addUserDraft
}

// Dialogs a console response can reopen (adminResult.Reopen).
const (
	reopenAddUser = "add-user"
	// reopenAddUserCode asks for the administrator's authenticator code when
	// Create account was refused only because it is not fresh.
	reopenAddUserCode = "add-user-code"
	// reopenTempPassword shows a one-time temporary password in a popup, so
	// it cannot scroll past unnoticed the way a banner can.
	reopenTempPassword = "temp-password"
	// reopenStepUp asks for the code before any other gated change, and
	// reopenConfirmChange then asks to confirm that change (Pending).
	reopenStepUp        = "step-up"
	reopenConfirmChange = "confirm-change"
)

// pendingFields lists, for every gated action but create (whose Add user
// draft has its own flow), the form fields its handler reads. Only these
// are carried through the code and confirm popups, and only from the
// request body, so the repeated request is the one the administrator made.
var pendingFields = map[string][]string{
	"set-policy":       {"mode", "revision"},
	"set-mfa-required": {"email", "required"},
	"disable":          {"email"},
	"enable":           {"email"},
	"reset-password":   {"email"},
	"revoke-sessions":  {"email"},
	"grant-admin":      {"email"},
	"revoke-admin":     {"email"},
	"reset-mfa":        {"email", "reason"},
	"set-access":       {"email", "apps", "admin", "fleet_admin", "fleet_chat_role", "fleet_ops_role"},
	"disable-app":      {"app"},
	"enable-app":       {"app"},
	"rename-team":      {"from", "to"},
	"batch":            {"op", "emails"},
}

// batchGated names the batch operations that are sensitive (team tags are
// not), with how the popups describe them.
var batchGated = map[string]string{
	"signout":       "signing accounts out everywhere",
	"require-mfa":   "changing two-factor requirements",
	"unrequire-mfa": "changing two-factor requirements",
}

// pendingChange is a gated request carried through the code popup and
// repeated from the confirm popup. Repeating it is an ordinary POST: it
// passes the CSRF check, the freshness gate and the store's actor proof
// again, so the popups grant nothing by themselves.
type pendingChange struct {
	Action   string
	Fields   []pendingField // the allowlisted body fields, every value, in pendingFields order
	Why      string         // "Changing the two-factor policy": what needs the code
	Question string         // the confirm popup's summary of the change
	Detail   string         // what else it does, when that matters
}

type pendingField struct{ Name, Value string }

// newPendingChange captures action's allowlisted fields from the request
// body. ok is false for an action that cannot be carried (not gated, a
// batch operation that is not gated) or for a request that supplies one of
// those fields in the URL, which the popups would otherwise drop.
func newPendingChange(r *http.Request, action string) (*pendingChange, bool) {
	names, ok := pendingFields[action]
	if !ok {
		return nil, false
	}
	what := sensitiveActions[action]
	if action == "batch" {
		if what, ok = batchGated[r.PostFormValue("op")]; !ok {
			return nil, false
		}
	}
	query := r.URL.Query()
	p := &pendingChange{Action: action, Why: strings.ToUpper(what[:1]) + what[1:]}
	for _, name := range names {
		if _, inQuery := query[name]; inQuery {
			return nil, false
		}
		for _, value := range r.PostForm[name] {
			p.Fields = append(p.Fields, pendingField{Name: name, Value: value})
		}
	}
	return p, true
}

func (p *pendingChange) values() url.Values {
	v := url.Values{}
	for _, f := range p.Fields {
		v.Add(f.Name, f.Value)
	}
	return v
}

// describeChange words the confirm popup from the live state: what the
// policy is now, which applications an access save removes, what an
// application is called. Lookups are best effort (a failed one leaves
// plainer wording); the change itself is checked again when confirmed.
func (s *Server) describeChange(r *http.Request, p *pendingChange) {
	ctx := r.Context()
	v := p.values()
	email := v.Get("email")
	switch p.Action {
	case "set-policy":
		current := s.mfaPolicy(r)
		mode, err := mfa.ParseMode(v.Get("mode"))
		if err != nil {
			p.Question = "Change the two-factor policy?"
			return
		}
		if mode == current.Mode {
			p.Question = fmt.Sprintf("Keep the two-factor policy at %s?", mode.Label())
			p.Detail = "It is already set to that, so nothing changes."
			return
		}
		p.Question = fmt.Sprintf("Change the two-factor policy from %s to %s?", current.Mode.Label(), mode.Label())
		if n, err := s.store.CountNewlyRequiredWithoutFactor(ctx, mode); err == nil && n > 0 {
			p.Detail = fmt.Sprintf("By the current count, %s without an authenticator %s signed out now and set one up at their next sign-in.", plural(int(n), "account"), map[bool]string{true: "is", false: "are"}[n == 1])
		}
	case "set-mfa-required":
		if v.Get("required") != "on" {
			p.Question = fmt.Sprintf("Stop requiring two-factor sign-in for %s?", email)
			p.Detail = "They keep their authenticator but may turn it off."
			if target, err := s.store.PasswordAccountByEmail(ctx, email); err == nil && mfa.Required(s.mfaPolicy(r).Mode, target.IsAdmin, false) {
				p.Detail = "Only this account's own requirement is removed: the deployment policy still requires two-factor sign-in of them."
			}
			return
		}
		p.Question = fmt.Sprintf("Require two-factor sign-in for %s?", email)
		if target, err := s.store.PasswordAccountByEmail(ctx, email); err == nil && !target.MFAEnrolled {
			p.Detail = "They have no authenticator yet, so they are signed out now and set one up at their next sign-in."
		}
	case "disable":
		p.Question = fmt.Sprintf("Disable %s?", email)
		p.Detail = "They are signed out of every app and device and cannot sign in until the account is enabled again."
	case "enable":
		p.Question = fmt.Sprintf("Enable %s?", email)
		p.Detail = "They can sign in again with their current password."
	case "reset-password":
		p.Question = fmt.Sprintf("Reset the password for %s?", email)
		p.Detail = "They are signed out everywhere, and you get a new temporary password to give them."
	case "revoke-sessions":
		p.Question = fmt.Sprintf("Sign %s out of every app and device?", email)
	case "grant-admin":
		p.Question = fmt.Sprintf("Make %s an administrator?", email)
		p.Detail = "They can open this console and manage every account." + s.promotionSignOut(r, email)
	case "revoke-admin":
		p.Question = fmt.Sprintf("Remove administrator access from %s?", email)
	case "reset-mfa":
		p.Question = fmt.Sprintf("Reset two-factor sign-in for %s?", email)
		p.Detail = fmt.Sprintf("Their authenticator is removed and they are signed out everywhere; they set up a new one at their next sign-in. Reason recorded: %q.", v.Get("reason"))
	case "set-access":
		p.Question = fmt.Sprintf("Save access for %s?", email)
		p.Detail = s.describeAccess(r, email, v)
	case "disable-app", "enable-app":
		name := v.Get("app")
		if app, err := s.store.ApplicationByID(ctx, name); err == nil {
			name = app.Name
		}
		if p.Action == "disable-app" {
			p.Question = fmt.Sprintf("Disable %s for everyone?", name)
			p.Detail = "Nobody can sign in to it until it is enabled again."
		} else {
			p.Question = fmt.Sprintf("Enable %s?", name)
			p.Detail = "Everyone granted it can sign in to it again."
		}
	case "rename-team":
		p.Question, p.Detail = s.describeTeamRename(r, v.Get("from"), v.Get("to"))
	case "batch":
		emails := v["emails"]
		list := strings.Join(emails, ", ")
		if len(emails) > 5 {
			list = fmt.Sprintf("%s and %d more", strings.Join(emails[:5], ", "), len(emails)-5)
		}
		switch v.Get("op") {
		case "signout":
			p.Question = fmt.Sprintf("Sign %s out of every app and device?", plural(len(emails), "account"))
			p.Detail = list + "."
		case "require-mfa":
			p.Question = fmt.Sprintf("Require two-factor sign-in for %s?", plural(len(emails), "account"))
			p.Detail = list + ". Those without an authenticator are signed out now and set one up at their next sign-in."
		case "unrequire-mfa":
			p.Question = fmt.Sprintf("Stop requiring two-factor sign-in for %s?", plural(len(emails), "account"))
			p.Detail = list + "."
		}
	}
	if p.Question == "" {
		p.Question = "Make this change?"
	}
}

// describeAccess spells out an Access save: the applications after it
// (with Fleet's roles), the ones it removes, and the Auth Admin flag.
func (s *Server) describeAccess(r *http.Request, email string, v url.Values) string {
	ctx := r.Context()
	names := map[string]string{}
	if apps, err := s.store.ListApplications(ctx); err == nil {
		for _, app := range apps {
			names[app.ID] = app.Name
		}
	}
	name := func(id string) string {
		if n, ok := names[id]; ok {
			return n
		}
		return id
	}
	want := map[string]bool{}
	var after []string
	for _, id := range v["apps"] {
		id = strings.TrimSpace(id)
		if id == "" || want[id] {
			continue
		}
		want[id] = true
		label := name(id)
		if id == store.FleetApplicationID {
			label += " (" + fleetRoleSummary(v) + ")"
		}
		after = append(after, label)
	}
	parts := []string{"Applications: " + orNone(after) + "."}
	if target, err := s.store.PasswordAccountByEmail(ctx, email); err == nil {
		if have, err := s.store.ApplicationAccess(ctx, target.ID); err == nil {
			var removed []string
			for _, id := range have {
				if !want[id] {
					removed = append(removed, name(id))
				}
			}
			if len(removed) > 0 {
				parts = append(parts, "Removed, which signs them out of it now: "+strings.Join(removed, ", ")+".")
			}
		}
	}
	admin := v.Get("admin") == "on"
	parts = append(parts, "Auth Admin: "+map[bool]string{true: "yes", false: "no"}[admin]+"."+map[bool]string{true: s.promotionSignOut(r, email), false: ""}[admin])
	return strings.Join(parts, " ")
}

// promotionSignOut is what promoting email also does, worded for the
// confirm popup: under "Required for administrators" a new administrator
// without an authenticator is signed out to set one up.
func (s *Server) promotionSignOut(r *http.Request, email string) string {
	target, err := s.store.PasswordAccountByEmail(r.Context(), email)
	if err != nil || target.IsAdmin || target.MFAEnrolled || s.mfaPolicy(r).Mode != mfa.ModeAdmins {
		return ""
	}
	return " The policy requires two-factor sign-in of administrators and they have no authenticator, so they are signed out now and set one up at their next sign-in."
}

// fleetRoleSummary is the Fleet permissions an Access form chose, worded
// like the console's Fleet button.
func fleetRoleSummary(v url.Values) string {
	if v.Get("fleet_admin") == "on" {
		return "Fleet Admin"
	}
	chat := map[string]string{"viewer": "Viewer"}[v.Get("fleet_chat_role")]
	if chat == "" {
		chat = "Contributor"
	}
	ops := map[string]string{"readonly": "Viewer", "client": "Contributor"}[v.Get("fleet_ops_role")]
	if ops == "" {
		ops = "None"
	}
	return "Chat " + chat + " \u00b7 Ops " + ops
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// addUserDraft is the Add user form as submitted. It is echoed back only
// into this administrator's own no-store page, never logged, and dropped
// once the account is created. Everything is validated again when Create
// account is chosen.
type addUserDraft struct {
	Email, Team   string
	Password      string // the typed temporary password, byte for byte
	Admin         bool
	Apps          map[string]bool // ticked applications; none ticked stays none
	FleetAdmin    bool
	FleetChatRole string
	FleetOpsRole  string
}

func addUserDraftFromForm(r *http.Request) *addUserDraft {
	d := &addUserDraft{
		Email: r.FormValue("email"), Team: r.FormValue("team"), Password: r.FormValue("password"),
		Admin: r.FormValue("admin") == "on", Apps: map[string]bool{}, FleetAdmin: r.FormValue("fleet_admin") == "on",
		FleetChatRole: r.FormValue("fleet_chat_role"), FleetOpsRole: r.FormValue("fleet_ops_role"),
	}
	for _, id := range r.Form["apps"] {
		d.Apps[strings.TrimSpace(id)] = true
	}
	return d
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
	"rename-team":      "renaming a team",
}

// adminRenameTeam renames a team on every account (store.RenameTeam). Where
// team sync sends teams to Fleet the rename goes there as one message, so
// what is shared with the team stays shared; the store re-checks the actor
// proof in its transaction.
func (s *Server) adminRenameTeam(r *http.Request, res adminResult, actorID string, proof *store.ActorProof, now time.Time,
	needVerify func() adminResult, audit func(event, targetID, appID string)) adminResult {
	res.Tab = adminAccountsTab
	from := strings.TrimSpace(r.FormValue("from"))
	result, err := s.store.RenameTeam(r.Context(), from, r.FormValue("to"), actorID, proof, now.Unix())
	switch {
	case errors.Is(err, store.ErrActorNotFresh):
		return needVerify()
	case errors.Is(err, store.ErrInvalidTeam):
		res.Error = "A team name must be 1 to 64 bytes (64 plain letters) with no control characters."
		return res
	case errors.Is(err, store.ErrTeamNotFound):
		res.Error = fmt.Sprintf("No account is on team %s any more.", from)
		return res
	case errors.Is(err, store.ErrTeamRenameNoChange):
		res.Error = fmt.Sprintf("%s is already the team's name.", result.To)
		return res
	case err != nil:
		return res.failed("rename team", err)
	}
	audit("admin.team_renamed", "", "")
	res.Notice = fmt.Sprintf("Renamed team %s to %s (%s).", result.From, result.To, plural(int(result.Accounts), "account"))
	if result.Merged {
		res.Notice = fmt.Sprintf("Merged team %s into %s (%s moved).", result.From, result.To, plural(int(result.Accounts), "account"))
	}
	switch {
	case result.AwaitingEndpoint:
		res.Notice += " Fleet has no back-channel endpoint, so it gets the rename, and its other access updates, once one is set."
	case result.Sent:
		res.Notice += " Fleet is updated in the background."
	}
	return res
}

// describeTeamRename words the confirm popup for a team rename from the live
// teams, resolved exactly as the rename will be (store.PreviewTeamRename): how
// many accounts move, whether it merges into an existing team, and what Fleet
// keeps.
func (s *Server) describeTeamRename(r *http.Request, from, to string) (question, detail string) {
	from, to = strings.TrimSpace(from), strings.TrimSpace(to)
	question = fmt.Sprintf("Rename team %s to %s?", from, to)
	p, err := s.store.PreviewTeamRename(r.Context(), from, to)
	if err != nil {
		return question, ""
	}
	synced, _ := s.store.ApplicationTeamSync(r.Context(), store.FleetApplicationID)
	if p.Merged {
		question = fmt.Sprintf("Merge team %s (%s) into %s?", from, plural(p.Members, "account"), p.To)
		detail = fmt.Sprintf("%s already has %s: the two become one team.", p.To, plural(p.MergeMembers, "account"))
		if synced {
			detail += " In Fleet, each side then sees what the other shared with its team."
		}
		return question, detail
	}
	question = fmt.Sprintf("Rename team %s (%s) to %s?", from, plural(p.Members, "account"), p.To)
	if synced {
		detail = fmt.Sprintf("Fleet gets the rename too: everything shared with %s there stays shared with %s.", from, p.To)
	}
	return question, detail
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
			// An Add user draft is deliberately not carried: only input
			// that passed the CSRF check is echoed back into a form, so a
			// forged POST cannot open a pre-filled Add user.
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
	// counts, Add user's code popup counts, a recovery-code sign-in or a
	// password-only re-verification does not. An administrator without an
	// authenticator is sent to set one up first.
	fresh := actor.MFAEnrolled && factorRecentlyVerified(identity.Session, now, s.reauthWindow())
	// The same facts, re-checked inside the store transactions that accept
	// an actor proof.
	// Window makes the store judge freshness when each write's transaction
	// runs (after password hashing, a lock wait, earlier accounts of a
	// batch), not only as of now.
	proof := &store.ActorProof{SessionHash: identity.Session.TokenHash, FreshAfter: now.Add(-s.reauthWindow()).Unix(), RequireFactor: true, Window: s.reauthWindow()}
	var draft *addUserDraft
	if action == "create" || action == "step-up" {
		draft = addUserDraftFromForm(r)
	}
	// stepUp is every other gated action's answer to a stale proof: the code
	// popup, carrying the request so that the confirm popup can repeat it.
	stepUp := func() adminResult {
		p, ok := newPendingChange(r, action)
		if !ok {
			res.Status = http.StatusBadRequest
			return res
		}
		res.Tab, res.Reopen, res.Pending, res.Error = adminAccountsTab, reopenStepUp, p, ""
		return res
	}
	needVerify := stepUp
	// askForCode is Add user's answer to a stale proof: the code popup,
	// keeping what was typed; Create account is then chosen again. The
	// popup says why; Error is kept for a refused code.
	askForCode := func() adminResult {
		res.Tab, res.Reopen, res.Draft, res.Error = adminAccountsTab, reopenAddUserCode, draft, ""
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
			if draft != nil {
				return askForCode(), false
			}
			return stepUp(), false
		}
		return res, true
	}
	if action == "step-up" {
		// The code popup. It is not itself a change, but it is refused the
		// same way when the server or the administrator has no
		// authenticator to check. Without pending_action it is Add user's.
		then := r.PostFormValue("pending_action")
		if len(r.PostForm["pending_action"]) > 1 || then == "create" {
			res.Status = http.StatusBadRequest
			return res
		}
		var pending *pendingChange
		if then != "" {
			var ok bool
			if pending, ok = newPendingChange(r, then); !ok {
				res.Status = http.StatusBadRequest
				return res
			}
			draft = nil
		}
		if !s.mfaAvailable() || !actor.MFAEnrolled {
			r, _ := gate(sensitiveActions["create"])
			return r
		}
		return s.adminStepUp(r, identity, res, draft, pending, now)
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

	if action == "rename-team" {
		return s.adminRenameTeam(r, res, actor.ID, proof, now, needVerify, audit)
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
	if action == "create" {
		// A rejected entry reopens Add user, filled in, with the reason.
		res.Reopen, res.Draft = reopenAddUser, draft
	}
	email, ok := validAdminEmail(r.FormValue("email"))
	if !ok {
		res.Error = "Enter a valid email address."
		return res
	}
	res.ForEmail = email

	if action == "create" {
		team, err := store.NormalizeTeam(r.FormValue("team"))
		if err != nil {
			res.Error = "Team must be at most 64 bytes (64 plain letters) with no control characters."
			return res
		}
		appSettings, settingsErr := fleetSettingsFromForm(r, r.Form["apps"])
		if settingsErr != nil {
			res.Error = "Choose valid Fleet permissions."
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
		// One transaction: the administrator is re-checked when it runs,
		// after the hashing (they may have been signed out, demoted or
		// passed the window meanwhile), and the account is created with
		// everything chosen for it or not at all.
		account, granted, err := s.store.CreateAccountBy(ctx, store.AccountCreate{
			Email: email, PasswordHash: encoded, Team: team, Admin: r.FormValue("admin") == "on",
			Applications: r.Form["apps"], ApplicationSettings: appSettings,
		}, actor.ID, proof, now.Unix())
		switch {
		case errors.Is(err, store.ErrActorNotFresh):
			return askForCode()
		case errors.Is(err, store.ErrAccountExists):
			res.Error = "An account with that email already exists."
			return res
		case errors.Is(err, store.ErrApplicationNotFound):
			res.Error = "One of the chosen applications no longer exists. Choose the applications again."
			return res
		case err != nil:
			return res.failed("create account", err)
		}
		res.Reopen, res.Draft = "", nil
		audit("admin.user_created", account.ID, "")
		if account.IsAdmin {
			audit("admin.admin_granted", account.ID, "")
		}
		for _, id := range granted {
			audit("admin.access_granted", account.ID, id)
		}
		if typed {
			res.Notice = fmt.Sprintf("Created %s with the password you entered; they must change it at first sign-in.", account.Email)
		} else {
			res.Notice = fmt.Sprintf("Created %s. Share the temporary password with them; they must change it at first sign-in.", account.Email)
			res.Secret, res.SecretTitle, res.Reopen = plain, "Account created", reopenTempPassword
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
				// The administrator is re-checked in the same transaction,
				// when it runs (after the hashing).
				err = s.store.SetPasswordBy(ctx, target.Email, encoded, true, actor.ID, proof, now.Unix())
			}
		}
		if errors.Is(err, store.ErrActorNotFresh) {
			return needVerify()
		}
		if err != nil {
			return res.failed("reset password", err)
		}
		audit("admin.password_reset", target.ID, "")
		res.Notice = fmt.Sprintf("Reset the password for %s and signed them out everywhere. Share the temporary password with them.", target.Email)
		res.Secret, res.SecretTitle, res.Reopen = plain, "Password reset", reopenTempPassword
	case "revoke-sessions":
		// Allowed on one's own row too: it is "sign out everywhere", which
		// ends this session as well, so the browser goes to the sign-in page.
		// Anyone else's sessions are a sensitive change.
		var revokeProof *store.ActorProof
		if !self {
			if r, ok := gate(sensitiveActions[action]); !ok {
				return r
			}
			revokeProof = proof
		}
		n, err := s.store.RevokeAllAuthSessionsBy(ctx, target.ID, actor.ID, revokeProof, now.Unix(), "admin_revoked")
		if errors.Is(err, store.ErrActorNotFresh) {
			return needVerify()
		}
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
		err := s.store.SetAccountDisabledBy(ctx, target.Email, disable, actor.ID, proof, now.Unix())
		if errors.Is(err, store.ErrActorNotFresh) {
			return needVerify()
		}
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
		err := s.store.SetAccountAdminBy(ctx, target.Email, grant, actor.ID, proof, now.Unix())
		if errors.Is(err, store.ErrActorNotFresh) {
			return needVerify()
		}
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
			res.Error = "Team must be at most 64 bytes (64 plain letters) with no control characters."
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
		appSettings, err := fleetSettingsFromForm(r, apps)
		if err != nil {
			res.Error = "Choose valid Fleet permissions."
			return res
		}
		save := store.AccessSave{Applications: apps, ApplicationSettings: appSettings}
		if adminChange {
			save.Admin = &wantAdmin
		}
		// Every Access save is gated, so every one is re-checked in its
		// transaction, applications alone included.
		outcome, err := s.store.SaveAccountAccess(ctx, target.Email, save, actor.ID, proof, now.Unix())
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
		for _, id := range outcome.Updated {
			audit("admin.access_settings_changed", target.ID, id)
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

// adminStepUp checks the code typed into Add user's popup. It needs no
// password: it proves the factor, which is what console changes ask for,
// and it never marks the session as password-verified, so it does not
// unlock the Security page. Accepted, Add user reopens filled in for
// Create account to be chosen again; refused, the popup reopens with why.
func (s *Server) adminStepUp(r *http.Request, identity *passwordIdentity, res adminResult, draft *addUserDraft, pending *pendingChange, now time.Time) adminResult {
	res.Tab, res.Draft, res.Pending = adminAccountsTab, draft, pending
	refusal, err := s.verifySessionCode(r, identity, r.FormValue("code"), now, false)
	switch {
	case errors.Is(err, store.ErrInvalidSession):
		res.Redirect = "/"
		return res
	case err != nil:
		return res.failed("step-up", err)
	case refusal != "" && pending != nil:
		res.Reopen, res.Error = reopenStepUp, refusal
		return res
	case refusal != "":
		res.Reopen, res.Error = reopenAddUserCode, refusal
		return res
	}
	// The page rendered next reflects the proof just recorded (the policy
	// popup's hint reads it).
	at := time.Unix(now.Unix(), 0)
	identity.Session.MFAVerifiedAt, identity.Session.AMR = &at, []string{"pwd", "otp"}
	if pending != nil {
		// Nothing changes yet: the confirm popup says what will, and its
		// Confirm repeats the request through every check again.
		s.describeChange(r, pending)
		res.Reopen = reopenConfirmChange
		return res
	}
	res.Reopen = reopenAddUser
	res.Notice = "Code accepted. Check the details and choose Create account."
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
			res.Error = "Team must be at most 64 bytes (64 plain letters) with no control characters."
			return res
		}
	case "signout", "require-mfa", "unrequire-mfa":
		if r, ok := gate(batchGated[op]); !ok {
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
	// expired: the store refused the administrator's proof part-way. Not
	// offered for repeating: part of the selection is already done, and
	// repeating all of it could undo what someone changed since.
	expired := func() adminResult {
		res.Error = fmt.Sprintf("Your authenticator code expired partway through. Already done: %s. Select the accounts that remain and repeat the change.", orNone(done))
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
			if _, err := s.store.RevokeAllAuthSessionsBy(ctx, target.ID, actor.ID, proof, now.Unix(), "admin_revoked"); err != nil {
				if errors.Is(err, store.ErrActorNotFresh) {
					return expired()
				}
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
					return expired()
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
		"Secret": result.Secret, "SecretTitle": result.SecretTitle, "SecretFor": result.ForEmail, "Reopen": result.Reopen, "Draft": result.Draft,
		"Pending": result.Pending, "NeedEnroll": result.NeedEnroll, "MFAAvailable": s.mfaAvailable(),
		"ActorEnrolled": actor.MFAEnrolled, "ActorFresh": actor.MFAEnrolled && factorRecentlyVerified(identity.Session, now, s.reauthWindow()),
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
		accessSettings, err := s.store.AllApplicationAccessSettings(ctx)
		if err != nil {
			logUnlessCancelled("admin list access settings", err)
			data["Error"] = joinMessages(result.Error, "Application permissions could not be loaded.")
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
			fleetSettings := decodeFleetSettings(accessSettings[a.ID]["fleet"])
			row.FleetGranted = granted["fleet"]
			row.FleetAdmin = fleetSettings.ChatRole == "admin" && fleetSettings.OpsRole == "admin"
			row.FleetChatRole, row.FleetOpsRole = fleetSettings.ChatRole, fleetSettings.OpsRole
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
			if app.ID == "fleet" && app.DisabledAt == nil {
				data["HasFleet"] = true
			}
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
		if counts, err := s.store.TeamCounts(ctx); err != nil {
			logUnlessCancelled("admin team counts", err)
		} else {
			data["TeamCounts"] = counts
		}
		data["TeamSync"], _ = s.store.ApplicationTeamSync(ctx, store.FleetApplicationID)
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
