package httpapi

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"net/url"
	"sort"
	"strings"
	"time"

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
	Created     string
	Sessions    int
	Apps        []adminAppChoice
	Self        bool
	CanDisable  bool // not self and not the last enabled admin
	CanDemote   bool
}

type adminSignInRow struct {
	Email    string
	Count    int
	Last     string
	Disabled bool
}

type adminDeliveryRow struct {
	Reason      string
	Issued      string
	Attempts    int
	NextAttempt string
	LastError   string
	Abandoned   bool
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
	Pending     []adminDeliveryRow
	Granted     int
}

// adminResult is what one POST leaves for the re-rendered page. Status is
// non-zero when the action must not render the page at all: an unexpected
// failure (500, so an uncertain outcome is never dressed up as "nothing
// changed") or a request the UI never sends (400).
type adminResult struct {
	Notice   string
	Error    string
	Secret   string // temporary password, shown once
	ForEmail string
	Tab      string
	Status   int
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
	identity := s.currentPasswordSession(r)
	if identity == nil {
		http.Redirect(w, r, "/?return_to="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return
	}
	if identity.Account.MustChangePassword {
		http.Redirect(w, r, "/change-password", http.StatusSeeOther)
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
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if !s.validCSRF(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		result = s.adminAction(r, identity.Account)
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
	s.renderAdmin(w, r, identity.Account, csrf, result)
}

// adminAction performs one console action and reports the outcome for the
// page. Every failure is a message, never a 500: the administrator is
// looking at the page and can act on it.
func (s *Server) adminAction(r *http.Request, actor store.Account) adminResult {
	ctx := r.Context()
	now := time.Now()
	action := r.FormValue("action")
	tab := r.FormValue("tab")
	res := adminResult{Tab: tab}
	ipHash := s.rateKey("ip", clientIP(r))
	audit := func(event, targetID, appID string) {
		if err := s.store.RecordAdminAction(ctx, event, actor.ID, targetID, appID, ipHash, now.Unix()); err != nil {
			log.Printf("admin audit %s: %v", event, err)
		}
	}

	// Application actions live on that application's tab.
	switch action {
	case "disable-app", "enable-app":
		appID := strings.TrimSpace(r.FormValue("app"))
		app, err := s.store.ApplicationByID(ctx, appID)
		if err != nil {
			res.Error = "No application with that ID."
			return res
		}
		res.Tab = app.ID
		disable := action == "disable-app"
		if err := s.store.SetApplicationDisabled(ctx, app.ID, disable, now.Unix()); err != nil {
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

	res.Tab = adminAccountsTab
	email, ok := validAdminEmail(r.FormValue("email"))
	if !ok {
		res.Error = "Enter a valid email address."
		return res
	}
	res.ForEmail = email

	if action == "create" {
		plain, err := passwordauth.Generate(s.passwordContext(email)...)
		if err != nil {
			return res.failed("generate password", err)
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
		audit("admin.user_created", account.ID, "")
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
			res.Notice = fmt.Sprintf("Created %s. Share the temporary password below; they must change it at first sign-in.", account.Email)
		}
		res.Secret = plain
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
		if self {
			res.Error = "Use Sign out for your own sessions."
			return res
		}
		n, err := s.store.RevokeAllAuthSessions(ctx, target.ID, now.Unix(), "admin_revoked")
		if err != nil {
			return res.failed("revoke sessions", err)
		}
		audit("admin.sessions_revoked", target.ID, "")
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
	case "set-access":
		added, removed, err := s.store.SetApplicationAccess(ctx, target.ID, r.Form["apps"], now.Unix())
		if errors.Is(err, store.ErrApplicationNotFound) {
			res.Error = "One of those applications is not registered."
			return res
		}
		if err != nil {
			return res.failed("set access", err)
		}
		for _, id := range added {
			audit("admin.access_granted", target.ID, id)
		}
		for _, id := range removed {
			audit("admin.access_revoked", target.ID, id)
		}
		switch {
		case len(added) == 0 && len(removed) == 0:
			res.Notice = fmt.Sprintf("No change to %s's applications.", target.Email)
		case len(removed) == 0:
			res.Notice = fmt.Sprintf("%s can now sign in to %s.", target.Email, strings.Join(added, ", "))
		case len(added) == 0:
			res.Notice = fmt.Sprintf("%s was signed out of and can no longer sign in to %s.", target.Email, strings.Join(removed, ", "))
		default:
			res.Notice = fmt.Sprintf("%s: added %s; removed %s (and signed out of it).", target.Email, strings.Join(added, ", "), strings.Join(removed, ", "))
		}
	default:
		res.Status = http.StatusBadRequest
	}
	return res
}

// renderAdmin builds the whole page for the chosen tab. Read failures fall
// back to a visible error line with whatever did load, since the page is
// where an administrator would go to fix things.
func (s *Server) renderAdmin(w http.ResponseWriter, r *http.Request, actor store.Account, csrf string, result adminResult) {
	ctx := r.Context()
	now := time.Now()
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
		"Secret": result.Secret, "SecretFor": result.ForEmail,
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
				Email: a.Email, IsAdmin: a.IsAdmin, Created: a.CreatedAt.UTC().Format("2006-01-02"),
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
			granted := accessSet(access[a.ID])
			for _, app := range apps {
				row.Apps = append(row.Apps, adminAppChoice{ID: app.ID, Name: app.Name, Granted: granted[app.ID]})
			}
			rows = append(rows, row)
		}
		choices := make([]adminAppChoice, 0, len(apps))
		for _, app := range apps {
			choices = append(choices, adminAppChoice{ID: app.ID, Name: app.Name, Granted: app.DisabledAt == nil})
		}
		data["Accounts"] = rows
		data["AppChoices"] = choices
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
		pending, err := s.store.PendingLogoutDeliveries(ctx, app.ID, now.Unix())
		if err != nil {
			logUnlessCancelled("admin pending deliveries", err)
			data["Error"] = joinMessages(result.Error, "Pending sign-outs could not be loaded.")
		}
		for _, d := range pending {
			view.Pending = append(view.Pending, adminDeliveryRow{
				Reason: d.Reason, Issued: d.IssuedAt.UTC().Format("2006-01-02 15:04 UTC"),
				Attempts: d.Attempts, NextAttempt: d.NextAttemptAt.UTC().Format("15:04:05 UTC"),
				LastError: d.LastError, Abandoned: d.Abandoned,
			})
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
