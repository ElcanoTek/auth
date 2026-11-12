package httpapi

import (
	"strings"
	"testing"
)

func TestAdminPermissionDefaultsStayInSync(t *testing.T) {
	for _, want := range []string{
		`["explorer", "fleet"].indexOf(app.value)`,
		`app.checked = toggle.checked`,
		`fleetAdmin.checked = toggle.checked`,
		`input[name="fleet_chat_role"], input[name="fleet_ops_role"]`,
		`if (fleetAdmin) fleetAdmin.checked = false`,
	} {
		if !strings.Contains(adminScript, want) {
			t.Fatalf("admin permission script lacks %q", want)
		}
	}
}

// The one-time password popup must not close on a stray click outside it,
// and its Copy button is wired to the password itself.
func TestTemporaryPasswordPopupScript(t *testing.T) {
	for _, want := range []string{
		`document.querySelectorAll("dialog.modal:not([data-keep-open])")`,
		`navigator.clipboard.writeText(source.textContent)`,
	} {
		if !strings.Contains(adminScript, want) {
			t.Fatalf("admin script lacks %q", want)
		}
	}
	if !strings.Contains(componentCSS, `.temp-password .secret .btn[hidden] { display: none; }`) {
		t.Fatal("the Copy button shows without script (.btn overrides [hidden])")
	}
}

// With an invite chosen, Add user hides the temporary password field and
// disables its input (a typed value is not sent, and cannot block the form's
// validation out of sight). Only script hides it: a stylesheet rule would
// hide an enabled input, and a too-short value left in it would stop the
// form submitting with nothing visible to fix.
func TestInviteHidesTheTemporaryPasswordField(t *testing.T) {
	for _, want := range []string{
		`document.querySelectorAll("[data-temp-password]")`,
		`field.hidden = !temp.checked`,
		`input.disabled = !temp.checked`,
		`if (only) only.hidden = true`,
	} {
		if !strings.Contains(adminScript, want) {
			t.Fatalf("admin script lacks %q", want)
		}
	}
	if strings.Contains(componentCSS, "data-temp-password") {
		t.Fatal("a stylesheet rule hides the temporary password field; without script its input stays enabled")
	}
}

func TestSelectedPermissionChoiceGetsTheOutline(t *testing.T) {
	if !strings.Contains(componentCSS, `.permission-choice:has(input:checked)`) {
		t.Fatal("selected permission choices do not receive the outline")
	}
}
