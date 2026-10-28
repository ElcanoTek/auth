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
	if !strings.Contains(componentCSS, `.temp-password .secret .btn-ghost[hidden] { display: none; }`) {
		t.Fatal("the Copy button shows without script (btn-ghost overrides [hidden])")
	}
}

func TestSelectedPermissionChoiceGetsTheOutline(t *testing.T) {
	if !strings.Contains(componentCSS, `.permission-choice:has(input:checked)`) {
		t.Fatal("selected permission choices do not receive the outline")
	}
}
