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

// The console never shows or takes a temporary password (the operator CLI
// alone sets one), so none of the machinery for one is left: no password
// field to toggle or generate, no one-time password popup, no Copy button.
func TestConsoleHasNoTemporaryPasswordMachinery(t *testing.T) {
	for _, gone := range []string{"data-temp-password", "data-generate", "data-keep-open", "navigator.clipboard"} {
		if strings.Contains(adminScript, gone) {
			t.Errorf("admin script still has %q", gone)
		}
	}
	if strings.Contains(componentCSS, ".temp-password") {
		t.Error("the stylesheet still styles the temporary password popup")
	}
}

func TestSelectedPermissionChoiceGetsTheOutline(t *testing.T) {
	if !strings.Contains(componentCSS, `.permission-choice:has(input:checked)`) {
		t.Fatal("selected permission choices do not receive the outline")
	}
}
