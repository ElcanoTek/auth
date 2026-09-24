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

func TestSelectedPermissionChoiceGetsTheOutline(t *testing.T) {
	if !strings.Contains(componentCSS, `.permission-choice:has(input:checked)`) {
		t.Fatal("selected permission choices do not receive the outline")
	}
}
