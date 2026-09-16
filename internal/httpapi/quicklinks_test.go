package httpapi

import (
	"testing"
	"time"

	"github.com/elcanotek/auth/internal/store"
)

// allAccess grants every listed application, so these tests exercise the
// application-selection rule alone; access itself is tested separately.
func allAccess(apps []store.Application) map[string]bool {
	out := map[string]bool{}
	for _, app := range apps {
		out[app.ID] = true
	}
	return out
}

func linksByName(apps []store.Application) map[string]quickLink {
	out := map[string]quickLink{}
	for _, link := range quickLinksFor(apps, allAccess(apps), false) {
		out[link.Name] = link
	}
	return out
}

func TestQuickLinksResolveAgainstRegisteredApplications(t *testing.T) {
	apps := []store.Application{
		{ID: "explorer", Name: "Explorer", RedirectURI: "https://explorer.client.example/auth/callback"},
		{ID: "fleet", Name: "Fleet", RedirectURI: "https://Fleet.Client.Example/api/auth/oidc/callback"},
	}
	links := quickLinksFor(apps, allAccess(apps), true)
	want := []quickLink{
		{Kicker: "Administration", Name: "Admin", Description: "Accounts, access, and applications on this sign-in.", URL: "/admin", Available: true},
		{Kicker: "Agents", Name: "Fleet", Description: "Work with your AI agents and their tasks.", URL: "https://fleet.client.example/", Available: true},
		{Kicker: "Reporting", Name: "Explorer", Description: "Explore reporting on your programmatic activity.", URL: "https://explorer.client.example/", Available: true},
		{Kicker: "Classification", Name: "Lens", Description: "Classify supply quality with AI signals."},
	}
	if len(links) != len(want) {
		t.Fatalf("got %d links, want %d", len(links), len(want))
	}
	for i := range want {
		if links[i] != want[i] {
			t.Errorf("link %d = %+v, want %+v", i, links[i], want[i])
		}
	}
}

// Nothing usable means a greyed tile, never a guess: no rows, a disabled
// row, an unknown family, a display name that only *looks* like a family,
// and every redirect shape validApplicationRedirect refuses.
func TestQuickLinksGreyOutWhatTheClientDoesNotHave(t *testing.T) {
	disabled := time.Now()
	cases := []struct {
		name string
		apps []store.Application
	}{
		{"no applications", nil},
		{"disabled application", []store.Application{{ID: "lens", RedirectURI: "https://lens.example/auth/callback", DisabledAt: &disabled}}},
		{"unknown family", []store.Application{{ID: "pages", Name: "Pages", RedirectURI: "https://pages.example/cb"}}},
		{"name is not an identity", []store.Application{{ID: "client-42", Name: "Fleet", RedirectURI: "https://evil.example/cb"}}},
		{"bare prefix", []store.Application{{ID: "fleet-", RedirectURI: "https://fleet.example/cb"}}},
		{"prefix without dash", []store.Application{{ID: "fleetish", RedirectURI: "https://fleet.example/cb"}}},
		{"plain http off loopback", []store.Application{{ID: "lens", RedirectURI: "http://lens.example/cb"}}},
		{"non-http scheme", []store.Application{{ID: "lens", RedirectURI: "javascript:alert(1)"}}},
		{"scheme-relative", []store.Application{{ID: "lens", RedirectURI: "//lens.example/cb"}}},
		{"userinfo", []store.Application{{ID: "lens", RedirectURI: "https://lens.example@evil.example/cb"}}},
		{"query", []store.Application{{ID: "lens", RedirectURI: "https://lens.example/cb?x=1"}}},
		{"fragment", []store.Application{{ID: "lens", RedirectURI: "https://lens.example/cb#f"}}},
		{"no path", []store.Application{{ID: "lens", RedirectURI: "https://lens.example"}}},
		{"unparsable", []store.Application{{ID: "lens", RedirectURI: "https://[::1"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, link := range quickLinksFor(tc.apps, allAccess(tc.apps), false) {
				if link.Available || link.URL != "" {
					t.Fatalf("%s: tile %q is linked to %q, want greyed out", tc.name, link.Name, link.URL)
				}
			}
		})
	}
}

// Exact ID beats a suffixed one; a single suffixed ID stands in for the kind;
// two suffixed IDs with no exact one are ambiguous and fail closed. The
// disabled exact row does not block the enabled suffixed one, and a
// disabled suffixed row does not make the remaining one ambiguous.
func TestQuickLinksSelectionRule(t *testing.T) {
	disabled := time.Now()
	t.Run("exact over suffixed", func(t *testing.T) {
		links := linksByName([]store.Application{
			{ID: "explorer-staging", RedirectURI: "https://explorer-staging.example/auth/callback"},
			{ID: "explorer", RedirectURI: "https://explorer.example/auth/callback"},
		})
		if links["Explorer"].URL != "https://explorer.example/" {
			t.Fatalf("Explorer = %+v", links["Explorer"])
		}
	})
	t.Run("single suffixed", func(t *testing.T) {
		links := linksByName([]store.Application{
			{ID: "explorer-omnicom", RedirectURI: "https://explorer.omc.example/auth/callback"},
			{ID: "Fleet-Omnicom", RedirectURI: "http://localhost:3000/api/auth/oidc/callback"},
		})
		if links["Explorer"].URL != "https://explorer.omc.example/" {
			t.Fatalf("Explorer = %+v", links["Explorer"])
		}
		if links["Fleet"].URL != "http://localhost:3000/" {
			t.Fatalf("Fleet = %+v", links["Fleet"])
		}
	})
	t.Run("ambiguous suffixed fails closed", func(t *testing.T) {
		links := linksByName([]store.Application{
			{ID: "fleet-a", RedirectURI: "https://a.example/cb"},
			{ID: "fleet-b", RedirectURI: "https://b.example/cb"},
		})
		if links["Fleet"].Available {
			t.Fatalf("ambiguous fleet linked: %+v", links["Fleet"])
		}
	})
	t.Run("disabled rows do not count either way", func(t *testing.T) {
		links := linksByName([]store.Application{
			{ID: "fleet", RedirectURI: "https://old.example/cb", DisabledAt: &disabled},
			{ID: "fleet-b", RedirectURI: "https://gone.example/cb", DisabledAt: &disabled},
			{ID: "fleet-a", RedirectURI: "https://a.example/cb"},
		})
		if links["Fleet"].URL != "https://a.example/" {
			t.Fatalf("Fleet = %+v", links["Fleet"])
		}
	})
	t.Run("exact match with an unusable redirect does not fall through", func(t *testing.T) {
		links := linksByName([]store.Application{
			{ID: "lens", RedirectURI: "http://lens.example/cb"},
			{ID: "lens-b", RedirectURI: "https://lens-b.example/cb"},
		})
		if links["Lens"].Available {
			t.Fatalf("Lens fell through to a suffixed row: %+v", links["Lens"])
		}
	})
}

func TestAppOriginKeepsSchemeAndHostOnly(t *testing.T) {
	cases := map[string]string{
		"https://fleet.example/api/auth/oidc/callback": "https://fleet.example",
		"https://Fleet.Example:8443/cb":                "https://fleet.example:8443",
		"http://localhost:3000/cb":                     "http://localhost:3000",
		"http://127.0.0.1:9000/cb":                     "http://127.0.0.1:9000",
		"http://[::1]:9000/cb":                         "http://[::1]:9000",
		"http://fleet.example/cb":                      "",
		"ftp://fleet.example/cb":                       "",
		"/relative/cb":                                 "",
		"":                                             "",
	}
	for in, want := range cases {
		got, ok := appOrigin(in)
		switch {
		case want == "" && ok:
			t.Errorf("appOrigin(%q) = %v, want rejection", in, got)
		case want != "" && (!ok || got.String() != want):
			t.Errorf("appOrigin(%q) = %v %v, want %q", in, got, ok, want)
		}
	}
}

// A tile is "you can open this": registered is not enough, the account must
// have been granted the application. Admin follows the account flag alone.
func TestQuickLinksFollowAccessAndAdminFlag(t *testing.T) {
	apps := []store.Application{
		{ID: "explorer", RedirectURI: "https://explorer.example/auth/callback"},
		{ID: "fleet", RedirectURI: "https://fleet.example/api/auth/oidc/callback"},
	}
	byName := func(access map[string]bool, admin bool) map[string]quickLink {
		out := map[string]quickLink{}
		for _, l := range quickLinksFor(apps, access, admin) {
			out[l.Name] = l
		}
		return out
	}
	only := byName(map[string]bool{"fleet": true}, false)
	if !only["Fleet"].Available || only["Explorer"].Available || only["Admin"].Available {
		t.Fatalf("fleet-only access: %+v", only)
	}
	none := byName(nil, false)
	for _, name := range []string{"Admin", "Fleet", "Explorer", "Lens"} {
		if none[name].Available {
			t.Fatalf("%s available with no access", name)
		}
	}
	admin := byName(nil, true)
	if !admin["Admin"].Available || admin["Admin"].URL != "/admin" || admin["Fleet"].Available {
		t.Fatalf("admin without app access: %+v", admin)
	}
}
