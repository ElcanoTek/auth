package httpapi

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/elcanotek/auth/internal/config"
)

// The signed-in page links to the applications this deployment registered
// and greys out the rest. Availability is the applications table, nothing
// else: registering explorer + fleet lights Admin (Fleet's console), Fleet and
// Explorer; Lens stays a non-link.
func TestAccountPageLinksRegisteredAppsAndGreysOutTheRest(t *testing.T) {
	ts, st, cfg, plain := newPasswordTestServer(t, false)
	now := time.Now().Unix()
	if _, err := st.CreateApplication(context.Background(), "explorer", "Explorer", "https://explorer.client.example/auth/callback", "https://explorer.client.example/signed-out", hashSecret("s1"), now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateApplication(context.Background(), "fleet", "Fleet", "https://fleet.client.example/api/auth/oidc/callback", "", hashSecret("s2"), now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateApplication(context.Background(), "lens", "Lens", "https://lens.client.example/auth/callback", "", hashSecret("s3"), now); err != nil {
		t.Fatal(err)
	}
	if err := st.SetApplicationDisabled(context.Background(), "lens", true, now); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"explorer", "fleet", "lens"} {
		grantAccess(t, st, "alice@example.com", id)
	}
	if err := st.SetAccountAdmin(context.Background(), "alice@example.com", true, now); err != nil {
		t.Fatal(err)
	}

	body := accountPage(t, ts, cfg, plain)
	for _, want := range []string{
		`href="/admin"`,
		`href="https://fleet.client.example/"`,
		`href="https://explorer.client.example/"`,
		`<h3>Lens</h3>`,
		`aria-disabled="true"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("account page lacks %s\n%s", want, body)
		}
	}
	if strings.Contains(body, "lens.client.example") {
		t.Fatalf("disabled lens application is linked:\n%s", body)
	}
	// Tiles keep the catalogue order regardless of registration order.
	order := regexp.MustCompile(`<h3>(Admin|Fleet|Explorer|Lens)</h3>`).FindAllStringSubmatch(body, -1)
	var names []string
	for _, m := range order {
		names = append(names, m[1])
	}
	if strings.Join(names, ",") != "Admin,Fleet,Explorer,Lens" {
		t.Fatalf("tile order = %v", names)
	}
	// Exactly one greyed tile, and it is not an anchor.
	if n := strings.Count(body, `class="tile tile-off"`); n != 1 {
		t.Fatalf("greyed tiles = %d, want 1", n)
	}
	if n := strings.Count(body, `<a class="tile"`); n != 3 {
		t.Fatalf("linked tiles = %d, want 3", n)
	}
	// The greyed tile is inert: no href, not focusable, no leftover URL.
	off := body[strings.Index(body, `class="tile tile-off"`):]
	off = off[:strings.Index(off, "</div>")]
	if strings.Contains(off, "href=") || strings.Contains(off, "tabindex") || strings.Contains(off, "http") {
		t.Fatalf("greyed tile is not inert:\n%s", off)
	}
	if strings.Contains(body, "ZgotmplZ") {
		t.Fatalf("template refused a URL:\n%s", body)
	}
}

// The signed-in page names the account and now the deployment's application
// hosts, so it must not be cached or leak a referrer; the tiles open the apps
// without one either.
func TestAccountPageIsUncachedAndReferrerFree(t *testing.T) {
	ts, st, cfg, plain := newPasswordTestServer(t, false)
	if _, err := st.CreateApplication(context.Background(), "fleet", "Fleet", "https://fleet.client.example/api/auth/oidc/callback", "", hashSecret("s"), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	grantAccess(t, st, "alice@example.com", "fleet")
	_, session, csrf := passwordLogin(t, ts, cfg, "alice@example.com", plain)
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/account", nil)
	req.AddCookie(session)
	req.AddCookie(csrf)
	resp, err := noFollowClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("headers: Cache-Control=%q Referrer-Policy=%q", resp.Header.Get("Cache-Control"), resp.Header.Get("Referrer-Policy"))
	}
	if !strings.Contains(string(body), `<a class="tile" href="https://fleet.client.example/" rel="noreferrer">`) {
		t.Fatalf("fleet tile is not a noreferrer link:\n%s", body)
	}
}

// With nothing registered every tile is greyed and nothing links anywhere;
// the page still renders (it is where people sign out).
func TestAccountPageWithNoApplicationsGreysEveryTile(t *testing.T) {
	ts, _, cfg, plain := newPasswordTestServer(t, false)
	body := accountPage(t, ts, cfg, plain)
	if n := strings.Count(body, `class="tile tile-off"`); n != 4 {
		t.Fatalf("greyed tiles = %d, want 4\n%s", n, body)
	}
	if strings.Contains(body, `<a class="tile"`) || !strings.Contains(body, `action="/logout"`) {
		t.Fatalf("unexpected link or missing sign-out form:\n%s", body)
	}
}

func accountPage(t *testing.T, ts *httptest.Server, cfg *config.Config, plain string) string {
	t.Helper()
	_, session, csrf := passwordLogin(t, ts, cfg, "alice@example.com", plain)
	if session == nil || csrf == nil {
		t.Fatal("login did not issue a session and CSRF cookie")
	}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/account", nil)
	req.AddCookie(session)
	req.AddCookie(csrf)
	resp, err := noFollowClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /account = %d\n%s", resp.StatusCode, body)
	}
	return string(body)
}

// Registered but not granted: the tile is greyed for this account, and the
// page says so with the same inert markup.
func TestAccountPageGreysAppsTheAccountCannotOpen(t *testing.T) {
	ts, st, cfg, plain := newPasswordTestServer(t, false)
	now := time.Now().Unix()
	if _, err := st.CreateApplication(context.Background(), "fleet", "Fleet", "https://fleet.client.example/api/auth/oidc/callback", "", hashSecret("s"), now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateApplication(context.Background(), "explorer", "Explorer", "https://explorer.client.example/auth/callback", "", hashSecret("s"), now); err != nil {
		t.Fatal(err)
	}
	grantAccess(t, st, "alice@example.com", "explorer")
	body := accountPage(t, ts, cfg, plain)
	if strings.Contains(body, "fleet.client.example") || !strings.Contains(body, `href="https://explorer.client.example/"`) {
		t.Fatalf("access not reflected:\n%s", body)
	}
	if n := strings.Count(body, `class="tile tile-off"`); n != 3 {
		t.Fatalf("greyed tiles = %d, want 3 (Admin, Fleet, Lens)", n)
	}
}
