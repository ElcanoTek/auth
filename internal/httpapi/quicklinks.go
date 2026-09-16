package httpapi

import (
	"log"
	"net/url"
	"strings"

	"github.com/elcanotek/auth/internal/store"
)

// quickLink is one tile on the signed-in page: a fixed catalogue entry
// (name, blurb) resolved against the applications this deployment has
// registered. Available is false when no enabled application of that kind
// exists, and the tile renders greyed out instead of as a link.
type quickLink struct {
	Kicker      string
	Name        string
	Description string
	URL         string
	Available   bool
}

// quickLinkSpec is the static half of a tile. Kind is the application family
// it belongs to (see selectApplication) and Path is the origin-rooted path
// the tile opens. Descriptions are deliberately generic: this is the engine
// repo, and client wording lives in the client bundle.
type quickLinkSpec struct {
	Kicker, Name, Description, Kind, Path string
}

// adminKind marks the tile for Auth's own console: it follows the signed-in
// account's administrator flag, not the applications table.
const adminKind = "admin"

// quickLinkCatalog is the fixed tile order.
var quickLinkCatalog = []quickLinkSpec{
	{Kicker: "Administration", Name: "Admin", Description: "Accounts, access, and applications on this sign-in.", Kind: adminKind, Path: "/admin"},
	{Kicker: "Agents", Name: "Fleet", Description: "Work with your AI agents and their tasks.", Kind: "fleet", Path: "/"},
	{Kicker: "Reporting", Name: "Explorer", Description: "Explore reporting on your programmatic activity.", Kind: "explorer", Path: "/"},
	{Kicker: "Classification", Name: "Lens", Description: "Classify supply quality with AI signals.", Kind: "lens", Path: "/"},
}

// quickLinkKinds are the application families the catalogue knows.
var quickLinkKinds = []string{"fleet", "explorer", "lens"}

// quickLinksFor resolves the catalogue for one signed-in account: a tile is
// live when an enabled application of that kind is registered with a usable
// origin AND the account has been granted access to it (access is keyed by
// application ID). The Admin tile is live for administrators only. It never
// fails: anything unusable leaves its tile greyed out.
func quickLinksFor(apps []store.Application, access map[string]bool, isAdmin bool) []quickLink {
	origins := map[string]*url.URL{}
	for _, kind := range quickLinkKinds {
		app, ok := selectApplication(apps, kind)
		if !ok || !access[app.ID] {
			continue
		}
		if origin, ok := appOrigin(app.RedirectURI); ok {
			origins[kind] = origin
		} else {
			log.Printf("quick links: application %q has no https origin to link to; %s tile greyed out", app.ID, kind)
		}
	}
	out := make([]quickLink, 0, len(quickLinkCatalog))
	for _, spec := range quickLinkCatalog {
		link := quickLink{Kicker: spec.Kicker, Name: spec.Name, Description: spec.Description}
		switch {
		case spec.Kind == adminKind:
			if isAdmin {
				link.URL, link.Available = spec.Path, true
			}
		default:
			if origin, ok := origins[spec.Kind]; ok {
				link.URL = (&url.URL{Scheme: origin.Scheme, Host: origin.Host, Path: spec.Path}).String()
				link.Available = true
			}
		}
		out = append(out, link)
	}
	return out
}

// accessSet turns an account's application IDs into a lookup.
func accessSet(ids []string) map[string]bool {
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out
}

// selectApplication picks the one enabled application that stands for a
// kind, by ID only (the operator's choice at `auth app create`; names are
// free text and must not steer a trusted link). The exact ID wins; otherwise
// exactly one `<kind>-<suffix>` ID (DEPLOY.md's `explorer-omnicom` shape)
// does. Two or more suffixed candidates and no exact one is ambiguous: the
// tile stays greyed out and the operator is told, because a wrong guess
// would send every user to the wrong deployment under a trusted label.
// Disabled applications never count.
func selectApplication(apps []store.Application, kind string) (store.Application, bool) {
	var suffixed []store.Application
	for _, app := range apps {
		if app.DisabledAt != nil {
			continue
		}
		id := strings.ToLower(app.ID)
		switch {
		case id == kind:
			return app, true
		case strings.HasPrefix(id, kind+"-") && len(id) > len(kind)+1:
			suffixed = append(suffixed, app)
		}
	}
	switch len(suffixed) {
	case 0:
		return store.Application{}, false
	case 1:
		return suffixed[0], true
	default:
		ids := make([]string, 0, len(suffixed))
		for _, app := range suffixed {
			ids = append(ids, app.ID)
		}
		log.Printf("quick links: %d enabled %s-* applications (%s) and no %q; %s tile greyed out until one is named %q or the rest are disabled",
			len(suffixed), kind, strings.Join(ids, ", "), kind, kind, kind)
		return store.Application{}, false
	}
}

// appOrigin returns the scheme and lowercased host of an application's
// redirect URI, or false when the URI would not pass validApplicationRedirect
// (https, or http on loopback; a host; no userinfo, query or fragment). The
// CLI applies that rule at `auth app create`, but the store does not, so a
// row that arrived another way is re-checked here before its origin is shown
// to every signed-in user as a trusted link. Only the origin is kept: the
// callback path is the OIDC endpoint, not a place to send people.
func appOrigin(redirectURI string) (*url.URL, bool) {
	if !validApplicationRedirect(redirectURI) {
		return nil, false
	}
	u, err := url.Parse(redirectURI)
	if err != nil {
		return nil, false
	}
	return &url.URL{Scheme: u.Scheme, Host: strings.ToLower(u.Host)}, true
}
