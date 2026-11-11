package httpapi

import (
	"log"
	"net/http"
)

// handleAuthenticatorHelp serves the public guide to setting up an
// authenticator app (/help/authenticator): what two-factor sign-in is, the
// three ways to add the account, app-by-app steps and troubleshooting. The
// set-up, sign-in code, Security and sign-in pages link to it. It needs no
// session and holds nothing secret; magic-link mode has no second factor, so
// there it is a 404 like the other two-factor routes.
func (s *Server) handleAuthenticatorHelp(w http.ResponseWriter, r *http.Request) {
	if !s.passwordMode() {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, translate(requestLanguage(r), "method not allowed"), http.StatusMethodNotAllowed)
		return
	}
	if err := s.render(w, "help-authenticator.html", map[string]any{
		"Brand":  s.cfg.BrandName,
		"Issuer": s.cfg.MFAIssuer,
	}); err != nil {
		log.Printf("render authenticator help: %v", err)
	}
}
