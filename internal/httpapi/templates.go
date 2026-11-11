package httpapi

import (
	"fmt"
	"html"
	"time"
)

// Page templates live in templates/*.html and their CSS and JavaScript in
// static/, both embedded (see assets.go). This file keeps the two magic-link
// email bodies, which are plain strings rather than pages.

// Email bodies are intentionally generic — no logos, no brand colors,
// no marketing copy. Goal: a message that works unchanged for every
// client deployment without per-tenant theming.
// {{Brand}} only appears in the subject line; the body is plain text
// wrapped in the most minimal HTML that still gets a clickable button.

func renderTextEmail(_, link, code string, ttl time.Duration, languages ...string) string {
	return fmt.Sprintf(translate(selectedLanguage(languages), `Your sign-in code: %s

Type it on the sign-in page that asked for it. Or open this one-time link
(both expire in %d minutes):

%s

Never share this code. If you didn't request this, you can ignore this email.
`), code, int(ttl.Minutes()), link)
}

func renderHTMLEmail(_, link, code string, ttl time.Duration, languages ...string) string {
	lang := selectedLanguage(languages)
	return fmt.Sprintf(`<!doctype html>
<html lang="%s"><body style="font:16px/1.5 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;color:#1a1a1a;padding:24px">
  <p>%s</p>
  <p style="font:600 28px/1.2 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;letter-spacing:.2em;margin:8px 0 16px">%s</p>
  <p>%s</p>
  <p><a ses:no-track href="%s" style="display:inline-block;padding:10px 18px;background:#1a1a1a;color:#fff;text-decoration:none;border-radius:6px">%s</a></p>
  <p style="color:#666;font-size:.9em;word-break:break-all">%s</p>
  <p style="color:#888;font-size:.85em;margin-top:24px">%s</p>
</body></html>`, lang,
		html.EscapeString(translate(lang, "Your sign-in code:")), html.EscapeString(code),
		html.EscapeString(translate(lang, "Type it on the sign-in page that asked for it. Or open this one-time link (both expire in {0} minutes):", int(ttl.Minutes()))),
		html.EscapeString(link), html.EscapeString(translate(lang, "Sign in")),
		html.EscapeString(translate(lang, "Or paste this link: {0}", link)),
		html.EscapeString(translate(lang, "Never share this code. If you didn't request this, you can ignore this email.")))
}
