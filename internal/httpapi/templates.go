package httpapi

import (
	"fmt"
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

func renderTextEmail(_, link, code string, ttl time.Duration) string {
	return fmt.Sprintf(`Your sign-in code: %s

Type it on the sign-in page that asked for it. Or open this one-time link
(both expire in %d minutes):

%s

Never share this code. If you didn't request this, you can ignore this email.
`, code, int(ttl.Minutes()), link)
}

func renderHTMLEmail(_, link, code string, ttl time.Duration) string {
	return fmt.Sprintf(`<!doctype html>
<html><body style="font:16px/1.5 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;color:#1a1a1a;padding:24px">
  <p>Your sign-in code:</p>
  <p style="font:600 28px/1.2 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;letter-spacing:.2em;margin:8px 0 16px">%s</p>
  <p>Type it on the sign-in page that asked for it. Or open this one-time link (both expire in %d minutes):</p>
  <p><a ses:no-track href="%s" style="display:inline-block;padding:10px 18px;background:#1a1a1a;color:#fff;text-decoration:none;border-radius:6px">Sign in</a></p>
  <p style="color:#666;font-size:.9em;word-break:break-all">Or paste this link: %s</p>
  <p style="color:#888;font-size:.85em;margin-top:24px">Never share this code. If you didn't request this, you can ignore this email.</p>
</body></html>`, code, int(ttl.Minutes()), link, link)
}
