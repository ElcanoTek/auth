package httpapi

import (
	"fmt"
	"html/template"
	"time"
)

// Templates live inline so the binary stays self-contained — no
// embed.FS-vs-cwd-vs-systemd-WorkingDirectory gotchas, no separate
// files to keep in sync with the deploy pipeline. Two pages and two
// email bodies; trivial to read inline.

func parseTemplates() *template.Template {
	t := template.Must(template.New("login.html").Parse(loginHTML))
	template.Must(t.New("sent.html").Parse(sentHTML))
	return t
}

const baseCSS = `
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body {
  font: 16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, sans-serif;
  margin: 0; padding: 0;
  min-height: 100vh; display: flex; align-items: center; justify-content: center;
  background: linear-gradient(135deg, #fafafa 0%, #eef2f7 100%);
  color: #1a1a1a;
}
@media (prefers-color-scheme: dark) {
  body { background: linear-gradient(135deg, #0f1115 0%, #1b1f27 100%); color: #f0f0f0; }
  .card { background: #15181f; border-color: #2a2f3a; }
  input { background: #0f1115; color: #f0f0f0; border-color: #2a2f3a; }
  .muted { color: #8b95a7; }
  .err { background: #3a1c1c; color: #ffb4b4; border-color: #5a2424; }
}
.card {
  width: 100%; max-width: 380px; padding: 2.25rem;
  background: #fff; border: 1px solid #e4e7ec; border-radius: 14px;
  box-shadow: 0 4px 20px rgba(0,0,0,0.04);
}
h1 { font-size: 1.45rem; margin: 0 0 .35rem; font-weight: 600; letter-spacing: -0.01em; }
.muted { color: #5a6578; margin: 0 0 1.5rem; font-size: .95rem; }
label { display: block; font-size: .85rem; margin-bottom: .4rem; font-weight: 500; }
input[type=email] {
  width: 100%; padding: .7rem .85rem;
  border: 1px solid #d4d8e0; border-radius: 9px; font-size: 1rem;
  outline: none; transition: border-color 80ms, box-shadow 80ms;
}
input[type=email]:focus { border-color: #4f6cf2; box-shadow: 0 0 0 3px rgba(79,108,242,0.18); }
button {
  width: 100%; margin-top: 1rem; padding: .75rem;
  background: #1a1a1a; color: #fff; border: 0; border-radius: 9px;
  font-size: 1rem; font-weight: 500; cursor: pointer;
  transition: background 80ms, transform 80ms;
}
button:hover { background: #000; }
button:active { transform: translateY(1px); }
@media (prefers-color-scheme: dark) {
  button { background: #f0f0f0; color: #0f1115; }
  button:hover { background: #fff; }
}
.err {
  background: #fff4f4; color: #6e2222; border: 1px solid #ffd7d7;
  padding: .65rem .8rem; border-radius: 9px; font-size: .9rem; margin-bottom: 1rem;
}
.brand { font-size: .78rem; letter-spacing: .12em; text-transform: uppercase;
         color: #8a93a3; margin-bottom: 1.5rem; }
.foot { margin-top: 1.5rem; font-size: .8rem; color: #8a93a3; text-align: center; }
`

const loginHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Brand}} — Sign in</title>
<style>` + baseCSS + `</style>
</head>
<body>
  <main class="card">
    <div class="brand">{{.Brand}}</div>
    <h1>Sign in</h1>
    <p class="muted">Enter your work email. We'll send you a one-time link.</p>
    {{if .Error}}<div class="err">{{.Error}}</div>{{end}}
    <form method="post" action="/magic">
      <label for="email">Email</label>
      <input id="email" name="email" type="email" required autofocus autocomplete="email"
             placeholder="you@example.com">
      {{if .ReturnTo}}<input type="hidden" name="return_to" value="{{.ReturnTo}}">{{end}}
      <button type="submit">Send link</button>
    </form>
    <div class="foot">No passwords. Links expire after 15 minutes.</div>
  </main>
</body>
</html>`

const sentHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Brand}} — Check your inbox</title>
<style>` + baseCSS + `</style>
</head>
<body>
  <main class="card">
    <div class="brand">{{.Brand}}</div>
    <h1>Check your inbox</h1>
    <p class="muted">We sent a sign-in link to <b>{{.Email}}</b>. Click it to continue.</p>
    <div class="foot">The link expires in 15 minutes. Didn't get it? Check spam, or
      <a href="/">try again</a>.</div>
  </main>
</body>
</html>`

// Email bodies are intentionally generic — no logos, no brand colors,
// no marketing copy. Goal: a message that works unchanged for every
// client (Elcano, Omnicom, John Deere, etc.) without per-tenant theming.
// {{Brand}} only appears in the subject line; the body is plain text
// wrapped in the most minimal HTML that still gets a clickable button.

func renderTextEmail(_, link string, ttl time.Duration) string {
	return fmt.Sprintf(`Your sign-in link (expires in %d minutes, one-time use):

%s

If you didn't request this, you can ignore this email.
`, int(ttl.Minutes()), link)
}

func renderHTMLEmail(_, link string, ttl time.Duration) string {
	return fmt.Sprintf(`<!doctype html>
<html><body style="font:16px/1.5 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;color:#1a1a1a;padding:24px">
  <p>Your sign-in link (expires in %d minutes, one-time use):</p>
  <p><a href="%s" style="display:inline-block;padding:10px 18px;background:#1a1a1a;color:#fff;text-decoration:none;border-radius:6px">Sign in</a></p>
  <p style="color:#666;font-size:.9em;word-break:break-all">Or paste this link: %s</p>
  <p style="color:#888;font-size:.85em;margin-top:24px">If you didn't request this, you can ignore this email.</p>
</body></html>`, int(ttl.Minutes()), link, link)
}
