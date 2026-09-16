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
	template.Must(t.New("change-password.html").Parse(changePasswordHTML))
	template.Must(t.New("account.html").Parse(accountHTML))
	return t
}

// fontFaceCSS self-hosts the flag brand face (Nebula Sans 400/700) from the
// binary, served by fontHandler at /fonts/. font-display: swap renders the
// token fallback ("Segoe UI", system-ui, sans-serif) immediately, then swaps
// to Nebula Sans once the woff2 loads — no blank-text flash, no CDN
// dependency. Only the two weights these pages render are embedded; see
// fonts.go for why 500/600, the italics and Hack are deliberately absent.
const fontFaceCSS = `
@font-face {
  font-family: "Nebula Sans";
  font-style: normal; font-weight: 400; font-display: swap;
  src: url("/fonts/NebulaSans-400.woff2") format("woff2");
}
@font-face {
  font-family: "Nebula Sans";
  font-style: normal; font-weight: 700; font-display: swap;
  src: url("/fonts/NebulaSans-700.woff2") format("woff2");
}
`

// tokensCSS is the subset of the Elcano "flag" design system this surface
// consumes, copied verbatim from flag/design-system/tokens/design-tokens.css
// (the canonical source of truth). The system is dark-first: :root holds the
// dark palette and :root[data-theme="light"] overrides it. Theme is resolved
// by themeScript below per the shared contract (system default, explicit
// choice persisted under flag-theme-preference). When adding a new visual,
// add the token upstream in flag first, then mirror it here.
const tokensCSS = `
:root {
  color-scheme: dark;
  --font-heading: "Nebula Sans", "Segoe UI", system-ui, -apple-system, sans-serif;
  --font-body: "Nebula Sans", "Segoe UI", system-ui, -apple-system, sans-serif;
  --font-weight-regular: 400;
  --font-weight-bold: 700;
  --font-size-title: 1.75rem;
  --line-height-title: 1.2;
  --font-size-body: 1rem;
  --line-height-body: 1.5;
  --font-size-caption: 0.8125rem;
  --line-height-caption: 1.4;
  --font-size-overline: 0.75rem;
  --line-height-overline: 1.4;

  --color-bg: #1a0b1e;
  --color-surface-1: #241b31;
  --color-primary: #7272ab;
  --color-primary-hover: #8686c4;
  --color-accent: #9da7ef;
  --color-white: #ffffff;
  --color-border: rgba(114, 114, 171, 0.35);
  --color-border-strong: rgba(114, 114, 171, 0.55);
  --color-text-primary: #ffffff;
  --color-text-secondary: #d2d9de;
  --color-text-muted: #beb6cd;
  --color-status-error-fg: #ffd2d2;
  --color-status-error-bg: rgba(255, 85, 85, 0.14);
  --color-status-error-border: rgba(255, 85, 85, 0.6);

  --gradient-bg-home-signature:
    radial-gradient(circle at 8% -4%, rgba(114, 114, 171, 0.34), transparent 34%),
    radial-gradient(circle at 92% 2%, rgba(88, 111, 124, 0.28), transparent 32%),
    radial-gradient(circle at 72% 82%, rgba(114, 114, 171, 0.18), transparent 30%),
    linear-gradient(150deg, #0f0612 0%, #1a0b1e 52%, #090409 100%);
  --gradient-surface-card:
    linear-gradient(145deg, rgba(38, 21, 44, 0.92), rgba(23, 13, 29, 0.88));
  --gradient-action-primary:
    linear-gradient(140deg, #7272ab, #586f7c);

  --space-2: 0.5rem;
  --space-3: 0.75rem;
  --space-4: 1rem;
  --space-5: 1.25rem;
  --space-6: 1.5rem;
  --space-8: 2.5rem;

  --radius-md: 0.625rem;
  --radius-xl: 1.125rem;
  --radius-pill: 999rem;

  --shadow-lg: 0 22px 54px rgba(0, 0, 0, 0.52);
  --transition-fast: 140ms ease;
  --focus-ring: 0 0 0 2px var(--color-bg), 0 0 0 4px var(--color-accent);
}

:root[data-theme="light"] {
  color-scheme: light;
  --color-bg: #f4f6fb;
  --color-surface-1: #ffffff;
  --color-primary-hover: #5f5f97;
  --color-border: rgba(38, 55, 92, 0.2);
  --color-border-strong: rgba(38, 55, 92, 0.32);
  --color-text-primary: #141824;
  --color-text-secondary: #33415f;
  --color-text-muted: #5c6a87;
  --color-status-error-fg: #7c1f1f;
  --color-status-error-bg: rgba(255, 85, 85, 0.18);
  --color-status-error-border: rgba(255, 85, 85, 0.44);
  --gradient-bg-home-signature:
    radial-gradient(circle at 9% -8%, rgba(114, 114, 171, 0.28), transparent 42%),
    radial-gradient(circle at 90% 0%, rgba(88, 111, 124, 0.24), transparent 38%),
    linear-gradient(150deg, #f7f9ff 0%, #eaf0ff 52%, #e2e9fb 100%);
  --gradient-surface-card: linear-gradient(145deg, #ffffff, #eef3ff);
  --shadow-lg: 0 16px 34px rgba(38, 55, 92, 0.2);
  --focus-ring: 0 0 0 2px var(--color-white), 0 0 0 4px var(--color-accent);
}
`

// componentCSS styles the login + sent cards with semantic tokens only —
// no hardcoded colors/radii/spacing — per the flag AGENT_GUIDE. Primary
// action uses the primary gradient; focus uses var(--focus-ring).
const componentCSS = `
* { box-sizing: border-box; }
html, body { height: 100%; }
body {
  margin: 0;
  min-height: 100vh;
  display: flex; align-items: center; justify-content: center;
  padding: var(--space-6);
  font-family: var(--font-body);
  font-size: var(--font-size-body); line-height: var(--line-height-body);
  color: var(--color-text-secondary);
  background: var(--gradient-bg-home-signature) fixed;
  background-color: var(--color-bg);
  -webkit-font-smoothing: antialiased;
}
.card {
  width: 100%; max-width: 25rem;
  padding: var(--space-8);
  background: var(--gradient-surface-card);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-xl);
  box-shadow: var(--shadow-lg);
}
.brand {
  font-size: var(--font-size-overline); line-height: var(--line-height-overline);
  letter-spacing: 0.14em; text-transform: uppercase;
  font-weight: var(--font-weight-bold);
  color: var(--color-text-muted); margin-bottom: var(--space-5);
}
h1 {
  font-family: var(--font-heading); font-weight: var(--font-weight-bold);
  font-size: var(--font-size-title); line-height: var(--line-height-title);
  color: var(--color-text-primary); letter-spacing: -0.01em;
  margin: 0 0 var(--space-2);
}
.muted { color: var(--color-text-muted); margin: 0 0 var(--space-6); }
label {
  display: block; font-size: var(--font-size-caption);
  font-weight: var(--font-weight-bold); color: var(--color-text-secondary);
  margin-bottom: var(--space-2);
}
input[type=email], input[type=password] {
  width: 100%; min-height: 2.5rem; padding: var(--space-2) var(--space-3);
  font-family: var(--font-body); font-size: var(--font-size-body);
  color: var(--color-text-primary);
  background: var(--color-surface-1);
  border: 1px solid var(--color-border-strong);
  border-radius: var(--radius-md);
  outline: none;
  transition: border-color var(--transition-fast), box-shadow var(--transition-fast);
}
input[type=email]::placeholder, input[type=password]::placeholder { color: var(--color-text-muted); }
input[type=email]:hover, input[type=password]:hover { border-color: var(--color-primary); }
input[type=email]:focus-visible, input[type=password]:focus-visible { border-color: var(--color-primary); box-shadow: var(--focus-ring); }
.btn {
  display: inline-flex; align-items: center; justify-content: center;
  width: 100%; min-height: 2.75rem; margin-top: var(--space-5);
  padding: var(--space-3) var(--space-4);
  font-family: var(--font-body); font-size: var(--font-size-body);
  font-weight: var(--font-weight-bold); color: var(--color-white);
  background: var(--gradient-action-primary);
  border: 0; border-radius: var(--radius-md); cursor: pointer;
  transition: filter var(--transition-fast), transform var(--transition-fast);
}
.btn:hover { filter: brightness(1.08); }
.btn:active { transform: translateY(1px); }
.btn:focus-visible { outline: none; box-shadow: var(--focus-ring); }
.err {
  color: var(--color-status-error-fg);
  background: var(--color-status-error-bg);
  border: 1px solid var(--color-status-error-border);
  padding: var(--space-3); border-radius: var(--radius-md);
  font-size: var(--font-size-caption); margin-bottom: var(--space-5);
}
.foot { margin-top: var(--space-6); font-size: var(--font-size-caption); color: var(--color-text-muted); text-align: center; }
.foot a { color: var(--color-accent); }
.theme-toggle {
  position: fixed; top: var(--space-5); right: var(--space-5);
  width: 2.5rem; height: 2.5rem;
  display: inline-flex; align-items: center; justify-content: center;
  color: var(--color-text-secondary);
  background: var(--color-surface-1); border: 1px solid var(--color-border);
  border-radius: var(--radius-pill); cursor: pointer;
  transition: color var(--transition-fast), border-color var(--transition-fast);
}
.theme-toggle:hover { color: var(--color-text-primary); border-color: var(--color-border-strong); }
.theme-toggle:focus-visible { outline: none; box-shadow: var(--focus-ring); }
.theme-toggle svg { width: 1.25rem; height: 1.25rem; }
.theme-toggle .icon-moon { display: none; }
:root[data-theme="light"] .theme-toggle .icon-sun { display: none; }
:root[data-theme="light"] .theme-toggle .icon-moon { display: inline; }
@media (prefers-reduced-motion: reduce) {
  * { transition: none !important; }
}
`

// themeScript is the shared flag theme controller, inlined. It resolves the
// theme before first paint (stored explicit choice → system preference),
// sets the canonical html[data-theme] attribute, persists explicit toggles
// under flag-theme-preference, and auto-follows the OS only while unset.
// Mirrors flag/design-system/theme/theme-controller.js.
const themeScript = `
(function () {
  var root = document.documentElement;
  var key = "flag-theme-preference";
  var media = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
  function stored() { try { return localStorage.getItem(key); } catch (e) { return null; } }
  function systemTheme() { return media && media.matches ? "dark" : "light"; }
  function resolve() { var s = stored(); return s === "light" || s === "dark" ? s : systemTheme(); }
  function apply(theme) {
    root.setAttribute("data-theme", theme);
    var dark = theme === "dark";
    document.querySelectorAll("[data-flag-theme-toggle]").forEach(function (t) {
      t.setAttribute("aria-pressed", dark ? "true" : "false");
      t.setAttribute("aria-label", dark ? "Switch to light mode" : "Switch to dark mode");
    });
  }
  function toggle() {
    var next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
    try { localStorage.setItem(key, next); } catch (e) {}
    apply(next);
  }
  apply(resolve());
  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("[data-flag-theme-toggle]").forEach(function (t) { t.addEventListener("click", toggle); });
    apply(root.getAttribute("data-theme") || resolve());
  });
  if (media) {
    media.addEventListener("change", function () {
      var s = stored();
      if (s === "light" || s === "dark") { return; }
      apply(systemTheme());
    });
  }
})();
`

// themeToggle is the shared sun/moon control. Icons are the flag core-icons
// sprite's "sun" and "moon" glyphs, inlined. aria-label/aria-pressed are set
// by themeScript on load. The CSS swaps which glyph shows per data-theme.
const themeToggle = `<button type="button" class="theme-toggle" data-flag-theme-toggle aria-label="Toggle color theme">
  <svg class="icon-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <circle cx="12" cy="12" r="4"></circle>
    <path d="M12 2.5v2.5"></path><path d="M12 19v2.5"></path><path d="M2.5 12H5"></path><path d="M19 12h2.5"></path>
    <path d="M5.6 5.6l1.8 1.8"></path><path d="M16.6 16.6l1.8 1.8"></path><path d="M5.6 18.4l1.8-1.8"></path><path d="M16.6 7.4l1.8-1.8"></path>
  </svg>
  <svg class="icon-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <path d="M20 14.2A8.5 8.5 0 1 1 9.8 4a7 7 0 0 0 10.2 10.2z"></path>
  </svg>
</button>`

const loginHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{{.Brand}} — Sign in</title>
<style nonce="{{.Nonce}}">` + fontFaceCSS + tokensCSS + componentCSS + `</style>
<script nonce="{{.Nonce}}">` + themeScript + `</script>
</head>
<body>
  ` + themeToggle + `
  <main class="card">
    <div class="brand">{{.Brand}}</div>
    <h1>Sign in</h1>
    {{if .PasswordMode}}<p class="muted">Enter your work email and password.</p>{{else}}<p class="muted">Enter your work email. We'll send you a one-time link.</p>{{end}}
    {{if .Notice}}<p class="muted">{{.Notice}}</p>{{end}}
    {{if .Error}}<div class="err">{{.Error}}</div>{{end}}
    <form method="post" action="{{if .PasswordMode}}/login{{else}}/magic{{end}}">
      <label for="email">Email</label>
      <input id="email" name="email" type="email" required autofocus autocomplete="email"
             placeholder="you@example.com">
      {{if .PasswordMode}}
      <label for="password">Password</label>
      <input id="password" name="password" type="password" required autocomplete="current-password">
      <input type="hidden" name="csrf_token" value="{{.CSRF}}">
      {{end}}
      {{if .ReturnTo}}<input type="hidden" name="return_to" value="{{.ReturnTo}}">{{end}}
      <button class="btn" type="submit">{{if .PasswordMode}}Sign in{{else}}Send link{{end}}</button>
    </form>
    {{if .PasswordMode}}<div class="foot">Accounts are created by an administrator.</div>{{else}}<div class="foot">No passwords. Links expire after 15 minutes.</div>{{end}}
  </main>
</body>
</html>`

const changePasswordHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{{.Brand}} — Change password</title>
<style nonce="{{.Nonce}}">` + fontFaceCSS + tokensCSS + componentCSS + `</style>
<script nonce="{{.Nonce}}">` + themeScript + `</script>
</head>
<body>
  ` + themeToggle + `
  <main class="card">
    <div class="brand">{{.Brand}}</div>
    <h1>Change password</h1>
    <p class="muted">Use at least 12 characters; a few unrelated words work well. Spaces and Unicode are allowed. Avoid common passwords and anything similar to your email or the organisation's name.</p>
    {{if .Error}}<div class="err">{{.Error}}</div>{{end}}
    <form method="post" action="/change-password">
      <label for="current_password">Current password</label>
      <input id="current_password" name="current_password" type="password" required autocomplete="current-password">
      <label for="new_password">New password</label>
      <input id="new_password" name="new_password" type="password" required minlength="12" maxlength="128" autocomplete="new-password">
      <label for="confirm_password">Confirm new password</label>
      <input id="confirm_password" name="confirm_password" type="password" required minlength="12" maxlength="128" autocomplete="new-password">
      <input type="hidden" name="csrf_token" value="{{.CSRF}}">
      {{if .ReturnTo}}<input type="hidden" name="return_to" value="{{.ReturnTo}}">{{end}}
      <button class="btn" type="submit">Replace password</button>
    </form>
  </main>
</body>
</html>`

const accountHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{{.Brand}} — Signed in</title>
<style nonce="{{.Nonce}}">` + fontFaceCSS + tokensCSS + componentCSS + `</style>
<script nonce="{{.Nonce}}">` + themeScript + `</script>
</head>
<body>
  ` + themeToggle + `
  <main class="card">
    <div class="brand">{{.Brand}}</div>
    <h1>Signed in</h1>
    <p class="muted">You are signed in as <strong>{{.Email}}</strong>.</p>
    <p><a href="/change-password">Change password</a></p>
    <form method="post" action="/logout">
      <input type="hidden" name="csrf_token" value="{{.CSRF}}">
      <input type="hidden" name="redirect_to" value="/?notice=signed_out">
      <button class="btn" type="submit">Sign out</button>
    </form>
    <div class="foot">Signing out ends your session in every {{.Brand}} app, on every device.</div>
  </main>
</body>
</html>`

const sentHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{{.Brand}} — Check your inbox</title>
<style nonce="{{.Nonce}}">` + fontFaceCSS + tokensCSS + componentCSS + `</style>
<script nonce="{{.Nonce}}">` + themeScript + `</script>
</head>
<body>
  ` + themeToggle + `
  <main class="card">
    <div class="brand">{{.Brand}}</div>
    <h1>Check your inbox</h1>
    <p class="muted">If <b>{{.Email}}</b> has an account, a one-time sign-in link is on its way. Click it to continue.</p>
    <div class="foot">The link expires in 15 minutes. Didn't get one? Check spam, or
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
