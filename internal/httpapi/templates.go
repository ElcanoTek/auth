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
	template.Must(t.New("no-access.html").Parse(noAccessHTML))
	template.Must(t.New("admin.html").Parse(adminHTML))
	template.Must(t.New("mfa-verify.html").Parse(mfaVerifyHTML))
	template.Must(t.New("mfa-enroll.html").Parse(mfaEnrollHTML))
	template.Must(t.New("recovery-codes.html").Parse(recoveryCodesHTML))
	template.Must(t.New("security.html").Parse(securityHTML))
	template.Must(t.New("reauth.html").Parse(reauthHTML))
	template.Must(t.New("status.html").Parse(statusHTML))
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
  --color-surface-2: #2f2741;
  --color-primary: #7272ab;
  --color-primary-hover: #8686c4;
  --color-secondary: #586f7c;
  --color-accent: #9da7ef;
  --color-on-primary: #ffffff;
  --color-white: #ffffff;
  --color-border: rgba(114, 114, 171, 0.35);
  --color-border-strong: rgba(114, 114, 171, 0.55);
  --color-text-primary: #ffffff;
  --color-text-secondary: #d2d9de;
  --color-text-muted: #beb6cd;
  --color-status-error-fg: #ffd2d2;
  --color-status-error-bg: rgba(255, 85, 85, 0.14);
  --color-status-error-border: rgba(255, 85, 85, 0.6);
  --color-status-success-fg: #c9f3d6;
  --color-status-success-bg: rgba(52, 199, 122, 0.16);
  --color-status-success-border: rgba(52, 199, 122, 0.55);
  --color-status-warning-fg: #ffe4b5;
  --color-status-warning-bg: rgba(255, 176, 32, 0.16);
  --color-status-warning-border: rgba(255, 176, 32, 0.55);

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
  --color-surface-2: #e9eefc;
  --color-primary-hover: #5f5f97;
  --color-border: rgba(38, 55, 92, 0.2);
  --color-border-strong: rgba(38, 55, 92, 0.32);
  --color-text-primary: #141824;
  --color-text-secondary: #33415f;
  --color-text-muted: #5c6a87;
  --color-status-error-fg: #7c1f1f;
  --color-status-error-bg: rgba(255, 85, 85, 0.18);
  --color-status-error-border: rgba(255, 85, 85, 0.44);
  --color-status-success-fg: #145a32;
  --color-status-success-bg: rgba(52, 199, 122, 0.16);
  --color-status-success-border: rgba(52, 199, 122, 0.45);
  --color-status-warning-fg: #6e4a00;
  --color-status-warning-bg: rgba(255, 176, 32, 0.18);
  --color-status-warning-border: rgba(255, 176, 32, 0.5);
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
  display: flex;
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
  margin: auto;
  padding: var(--space-8);
  background: var(--gradient-surface-card);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-xl);
  box-shadow: var(--shadow-lg);
}
.mark { display: block; height: 2.25rem; width: auto; max-width: 12rem; margin-bottom: var(--space-4); }
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
  font-weight: var(--font-weight-bold); color: var(--color-on-primary);
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
.card.wide { max-width: 40rem; }
.apps { margin-bottom: var(--space-6); padding-bottom: var(--space-6); border-bottom: 1px solid var(--color-border); }
.apps h2 {
  font-family: var(--font-heading); font-weight: var(--font-weight-bold);
  font-size: 1.125rem; line-height: var(--line-height-title);
  color: var(--color-text-primary); letter-spacing: -0.01em; margin: 0 0 var(--space-2);
}
.apps .muted { margin-bottom: var(--space-4); }
.tiles { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: var(--space-3); }
.tile {
  position: relative; display: flex; flex-direction: column; gap: var(--space-2);
  padding: var(--space-4); overflow: hidden;
  color: var(--color-text-primary); text-decoration: none;
  background: var(--color-surface-1);
  border: 1px solid var(--color-border); border-radius: var(--radius-md);
  transition: transform var(--transition-fast), border-color var(--transition-fast), box-shadow var(--transition-fast);
}
.tile::before {
  content: ""; position: absolute; top: 0; left: 0; right: 0; height: 2px;
  background: linear-gradient(90deg, var(--color-accent), var(--color-primary)); opacity: 0.85;
}
a.tile:hover, a.tile:focus-visible { border-color: var(--color-border-strong); transform: translateY(-2px); box-shadow: var(--shadow-lg); }
a.tile:focus-visible { outline: none; box-shadow: var(--focus-ring); }
.tile-kicker {
  margin: 0; font-size: var(--font-size-overline); line-height: var(--line-height-overline);
  letter-spacing: 0.14em; text-transform: uppercase; color: var(--color-accent);
}
.tile h3 { margin: 0; font-family: var(--font-heading); font-weight: var(--font-weight-bold); font-size: var(--font-size-body); color: var(--color-text-primary); }
.tile p { margin: 0; font-size: var(--font-size-caption); line-height: var(--line-height-caption); color: var(--color-text-secondary); }
.tile-off { cursor: default; background: transparent; border-style: dashed; }
.tile-off::before { background: var(--color-border-strong); opacity: 1; }
.tile-off .tile-kicker, .tile-off h3 { color: var(--color-text-muted); }
.tile-off .tile-meta { color: var(--color-text-muted); font-style: italic; }
@media (max-width: 30rem) { .tiles { grid-template-columns: 1fr; } }
/* ── notices ── */
.banner { padding: var(--space-3) var(--space-4); border-radius: var(--radius-md); border: 1px solid var(--color-border-strong); background: var(--color-surface-1); color: var(--color-text-secondary); font-size: var(--font-size-caption); margin-bottom: var(--space-5); }
.banner strong { color: var(--color-text-primary); margin-right: 0.35em; }
.banner.alert { color: var(--color-status-error-fg); background: var(--color-status-error-bg); border-color: var(--color-status-error-border); }
.banner.alert strong { color: var(--color-status-error-fg); }
.banner.warn { color: var(--color-status-warning-fg); background: var(--color-status-warning-bg); border-color: var(--color-status-warning-border); }
.banner.warn strong { color: var(--color-status-warning-fg); }
/* ── admin console ── */
.corner-actions { position: fixed; top: var(--space-5); right: var(--space-5); display: flex; gap: var(--space-2); z-index: 3; }
.corner-actions .theme-toggle { position: static; }
.corner-bottom { position: fixed; left: var(--space-5); bottom: var(--space-5); display: flex; gap: var(--space-3); align-items: center; z-index: 3; }
.corner-bottom form { margin: 0; }
a.btn-ghost { text-decoration: none; }
.icon-btn {
  width: 2.5rem; height: 2.5rem; display: inline-flex; align-items: center; justify-content: center;
  font-size: 1.25rem; line-height: 1; text-decoration: none;
  color: var(--color-text-secondary); background: var(--color-surface-1); border: 1px solid var(--color-border);
  border-radius: var(--radius-pill); cursor: pointer;
  transition: color var(--transition-fast), border-color var(--transition-fast);
}
.icon-btn:hover { color: var(--color-text-primary); border-color: var(--color-border-strong); }
/* The top-right X (back to your apps) reads as "leave": red, darker on hover. */
.corner-actions .close { color: var(--color-status-error-fg); background: var(--color-status-error-bg); border-color: var(--color-status-error-border); }
.corner-actions .close:hover { color: #fff; background: #b91c1c; border-color: #991b1b; }
:root[data-theme="dark"] .corner-actions .close:hover { background: #991b1b; border-color: #7f1d1d; }
.icon-btn:focus-visible { outline: none; box-shadow: var(--focus-ring); }
.section-head { display: flex; align-items: flex-start; justify-content: space-between; gap: var(--space-4); flex-wrap: wrap; }
.section-head .muted { margin: 0; }
.btn.inline { width: auto; margin: 0; min-height: 2.5rem; padding-inline: var(--space-5); font-size: var(--font-size-caption); }
.row-actions { display: flex; gap: var(--space-2); justify-content: flex-end; white-space: nowrap; }
.row-actions .btn-ghost { padding-inline: var(--space-3); }
.modal[popover] {
  position: fixed; inset: 0; margin: auto; width: min(30rem, calc(100vw - 2rem)); max-height: calc(100vh - 2rem); overflow: auto;
  padding: var(--space-6); border: 1px solid var(--color-border-strong); border-radius: var(--radius-xl);
  background: var(--color-surface-1); color: var(--color-text-secondary); box-shadow: var(--shadow-lg);
}
.modal[popover]::backdrop { background: rgba(0, 0, 0, 0.55); }
.modal-head { display: flex; align-items: flex-start; justify-content: space-between; gap: var(--space-4); margin-bottom: var(--space-2); }
.modal-head h3 { margin: 0; font-family: var(--font-heading); font-size: 1.125rem; color: var(--color-text-primary); }
.modal-head .icon-btn { width: 2rem; height: 2rem; font-size: 1.1rem; }
.modal .who { color: var(--color-text-muted); font-size: var(--font-size-caption); margin: 0 0 var(--space-5); overflow-wrap: anywhere; }
.modal .who .dot { margin: 0 0.35em; }
.modal .field { margin-bottom: var(--space-4); }
.modal .field label { margin-bottom: var(--space-2); }
.modal input[type=email], .modal input[type=text], .modal input[type=password] {
  width: 100%; min-height: 2.5rem; padding: var(--space-2) var(--space-3);
  font-family: var(--font-body); font-size: var(--font-size-body); color: var(--color-text-primary);
  background: var(--color-bg); border: 1px solid var(--color-border-strong); border-radius: var(--radius-md); outline: none;
}
.modal input:focus-visible { border-color: var(--color-primary); box-shadow: var(--focus-ring); }
.modal .hint { margin: var(--space-2) 0 0; font-size: var(--font-size-caption); color: var(--color-text-muted); }
.modal .with-btn { display: flex; gap: var(--space-2); }
.modal .with-btn input { flex: 1; }
.modal .with-btn .btn-ghost { min-height: 2.5rem; }
.modal .btn { margin-top: var(--space-2); }
.setting { display: flex; align-items: center; justify-content: space-between; gap: var(--space-4); padding: var(--space-3) 0; border-top: 1px solid var(--color-border); }
.setting:first-of-type { border-top: 0; }
.setting strong { display: block; color: var(--color-text-primary); font-size: var(--font-size-caption); }
.setting .muted { margin: 0; font-size: var(--font-size-caption); }
.setting .confirm .pane { left: auto; right: 0; border-radius: var(--radius-md) 0 var(--radius-md) var(--radius-md); }
.setting .confirm > summary, .setting .btn-ghost { white-space: nowrap; }
.modal .checks { margin-top: var(--space-2); }
/* Segmented pills, copied from Fleet's Segmented control: a hairline-bordered
   pill group whose selected options fill with the primary colour. Here each
   option is a real checkbox (multi-select for applications, a single toggle
   for Admin) so the form posts without script; :has() paints the state. */
.seg-label { display: block; margin-bottom: 0.3rem; font-size: 0.64rem; font-weight: var(--font-weight-bold); letter-spacing: 0.07em; text-transform: uppercase; color: var(--color-text-muted); }
.seg { display: inline-flex; flex-wrap: wrap; border: 1px solid var(--color-border); border-radius: var(--radius-pill); overflow: hidden; }
.seg-opt { position: relative; display: inline-flex; align-items: center; margin: 0; padding: 0.18rem 0.6rem; font-size: 0.72rem; font-weight: 500; color: var(--color-text-muted); cursor: pointer; user-select: none; transition: color var(--transition-fast), background var(--transition-fast); }
.seg-opt + .seg-opt { border-left: 1px solid var(--color-border); }
.seg-opt:hover { color: var(--color-text-primary); }
.seg-opt input { position: absolute; inset: 0; width: 100%; height: 100%; margin: 0; opacity: 0; cursor: pointer; }
.seg-opt:has(input:checked) { background: var(--color-primary); color: var(--color-on-primary); }
ul.plain { margin: 0 0 var(--space-4); padding-left: 1.1rem; font-size: var(--font-size-caption); color: var(--color-text-secondary); }
ul.plain li { margin: 0.2rem 0; }
.modal label[for^="reason-"] { display: block; margin: var(--space-2) 0; }
.seg-opt:has(input:focus-visible) { box-shadow: inset 0 0 0 2px var(--color-accent); }
.seg-opt.off { opacity: 0.55; }
.seg-opt.locked { cursor: not-allowed; }
.seg-opt.locked input { cursor: not-allowed; }
.seg-group { margin-bottom: var(--space-4); }
.list th.sel, .list td.sel { width: 1.6rem; padding-right: 0; }
.list td.sel input, .list th.sel input { width: 1rem; height: 1rem; margin: 0; accent-color: var(--color-primary); cursor: pointer; }
.batch { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-2); margin: 0 0 var(--space-3); padding: var(--space-2) var(--space-3); border: 1px solid var(--color-border); border-radius: var(--radius-md); background: var(--color-surface-2); }
.batch-count { font-size: var(--font-size-caption); color: var(--color-text-muted); min-width: 5.5rem; }
.batch select, .batch input[type=text] { min-height: 2.25rem; padding: 0 var(--space-3); font: inherit; font-size: var(--font-size-caption); color: var(--color-text-primary); background: var(--color-surface-1); border: 1px solid var(--color-border); border-radius: var(--radius-md); }
.batch input[type=text] { flex: 1; min-width: 12rem; }
.batch select:focus-visible, .batch input:focus-visible { outline: none; border-color: var(--color-primary); box-shadow: var(--focus-ring); }
.sr-only { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
.seg-group .hint { margin-top: var(--space-2); }
.tag { display: inline-block; padding: 0.1rem 0.5rem; border-radius: var(--radius-pill); font-size: 0.6875rem; font-weight: var(--font-weight-bold); letter-spacing: 0.04em; background: var(--color-bg); border: 1px solid var(--color-border-strong); color: var(--color-text-secondary); white-space: nowrap; }
.card.admin { max-width: 68rem; }
.topline { display: flex; align-items: baseline; justify-content: space-between; gap: var(--space-4); flex-wrap: wrap; }
.topline .muted { margin: 0; }
.tabs { display: flex; gap: var(--space-2); flex-wrap: wrap; margin: var(--space-5) 0 var(--space-5); border-bottom: 1px solid var(--color-border); }
.tab {
  display: inline-block; padding: var(--space-2) var(--space-3); margin-bottom: -1px;
  font-size: var(--font-size-caption); font-weight: var(--font-weight-bold); letter-spacing: 0.02em;
  color: var(--color-text-muted); text-decoration: none;
  border: 1px solid transparent; border-bottom: 2px solid transparent; border-radius: var(--radius-md) var(--radius-md) 0 0;
}
.tab:hover { color: var(--color-text-primary); }
.tab.active { color: var(--color-text-primary); border-bottom-color: var(--color-accent); }
.tab:focus-visible { outline: none; box-shadow: var(--focus-ring); }
.section { margin-top: var(--space-6); }
.section h2 { font-family: var(--font-heading); font-size: 1.125rem; margin: 0 0 var(--space-2); color: var(--color-text-primary); }
.section > .muted { margin-bottom: var(--space-4); }
.notice {
  color: var(--color-status-success-fg); background: var(--color-status-success-bg);
  border: 1px solid var(--color-status-success-border);
  padding: var(--space-3); border-radius: var(--radius-md); font-size: var(--font-size-caption); margin-bottom: var(--space-5);
}
.secret {
  display: flex; flex-direction: column; gap: var(--space-2);
  padding: var(--space-4); margin-bottom: var(--space-5);
  background: var(--color-surface-1); border: 1px dashed var(--color-border-strong); border-radius: var(--radius-md);
}
.secret code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 1.05rem; letter-spacing: 0.04em;
  color: var(--color-text-primary); user-select: all; -webkit-user-select: all; word-break: break-all;
}
.secret .muted { margin: 0; font-size: var(--font-size-caption); }
.qr { display: block; width: 220px; height: 220px; margin: 0 auto var(--space-4); border-radius: var(--radius-md); background: #fff; padding: var(--space-2); }
.codes { display: grid; grid-template-columns: 1fr; gap: var(--space-2); margin: 0 0 var(--space-5); padding: 0; list-style: none; }
.codes li { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.9rem; letter-spacing: 0.03em; white-space: nowrap; color: var(--color-text-primary); padding: var(--space-2) var(--space-3); background: var(--color-surface-1); border: 1px dashed var(--color-border-strong); border-radius: var(--radius-md); user-select: all; -webkit-user-select: all; }
a.btn { text-decoration: none; }
.actions .btn-ghost { width: 100%; min-height: 2.5rem; font-size: var(--font-size-caption); }
.status-line { display: flex; align-items: center; gap: var(--space-3); margin: 0 0 var(--space-5); }
.status-line .tag.on { color: var(--color-status-success-fg); background: var(--color-status-success-bg); border-color: var(--color-status-success-border); }
.status-line .tag.need { color: var(--color-status-warning-fg); background: var(--color-status-warning-bg); border-color: var(--color-status-warning-border); }
input.code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 1.35rem; letter-spacing: 0.35em; text-align: center; }
.actions { display: flex; flex-direction: column; gap: var(--space-2); }
.actions form { margin: 0; }
.link-row { display: flex; justify-content: space-between; gap: var(--space-4); margin-top: var(--space-4); font-size: var(--font-size-caption); }
.link-row a, .link-row button.linkish { color: var(--color-accent); background: none; border: 0; padding: 0; font: inherit; cursor: pointer; text-decoration: underline; }
.table-wrap { overflow-x: auto; }
table.list { width: 100%; border-collapse: collapse; font-size: var(--font-size-caption); }
table.list th, table.list td { text-align: left; padding: var(--space-2) var(--space-3); border-bottom: 1px solid var(--color-border); vertical-align: top; }
table.list th { color: var(--color-text-muted); font-weight: var(--font-weight-bold); letter-spacing: 0.08em; text-transform: uppercase; font-size: 0.6875rem; }
table.list td { color: var(--color-text-secondary); }
table.list td.who { color: var(--color-text-primary); font-weight: var(--font-weight-bold); overflow-wrap: anywhere; }
table.list td.num { text-align: right; font-variant-numeric: tabular-nums; }
table.list tr:last-child td { border-bottom: 0; }
table.list tr.account td { border-bottom: 0; padding-bottom: var(--space-2); }
table.list tr.manage td { padding-top: 0; padding-bottom: var(--space-3); }
table.list tr.manage:last-child td { border-bottom: 0; }
.badge {
  display: inline-block; padding: 0.1rem 0.5rem; border-radius: var(--radius-pill);
  font-size: 0.6875rem; font-weight: var(--font-weight-bold); letter-spacing: 0.04em; white-space: nowrap;
  border: 1px solid var(--color-border-strong); color: var(--color-text-secondary);
}
.badge.ok { color: var(--color-status-success-fg); background: var(--color-status-success-bg); border-color: var(--color-status-success-border); }
.badge.warn { color: var(--color-status-warning-fg); background: var(--color-status-warning-bg); border-color: var(--color-status-warning-border); }
.badge.off { color: var(--color-text-muted); border-style: dashed; }
.badge.admin { color: var(--color-accent); border-color: var(--color-accent); }
.chips { display: flex; flex-wrap: wrap; gap: var(--space-2); }
.chip { display: inline-block; padding: 0.1rem 0.5rem; border-radius: var(--radius-pill); font-size: 0.6875rem; border: 1px solid var(--color-border); color: var(--color-text-secondary); }
.chip.off { color: var(--color-text-muted); border-style: dashed; text-decoration: line-through; }
.actions { display: flex; flex-wrap: wrap; gap: var(--space-2); align-items: flex-start; }
.btn-ghost, .confirm > summary {
  display: inline-flex; align-items: center; min-height: 1.9rem; padding: 0.2rem var(--space-3);
  font-family: var(--font-body); font-size: var(--font-size-caption); font-weight: var(--font-weight-bold);
  color: var(--color-text-secondary); background: transparent;
  border: 1px solid var(--color-border); border-radius: var(--radius-md); cursor: pointer; list-style: none;
  transition: color var(--transition-fast), border-color var(--transition-fast), background var(--transition-fast);
}
.confirm > summary::-webkit-details-marker { display: none; }
.btn-ghost:hover, .confirm > summary:hover { color: var(--color-text-primary); border-color: var(--color-border-strong); background: var(--color-surface-1); }
.btn-ghost:focus-visible, .confirm > summary:focus-visible { outline: none; box-shadow: var(--focus-ring); }
.confirm.danger > summary:hover { color: var(--color-status-error-fg); border-color: var(--color-status-error-border); background: var(--color-status-error-bg); }
.confirm[open] > summary { color: var(--color-text-primary); border-color: var(--color-border-strong); border-bottom-left-radius: 0; border-bottom-right-radius: 0; }
.confirm[open].danger > summary { color: var(--color-status-error-fg); border-color: var(--color-status-error-border); background: var(--color-status-error-bg); }
.confirm { position: relative; display: inline-block; }
.confirm .pane {
  position: absolute; z-index: 2; top: 100%; left: 0; min-width: 16rem; max-width: min(22rem, 80vw);
  display: flex; flex-direction: column; gap: var(--space-3);
  padding: var(--space-3); background: var(--color-surface-1);
  border: 1px solid var(--color-border-strong); border-radius: 0 var(--radius-md) var(--radius-md) var(--radius-md);
  box-shadow: var(--shadow-lg);
}
.confirm .pane .muted { margin: 0; font-size: var(--font-size-caption); }
.confirm .pane .btn { margin-top: 0; min-height: 2.25rem; font-size: var(--font-size-caption); }
.confirm.danger .pane .btn { background: none; background-color: var(--color-status-error-bg); color: var(--color-status-error-fg); border: 1px solid var(--color-status-error-border); }
.topline .confirm .pane { left: auto; right: 0; border-radius: var(--radius-md) 0 var(--radius-md) var(--radius-md); }
.checks { display: flex; flex-wrap: wrap; gap: var(--space-2) var(--space-4); }
.checks label { display: inline-flex; align-items: center; gap: 0.4rem; margin: 0; font-weight: var(--font-weight-regular); color: var(--color-text-secondary); font-size: var(--font-size-caption); }
.checks input { accent-color: var(--color-primary); width: 1rem; height: 1rem; margin: 0; }
.checks label.off { color: var(--color-text-muted); }
.add { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: var(--space-3) var(--space-4); align-items: end; }
.add .wide-field { grid-column: 1 / -1; }
.add .btn { margin-top: 0; min-height: 2.5rem; width: auto; padding-inline: var(--space-5); }
.kv { display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: var(--space-2) var(--space-4); font-size: var(--font-size-caption); margin: 0; }
.kv dt { color: var(--color-text-muted); }
.kv dd { margin: 0; color: var(--color-text-secondary); word-break: break-all; }
.kv dd code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.8125rem; }
.empty { margin: 0; padding: var(--space-4); border: 1px dashed var(--color-border); border-radius: var(--radius-md); color: var(--color-text-muted); font-size: var(--font-size-caption); text-align: center; }
@media (max-width: 40rem) {
  table.list .num { display: none; }
  /* The corner controls would float over a long table on a phone; let them
     end the page instead: body is a flex row for centring the card, so they
     wrap onto their own full-width line below it. */
  body { flex-wrap: wrap; }
  .corner-bottom { position: static; flex: 0 0 100%; margin-top: var(--space-4); justify-content: center; }
}
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
<title>{{.Wordmark}} — Sign in</title>
{{if .LogoURL}}<link rel="icon" href="{{.LogoURL}}">{{end}}
<style nonce="{{.Nonce}}">` + fontFaceCSS + tokensCSS + componentCSS + `{{.BrandCSS}}</style>
<script nonce="{{.Nonce}}">` + themeScript + `</script>
</head>
<body>
  ` + themeToggle + `
  <main class="card">
    {{if .LogoURL}}<img class="mark" src="{{.LogoURL}}" alt="">{{end}}
    <div class="brand">{{.Wordmark}}</div>
    <h1>{{if .LoginTitle}}{{.LoginTitle}}{{else}}Sign in{{end}}</h1>
    {{if .LoginTagline}}<p class="muted">{{.LoginTagline}}</p>{{else if .PasswordMode}}<p class="muted">Enter your work email and password.</p>{{else}}<p class="muted">Enter your work email. We'll send you a one-time link.</p>{{end}}
    {{if .Notice}}<div class="banner {{.NoticeClass}}" role="status"><strong>{{.NoticeTitle}}</strong> {{.Notice}}</div>{{end}}
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
<title>{{.Wordmark}} — Change password</title>
{{if .LogoURL}}<link rel="icon" href="{{.LogoURL}}">{{end}}
<style nonce="{{.Nonce}}">` + fontFaceCSS + tokensCSS + componentCSS + `{{.BrandCSS}}</style>
<script nonce="{{.Nonce}}">` + themeScript + `</script>
</head>
<body>
  ` + themeToggle + `
  <main class="card">
    {{if .LogoURL}}<img class="mark" src="{{.LogoURL}}" alt="">{{end}}
    <div class="brand">{{.Wordmark}}</div>
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
<title>{{.Wordmark}} — Signed in</title>
{{if .LogoURL}}<link rel="icon" href="{{.LogoURL}}">{{end}}
<style nonce="{{.Nonce}}">` + fontFaceCSS + tokensCSS + componentCSS + `{{.BrandCSS}}</style>
<script nonce="{{.Nonce}}">` + themeScript + `</script>
</head>
<body>
  ` + themeToggle + `
  <main class="card wide">
    {{if .LogoURL}}<img class="mark" src="{{.LogoURL}}" alt="">{{end}}
    <div class="brand">{{.Wordmark}}</div>
    <h1>Signed in</h1>
    <p class="muted">You are signed in as <strong>{{.Email}}</strong>.</p>
    {{if .UsedRecovery}}<div class="banner warn" role="status"><strong>Recovery code used.</strong> You signed in with a recovery code. <a href="/account/security">Set up a new authenticator</a> if you lost the old one.</div>{{end}}
    <section class="apps" aria-labelledby="apps-heading">
      <h2 id="apps-heading">Your apps</h2>
      <div class="tiles">
        {{range .Links}}{{if .Available}}<a class="tile" href="{{.URL}}" rel="noreferrer">
          <p class="tile-kicker">{{.Kicker}}</p>
          <h3>{{.Name}}</h3>
          <p>{{.Description}}</p>
        </a>{{else}}<div class="tile tile-off" aria-disabled="true">
          <p class="tile-kicker">{{.Kicker}}</p>
          <h3>{{.Name}}</h3>
          <p class="tile-meta">Not available</p>
        </div>{{end}}
        {{end}}
      </div>
    </section>
    <form method="post" action="/logout">
      <input type="hidden" name="csrf_token" value="{{.CSRF}}">
      <input type="hidden" name="redirect_to" value="/?notice=signed_out">
      <button class="btn" type="submit">Sign out</button>
    </form>
    <div class="foot">Signing out ends your session in every {{.Brand}} app, on every device. <a href="/account/security">Security settings</a></div>
  </main>
</body>
</html>`

const noAccessHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{{.Wordmark}} — No access</title>
{{if .LogoURL}}<link rel="icon" href="{{.LogoURL}}">{{end}}
<style nonce="{{.Nonce}}">` + fontFaceCSS + tokensCSS + componentCSS + `{{.BrandCSS}}</style>
<script nonce="{{.Nonce}}">` + themeScript + `</script>
</head>
<body>
  ` + themeToggle + `
  <main class="card">
    {{if .LogoURL}}<img class="mark" src="{{.LogoURL}}" alt="">{{end}}
    <div class="brand">{{.Wordmark}}</div>
    <h1>No access to {{.AppName}}</h1>
    <p class="muted">You are signed in as <strong>{{.Email}}</strong>, but this account is not set up for {{.AppName}}. Ask your administrator to grant access, then try again.</p>
    <a class="btn" href="/account">Back to your apps</a>
  </main>
</body>
</html>`

// adminScript is the console's only script, inlined under the page nonce:
// the Generate button fills the temporary-password field client-side (the
// server generates one anyway when the field is blank), and a form the
// server rejected reopens its popover so the input is not hidden behind a
// closed dialog. The console works without it.
const adminScript = `
(function () {
  var alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789-_.!@*=~";
  var all = document.querySelector("[data-select-all]");
  var boxes = Array.prototype.slice.call(document.querySelectorAll("[data-select]"));
  var count = document.querySelector("[data-batch-count]");
  function refresh() {
    var n = boxes.filter(function (b) { return b.checked; }).length;
    if (count) { count.textContent = n + " selected"; }
    if (all) { all.checked = n > 0 && n === boxes.length; all.indeterminate = n > 0 && n < boxes.length; }
  }
  if (all) { all.addEventListener("change", function () { boxes.forEach(function (b) { b.checked = all.checked; }); refresh(); }); }
  boxes.forEach(function (b) { b.addEventListener("change", refresh); });
  refresh();
  document.querySelectorAll("[data-generate]").forEach(function (button) {
    button.addEventListener("click", function () {
      var field = document.getElementById(button.getAttribute("data-generate"));
      if (!field) return;
      var bytes = new Uint8Array(20);
      crypto.getRandomValues(bytes);
      var out = "";
      for (var i = 0; i < bytes.length; i++) out += alphabet[bytes[i] % 64];
      field.type = "text";
      field.value = out;
      field.focus();
    });
  });
  var reopen = document.body.getAttribute("data-reopen");
  if (reopen) {
    var popover = document.getElementById(reopen);
    if (popover && popover.showPopover) { try { popover.showPopover(); } catch (e) {} }
  }
})();
`

const adminHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{{.Wordmark}} — Admin</title>
{{if .LogoURL}}<link rel="icon" href="{{.LogoURL}}">{{end}}
<style nonce="{{.Nonce}}">` + fontFaceCSS + tokensCSS + componentCSS + `{{.BrandCSS}}</style>
<script nonce="{{.Nonce}}">` + themeScript + `</script>
</head>
<body{{if .Reopen}} data-reopen="{{.Reopen}}"{{end}}>
  <div class="corner-actions">
    ` + themeToggle + `
    <a class="icon-btn close" href="/account" aria-label="Back to your apps" title="Back to your apps">&times;</a>
  </div>
  <div class="corner-bottom">
    <form method="post" action="/logout">
      <input type="hidden" name="csrf_token" value="{{.CSRF}}">
      <input type="hidden" name="redirect_to" value="/?notice=signed_out">
      <button class="btn-ghost" type="submit">Sign out</button>
    </form>
  </div>
  <main class="card admin">
    {{if .LogoURL}}<img class="mark" src="{{.LogoURL}}" alt="">{{end}}
    <div class="brand">{{.Wordmark}}</div>
    <div class="topline">
      <h1>Admin</h1>
      <p class="muted">Signed in as <strong>{{.Email}}</strong></p>
    </div>
    <nav class="tabs" aria-label="Admin sections">
      {{range .Tabs}}<a class="tab{{if .Active}} active{{end}}" href="{{.URL}}"{{if .Active}} aria-current="page"{{end}}>{{.Label}}</a>{{end}}
    </nav>
    {{if .NeedVerify}}<div class="banner warn" role="alert"><strong>Confirm it is you.</strong> {{.Error}} Sensitive changes (disabling accounts, resets, sign-outs, who is an administrator, two-factor settings) need your authenticator code entered less than five minutes ago. <a href="/account/security/verify?return_to=%2Fadmin">Enter it now</a> and then repeat the change.</div>
    {{else if .NeedEnroll}}<div class="banner warn" role="alert"><strong>Set up two-factor sign-in first.</strong> {{.Error}} Sensitive changes (disabling accounts, resets, sign-outs, who is an administrator, two-factor settings) need an administrator's own authenticator. <a href="/account/security?return_to=%2Fadmin">Set yours up</a> and then repeat the change.</div>
    {{else if .Error}}<div class="err" role="alert">{{.Error}}</div>{{end}}
    {{if .Notice}}<div class="notice" role="status">{{.Notice}}</div>{{end}}
    {{if .Secret}}<div class="secret" role="status">
      <p class="muted">Temporary password for <strong>{{.SecretFor}}</strong>. It is shown once and not stored: copy it now.</p>
      <code>{{.Secret}}</code>
      <p class="muted">They sign in with it and are asked to choose their own password before anything else. It does not expire on its own; if it is lost, run the action again for a new one. Reloading this page repeats the action.</p>
    </div>{{end}}

    {{if eq .Tab "accounts"}}
    <section class="section" aria-labelledby="accounts-heading">
      <div class="section-head">
        <div>
          <h2 id="accounts-heading">Accounts</h2>
          <p class="muted">Who can sign in, to which applications, and whether they can open this console. Two-factor policy: <strong>{{.MFAPolicy}}</strong>. Tick accounts to change several at once.</p>
        </div>
        <div class="row-actions">
          <button class="btn-ghost" type="button" popovertarget="mfa-policy">Two-factor policy</button>
          <button class="btn inline" type="button" popovertarget="add-user">Add user</button>
        </div>
      </div>
      {{if .Accounts}}
      <form id="batch-form" class="batch" method="post" action="/admin" aria-label="Change the selected accounts">
        <input type="hidden" name="csrf_token" value="{{.CSRF}}"><input type="hidden" name="action" value="batch">
        <span class="batch-count" data-batch-count aria-live="polite">0 selected</span>
        <label class="sr-only" for="batch-op">What to do with the selected accounts</label>
        <select id="batch-op" name="op">
          <option value="team">Set team</option>
          <option value="signout">Sign out everywhere</option>
          <option value="require-mfa">Require two-factor</option>
          <option value="unrequire-mfa">Stop requiring two-factor</option>
        </select>
        <input name="team" type="text" list="teams" maxlength="40" placeholder="Team (for Set team; blank removes it)" aria-label="Team for the selected accounts">
        <button class="btn-ghost" type="submit">Apply to selected</button>
      </form>
      <div class="table-wrap"><table class="list">
        <thead><tr><th class="sel"><input type="checkbox" data-select-all aria-label="Select every account"></th><th>Account</th><th>Status</th><th>Team</th><th>Applications</th><th></th></tr></thead>
        <tbody>
        {{range $i, $row := .Accounts}}<tr>
          <td class="sel"><input type="checkbox" name="emails" value="{{$row.Email}}" form="batch-form" data-select aria-label="Select {{$row.Email}}"></td>
          <td class="who">{{$row.Email}}{{if $row.IsAdmin}} <span class="badge admin">Admin</span>{{end}}{{if $row.Self}} <span class="badge">You</span>{{end}}</td>
          <td><div class="chips"><span class="badge {{$row.StatusClass}}">{{$row.Status}}</span><span class="badge {{$row.MFAClass}}" title="Two-factor sign-in">2FA: {{$row.MFAStatus}}</span></div></td>
          <td>{{if $row.Team}}<span class="tag">{{$row.Team}}</span>{{else}}<span class="chip off">none</span>{{end}}</td>
          <td><div class="chips">{{range $row.Apps}}{{if .Granted}}<span class="chip">{{.Name}}</span>{{end}}{{end}}{{if eq $row.GrantedApps 0}}<span class="chip off">none</span>{{end}}</div></td>
          <td><div class="row-actions">
            <button class="btn-ghost" type="button" popovertarget="access-{{$i}}" aria-label="Access: {{$row.Email}}">Access</button>
            <button class="btn-ghost" type="button" popovertarget="settings-{{$i}}" aria-label="Settings: {{$row.Email}}">Settings</button>
          </div>
          <div id="access-{{$i}}" class="modal" popover aria-labelledby="access-{{$i}}-title">
            <div class="modal-head"><h3 id="access-{{$i}}-title">Access</h3><button class="icon-btn" type="button" popovertarget="access-{{$i}}" popovertargetaction="hide" aria-label="Close">&times;</button></div>
            <p class="who">{{$row.Email}}</p>
            <form method="post" action="/admin">
              <input type="hidden" name="csrf_token" value="{{$.CSRF}}"><input type="hidden" name="action" value="set-access"><input type="hidden" name="email" value="{{$row.Email}}">
              <div class="seg-group"><span class="seg-label">Admin</span>
                <span class="seg" role="group" aria-label="Admin permissions for {{$row.Email}}">
                  {{if or $row.Self (and $row.IsAdmin (not $row.CanDemote))}}<label class="seg-opt locked"><input type="checkbox" checked disabled> Admin</label><input type="hidden" name="admin" value="on">
                  {{else}}<label class="seg-opt"><input type="checkbox" name="admin" value="on"{{if $row.IsAdmin}} checked{{end}}> Admin</label>{{end}}
                </span>
                <p class="hint">{{if $row.Self}}You cannot remove your own administrator access.{{else if and $row.IsAdmin (not $row.CanDemote)}}The last enabled administrator cannot be removed.{{else}}Full permissions: opens this console and manages every account.{{end}}</p>
              </div>
              <div class="seg-group"><span class="seg-label">Applications</span>
                {{if $row.Apps}}<span class="seg" role="group" aria-label="Applications for {{$row.Email}}">{{range $row.Apps}}<label class="seg-opt"><input type="checkbox" name="apps" value="{{.ID}}"{{if .Granted}} checked{{end}}> {{.Name}}</label>{{end}}</span>
                <p class="hint">Selected applications sign in through {{$.Brand}}; deselecting one signs them out of it now.</p>{{else}}<p class="muted">No applications are registered yet.</p>{{end}}
              </div>
              <button class="btn" type="submit">Save access</button>
            </form>
          </div>
          <div id="settings-{{$i}}" class="modal" popover aria-labelledby="settings-{{$i}}-title">
            <div class="modal-head"><h3 id="settings-{{$i}}-title">Settings</h3><button class="icon-btn" type="button" popovertarget="settings-{{$i}}" popovertargetaction="hide" aria-label="Close">&times;</button></div>
            <p class="who">{{$row.Email}} <span class="dot">&middot;</span> created {{$row.Created}} <span class="dot">&middot;</span> {{$row.Sessions}} active session{{if ne $row.Sessions 1}}s{{end}}</p>
            <form method="post" action="/admin">
              <input type="hidden" name="csrf_token" value="{{$.CSRF}}"><input type="hidden" name="action" value="set-team"><input type="hidden" name="email" value="{{$row.Email}}">
              <div class="field"><label for="team-{{$i}}">Team</label>
                <div class="with-btn"><input id="team-{{$i}}" name="team" type="text" list="teams" maxlength="40" value="{{$row.Team}}" placeholder="e.g. Trading"><button class="btn-ghost" type="submit">Save</button></div>
                <p class="hint">A tag for grouping accounts. Leave blank to remove it.</p>
              </div>
            </form>
            {{if not $row.Self}}
            <div class="setting">
              <div><strong>Reset password</strong><p class="muted">Signs them out of every app and device; shows a new temporary password they must change.</p></div>
              <details class="confirm danger"><summary aria-label="Reset password: {{$row.Email}}">Reset</summary>
                <form class="pane" method="post" action="/admin">
                  <input type="hidden" name="csrf_token" value="{{$.CSRF}}"><input type="hidden" name="action" value="reset-password"><input type="hidden" name="email" value="{{$row.Email}}">
                  <p class="muted">{{$row.Email}} is signed out everywhere and gets a new temporary password.</p>
                  <button class="btn" type="submit">Confirm reset</button>
                </form>
              </details>
            </div>
            <div class="setting">
              <div><strong>Two-factor sign-in</strong><p class="muted">{{if not $.MFAAvailable}}Not set up on this server (AUTH_MFA_KEY).{{else if $row.MFAPolicyBound}}Required by the deployment policy; {{$row.MFAStatus}}.{{else if $row.MFARequired}}Required for this account; {{$row.MFAStatus}}. They cannot turn it off.{{else if $row.MFAEnrolled}}Enrolled voluntarily. Requiring it means they cannot turn it off.{{else}}Not enrolled. Requiring it signs them out now; they set up an authenticator at their next sign-in.{{end}}</p></div>
              {{if and $.MFAAvailable (not $row.MFAPolicyBound)}}<form method="post" action="/admin">
                <input type="hidden" name="csrf_token" value="{{$.CSRF}}"><input type="hidden" name="action" value="set-mfa-required"><input type="hidden" name="email" value="{{$row.Email}}"><input type="hidden" name="required" value="{{if $row.MFARequired}}off{{else}}on{{end}}">
                <button class="btn-ghost" type="submit" aria-label="{{if $row.MFARequired}}Stop requiring two-factor: {{$row.Email}}{{else}}Require two-factor: {{$row.Email}}{{end}}">{{if $row.MFARequired}}Stop requiring{{else}}Require{{end}}</button>
              </form>{{else if $row.MFAPolicyBound}}<span class="badge ok">Policy</span>{{end}}
            </div>
            <div class="setting">
              <div><strong>Reset two-factor</strong><p class="muted">{{if $row.MFAEnrolled}}Lost authenticator: removes it and the recovery codes, signs them out everywhere; they set up a new one at their next sign-in.{{else}}No authenticator is set up ({{$row.MFAStatus}}).{{end}}</p></div>
              {{if $row.MFAEnrolled}}{{if $.ActorEnrolled}}<details class="confirm danger"><summary aria-label="Reset two-factor: {{$row.Email}}">Reset</summary>
                <form class="pane" method="post" action="/admin">
                  <input type="hidden" name="csrf_token" value="{{$.CSRF}}"><input type="hidden" name="action" value="reset-mfa"><input type="hidden" name="email" value="{{$row.Email}}">
                  <p class="muted">Confirm you verified it is really {{$row.Email}} (for example by phone or in person) and say how.</p>
                  <label for="reason-{{$i}}">Reason</label>
                  <input id="reason-{{$i}}" name="reason" type="text" required maxlength="200" placeholder="e.g. lost phone, verified by call">
                  <button class="btn" type="submit">Confirm reset</button>
                </form>
              </details>{{else}}<a class="btn-ghost" href="/account/security" title="Set up your own authenticator first">Set up yours first</a>{{end}}{{end}}
            </div>
            <div class="setting">
              <div><strong>Sign out everywhere</strong><p class="muted">Ends every session, in every application, on every device.</p></div>
              <details class="confirm danger"><summary aria-label="Sign out: {{$row.Email}}">Sign out</summary>
                <form class="pane" method="post" action="/admin">
                  <input type="hidden" name="csrf_token" value="{{$.CSRF}}"><input type="hidden" name="action" value="revoke-sessions"><input type="hidden" name="email" value="{{$row.Email}}">
                  <p class="muted">Ends every session of {{$row.Email}}.</p>
                  <button class="btn" type="submit">Confirm sign out</button>
                </form>
              </details>
            </div>
            <div class="setting">
              {{if eq $row.StatusClass "off"}}
              <div><strong>Enable account</strong><p class="muted">Lets {{$row.Email}} sign in again.</p></div>
              <form method="post" action="/admin">
                <input type="hidden" name="csrf_token" value="{{$.CSRF}}"><input type="hidden" name="action" value="enable"><input type="hidden" name="email" value="{{$row.Email}}">
                <button class="btn-ghost" type="submit" aria-label="Enable {{$row.Email}}">Enable</button>
              </form>
              {{else}}
              <div><strong>Disable account</strong><p class="muted">Signs them out everywhere; they cannot sign in until enabled again.</p></div>
              {{if $row.CanDisable}}<details class="confirm danger"><summary aria-label="Disable: {{$row.Email}}">Disable</summary>
                <form class="pane" method="post" action="/admin">
                  <input type="hidden" name="csrf_token" value="{{$.CSRF}}"><input type="hidden" name="action" value="disable"><input type="hidden" name="email" value="{{$row.Email}}">
                  <p class="muted">{{$row.Email}} is signed out everywhere and cannot sign in until enabled again.</p>
                  <button class="btn" type="submit">Confirm disable</button>
                </form>
              </details>{{else}}<span class="badge off">Last admin</span>{{end}}
              {{end}}
            </div>
            {{else}}
            <div class="setting">
              <div><strong>Reset password</strong><p class="muted">Your own password: change it with your current one. Every other device and app is signed out; this browser stays signed in.</p></div>
              <a class="btn-ghost" href="/change-password?return_to=/admin">Change</a>
            </div>
            <div class="setting">
              <div><strong>Sign out everywhere</strong><p class="muted">Ends every one of your sessions, in every application, on every device, this one included.</p></div>
              <details class="confirm danger"><summary aria-label="Sign out everywhere: {{$row.Email}}">Sign out</summary>
                <form class="pane" method="post" action="/admin">
                  <input type="hidden" name="csrf_token" value="{{$.CSRF}}"><input type="hidden" name="action" value="revoke-sessions"><input type="hidden" name="email" value="{{$row.Email}}">
                  <p class="muted">You will be signed out here too and return to the sign-in page.</p>
                  <button class="btn" type="submit">Confirm sign out</button>
                </form>
              </details>
            </div>
            {{end}}
          </div></td>
        </tr>{{end}}
        </tbody>
      </table></div>{{else}}<p class="empty">No accounts yet. Add the first one with the button above.</p>{{end}}
      <datalist id="teams">{{range .Teams}}<option value="{{.}}">{{end}}</datalist>
    </section>

    <div id="add-user" class="modal" popover aria-labelledby="add-user-title">
      <div class="modal-head"><h3 id="add-user-title">Add user</h3><button class="icon-btn" type="button" popovertarget="add-user" popovertargetaction="hide" aria-label="Close">&times;</button></div>
      <p class="who">A temporary password is shown once; they choose their own at first sign-in.</p>
      <form method="post" action="/admin">
        <input type="hidden" name="csrf_token" value="{{.CSRF}}"><input type="hidden" name="action" value="create">
        <div class="field"><label for="new-email">Work email</label>
          <input id="new-email" name="email" type="email" required autocomplete="off" placeholder="name@company.com"></div>
        <div class="field"><label for="new-team">Team <span class="muted">(optional)</span></label>
          <input id="new-team" name="team" type="text" list="teams" maxlength="40" placeholder="e.g. Trading"></div>
        <div class="field"><label for="new-password">Temporary password</label>
          <div class="with-btn"><input id="new-password" name="password" type="text" autocomplete="off" minlength="12" placeholder="Leave blank to generate one"><button class="btn-ghost" type="button" data-generate="new-password">Generate</button></div>
          <p class="hint">At least 12 characters, not built from their name or {{.Brand}}. Blank means a strong one is generated for you.</p></div>
        <div class="seg-group"><span class="seg-label">Admin</span>
          <span class="seg" role="group" aria-label="Admin permissions"><label class="seg-opt"><input type="checkbox" name="admin" value="on"> Admin</label></span>
          <p class="hint">Full permissions: opens this console and manages every account.</p>
        </div>
        <div class="seg-group"><span class="seg-label">Applications</span>
          {{if .AppChoices}}<span class="seg" role="group" aria-label="Applications">{{range .AppChoices}}<label class="seg-opt{{if not .Granted}} off{{end}}"{{if not .Granted}} title="Application disabled"{{end}}><input type="checkbox" name="apps" value="{{.ID}}"{{if .Granted}} checked{{end}}> {{.Name}}</label>{{end}}</span>
          <p class="hint">Which applications they may sign in to.</p>
          {{else}}<p class="muted">No applications are registered yet; register them with <code>auth app create</code> on the server.</p>{{end}}
        </div>
        <button class="btn" type="submit">Create account</button>
      </form>
    </div>

    <div id="mfa-policy" class="modal" popover aria-labelledby="mfa-policy-title">
      <div class="modal-head"><h3 id="mfa-policy-title">Two-factor policy</h3><button class="icon-btn" type="button" popovertarget="mfa-policy" popovertargetaction="hide" aria-label="Close">&times;</button></div>
      <p class="who">Who must enter a code from an authenticator app after their password. Anyone may set one up from their Security page, and once they have, they always use it; this policy decides who is made to. A per-account requirement (Settings) adds to whichever policy is chosen.</p>
      {{if not .MFAAvailable}}<div class="err">Two-factor sign-in is not set up on this server: set AUTH_MFA_KEY (see <code>auth mfa keygen</code>) and restart.</div>{{else}}
      <form method="post" action="/admin">
        <input type="hidden" name="csrf_token" value="{{.CSRF}}"><input type="hidden" name="action" value="set-policy"><input type="hidden" name="revision" value="{{.MFARevision}}">
        <div class="seg-group"><span class="seg-label">Policy</span>
          <span class="seg" role="radiogroup" aria-label="Two-factor policy">{{range .MFAOptions}}<label class="seg-opt"><input type="radio" name="mode" value="{{.Mode}}"{{if .Current}} checked{{end}}> {{.Label}}</label>{{end}}</span>
          <p class="hint">{{range .MFAOptions}}{{if .Current}}Current: {{.Label}}.{{end}}{{end}}</p>
        </div>
        {{if .MFACountError}}<div class="err">The affected-account counts could not be loaded, so the policy cannot be changed from here right now. Reload and try again.</div>{{else}}
        <ul class="plain">{{range .MFAOptions}}<li><strong>{{.Label}}</strong>: {{.Describe}} {{if eq .ToEnroll 0}}Choosing it now makes nobody new enroll.{{else if eq .ToEnroll 1}}Choosing it now signs out 1 account without an authenticator; they set one up at their next sign-in.{{else}}Choosing it now signs out {{.ToEnroll}} accounts without an authenticator; they set one up at their next sign-in.{{end}}</li>{{end}}</ul>
        <p class="hint">Relaxing the policy never removes anyone's authenticator. Changes take effect immediately{{if not .ActorFresh}} and need your authenticator code entered less than five minutes ago{{end}}.</p>
        <button class="btn" type="submit">Save policy</button>{{end}}
      </form>{{end}}
    </div>
    {{else}}{{with .App}}
    <section class="section" aria-labelledby="app-heading">
      <div class="topline">
        <h2 id="app-heading">{{.Name}} {{if .Disabled}}<span class="badge off">Disabled</span>{{else}}<span class="badge ok">Enabled</span>{{end}}</h2>
        {{if .Disabled}}
        <form method="post" action="/admin">
          <input type="hidden" name="csrf_token" value="{{$.CSRF}}"><input type="hidden" name="action" value="enable-app"><input type="hidden" name="app" value="{{.ID}}">
          <button class="btn-ghost" type="submit">Enable application</button>
        </form>
        {{else}}
        <details class="confirm danger"><summary>Disable application</summary>
          <form class="pane" method="post" action="/admin">
            <input type="hidden" name="csrf_token" value="{{$.CSRF}}"><input type="hidden" name="action" value="disable-app"><input type="hidden" name="app" value="{{.ID}}">
            <p class="muted">Nobody can sign in to {{.Name}} until it is enabled again. Existing application sessions are not ended.</p>
            <button class="btn" type="submit">Confirm disable</button>
          </form>
        </details>
        {{end}}
      </div>
      <dl class="kv">
        <dt>Client ID</dt><dd><code>{{.ID}}</code></dd>
        <dt>Callback</dt><dd><code>{{.Callback}}</code></dd>
        <dt>Signed-out page</dt><dd>{{if .Logout}}<code>{{.Logout}}</code>{{else}}<span class="muted">none</span>{{end}}</dd>
        <dt>Back-channel logout</dt><dd>{{if .Backchannel}}<code>{{.Backchannel}}</code>{{else}}<span class="badge warn">not configured</span> sign-outs elsewhere will not reach this application{{end}}</dd>
        <dt>Accounts with access</dt><dd>{{.Granted}}</dd>
        <dt>Registered</dt><dd>{{.Created}}</dd>
      </dl>
    </section>
    <section class="section" aria-labelledby="signins-heading">
      <h2 id="signins-heading">Who signs in here</h2>
      <p class="muted">Accounts that have completed a sign-in to {{.Name}}, most recent first.</p>
      {{if .SignIns}}<div class="table-wrap"><table class="list">
        <thead><tr><th>Account</th><th class="num">Sign-ins</th><th>Last</th></tr></thead>
        <tbody>{{range .SignIns}}<tr><td class="who">{{.Email}}{{if .Disabled}} <span class="badge off">Disabled</span>{{end}}</td><td class="num">{{.Count}}</td><td>{{.Last}}</td></tr>{{end}}</tbody>
      </table></div>{{else}}<p class="empty">Nobody has signed in to {{.Name}} yet.</p>{{end}}
    </section>
    <section class="section" aria-labelledby="pending-heading">
      <h2 id="pending-heading">Pending sign-outs</h2>
      <p class="muted">Back-channel logouts {{.Name}} has not accepted yet. Empty is healthy.</p>
      {{if .Pending}}<div class="table-wrap"><table class="list">
        <thead><tr><th>Reason</th><th>Issued</th><th class="num">Attempts</th><th>Next try</th><th>Last error</th></tr></thead>
        <tbody>{{range .Pending}}<tr><td>{{.Reason}}{{if .Abandoned}} <span class="badge off">given up</span>{{end}}</td><td>{{.Issued}}</td><td class="num">{{.Attempts}}</td><td>{{.NextAttempt}}</td><td>{{.LastError}}</td></tr>{{end}}</tbody>
      </table></div>{{else}}<p class="empty">Nothing pending.</p>{{end}}
    </section>
    {{end}}{{end}}

  </main>
  <script nonce="{{.Nonce}}">` + adminScript + `</script>
</body>
</html>`

const sentHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{{.Wordmark}} — Check your inbox</title>
{{if .LogoURL}}<link rel="icon" href="{{.LogoURL}}">{{end}}
<style nonce="{{.Nonce}}">` + fontFaceCSS + tokensCSS + componentCSS + `{{.BrandCSS}}</style>
<script nonce="{{.Nonce}}">` + themeScript + `</script>
</head>
<body>
  ` + themeToggle + `
  <main class="card">
    {{if .LogoURL}}<img class="mark" src="{{.LogoURL}}" alt="">{{end}}
    <div class="brand">{{.Wordmark}}</div>
    <h1>Check your inbox</h1>
    <p class="muted">If <b>{{.Email}}</b> has an account, a one-time sign-in link is on its way. Click it to continue.</p>
    <div class="foot">The link expires in 15 minutes. Didn't get one? Check spam, or
      <a href="/">try again</a>.</div>
  </main>
</body>
</html>`

// Email bodies are intentionally generic — no logos, no brand colors,
// no marketing copy. Goal: a message that works unchanged for every
// client deployment without per-tenant theming.
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

// ── second factor pages ─────────────────────────────────────────────

const mfaVerifyHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{{.Wordmark}} — Two-factor sign-in</title>
{{if .LogoURL}}<link rel="icon" href="{{.LogoURL}}">{{end}}
<style nonce="{{.Nonce}}">` + fontFaceCSS + tokensCSS + componentCSS + `{{.BrandCSS}}</style>
<script nonce="{{.Nonce}}">` + themeScript + `</script>
</head>
<body>
  ` + themeToggle + `
  <main class="card">
    {{if .LogoURL}}<img class="mark" src="{{.LogoURL}}" alt="">{{end}}
    <div class="brand">{{.Wordmark}}</div>
    <h1>Enter your code</h1>
    <p class="muted">Signing in as <strong>{{.Email}}</strong>. {{if .Recovery}}Enter one of your recovery codes.{{else}}Open your authenticator app and enter the six-digit code for {{.Brand}}.{{end}}</p>
    {{if .Error}}<div class="err">{{.Error}}</div>{{end}}
    <form method="post" action="/login/verify" autocomplete="off">
      <input type="hidden" name="csrf_token" value="{{.CSRF}}">
      {{if .Recovery}}
      <input type="hidden" name="mode" value="recovery">
      <label for="recovery_code">Recovery code</label>
      <input id="recovery_code" name="recovery_code" type="text" required autofocus autocomplete="off" spellcheck="false" placeholder="xxxxx-xxxxx-xxxxx-xxxxx-xxxxx-x">
      {{else}}
      <label for="code">Authenticator code</label>
      <input id="code" name="code" class="code" type="text" inputmode="numeric" pattern="[0-9 ]*" maxlength="7" required autofocus autocomplete="one-time-code" placeholder="000000">
      {{end}}
      <button class="btn" type="submit">Continue</button>
    </form>
    <div class="link-row">
      {{if .Recovery}}<a href="/login/verify">Use my authenticator app</a>{{else if .HasRecovery}}<a href="/login/verify?mode=recovery">Use a recovery code</a>{{else}}<span></span>{{end}}
      <form method="post" action="/login/cancel"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><button class="linkish" type="submit">Cancel sign-in</button></form>
    </div>
  </main>
</body>
</html>`

const mfaEnrollHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{{.Wordmark}} — Set up your authenticator</title>
{{if .LogoURL}}<link rel="icon" href="{{.LogoURL}}">{{end}}
<style nonce="{{.Nonce}}">` + fontFaceCSS + tokensCSS + componentCSS + `{{.BrandCSS}}</style>
<script nonce="{{.Nonce}}">` + themeScript + `</script>
</head>
<body>
  ` + themeToggle + `
  <main class="card">
    {{if .LogoURL}}<img class="mark" src="{{.LogoURL}}" alt="">{{end}}
    <div class="brand">{{.Wordmark}}</div>
    <h1>{{if .Replace}}Replace your authenticator{{else}}Set up your authenticator{{end}}</h1>
    <p class="muted">{{if .Required}}Your account requires a second step at sign-in. {{end}}Scan this code with an authenticator app (Google Authenticator, Microsoft Authenticator, 1Password, Authy and others all work), then enter the six-digit code it shows.</p>
    {{if .Error}}<div class="err">{{.Error}}</div>{{end}}
    <img class="qr" src="{{.QR}}" alt="QR code for {{.Issuer}}: {{.Email}}" width="220" height="220">
    <div class="secret">
      <p class="muted">Cannot scan? Enter this key by hand (time-based, six digits):</p>
      <code id="manual-key">{{.ManualKey}}</code>
      <p class="muted">Account: {{.Email}} · Issuer: {{.Issuer}}</p>
    </div>
    <form method="post" action="{{.Action}}" autocomplete="off">
      <input type="hidden" name="csrf_token" value="{{.CSRF}}">
      <input type="hidden" name="action" value="confirm">
      {{if .ReturnTo}}<input type="hidden" name="return_to" value="{{.ReturnTo}}">{{end}}
      <label for="code">Code from the app</label>
      <input id="code" name="code" class="code" type="text" inputmode="numeric" pattern="[0-9 ]*" maxlength="7" required autofocus autocomplete="one-time-code" placeholder="000000">
      <button class="btn" type="submit">{{if .Replace}}Replace authenticator{{else}}Turn on two-factor sign-in{{end}}</button>
    </form>
    {{if eq .Action "/login/enroll"}}<div class="link-row"><span></span><form method="post" action="/login/cancel"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><button class="linkish" type="submit">Cancel sign-in</button></form></div>
    {{else}}<div class="link-row"><a href="/account/security">Back to security settings</a><span></span></div>{{end}}
  </main>
</body>
</html>`

const recoveryCodesHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{{.Wordmark}} — Recovery codes</title>
{{if .LogoURL}}<link rel="icon" href="{{.LogoURL}}">{{end}}
<style nonce="{{.Nonce}}">` + fontFaceCSS + tokensCSS + componentCSS + `{{.BrandCSS}}</style>
<script nonce="{{.Nonce}}">` + themeScript + `</script>
</head>
<body>
  ` + themeToggle + `
  <main class="card">
    {{if .LogoURL}}<img class="mark" src="{{.LogoURL}}" alt="">{{end}}
    <div class="brand">{{.Wordmark}}</div>
    <h1>{{.Title}}</h1>
    <p class="muted">Save these recovery codes somewhere safe, such as a password manager. Each one signs you in once if you lose your authenticator. They are shown only now.</p>
    <ol class="codes">{{range .Codes}}<li>{{.}}</li>{{end}}</ol>
    <a class="btn" href="{{.ContinueTo}}">I have saved them, continue</a>
  </main>
</body>
</html>`

const securityHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{{.Wordmark}} — Security</title>
{{if .LogoURL}}<link rel="icon" href="{{.LogoURL}}">{{end}}
<style nonce="{{.Nonce}}">` + fontFaceCSS + tokensCSS + componentCSS + `{{.BrandCSS}}</style>
<script nonce="{{.Nonce}}">` + themeScript + `</script>
</head>
<body>
  ` + themeToggle + `
  <main class="card">
    {{if .LogoURL}}<img class="mark" src="{{.LogoURL}}" alt="">{{end}}
    <div class="brand">{{.Wordmark}}</div>
    <h1>Security</h1>
    <p class="muted">Two-factor sign-in for <strong>{{.Email}}</strong>.</p>
    {{if .Notice}}<div class="banner" role="status"><strong>Done.</strong> {{.Notice}}</div>{{end}}
    {{if .UsedRecovery}}<div class="banner warn" role="status"><strong>Recovery code used.</strong> You signed in with a recovery code. If you lost your authenticator, replace it now.</div>{{end}}
    {{if .Error}}<div class="err">{{.Error}}</div>{{end}}
    <div class="status-line"><span class="tag {{if .Enrolled}}on{{else if .Required}}need{{end}}">{{.Status}}</span>{{if .Enrolled}}<span class="muted">{{.Remaining}} recovery codes left</span>{{else if .Required}}<span class="muted">Set up an authenticator to continue.</span>{{end}}</div>
    {{if not .Available}}<div class="err">Two-factor sign-in is not set up on this server. Ask your administrator to configure AUTH_MFA_KEY.</div>{{else}}
    <div class="actions">
      <form method="post" action="/account/security"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><input type="hidden" name="action" value="start">{{if .ReturnTo}}<input type="hidden" name="return_to" value="{{.ReturnTo}}">{{end}}
        <button class="btn" type="submit">{{if .Enrolled}}Replace authenticator{{else}}Set up authenticator{{end}}</button></form>
      {{if .Enrolled}}
      <form method="post" action="/account/security"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><input type="hidden" name="action" value="regenerate">
        <button class="btn-ghost" type="submit">New recovery codes</button></form>
      {{if not .Required}}
      <form method="post" action="/account/security"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><input type="hidden" name="action" value="disable">
        <button class="btn-ghost" type="submit">Turn off two-factor sign-in</button></form>
      {{end}}
      {{end}}
    </div>
    <p class="hint muted">Changes ask for your password{{if .Enrolled}} and current code{{end}} again if you signed in more than five minutes ago.</p>
    {{end}}
    <div class="link-row"><a href="/account">Back to your apps</a>{{if .IsAdmin}}<a href="/admin">Admin</a>{{end}}</div>
  </main>
</body>
</html>`

const reauthHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{{.Wordmark}} — Confirm it is you</title>
{{if .LogoURL}}<link rel="icon" href="{{.LogoURL}}">{{end}}
<style nonce="{{.Nonce}}">` + fontFaceCSS + tokensCSS + componentCSS + `{{.BrandCSS}}</style>
<script nonce="{{.Nonce}}">` + themeScript + `</script>
</head>
<body>
  ` + themeToggle + `
  <main class="card">
    {{if .LogoURL}}<img class="mark" src="{{.LogoURL}}" alt="">{{end}}
    <div class="brand">{{.Wordmark}}</div>
    <h1>Confirm it is you</h1>
    <p class="muted">Enter your password{{if .Enrolled}} and the current code from your authenticator app{{end}} to change security settings for <strong>{{.Email}}</strong>.</p>
    {{if .Error}}<div class="err">{{.Error}}</div>{{end}}
    <form method="post" action="/account/security/verify" autocomplete="off">
      <input type="hidden" name="csrf_token" value="{{.CSRF}}">
      {{if .Action}}<input type="hidden" name="action" value="{{.Action}}">{{end}}
      {{if .ReturnTo}}<input type="hidden" name="return_to" value="{{.ReturnTo}}">{{end}}
      <label for="password">Password</label>
      <input id="password" name="password" type="password" required autofocus autocomplete="current-password">
      {{if .Enrolled}}
      <label for="code">Authenticator code</label>
      <input id="code" name="code" class="code" type="text" inputmode="numeric" pattern="[0-9 ]*" maxlength="7" required autocomplete="one-time-code" placeholder="000000">
      {{end}}
      <button class="btn" type="submit">Continue</button>
    </form>
    <div class="link-row"><a href="/account/security">Cancel</a><span></span></div>
  </main>
</body>
</html>`

const statusHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{{.Wordmark}} — {{.Title}}</title>
{{if .LogoURL}}<link rel="icon" href="{{.LogoURL}}">{{end}}
<style nonce="{{.Nonce}}">` + fontFaceCSS + tokensCSS + componentCSS + `{{.BrandCSS}}</style>
<script nonce="{{.Nonce}}">` + themeScript + `</script>
</head>
<body>
  ` + themeToggle + `
  <main class="card">
    {{if .LogoURL}}<img class="mark" src="{{.LogoURL}}" alt="">{{end}}
    <div class="brand">{{.Wordmark}}</div>
    <h1>{{.Title}}</h1>
    <p class="muted">{{.Message}}</p>
    <a class="btn" href="/">Back to sign-in</a>
  </main>
</body>
</html>`
