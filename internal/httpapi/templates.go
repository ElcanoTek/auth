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
/* ── admin console ── */
.card.admin { max-width: 60rem; }
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
.table-wrap { overflow-x: auto; }
table.list { width: 100%; border-collapse: collapse; font-size: var(--font-size-caption); }
table.list th, table.list td { text-align: left; padding: var(--space-2) var(--space-3); border-bottom: 1px solid var(--color-border); vertical-align: top; }
table.list th { color: var(--color-text-muted); font-weight: var(--font-weight-bold); letter-spacing: 0.08em; text-transform: uppercase; font-size: 0.6875rem; }
table.list td { color: var(--color-text-secondary); }
table.list td.who { color: var(--color-text-primary); font-weight: var(--font-weight-bold); white-space: nowrap; }
table.list td.num { text-align: right; font-variant-numeric: tabular-nums; }
table.list tr:last-child td { border-bottom: 0; }
table.list td.date { white-space: nowrap; }
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
.footer-actions { margin-top: var(--space-8); display: flex; gap: var(--space-4); align-items: center; justify-content: space-between; flex-wrap: wrap; }
.footer-actions .btn { width: auto; margin: 0; padding-inline: var(--space-6); min-height: 2.5rem; }
.footer-actions a { color: var(--color-accent); font-size: var(--font-size-caption); }
@media (max-width: 40rem) {
  .add { grid-template-columns: 1fr; } .add .btn { width: 100%; }
  table.list .num, table.list .date { display: none; }
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
    <section class="apps" aria-labelledby="apps-heading">
      <h2 id="apps-heading">Your apps</h2>
      <p class="muted">One sign-in for every {{.Brand}} app. Greyed tiles are not part of this deployment.</p>
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
<body>
  ` + themeToggle + `
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
    {{if .Error}}<div class="err" role="alert">{{.Error}}</div>{{end}}
    {{if .Notice}}<div class="notice" role="status">{{.Notice}}</div>{{end}}
    {{if .Secret}}<div class="secret" role="status">
      <p class="muted">Temporary password for <strong>{{.SecretFor}}</strong>. It is shown once and not stored: copy it now.</p>
      <code>{{.Secret}}</code>
      <p class="muted">They sign in with it and are asked to choose their own password before anything else.</p>
    </div>{{end}}

    {{if eq .Tab "accounts"}}
    <section class="section" aria-labelledby="accounts-heading">
      <h2 id="accounts-heading">Accounts</h2>
      <p class="muted">Who can sign in, to which applications, and whether they can open this console.</p>
      {{if .Accounts}}<div class="table-wrap"><table class="list">
        <thead><tr><th>Account</th><th>Status</th><th>Applications</th><th class="num">Sessions</th><th>Created</th></tr></thead>
        <tbody>
        {{range .Accounts}}<tr class="account">
          <td class="who">{{.Email}}{{if .IsAdmin}} <span class="badge admin">Admin</span>{{end}}{{if .Self}} <span class="badge">You</span>{{end}}</td>
          <td><span class="badge {{.StatusClass}}">{{.Status}}</span></td>
          <td><div class="chips">{{range .Apps}}{{if .Granted}}<span class="chip">{{.Name}}</span>{{end}}{{end}}{{if not .Apps}}<span class="chip off">none</span>{{end}}</div></td>
          <td class="num">{{.Sessions}}</td>
          <td class="date">{{.Created}}</td>
        </tr><tr class="manage">
          <td colspan="5"><div class="actions">
            <details class="confirm"><summary>Access</summary>
              <form class="pane" method="post" action="/admin">
                <input type="hidden" name="csrf_token" value="{{$.CSRF}}"><input type="hidden" name="action" value="set-access"><input type="hidden" name="email" value="{{.Email}}">
                <div class="checks">{{range .Apps}}<label><input type="checkbox" name="apps" value="{{.ID}}"{{if .Granted}} checked{{end}}> {{.Name}}</label>{{end}}</div>
                {{if .Apps}}<p class="muted">Unticking an application signs them out of it now.</p><button class="btn" type="submit">Save access</button>{{else}}<p class="muted">No applications are registered yet.</p>{{end}}
              </form>
            </details>
            {{if not .Self}}
            <details class="confirm danger"><summary>Reset password</summary>
              <form class="pane" method="post" action="/admin">
                <input type="hidden" name="csrf_token" value="{{$.CSRF}}"><input type="hidden" name="action" value="reset-password"><input type="hidden" name="email" value="{{.Email}}">
                <p class="muted">Signs {{.Email}} out everywhere and shows a new temporary password.</p>
                <button class="btn" type="submit">Confirm reset</button>
              </form>
            </details>
            <details class="confirm danger"><summary>Sign out</summary>
              <form class="pane" method="post" action="/admin">
                <input type="hidden" name="csrf_token" value="{{$.CSRF}}"><input type="hidden" name="action" value="revoke-sessions"><input type="hidden" name="email" value="{{.Email}}">
                <p class="muted">Ends every session of {{.Email}}, in every application, on every device.</p>
                <button class="btn" type="submit">Confirm sign out</button>
              </form>
            </details>
            {{if eq .StatusClass "off"}}
            <form method="post" action="/admin">
              <input type="hidden" name="csrf_token" value="{{$.CSRF}}"><input type="hidden" name="action" value="enable"><input type="hidden" name="email" value="{{.Email}}">
              <button class="btn-ghost" type="submit">Enable</button>
            </form>
            {{else if .CanDisable}}
            <details class="confirm danger"><summary>Disable</summary>
              <form class="pane" method="post" action="/admin">
                <input type="hidden" name="csrf_token" value="{{$.CSRF}}"><input type="hidden" name="action" value="disable"><input type="hidden" name="email" value="{{.Email}}">
                <p class="muted">{{.Email}} is signed out everywhere and cannot sign in until enabled again.</p>
                <button class="btn" type="submit">Confirm disable</button>
              </form>
            </details>
            {{end}}
            {{if .IsAdmin}}{{if .CanDemote}}
            <details class="confirm danger"><summary>Remove admin</summary>
              <form class="pane" method="post" action="/admin">
                <input type="hidden" name="csrf_token" value="{{$.CSRF}}"><input type="hidden" name="action" value="revoke-admin"><input type="hidden" name="email" value="{{.Email}}">
                <p class="muted">{{.Email}} keeps their account and applications but can no longer open this console.</p>
                <button class="btn" type="submit">Confirm remove</button>
              </form>
            </details>
            {{end}}{{else}}
            <form method="post" action="/admin">
              <input type="hidden" name="csrf_token" value="{{$.CSRF}}"><input type="hidden" name="action" value="grant-admin"><input type="hidden" name="email" value="{{.Email}}">
              <button class="btn-ghost" type="submit">Make admin</button>
            </form>
            {{end}}
            {{end}}
          </div></td>
        </tr>{{end}}
        </tbody>
      </table></div>{{else}}<p class="empty">No accounts yet. Add the first one below.</p>{{end}}
    </section>

    <section class="section" aria-labelledby="add-heading">
      <h2 id="add-heading">Add user</h2>
      <p class="muted">A temporary password is generated for you and shown once. They choose their own at first sign-in.</p>
      <form class="add" method="post" action="/admin">
        <input type="hidden" name="csrf_token" value="{{.CSRF}}"><input type="hidden" name="action" value="create">
        <div><label for="new-email">Work email</label>
        <input id="new-email" name="email" type="email" required autocomplete="off" placeholder="name@company.com"></div>
        <button class="btn" type="submit">Add user</button>
        <div class="wide-field"><label>Applications</label>
          {{if .AppChoices}}<div class="checks">{{range .AppChoices}}<label{{if not .Granted}} class="off"{{end}}><input type="checkbox" name="apps" value="{{.ID}}"{{if .Granted}} checked{{end}}> {{.Name}}{{if not .Granted}} (disabled){{end}}</label>{{end}}</div>
          {{else}}<p class="muted">No applications are registered yet; register them with <code>auth app create</code> on the server.</p>{{end}}
        </div>
      </form>
    </section>
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

    <div class="footer-actions">
      <a href="/account">Back to your apps</a>
      <form method="post" action="/logout">
        <input type="hidden" name="csrf_token" value="{{.CSRF}}">
        <input type="hidden" name="redirect_to" value="/?notice=signed_out">
        <button class="btn" type="submit">Sign out</button>
      </form>
    </div>
  </main>
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
