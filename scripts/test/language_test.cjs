// Browser preference logic without a framework or runtime dependency.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../../internal/httpapi/static/language.js'), 'utf8');
function run({ query = '', lang = 'en', saved = '', post = false, blocked = false, theme = false } = {}) {
  const result = { saved, redirect: null, submit: null };
  const root = { lang, dataset: { languageSync: String(!post), theme: 'light' } };
  const toggle = { dataset: { themeLabelLight: 'Modo claro', themeLabelDark: 'Modo oscuro' }, setAttribute: (name, value) => { result.label = value; } };
  result.dark = () => { root.dataset.theme = 'dark'; result.observer(); };
  const form = { elements: { lang: { value: 'pt' } }, addEventListener: (_, fn) => { result.submit = fn; } };
  vm.runInNewContext(source, {
    URL,
    MutationObserver: class { constructor(fn) { result.observer = fn; } observe() {} },
    window: { location: { href: 'https://auth.example/set-password?' + query + '#example-token', replace: url => { result.redirect = new URL(url); } } },
    document: {
      documentElement: root,
      querySelectorAll: () => theme ? [toggle] : [],
      addEventListener: (_, fn) => fn(), querySelector: () => post ? null : form,
    },
    localStorage: {
      getItem: () => { if (blocked) throw Error('blocked'); return saved; },
      setItem: (key, value) => { if (blocked) throw Error('blocked'); assert.equal(key, 'elcano.language'); result.saved = value; },
    },
  });
  return result;
}
test('saved regional preference wins over a browser-rendered language and preserves URL values', () => {
  const result = run({ saved: 'PT-br', lang: 'es', query: 'state=a%2Bb&return_to=%2Faccount' });
  assert.equal(result.redirect.searchParams.get('lang'), 'pt');
  assert.equal(result.redirect.searchParams.get('state'), 'a+b');
  assert.equal(result.redirect.searchParams.get('return_to'), '/account');
  assert.equal(result.redirect.hash, '#example-token');
});
test('explicit language wins over OIDC and saved choices', () => {
  const result = run({ query: 'lang=en&ui_locales=es', saved: 'pt' });
  assert.equal(result.redirect, null); assert.equal(result.saved, 'en');
});
test('OIDC uses first supported regional language before storage', () => {
  const result = run({ query: 'ui_locales=fr+es-MX+pt', lang: 'es', saved: 'pt' });
  assert.equal(result.redirect, null); assert.equal(result.saved, 'es');
});
test('browser fallback and blocked storage do not reload', () => {
  assert.equal(run({ lang: 'pt' }).redirect, null);
  assert.equal(run({ blocked: true, lang: 'es', query: 'lang=es' }).redirect, null);
  assert.equal(run({ lang: 'en', saved: 'fr' }).redirect, null);
});
test('one-time POST results are never replayed or redirected', () => {
  const result = run({ post: true, lang: 'es', saved: 'pt' });
  assert.equal(result.redirect, null); assert.equal(result.submit, null);
});
test('the language form persists the selected autonym value', () => {
  const result = run(); result.submit(); assert.equal(result.saved, 'pt');
});

test('theme labels follow Flag changes on GET and one-time POST pages', () => {
  for (const post of [false, true]) {
    const result = run({ theme: true, post });
    assert.equal(result.label, 'Modo oscuro'); result.dark();
    assert.equal(result.label, 'Modo claro');
  }
});
