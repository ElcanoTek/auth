(function () {
  'use strict';
  function normalize(value) {
    var base = (value || '').trim().toLowerCase().split('-')[0];
    return ['en', 'es', 'pt'].indexOf(base) >= 0 ? base : '';
  }
  var page = document.documentElement;
  var url = new URL(window.location.href);
  var explicit = normalize(url.searchParams.get('lang'));
  var oidc = (url.searchParams.get('ui_locales') || '').split(/\s+/).map(normalize).filter(Boolean)[0];
  var saved = '';
  try { saved = normalize(localStorage.getItem('elcano.language')); } catch (_) { /* Storage can be unavailable. */ }
  var selected = explicit || oidc || saved;
  if (selected && page.dataset.languageSync === 'true' && selected !== page.lang) {
    url.searchParams.set('lang', selected);
    window.location.replace(url.href);
    return;
  }
  if (explicit || oidc) {
    try { localStorage.setItem('elcano.language', explicit || oidc); } catch (_) { /* The server cookie also persists the choice. */ }
  }
  document.addEventListener('DOMContentLoaded', function () {
    var form = document.querySelector('[data-language-choice]');
    if (!form) return;
    form.addEventListener('submit', function () {
      try { localStorage.setItem('elcano.language', form.elements.lang.value); } catch (_) { /* The query parameter still works. */ }
    });
  });
}());
