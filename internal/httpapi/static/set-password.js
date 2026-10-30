// set-password.js: opens an emailed password link. The token is in the
// link's fragment (never sent to a server); this moves it into the form,
// takes it out of the address bar and history, and posts the form, which
// only shows the password form: nothing is used up until a password is
// saved.
(function () {
  'use strict';
  var form = document.getElementById('open-link');
  if (!form) { return; }
  var token = window.location.hash.slice(1);
  if (window.history && window.history.replaceState) {
    window.history.replaceState(null, '', window.location.pathname);
  }
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) {
    var missing = document.getElementById('link-missing');
    var opening = document.getElementById('link-opening');
    if (missing) { missing.hidden = false; }
    if (opening) { opening.hidden = true; }
    return;
  }
  form.elements.token.value = token;
  form.submit();
}());
