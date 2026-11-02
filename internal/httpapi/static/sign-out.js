// The apps page's Sign out button (account.html) asks first: it opens the
// Sign out popup (_partials.html "sign-out") instead of submitting its form
// at once. Without script, or without <dialog>, it stays the plain submit
// button it is in the markup and signs out directly. Your account's Sign out
// opens the popup by itself (commandfor), so it needs nothing here.
(function () {
  "use strict";
  var dialog = document.getElementById("sign-out");
  if (!dialog || typeof dialog.showModal !== "function") return;
  document.querySelectorAll("[data-sign-out]").forEach(function (button) {
    button.addEventListener("click", function (event) {
      event.preventDefault();
      if (!dialog.open) dialog.showModal();
    });
  });
})();
