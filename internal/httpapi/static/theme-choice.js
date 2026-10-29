// The theme choice in Your account (_partials.html "account-menu"): Light,
// Dark or Auto, which follows the device. Flag's theme controller
// (flag/theme/theme-controller.js, vendored, loaded in <head>) applies a
// stored "light" or "dark" from localStorage "flag-theme-preference" and
// otherwise follows prefers-color-scheme, re-applying on a device change only
// while nothing explicit is stored. This writes the same key ("system" for
// Auto, Flag's documented value) and the same data-theme attribute.
(function () {
  "use strict";
  var key = "flag-theme-preference";
  var root = document.documentElement;
  var media = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
  var options = document.querySelectorAll("[data-theme-option]");
  if (!options.length) return;

  function stored() {
    try {
      return window.localStorage.getItem(key);
    } catch (error) {
      return null;
    }
  }

  var current = stored() === "light" || stored() === "dark" ? stored() : "system";

  function show() {
    options.forEach(function (option) {
      option.setAttribute("aria-pressed", option.getAttribute("data-theme-option") === current ? "true" : "false");
    });
  }

  options.forEach(function (option) {
    option.addEventListener("click", function () {
      var value = option.getAttribute("data-theme-option");
      try {
        window.localStorage.setItem(key, value);
      } catch (error) {
        // Storage refused: the choice still applies to this page.
      }
      current = value;
      root.setAttribute("data-theme", value === "system" ? (media && media.matches ? "dark" : "light") : value);
      show();
    });
  });
  document.querySelectorAll("[data-theme-choice]").forEach(function (row) {
    row.hidden = false;
  });
  show();
})();
