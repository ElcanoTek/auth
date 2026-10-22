(function () {
  var root = document.documentElement;
  var key = "flag-theme-preference";
  var media = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;

  function getStoredPreference() {
    try {
      return window.localStorage.getItem(key);
    } catch (error) {
      return null;
    }
  }

  function getSystemTheme() {
    return media && media.matches ? "dark" : "light";
  }

  function applyTheme(theme) {
    root.setAttribute("data-theme", theme);

    var toggles = document.querySelectorAll("[data-flag-theme-toggle]");
    toggles.forEach(function (toggle) {
      var darkMode = theme === "dark";
      toggle.setAttribute("aria-pressed", darkMode ? "true" : "false");
      toggle.setAttribute("aria-label", darkMode ? "Switch to light mode" : "Switch to dark mode");
    });
  }

  function resolveTheme() {
    var stored = getStoredPreference();
    return stored === "light" || stored === "dark" ? stored : getSystemTheme();
  }

  function toggleTheme() {
    var nextTheme = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
    try {
      window.localStorage.setItem(key, nextTheme);
    } catch (error) {
      // Ignore storage failures and still update the current page theme.
    }
    applyTheme(nextTheme);
  }

  applyTheme(resolveTheme());

  // Loaded in <head> (the recommended placement, so data-theme is set before
  // first paint), the applyTheme() above runs before any toggle exists. Once
  // the document is parsed, bind the toggles and give them their aria state.
  function bindToggles() {
    var toggles = document.querySelectorAll("[data-flag-theme-toggle]");
    toggles.forEach(function (toggle) {
      toggle.addEventListener("click", toggleTheme);
    });
    applyTheme(root.getAttribute("data-theme") || resolveTheme());
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bindToggles);
  } else {
    bindToggles();
  }

  if (media) {
    media.addEventListener("change", function () {
      var stored = getStoredPreference();
      if (stored === "light" || stored === "dark") {
        return;
      }
      applyTheme(getSystemTheme());
    });
  }
})();
