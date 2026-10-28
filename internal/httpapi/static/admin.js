(function () {
  var alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789-_.!@*=~";
  var all = document.querySelector("[data-select-all]");
  var boxes = Array.prototype.slice.call(document.querySelectorAll("[data-select]"));
  var count = document.querySelector("[data-batch-count]");
  var bar = document.querySelector("[data-batch]");
  var search = document.querySelector("[data-account-search]");
  var filter = document.querySelector("[data-account-filter]");
  var accountRows = Array.prototype.slice.call(document.querySelectorAll("[data-account-row]"));
  var noMatches = document.querySelector("[data-account-empty]");
  function visibleBoxes() {
    return boxes.filter(function (box) { var row = box.closest("[data-account-row]"); return !row || !row.hidden; });
  }
  function refresh() {
    var visible = visibleBoxes();
    var n = visible.filter(function (b) { return b.checked; }).length;
    if (count) { count.textContent = n + " selected"; }
    if (bar) { bar.classList.toggle("on", n > 0); }
    if (all) { all.checked = n > 0 && n === visible.length; all.indeterminate = n > 0 && n < visible.length; all.disabled = visible.length === 0; }
  }
  function filterAccounts() {
    var query = search ? search.value.trim().toLocaleLowerCase() : "";
    var mode = filter ? filter.value : "";
    var shown = 0;
    accountRows.forEach(function (row) {
      var text = (row.getAttribute("data-account-search-value") || "").toLocaleLowerCase();
      var modes = (row.getAttribute("data-account-filter-values") || "").split(" ");
      var matches = (!query || text.indexOf(query) !== -1) && (!mode || modes.indexOf(mode) !== -1);
      row.hidden = !matches;
      if (!matches) { var box = row.querySelector("[data-select]"); if (box) box.checked = false; }
      if (matches) shown++;
    });
    if (noMatches) noMatches.hidden = shown !== 0;
    refresh();
  }
  if (all) { all.addEventListener("change", function () { visibleBoxes().forEach(function (b) { b.checked = all.checked; }); refresh(); }); }
  boxes.forEach(function (b) { b.addEventListener("change", refresh); });
  if (search) { search.addEventListener("input", filterAccounts); }
  if (filter) { filter.addEventListener("change", filterAccounts); }
  filterAccounts();
  // Fleet permissions live in their own dialog inside the form. Ticking Fleet
  // opens it (unless the account is an Auth Admin, which defaults to Fleet
  // Admin with no prompt); the gear button beside Fleet reopens it and shows
  // the current choice, so closing the dialog never loses the way back.
  function isAuthAdmin(form) {
    var admin = form.querySelector('input[name="admin"]');
    return !!admin && (admin.type === "hidden" || admin.checked);
  }
  function fleetSummary(form) {
    var fa = form.querySelector('input[name="fleet_admin"]');
    if (fa && fa.checked) return "Fleet Admin";
    var chat = form.querySelector('input[name="fleet_chat_role"]:checked');
    var ops = form.querySelector('input[name="fleet_ops_role"]:checked');
    var chatLabel = chat && chat.value === "viewer" ? "Viewer" : "Contributor";
    var opsLabel = !ops || ops.value === "none" ? "None" : ops.value === "readonly" ? "Viewer" : "Contributor";
    return "Chat " + chatLabel + " \u00b7 Ops " + opsLabel;
  }
  document.querySelectorAll("form").forEach(function (form) {
    var toggle = form.querySelector('[data-fleet-toggle]');
    var dialog = form.querySelector('[data-fleet-permissions]');
    var edit = form.querySelector('[data-fleet-edit]');
    if (!toggle || !dialog) return;
    var summary = edit && edit.querySelector('[data-fleet-summary]');
    // Deferred: the Fleet Admin and role handlers below adjust the other
    // choices in the same change event, after this listener runs.
    function refreshSummary() { setTimeout(function () { if (summary) summary.textContent = fleetSummary(form); }, 0); }
    form.querySelectorAll('input[name="fleet_admin"], input[name="fleet_chat_role"], input[name="fleet_ops_role"]').forEach(function (input) {
      input.addEventListener("change", refreshSummary);
    });
    toggle.addEventListener("change", function () {
      if (edit) edit.hidden = !toggle.checked;
      if (toggle.checked && isAuthAdmin(form)) {
        // An Auth Admin defaults to Fleet Admin, including one who already
        // was an Auth Admin (or is locked in) and ticks Fleet afterwards.
        var fa = form.querySelector('input[name="fleet_admin"]');
        if (fa && !fa.checked) { fa.checked = true; fa.dispatchEvent(new Event("change", { bubbles: true })); }
      } else if (toggle.checked && dialog.showModal && !dialog.open) {
        dialog.showModal();
      }
      if (!toggle.checked && dialog.open) dialog.close();
    });
    // Rendered visible so the permissions stay reachable without script;
    // with script, it shows only while Fleet is ticked.
    if (edit) edit.hidden = !toggle.checked;
    refreshSummary();
  });
  document.querySelectorAll('input[name="admin"][type="checkbox"]').forEach(function (toggle) {
    toggle.addEventListener("change", function () {
      var form = toggle.closest("form");
      if (!form) return;
      form.querySelectorAll('input[name="apps"]').forEach(function (app) {
        if (["explorer", "fleet"].indexOf(app.value) === -1) return;
        app.checked = toggle.checked;
        app.dispatchEvent(new Event("change", { bubbles: true }));
      });
      var fleetAdmin = form.querySelector('input[name="fleet_admin"]');
      if (fleetAdmin) {
        fleetAdmin.checked = toggle.checked;
        fleetAdmin.dispatchEvent(new Event("change", { bubbles: true }));
      }
    });
  });
  document.querySelectorAll('input[name="fleet_admin"]').forEach(function (toggle) {
    toggle.addEventListener("change", function () {
      var form = toggle.closest("form");
      if (!form) return;
      var chat = form.querySelector('input[name="fleet_chat_role"][value="member"]');
      var ops = form.querySelector('input[name="fleet_ops_role"][value="' + (toggle.checked ? 'client' : 'none') + '"]');
      if (chat) chat.checked = true;
      if (ops) ops.checked = true;
    });
  });
  document.querySelectorAll('input[name="fleet_chat_role"], input[name="fleet_ops_role"]').forEach(function (choice) {
    choice.addEventListener("change", function () {
      if (!choice.checked) return;
      var form = choice.closest("form");
      if (!form) return;
      var fleetAdmin = form.querySelector('input[name="fleet_admin"]');
      if (fleetAdmin) fleetAdmin.checked = false;
    });
  });
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
  // Dialog buttons carry command/commandfor, which modern browsers act on
  // without script; older ones get the same behaviour here.
  if (!("command" in HTMLButtonElement.prototype)) {
    document.querySelectorAll("button[commandfor]").forEach(function (button) {
      button.addEventListener("click", function () {
        var dialog = document.getElementById(button.getAttribute("commandfor"));
        if (!dialog) return;
        var command = button.getAttribute("command");
        if (command === "show-modal" && !dialog.open) dialog.showModal();
        if (command === "close" && dialog.open) dialog.close();
      });
    });
  }
  // A click on the backdrop (outside the panel) closes it, as the popovers
  // these replaced did.
  // Both ends of the gesture must be outside: a press inside the panel (or
  // a text-selection drag) that is released over the backdrop stays open.
  document.querySelectorAll("dialog.modal").forEach(function (dialog) {
    function outside(event) {
      if (event.target !== dialog) return false;
      var r = dialog.getBoundingClientRect();
      return event.clientX < r.left || event.clientX > r.right || event.clientY < r.top || event.clientY > r.bottom;
    }
    var pressedOutside = false;
    dialog.addEventListener("pointerdown", function (event) { pressedOutside = outside(event); });
    dialog.addEventListener("click", function (event) {
      if (pressedOutside && outside(event)) dialog.close();
      pressedOutside = false;
    });
  });
  // A reopened dialog is rendered open (non-modal) so it shows without
  // script; here it becomes modal like any other.
  var reopen = document.body.getAttribute("data-reopen");
  if (reopen) {
    var dialog = document.getElementById(reopen);
    if (dialog && dialog.showModal) {
      if (dialog.open) dialog.close();
      try { dialog.showModal(); } catch (e) { dialog.show(); }
    }
  }
})();
