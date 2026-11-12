// Approve, reject and kill switch buttons. The admin token is typed by the operator, kept in
// sessionStorage for this tab and sent only as an Authorization header. All output uses textContent.
(function () {
  "use strict";
  var input = document.getElementById("admin-token");
  var out = document.getElementById("admin-result");

  function token() {
    try {
      if (input && input.value) { sessionStorage.setItem("kubeheal-admin-token", input.value); }
      return (input && input.value) || sessionStorage.getItem("kubeheal-admin-token") || "";
    } catch (e) { return (input && input.value) || ""; }
  }

  function say(text) { if (out) { out.textContent = text; } }

  function call(path, body) {
    var t = token();
    if (!t) { say("Enter the admin token first."); return; }
    say("Working...");
    fetch(path, {
      method: "POST",
      headers: { "Authorization": "Bearer " + t, "Content-Type": "application/json" },
      body: JSON.stringify(body || {})
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) { return { ok: r.ok, status: r.status, body: j }; });
    }).then(function (res) {
      if (res.ok) {
        say(typeof res.body.message === "string" ? res.body.message : "Done: " + (res.body.status || "ok"));
        // A dry run changed nothing: keep the message on screen instead of reloading.
        if (res.body.status !== "dry_run") { setTimeout(function () { window.location.reload(); }, 600); }
      } else {
        say("Failed (" + res.status + "): " + (typeof res.body.detail === "string" ? res.body.detail : "see server log"));
      }
    }).catch(function () { say("Request failed."); });
  }

  document.addEventListener("click", function (ev) {
    var b = ev.target.closest("button[data-action]");
    if (!b) { return; }
    var action = b.getAttribute("data-action");
    if (action === "mode") {
      call("/api/kill-switch", { mode: b.getAttribute("data-mode") });
    } else if (action === "baseline-approve" || action === "baseline-reject") {
      var reason = document.getElementById("baseline-reason");
      call("/api/baseline-candidates/" + encodeURIComponent(b.getAttribute("data-namespace")) + "/" +
           encodeURIComponent(b.getAttribute("data-deployment")) + "/" + action.replace("baseline-", ""),
           { candidate_id: b.getAttribute("data-candidate"), reason: reason ? reason.value : "" });
    } else if (action === "approve" || action === "reject") {
      call("/api/approvals/" + encodeURIComponent(b.getAttribute("data-incident")) + "/" + action, {});
    } else if (action === "snapshot-freeze-release") {
      var reason = document.getElementById("snapshot-freeze-reason");
      var force = document.getElementById("snapshot-freeze-force");
      call("/api/incidents/" + encodeURIComponent(b.getAttribute("data-incident")) + "/release-snapshot-freeze",
           { reason: reason ? reason.value : "", force: !!(force && force.checked) });
    }
  });
})();
