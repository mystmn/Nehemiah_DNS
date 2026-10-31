// SentinelDNS admin helpers (served from 'self' so the strict CSP stays intact).
(function () {
  "use strict";

  // Confirm dialogs for destructive buttons: <button data-confirm="...">
  document.addEventListener("click", function (event) {
    var button = event.target.closest("[data-confirm]");
    if (button && !window.confirm(button.getAttribute("data-confirm"))) {
      event.preventDefault();
    }
  });

  // Auto-fade success flashes after 4s.
  window.setTimeout(function () {
    document.querySelectorAll(".flash.success").forEach(function (el) {
      el.classList.add("fade");
    });
  }, 4000);
})();
