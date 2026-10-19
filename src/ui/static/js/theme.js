// Set the theme before first paint: the saved choice, else the OS preference.
// A classic script (not a module) so it runs before the stylesheet applies.
(function () {
  var t = null;
  try { t = localStorage.getItem("penthera-ui-theme"); } catch (e) { /* storage off */ }
  if (t !== "light" && t !== "dark") {
    t = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }
  document.documentElement.setAttribute("data-theme", t);
})();
