/*
 * Theme, set before paint. One system: [data-theme] on <html>. The first visit
 * follows prefers-color-scheme; the toggle stores a choice in localStorage
 * (never a cookie). Loaded as a classic script in <head>, so it blocks paint.
 */
(function () {
  var KEY = "penthera-site-theme";
  var root = document.documentElement;
  root.classList.add("js");
  var stored = null;
  try { stored = localStorage.getItem(KEY); } catch (e) { /* storage blocked */ }
  var system = window.matchMedia && matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  // The blog is printed on paper (data-paper): always light, with no switch.
  var paper = root.hasAttribute("data-paper");
  if (!paper) root.setAttribute("data-theme", stored === "light" || stored === "dark" ? stored : system);

  // Switches labelled "Dark theme" (one in the bar, one in the footer): on is
  // dark, off is light. They all show the same state.
  function sync(btns) {
    var dark = root.getAttribute("data-theme") === "dark";
    for (var i = 0; i < btns.length; i++) btns[i].setAttribute("aria-checked", dark ? "true" : "false");
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta && !paper) meta.setAttribute("content", dark ? "#000000" : "#fdfdfa");
  }

  document.addEventListener("DOMContentLoaded", function () {
    var btns = paper ? [] : document.querySelectorAll("[data-theme-toggle]");
    for (var i = 0; i < btns.length; i++) {
      btns[i].hidden = false;
      btns[i].addEventListener("click", function () {
        var next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
        root.setAttribute("data-theme", next);
        try { localStorage.setItem(KEY, next); } catch (e) { /* storage blocked */ }
        sync(btns);
      });
    }
    sync(btns);

    // The footer's LED breathes only while it is on screen (styles.css).
    var led = document.querySelector(".foot-led");
    if (led && "IntersectionObserver" in window) {
      new IntersectionObserver(function (entries) {
        if (entries[0].isIntersecting) led.removeAttribute("data-rest");
        else led.setAttribute("data-rest", "");
      }).observe(led);
    }
  });
})();
