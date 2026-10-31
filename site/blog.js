/*
 * /blog: the mosaic title plays. The pointer inverts the blocks under it, and a
 * click shows the word hidden in the same grid. On a post, the contents in the
 * margin follow the section being read.
 *
 * It is a toy, not a control: the title is whole in the HTML and the h1 carries
 * its text, so a reader without a pointer or JavaScript loses nothing. No
 * dependencies, tracking or storage.
 */
/* global document, innerHeight, matchMedia, requestAnimationFrame, window */
(function () {
  "use strict";

  var COLS = 23, ROWS = 7, HOLD = 420;

  function title() {
    var svg = document.querySelector(".ttx-title");
    if (!svg) return;
    var cells = Array.prototype.slice.call(svg.querySelectorAll("rect"));
    var still = matchMedia("(prefers-reduced-motion: reduce)").matches;
    var hidden = false, hit = new Map(), running = false;

    function reveal() {
      hidden = !hidden;
      var word = hidden ? "d" : "b";
      cells.forEach(function (c) {
        var want = c.classList.contains(word);
        if (still) c.classList.toggle("on", want);
        else setTimeout(function () { c.classList.toggle("on", want); }, Math.random() * 320);
      });
    }

    function fade(now) {
      hit.forEach(function (until, c) {
        if (now < until) return;
        c.classList.remove("x");
        hit.delete(c);
      });
      if (hit.size) requestAnimationFrame(fade);
      else running = false;
    }

    function punch(e) {
      var box = svg.getBoundingClientRect();
      var x = (e.clientX - box.left) / box.width * COLS;
      var y = (e.clientY - box.top) / box.height * ROWS;
      var now = performance.now();
      cells.forEach(function (c) {
        var dx = c.x.baseVal.value + 0.5 - x, dy = c.y.baseVal.value + 0.5 - y;
        if (dx * dx + dy * dy > 2.4) return;
        c.classList.add("x");
        hit.set(c, now + HOLD);
      });
      if (!running) { running = true; requestAnimationFrame(fade); }
    }

    svg.addEventListener("click", reveal);
    if (!still) svg.addEventListener("pointermove", punch);
  }

  // The margin's contents show which section is being read.
  function contents() {
    var links = Array.prototype.slice.call(document.querySelectorAll(".paper-toc a"));
    if (!links.length) return;
    var heads = links.map(function (a) { return document.getElementById(a.getAttribute("href").slice(1)); });
    function mark() {
      var at = -1;
      heads.forEach(function (h, i) { if (h.getBoundingClientRect().top < innerHeight * 0.35) at = i; });
      links.forEach(function (a, i) {
        if (i === at) a.setAttribute("aria-current", "true");
        else a.removeAttribute("aria-current");
      });
    }
    // On scroll, not an observer: a fast jump can pass a head without crossing anything.
    var queued = false;
    window.addEventListener("scroll", function () {
      if (queued) return;
      queued = true;
      requestAnimationFrame(function () { queued = false; mark(); });
    }, { passive: true });
    mark();
  }

  function init() {
    title();
    contents();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
