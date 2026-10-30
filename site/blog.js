/*
 * /blog: the mosaic title plays. The pointer inverts the blocks under it, and
 * Reveal, as on a teletext remote, shows the word hidden in the same grid.
 *
 * The title is whole in the HTML and the h1 carries its text, so a reader
 * without JavaScript loses nothing. No dependencies, tracking or storage.
 */
/* global document, matchMedia, requestAnimationFrame */
(function () {
  "use strict";

  var COLS = 23, ROWS = 7, HOLD = 420;

  function init() {
    var svg = document.querySelector(".ttx-title");
    var key = document.querySelector(".ttx-reveal");
    var note = document.querySelector(".ttx-note");
    if (!svg || !key) return;
    var cells = Array.prototype.slice.call(svg.querySelectorAll("rect"));
    var still = matchMedia("(prefers-reduced-motion: reduce)").matches;
    var hidden = false, hit = new Map(), running = false;

    function reveal() {
      hidden = !hidden;
      key.setAttribute("aria-pressed", hidden ? "true" : "false");
      note.textContent = hidden ? "The title now reads DATA." : "The title reads BLOG again.";
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

    key.hidden = false;
    key.addEventListener("click", reveal);
    svg.addEventListener("click", reveal);
    if (!still) svg.addEventListener("pointermove", punch);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
