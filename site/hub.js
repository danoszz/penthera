/*
 * The hub's motion. Every chip is an ordinary link to a real page, so nothing
 * here is needed to read the site. On arrival this script filters by ?kind= or
 * ?status=, turns the old title into the new one block by block, and names the
 * rows so the browser's view transition can carry them across. No dependencies,
 * tracking or fetches; only the last word is kept, for this tab.
 */
/* global document, history, location, matchMedia, requestAnimationFrame, window */
(function () {
  "use strict";

  var COLS = 23, ROWS = 7, HOLD = 420, KEY = "penthera-hub-word";
  var done = false;
  var still = matchMedia("(prefers-reduced-motion: reduce)").matches;

  function read() { try { return sessionStorage.getItem(KEY); } catch (e) { return null; } }
  function write(w) { try { sessionStorage.setItem(KEY, w); } catch (e) { /* storage blocked */ } }

  function filter() {
    var q = new URLSearchParams(location.search);
    var kind = q.get("kind"), status = q.get("status"), type = q.get("type"), text = (q.get("q") || "").toLowerCase();
    var rows = Array.prototype.slice.call(document.querySelectorAll(".hub-row"));
    var shown = 0;
    rows.forEach(function (r) {
      var on = (!kind || r.dataset.kind === kind) && (!status || r.dataset.status === status) && (!type || r.dataset.type === type) && (!text || r.textContent.toLowerCase().indexOf(text) >= 0);
      r.hidden = !on;
      if (on) shown += 1;
    });
    var none = document.querySelector(".hub-none");
    if (none) none.hidden = shown > 0;
    var chip = kind && document.querySelector('.hub-chip[data-kind="' + kind + '"]');
    if (chip) {
      document.querySelectorAll(".hub-chip[aria-current]").forEach(function (c) { c.removeAttribute("aria-current"); });
      chip.setAttribute("aria-current", "page");
      document.documentElement.dataset.view = chip.dataset.view;
      document.querySelector("h1 .sr").textContent = chip.dataset.h1;
      document.title = chip.dataset.h1 + " · Penthera";
      document.querySelector(".ttx-title").dataset.word = chip.dataset.word;
    }
    var link = status && document.querySelector('.hub-status [data-status="' + status + '"]');
    if (link) link.setAttribute("aria-current", "true");
  }

  // The search filters as you type, and keeps the query in the address.
  function search() {
    var box = document.getElementById("hub-q");
    if (!box) return;
    box.value = new URLSearchParams(location.search).get("q") || "";
    box.addEventListener("input", function () {
      var q = new URLSearchParams(location.search);
      if (box.value) q.set("q", box.value);
      else q.delete("q");
      var rest = q.toString();
      history.replaceState(null, "", location.pathname + (rest ? "?" + rest : ""));
      filter();
    });
  }

  function title() {
    var svg = document.querySelector(".ttx-title");
    if (!svg) return;
    var glyphs = JSON.parse(svg.dataset.glyphs);
    var cells = Array.prototype.slice.call(svg.querySelectorAll("rect"));
    var lit = function (word, c) {
      var col = c.x.baseVal.value, row = c.y.baseVal.value;
      return col % 6 !== 5 && glyphs[word[Math.floor(col / 6)]].split(" ")[row][col % 6] === "1";
    };
    var word = svg.dataset.word, from = read();
    write(word);
    cells.forEach(function (c) { c.classList.toggle("on", lit(still || !from ? word : from, c)); });
    if (!still && from && from !== word) {
      svg.classList.add("hub-settled");
      cells.forEach(function (c) {
        if (lit(word, c) !== lit(from, c)) setTimeout(function () { c.classList.toggle("on", lit(word, c)); }, 60 + Math.random() * 340);
      });
    }

    // The pointer inverts what it crosses.
    var hit = new Map(), running = false;
    function fade(now) {
      hit.forEach(function (until, c) {
        if (now < until) return;
        c.classList.remove("x");
        hit.delete(c);
      });
      if (hit.size) requestAnimationFrame(fade);
      else running = false;
    }
    if (!still) svg.addEventListener("pointermove", function (e) {
      var box = svg.getBoundingClientRect(), x = (e.clientX - box.left) / box.width * COLS, y = (e.clientY - box.top) / box.height * ROWS, now = performance.now();
      cells.forEach(function (c) {
        var dx = c.x.baseVal.value + 0.5 - x, dy = c.y.baseVal.value + 0.5 - y;
        if (dx * dx + dy * dy > 2.4) return;
        c.classList.add("x");
        hit.set(c, now + HOLD);
      });
      if (!running) { running = true; requestAnimationFrame(fade); }
    });
  }

  function name() {
    document.querySelectorAll(".hub-row:not([hidden])").forEach(function (r, i) {
      if (i < 24) r.style.viewTransitionName = r.dataset.id;
    });
  }

  function arrive() {
    if (done) return;
    done = true;
    filter();
    search();
    title();
    name();
  }

  // pagereveal runs before the first paint where view transitions exist.
  window.addEventListener("pagereveal", arrive);
  document.addEventListener("DOMContentLoaded", arrive);
})();
