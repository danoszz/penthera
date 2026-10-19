// "Hacker typer" output: lines arrive whole from the server and are typed out
// a few characters per frame. The speed scales with the backlog, so the
// screen never falls more than a moment behind the real run. With
// prefers-reduced-motion, lines appear at once.
//
// Screen readers: each line holds its full text in a visually hidden span;
// the typed copy is aria-hidden, so nothing is read out letter by letter.
import { h, prefersReducedMotion } from "./dom.js";

export function createTyper(container) {
  const cursor = h("span", { class: "cursor", "aria-hidden": "true" });
  const queue = [];
  let current = null;
  let raf = 0;
  let stopped = false;

  function backlog() {
    return queue.reduce((n, q) => n + q.text.length, current ? current.text.length - current.pos : 0);
  }

  function nearBottom() {
    return container.scrollHeight - container.scrollTop - container.clientHeight < 60;
  }

  function startLine(item) {
    const typed = h("span", { "aria-hidden": "true" });
    const line = h("div", { class: ["ln", item.cls] }, h("span", { class: "sr" }, item.text), typed);
    container.append(line);
    line.append(cursor);
    return { ...item, typed, pos: 0 };
  }

  function tick() {
    raf = 0;
    if (stopped) return;
    const stick = nearBottom();
    let budget = 3 + Math.floor(backlog() / 30);
    while (budget > 0 && (current || queue.length)) {
      if (!current) current = startLine(queue.shift());
      const take = Math.min(budget, current.text.length - current.pos);
      current.pos += take;
      budget -= take;
      current.typed.textContent = current.text.slice(0, current.pos);
      if (current.pos >= current.text.length) current = null;
      if (budget <= 0) break;
      budget--; // a line break costs a character
    }
    if (stick) container.scrollTop = container.scrollHeight;
    if (current || queue.length) raf = requestAnimationFrame(tick);
  }

  return {
    /** Add a line. cls: cmd | dim | ok | bad | hl */
    push(text, cls = null) {
      const item = { text: String(text), cls };
      if (prefersReducedMotion()) {
        const stick = nearBottom();
        const typed = h("span", { "aria-hidden": "true" }, item.text);
        const line = h("div", { class: ["ln", cls] }, h("span", { class: "sr" }, item.text), typed);
        container.append(line);
        line.append(cursor);
        if (stick) container.scrollTop = container.scrollHeight;
        return;
      }
      queue.push(item);
      if (!raf) raf = requestAnimationFrame(tick);
    },
    /** Finish typing everything now (e.g. before showing an approval). */
    flush() {
      while (current || queue.length) {
        if (!current) current = startLine(queue.shift());
        current.typed.textContent = current.text;
        current = null;
      }
      container.scrollTop = container.scrollHeight;
    },
    idle: () => !current && !queue.length,
    stop() {
      stopped = true;
      if (raf) cancelAnimationFrame(raf);
    },
  };
}

/** Type a short string into an element once (the header prompt). */
const typing = new WeakMap(); // element -> timer, so a new line cancels the one still typing

export function typeInto(el, text, { cps = 40 } = {}) {
  clearTimeout(typing.get(el));
  if (prefersReducedMotion()) { el.textContent = text; return; }
  let i = 0;
  const step = () => {
    i++;
    el.textContent = text.slice(0, i);
    if (i < text.length) typing.set(el, setTimeout(step, 1000 / cps));
  };
  el.textContent = "";
  step();
}
