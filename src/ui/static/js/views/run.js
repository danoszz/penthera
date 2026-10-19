import { h, put, panel, clear, empty, diffBlock, announce, sevBadge, subwin, whatNext } from "../dom.js";
import { createTyper } from "../typer.js";
import { bars } from "../charts.js";
import { ago, duration, pct, shortProject } from "../format.js";
import { SCREENS, RUN_KINDS, NEXT, EMPTY } from "../copy.js";

const LOCAL = /^(localhost|127\.\d+\.\d+\.\d+|\[::1\]|[a-z0-9-]+\.localhost)$/i;

function hostOf(raw) {
  const v = String(raw || "").trim();
  if (!v) return null;
  try { return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(v) ? v : `http://${v}`).hostname; } catch { return null; }
}

export async function render(root, { api, params, meta, go }) {
  const [{ live, past }, mem] = await Promise.all([api.get("/api/runs"), api.get("/api/memory")]);
  const projects = meta.projects || [];
  const startKind = RUN_KINDS.some((k) => k.kind === params.get("kind")) ? params.get("kind") : "scan";

  // ── Form ──
  const radios = RUN_KINDS.map((k) => h("input", { type: "radio", name: "r-kind", value: k.kind, checked: k.kind === startKind }));
  const kindOf = () => radios.find((r) => r.checked)?.value || "scan";
  const repo = h("input", { type: "text", id: "r-repo", list: "r-projects", autocomplete: "off", spellcheck: "false", value: params.get("repo") || projects[0] || "", placeholder: "/path/to/project" });
  const url = h("input", { type: "text", id: "r-url", autocomplete: "off", spellcheck: "false", value: params.get("url") || "", placeholder: "http://localhost:3000" });
  const confirm = h("input", { type: "text", id: "r-confirm", autocomplete: "off", spellcheck: "false" });
  const confirmHint = h("span", { class: "hint" });
  const confirmWrap = h("label", { class: "field c12", for: "r-confirm", hidden: true }, h("span", {}, "Confirm the target"), confirm, confirmHint);
  const iters = h("input", { type: "number", id: "r-iter", min: "1", max: "50", value: "5" });
  const tests = h("input", { type: "checkbox", id: "r-tests" });
  const urlWrap = h("label", { class: "field c4", for: "r-url" }, h("span", {}, "Running app URL ", h("span", { class: "hint" }, "(optional)")), url);
  const iterWrap = h("label", { class: "field c2", for: "r-iter" }, h("span", {}, "Max rounds"), iters);
  const testsWrap = h("label", { class: "check", for: "r-tests" }, tests, "also run the project's tests to verify");
  const note = h("span", { class: "muted" });
  const start = h("button", { type: "submit", class: "btn primary" });
  const formErr = h("p", { class: "error", role: "alert", hidden: true });

  const NOTES = {
    scan: "Contacts only the URL's host (and nothing at all for a folder-only scan) while offline is on in Settings.",
    deps: "Reads package-lock.json and node_modules. No network.",
    agents: "Reads skills, MCP config, hooks and rule files. Read-only, no network.",
    loop: "Always offline :: works on a local branch :: every diff waits for you :: never pushes.",
  };
  const sync = () => {
    const k = kindOf();
    const def = RUN_KINDS.find((x) => x.kind === k);
    urlWrap.hidden = k === "deps" || k === "agents";
    iterWrap.hidden = k !== "loop";
    testsWrap.hidden = k !== "loop";
    note.textContent = NOTES[k];
    start.textContent = `${def.button} ▸`;
    const host = urlWrap.hidden ? null : hostOf(url.value);
    const remote = host && !LOCAL.test(host);
    confirmWrap.hidden = !remote;
    if (remote) {
      confirm.placeholder = host;
      confirmHint.textContent = `${host} is not on this machine. Type its name to confirm you own it or have written permission to test it.`;
    }
  };
  url.addEventListener("input", sync);
  for (const r of radios) r.addEventListener("change", sync);

  const form = h("form", { class: "form-grid", novalidate: true },
    h("div", { class: "c12" }, h("div", { class: "seg", role: "radiogroup", "aria-label": "What to run" },
      RUN_KINDS.map((k, i) => h("label", {}, radios[i], h("span", {}, k.label))),
    )),
    h("label", { class: "field c6", for: "r-repo" }, h("span", {}, "Project folder"), repo, h("datalist", { id: "r-projects" }, projects.map((p) => h("option", { value: p })))),
    urlWrap,
    iterWrap,
    confirmWrap,
    h("div", { class: "c12 filters" }, testsWrap, note),
    h("div", { class: "c12" }, start, formErr),
  );

  // ── Terminal ──
  const term = h("div", { class: "term", role: "log", "aria-live": "off", "aria-label": "Run output", tabindex: "0" });
  const statusChip = h("span", { class: "chip" }, "idle");
  const stopBtn = h("button", { type: "button", class: "btn", disabled: true }, "Stop");
  const approvalSlot = h("div");
  const nextSlot = h("div");
  const timeline = h("ol", { class: "timeline", "aria-label": "Rounds" });
  const runInfo = h("div", { class: "muted" }, "tty :: idle");
  const ttyTitle = h("span", { class: "title" }, "penthera :: tty");

  const termWin = subwin("Terminal", { class: "span-8" },
    h("div", { class: "term-head" }, runInfo, h("div", { class: "filters" }, statusChip, stopBtn)),
    term,
    approvalSlot,
  );
  termWin.querySelector(".titlebar .title").replaceWith(ttyTitle);

  put(root, 
    h("h1", {}, SCREENS.run.title),
    h("p", { class: "lede" }, SCREENS.run.lede),
    h("div", { class: "grid" },
      panel("What to run", { class: "span-12" }, form),
      termWin,
      h("div", { class: "span-4 grid" },
        panel("Rounds", { class: "span-12" }, timeline),
        panel("Memory", { class: "span-12" }, memoryPanel(mem.projects)),
      ),
      h("div", { class: "span-12" }, nextSlot),
      panel("Past loop runs", { class: "span-12" }, pastRuns(past)),
    ),
  );

  let typer = createTyper(term);
  let es = null;
  let run = null;
  let pending = null;
  const its = new Map();

  timeline.append(h("li", {}, h("span", { class: "muted" }, "Rounds appear here when the fix loop runs.")));
  typer.push("Ready. Pick what to run, check the folder, and press the button.", "dim");
  typer.push("The fix loop stops at every diff :: [y] approve  [n] skip  [q] stop.", "dim");

  function setStatus(st) {
    statusChip.textContent = st;
    statusChip.className = `chip ${st === "running" ? "on" : st === "awaiting you" ? "blue" : st === "error" ? "inv" : ""}`;
    stopBtn.disabled = !(st === "running" || st === "awaiting you");
  }

  function itemFor(n, of) {
    if (!its.has(n)) {
      const fixes = h("ul", { class: "fixes" });
      const head = h("div", { class: "t1" }, `Round ${n}`, of ? h("span", { class: "muted" }, ` of ${of}`) : null);
      const sub = h("div", { class: "muted" }, "scanning…");
      const li = h("li", {}, head, sub, fixes);
      timeline.append(li);
      its.set(n, { li, sub, fixes, current: null });
    }
    return its.get(n);
  }
  let lastIt = null;
  const mark = (li, txt, cls) => { li.firstChild.textContent = txt; li.firstChild.className = cls; };

  function onEvent(ev) {
    const d = ev.data;
    switch (ev.type) {
      case "log": {
        const t = d.text.replace(/^\n/, "");
        const cls = /^penthera /.test(t) ? "cmd" : /verified and committed|done:|^(scan|deps|agents) done/.test(t) ? "ok"
          : /failed verification|^error|not applied/.test(t) ? "bad" : /^\s*iteration \d+/.test(t) ? "hl" : /^\s{3,}/.test(t) || /\.\.\.$/.test(t) ? "dim" : null;
        typer.push(cls === "dim" || cls === "bad" ? t.trim() : t, cls);
        break;
      }
      case "iteration": lastIt = itemFor(d.n, d.of); break;
      case "scanned": if (lastIt) lastIt.sub.textContent = `${d.findings} findings :: ${d.fixable} fixable :: ${d.suppressed} suppressed`; break;
      case "approval": {
        pending = d;
        const it = itemFor(d.iteration);
        const li = h("li", {}, h("span", { class: "blue" }, "??"), h("span", { class: "t" }, d.plan.title));
        it.fixes.append(li);
        it.current = li;
        showApproval(d);
        setStatus("awaiting you");
        announce(`Diff ${d.index} of ${d.total} is waiting for you: ${d.plan.title}`);
        break;
      }
      case "decision": {
        pending = null;
        clear(approvalSlot);
        const it = lastIt || itemFor(1);
        const m = { y: ["..", "muted"], n: ["--", "muted"], skip: ["~~", "muted"], quit: ["xx", "bad"] }[d.answer] || ["..", "muted"];
        if (it.current) mark(it.current, ...m);
        if (d.answer !== "y") it.current = null;
        setStatus("running");
        break;
      }
      case "fix": {
        if (lastIt?.current) {
          const [txt, cls] = d.status === "verified" ? ["OK", "ok"] : d.status === "failed" ? ["!!", "bad"] : ["--", "muted"];
          mark(lastIt.current, txt, cls);
          lastIt.current = null;
        }
        break;
      }
      case "status": {
        if (d.status === "running") { setStatus("running"); break; }
        setStatus(d.status);
        clear(approvalSlot);
        start.disabled = false;
        const sum = d.summary;
        if (sum?.totals) {
          const t = sum.totals;
          typer.push(`done: ${sum.stopReason} after ${t.iterations} round${t.iterations === 1 ? "" : "s"} (${duration(sum.durationMs)})`, "ok");
          typer.push(`${t.verified} verified and committed :: ${t.failed} failed and reverted :: ${t.declined} skipped`, t.failed ? "bad" : "ok");
          for (const it of its.values()) if (it.sub.textContent === "scanning…") it.sub.textContent = "nothing left to fix";
        }
        if (d.status === "done" || d.status === "stopped") {
          clear(nextSlot).append(whatNext(NEXT[run.kind] || NEXT.scan, go));
        }
        announce(`Run ${d.status}`);
        break;
      }
      default: break;
    }
  }

  function showApproval(d) {
    typer.flush();
    const p = d.plan;
    const decide = async (answer) => {
      for (const b of approvalSlot.querySelectorAll("button")) b.disabled = true;
      try {
        await api.post(`/api/runs/${run.id}/decision`, { approvalId: d.approvalId, answer });
      } catch (e) {
        typer.push(`error: ${e.message}`, "bad");
        for (const b of approvalSlot.querySelectorAll("button")) b.disabled = false;
      }
    };
    const approve = h("button", { type: "button", class: "btn primary", onclick: () => decide("approve") }, "Apply this fix", h("span", { class: "k" }, "y"));
    clear(approvalSlot).append(h("section", { class: "alert", role: "alertdialog", "aria-labelledby": "ap-h", "aria-describedby": "ap-d" },
      h("div", { class: "icon", "aria-hidden": "true" }, "?"),
      h("h3", { id: "ap-h" }, `Apply fix ${d.index} of ${d.total}?`),
      h("p", { id: "ap-d", class: "t1" }, p.title),
      h("p", { class: "muted" }, d.memory ? `Memory :: this recipe verified ${d.memory.verified} times, failed ${d.memory.failed} on this stack.` : "Memory :: no history for this recipe yet."),
      h("div", { class: "body" },
        h("dl", { class: "kv" },
          h("dt", {}, "recipe"), h("dd", {}, `${p.recipe}${p.framework ? ` (${p.framework})` : ""} :: confidence ${p.confidence}`),
          h("dt", {}, "files"), h("dd", {}, p.files.join(", ")),
          h("dt", {}, "fixes"), h("dd", {}, p.findings.map((f) => h("div", {}, sevBadge(f.severity), " ", f.title))),
        ),
        diffBlock(p.diff),
        p.redacted ? h("p", { class: "muted" }, "Secret values are masked here; the real patch uses them.") : null,
      ),
      h("div", { class: "actions" },
        h("button", { type: "button", class: "btn", onclick: () => decide("stop") }, "Stop the loop", h("span", { class: "k" }, "q")),
        h("button", { type: "button", class: "btn", onclick: () => decide("skip") }, "Skip", h("span", { class: "k" }, "n")),
        approve,
      ),
    ));
    approve.focus({ preventScroll: true });
    approvalSlot.scrollIntoView({ block: "nearest" });
  }

  function attach(r) {
    run = r;
    const what = RUN_KINDS.find((k) => k.kind === r.kind)?.label.toLowerCase() || r.kind;
    runInfo.textContent = `${what} :: ${r.repo ? shortProject(r.repo) : ""}${r.url ? ` + ${r.url}` : ""} :: started ${ago(r.startedAt)}`;
    ttyTitle.textContent = `penthera :: tty :: ${what}`;
    es?.close();
    es = new EventSource(`/api/runs/${r.id}/stream`);
    for (const type of ["log", "iteration", "scanned", "approval", "decision", "fix", "status"]) {
      es.addEventListener(type, (m) => { try { onEvent(JSON.parse(m.data)); } catch { /* malformed event */ } });
    }
    es.addEventListener("end", () => { es.close(); es = null; });
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    formErr.hidden = true;
    start.disabled = true;
    const kind = kindOf();
    try {
      const r = await api.post("/api/runs", {
        kind, repo: repo.value, url: urlWrap.hidden ? "" : url.value, confirm: confirm.value,
        maxIterations: Number(iters.value), runTests: kind === "loop" && tests.checked,
      });
      typer.stop();
      clear(term);
      clear(timeline);
      clear(nextSlot);
      its.clear();
      lastIt = null;
      typer = createTyper(term);
      attach(r);
    } catch (err) {
      formErr.textContent = err.message;
      formErr.hidden = false;
      start.disabled = false;
      if (err.status === 428) confirm.focus();
    }
  });

  stopBtn.addEventListener("click", async () => {
    if (!run) return;
    stopBtn.disabled = true;
    try { await api.post(`/api/runs/${run.id}/stop`); } catch (e) { typer.push(`error: ${e.message}`, "bad"); }
  });

  const onKey = (e) => {
    if (!pending || e.metaKey || e.ctrlKey || e.altKey) return;
    if (/^(INPUT|SELECT|TEXTAREA)$/.test(document.activeElement?.tagName || "")) return;
    const btns = approvalSlot.querySelectorAll(".actions button");
    const map = { q: 0, n: 1, y: 2 };
    if (e.key in map && btns[map[e.key]] && !btns[map[e.key]].disabled) { e.preventDefault(); btns[map[e.key]].click(); }
  };
  document.addEventListener("keydown", onKey);

  // Re-attach to a run that is still going (navigated away and back).
  const running = live.find((r) => r.status === "running");
  if (running) {
    start.disabled = true;
    typer.stop();
    clear(term);
    typer = createTyper(term);
    attach(running);
  }
  sync();

  return () => {
    es?.close();
    typer.stop();
    document.removeEventListener("keydown", onKey);
  };
}

function memoryPanel(projects) {
  if (!projects.length) return empty(EMPTY.memory);
  const recipes = new Map();
  for (const p of projects) for (const r of p.recipes) {
    const cur = recipes.get(r.recipe) || { verified: 0, failed: 0 };
    cur.verified += r.verified;
    cur.failed += r.failed;
    recipes.set(r.recipe, cur);
  }
  const events = projects.reduce((n, p) => n + p.events, 0);
  const verified = projects.reduce((n, p) => n + p.verifiedFixes, 0);
  const failed = projects.reduce((n, p) => n + p.failedFixes, 0);
  const broken = projects.filter((p) => p.chain !== "ok");
  return h("div", {},
    h("dl", { class: "kv" },
      h("dt", {}, "projects"), h("dd", {}, String(projects.length)),
      h("dt", {}, "events"), h("dd", {}, String(events)),
      h("dt", {}, "chain"), h("dd", { class: broken.length ? "bad" : "ok" }, broken.length ? `${broken.length} broken :: ignored there` : "[OK] sha-256 hash chain"),
      h("dt", {}, "fixes"), h("dd", {}, h("span", { class: "ok" }, `${verified} verified`), ` :: ${failed} failed`),
    ),
    h("p", { class: "label" }, "Recipe success"),
    bars([...recipes].map(([recipe, r]) => ({ label: recipe, value: r.verified })), { width: 10 }),
    h("p", { class: "panel-note" }, [...recipes].map(([recipe, r]) => `${recipe} ${pct(r.verified / Math.max(1, r.verified + r.failed))}`).join(" :: ")),
  );
}

function pastRuns(past) {
  if (!past.length) return empty(EMPTY.pastRuns);
  return h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, ...["When", "Project", "Findings", "Verified", "Reverted", "Skipped", "Stopped because", "Branch"].map((t, i) => h("th", { class: [i >= 3 && i <= 5 ? "num" : null, i === 7 ? "hide-narrow" : null] }, t)))),
    h("tbody", {}, past.map((l) => h("tr", {},
      h("td", { class: "muted" }, ago(l.startedAt)),
      h("td", { class: "trunc t1", title: l.target.repo || "" }, shortProject(l.target.repo)),
      h("td", { class: "t1" }, `${l.findings.initial ?? "?"} → ${l.findings.final ?? "?"}`),
      h("td", { class: "num ok" }, String(l.totals.verified)),
      h("td", { class: ["num", l.totals.failed ? "bad" : "muted"] }, String(l.totals.failed)),
      h("td", { class: "num muted" }, String(l.totals.declined + l.totals.skipped)),
      h("td", { class: "muted" }, l.stopReason || "-"),
      h("td", { class: "muted hide-narrow" }, l.branch || "-"),
    ))),
  ));
}
