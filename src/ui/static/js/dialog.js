// Floating windows: the New scan dialog and About. A native <dialog> opened
// with showModal(), so focus is trapped, Esc closes it and the page behind is
// inert. Focus returns to whatever opened it.
import { h, announce, clear } from "./dom.js";
import { api } from "./api.js";
import { state, set, folderFor, liveRun, simple } from "./state.js";
import { keyParts, shortProject } from "./format.js";
import { KINDS, NOTES, ABOUT, SIMPLE_KINDS, AI, aiLines, AI_TEXT_VERSION, AI_CLOUD_HOST } from "./copy.js";

const LOCAL = /^(localhost|127\.\d+\.\d+\.\d+|\[::1\]|[a-z0-9-]+\.localhost)$/i;

function hostOf(raw) {
  const v = String(raw || "").trim();
  if (!v) return null;
  try { return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(v) ? v : `http://${v}`).hostname; } catch { return null; }
}

/** Open a modal window. Returns { el, close }. */
export function openWindow({ title, label, body, wide = false, striped = false }) {
  const opener = document.activeElement;
  const dlg = h("dialog", { class: ["window", wide ? "wide" : null], "aria-label": label || title });
  const close = () => { if (dlg.open) dlg.close(); };
  dlg.append(
    h("div", { class: ["win-bar", striped ? "striped" : null] },
      h("button", { type: "button", class: "icon close-box", "aria-label": "Close (Esc)", title: "Close  Esc", onclick: close }),
      h("span", { class: "title" }, title)),
    h("div", { class: "window-body" }, body),
  );
  dlg.addEventListener("close", () => {
    dlg.remove();
    if (opener instanceof HTMLElement && opener.isConnected) opener.focus({ preventScroll: true });
  });
  // A click on the backdrop (the dialog element itself, outside its box) closes it.
  dlg.addEventListener("click", (e) => {
    if (e.target !== dlg) return;
    const r = dlg.getBoundingClientRect();
    if (e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom) close();
  });
  document.body.append(dlg);
  dlg.showModal();
  return { el: dlg, close };
}

/**
 * New scan: what to run, on which folder, against which URL. The hostname of
 * a URL that is not on this machine must be typed back before the run starts.
 */
export function newScan(ctx, { kind = "scan", project = null } = {}) {
  const selected = project ?? (state.sel.kind === "project" ? state.sel.key : null);
  const folders = state.meta?.projects || [];
  const busy = liveRun();

  const easy = simple();
  const kinds = easy ? SIMPLE_KINDS : KINDS.map((k) => ({ ...k, body: NOTES[k.kind] }));
  if (!kinds.some((k) => k.kind === kind)) kind = kinds[0].kind;
  const radios = kinds.map((k) => {
    const input = h("input", { type: "radio", name: "kind", value: k.kind, checked: k.kind === kind });
    return h("label", { class: "choice" }, input,
      h("span", {}, h("span", { class: "t1" }, k.title), h("span", { class: "note prose" }, k.body)));
  });
  const kindNow = () => radios.map((r) => r.querySelector("input")).find((i) => i.checked)?.value || "scan";

  const folder = h("select", { id: "ns-folder", "aria-describedby": "ns-folder-note" },
    folders.map((f) => h("option", { value: f, selected: f === folderFor(selected) }, shortProject(f))));
  const url = h("input", { type: "text", id: "ns-url", autocomplete: "off", spellcheck: "false", placeholder: "http://localhost:3000" });
  url.value = keyParts(selected).url;
  const urlRow = h("div", { class: "field" }, h("label", { for: "ns-url" }, easy ? "Where your app runs " : "Running app URL ", h("span", { class: "muted" }, "(optional)")), url);

  const confirm = h("input", { type: "text", id: "ns-confirm", autocomplete: "off", spellcheck: "false" });
  const confirmQ = h("label", { for: "ns-confirm", class: "prose" });
  const confirmRow = h("div", { class: "field confirm", hidden: true }, confirmQ, confirm);

  const offline = h("input", { type: "checkbox", id: "ns-offline", checked: state.meta?.settings?.offline !== false });
  offline.addEventListener("change", async () => {
    const s = await api.post("/api/settings", { offline: offline.checked }).catch(() => null);
    if (!s) { offline.checked = !offline.checked; return; }
    state.meta.settings = s;
    set({ meta: state.meta });
    announce(`Offline ${s.offline ? "on" : "off"}`);
  });

  // AI mode: off; switching it on opens the consent sheet, on every new scan.
  const aiBox = h("input", { type: "checkbox", id: "ns-ai" });
  const aiChosen = h("span", { class: "muted prose" });
  const aiChange = h("button", { type: "button", class: "btn small" }, AI.change);
  const aiPicked = h("p", { class: "ai-chosen", hidden: true }, aiChosen, " ", aiChange);
  const aiRow = h("div", {},
    h("label", { class: "check" }, aiBox, h("span", {}, h("span", { class: "t1" }, AI.label), h("span", { class: "note prose" }, ` :: ${AI.note}`))),
    aiPicked);
  let aiChoice = null;
  const aiReset = () => { aiChoice = null; aiBox.checked = false; aiPicked.hidden = true; };
  const aiPick = async () => {
    const r = await aiSheet({ project: shortProject(folder.value || folderFor(selected) || "") });
    if (r) {
      aiChoice = r;
      aiBox.checked = true;
      aiChosen.textContent = AI.chosen(r.model, r.route === "ollama-cloud");
      aiPicked.hidden = false;
    } else if (!aiChoice) aiReset();
    else aiBox.checked = true;
  };
  aiBox.addEventListener("change", () => (aiBox.checked ? aiPick() : aiReset()));
  aiChange.addEventListener("click", aiPick);
  // Consent names the project, so another folder needs the sheet again.
  folder.addEventListener?.("change", aiReset);

  const err = h("p", { class: "err", role: "alert", hidden: true });
  const start = h("button", { type: "submit", class: "btn primary", disabled: Boolean(busy) });
  const cancel = h("button", { type: "button", class: "btn" }, "Cancel");

  const sync = () => {
    const k = kindNow();
    const def = kinds.find((x) => x.kind === k);
    const usesUrl = k === "scan" || k === "loop";
    urlRow.hidden = !usesUrl;
    aiRow.hidden = k !== "scan" || !folders.length;
    const host = usesUrl ? hostOf(url.value) : null;
    const remote = Boolean(host && !LOCAL.test(host));
    confirmRow.hidden = !remote;
    if (remote) confirmQ.textContent = `${host} is not on this machine. Type its name to confirm you own it or may test it:`;
    start.textContent = `${def.button} ▸`;
  };
  for (const r of radios) r.querySelector("input").addEventListener("change", sync);
  url.addEventListener("input", sync);

  const form = h("form", { class: "form", novalidate: true },
    h("fieldset", {}, h("legend", {}, easy ? "What do you want to do?" : "What to run"), h("div", { class: "choices" }, radios)),
    h("div", { class: "field" }, h("label", { for: "ns-folder" }, easy ? "Your app's folder" : "Project folder"), folders.length ? folder : h("p", { class: "muted" }, "No folders. Start penthera ui with --project <dir>."),
      h("p", { id: "ns-folder-note", class: "muted prose" }, "Runs read and write only inside this folder.")),
    urlRow,
    confirmRow,
    aiRow,
    h("label", { class: "check" }, offline, h("span", {}, h("span", { class: "t1" }, "Offline"), h("span", { class: "note prose" }, " :: contact only the target. Applies to every run started here."))),
    busy ? h("p", { class: "muted prose" }, "A run is in progress. Stop it or wait for it to finish first.") : null,
    err,
    h("div", { class: "actions" }, h("span", { class: "grow muted" }, easy ? "Only check what you own or may test." : "Only scan what you own or may test."), cancel, start),
  );
  const win = openWindow({ title: easy ? "Check my app" : "New scan", body: form });
  cancel.addEventListener("click", win.close);
  sync();

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    err.hidden = true;
    start.disabled = true;
    const k = kindNow();
    const usesUrl = k === "scan" || k === "loop";
    try {
      const ai = k === "scan" && aiChoice ? { model: aiChoice.model, consent: true, textVersion: AI_TEXT_VERSION, confirmHost: aiChoice.confirmHost || "" } : undefined;
      const r = await api.post("/api/runs", { kind: k, repo: folder.value || folderFor(selected), url: usesUrl ? url.value : "", confirm: confirm.value, maxIterations: 5, ai });
      win.close();
      await ctx.refresh();
      set({ sel: { kind: "run", key: r.id, run: r } });
    } catch (ex) {
      err.textContent = ex.message;
      err.hidden = false;
      start.disabled = false;
      if (ex.status === 428) confirm.focus();
    }
  });
  queueMicrotask(() => (radios.find((r) => r.querySelector("input").checked)?.querySelector("input"))?.focus());
}

/**
 * The AI mode sheet: where the code goes (a picture first, then words), which
 * model, and two choices of equal weight. A cloud model shows ollama.com in the
 * picture and needs the host typed. Esc and "Not now" decline.
 * @returns {Promise<{ model: string, route: string, confirmHost: string } | null>}
 */
export function aiSheet({ project, maxUnits = 200 }) {
  return new Promise((done) => {
    let result = null;
    const box = (text, cls) => h("span", { class: ["ai-box", cls || null] }, text);
    const arrow = () => h("span", { class: "ai-arrow" }, "→");
    const outside = box("internet", "out");
    const flow = h("div", { class: "ai-flow", "aria-hidden": "true" }, box("your code"), arrow(), box("Penthera"), arrow(), box("Ollama on this computer"), arrow(), outside);
    const flowAlt = h("p", { class: "sr-only" });
    const select = h("select", { id: "ai-model", disabled: true }, h("option", {}, "Asking Ollama…"));
    const lines = h("dl", { class: "kv ai-lines", hidden: true });
    const modelRow = h("div", { class: "field", hidden: true }, h("label", { for: "ai-model" }, "Model"), select);
    const hostQ = h("label", { for: "ai-host", class: "prose" }, AI.cloudConfirm);
    const host = h("input", { type: "text", id: "ai-host", autocomplete: "off", spellcheck: "false" });
    const hostRow = h("div", { class: "field confirm", hidden: true }, hostQ, host);
    const note = h("p", { class: "muted prose", role: "status" });
    const use = h("button", { type: "button", class: "btn", disabled: true }, "Use");
    const notNow = h("button", { type: "button", class: "btn" }, AI.notNow);
    let models = [];

    const current = () => models.find((m) => m.name === select.value) || null;
    const sync = () => {
      const m = current();
      const cloud = m?.route === "ollama-cloud";
      outside.textContent = cloud ? AI_CLOUD_HOST : "internet";
      outside.classList.toggle("live", cloud);
      flowAlt.textContent = AI.flowAlt(cloud);
      clear(lines).append(...aiLines({ route: m?.route || "local", model: m?.name || "…", project, maxUnits }).flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]));
      hostRow.hidden = !cloud;
      use.textContent = m ? AI.use(m.name, cloud) : "Use";
      use.disabled = !m || (cloud && host.value.trim().toLowerCase() !== AI_CLOUD_HOST);
    };
    select.addEventListener("change", sync);
    host.addEventListener("input", sync);

    const body = h("div", { class: "form ai-sheet" },
      h("p", { class: "prose" }, AI.intro),
      flow, flowAlt,
      modelRow,
      lines,
      hostRow,
      note,
      h("div", { class: "actions" }, h("span", { class: "grow" }), notNow, use));
    const win = openWindow({ title: AI.title, label: "AI mode: what happens to your code", body });
    win.el.addEventListener("close", () => done(result));
    notNow.addEventListener("click", win.close);
    use.addEventListener("click", () => {
      const m = current();
      if (!m) return;
      result = { model: m.name, route: m.route, confirmHost: m.route === "ollama-cloud" ? host.value.trim().toLowerCase() : "" };
      win.close();
    });
    sync();
    notNow.focus();

    api.get("/api/ai-mode/models").then((r) => {
      if (r.textVersion != null && r.textVersion !== AI_TEXT_VERSION) {
        note.textContent = "What AI mode does has changed since this page loaded. Reload the page to read the new text.";
        return;
      }
      models = [...(r.models || []).filter((m) => m.route === "local"), ...(r.models || []).filter((m) => m.route !== "local")];
      if (r.error) note.textContent = r.error;
      else if (!models.length) note.textContent = AI.noModels;
      clear(select).append(...models.map((m) => h("option", { value: m.name }, m.route === "local" ? m.name : `${m.name}  (runs on ${AI_CLOUD_HOST})`)));
      select.disabled = !models.length;
      modelRow.hidden = lines.hidden = !models.length;
      sync();
      if (models.length) select.focus();
    }).catch((e) => { note.textContent = e.message; });
  });
}

/** About Penthera: the wordmark, the version and what this page is. */
export function about() {
  const body = h("div", { class: "about" },
    h("span", { class: "logotype xl", role: "img", "aria-label": "Penthera" }),
    h("p", { class: "prose" }, ABOUT.line),
    h("dl", { class: "kv" },
      h("dt", {}, "version"), h("dd", {}, `v${state.meta?.version || ""}${state.meta?.demo ? " · demo data" : ""}`),
      h("dt", {}, "license"), h("dd", {}, ABOUT.license),
      h("dt", {}, "type"), h("dd", {}, ABOUT.type)),
    h("p", { class: "muted prose" }, ABOUT.local),
  );
  const win = openWindow({ title: "About Penthera", body });
  const ok = h("button", { type: "button", class: "btn primary", onclick: win.close }, "OK");
  body.append(h("div", { class: "actions" }, ok));
  ok.focus();
}

