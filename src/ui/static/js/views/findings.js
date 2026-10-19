import { h, put, panel, clear, empty, sevBadge, diffBlock, announce } from "../dom.js";
import { SEVERITIES, ago, shortProject } from "../format.js";
import { SCREENS, EMPTY } from "../copy.js";

export async function render(root, { api, params, go }) {
  const { findings } = await api.get("/api/findings");
  const projects = [...new Set(findings.map((f) => f.project))].sort();
  const state = {
    q: params.get("q") || "",
    sev: new Set(SEVERITIES.filter((x) => x !== "info")),
    project: params.get("project") || "",
    suppressed: false,
    selected: params.get("id") ? `${params.get("project")}|${params.get("id")}` : null,
  };

  const search = h("input", { type: "search", class: "search", placeholder: "filter  (press /)", "aria-label": "Filter findings", value: state.q });
  const projectSel = h("select", { "aria-label": "Project" },
    h("option", { value: "" }, `All projects (${projects.length})`),
    projects.map((p) => h("option", { value: p, selected: p === state.project }, shortProject(p))),
  );
  const toggles = SEVERITIES.map((sev) => h("button", {
    type: "button", class: `toggle sev-${sev}`, "aria-pressed": String(state.sev.has(sev)),
    onclick: (e) => {
      if (state.sev.has(sev)) state.sev.delete(sev); else state.sev.add(sev);
      e.currentTarget.setAttribute("aria-pressed", String(state.sev.has(sev)));
      draw();
    },
  }, sev));
  const supp = h("input", { type: "checkbox", id: "f-supp" });
  const count = h("span", { class: "muted", "aria-live": "polite" });
  const tbody = h("tbody");
  const detail = h("div", { class: "detail" });

  put(root, 
    h("h1", {}, SCREENS.findings.title),
    h("p", { class: "lede" }, SCREENS.findings.lede),
    h("div", { class: "filters", role: "search" }, search, projectSel, h("div", { class: "filters", role: "group", "aria-label": "Severity" }, toggles),
      h("label", { class: "check", for: "f-supp" }, supp, "suppressed"), count),
    h("div", { class: "split" },
      panel("Findings", {}, h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, h("th", {}, "Sev"), h("th", {}, "Finding"), h("th", { class: "hide-narrow" }, "Project"), h("th", { class: "hide-narrow" }, "Category"))),
        tbody,
      ))),
      detail,
    ),
  );

  let visible = [];
  const keyOf = (f) => `${f.project}|${f.id}`;

  function draw() {
    const q = state.q.trim().toLowerCase();
    visible = findings.filter((f) => state.sev.has(f.severity)
      && (!state.project || f.project === state.project)
      && (state.suppressed || !f.suppressed)
      && (!q || `${f.title} ${f.category} ${f.location} ${f.source}`.toLowerCase().includes(q)));
    clear(tbody);
    let group = null;
    for (const f of visible) {
      if (f.severity !== group) {
        group = f.severity;
        const n = visible.filter((x) => x.severity === group).length;
        put(tbody, h("tr", { class: "group" }, h("td", { colspan: "4" }, `${group} :: ${n}`)));
      }
      const tr = h("tr", { class: keyOf(f) === state.selected ? "sel" : null, dataset: { key: keyOf(f) } },
        h("td", {}, sevBadge(f.severity)),
        h("td", {},
          h("button", { type: "button", class: "row-btn", onclick: () => select(f) }, f.title),
          h("span", { class: "faint" }, f.location ? `${f.location}` : ""),
          f.suppressed ? h("span", { class: "chip" }, " suppressed") : null),
        h("td", { class: "hide-narrow muted trunc", title: f.project }, shortProject(f.project)),
        h("td", { class: "hide-narrow muted" }, f.category || "-"),
      );
      put(tbody, tr);
    }
    if (!visible.length) {
      const hidden = [state.q.trim() ? "the text filter" : null, state.project ? "the project filter" : null, state.sev.size < SEVERITIES.length ? "the severity toggles" : null].filter(Boolean).join(", ");
      put(tbody, h("tr", {}, h("td", { colspan: "4" }, empty(findings.length ? EMPTY.findingsFiltered(hidden || "the filters") : EMPTY.findingsNone))));
    }
    count.textContent = `${visible.length} of ${findings.length}`;
  }

  let detailSeq = 0;
  async function select(f, { focus = false } = {}) {
    state.selected = keyOf(f);
    for (const tr of tbody.querySelectorAll("tr")) tr.classList.toggle("sel", tr.dataset.key === state.selected);
    const seq = ++detailSeq;
    clear(detail).append(panel("Detail", {}, h("p", { class: "muted" }, "Reading evidence…")));
    let d;
    try {
      d = await api.get(`/api/findings/${f.id}?project=${encodeURIComponent(f.project)}`);
    } catch (e) {
      if (seq === detailSeq) clear(detail).append(panel("Detail", {}, h("p", { class: "error" }, e.message)));
      return;
    }
    if (seq !== detailSeq) return;
    clear(detail).append(renderDetail(d, f, go));
    announce(`Showing ${f.severity} finding: ${f.title}`);
    if (focus) detail.querySelector("h2")?.focus();
  }

  search.addEventListener("input", () => { state.q = search.value; draw(); });
  projectSel.addEventListener("change", () => { state.project = projectSel.value; draw(); });
  supp.addEventListener("change", () => { state.suppressed = supp.checked; draw(); });

  const onKey = (e) => {
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    const typing = /^(INPUT|SELECT|TEXTAREA)$/.test(document.activeElement?.tagName || "");
    if (e.key === "/" && !typing) { e.preventDefault(); search.focus(); return; }
    if (e.key === "Escape" && document.activeElement === search) { search.blur(); return; }
    if (typing || !visible.length) return;
    if (e.key === "j" || e.key === "k") {
      e.preventDefault();
      const i = visible.findIndex((f) => keyOf(f) === state.selected);
      const next = visible[Math.max(0, Math.min(visible.length - 1, i < 0 ? 0 : i + (e.key === "j" ? 1 : -1)))];
      select(next);
      tbody.querySelector(`tr.sel button`)?.focus();
    }
  };
  document.addEventListener("keydown", onKey);

  draw();
  const first = state.selected ? visible.find((f) => keyOf(f) === state.selected) : visible[0];
  if (first) select(first);
  else put(detail, panel("Detail", {}, empty("Select a finding.")));

  return () => document.removeEventListener("keydown", onKey);
}

function renderDetail(d, f, go) {
  const section = (label, ...body) => h("section", {}, h("div", { class: "label" }, label), ...body);
  const repo = f.project.startsWith("/") ? f.project : null;
  const x = d.explain || {};
  return panel("Detail", {},
    h("div", {}, sevBadge(d.severity), " ", h("span", { class: "chip" }, d.confidence || "unrated"), " ", d.category ? h("span", { class: "chip" }, d.category) : null),
    h("h2", { tabindex: "-1" }, d.title),
    h("dl", { class: "kv" },
      h("dt", {}, "where"), h("dd", {}, d.location || "-"),
      h("dt", {}, "project"), h("dd", {}, f.project),
      h("dt", {}, "source"), h("dd", {}, d.source || "-"),
      h("dt", {}, "seen"), h("dd", {}, ago(f.seen)),
      h("dt", {}, "id"), h("dd", { class: "faint" }, d.id),
    ),
    h("div", { class: "plain", "aria-label": "In plain words" },
      h("p", {}, h("span", { class: "strong" }, "In plain words :: "), (x.plainSeverity || d.severity) === "note" ? "a note, not a problem." : `a ${x.plainSeverity || d.severity} problem${d.category ? ` with ${d.category.replace(/-/g, " ")}` : ""}.`),
      x.confidenceMeaning ? h("p", {}, h("span", { class: "strong" }, `How sure (${x.confidence}) :: `), x.confidenceMeaning) : null,
      x.fixText ? h("p", {}, h("span", { class: "strong" }, "What to do :: "), x.fixText) : null,
      x.owasp?.length ? h("p", { class: "muted" }, `Maps to ${x.owasp.join(" · ")}`) : null,
    ),
    d.description ? section("What we saw", h("p", {}, d.description)) : null,
    d.evidence ? section("Evidence", h("pre", { class: "block" }, d.evidence)) : null,
    d.request ? section("Request", h("pre", { class: "block" }, d.request)) : null,
    d.response ? section("Response", h("pre", { class: "block" }, d.response)) : null,
    d.remediation ? section("How to fix", h("p", {}, d.remediation)) : null,
    d.suppression ? section("Suppressed", h("p", { class: "muted" }, `${d.suppression.reason} (${d.suppression.source})`)) : null,
    d.sources?.length ? section("Sources", h("ul", { class: "list" }, d.sources.map((s) => h("li", {}, h("span", { class: "faint" }, "↗"), h("a", { href: s.url, target: "_blank", rel: "noopener noreferrer" }, s.cite))))) : null,
    d.fix
      ? section("Fix recipe",
        h("p", {}, h("span", { class: "ok" }, d.fix.recipe), ` :: ${d.fix.title} `, h("span", { class: "chip" }, `confidence ${d.fix.confidence}`)),
        h("p", { class: "faint" }, `files: ${d.fix.files.join(", ")}`),
        diffBlock(d.fix.diff),
        repo ? h("p", {}, h("button", { type: "button", class: "btn", onclick: () => go("run", { kind: "loop", repo }) }, "Fix it with the agent ▸")) : null)
      : section("Fix recipe", h("p", { class: "muted" }, "No recipe matches this finding. Fix it by hand, or run the loop with a local model (--fix-model) from the CLI.")),
  );
}
