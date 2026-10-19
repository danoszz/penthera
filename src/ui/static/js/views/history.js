import { h, put, panel, clear, empty, sevBadge, fig, whatNext } from "../dom.js";
import { trendChart, ganttChart } from "../charts.js";
import { stamp, ago, shortProject } from "../format.js";
import { SCREENS, EMPTY } from "../copy.js";

export async function render(root, { api, params, go }) {
  const o = await api.get("/api/overview");
  put(root, h("h1", {}, SCREENS.history.title), h("p", { class: "lede" }, SCREENS.history.lede));
  if (!o.projects.length) { put(root, h("div", { class: "notice" }, empty(EMPTY.history))); return; }

  const keys = o.projects.map((p) => p.key);
  // Default to the project whose last two scans differ most: that is the interesting comparison.
  const delta = (p) => (p.trend.length > 1 ? Math.abs(p.trend[p.trend.length - 1].total - p.trend[p.trend.length - 2].total) + 0.5 : 0);
  let project = keys.includes(params.get("project")) ? params.get("project") : [...o.projects].sort((x, y) => delta(y) - delta(x))[0].key;
  const projSel = h("select", { "aria-label": "Project" }, keys.map((k) => h("option", { value: k, selected: k === project }, shortProject(k))));
  const aSel = h("select", { "aria-label": "Before" });
  const bSel = h("select", { "aria-label": "After" });
  const body = h("div");
  put(root, 
    h("div", { class: "filters" },
      h("label", { class: "field" }, h("span", {}, "Project"), projSel),
      h("label", { class: "field" }, h("span", {}, "Before"), aSel),
      h("label", { class: "field" }, h("span", {}, "After"), bSel),
    ),
    body,
  );

  let seq = 0;
  async function load(a = null, b = null) {
    const n = ++seq;
    const q = new URLSearchParams({ project });
    if (a != null) q.set("a", a);
    if (b != null) q.set("b", b);
    let hst;
    try { hst = await api.get(`/api/history?${q}`); } catch (e) { clear(body).append(h("p", { class: "error" }, e.message)); return; }
    if (n !== seq) return;
    const opts = (sel, cur) => clear(sel).append(...hst.scans.map((sc) => h("option", { value: String(sc.i), selected: sc.i === cur.i }, `#${sc.i + 1} · ${stamp(sc.ts).slice(5)} · ${sc.open} open`)));
    opts(aSel, hst.a);
    opts(bSel, hst.b);
    const one = hst.scans.length < 2;
    clear(body).append(
      one ? h("p", { class: "notice" }, EMPTY.history) : null,
      h("div", { class: "strip" },
        cell("Before", String(hst.a.open), `${stamp(hst.a.ts)} :: ${ago(hst.a.ts)}`),
        cell("After", String(hst.b.open), `${stamp(hst.b.ts)} :: ${ago(hst.b.ts)}`),
        cell("New", String(hst.new.length), "in after, not in before"),
        cell("Fixed", String(hst.fixed.length), "in before, gone after", "ok"),
      ),
      panel(`Between scan ${hst.a.i + 1} and scan ${hst.b.i + 1}`, { meta: `${stamp(hst.b.ts)}` },
        h("div", { class: "cols" },
          col(`New · ${hst.new.length}`, hst.new, "Nothing new."),
          col(`Fixed · ${hst.fixed.length}`, hst.fixed, "Nothing fixed between these two scans."),
          col(`Still open · ${hst.still.length}`, hst.still, "Nothing carried over."),
        )),
      h("div", { class: "grid stack" }, panel("Timeline", { class: "span-12", meta: `${hst.lifetimes.filter((l) => l.open).length} open · ${hst.lifetimes.filter((l) => !l.open).length} fixed` },
        h("div", { class: "table-wrap" }, ganttChart(hst.lifetimes, hst.scans)),
        h("div", { class: "legend" },
          h("span", {}, "▨ open, up to now"), h("span", {}, "█ open and critical"), h("span", {}, "□ fixed: first seen to last seen"), h("span", {}, "┊ a scan"),
        ),
        fig(`fig 1 :: every finding of ${shortProject(project)} across ${hst.scans.length} scans`, "from the reports folder"),
      ),
      panel("Open findings per scan", { class: "span-12", meta: `${hst.scans.length} scans` },
        trendChart(hst.scans.map((sc) => ({ ts: sc.ts, total: sc.open, severe: sc.counts.critical + sc.counts.high })), { width: 1100, height: 200 }),
        fig(`fig 2 :: ${shortProject(project)}, every scan in the reports folder`, `${hst.scans.length} scans`),
      )),
      whatNext([
        { label: "Read what is still open", go: ["findings", { project }] },
        { label: "Fix it with the agent", why: "then compare again", go: ["run", { kind: "loop", repo: project.startsWith("/") ? project : "" }] },
        { label: "Create evidence for an auditor", go: ["evidence"] },
      ], go),
    );
  }

  projSel.addEventListener("change", () => { project = projSel.value; load(); });
  aSel.addEventListener("change", () => load(Number(aSel.value), Number(bSel.value)));
  bSel.addEventListener("change", () => load(Number(aSel.value), Number(bSel.value)));
  await load();

  function col(title, rows, none) {
    return h("div", {}, h("h3", {}, title),
      rows.length ? h("ul", { class: "rows" }, rows.map((r) => h("li", {}, h("span", { class: "code" }, r.severity.slice(0, 1).toUpperCase() + "+"), h("span", { class: ["t", r.severity === "critical" || r.severity === "high" ? "b" : null] }, r.title)))) : empty(none));
  }

  function list(title, rows, none) {
    return panel(`${title} (${rows.length})`, {},
      rows.length ? h("ul", { class: "list" }, rows.map((r) => h("li", {}, sevBadge(r.severity), h("span", { class: "grow t1" }, r.title)))) : empty(none));
  }
}

function cell(label, value, sub, cls) {
  return h("div", { class: "cell" }, h("span", { class: "label" }, label), h("div", { class: ["big", cls] }, value), h("div", { class: "sub" }, sub));
}
