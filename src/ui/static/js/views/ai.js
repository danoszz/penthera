import { h, put, panel, empty, sevBadge } from "../dom.js";
import { bigGrade, sparkline, severityBars } from "../charts.js";
import { ago } from "../format.js";
import { SCREENS, EMPTY } from "../copy.js";

const GRADE_SCORE = { A: 95, B: 80, C: 65, D: 50, F: 20 };

export async function render(root, { api }) {
  const d = await api.get("/api/ai");
  put(root, 
    h("h1", {}, SCREENS.ai.title),
    h("p", { class: "lede" }, SCREENS.ai.lede),
  );
  const l = d.latest;
  if (!l) {
    put(root, h("div", { class: "notice" }, empty(EMPTY.ai)));
    return;
  }
  const grid = h("div", { class: "grid" });
  put(root, grid);

  const lock = l.lock || {};
  const drift = (lock.changed || 0) + (lock.added || 0) + (lock.removed || 0);
  put(grid, panel("Agent config grade", { class: "span-4" },
    h("div", { class: "filters" },
      bigGrade(l.grade),
      h("div", {},
        h("div", { class: "big" }, h("span", { class: `grade-${l.grade}` }, `Grade ${l.grade}`)),
        h("div", { class: "muted" }, `score ${l.score}/100`),
        h("div", { class: "faint" }, `${l.home ? "repo + home config" : "repo config"} :: ${ago(l.ts)}`),
      ),
    ),
    h("p", { class: "label" }, "Grade over time"),
    sparkline(d.history.map((x) => x.score ?? GRADE_SCORE[x.grade]), { width: 260, height: 32, label: "agent config score", zero: false }),
    h("p", { class: "panel-note" }, d.history.map((x) => x.grade).join(" → ")),
  ));

  const inv = l.inventory || {};
  put(grid, panel("Inventory", { class: "span-4" },
    h("dl", { class: "kv" }, ...[["skills", inv.skills], ["MCP servers", inv.mcpServers], ["hooks", inv.hooks], ["permissions", inv.permissions], ["plugins", inv.plugins], ["marketplaces", inv.marketplaces], ["instruction files", inv.instructionFiles]]
      .flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, String(v ?? 0))])),
  ));

  put(grid, panel("penthera.lock drift", { class: "span-4" },
    h("div", { class: "big" }, h("span", { class: drift ? "t1" : "ok" }, drift ? `${drift} drifted` : lock.status === "missing" ? "not pinned" : "no drift")),
    h("dl", { class: "kv" },
      h("dt", {}, "status"), h("dd", {}, lock.status || "-"),
      h("dt", {}, "changed"), h("dd", { class: lock.changed ? "bad" : null }, String(lock.changed || 0)),
      h("dt", {}, "new"), h("dd", { class: lock.added ? "bad" : null }, String(lock.added || 0)),
      h("dt", {}, "removed"), h("dd", {}, String(lock.removed || 0)),
      h("dt", {}, "pinned"), h("dd", {}, String(lock.entries || 0)),
    ),
    h("p", { class: "panel-note" }, "A pinned skill or server that changes after review is how a rug pull works. Diff it, then re-pin with penthera agents --pin."),
  ));

  put(grid, panel(`Hidden content (${l.hidden.length})`, { class: "span-7" },
    l.hidden.length ? h("ul", { class: "list" }, l.hidden.map((x) => h("li", {},
      sevBadge(x.severity),
      h("div", { class: "grow" }, h("div", {}, x.title), h("div", { class: "faint" }, `${x.location || ""}${x.rule ? `  [${x.rule}]` : ""}`), x.description ? h("pre", { class: "block" }, x.description) : null),
    ))) : empty("No hidden instructions, invisible characters or smuggled binaries found."),
  ));

  put(grid, panel("Other findings", { class: "span-5" },
    severityBars(l.counts, { width: 14 }),
    h("p", { class: "label" }, "Config findings"),
    h("ul", { class: "list" }, l.findings.slice(0, 12).map((x) => h("li", {}, sevBadge(x.severity), h("span", { class: "grow" }, x.title)))),
  ));
}
