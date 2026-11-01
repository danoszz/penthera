// The projects window: "New scan…", then every project with its grade, open
// findings and last scan, "All projects" first. Runs live with their project
// (History tab) and in the menu bar while one is going; a project with a run
// in progress shows a blinking half-tone square.
import { h, clear } from "./dom.js";
import { state, set, projectKeys, projectOf, simple } from "./state.js";
import { ago, shortProject, plural, checkedWhat } from "./format.js";
import { EMPTY } from "./copy.js";

export function renderLeft(el, ctx) {
  const projects = state.overview?.projects || [];
  const keys = projectKeys();
  const totalOpen = state.overview?.open ?? projects.reduce((n, p) => n + p.open, 0);
  const running = new Set(state.runs.live.filter((r) => r.status === "running").flatMap((r) => [r.repo, r.url]).filter(Boolean));
  const viewing = state.sel.kind === "all" || state.sel.kind === "project";

  const item = (attrs, ...kids) => h("button", { type: "button", class: "item", ...attrs }, ...kids);
  const current = (key) => String(viewing && (key == null ? state.sel.kind === "all" : state.sel.key === key));

  const list = h("ul", { class: "side-list", "aria-label": "Projects" },
    h("li", {}, item({ "aria-current": current(null), onclick: () => set({ sel: { kind: "all", key: null } }) },
      h("span", { class: "grade" }, "∑"), h("span", { class: "name" }, "All projects"), h("span", { class: "count" }, String(totalOpen)),
      h("span", { class: "sub" }, `${plural(state.overview?.apps ?? projects.length, "project")} · ${totalOpen} open`))),
    keys.map((key) => {
      const p = projectOf(key);
      return h("li", {}, item({ "aria-current": current(key), title: key, onclick: () => set({ sel: { kind: "project", key } }) },
        h("span", { class: `grade grade-${p?.grade || "x"}` }, p ? p.grade : "·"),
        h("span", { class: "name" }, shortProject(key)),
        running.has(key) ? h("span", { class: "dot live", role: "img", "aria-label": "a run is in progress" }) : h("span", { class: "count" }, p ? String(p.open) : ""),
        h("span", { class: "sub" }, p ? `${simple() ? checkedWhat(p.mode, p.unread) : p.mode || "scan"} · ${ago(p.lastScan)}` : simple() ? "not checked yet" : "not scanned yet")));
    }),
  );
  if (!keys.length) list.append(h("li", { class: "group-h" }, EMPTY.projects));

  clear(el).append(
    h("div", { class: "win-bar" },
      h("span", { class: "title" }, "Projects"),
      h("span", { class: "grow" }),
      h("button", { type: "button", class: "icon", "aria-label": "Hide the projects window ([)", title: "Hide  [", onclick: ctx.toggleLeft }, "⇤"),
    ),
    h("div", { class: "pane-body" },
      h("button", { type: "button", class: "btn new-scan", onclick: () => ctx.newScan() }, "New scan…", h("kbd", {}, "n")),
      list,
    ),
  );
}
