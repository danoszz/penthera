import { keyParts } from "./format.js";

// One store for the single view. Renderers subscribe and redraw their window.
export const state = {
  meta: null,
  overview: null,
  findings: [],
  runs: { live: [], past: [] },
  sel: { kind: "all", key: null },   // all | project | run | past
  tab: "findings",                   // findings | deps | ai | history | proof (for all / project)
  finding: null,                     // { id, project } open in the inspector
  right: "none",                     // none | finding | settings
  query: "",
  filter: null,                      // { severity, confidence } from the triage matrix, advanced only
  source: null,                      // "penthera" or another tool's name (--giants), advanced only
  giants: [],                        // coverage by area per project, from --giants scans
  pending: null,                     // the live run's diff waiting for a decision, if any
  ux: "simple",                      // simple | advanced, chosen in setup, remembered per browser
};

export const simple = () => state.ux === "simple";

export const TABS = [
  { id: "findings", label: "Findings", key: "1" },
  { id: "deps", label: "Dependencies", key: "2" },
  { id: "ai", label: "AI tooling", key: "3" },
  { id: "history", label: "History", key: "4" },
  { id: "proof", label: "Proof", key: "5" },
];

const subs = new Set();
export function on(fn) { subs.add(fn); return () => subs.delete(fn); }
export function set(patch) {
  // A finding from another project has no place beside this one.
  const key = patch.sel?.kind === "project" ? patch.sel.key : null;
  if (key && !("finding" in patch) && state.finding && state.finding.project !== key) Object.assign(patch, { finding: null, right: state.right === "finding" ? "none" : state.right });
  Object.assign(state, patch);
  for (const fn of subs) fn(patch);
}

/** Every project key: scanned targets first, then project folders with no scans yet. */
export function projectKeys() {
  const scanned = (state.overview?.projects || []).map((p) => p.key);
  const covered = scanned.map((k) => keyParts(k).folder);
  const folders = (state.meta?.projects || []).filter((f) => !covered.includes(f));
  return [...scanned, ...folders];
}

export const projectOf = (key) => (state.overview?.projects || []).find((p) => p.key === key) || null;

/** The folder a run should use: the selected project if it is a folder, else the first project folder. */
export function folderFor(key) {
  return keyParts(key).folder || state.meta?.projects?.[0] || "";
}

/** The project the current view is about, if any (a run or past run counts as its project). */
export function currentProject() {
  const s = state.sel;
  if (s.kind === "project") return s.key;
  if (s.kind === "past") return s.past?.target?.repo || s.past?.target?.url || null;
  if (s.kind === "run") return s.run?.repo || s.run?.url || null;
  return null;
}

/** The live run that is still going, if any. */
export const liveRun = () => state.runs.live.find((r) => r.status === "running") || null;

/** Severity counts for what is on screen: the selected project, or all of them. */
export function countsInView() {
  const key = currentProject();
  if (key) return projectOf(key)?.counts || null;
  return state.overview?.mix || null;
}
