// What a maker sees once the fix has run: their own steps stay, one app counts once,
// and the wizard's results land in the project.
import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { buildOverview, ownerDuties } from "../src/ui/api/summarize.js";
import { createDataSource } from "../src/ui/api/data.js";
import { createRunManager } from "../src/ui/api/runs.js";
import { createSettings } from "../src/ui/server.js";
import { isWizardFile, LOOP_RUN_SCHEMA } from "../src/agent/loop.js";

const dirs = [];
const temp = () => { const d = realpathSync(mkdtempSync(join(tmpdir(), "penthera-after-"))); dirs.push(d); return d; };
afterEach(() => { while (dirs.length) rmSync(dirs.pop(), { recursive: true, force: true }); });

const timestamp = "2026-11-01T10:00:00.000Z";
const crit = (n) => ({ templateId: `rule-${n}`, title: `Problem ${n}`, severity: "critical", url: "x", location: "x" });
const scan = (target, findings, at = timestamp) => ({ name: `${target}.json`, mtime: 1, data: { target, mode: "repo", timestamp: at, findings } });

describe("All projects", () => {
  const two = [crit(1), crit(2)];
  it("counts one app once, however many checks made a row", () => {
    const o = buildOverview({ scans: [scan("/app", two), scan("http://localhost:3000 + /app", two), scan("http://localhost:3000", two)] });
    expect(o.projects).toHaveLength(3);
    expect(o.apps).toBe(1);
    expect(o.mix.critical).toBe(2);
    expect(o.open).toBe(2);
    expect(o.counted).toHaveLength(1);
  });
  it("counts the newest check of that app", () => {
    const o = buildOverview({ scans: [scan("/app", two, "2026-11-01T10:00:00.000Z"), scan("http://localhost:3000 + /app", [crit(1)], "2026-11-01T11:00:00.000Z")] });
    expect(o.open).toBe(1);
  });
  it("never merges two folders that share an address", () => {
    const o = buildOverview({ scans: [scan("http://127.0.0.1:3000 + /shop", two), scan("http://127.0.0.1:3000 + /blog", [], "2026-11-01T11:00:00.000Z")] });
    expect(o.apps).toBe(2);
    expect(o.mix.critical).toBe(2);
    expect(o.open).toBe(2);
    expect(o.counted).toHaveLength(2);
  });
  it("keeps an address apart when two folders could own it", () => {
    const o = buildOverview({ scans: [scan("http://127.0.0.1:3000", two), scan("http://127.0.0.1:3000 + /shop", []), scan("http://127.0.0.1:3000 + /blog", [])] });
    expect(o.apps).toBe(3);
    expect(o.open).toBe(2);
  });
  it("merges an address with the one folder that owns it, in any order", () => {
    const rows = [scan("http://127.0.0.1:3000", two), scan("/shop", two), scan("http://127.0.0.1:3000 + /shop", two)];
    for (const scans of [rows, [...rows].reverse()]) expect(buildOverview({ scans }).apps).toBe(1);
  });
  it("doesn't let a newer clean look at the address hide the code's problems", () => {
    const scans = [scan("http://127.0.0.1:3000 + /shop", two), scan("http://127.0.0.1:3000", [], "2026-11-01T11:00:00.000Z")];
    expect(buildOverview({ scans }).mix.critical).toBe(2);
  });
  it("doesn't let a later, narrower check hide a wider one's problems", () => {
    const later = "2026-11-01T11:00:00.000Z";
    const o = buildOverview({ scans: [scan("http://localhost:3000 + /app", two), scan("/app", [], later)] });
    expect(o.apps).toBe(1);
    expect(o.open).toBe(2);
    expect(o.mix.critical).toBe(2);
    expect(o.counted).toEqual(["http://localhost:3000 + /app"]);
  });
  it("lets a later check of the same or wider reach replace it", () => {
    const later = "2026-11-01T11:00:00.000Z";
    expect(buildOverview({ scans: [scan("/app", two), scan("http://localhost:3000 + /app", [], later)] }).open).toBe(0);
    expect(buildOverview({ scans: [scan("http://localhost:3000", two), scan("http://localhost:3000 + /app", [], later)] }).open).toBe(0);
  });
  it("doesn't let a wider check that couldn't read the site replace the site's problems", () => {
    const later = "2026-11-01T11:00:00.000Z";
    const blocked = scan("http://localhost:3000 + /app", [], later);
    blocked.data = { ...blocked.data, mode: "url+repo", modes: ["url", "repo"], reachable: false };
    expect(buildOverview({ scans: [scan("http://localhost:3000", two), blocked] }).open).toBe(2);
  });
  it("adds up different apps", () => {
    const o = buildOverview({ scans: [scan("/a", two), scan("/b", two)] });
    expect(o.apps).toBe(2);
    expect(o.open).toBe(4);
  });
});

describe("the owner's steps", () => {
  const loop = (fixes, startedAt = timestamp) => ({ data: { loopRun: { startedAt, target: { repo: "/app" }, iterations: [{ fixes }] } } });
  const rotate = "Rotate this secret at the provider";
  it("come from fixes that landed, once each", () => {
    const duties = ownerDuties([
      loop([{ status: "verified", ownerActions: [rotate] }, { status: "failed", ownerActions: ["Not this one"] }]),
      loop([{ status: "verified", ownerActions: [rotate, "Set STRIPE_KEY"] }]),
    ], "/app");
    expect(duties.map((d) => d.text)).toEqual([rotate, "Set STRIPE_KEY"]);
    expect(duties[0].id).toMatch(/^[0-9a-f]{16}$/);
  });
  it("belong to their own folder", () => {
    expect(ownerDuties([loop([{ status: "verified", ownerActions: [rotate] }])], "/other")).toEqual([]);
  });
  it("reach the end of the run", async () => {
    const root = temp();
    const loopRun = { id: "l", stopReason: "done", totals: { verified: 1 }, findings: {}, branch: { base: "main", fix: "penthera/fix" }, durationMs: 1, iterations: [{ n: 1, fixes: [
      { title: "Move the key", status: "verified", ownerActions: [rotate, rotate] }, { title: "Skipped", status: "declined", ownerActions: ["Not this one"] }] }] };
    const mgr = createRunManager({ runLoop: async () => loopRun, settings: () => ({ offline: true }), projectRoots: [root] });
    const run = mgr.start({ kind: "loop", repo: root });
    while (mgr.get(run.id).status === "running") await new Promise((r) => setTimeout(r, 5));
    const done = mgr.get(run.id).summary;
    expect(done.ownerActions).toEqual([rotate]);
    expect(done.mergeBase).toBe("main");
  });
  it("stay dismissed across a restart, with nothing but an id on disk", () => {
    const file = join(temp(), "ui.json");
    const s = createSettings({ file });
    s.update({ doneAction: "0123456789abcdef" });
    s.update({ doneAction: "/etc/passwd" });
    expect(createSettings({ file }).get().done).toEqual(["0123456789abcdef"]);
  });
});

describe("the fix button", () => {
  const loop = (stopReason, startedAt) => ({ data: { loopRun: { startedAt, durationMs: 1000, stopReason, target: { repo: "/app" }, iterations: [] } } });
  const noFixes = (runs, at) => buildOverview({ scans: [scan("/app", [crit(1)], at)], runs, nothingToFix: () => runs.length > 0 && runs[0].data.loopRun.stopReason === "no-fixable-findings" }).projects[0].nothingToFix;
  it("stands down after a run that could fix nothing", () => {
    expect(noFixes([loop("no-fixable-findings", "2026-11-01T11:00:00.000Z")], timestamp)).toBe(true);
    expect(noFixes([loop("done", "2026-11-01T11:00:00.000Z")], timestamp)).toBe(false);
  });
});

describe("a saved fix run, read back", () => {
  const source = (loopRun, findings = [crit(1)]) => {
    const root = temp();
    const app = join(root, "app");
    mkdirSync(join(app, "reports"), { recursive: true });
    writeFileSync(join(app, "reports", "code.json"), JSON.stringify({ target: app, mode: "repo", timestamp, findings }));
    const src = createDataSource({ projects: [app], reportsDir: join(app, "reports"), home: join(root, "h"), memoryRoot: join(root, "m"), settings: { get: () => ({}) } });
    src.saveLoopRun({ schema: LOOP_RUN_SCHEMA, id: "l", startedAt: "2026-11-01T11:00:00.000Z", durationMs: 1000, target: { repo: app }, ...loopRun });
    return new Promise((r) => setTimeout(r, 60)).then(() => createDataSource({ projects: [app], reportsDir: join(app, "reports"), home: join(root, "h"), memoryRoot: join(root, "m"), settings: { get: () => ({}) } }).overview().projects[0]);
  };
  it("keeps the owner's steps on the project", async () => {
    const p = await source({ stopReason: "done", iterations: [{ fixes: [{ status: "verified", ownerActions: ["Rotate the key"] }] }] });
    expect(p.duties.map((d) => d.text)).toEqual(["Rotate the key"]);
    expect(p.nothingToFix).toBe(false);
  });
  it("stands the fix button down when it could fix nothing", async () => {
    expect((await source({ stopReason: "no-fixable-findings", iterations: [] })).nothingToFix).toBe(true);
  });
});

describe("the wizard's results", () => {
  it("land in the project, with no project made of the reports folder", () => {
    const root = temp();
    const app = join(root, "app");
    const run = join(app, "reports", "penthera-2026-11-01");
    mkdirSync(run, { recursive: true });
    writeFileSync(join(run, "code.json"), JSON.stringify({ target: app, mode: "repo", timestamp, findings: [crit(1)] }));
    writeFileSync(join(run, "deps.json"), JSON.stringify({ target: ".", mode: "deps", timestamp, deps: { total: 1, scanned: 1, notInstalled: [], direct: [], capabilityCounts: {} }, findings: [] }));
    const src = createDataSource({ projects: [app], reportsDir: run, home: join(root, "h"), memoryRoot: join(root, "m"), settings: { get: () => ({}) } });
    expect(src.overview().projects.map((p) => p.key)).toEqual([app]);
  });
  it("don't stop the fix loop over the wizard's own files", () => {
    expect([".gitignore", ".github/workflows/penthera.yml"].every(isWizardFile)).toBe(true);
    expect(isWizardFile("src/app.js")).toBe(false);
    expect(isWizardFile(".github/workflows/deploy.yml")).toBe(false);
  });
});

describe("the merge hint", () => {
  const summary = async (branch, totals) => {
    const roots = [temp()];
    const mgr = createRunManager({
      runLoop: async () => ({ stopReason: "no-fixable-findings", error: null, totals, findings: {}, branch, durationMs: 1, iterations: [] }),
      saveLoopRun: () => null, settings: () => ({ offline: true }), projectRoots: roots,
    });
    const run = mgr.start({ kind: "loop", repo: roots[0] });
    await new Promise((done) => mgr.subscribe(run.id, 0, (ev) => { if (!ev) done(); }));
    return mgr.get(run.id).summary;
  };

  it("offers no merge when a run on a fix branch landed nothing", async () => {
    expect((await summary({ fix: "penthera/fix-1", base: "penthera/fix-1" }, { verified: 0 })).mergeBase).toBeNull();
    expect((await summary({ fix: "penthera/fix-1", base: "penthera/fix-1" }, { verified: 1 })).mergeBase).toBeNull();
  });

  it("offers one when a fix landed on a new branch", async () => {
    expect((await summary({ fix: "penthera/fix-1", base: "main" }, { verified: 1 })).mergeBase).toBe("main");
  });

  it("does not send you to a list that may be empty", () => {
    expect(readFileSync(resolve("src/ui/static/js/center.js"), "utf-8")).not.toContain("copy its prompt");
  });
});
