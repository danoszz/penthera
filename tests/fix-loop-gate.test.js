/**
 * The fix loop as a user meets it, stage by stage, on a fresh app: G1. And the
 * proof that each stage can fail: G2. A gate that cannot go red is not a gate.
 */
import { describe, it, expect, afterAll } from "vitest";
import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { LoopError, loopVerdict, runLoop } from "../src/agent/loop.js";
import { scanRepo } from "../src/scan-repo.js";
import { RECIPES, applyDiff, findingKey, planFixes, probeRepo, restoreFiles } from "../lib/fix/index.js";

const dirs = [];
afterAll(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

const temp = () => {
  const d = mkdtempSync(join(tmpdir(), "penthera-gate-"));
  dirs.push(d);
  return d;
};

const git = (dir, ...args) => execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@localhost", "-C", dir, ...args], { encoding: "utf-8" });

/** A small Express app with one bug a recipe can fix and one it cannot, and a report left by an earlier scan. */
function freshApp({ critical = true } = {}) {
  const dir = temp();
  cpSync(resolve("tests/fixtures/fix/express"), dir, { recursive: true });
  if (critical) {
    writeFileSync(join(dir, "routes/tools.js"), [
      'import { exec } from "node:child_process";',
      'import { Router } from "express";',
      "export const tools = Router();",
      'tools.get("/ping", (req, res) => exec("ping " + req.query.host, (e, out) => res.send(out)));',
      "",
    ].join("\n"));
  }
  git(dir, "init", "-q", "-b", "main");
  git(dir, "add", "-A");
  git(dir, "commit", "-qm", "fresh app");
  mkdirSync(join(dir, "reports"));
  writeFileSync(join(dir, "reports/first-scan.json"), "{}\n");
  return dir;
}

const actionable = (r) => r.findings.filter((f) => f.severity !== "info");

/** Scan, plan, fix, rescan, end. Each stage is PASS or FAIL, and a failed stage does not hide the next. */
async function walk(repo, { ask = async () => "y", scan = scanRepo, deps = {} } = {}) {
  const stages = {};
  const before = await scan(repo);
  stages.scan = actionable(before).length > 0;
  stages.plan = (await planFixes(repo, [...before.findings, ...probeRepo(repo)])).plans.length > 0;

  let run = null;
  try {
    run = await runLoop({ repo, ask, deps, memoryRoot: temp(), maxIterations: 3 });
  } catch (e) {
    if (!(e instanceof LoopError)) throw e;
  }
  stages.fix = Boolean(run?.totals.verified) && run.totals.failed === 0 && run.gaveUp.length === 0;

  const after = await scanRepo(repo);
  stages.rescan = actionable(after).length < actionable(before).length;
  // The honest end: a critical is left, so the run must not read as clean.
  stages.ending = Boolean(run) && !loopVerdict(run).clean && /critical.* left/.test(loopVerdict(run).headline);
  return stages;
}

const ALL_PASS = { scan: true, plan: true, fix: true, rescan: true, ending: true };

describe("G1: the fix loop on a fresh app", () => {
  it("passes every stage, with an old report in the tree", async () => {
    expect(await walk(freshApp())).toEqual(ALL_PASS);
  });

  it("exits 1 from the CLI, and the branch holds the fixes", async () => {
    const repo = freshApp();
    let status = 0;
    try {
      execFileSync(process.execPath, [resolve("bin/penthera.js"), "agent", "--loop", "--repo", repo], {
        input: "y\n".repeat(30), encoding: "utf-8", stdio: ["pipe", "pipe", "ignore"],
        env: { ...process.env, NO_COLOR: "1", PENTHERA_HOME: temp() },
      });
    } catch (e) { status = e.status; }
    expect(status).toBe(1);
    expect(git(repo, "rev-list", "--count", "main..HEAD").trim()).not.toBe("0");
    expect(git(repo, "status", "--porcelain").trim()).toBe("?? reports/");
  });
});

describe("G2: each stage can fail", () => {
  it("scan: a scanner that finds nothing fails the scan stage", async () => {
    const stages = await walk(freshApp(), { scan: async () => ({ findings: [] }) });
    expect(stages.scan).toBe(false);
  });

  it("fix: declining every diff fails the fix stage", async () => {
    const stages = await walk(freshApp(), { ask: async () => "n" });
    expect(stages.fix).toBe(false);
    expect(stages.rescan).toBe(false);
  });

  it("fix: a dirty tree fails it, as the reports/ bug did", async () => {
    const repo = freshApp();
    writeFileSync(join(repo, "scratch.js"), "work in progress\n");
    expect((await walk(repo)).fix).toBe(false);
  });

  it("fix: a tree that goes dirty during a run stops it at the first fix", async () => {
    const repo = freshApp();
    let asked = 0;
    const stages = await walk(repo, { ask: async () => { asked++; writeFileSync(join(repo, "scratch.js"), "mine\n"); return "y"; } });
    expect(stages.fix).toBe(false);
    expect(asked).toBe(1);
  });

  it("fix: a re-scan that still sees the finding reverts the fix", async () => {
    const repo = freshApp();
    const stale = await scanRepo(repo);
    const stages = await walk(repo, { deps: { scanRepo: async () => stale } });
    expect(stages.fix).toBe(false);
    expect(git(repo, "status", "--porcelain").trim()).toBe("?? reports/");
  });

  it("ending: the check goes red when no critical is left to report", async () => {
    expect((await walk(freshApp({ critical: false }))).ending).toBe(false);
  });

  it("every recipe: the finding goes when the fix lands and comes back when it is reverted", async () => {
    const repo = freshApp({ critical: false });
    const seen = async () => {
      const scanned = await scanRepo(repo);
      return [...scanned.findings, ...probeRepo(repo)];
    };
    const { plans } = await planFixes(repo, await seen());
    expect([...new Set(plans.map((p) => p.recipe))].sort()).toEqual(RECIPES.map((r) => r.id).sort());
    for (const plan of plans) {
      const keys = plan.findings.map(findingKey);
      const present = async () => {
        const now = new Set((await seen()).map(findingKey));
        return keys.filter((k) => now.has(k));
      };
      expect(await present(), plan.recipe).toEqual(keys);
      const { files } = applyDiff(repo, plan.diff, { allowDirty: true });
      expect((await present()).length, plan.recipe).toBeLessThan(keys.length);
      restoreFiles(repo, files);
      expect(await present(), plan.recipe).toEqual(keys);
    }
    expect(readFileSync(join(repo, "server.js"), "utf-8")).toContain("h3J9sK2dLq8Wm4Zx");
  });
});
