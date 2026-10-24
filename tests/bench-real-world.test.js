/**
 * Penthera Bench v1 (bench/real-world): statistics, manifest rules, blind
 * sampling, the network guard, and a hermetic end-to-end run on fixture repos
 * built in a temp folder (git over file://, no network).
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { execFileSync, spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { wilson, newcombeDiff, cohenKappa, kishN, holm, percentile, clusterBootstrap } from "../bench/real-world/stats.js";
import { validateManifest, cacheDir, projectId, seededOrder, REPO_ROOT, readJsonl, writeJsonl, studyDir } from "../bench/real-world/lib.js";
import { drawSample, drawCalibrationRound, queueFor, blind, questionFor, buildStudy } from "../bench/real-world/units.js";
import { gate, agreement, finalLabels } from "../bench/real-world/kappa.js";
import { estimate, score } from "../bench/real-world/score.js";
import { cloneProject } from "../bench/real-world/fetch.js";
import { scanProject } from "../bench/real-world/run.js";
import { syntheticLabels } from "../bench/real-world/synthetic-labels.js";
import { excerpt, pending } from "../bench/real-world/label.js";
import { buildFixtures } from "./fixtures/deps/build.js";

const GUARD = join(REPO_ROOT, "bench", "real-world", "no-network.mjs");

describe("stats", () => {
  it("Wilson interval matches known values", () => {
    const w = wilson(0.85 * 307, 307);
    expect(w.lo).toBeCloseTo(0.8057, 3);
    expect(w.hi).toBeCloseTo(0.8856, 3);
    const z = wilson(0, 10);
    expect(z.lo).toBe(0);
    expect(z.hi).toBeCloseTo(0.2775, 3);
    expect(wilson(0, 0).p).toBeNull();
  });

  it("the E1 sample size gives a half-width of about 0.04", () => {
    const n = Math.ceil((1.96 ** 2 * 0.85 * 0.15) / 0.04 ** 2);
    expect(n).toBe(307);
    const w = wilson(0.85 * n, n);
    expect((w.hi - w.lo) / 2).toBeLessThan(0.041);
  });

  it("Newcombe method 10 reproduces Newcombe (1998), 56/70 vs 48/80", () => {
    const d = newcombeDiff(56, 70, 48, 80);
    expect(d.d).toBeCloseTo(0.2, 6);
    expect(d.lo).toBeCloseTo(0.0524, 3);
    expect(d.hi).toBeCloseTo(0.3339, 3);
  });

  it("Cohen's kappa: the textbook 2x2 example gives 0.40", () => {
    const pairs = [
      ...Array(20).fill(["yes", "yes"]), ...Array(5).fill(["yes", "no"]),
      ...Array(10).fill(["no", "yes"]), ...Array(15).fill(["no", "no"]),
    ];
    const k = cohenKappa(pairs);
    expect(k.kappa).toBeCloseTo(0.4, 6);
    expect(k.agreement).toBeCloseTo(0.7, 6);
    expect(k.lo).toBeLessThan(0.4);
    expect(k.hi).toBeGreaterThan(0.4);
  });

  it("kappa's analytic standard error agrees with a bootstrap", () => {
    const pairs = [
      ...Array(40).fill(["yes", "yes"]), ...Array(6).fill(["yes", "no"]),
      ...Array(9).fill(["no", "yes"]), ...Array(45).fill(["no", "no"]),
    ];
    const k = cohenKappa(pairs);
    const idx = pairs.map((_, i) => String(i));
    const boots = clusterBootstrap(idx, (s) => cohenKappa(s.map((i) => pairs[Number(i)])).kappa, { reps: 4000, seed: 7 });
    const mean = boots.reduce((a, b) => a + b, 0) / boots.length;
    const sd = Math.sqrt(boots.reduce((a, b) => a + (b - mean) ** 2, 0) / (boots.length - 1));
    expect(k.se).toBeGreaterThan(sd * 0.85);
    expect(k.se).toBeLessThan(sd * 1.15);
  });

  it("perfect agreement gives kappa 1; one category gives no kappa", () => {
    expect(cohenKappa([["yes", "yes"], ["no", "no"]]).kappa).toBe(1);
    expect(cohenKappa([["yes", "yes"], ["yes", "yes"]]).kappa).toBeNull();
  });

  it("Kish effective n, Holm and percentiles", () => {
    expect(kishN([1, 1, 1, 1])).toBe(4);
    expect(kishN([1, 3])).toBeCloseTo(1.6, 6);
    expect(holm([0.01, 0.04, 0.03])).toEqual([0.03, 0.06, 0.06]);
    expect(holm([0.01, null])).toEqual([0.01, null]);
    expect(percentile([1, 2, 3, 4, 5], 0.5)).toBe(3);
  });
});

describe("manifest and cache", () => {
  const good = { url: "https://github.com/acme/shop", commit: "a".repeat(40), license: "MIT", stratum: "express", framework: "express" };

  it("accepts a valid manifest and rejects bad entries", () => {
    expect(validateManifest({ version: 1, set: "pilot", projects: [good] })).toEqual([]);
    const errs = validateManifest({ version: 1, set: "pilot", projects: [
      { ...good, commit: "abc" },
      { ...good, url: "https://github.com/acme/other", license: "GPL-3.0" },
      { ...good, url: "https://gitlab.com/acme/x" },
      { ...good, url: "https://github.com/acme/y", stratum: "django" },
      good, good,
    ] });
    expect(errs.join("\n")).toMatch(/commit/);
    expect(errs.join("\n")).toMatch(/GPL-3.0/);
    expect(errs.join("\n")).toMatch(/github\.com/);
    expect(errs.join("\n")).toMatch(/stratum/);
    expect(errs.join("\n")).toMatch(/twice/);
  });

  it("file:// URLs only with allowFile", () => {
    const m = { version: 1, set: "test", projects: [{ ...good, url: "file:///tmp/x" }] };
    expect(validateManifest(m).length).toBe(1);
    expect(validateManifest(m, { allowFile: true })).toEqual([]);
  });

  it("refuses a cache inside the repository", () => {
    expect(() => cacheDir(join(REPO_ROOT, "bench", "cache"))).toThrow(/inside the Penthera repository/);
  });

  it("the committed manifests are valid and pilot projects are kept out of the E1 corpus", () => {
    const pilot = JSON.parse(readFileSync(join(REPO_ROOT, "bench/real-world/pilot/corpus.json"), "utf8"));
    const e1 = JSON.parse(readFileSync(join(REPO_ROOT, "bench/real-world/corpus.json"), "utf8"));
    expect(validateManifest(pilot)).toEqual([]);
    expect(validateManifest(e1)).toEqual([]);
    expect(pilot.set).toBe("pilot");
    const pilotUrls = new Set(pilot.projects.map((p) => p.url));
    expect(e1.projects.filter((p) => pilotUrls.has(p.url))).toEqual([]);
    expect(e1.excludedUrls || []).toEqual(expect.arrayContaining([...pilotUrls]));
  });

  it("project ids and seeded order are deterministic", () => {
    expect(projectId("https://github.com/acme/shop")).toBe("acme__shop");
    expect(projectId("file:///tmp/x/acme/shop.git")).toBe("acme__shop");
    const a = seededOrder(["a", "b", "c", "d"], "s1");
    expect(seededOrder(["d", "c", "b", "a"], "s1")).toEqual(a);
    expect(seededOrder(["a", "b", "c", "d"], "s2")).not.toEqual(a);
  });
});

function fakeProject(id, nFlagged, nCand) {
  const base = { project: id, stratum: "express", framework: "express" };
  const flagged = Array.from({ length: nFlagged }, (_, i) => ({ ...base, key: `secrets:f${i}`, category: "secrets", flagged: true, confidence: i % 2 ? "confirmed" : "potential", rules: ["r"], show: { kind: "file", path: `f${i}` } }));
  const candidates = { secrets: Array.from({ length: nCand }, (_, i) => ({ ...base, key: `secrets:u${i}`, category: "secrets", show: { kind: "file", path: `u${i}` } })), route: [], "code-pattern": [], dependency: [], "agent-config": [] };
  return { id, base, flagged, candidates, other: 0 };
}

describe("sampling and blinding", () => {
  const all = [fakeProject("p1", 7, 10), fakeProject("p2", 2, 10), fakeProject("p3", 0, 1)];

  it("caps flagged units per project per category and draws unflagged round-robin", () => {
    const s = drawSample(all, { seed: "x", unflaggedPerCategory: 4, calibrationPerCategory: 4 });
    const fl = s.analysis.filter((u) => u.flagged);
    expect(fl.filter((u) => u.project === "p1").length).toBe(3);
    expect(fl.filter((u) => u.project === "p2").length).toBe(2);
    const un = s.analysis.filter((u) => !u.flagged);
    expect(un.length).toBe(4);
    for (const p of ["p1", "p2", "p3"]) expect(un.filter((u) => u.project === p).length).toBeLessThanOrEqual(2);
    // Calibration comes from what is left, never overlapping the analysis set.
    const ids = new Set(s.analysis.map((u) => u.id));
    expect(s.calibration.length).toBe(4);
    expect(s.calibration.some((u) => ids.has(u.id))).toBe(false);
  });

  it("is deterministic for a seed and skips unreadable units", () => {
    const a = drawSample(all, { seed: "x", unflaggedPerCategory: 4 });
    const b = drawSample(all, { seed: "x", unflaggedPerCategory: 4 });
    expect(a.analysis.map((u) => u.id)).toEqual(b.analysis.map((u) => u.id));
    const c = drawSample(all, { seed: "x", unflaggedPerCategory: 4, readable: (u) => u.key !== "secrets:u0" });
    expect(c.analysis.some((u) => u.key === "secrets:u0" && !u.flagged)).toBe(false);
  });

  it("queues reveal nothing about Penthera's verdict and differ per labeller", () => {
    const s = drawSample(all, { seed: "x", unflaggedPerCategory: 4 });
    const units = [...s.calibration, ...s.analysis];
    const qa = queueFor(units, "x", "A");
    const qb = queueFor(units, "x", "B");
    for (const q of qa) {
      expect(Object.keys(q).filter((k) => k !== "round").sort()).toEqual(["category", "id", "project", "question", "set", "show"]);
      expect(JSON.stringify(q)).not.toMatch(/flagged|confidence|rules|"key"/);
    }
    expect(new Set(qa.map((q) => q.id))).toEqual(new Set(qb.map((q) => q.id)));
    expect(qa.map((q) => q.id)).not.toEqual(qb.map((q) => q.id));
    expect(qa.slice(0, s.calibration.length).every((q) => q.set === "calibration")).toBe(true);
    // Unit ids are opaque hashes, not keys.
    expect(qa.every((q) => /^[0-9a-f]{12}$/.test(q.id))).toBe(true);
  });

  it("a further calibration round is fresh: no unit from the analysis set or an earlier round", () => {
    const big = [fakeProject("p1", 12, 30), fakeProject("p2", 12, 30)];
    const s = drawSample(big, { seed: "x", unflaggedPerCategory: 4, calibrationPerCategory: 4 });
    const existing = [...s.analysis, ...s.calibration];
    const r2 = drawCalibrationRound(big, existing, { seed: "x", round: 2, perCategory: 4 });
    expect(r2.length).toBe(4);
    expect(r2.every((u) => u.round === 2 && u.set === "calibration")).toBe(true);
    const used = new Set(existing.map((u) => u.id));
    expect(r2.some((u) => used.has(u.id))).toBe(false);
    const q = queueFor([...existing, ...r2], "x", "A");
    const firstAnalysis = q.findIndex((u) => u.set === "analysis");
    expect(q.slice(0, firstAnalysis).map((u) => u.round || 1)).toEqual([...q.slice(0, firstAnalysis).map((u) => u.round || 1)].sort());
  });

  it("asks flagged and unflagged units of a category the same question", () => {
    const f = all[0].flagged[0];
    const u = all[0].candidates.secrets[0];
    expect(questionFor(f)).toBe(questionFor(u));
    const d1 = { category: "dependency", package: "x", version: "1.0.0", capability: "network", ecosystem: "npm" };
    expect(questionFor(d1)).toMatch(/x@1\.0\.0 have this capability: network/);
    expect(blind({ ...f, id: "i", set: "analysis", question: "q" })).not.toHaveProperty("flagged");
  });

  it("label tool helpers: excerpt marks lines and pending resumes", () => {
    const e = excerpt("a\nGET /api/x\nb", { mark: "x" });
    expect(e.split("\n")[1].startsWith(">")).toBe(true);
    const q = [{ id: "1", set: "calibration" }, { id: "2", set: "calibration" }, { id: "3", set: "analysis" }];
    expect(pending(q, [{ id: "1" }], "calibration").map((x) => x.id)).toEqual(["2"]);
  });
});

describe("agreement, gate and scoring", () => {
  const units = Array.from({ length: 20 }, (_, i) => ({ id: `u${i}`, set: i < 10 ? "calibration" : "analysis", category: "secrets", project: `p${i % 4}`, flagged: i % 2 === 0, confidence: "confirmed", stratum: "express" }));
  const lab = (L, f) => units.map((u, i) => ({ id: u.id, labeller: L, set: u.set, correct: f(u, i), actionable: f(u, i) === "yes" ? "yes" : null }));

  it("the gate passes on full agreement and fails on chance-level agreement", () => {
    const A = lab("A", (u) => (u.flagged ? "yes" : "no"));
    expect(gate(agreement(units, A, A, "calibration")).passed).toBe(true);
    const B = lab("B", (u, i) => (i % 3 === 0 ? "yes" : "no"));
    expect(gate(agreement(units, A, B, "calibration")).passed).toBe(false);
    expect(gate(agreement(units, A, A.slice(0, 5), "calibration")).passed).toBe(false); // incomplete
  });

  it("final labels use agreement, then adjudication; the rest is unresolved", () => {
    const A = lab("A", () => "yes");
    const B = lab("B", (u, i) => (i === 10 || i === 11 ? "no" : "yes"));
    const r = finalLabels(units, A, B, [{ id: "u10", correct: "no", actionable: null, by: "C", reason: "test" }]);
    expect(r.labels.get("u10").correct).toBe("no");
    expect(r.labels.has("u11")).toBe(false);
    expect(r.unresolved).toBe(1);
  });

  it("estimates precision (stratified) and recall from the unflagged sample", () => {
    const pop = { p1: { flagged: { secrets: 10, route: 10 }, unflagged: { secrets: 100, route: 0 } } };
    const rows = [
      ...Array(8).fill({ project: "p1", category: "secrets", flagged: true, correct: true }),
      ...Array(2).fill({ project: "p1", category: "secrets", flagged: true, correct: false }),
      ...Array(5).fill({ project: "p1", category: "route", flagged: true, correct: true }),
      ...Array(5).fill({ project: "p1", category: "route", flagged: true, correct: false }),
      ...Array(1).fill({ project: "p1", category: "secrets", flagged: false, correct: true }),
      ...Array(19).fill({ project: "p1", category: "secrets", flagged: false, correct: false }),
    ];
    const e = estimate(rows, pop, ["p1"]);
    expect(e.precision).toBeCloseTo(0.5 * 0.8 + 0.5 * 0.5, 6);
    expect(e.nEff).toBeCloseTo(20, 6);
    // Secrets: TP = 0.8 × 10 = 8, FN = 0.05 × 100 = 5 → 8/13. Route has no unflagged sample.
    expect(e.recall).toBeCloseTo(8 / 13, 6);
  });
});

describe("network guard", () => {
  it("refuses non-loopback connections and DNS, and logs them", () => {
    const dir = mkdtempSync(join(tmpdir(), "bench-guard-"));
    const log = join(dir, "net.jsonl");
    const code = `
      const r = [];
      try { await fetch("http://203.0.113.7/"); r.push("fetch ok"); } catch (e) { r.push("fetch refused " + (e.cause?.code || e.code)); }
      await new Promise((res) => require("node:dns").lookup("example.com", (e) => { r.push(e ? "dns refused" : "dns ok"); res(); }));
      const http = require("node:http");
      const srv = http.createServer((q, s) => s.end("hi")).listen(0, "127.0.0.1");
      await new Promise((res) => srv.on("listening", res));
      const body = await (await fetch("http://127.0.0.1:" + srv.address().port + "/")).text();
      r.push("loopback " + body);
      srv.close();
      console.log(JSON.stringify(r));
    `;
    const out = spawnSync(process.execPath, ["--import", GUARD, "--input-type=commonjs", "-e", `(async () => { ${code} })()`], { env: { ...process.env, PENTHERA_BENCH_NET_LOG: log }, encoding: "utf8", timeout: 20000 });
    const r = JSON.parse(out.stdout.trim().split("\n").pop());
    expect(r[0]).toMatch(/fetch refused/);
    expect(r[1]).toBe("dns refused");
    expect(r[2]).toBe("loopback hi");
    expect(readFileSync(log, "utf8").trim().split("\n").length).toBeGreaterThanOrEqual(2);
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("end to end on fixture repos (hermetic)", () => {
  let tmp;
  let cache;
  let manifest;

  function commitRepo(dir) {
    const env = { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.invalid", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.invalid", GIT_CONFIG_GLOBAL: "/dev/null" };
    const g = (...a) => execFileSync("git", ["-c", "init.defaultBranch=main", ...a], { cwd: dir, env }).toString().trim();
    g("init", "-q");
    g("add", "-A", "-f");
    g("commit", "-q", "-m", "fixture");
    return g("rev-parse", "HEAD");
  }

  beforeAll(() => {
    tmp = mkdtempSync(join(tmpdir(), "bench-e2e-"));
    cache = join(tmp, "cache");
    const src = join(tmp, "src");
    // Project 1: the Next.js fix fixture plus an agent config.
    const next = join(src, "acme", "next-app");
    cpSync(join(REPO_ROOT, "tests/fixtures/fix/next"), next, { recursive: true });
    writeFileSync(join(next, ".mcp.json"), JSON.stringify({ mcpServers: { fs: { command: "npx", args: ["-y", "some-mcp-server"] } } }));
    writeFileSync(join(next, "AGENTS.md"), "# Agents\nUse the formatter.\n");
    // Project 2: a lockfile-only npm project whose sources come from the npm cache.
    const deps = buildFixtures(join(tmp, "deps"));
    const api = join(src, "acme", "express-api");
    cpSync(deps.baseLockOnly, api, { recursive: true });
    mkdirSync(join(api, "routes"), { recursive: true });
    writeFileSync(join(api, "routes", "users.js"), "const express = require('express');\nconst router = express.Router();\nrouter.get('/users/:id', (req, res) => res.json({ id: req.params.id }));\nmodule.exports = router;\n");
    mkdirSync(join(cache, "npm-cache"), { recursive: true });
    cpSync(deps.cache, join(cache, "npm-cache"), { recursive: true });
    manifest = {
      version: 1,
      set: "test",
      projects: [
        { url: `file://${next}`, commit: commitRepo(next), license: "MIT", stratum: "nextjs", framework: "nextjs" },
        { url: `file://${api}`, commit: commitRepo(api), license: "MIT", stratum: "express", framework: "express" },
      ],
    };
    expect(validateManifest(manifest, { allowFile: true })).toEqual([]);
  }, 60000);

  afterAll(() => { if (tmp) rmSync(tmp, { recursive: true, force: true }); });

  it("fetches, scans offline, samples blind, scores, and writes only aggregates", () => {
    const scanner = { bin: join(REPO_ROOT, "bin", "penthera.js"), version: "dev", integrity: null, frozen: false };
    for (const p of manifest.projects) {
      const c = cloneProject(p, cache, { allowFile: true });
      expect(c.status).toBe("cloned");
      expect(cloneProject(p, cache, { allowFile: true }).status).toBe("cached");
      const m = scanProject(p, { cache, set: "test", scanner, timeoutMs: 120000 });
      expect(m.networkRefusals).toBe(0);
      expect(m.scans.repo.ok).toBe(true);
      expect(m.scans.agents.ok).toBe(true);
      expect(m.scans.deps.ok || m.scans.deps.noInput).toBe(true);
    }
    // A clone at the wrong commit is refused.
    expect(() => cloneProject({ ...manifest.projects[0], url: manifest.projects[0].url, commit: "b".repeat(40) }, join(tmp, "cache2"), { allowFile: true })).toThrow();

    const { population, units } = buildStudy({ manifest, cache, seed: "e2e", config: { unflaggedPerCategory: 6, calibrationPerCategory: 4 } });
    const pop = population.projects;
    expect(pop["acme__next-app"].flagged.secrets).toBeGreaterThan(0);
    expect(pop["acme__next-app"].flagged["agent-config"]).toBeGreaterThan(0);
    expect(pop["acme__express-api"].unflagged.dependency).toBeGreaterThan(0);
    expect(units.some((u) => u.category === "dependency" && !u.flagged)).toBe(true);
    // Dependency units have their package unpacked for the labeller.
    expect(existsSync(join(studyDir(cache, "test"), "packages"))).toBe(true);

    expect(() => buildStudy({ manifest, cache, seed: "e2e" })).toThrow(/already exists/);
    const out = studyDir(cache, "test");
    const qa = readJsonl(join(out, "queue-A.jsonl"));
    expect(qa.length).toBe(units.length);
    expect(JSON.stringify(qa)).not.toMatch(/"flagged"|"confidence"/);

    const { A, B } = syntheticLabels(units, 3);
    writeJsonl(join(out, "synthetic", "labels-A.jsonl"), A);
    writeJsonl(join(out, "synthetic", "labels-B.jsonl"), B);
    const { md, results } = score({ manifest, cache, labelsDir: join(out, "synthetic"), reps: 200, synthetic: true, outPath: join(REPO_ROOT, "bench/real-world/pilot/RESULTS.md") });
    expect(md).toMatch(/Pipeline check with synthetic labels/);
    expect(md).toMatch(/## Precision/);
    expect(md).toMatch(/Network connections refused during scans: \*\*0\*\*/);
    expect(md).toMatch(/\.\.\/\.\.\/\.\.\/docs\/research\/prereg\/E1-real-world-accuracy\.md/);
    expect(results.main.precision).toBeGreaterThanOrEqual(0);
    // Aggregates only: no file paths or package names from the corpus.
    expect(md).not.toMatch(/route\.ts|\.mcp\.json|tiny-format|net-helper/);
  }, 180000);
});
