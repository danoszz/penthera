/**
 * 2.3.2, group 2: false cleans and gate bypasses found in Vercel's review
 * (B01, B07, A07, C03 in the secret scan; B02 deps; B03 baseline; B04
 * suppressions; B05 the giants merge). Each test failed on the code before.
 */
import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { execFileSync } from "node:child_process";
import {
  scanSecrets, findSecretsInText, maskMatch, isSecretScanTarget, isShapesOnlyFile, secretRulesFor, isSecretSkipDir,
} from "../lib/whitebox/secrets.js";
import { gitIgnored } from "../lib/git.js";
import { riskFindings } from "../lib/deps/findings.js";
import { compareWithBaseline } from "../src/cli/baseline.js";
import { findingId, isSuppressed, withRepoSuppressions, buildViews, suppressionCovers } from "../lib/memory/views.js";
import { parseRepoSuppressions } from "../lib/memory/repo-suppress.js";
import { mergePentheraFirst } from "../lib/giants/merge.js";
import { makeFinding } from "../lib/giants/finding.js";
import { dedupeFindings } from "../src/cli/merge-results.js";
import { cpuMs } from "./fixtures/cpu-time.js";

// Built from parts so this file is not itself a finding.
const AWS = ["AKIA", "Q3EGRZ7XN", "BCD", "PLMQ"].join("");
const PW = ["Xk92", "-prod-Pw!"].join("");

function repo(files) {
  const dir = mkdtempSync(join(tmpdir(), "pen-232-"));
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  return dir;
}
const titles = (fs) => fs.map((f) => `${f.url}|${f.title}`).sort();
const hasGit = (() => { try { execFileSync("git", ["--version"], { stdio: "ignore" }); return true; } catch { return false; } })();

describe("B01: build, vendor, coverage and reports folders", () => {
  it("are read below the repo root, with every rule", () => {
    const dir = repo({
      "src/vendor/keys.js": `const k = "${AWS}";\n`,
      "app/api/build/route.ts": `const password = "${PW}";\n`,
      "src/coverage/x.js": `export const k = "${AWS}";\n`,
      "lib/reports/r.js": `const k = "${AWS}";\n`,
      "pkg/dist/d.js": `const k = "${AWS}";\n`,
    });
    try {
      expect(titles(scanSecrets(dir))).toEqual([
        "app/api/build/route.ts|Hardcoded password in source",
        "lib/reports/r.js|AWS access key in source",
        "pkg/dist/d.js|AWS access key in source",
        "src/coverage/x.js|AWS access key in source",
        "src/vendor/keys.js|AWS access key in source",
      ]);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it("at the repo root run the fixed-shape rules, not the guesses", () => {
    const dir = repo({
      "dist/app.js": `const k = "${AWS}";\n`,
      "vendor/conf.js": `const password = "${PW}";\n`,
    });
    try {
      expect(titles(scanSecrets(dir))).toEqual(["dist/app.js|AWS access key in source"]);
    } finally { rmSync(dir, { recursive: true, force: true }); }
    expect(secretRulesFor("dist/app.js")).toBe("shapes");
    expect(secretRulesFor("src/dist/app.js")).toBe("all");
    expect(isSecretScanTarget("vendor/a/b.go")).toBe(true);
    expect(isShapesOnlyFile("coverage/lcov.json")).toBe(true);
    // Self-review: a .env file gets every rule, even in a root build folder.
    expect(isShapesOnlyFile("dist/.env")).toBe(false);
    expect(isShapesOnlyFile("build/.env.production")).toBe(false);
    expect(isSecretSkipDir("vendor")).toBe(false);
    // Dependencies and caches stay skipped at any depth.
    expect(isSecretScanTarget("node_modules/x/a.js")).toBe(false);
    expect(isSecretScanTarget("a/node_modules/x/a.js")).toBe(false);
    expect(isSecretSkipDir("node_modules")).toBe(true);
  });

  it.skipIf(!hasGit)("skips a root build folder git ignores, and reads a tracked one", () => {
    const dir = repo({ ".gitignore": "dist/\n", "dist/app.js": `const k = "${AWS}";\n`, "build/app.js": `const k = "${AWS}";\n` });
    try {
      execFileSync("git", ["init", "-q"], { cwd: dir });
      expect(titles(scanSecrets(dir, { ignored: gitIgnored(dir) }))).toEqual(["build/app.js|AWS access key in source"]);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});

describe("B01: the coverage ledger says what the secret scan read", () => {
  it("counts build folders as read, and notes the shape-only root ones", async () => {
    const { buildCoverage, describeCoverage, fileCoverage } = await import("../lib/coverage.js");
    const dir = repo({ "dist/app.js": "x\n", "src/vendor/v.js": "x\n", "src/app.js": "x\n", "node_modules/x/i.js": "x\n" });
    try {
      const { files } = fileCoverage(dir, {});
      expect(files.get("dist/app.js").secrets).toBe("examined");
      expect(files.get("src/vendor/v.js").secrets).toBe("examined");
      const cov = buildCoverage(dir, {});
      expect(cov.excludedDirs).toEqual(["node_modules"]);
      expect(cov.rootOutputDirs).toEqual(["dist"]);
      expect(cov.sourceFiles).toBe(1); // build output is not counted as source, as before
      expect(describeCoverage(cov).map((l) => l.text).join(" ")).toMatch(/only the fixed-shape rules .* in dist\/ at the repo root/);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});

describe("B07: translation folders", () => {
  it("run only the shape rules on translation file types, never on code or .env", () => {
    expect(isShapesOnlyFile("src/locales/de.json")).toBe(true);
    expect(isShapesOnlyFile("i18n/de.yaml")).toBe(true);
    expect(isShapesOnlyFile("lang/messages.properties")).toBe(true);
    expect(isShapesOnlyFile("i18n/de.po")).toBe(true);
    expect(isShapesOnlyFile("app/i18n/messages.js")).toBe(false);
    expect(isShapesOnlyFile("lang/server.ts")).toBe(false);
    expect(isShapesOnlyFile("lang/.env")).toBe(false);
    expect(isShapesOnlyFile("locales/.env.production")).toBe(false);
  });

  it("finds a password in .env and code under lang/", () => {
    const dir = repo({ "lang/.env": `DB_PASSWORD=${PW}\n`, "i18n/db.ts": `const password = "${PW}";\n` });
    try {
      expect(titles(scanSecrets(dir))).toEqual(["i18n/db.ts|Hardcoded password in source", "lang/.env|Hardcoded password in source"]);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});

describe("A07: a short fallback secret", () => {
  const SHORT = ["kq7", "Zp9"].join("");
  it("masks the quoted literal after process.env.X ||", () => {
    for (const op of ["||", "??"]) {
      const m = maskMatch(`secret: process.env.SESSION_SECRET ${op} '${SHORT}'`);
      expect(m).not.toMatch(/Zp9|p9|7Zp/);
      expect(m).toBe(`secret: process.env.SESSION_SECRET ${op} '***'`);
    }
    // A long literal keeps the usual first and last 4.
    expect(maskMatch(`secret: process.env.X || '${"aB3d".repeat(6)}'`)).toBe(`secret: process.env.X || 'aB3d…aB3d'`);
  });

  it("in a repo scan report", () => {
    const dir = repo({ "server.js": `app.use(session({ secret: process.env.SESSION_SECRET || '${SHORT}' }));\n` });
    try {
      const fs = scanSecrets(dir);
      expect(fs.map((f) => f.title)).toEqual(["Hardcoded session secret in source"]);
      expect(fs[0].description).not.toMatch(/Zp9/);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});

describe("C03: line numbers stay linear", () => {
  const L = "BCDFGHJKLM";
  const aws = (i) => `"AKIAQ3EGRZ7XN${String(i).padStart(3, "0").replace(/\d/g, (d) => L[d])}PLMQ"`;
  const keys = Array.from({ length: 200 }, (_, i) => `k${i}=${aws(i)}`).join("\n");

  // Linear, measured as growth: twice the input may take about twice the time,
  // never four times (the old line counting was quadratic: 26.7 s at 2 MB).
  // An absolute budget failed on CI's Node 22, whose regex engine is ~50x
  // slower here than Node 24+ while still linear (3 to 6.6 s, 5 Nov 2026).
  it("scanSecrets on 2 MB of newlines and 200 keys", () => {
    const one = repo({ "config.js": "\n".repeat(1024 * 1024) + keys + "\n" }); // 1 MB against 2 MB
    const two = repo({ "config.js": "\n".repeat(2 * 1024 * 1024) + keys + "\n" });
    try {
      let f;
      const t1 = cpuMs(() => scanSecrets(one), { runs: 2 });
      const t2 = cpuMs(() => { f = scanSecrets(two); }, { runs: 2 });
      expect(f[0].line).toBe(2 * 1024 * 1024 + 1);
      expect(f[0].lines).toHaveLength(200);
      expect(f[0].lines.at(-1)).toBe(2 * 1024 * 1024 + 200);
      expect(t2, `1 MB: ${t1} ms, 2 MB: ${t2} ms`).toBeLessThan(3 * t1 + 300);
      expect(t2).toBeLessThan(15_000);
    } finally {
      rmSync(one, { recursive: true, force: true });
      rmSync(two, { recursive: true, force: true });
    }
  }, 90_000); // four scans; Node 22 takes 3 to 6 s for each 2 MB one

  it("findSecretsInText with a \\u escape (the decoded pass)", () => {
    const body = "\\u0041\n" + "\n".repeat(2 * 1024 * 1024) + keys;
    let hits;
    const ms = cpuMs(() => { hits = findSecretsInText(body, { shapesOnly: true }); }, { runs: 2 });
    expect(hits).toHaveLength(200);
    expect(ms).toBeLessThan(1500);
  });

  it("decoded hits still point at the start of their line", () => {
    const text = `a\nb\nconst k = "\\u0041${AWS.slice(1)}";\n`;
    const hits = findSecretsInText(text);
    expect(hits).toHaveLength(1);
    expect(hits[0].index).toBe(4);
  });
});

describe("B02: the @anthropic-ai exemption", () => {
  const caps = { "ai-config-write": { evidence: [{ file: "x/cli.js", line: 1, snippet: "writeFileSync('.claude/settings.json')" }] } };
  const pkg = (o) => ({ version: "1.0.0", ecosystem: "npm", capabilities: caps, ...o });
  const crit = (p) => riskFindings(p).filter((f) => f.severity === "critical").length;
  const real = { name: "@anthropic-ai/claude-code", path: "node_modules/@anthropic-ai/claude-code", manifestName: "@anthropic-ai/claude-code", resolved: "https://registry.npmjs.org/@anthropic-ai/claude-code/-/claude-code-1.0.0.tgz" };

  it("holds when lock key, installed name and resolved URL agree", () => {
    expect(crit(pkg(real))).toBe(0);
  });

  it("does not hold on the lockfile name alone", () => {
    expect(crit(pkg({ ...real, path: "node_modules/claude-c0de" }))).toBe(1);
    expect(crit(pkg({ ...real, manifestName: "claude-c0de" }))).toBe(1);
    expect(crit(pkg({ ...real, manifestName: undefined }))).toBe(1);
    expect(crit(pkg({ ...real, resolved: "https://registry.npmjs.org/claude-c0de/-/claude-c0de-1.0.0.tgz" }))).toBe(1);
    expect(crit(pkg({ ...real, resolved: null }))).toBe(1);
    expect(crit(pkg({ ...real, resolved: "https://evil.example/x.tgz#/@anthropic-ai/claude-code/-/" }))).toBe(1);
    expect(crit(pkg({ ...real, resolved: "https://evil.example/@anthropic-ai/claude-code/-/claude-code-1.0.0.tgz" }))).toBe(1);
    expect(crit(pkg({ ...real, resolved: "http://registry.npmjs.org/@anthropic-ai/claude-code/-/claude-code-1.0.0.tgz" }))).toBe(1);
    expect(crit(pkg({ ...real, resolved: "https://registry.npmjs.org/evil/-/x.tgz?/@anthropic-ai/claude-code/-/claude-code-1.0.0.tgz" }))).toBe(1);
    // npm's %2f form of a scoped tarball path is the same package.
    expect(crit(pkg({ ...real, resolved: "https://registry.npmjs.org/@anthropic-ai%2fclaude-code/-/claude-code-1.0.0.tgz" }))).toBe(0);
    expect(crit(pkg({ ...real, name: "@anthropic-ai/claude-code", path: "node_modules/@anthropic-ai/other", manifestName: "@anthropic-ai/other" }))).toBe(1);
  });
});

describe("B03: --baseline counts an escalated finding as new", () => {
  const base = (findings) => {
    const dir = mkdtempSync(join(tmpdir(), "pen-232-b-"));
    const p = join(dir, "base.json");
    writeFileSync(p, JSON.stringify({ findings }));
    return { p, done: () => rmSync(dir, { recursive: true, force: true }) };
  };
  const f = { source: "secret-scan", category: "secrets", url: ".env", title: "Stripe secret key in source", description: "Possible secret in `.env`: `***`" };

  it("severity above the baseline's is new", () => {
    const b = base([{ ...f, severity: "low", localOnly: true }]);
    try {
      const r = compareWithBaseline([{ ...f, severity: "critical" }], b.p);
      expect(r.newFindings).toHaveLength(1);
      expect(r.unchangedFindings).toHaveLength(0);
      const same = compareWithBaseline([{ ...f, severity: "low" }], b.p);
      expect(same.newFindings).toHaveLength(0);
      const lower = compareWithBaseline([{ ...f, severity: "info" }], b.p);
      expect(lower.newFindings).toHaveLength(0);
    } finally { b.done(); }
  });

  it("a second secret of the same rule in the same file is new", () => {
    const b = base([{ ...f, severity: "critical", line: 3 }]);
    try {
      expect(compareWithBaseline([{ ...f, severity: "critical", line: 3, lines: [3, 9] }], b.p).newFindings).toHaveLength(1);
      expect(compareWithBaseline([{ ...f, severity: "critical", line: 5 }], b.p).newFindings).toHaveLength(0);
      expect(compareWithBaseline([{ ...f, severity: "critical", line: 3, description: "Possible secret in `.env`: `sk_l…9xQz`" }], b.p).newFindings).toHaveLength(1);
    } finally { b.done(); }
  });

  it("a new sink call in a file that already had one is new", () => {
    const sink = { source: "static-analysis", category: "code-pattern", url: "lib/run.js", title: "command-injection in lib/run.js", pattern: "command-injection", severity: "medium" };
    const b = base([{ ...sink, description: "A code-execution sink in `lib/run.js` takes a value Penthera cannot trace to a constant: exec on line 3." }]);
    try {
      expect(compareWithBaseline([{ ...sink, description: "A code-execution sink in `lib/run.js` takes a value Penthera cannot trace to a constant: exec on line 7." }], b.p).newFindings).toHaveLength(0);
      expect(compareWithBaseline([{ ...sink, description: "A code-execution sink in `lib/run.js` takes a value Penthera cannot trace to a constant: exec on line 3, execSync on line 9." }], b.p).newFindings).toHaveLength(1);
    } finally { b.done(); }
  });
});

describe("B04: a suppression stops at the severity it was given", () => {
  const low = { severity: "low", title: "Stripe secret key in source", url: ".env.production", category: "secrets", source: "secret-scan", localOnly: true };
  const crit = { ...low, severity: "critical", localOnly: undefined };

  it("an old entry without a severity applies up to medium only", () => {
    const v = withRepoSuppressions({ suppressions: [] }, [{ id: findingId(low), reason: "local dev key" }]);
    expect(isSuppressed(low, v)).toBeTruthy();
    expect(isSuppressed({ ...low, severity: "medium" }, v)).toBeTruthy();
    expect(isSuppressed({ ...low, severity: "high" }, v)).toBe(null);
    expect(isSuppressed(crit, v)).toBe(null);
  });

  it("an entry with a severity applies up to that severity", () => {
    const v = withRepoSuppressions({ suppressions: [] }, [{ id: findingId(low), reason: "local dev key", severity: "low" }]);
    expect(isSuppressed(low, v)).toBeTruthy();
    expect(isSuppressed({ ...low, severity: "medium" }, v)).toBe(null);
    const c = withRepoSuppressions({ suppressions: [] }, [{ id: findingId(low), reason: "fixture key", severity: "critical" }]);
    expect(isSuppressed(crit, c)).toBeTruthy();
  });

  it("an unknown finding severity is never under the cap", () => {
    expect(suppressionCovers({ severity: "critical" }, { severity: "weird" })).toBe(false);
    expect(suppressionCovers({}, {})).toBe(false);
  });

  it("memory events and the repo file keep the severity", () => {
    const v = buildViews([{ type: "fp_suppressed", ts: "2026-11-01T00:00:00Z", data: { id: findingId(low), reason: "r", severity: "high" } }], { now: "2026-11-02T00:00:00Z" });
    expect(v.suppressions[0].severity).toBe("high");
    expect(isSuppressed({ ...low, severity: "high" }, v)).toBeTruthy();
    expect(isSuppressed(crit, v)).toBe(null);
    const r = parseRepoSuppressions(Buffer.from(JSON.stringify({ version: 1, suppress: [
      { id: "0123456789abcdef", reason: "fixture", severity: "critical" },
      { id: "0123456789abcdee", reason: "fixture", severity: "urgent" },
      { id: "0123456789abcded", reason: "fixture" },
    ] })));
    expect(r.entries.map((e) => e.severity)).toEqual(["critical", null]);
    expect(r.warnings.join(" ")).toMatch(/severity/);
  });
});

describe("B05: the giants merge keeps the higher severity", () => {
  it("a tool's critical raises Penthera's medium on the same line", () => {
    const tool = makeFinding({ tool: { id: "semgrep", version: "1" }, ruleId: "js.child-process.injection", category: "code", severity: "critical", title: "Command injection", file: "lib/run.js", line: 3, key: { cwe: ["CWE-78"] } });
    const own = { severity: "medium", title: "command-injection in lib/run.js", url: "lib/run.js", file: "lib/run.js", line: 3, pattern: "command-injection", category: "code-pattern", source: "static-analysis" };
    const r = mergePentheraFirst([own], [tool]);
    expect(r.folded).toBe(1);
    expect(r.findings[0].severity).toBe("critical");
    // Never lower: Penthera's critical stays above a tool's low.
    const r2 = mergePentheraFirst([{ ...own, severity: "critical" }], [{ ...tool, severity: "low" }]);
    expect(r2.findings[0].severity).toBe("critical");
  });
});

describe("self-review: merging scan results keeps the more severe duplicate (R10)", () => {
  it("a later critical is not dropped behind an earlier low with the same identity", () => {
    const a = { source: "secret-scan", category: "secrets", url: ".env", title: "Stripe secret key in source", severity: "low" };
    const b = { ...a, severity: "critical" };
    const other = { ...a, url: "b.js" };
    expect(dedupeFindings([a, other, b]).map((f) => `${f.url}:${f.severity}`)).toEqual([".env:critical", "b.js:low"]);
    expect(dedupeFindings([b, a]).map((f) => f.severity)).toEqual(["critical"]);
  });
});
