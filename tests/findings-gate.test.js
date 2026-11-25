/**
 * The findings gate (scripts/ci/findings-gate.mjs) and the decoy corpus
 * (tests/corpus/code-cases.js).
 *
 * The gate compares this branch with its base, so it needs git and runs in CI
 * (`npm run findings:gate`). Here: its comparison, its allow list, a run of the
 * real corpus against a scanner that a decoy can silence, and the decoys
 * against this tree's own rules.
 */
import { describe, it, expect, afterAll } from "vitest";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { compareFindings, findingKey, loadCorpus, loadScanners, readAllow, runGate } from "../scripts/ci/findings-gate.mjs";
import { CODE_CASES, DECOYS, codeCases, withDecoy } from "./corpus/code-cases.js";

const ROOT = join(import.meta.dirname, "..");
const temps = [];
afterAll(() => { for (const d of temps) rmSync(d, { recursive: true, force: true }); });
const tempDir = () => { const d = mkdtempSync(join(tmpdir(), "penthera-gate-test-")); temps.push(d); return d; };
const f = (templateId, file, severity) => ({ templateId, file, severity });

describe("findings gate: what counts as lost", () => {
  it("reports a finding the base has and the target lacks, and one the target lowers", () => {
    const base = [f("a", "x.js", "high"), f("b", "x.js", "high"), f("c", "y.js", "medium")];
    const target = [f("a", "x.js", "high"), f("b", "x.js", "low"), f("d", "z.js", "critical")];
    expect(compareFindings(base, target)).toEqual([
      { kind: "lowered", key: "b in x.js", was: "high", now: "low" },
      { kind: "lost", key: "c in y.js", was: "medium", now: null },
    ]);
  });

  it("is quiet when the target reports the same or more, at the same or a higher severity", () => {
    const base = [f("a", "x.js", "medium")];
    expect(compareFindings(base, [f("a", "x.js", "medium"), f("e", "x.js", "low")])).toEqual([]);
    expect(compareFindings(base, [f("a", "x.js", "critical")])).toEqual([]);
    expect(compareFindings([], [f("a", "x.js", "low")])).toEqual([]);
  });

  it("keys a finding by rule and file, whichever fields the scanner filled", () => {
    expect(findingKey({ templateId: "r", file: "a.js", url: "u" })).toBe("r in a.js");
    expect(findingKey({ pattern: "command-injection", url: "s.js" })).toBe("command-injection in s.js");
    expect(findingKey({ category: "rate-limiting", title: "Public endpoint without rate limiting: /api/x", url: "/api/x" })).toBe("rate-limiting:Public endpoint without rate limiting in /api/x");
  });

  it("counts the same rule in the same file once, at its highest severity", () => {
    expect(compareFindings([f("a", "x.js", "low"), f("a", "x.js", "high")], [f("a", "x.js", "medium")])).toEqual([{ kind: "lowered", key: "a in x.js", was: "high", now: "medium" }]);
  });
});

describe("findings gate: the allow list", () => {
  it("needs a case, a rule and a real reason", () => {
    const file = join(tempDir(), "allow.json");
    writeFileSync(file, JSON.stringify([{ case: "code: x", rule: "r", reason: "too short" }]));
    expect(() => readAllow(file)).toThrow(/reason of 20 characters/);
    writeFileSync(file, JSON.stringify([{ case: "code: x", rule: "r", reason: "the base reported a test fixture, not a webhook" }]));
    expect(readAllow(file)).toHaveLength(1);
    expect(readAllow(join(tempDir(), "missing.json"))).toEqual([]);
  });

  it("the checked-in list is valid", () => {
    expect(() => readAllow()).not.toThrow();
  });
});

describe("findings gate: on the real corpus", () => {
  it("passes this tree against itself, and catches a scanner that a decoy silences", async () => {
    const corpus = await loadCorpus(ROOT);
    expect(corpus.length).toBeGreaterThan(100);
    const real = await loadScanners(ROOT);
    const same = await runGate({ base: real, target: real, corpus });
    expect(same.problems).toEqual([]);

    // The bypass Vercel found on 22 Nov 2026 (01M81DE1ZQ25A0CTBBY691821B), as a scanner:
    // a login URL getter in the file hides the webhook finding.
    const silenced = {
      ...real,
      scanRepo: async (dir) => {
        const findings = await real.scanRepo(dir);
        const texts = walk(dir).map((p) => readFileSync(p, "utf-8")).join("\n");
        return texts.includes("getLoginUrl(") ? findings.filter((x) => x.templateId !== "webhook-signature-missing") : findings;
      },
    };
    const r = await runGate({ base: real, target: silenced, corpus });
    const lost = r.problems.map((p) => `${p.kind} ${p.case}`);
    expect(lost).toContain("lost code: unsigned webhook, Next route + a login URL getter");
    expect(lost).toContain("lost code: unsigned webhook, Express route + a login URL getter");
    expect(r.problems.every((p) => p.case.includes("a login URL getter"))).toBe(true);

    // An allow entry moves a loss out of the problems, and only that one.
    const allowed = await runGate({ base: real, target: silenced, corpus, allow: [{ case: r.problems[0].case, rule: r.problems[0].key.split(" in ")[0], reason: "a reason long enough to count" }] });
    expect(allowed.allowed).toHaveLength(1);
    expect(allowed.problems).toHaveLength(r.problems.length - 1);
  }, 120_000);

  it("a target scan that throws loses what the base found", async () => {
    const corpus = [{ name: "code: one", kind: "repo", files: { "a.js": "x" } }];
    const base = { scanRepo: async () => [f("a", "a.js", "high")], scanAgents: async () => [] };
    const target = { scanRepo: async () => { throw new Error("boom"); }, scanAgents: async () => [] };
    const r = await runGate({ base, target, corpus });
    expect(r.problems).toEqual([{ case: "code: one", kind: "lost", key: "a in a.js", was: "high", now: null }]);
  });
});

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) walk(full, out);
    else out.push(full);
  }
  return out;
}

// ── decoys against this tree's own rules ──────────────────────────────────

// Look-alikes that silence a rule on main today, each with the pull request that fixes it.
// Empty since PR 336 merged (22 Nov). A decoy that silences a rule and is not listed here
// fails the test.
const KNOWN_SILENCED = new Set([]);
// The rate-limit note reads a line count, so a comment line can move it: not a rule being silenced.
const NOT_A_RULE = /^rate-limiting:/;

describe("decoys: a line named like a check never silences a rule", () => {
  it("every code case fires at least one rule, so the corpus tests something", async () => {
    const { scanRepo } = await loadScanners(ROOT);
    const quiet = [];
    for (const c of CODE_CASES) {
      const dir = write(c.files);
      if (!(await scanRepo(dir)).some((x) => x.templateId || x.pattern)) quiet.push(c.name);
    }
    expect(quiet).toEqual([]);
  }, 60_000);

  it("adds each decoy as the first statement of the first block", () => {
    expect(withDecoy("function a() {\n  b();\n}\n", "x();")).toBe("function a() {\n  x();\n  b();\n}\n");
    expect(withDecoy("on: push\n", "x();")).toBeNull();
    expect(codeCases().length).toBeGreaterThan(CODE_CASES.length + DECOYS.length);
  });

  it("no decoy silences a rule, apart from the known ones", async () => {
    const { scanRepo } = await loadScanners(ROOT);
    const rules = async (files) => new Set((await scanRepo(write(files))).map((x) => findingKey(x).split(" in ")[0]).filter((r) => !NOT_A_RULE.test(r)));
    const plain = new Map();
    for (const c of CODE_CASES) plain.set(c.name, await rules(c.files));
    const silenced = [];
    for (const c of codeCases().slice(CODE_CASES.length)) {
      const got = await rules(c.files);
      for (const rule of plain.get(c.name.split(" + ")[0])) if (!got.has(rule)) silenced.push(`${c.name}: ${rule}`);
    }
    expect(silenced.filter((s) => !KNOWN_SILENCED.has(s)), "a decoy silenced a rule: tie the silencer to the request, or it is a bypass").toEqual([]);
  }, 120_000);
});

function write(files) {
  const dir = tempDir();
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), text);
  }
  return dir;
}
