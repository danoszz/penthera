/**
 * `src/cli/baseline.js`: only what this run added against a baseline report
 * counts as new (`compareFindings` / `compareWithBaseline`). A finding that
 * is re-worded or re-counted must not show up as new: fingerprints come from
 * `lib/audit-loop.js`, which keys on source, category, URL and title, never
 * on the description or the severity.
 */
import { describe, it, expect, afterAll } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { compareFindings, compareWithBaseline } from "../src/cli/baseline.js";

const temps = [];
afterAll(() => { for (const d of temps) rmSync(d, { recursive: true, force: true }); });
const tempDir = () => { const d = mkdtempSync(join(tmpdir(), "penthera-baseline-test-")); temps.push(d); return d; };

const header = (o) => ({
  source: "headers", category: "headers", url: "https://shop.example/",
  title: "Missing Content-Security-Policy header", severity: "high", ...o,
});
// A secret's sites are the masked value it shows and how many lines hold it.
const secret = (o) => ({
  source: "secret-scan", category: "secrets", url: "src/app.js",
  title: "Hardcoded AWS key", severity: "high",
  description: "Possible secret in `src/app.js`: `AKIA****`", lines: [1], ...o,
});
// A sink's sites are the calls it lists, line numbers dropped.
const sink = (o) => ({
  source: "static-analysis", category: "code-pattern", url: "src/app.js",
  title: "Dangerous eval call", severity: "medium", pattern: "eval",
  description: "eval on line 12", ...o,
});

describe("baseline diff: what counts as new", () => {
  it("a re-worded description is unchanged", () => {
    const r = compareFindings(
      [header({ description: "new words" })],
      { findings: [header({ description: "old words" })] },
    );
    expect(r.stats).toMatchObject({ newCount: 0, resolvedCount: 0, unchangedCount: 1 });
  });

  it("a severity re-rated down is unchanged, up is new", () => {
    const down = compareFindings(
      [header({ severity: "low" })],
      { findings: [header({ severity: "high" })] },
    );
    expect(down.stats).toMatchObject({ newCount: 0, unchangedCount: 1 });
    const up = compareFindings(
      [header({ severity: "critical" })],
      { findings: [header({ severity: "low" })] },
    );
    expect(up.stats).toMatchObject({ newCount: 1, unchangedCount: 0 });
  });

  it("a key the baseline lacks is new, a key the run lacks is resolved", () => {
    const r = compareFindings(
      [header({ title: "Other header" })],
      { findings: [header({})] },
    );
    expect(r.stats).toMatchObject({ newCount: 1, resolvedCount: 1, unchangedCount: 0 });
    expect(r.newFindings.map((f) => f.title)).toEqual(["Other header"]);
    expect(r.resolvedFindings.map((f) => f.title)).toEqual(["Missing Content-Security-Policy header"]);
  });

  it("a secret on the same lines is unchanged, on more lines is new", () => {
    const same = compareFindings([secret({})], { findings: [secret({})] });
    expect(same.stats).toMatchObject({ newCount: 0, unchangedCount: 1 });
    const more = compareFindings([secret({ lines: [1, 2] })], { findings: [secret({})] });
    expect(more.stats).toMatchObject({ newCount: 1, unchangedCount: 0 });
  });

  it("a secret holding a value the baseline did not is new", () => {
    const r = compareFindings(
      [secret({ description: "Possible secret in `src/app.js`: `AKIA****`" })],
      { findings: [secret({ description: "Possible secret in `src/app.js`: `OTHER****`" })] },
    );
    expect(r.stats).toMatchObject({ newCount: 1, unchangedCount: 0 });
  });

  it("a sink with the same calls is unchanged, with an extra call is new", () => {
    const same = compareFindings([sink({})], { findings: [sink({})] });
    expect(same.stats).toMatchObject({ newCount: 0, unchangedCount: 1 });
    const more = compareFindings(
      [sink({ description: "eval on line 12, eval on line 40" })],
      { findings: [sink({})] },
    );
    expect(more.stats).toMatchObject({ newCount: 1, unchangedCount: 0 });
  });

  it("compareWithBaseline reads a report file and names it in stats", () => {
    const dir = tempDir();
    const path = join(dir, "base.json");
    writeFileSync(path, JSON.stringify({ findings: [header({})] }));
    const r = compareWithBaseline([header({})], path);
    expect(r.stats).toMatchObject({ path, newCount: 0, resolvedCount: 0, unchangedCount: 1 });
  });

  it("compareWithBaseline throws when the baseline cannot be read", () => {
    const dir = tempDir();
    expect(() => compareWithBaseline([], join(dir, "nope.json"))).toThrow(/Cannot read baseline report/);
  });
});
