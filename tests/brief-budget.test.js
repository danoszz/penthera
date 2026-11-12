/**
 * The agent brief's budget (BRIEF_BUDGET): at most 5 groups to act on, 3 to
 * check first, one line of likely noise, 3 Not checked lines and a hard
 * character cap. The counts stay exact, the worst groups are the ones kept,
 * and the last line says what was left out and where it is (E9: agents were
 * misled by a brief that opened with 23 items to act on).
 */
import { describe, it, expect } from "vitest";
import { buildBrief, formatBrief, clip, BRIEF_BUDGET } from "../src/report/brief.js";
import { buildResult, BRIEF_FULL } from "../src/mcp/results.js";
import { scrubSecrets } from "../lib/scrub.js";

const f = (o = {}) => ({ severity: "medium", confidence: "likely", source: "static-analysis", category: "code-pattern", title: "Finding", ...o });

// 30 groups to act on, the worst ones last in file order.
function thirty() {
  const findings = Array.from({ length: 25 }, (_, i) => f({ url: `src/f${i}.js`, rule: `r${i}`, title: `T${i}` }));
  findings.push(f({ url: "src/c.js", rule: "conf", title: "Medium confirmed", confidence: "confirmed" }));
  findings.push(...["a", "b", "c"].map((x) => f({ url: `src/big-${x}.js`, rule: "big", title: "Medium in three files" })));
  findings.push(f({ url: "src/hl.js", rule: "hl", title: "High likely", severity: "high" }));
  findings.push(f({ url: "src/hc.js", rule: "hc", title: "High confirmed", severity: "high", confidence: "confirmed" }));
  findings.push(f({ url: "src/crit.js", rule: "crit", title: "Critical one", severity: "critical" }));
  return { target: "/repo", mode: "repo", findings };
}

const items = (out) => out.split("\n").filter((l) => /^\d+\. /.test(l));
const lastLine = (out) => out.trimEnd().split("\n").at(-1);

describe("the brief budget", () => {
  it("shows the 5 worst of 30 groups to act on, with exact counts and an exact pointer", () => {
    const run = thirty();
    const b = buildBrief(run);
    expect(b.act_on).toHaveLength(30);
    expect(b.counts).toMatchObject({ problems: 32, act: 32, check: 0, total: 32 });
    const out = formatBrief(b);
    expect(out).toMatch(/^\*\*Penthera: Fix now\.\*\* 32 problems \(32 to act on, 0 to check first\), 0 likely noise\./);
    // Severity, then confidence, then group size: never the first five by file order.
    expect(items(out).map((l) => /\*\*(.+?)\*\*/.exec(l)[1])).toEqual(["Critical one", "High confirmed", "High likely", "Medium confirmed", "Medium in three files"]);
    expect(lastLine(out)).toMatch(/^\*\*Not shown here:\*\* 25 more groups to act on/);
    expect(lastLine(out)).toContain("`--json`");
    expect(out.length).toBeLessThanOrEqual(BRIEF_BUDGET.chars);
  });

  it("is the same brief whatever order the findings came in", () => {
    const run = thirty();
    const titles = (r) => buildBrief(r).act_on.map((i) => i.title);
    const reversed = { ...run, findings: [...run.findings].reverse() };
    expect(titles(reversed)).toEqual(titles(run));
    expect(items(formatBrief(buildBrief(reversed))).map((l) => l.split(" in ")[0])).toEqual(items(formatBrief(buildBrief(run))).map((l) => l.split(" in ")[0]));
    expect(lastLine(formatBrief(buildBrief(reversed)))).toBe(lastLine(formatBrief(buildBrief(run))));
  });

  it("leaves a small repo whole: every group, no pointer", () => {
    const run = { target: "/repo", mode: "repo", findings: [
      f({ url: "src/a.js", rule: "a", title: "First problem", severity: "high" }),
      f({ url: "src/b.js", rule: "b", title: "Second problem" }),
      f({ url: "src/c.js", rule: "c", title: "Something to check", confidence: "potential" }),
    ] };
    const b = buildBrief(run);
    const out = formatBrief(b);
    for (const t of ["First problem", "Second problem", "Something to check"]) expect(out).toContain(t);
    expect(out).not.toContain("Not shown here");
    expect(out).toContain("3 problems (2 to act on, 1 to check first)");
    // Nothing was cut: the same text with no character cap at all.
    expect(formatBrief(b, { budget: { ...BRIEF_BUDGET, chars: Infinity } })).toBe(out);
  });

  it("counts what it leaves out of Check first, Likely noise and Not checked", () => {
    const run = { target: "/repo", mode: "repo", findings: [
      ...Array.from({ length: 4 }, (_, i) => f({ url: `src/k${i}.js`, rule: `k${i}`, title: `Check ${i}`, confidence: "potential" })),
      f({ url: "tests/a.test.js", title: "Key in a test" }),
      f({ url: "tests/fixtures/b.js", title: "Key in a fixture" }),
    ] };
    const b = buildBrief(run, { limits: ["Limit one.", "Limit two.", "Limit three.", "Limit four.", "Limit five."] });
    const out = formatBrief(b);
    expect(out.split("\n").filter((l) => l.startsWith("- **Check"))).toHaveLength(3);
    expect(out).toContain("- 2 findings: 1 in test fixtures, 1 in test files.");
    const left = b.not_checked.length - 3;
    expect(lastLine(out)).toBe(`**Not shown here:** 1 more group to check first, the paths of 2 likely-noise groups and ${left} more Not checked lines. All of it: the \`brief\` field of the same scan with \`--json\`.`);
  });

  it("holds the character cap on pathological text, cutting inside a line, never across lines", () => {
    const long = (i) => `${"A very long title word ".repeat(250)}<b>|\`code ${i}`;
    const run = { target: "/repo", mode: "repo", findings: Array.from({ length: 40 }, (_, i) => f({
      url: `src/${"deep/".repeat(60)}f${i}.js`, rule: `rule-${"x".repeat(200)}-${i}`, title: long(i), severity: i % 2 ? "high" : "critical",
      description: "D ".repeat(3000), remediation: "R ".repeat(3000),
    })) };
    const b = buildBrief(run, { limits: Array.from({ length: 20 }, (_, i) => `${"Not read here ".repeat(200)}${i}`) });
    const out = formatBrief(b);
    expect(out.length).toBeLessThanOrEqual(BRIEF_BUDGET.chars);
    expect(out.startsWith("**Penthera: Fix now.** 40 problems (40 to act on, 0 to check first)")).toBe(true);
    expect(lastLine(out)).toMatch(/^\*\*Not shown here:\*\* \d+ more groups to act on/);
    const shown = items(out).length;
    expect(shown).toBeGreaterThan(0);
    expect(lastLine(out)).toContain(`${40 - shown} more groups to act on`);
    // Every item is whole: its title cut with an ellipsis, its bold and code spans closed.
    for (const l of items(out)) {
      expect(l).toMatch(/^\d+\. \*\*[^*\n]+…\*\* \[(critical|high)\]/);
      expect((l.match(/`/g) || []).length % 2).toBe(0);
    }
    expect(out).not.toContain("<b>");
  });

  it("cuts at a word with an ellipsis and never splits a surrogate pair", () => {
    expect(clip("short", 10)).toBe("short");
    expect(clip("one two three four five six", 15)).toBe("one two three…");
    expect(clip(`${"a".repeat(8)}😀tail`, 10)).toBe(`${"a".repeat(8)}…`);
    expect(clip("see `npm i x` now", 9)).toBe("see `npm…`");
  });

  it("never shows a secret, even when the cut falls inside it", () => {
    const key = `sk_${"live_"}${"aB3dE6gH9jK2mN5pQ8sT1vW4"}`;
    expect(scrubSecrets(key)).not.toContain(key);
    const run = { target: "/repo", mode: "repo", findings: Array.from({ length: 8 }, (_, i) => f({
      url: `src/k${i}.js`, rule: `k${i}`, title: `${"x".repeat(80 + i)} ${key}`, description: `Found ${key}.`, remediation: `Rotate ${key}.`,
    })) };
    const b = buildBrief(run);
    // A brief read back from a file, with the key put back in by hand: formatBrief scrubs it again.
    b.act_on[0].title = `${"y".repeat(84)}${key}`;
    b.first.action = `Rotate ${key} now`;
    const out = formatBrief(b);
    expect(out).not.toContain(key);
    expect(out).not.toContain(key.slice(0, 16));
  });

  it("keeps the report path and the footer outside the cut", () => {
    const b = buildBrief(thirty(), { reports: ["reports/repo.md"] });
    const out = formatBrief(b, { footer: true });
    const [body] = out.split("\n---\n");
    expect(body.length).toBeLessThanOrEqual(BRIEF_BUDGET.chars);
    expect(body).toContain("- Full report: `reports/repo.md`");
    expect(body).toContain("All of it: the full report under Next");
    expect(out).toMatch(/Checked by Penthera/);
  });
});

describe("the MCP result uses the same budget and the same order", () => {
  it("points to the structured result and keeps the worst findings when max_findings cuts", () => {
    const run = thirty();
    const r = buildResult({ tool: "scan_repo", target: ".", findings: run.findings, limits: [], maxFindings: 3, scan: { mode: "repo" } });
    expect(r.structured.brief.act_on).toHaveLength(30);
    expect(r.text).toContain("25 more groups to act on");
    expect(r.text).toContain(BRIEF_FULL);
    expect(r.structured.findings.map((x) => x.title)).toEqual(["Critical one", "High confirmed", "High likely"]);
    expect(r.structured.truncated).toBe(true);
    expect(r.text).toMatch(/The JSON lists 3 of 32 findings; raise max_findings/);
  });
});
