/**
 * Audience reports (--audience), the report model, the loop timeline and user
 * templates (--report-template) rendered against a real model.
 */
import { readFileSync } from "node:fs";
import { describe, it, expect } from "vitest";
import { formatAudienceReport, AUDIENCES } from "../src/report/audience.js";
import { buildReportModel } from "../src/report/model.js";
import { buildTimeline, formatDuration } from "../src/report/timeline.js";
import { renderTemplate } from "../src/report/template.js";
import { buildHistory } from "../lib/memory/history.js";
import { formatMarkdownReport } from "../src/report/markdown.js";
import { findingId } from "../lib/memory/views.js";
import { reportResult, REPORT_VERSION } from "./fixtures/report-result.js";

describe("audience reports", () => {
  for (const audience of AUDIENCES) {
    it(`${audience} report matches its snapshot`, async () => {
      const md = formatAudienceReport(reportResult(), audience, { version: REPORT_VERSION });
      await expect(md).toMatchFileSnapshot(`./__snapshots__/report-${audience}.md`);
    });
  }

  it("owner report says when serious findings sit in test or fixture files", () => {
    const f = (file, severity = "high") => ({ title: "Hardcoded AWS key", severity, category: "secrets", url: file, line: 1 });
    const one = formatAudienceReport({ target: ".", findings: [f("tests/fixtures/keys.js"), f("src/app.js")] }, "owner", { version: REPORT_VERSION });
    expect(one).toContain("if they are real, an attacker could use them");
    expect(one).toContain("1 of them is in test or fixture files");
    const all = formatAudienceReport({ target: ".", findings: [f("tests/keys.js"), f("src/a.spec.ts", "critical")] }, "owner", { version: REPORT_VERSION });
    expect(all).toContain("All of them are in test or fixture files");
    const none = formatAudienceReport({ target: ".", findings: [f("src/app.js")] }, "owner", { version: REPORT_VERSION });
    expect(none).not.toContain("test or fixture");
  });

  it("rejects an unknown audience", () => {
    expect(() => formatAudienceReport(reportResult(), "ceo")).toThrow(/Unknown --audience/);
  });

  it("Markdown findings tables show each finding's id, the one `memory suppress` takes", () => {
    const md = formatMarkdownReport({
      target: "https://shop.example",
      findings: [
        { fid: "0123456789abcdef", severity: "high", title: "Missing Content-Security-Policy header", url: "https://shop.example/", confidence: "confirmed", source: "headers" },
        { severity: "low", title: "Server banner discloses its version", url: "https://shop.example/", confidence: "likely", source: "headers" },
      ],
    }, { version: REPORT_VERSION });
    expect(md).toContain("| Finding | URL | Match | Source | Id |");
    expect(md).toContain("| `0123456789abcdef` |");
    // a finding without a stored fid gets the id `memory suppress` would compute for it
    expect(md).toContain(`| \`${findingId({ severity: "low", title: "Server banner discloses its version", url: "https://shop.example/", confidence: "likely", source: "headers" })}\` |`);
  });

  it("leaves the default Markdown report unchanged", () => {
    const md = formatMarkdownReport(reportResult(), { version: REPORT_VERSION });
    expect(md).toContain("# Penthera Security Report");
    expect(md).not.toContain("Security evidence report");
  });

  it("names the package.json version in the header when no version is passed", () => {
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf-8"));
    const md = formatMarkdownReport({ findings: [] });
    expect(md).toContain(`v${pkg.version}`);
    expect(md).not.toContain("v0.2.0");
  });

  it("prints a dash when duration is missing", () => {
    const result = reportResult();
    delete result.duration;

    const md = formatMarkdownReport(result, { version: REPORT_VERSION });

    expect(md).toContain("| **Duration** | - |");
  });

  it("developer report has file:line, recipe ids and sources", () => {
    const md = formatAudienceReport(reportResult(), "developer", { version: REPORT_VERSION });
    expect(md).toContain("`src/lib/payments.js:14`");
    expect(md).toContain("`secret-to-env`");
    expect(md).toContain("`security-headers`");
    expect(md).toMatch(/\*\*Sources:\*\* \[/);
  });

  it("developer report prints a fix diff from result.fixPlans in a fence it cannot break", () => {
    const r = reportResult();
    r.fixPlans = [{
      recipe: "security-headers", diff: "--- a/x\n+++ b/x\n+app.use(helmet()) // ```\n",
      findings: [{ category: "headers", title: "Missing Content-Security-Policy header", url: "https://shop.example/" }],
      ownerActions: ["Tighten the starter CSP once the app works with it"],
    }];
    const md = formatAudienceReport(r, "developer", { version: REPORT_VERSION });
    expect(md).toContain("````diff\n--- a/x");
    expect(formatAudienceReport(r, "owner", { version: REPORT_VERSION })).toContain("Tighten the starter CSP");
  });

  it("owner report states the trend from memory", () => {
    const md = formatAudienceReport(reportResult(), "owner", { version: REPORT_VERSION });
    expect(md).toContain("Serious problems went from 4 to 2 over the last 3 scans (down)");
  });

  it("auditor report covers scope, confidence, egress, suppressions, NIS2 and OWASP", () => {
    const md = formatAudienceReport(reportResult(), "auditor", { version: REPORT_VERSION });
    for (const s of [
      "docs/METHODOLOGY.md", "`needs-human-review`", "Blocked by --offline", "## Inconclusive probes",
      "| daan | Stripped at the CDN edge", "repo file (penthera.suppress.json)", "NIS2 Article 21(2)",
      "A01:2021 Broken Access Control", "## 5. Fix timeline",
    ]) expect(md).toContain(s);
  });

  it("escapes finding text so it cannot break a table or inject HTML", () => {
    const md = formatAudienceReport(reportResult(), "auditor", { version: REPORT_VERSION });
    expect(md).toContain("Secure \\| HttpOnly &lt;flags&gt;");
    expect(md).not.toContain("<flags>");
  });
});

describe("loop timeline", () => {
  it("builds found → fixed → verified from loopRun with time-to-fix", () => {
    const t = buildTimeline(reportResult());
    expect(t.source).toBe("agent loop");
    const cors = t.entries.find((e) => e.fid === "8b9c0d1e2f3a4b5c");
    expect(cors).toMatchObject({ found: "iteration 1", fixed: "iteration 1", recipe: "cors-allowlist", verified: "iteration 2", timeToFixMs: 64_500 });
    const csp = t.entries.find((e) => e.fid === "2b3c4d5e6f7a8b9c");
    expect(csp).toMatchObject({ failed: "iteration 2", verified: null, timeToFixMs: null });
    expect(t).toMatchObject({ verifiedCount: 1, failedCount: 1, openCount: 1 });
  });

  it("reads the penthera.loopRun/1 shape from penthera agent", () => {
    const loopRun = {
      schema: "penthera.loopRun/1",
      iterations: [
        { n: 1, durationMs: 30_000, fixes: [
          { recipe: "security-headers", status: "verified", findings: [{ fid: "aa", title: "Missing CSP" }, { fid: "bb", title: "Missing HSTS" }] },
          { recipe: "cookie-flags", status: "failed", findings: [{ fid: "cc", title: "Cookie flags" }] },
          { recipe: "cors-allowlist", status: "not-applied", findings: [{ fid: "dd", title: "CORS *" }] },
        ] },
        { n: 2, durationMs: 10_000, fixes: [{ recipe: "cookie-flags", status: "verified", findings: [{ fid: "cc", title: "Cookie flags" }] }] },
      ],
    };
    const t = buildTimeline({ loopRun, findings: [] });
    const by = Object.fromEntries(t.entries.map((e) => [e.fid, e]));
    expect(by.aa).toMatchObject({ title: "Missing CSP", recipe: "security-headers", found: "iteration 1", verified: "iteration 1", timeToFixMs: 30_000 });
    expect(by.cc).toMatchObject({ fixed: "iteration 2", verified: "iteration 2", failed: null, timeToFixMs: 40_000 });
    expect(by.dd).toMatchObject({ fixed: null, verified: null });
    expect(t).toMatchObject({ verifiedCount: 3, failedCount: 0, openCount: 1 });
  });

  it("falls back to memory fix events", () => {
    const events = [
      { ts: "2026-10-01T00:00:00.000Z", type: "scan", data: { counts: { critical: 1, total: 1 }, ids: ["aa"] } },
      { ts: "2026-10-02T00:00:00.000Z", type: "fix_applied", data: { id: "aa", recipe: "secret-to-env" } },
      { ts: "2026-10-03T12:00:00.000Z", type: "fix_verified", data: { id: "aa" } },
      { ts: "2026-10-04T00:00:00.000Z", type: "fix_applied", data: { id: "bb", recipe: "cookie-flags" } },
      { ts: "bogus", type: "fix_verified", data: { id: "bb" } },
      { ts: "2026-10-05T00:00:00.000Z", type: "fix_failed", data: { id: 42 } },
    ];
    const history = buildHistory(events);
    expect(history.trend).toEqual([{ ts: "2026-10-01T00:00:00.000Z", critical: 1, high: 0, medium: 0, low: 0, total: 1, suppressed: 0 }]);
    const t = buildTimeline({ memory: { history }, findings: [{ fid: "aa", title: "Key" }] });
    expect(t.source).toBe("memory");
    expect(t.entries[0]).toMatchObject({ fid: "aa", title: "Key", recipe: "secret-to-env", timeToFixMs: 2.5 * 86_400_000 });
    expect(t.entries[1]).toMatchObject({ fid: "bb", verified: null });
    expect(formatDuration(t.medianTimeToFixMs)).toBe("2.5 days");
  });

  it("returns null without loop or fix history", () => {
    expect(buildTimeline({ findings: [] })).toBeNull();
    expect(buildTimeline({ loopRun: { iterations: "nope" } })).toBeNull();
  });
});

describe("user templates on the report model", () => {
  it("renders summary counts, findings and conditionals", () => {
    const tpl = [
      "# {{summary.target}}",
      "Critical: {{summary.critical}}, total {{summary.total}}",
      "{{#each findings}}- [{{severity}}] {{title}} ({{confidence}}){{#if location}} at {{location}}{{/if}}",
      "{{/each}}{{#if suppressed}}Suppressed: {{#each suppressed}}{{actor}}; {{/each}}{{else}}none{{/if}}",
    ].join("\n");
    const out = renderTemplate(tpl, buildReportModel(reportResult(), { version: REPORT_VERSION }));
    expect(out).toContain("Critical: 1, total 5");
    expect(out).toContain("- [critical] Hardcoded Stripe secret key (confirmed) at src/lib/payments.js:14");
    expect(out).toContain("Suppressed: daan; ci-bot; ");
  });
});
