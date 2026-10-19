/**
 * The one-line product footer: on every human-readable Markdown output, off
 * with --no-footer, never in SARIF or JSON.
 */
import { describe, it, expect } from "vitest";
import { mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FOOTER, footerLines } from "../src/report/footer.js";
import { formatMarkdownReport } from "../src/report/markdown.js";
import { formatAudienceReport, AUDIENCES } from "../src/report/audience.js";
import { formatSarif } from "../src/reporter.js";
import { formatPrComment } from "../lib/deps/report.js";
import { writeEvidence, evidenceReadme } from "../src/cli/report-outputs.js";
import { reportResult, REPORT_VERSION } from "./fixtures/report-result.js";

const lastLine = (s) => s.trimEnd().split("\n").pop();
const depsResult = () => ({ findings: [], deps: { total: 3, diff: null } });

describe("product footer", () => {
  it("is one short line", () => {
    expect(FOOTER).not.toContain("\n");
    expect(FOOTER).toContain("https://github.com/danoszz/penthera");
    expect(footerLines({ footer: false })).toEqual([]);
  });

  it("ends the default Markdown report, and --no-footer removes it", () => {
    expect(lastLine(formatMarkdownReport(reportResult(), { version: REPORT_VERSION }))).toBe(FOOTER);
    expect(formatMarkdownReport(reportResult(), { version: REPORT_VERSION, footer: false })).not.toContain(FOOTER);
  });

  for (const a of AUDIENCES) {
    it(`ends the ${a} report, and footer: false removes it`, () => {
      expect(lastLine(formatAudienceReport(reportResult(), a, { version: REPORT_VERSION }))).toBe(FOOTER);
      expect(formatAudienceReport(reportResult(), a, { version: REPORT_VERSION, footer: false })).not.toContain(FOOTER);
    });
  }

  it("ends the PR comment", () => {
    expect(lastLine(formatPrComment(depsResult(), { version: "t" }))).toBe(FOOTER);
    expect(formatPrComment(depsResult(), { version: "t", footer: false })).not.toContain(FOOTER);
  });

  it("ends the evidence bundle README and never appears in SARIF or JSON", () => {
    expect(lastLine(evidenceReadme(reportResult(), { version: REPORT_VERSION }))).toBe(FOOTER);
    const dir = join(mkdtempSync(join(tmpdir(), "penthera-footer-")), "ev");
    writeEvidence(reportResult(), { evidence: dir }, { version: REPORT_VERSION, template: null, mdOpts: { version: REPORT_VERSION }, argv: [] });
    for (const f of readdirSync(dir)) {
      const text = readFileSync(join(dir, f), "utf-8");
      if (/\.(json|sarif|sig)$/.test(f)) expect(text, f).not.toContain("Checked by Penthera");
      else expect(lastLine(text), f).toBe(FOOTER);
    }
    expect(JSON.stringify(formatSarif(reportResult()))).not.toContain("Checked by Penthera");
  });

  it("--no-footer reaches every file in the bundle", () => {
    const dir = join(mkdtempSync(join(tmpdir(), "penthera-footer-")), "ev");
    writeEvidence(reportResult(), { evidence: dir, "no-footer": true }, { version: REPORT_VERSION, template: null, mdOpts: { version: REPORT_VERSION, footer: false }, argv: [] });
    for (const f of readdirSync(dir)) expect(readFileSync(join(dir, f), "utf-8"), f).not.toContain("Checked by Penthera");
  });
});
