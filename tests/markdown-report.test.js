/**
 * `src/report/markdown.js`: the Markdown report for a small fixed result
 * object, pinned by a file snapshot so formatting changes are deliberate.
 * The result is fixed (target, timestamp, duration, findings, baseline
 * comparison) and the version is the fixture's pinned test version, so the
 * snapshot does not move with the clock or the release.
 */
import { describe, it, expect } from "vitest";
import { formatMarkdownReport } from "../src/report/markdown.js";
import { REPORT_VERSION } from "./fixtures/report-result.js";

const result = {
  target: "https://shop.example",
  timestamp: "2026-10-19T09:30:00.000Z",
  duration: 18_400,
  mode: "url",
  reachable: true,
  findings: [
    {
      fid: "1a2b3c4d5e6f7a8b", severity: "high",
      title: "Missing Content-Security-Policy header",
      url: "https://shop.example/", confidence: "confirmed", source: "headers",
    },
    {
      fid: "2b3c4d5e6f7a8b9c", severity: "low",
      title: "Server banner discloses its version",
      url: "https://shop.example/", confidence: "likely", source: "headers",
    },
  ],
};

const opts = {
  version: REPORT_VERSION,
  baseline: { path: "baseline.json", newCount: 1, resolvedCount: 0, unchangedCount: 1 },
};

describe("Markdown report snapshot", () => {
  it("matches its snapshot for a small fixed result", async () => {
    const md = formatMarkdownReport(result, opts);
    await expect(md).toMatchFileSnapshot("./__snapshots__/markdown-report.md");
  });

  it("keeps the summary counts, baseline table and finding ids", () => {
    const md = formatMarkdownReport(result, opts);
    expect(md).toContain("Found **2** issue(s): 0 critical · 1 high · 0 medium · 1 low · 0 info");
    expect(md).toContain("| New findings | 1 |");
    expect(md).toContain("| Resolved since baseline | 0 |");
    expect(md).toContain("| Unchanged | 1 |");
    expect(md).toContain("| `1a2b3c4d5e6f7a8b` |");
    expect(md).toContain("| `2b3c4d5e6f7a8b9c` |");
  });

  it("renders the same input the same way twice", () => {
    expect(formatMarkdownReport(result, opts)).toBe(formatMarkdownReport(result, opts));
  });
});
