/**
 * Supplier passive rating — domain parsing, RAG scoring, and the (documented)
 * passive-only report. Network-dependent rating is exercised via the CLI demo.
 */
import { describe, it, expect } from "vitest";
import { parseDomain, parseSupplierList, scoreSupplier, formatSuppliersMarkdown } from "../lib/supply-chain.js";

describe("supplier domain parsing", () => {
  it("strips scheme, path, and port", () => {
    expect(parseDomain("https://acme.com/login")).toBe("acme.com");
    expect(parseDomain("acme.com:8443")).toBe("acme.com");
  });
  it("skips blanks and comments", () => {
    expect(parseDomain("# a comment")).toBeNull();
    expect(parseDomain("")).toBeNull();
  });
  it("parses a newline/comma list and dedupes", () => {
    const list = parseSupplierList("acme.com\n# vendors\nfoo.io, acme.com\nhttps://bar.dev/x");
    expect(list).toEqual(["acme.com", "foo.io", "bar.dev"]);
  });
});

describe("scoreSupplier RAG", () => {
  it("unreachable → unknown", () => {
    expect(scoreSupplier({ reachable: false, findings: [] }).rating).toBe("unknown");
  });
  it("clean → green 100", () => {
    expect(scoreSupplier({ reachable: true, findings: [] })).toEqual({ score: 100, rating: "green" });
  });
  it("penalises by severity (amber band)", () => {
    const r = scoreSupplier({ reachable: true, findings: [{ severity: "high" }, { severity: "medium" }, { severity: "low" }] });
    expect(r.score).toBe(58);
    expect(r.rating).toBe("amber");
  });
  it("multiple highs → red", () => {
    const r = scoreSupplier({ reachable: true, findings: [{ severity: "high" }, { severity: "high" }, { severity: "high" }] });
    expect(r.rating).toBe("red");
  });
});

describe("formatSuppliersMarkdown", () => {
  it("documents the passive methodology and lists suppliers", () => {
    const report = { count: 1, summary: { green: 1, amber: 0, red: 0, unknown: 0 }, suppliers: [{ domain: "acme.com", rating: "green", score: 100, keyIssues: [] }] };
    const md = formatSuppliersMarkdown(report);
    expect(md).toMatch(/passive, public-data-only/i);
    expect(md).toContain("acme.com");
    expect(md).toMatch(/not.*penetration test/i);
  });
});
