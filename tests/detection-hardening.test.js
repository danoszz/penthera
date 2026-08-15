/**
 * Regression tests for detection false-positive fixes.
 *
 *  - Secret scanner must not flag dummy/probe credentials (the exact class of
 *    false positive Penthera produced on its own repo).
 *  - SSTI probe must not fire on a coincidental "49" in the page — it uses a
 *    randomized arithmetic canary and only confirms on the evaluated product.
 */
import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { scanSecrets } from "../lib/whitebox/secrets.js";
import { buildSstiProbes, sstiEvaluated } from "../lib/injections.js";

// Scan a single throwaway file in an isolated temp dir.
function scanOne(name, content) {
  const dir = mkdtempSync(join(tmpdir(), "penthera-secrets-"));
  try {
    writeFileSync(join(dir, name), content);
    return scanSecrets(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("scanSecrets — false-positive handling", () => {
  it("does not flag dummy/probe credentials", () => {
    // The exact payload Penthera itself sends to test login endpoints.
    const findings = scanOne(
      "probe.js",
      `body: JSON.stringify({ username: "x", password: "invalid-password-12345" })`,
    );
    expect(findings).toHaveLength(0);
  });

  it("does not flag classic placeholders", () => {
    expect(scanOne("config.js", `const password = "changeme";`)).toHaveLength(0);
    expect(scanOne("app.js", `const apiKey = "your-api-key-here";`)).toHaveLength(0);
  });

  it("flags a real hardcoded password with a non-duplicated title", () => {
    const findings = scanOne("config.js", `const password = "S3cr3t-Prod-9!xQ";`);
    const pw = findings.find((f) => /password/i.test(f.title));
    expect(pw).toBeTruthy();
    expect(pw.title).toBe("Hardcoded password in source");
    expect(pw.title).not.toContain("in source in source");
  });

  it("still flags high-entropy provider keys", () => {
    // Assembled at runtime so this test file carries no matchable key literal
    // at rest — Penthera scans its own repo in CI and should stay clean.
    const key = "AKIA" + "QWERTY1234567890"; // AKIA + 16 chars, fake
    const findings = scanOne("aws.js", `const k = "${key}";`);
    expect(findings.some((f) => /AWS access key/.test(f.title))).toBe(true);
  });
});

describe("SSTI canary — randomized, no coincidental-number false positive", () => {
  it("uses a distinctive multi-digit product, not 7*7=49", () => {
    const { expr, product } = buildSstiProbes();
    expect(product).not.toBe("49");
    expect(product.length).toBeGreaterThanOrEqual(6);
    expect(expr).toMatch(/^\d{4}\*\d{4}$/);
  });

  it("does not fire on a page that merely contains '49'", () => {
    const { probes, expr, product } = buildSstiProbes();
    expect(sstiEvaluated("Item #49 — price 49.00", probes[0].payload, expr, product)).toBe(false);
  });

  it("does not fire when the payload is reflected unevaluated", () => {
    const { probes, expr, product } = buildSstiProbes();
    expect(sstiEvaluated(`echo: ${probes[0].payload}`, probes[0].payload, expr, product)).toBe(false);
  });

  it("fires only when the evaluated product appears", () => {
    const { probes, expr, product } = buildSstiProbes();
    expect(sstiEvaluated(`result: ${product}`, probes[0].payload, expr, product)).toBe(true);
  });
});
