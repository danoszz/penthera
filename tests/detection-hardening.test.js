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
import { buildSstiProbes, sstiEvaluated, isHtmlResponse } from "../lib/injections.js";
import { looksAuthenticated } from "../lib/blackbox/openapi.js";
import { redirectsToHost } from "../src/utils/url.js";

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

describe("login probe — no 'accepts arbitrary credentials' false positive", () => {
  it("does not flag a 200 that is actually a failure response", () => {
    expect(looksAuthenticated({ status: 200, body: '{"success":false,"error":"invalid credentials"}', headers: {} })).toBe(false);
    expect(looksAuthenticated({ status: 200, body: "Login failed", headers: {} })).toBe(false);
  });
  it("does not flag non-200 responses", () => {
    expect(looksAuthenticated({ status: 401, body: "", headers: {} })).toBe(false);
  });
  it("flags a 200 that sets an auth cookie or returns a token", () => {
    expect(looksAuthenticated({ status: 200, body: "{}", headers: { "set-cookie": "session=abc123; HttpOnly" } })).toBe(true);
    expect(looksAuthenticated({ status: 200, body: '{"access_token":"eyJ..."}', headers: {} })).toBe(true);
  });
});

describe("XSS — content-type gate", () => {
  it("treats HTML responses as XSS-capable", () => {
    expect(isHtmlResponse({ headers: { "content-type": "text/html; charset=utf-8" } })).toBe(true);
  });
  it("does not treat JSON/text responses as XSS-capable", () => {
    expect(isHtmlResponse({ headers: { "content-type": "application/json" } })).toBe(false);
    expect(isHtmlResponse({ headers: {} })).toBe(false);
  });
});

describe("open redirect — destination-origin check (no same-site FP)", () => {
  // The exact false positive found scanning a real Vercel site: apex→www 308
  // canonicalization preserves the evil URL in the query, but the browser goes
  // to the same site, not the attacker.
  const req = "https://gaia.example/api/auth/callback?redirect_uri=https://evil-attacker.example/capture";
  it("does not flag a same-site canonicalization redirect that preserves the evil query", () => {
    expect(redirectsToHost(
      "https://www.gaia.example/api/auth/callback?redirect_uri=https://evil-attacker.example/capture",
      req, "evil-attacker.example",
    )).toBe(false);
  });
  it("flags a redirect whose destination IS the attacker host", () => {
    expect(redirectsToHost("https://evil-attacker.example/capture", req, "evil-attacker.example")).toBe(true);
  });
  it("resolves protocol-relative redirects to the attacker host", () => {
    expect(redirectsToHost("//evil.com/x", "https://t.example/go?url=x", "evil.com")).toBe(true);
  });
  it("returns false for an empty or same-site relative location", () => {
    expect(redirectsToHost("", req, "evil.com")).toBe(false);
    expect(redirectsToHost("/dashboard", req, "evil.com")).toBe(false);
  });
});
