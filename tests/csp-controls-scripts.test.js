/**
 * A CSP that names no script source leaves every script allowed, so it earns neither the CLI's
 * silence nor the live check's pass. `frame-ancestors` alone still counts for framing.
 */
import { describe, it, expect } from "vitest";
import { auditSecurityHeaders, CSP_NO_SCRIPTS, cspControlsScripts } from "../lib/blackbox/headers.js";
import { grade, SCORE_VERSION } from "../api/_lib/grade.mjs";

const SITE = "https://shop.example/";
const LIVE = { liveResponse: true };
const titles = (headers) => auditSecurityHeaders(headers, SITE, LIVE).map((f) => f.title);
const NOW = Date.parse("2026-10-23");
const response = (csp) => ({
  url: SITE, status: 200, hops: [{ url: SITE }],
  tls: { protocol: "TLSv1.3", authorized: true, validTo: "Oct 1 00:00:00 2027 GMT" },
  headers: { "strict-transport-security": "max-age=63072000", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "permissions-policy": "camera=()", ...(csp === undefined ? {} : { "content-security-policy": csp }) },
});
const check = (report, id) => report.checks.find((c) => c.id === id);

describe("cspControlsScripts", () => {
  it.each([
    ["default-src 'self'", true],
    ["script-src 'self'", true],
    ["script-src-elem 'self'", true],
    ["SCRIPT-SRC 'self'", true],
    ["frame-ancestors 'none'; default-src 'none'", true],
    ["frame-ancestors 'none', script-src 'self'", true],
    ["frame-ancestors 'none'", false],
    ["upgrade-insecure-requests", false],
    ["script-src-attr 'none'", false],
    ["frame-src script-src", false],
    ["", false],
    ["script-src *", false],
    ["default-src *", false],
    ["script-src https:", false],
    ["script-src http: https: 'self'", false],
    ["default-src data:", false],
    ["default-src 'self'; script-src *", false],
    ["script-src-attr 'none'; script-src *", false],
    ["script-src * 'nonce-abc'", false],
    ["script-src 'nonce-abc' 'strict-dynamic' https:", true],
    ["script-src 'sha256-abc' 'strict-dynamic' https: 'unsafe-inline'", true],
    ["script-src 'strict-dynamic' https:", false],
    ["script-src 'NONE'", true],
    ["script-src https://cdn.example.com", true],
    ["script-src *.example.com", true],
    ["script-src 'self'; script-src *", true],
    ["script-src https://*", false],
    ["script-src http://*", false],
    ["script-src *:*", false],
    ["script-src *:443", false],
    ["script-src https://*:*", false],
    ["script-src https://*/", false],
    ["default-src *.com", false],
    ["script-src https://*.com", false],
    ["script-src *.example.com", true],
    ["script-src https://*.example.com", true],
    ["script-src https://cdn.example.com:*", true],
    ["default-src *, script-src 'self'", true],
  ])("%s: %s", (csp, want) => expect(cspControlsScripts(csp)).toBe(want));
});

describe("the CLI's header audit", () => {
  it("reports a frame-only policy, as a finding of its own", () => {
    const found = auditSecurityHeaders({ "Content-Security-Policy": "frame-ancestors 'none'" }, SITE, LIVE).find((f) => f.title === CSP_NO_SCRIPTS);
    expect(found).toMatchObject({ severity: "medium", category: "headers", source: "header-audit", confidence: "confirmed" });
    expect(found.evidence).toContain("frame-ancestors");
  });

  it("stays quiet on a policy that controls scripts, and a missing CSP keeps its own finding", () => {
    expect(titles({ "content-security-policy": "default-src 'self'" })).not.toContain(CSP_NO_SCRIPTS);
    expect(titles({})).toContain("Missing Content-Security-Policy");
    expect(titles({})).not.toContain(CSP_NO_SCRIPTS);
  });

  it("judges a value only when a server sent it, because the fix flow's probe passes a placeholder", () => {
    expect(auditSecurityHeaders({ "content-security-policy": "set" }, SITE).map((f) => f.title)).not.toContain(CSP_NO_SCRIPTS);
  });

  it("takes frame-ancestors for X-Frame-Options, but not a wildcard or a Report-Only policy", () => {
    expect(titles({ "content-security-policy": "default-src 'self'; frame-ancestors 'none'" })).not.toContain("Missing X-Frame-Options");
    expect(titles({ "content-security-policy": "default-src 'self'; FRAME-ANCESTORS 'self'" })).not.toContain("Missing X-Frame-Options");
    expect(titles({ "content-security-policy": "default-src 'self'; frame-ancestors *" })).toContain("Missing X-Frame-Options");
    expect(titles({ "content-security-policy": "default-src 'self'" })).toContain("Missing X-Frame-Options");
    expect(titles({ "content-security-policy-report-only": "frame-ancestors 'none'" })).toContain("Missing X-Frame-Options");
  });

  it("doesn't count Report-Only as a policy that needs script control", () => {
    expect(titles({ "content-security-policy-report-only": "frame-ancestors 'none'" })).not.toContain(CSP_NO_SCRIPTS);
  });
});

describe("the live check's grade", () => {
  it("stops passing a frame-only policy, and doesn't call it script control", () => {
    const r = grade(response("frame-ancestors 'none'"), { now: NOW });
    expect(check(r, "csp")).toMatchObject({ passed: false, title: CSP_NO_SCRIPTS });
    expect(check(r, "csp").evidence).toContain("frame-ancestors");
    expect(check(r, "csp-scripts")).toBeUndefined();
  });

  it("still counts frame-ancestors for framing", () => {
    expect(check(grade(response("frame-ancestors 'none'"), { now: NOW }), "framing").passed).toBe(true);
  });

  it("names frame-ancestors as the evidence for framing, and a wildcard fails", () => {
    expect(check(grade(response("frame-ancestors 'none'"), { now: NOW }), "framing")).toMatchObject({ passed: true, evidence: "frame-ancestors in the CSP" });
    expect(check(grade(response("frame-ancestors *"), { now: NOW }), "framing").passed).toBe(false);
  });

  it("charges a frame-only policy what no CSP costs on script control", () => {
    const frameOnly = grade(response("frame-ancestors 'none'"), { now: NOW });
    const none = grade(response(undefined), { now: NOW });
    expect(check(none, "csp").passed).toBe(false);
    expect(frameOnly.checks.find((c) => c.id === "csp").weight).toBe(check(none, "csp").weight);
    expect(frameOnly.score).toBeGreaterThan(none.score);
  });

  it("fails a wildcard policy, as it fails no script rule at all", () => {
    for (const csp of ["script-src *", "default-src *", "script-src https:"]) {
      const r = grade(response(csp), { now: NOW });
      expect(check(r, "csp"), csp).toMatchObject({ passed: false, title: CSP_NO_SCRIPTS });
      expect(check(r, "csp-scripts"), csp).toBeUndefined();
    }
  });

  it.each([
    ["script-src 'self' 'UNSAFE-INLINE'", false],
    ["script-src 'self' 'Unsafe-Eval'", false],
    ["script-src-attr 'none'; script-src 'self' 'unsafe-inline'", false],
    ["script-src-elem 'self'; default-src 'unsafe-inline'", true],
    ["default-src 'self' 'unsafe-inline'", false],
    ["script-src 'self' 'unsafe-inline' 'NONCE-abc'", true],
    ["script-src 'self' 'unsafe-inline' 'SHA256-abc'", true],
    ["script-src 'self'; style-src 'unsafe-inline'", true],
  ])("reads %s's script sources: passes %s", (csp, passed) => {
    expect(check(grade(response(csp), { now: NOW }), "csp-scripts").passed).toBe(passed);
  });

  it("passes a policy that controls scripts, and keeps grading its sources", () => {
    const strict = grade(response("default-src 'self'"), { now: NOW });
    expect(check(strict, "csp").passed).toBe(true);
    expect(check(strict, "csp-scripts").passed).toBe(true);
    const open = grade(response("script-src 'self' 'unsafe-inline'"), { now: NOW });
    expect(check(open, "csp").passed).toBe(true);
    expect(check(open, "csp-scripts").passed).toBe(false);
  });

  it("states the score's version", () => {
    expect(grade(response("default-src 'self'"), { now: NOW }).scoreVersion).toBe(SCORE_VERSION);
    expect(SCORE_VERSION).toBe(2);
  });
});
