/**
 * Security response header audit (lib/blackbox/headers.js).
 * Tests fixed header sets offline without network calls.
 */
import { describe, it, expect } from "vitest";
import { auditSecurityHeaders, CSP_NO_SCRIPTS } from "../lib/blackbox/headers.js";

const HTTPS_URL = "https://app.example.test/";
const HTTP_URL = "http://app.example.test/";

const HARDENED_HEADERS = {
  "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
  "x-frame-options": "DENY",
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=()",
};

describe("auditSecurityHeaders — missing security headers", () => {
  it("flags all five expected headers when none are sent over HTTPS", () => {
    const findings = auditSecurityHeaders({}, HTTPS_URL);
    const titles = findings.map((f) => f.title);

    expect(titles).toEqual([
      "Missing X-Frame-Options",
      "Missing Content-Security-Policy",
      "Missing X-Content-Type-Options",
      "Missing Referrer-Policy",
      "Missing Permissions-Policy",
    ]);
    expect(findings.every((f) => f.source === "header-audit" && f.url === HTTPS_URL)).toBe(true);
    expect(findings.find((f) => f.title === "Missing Content-Security-Policy")).toMatchObject({
      severity: "medium",
      category: "headers",
    });
    expect(findings.find((f) => f.title === "Missing X-Frame-Options")).toMatchObject({
      severity: "low",
      category: "headers",
    });
    expect(findings.find((f) => f.title === "Missing X-Content-Type-Options")).toMatchObject({
      severity: "low",
      category: "headers",
    });
    expect(findings.find((f) => f.title === "Missing Referrer-Policy")).toMatchObject({
      severity: "info",
      category: "headers",
    });
    expect(findings.find((f) => f.title === "Missing Permissions-Policy")).toMatchObject({
      severity: "info",
      category: "headers",
    });
  });

  it("flags missing Content-Security-Policy when other headers are set", () => {
    const { "content-security-policy": _csp, ...withoutCsp } = HARDENED_HEADERS;
    const findings = auditSecurityHeaders(withoutCsp, HTTPS_URL);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      severity: "medium",
      title: "Missing Content-Security-Policy",
      category: "headers",
      source: "header-audit",
      url: HTTPS_URL,
    });
  });

  it("suppresses Missing X-Frame-Options when CSP restricts frame-ancestors", () => {
    const { "x-frame-options": _xfo, ...headers } = HARDENED_HEADERS;
    expect(auditSecurityHeaders(headers, HTTPS_URL)).toEqual([]);

    const wildcardFraming = {
      ...headers,
      "content-security-policy": "default-src 'self'; frame-ancestors *",
    };
    const findings = auditSecurityHeaders(wildcardFraming, HTTPS_URL);
    expect(findings.map((f) => f.title)).toEqual(["Missing X-Frame-Options"]);
  });

  it("matches header names case-insensitively", () => {
    const mixedCase = {
      "Content-Security-Policy": "default-src 'self'",
      "X-Frame-Options": "SAMEORIGIN",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "Permissions-Policy": "geolocation=()",
    };
    expect(auditSecurityHeaders(mixedCase, HTTPS_URL, { liveResponse: true })).toEqual([]);
  });
});

describe("auditSecurityHeaders — CSP script control (liveResponse)", () => {
  it("flags a weak CSP only when liveResponse is enabled", () => {
    const weakCspHeaders = {
      ...HARDENED_HEADERS,
      "content-security-policy": "script-src *",
    };

    expect(auditSecurityHeaders(weakCspHeaders, HTTPS_URL)).toEqual([]);

    const findings = auditSecurityHeaders(weakCspHeaders, HTTPS_URL, { liveResponse: true });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      severity: "medium",
      title: CSP_NO_SCRIPTS,
      category: "headers",
      source: "header-audit",
      confidence: "confirmed",
      url: HTTPS_URL,
    });
    expect(findings[0].evidence).toContain("script-src *");
  });
});

describe("auditSecurityHeaders — transport and server disclosure", () => {
  it("flags plain HTTP when local is false, and skips it when local is true", () => {
    const nonLocal = auditSecurityHeaders(HARDENED_HEADERS, HTTP_URL, { local: false });
    expect(nonLocal).toHaveLength(1);
    expect(nonLocal[0]).toMatchObject({
      severity: "high",
      title: "No HTTPS, traffic sent in cleartext",
      category: "transport",
      source: "header-audit",
      url: HTTP_URL,
    });

    expect(auditSecurityHeaders(HARDENED_HEADERS, HTTP_URL, { local: true })).toEqual([]);
  });

  it("flags Python server banners (uvicorn, gunicorn, werkzeug) and ignores generic servers", () => {
    for (const banner of ["uvicorn", "gunicorn/21.2.0", "Werkzeug/3.0.1 Python/3.12"]) {
      const findings = auditSecurityHeaders({ ...HARDENED_HEADERS, server: banner }, HTTPS_URL);
      expect(findings, banner).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        severity: "info",
        title: "Server version disclosed",
        category: "disclosure",
        source: "header-audit",
        url: HTTPS_URL,
      });
    }

    expect(auditSecurityHeaders({ ...HARDENED_HEADERS, server: "nginx" }, HTTPS_URL)).toEqual([]);
  });
});

describe("auditSecurityHeaders — hardened response", () => {
  it("returns 0 findings for a fully hardened HTTPS response", () => {
    const findings = auditSecurityHeaders(HARDENED_HEADERS, HTTPS_URL, {
      local: false,
      liveResponse: true,
    });
    expect(findings).toEqual([]);
  });
});
