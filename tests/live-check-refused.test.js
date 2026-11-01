/**
 * A firewall's challenge sends strict security headers of its own, so grading it scored 100,
 * "Solid basics". Only the firewall's own header decides here: no body signature, so no false call.
 */
import { describe, it, expect } from "vitest";
import { grade } from "../api/_lib/grade.mjs";
import { refusedOf, ungraded } from "../api/_lib/tier1.mjs";
import { handoffTitle, reportMarkdown } from "../site/check/card.js";
import { SITE_NOT_READ } from "../src/report/unread.js";

const STRICT = { "content-type": "text/html", "content-security-policy": "default-src 'none'; script-src 'nonce-a'; frame-ancestors 'none'", "x-content-type-options": "nosniff", "referrer-policy": "same-origin", "permissions-policy": "camera=()", "strict-transport-security": "max-age=31536000" };
const response = (headers) => ({ url: "https://shop.example/", status: 403, hops: [{ url: "https://shop.example/" }], tls: { protocol: "TLSv1.3", authorized: true, validTo: "Oct 1 00:00:00 2027 GMT" }, headers });
const dmarc = { id: "dmarc", weight: 4, category: "email", passed: false, severity: "medium", title: "No DMARC", evidence: "", fix: "Publish a DMARC record for your domain.", verify: "dig txt _dmarc.shop.example" };
const report = (headers) => {
  const r = response(headers);
  const refused = refusedOf(r);
  return { tier: "passive", ...(refused ? { refused } : {}), ...grade(r, { now: Date.parse("2026-11-01"), extra: [dmarc], scope: "One GET." }) };
};

describe("the live check on a firewall's page", () => {
  it.each([["cf-mitigated", "challenge", "Cloudflare"], ["x-vercel-mitigated", "challenge", "Vercel"], ["x-vercel-mitigated", "deny", "Vercel"]])("%s: %s has no score", (name, value, provider) => {
    const r = ungraded(report({ ...STRICT, [name]: value }));
    expect(r.refused.provider).toBe(provider);
    expect(r).not.toHaveProperty("score");
    expect(r).not.toHaveProperty("scoreVersion");
    expect(r.verdict).toBe("We couldn't see your site");
    expect(`${r.verdict}.`).toBe(SITE_NOT_READ);
  });

  it("keeps the mail checks and drops what it read off the firewall's page", () => {
    const r = ungraded(report({ ...STRICT, "cf-mitigated": "challenge" }));
    expect(r.checks.map((c) => c.id)).toEqual(["dmarc"]);
    expect(r.categories.map((c) => c.id)).toEqual(["email"]);
  });

  it("never reads as clean or as a score", () => {
    const r = ungraded(report({ ...STRICT, "cf-mitigated": "challenge" }));
    expect(handoffTitle({ ...r, checks: [] })).toBe("We couldn't see your site");
    expect(reportMarkdown(r)).toContain(r.nextStep);
    expect(reportMarkdown(r)).not.toMatch(/undefined|\/100/);
  });

  it("still grades a real app's 403 with no firewall header", () => {
    const r = report(STRICT);
    expect(r.refused).toBeUndefined();
    expect(r.score).toBeGreaterThan(0);
  });
});
