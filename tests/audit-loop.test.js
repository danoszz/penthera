/**
 * Remediation / audit-loop tracking (measure f): stable fingerprint, history
 * folding (new/resolved/reopened), and metrics (time-to-fix, ageing).
 */
import { describe, it, expect } from "vitest";
import {
  fingerprintFinding, emptyHistory, updateHistory, buildAuditLoop, formatAuditLoopMarkdown,
} from "../lib/audit-loop.js";

const f = (o) => ({ severity: "high", title: "t", category: "c", source: "s", url: "/x", ...o });

describe("stable fingerprint", () => {
  const fp = (o) => fingerprintFinding(f(o));

  it("collapses numeric object ids in the URL so re-scanned ids match (IDOR)", () => {
    expect(fp({ title: "IDOR/BOLA on users", url: "/api/users/1" }))
      .toBe(fp({ title: "IDOR/BOLA on users", url: "/api/users/2" }));
  });

  it("does NOT merge genuinely distinct digit-bearing findings", () => {
    expect(fp({ title: "Weak cipher: AES128-GCM" })).not.toBe(fp({ title: "Weak cipher: AES256-GCM" }));
    expect(fp({ title: "Weak TLS protocol: TLSv1.0" })).not.toBe(fp({ title: "Weak TLS protocol: TLSv1.1" }));
    expect(fp({ title: "Vulnerable JS library: jquery 1.12.4" })).not.toBe(fp({ title: "Vulnerable JS library: jquery 3.4.0" }));
    expect(fp({ url: "/api/v1/users", title: "Unauthenticated endpoint" })).not.toBe(fp({ url: "/api/v2/users", title: "Unauthenticated endpoint" }));
  });

  it("separates distinct CVEs on the same library via description", () => {
    expect(fp({ category: "cve", title: "Vulnerable JS library: lodash 4.17.4", description: "CVE-2019-1111" }))
      .not.toBe(fp({ category: "cve", title: "Vulnerable JS library: lodash 4.17.4", description: "CVE-2020-2222" }));
  });

  it("distinguishes genuinely different findings", () => {
    expect(fp({ title: "CSP missing" })).not.toBe(fp({ title: "HSTS missing" }));
  });

  it("ignores severity (a severity change is not new+resolved churn)", () => {
    expect(fp({ severity: "low" })).toBe(fp({ severity: "high" }));
  });
});

describe("updateHistory + buildAuditLoop", () => {
  it("marks all findings new on the first scan", () => {
    const h = updateHistory(emptyHistory(), [f({ title: "a" }), f({ title: "b" })], "2026-01-01T00:00:00Z");
    expect(h.scans[0].new).toBe(2);
    const a = buildAuditLoop(h, "2026-01-01T00:00:00Z");
    expect(a.openCount).toBe(2);
    expect(a.resolvedCount).toBe(0);
  });

  it("resolves disappeared findings and computes time-to-fix", () => {
    let h = updateHistory(emptyHistory(), [f({ title: "a" }), f({ title: "b" })], "2026-01-01T00:00:00Z");
    h = updateHistory(h, [f({ title: "a" })], "2026-01-11T00:00:00Z"); // b fixed after 10 days
    const a = buildAuditLoop(h, "2026-01-11T00:00:00Z");
    expect(a.openCount).toBe(1);
    expect(a.resolvedCount).toBe(1);
    expect(a.medianTimeToFixDays).toBe(10);
    expect(a.oldestOpenDays).toBe(10);
  });

  it("reopens a finding that reappears", () => {
    let h = updateHistory(emptyHistory(), [f({ title: "a" })], "2026-01-01T00:00:00Z");
    h = updateHistory(h, [], "2026-01-05T00:00:00Z");
    h = updateHistory(h, [f({ title: "a" })], "2026-01-10T00:00:00Z");
    expect(h.scans[2].reopened).toBe(1);
    expect(buildAuditLoop(h, "2026-01-10T00:00:00Z").openCount).toBe(1);
  });

  it("excludes info findings from tracking", () => {
    const h = updateHistory(emptyHistory(), [f({ severity: "info", title: "z" })], "2026-01-01T00:00:00Z");
    expect(buildAuditLoop(h, "2026-01-01T00:00:00Z").openCount).toBe(0);
  });

  it("buckets ageing of open items", () => {
    let h = updateHistory(emptyHistory(), [f({ title: "old" })], "2026-01-01T00:00:00Z");
    h = updateHistory(h, [f({ title: "old" }), f({ title: "fresh" })], "2026-05-01T00:00:00Z");
    const a = buildAuditLoop(h, "2026-05-01T00:00:00Z");
    expect(a.ageing["90+"]).toBe(1); // "old" is ~120 days
    expect(a.ageing["0-7"]).toBe(1); // "fresh" just added
  });

  it("renders markdown", () => {
    const h = updateHistory(emptyHistory(), [f({ title: "a" })], "2026-01-01T00:00:00Z");
    const md = formatAuditLoopMarkdown(buildAuditLoop(h, "2026-01-08T00:00:00Z"));
    expect(md).toContain("Remediation & audit loop");
    expect(md).toMatch(/median time-to-fix/i);
  });
});
