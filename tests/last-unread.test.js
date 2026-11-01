/**
 * The last two ways a run that read nothing could look clean: a deps audit with no package code
 * to read, and a server error the live check graded by its headers.
 */
import { describe, it, expect } from "vitest";
import { buildBrief, VERDICTS } from "../src/report/brief.js";
import { readNothing } from "../src/report/unread.js";
import { buildOverview, withAudits } from "../src/ui/api/summarize.js";
import { grade } from "../api/_lib/grade.mjs";
import { refusedOf, ungraded } from "../api/_lib/tier1.mjs";
import { handoffTitle } from "../site/check/card.js";

const UNREAD = { total: 1, scanned: 0, notInstalled: ["a"], direct: [], capabilityCounts: {} };
const PART = { total: 2, scanned: 1, notInstalled: ["a"], direct: [], capabilityCounts: {} };
const READ = { total: 2, scanned: 2, notInstalled: [], direct: [], capabilityCounts: {} };
const deps = (d) => ({ target: "/app", mode: "deps", deps: d, timestamp: "2026-11-01T10:00:00Z", findings: [] });
const project = (data) => buildOverview({ scans: [{ name: "r.json", mtime: 1, data }] }).projects[0];

describe("readNothing", () => {
  it("is true only when every audit read nothing", () => {
    expect(readNothing(deps(UNREAD))).toBe(true);
    expect(readNothing(deps(PART))).toBe(false);
    expect(readNothing(deps(READ))).toBe(false);
    expect(readNothing({ mode: "agents", agents: { grade: null } })).toBe(true);
    expect(readNothing({ mode: "agents", agents: { grade: "A" } })).toBe(false);
    expect(readNothing({ mode: "deps+agents", deps: UNREAD, agents: { grade: "A" } })).toBe(false);
    expect(readNothing({ mode: "deps+agents", deps: UNREAD, agents: { grade: null } })).toBe(true);
  });

  it("leaves a repo scan that also read some deps alone", () => {
    expect(readNothing({ mode: "repo", deps: UNREAD })).toBe(false);
    expect(readNothing({ modes: ["url", "repo"], deps: UNREAD })).toBe(false);
  });
});

describe("a deps audit that read nothing", () => {
  it("doesn't say Nothing to fix", () => {
    expect(buildBrief(deps(UNREAD)).verdict).toBe(VERDICTS.none);
  });
  it("still says so with an info finding", () => {
    expect(buildBrief({ ...deps(UNREAD), findings: [{ severity: "info", title: "note" }] }).verdict).toBe(VERDICTS.none);
  });
  it("keeps a real result for an audit that read packages", () => {
    expect(buildBrief(deps(READ)).verdict).toBe(VERDICTS.clean);
  });
  it("has no grade in the dashboard", () => {
    expect(project(deps(UNREAD))).toMatchObject({ grade: "–", score: null });
    expect(project(deps(READ)).grade).toBe("–");
  });
  it("has no grade as a project made from audits alone", () => {
    const audits = [{ name: "d.json", mtime: 1, data: deps(UNREAD) }];
    const scans = withAudits([], audits, (d) => d.target);
    expect(buildOverview({ scans }).projects[0]).toMatchObject({ grade: "–", score: null });
  });
});

describe("the live check on a server error", () => {
  const STRICT = { "content-type": "text/html", "content-security-policy": "default-src 'self'", "x-content-type-options": "nosniff", "x-frame-options": "DENY", "referrer-policy": "no-referrer", "permissions-policy": "camera=()", "strict-transport-security": "max-age=31536000" };
  const response = (status, url = "https://shop.example/") => ({ url, status, hops: [{ url }], tls: url.startsWith("https") ? { protocol: "TLSv1.3", authorized: true, validTo: "Oct 1 00:00:00 2027 GMT" } : null, headers: STRICT });
  const report = (r) => { const refused = refusedOf(r); return { tier: "passive", ...(refused ? { refused } : {}), ...grade(r, { now: Date.parse("2026-11-01"), scope: "One GET." }) }; };

  it.each([[503, "https://shop.example/"], [503, "http://shop.example/"], [500, "https://shop.example/"]])("%s on %s has no score", (status, url) => {
    const r = ungraded(report(response(status, url)));
    expect(r).not.toHaveProperty("score");
    expect(r.verdict).toBe("We couldn't see your site");
    expect(r.refused.text).toBe(`It answered HTTP ${status}, so this says nothing about it, good or bad.`);
  });

  it("still names the firewall", () => {
    const r = report({ ...response(403), headers: { ...STRICT, "cf-mitigated": "challenge" } });
    expect(r.refused).toMatchObject({ provider: "Cloudflare", text: "Cloudflare answered instead of the site, so this says nothing about it, good or bad." });
  });

  it("keeps grading a 200 and a 404", () => {
    expect(refusedOf(response(200))).toBeNull();
    expect(refusedOf(response(404))).toBeNull();
  });
});

describe("a 403 with no firewall header", () => {
  const blocked = { target: "https://shop.example/", mode: "url", reachable: true, httpStatus: 403, findings: [] };

  it("doesn't read as clean in the brief, and the exit code stays", () => {
    const b = buildBrief(blocked);
    expect(b.verdict).toBe(VERDICTS.review);
    expect(b.exit_code).toBe(0);
    expect(b.not_checked.join(" ")).toContain("HTTP 403");
  });

  it("doesn't read as clean on the live check", () => {
    expect(handoffTitle({ status: 403, checks: [{ passed: true }] })).not.toContain("Nothing to fix");
  });

  it("leaves a 200 alone", () => {
    expect(buildBrief({ ...blocked, httpStatus: 200 }).verdict).toBe(VERDICTS.clean);
    expect(handoffTitle({ status: 200, checks: [{ passed: true }] })).toContain("Nothing to fix");
  });
});
