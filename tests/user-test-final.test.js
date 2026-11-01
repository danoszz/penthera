/**
 * The final user test: an unread site can't grade A in the wizard, the brief says what it skipped,
 * and the words on a project agree with each other.
 */
import { describe, it, expect } from "vitest";
import { mkdirSync, mkdtempSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { gradeArea, countLine } from "../src/cli/onboarding.js";
import { buildBrief } from "../src/report/brief.js";
import { createDataSource } from "../src/ui/api/data.js";
import { alsoOpen, SIMPLE_KINDS, KINDS, verdict } from "../src/ui/static/js/copy.js";
import { checkedWhat, runBelongs } from "../src/ui/static/js/format.js";
import { projectKeys, state } from "../src/ui/static/js/state.js";

const REFUSED = { target: "http://127.0.0.1:5173", mode: "url", reachable: true, challenge: { provider: "Cloudflare", action: "challenge" }, findings: [{ severity: "info", title: "Cloudflare served a bot challenge instead of the site" }] };

describe("the wizard on a firewall's page", () => {
  it("gives no grade and says why", () => {
    const r = { merged: REFUSED };
    gradeArea(r);
    expect(r.grade).toBe("–");
    expect(r.score).toBeNull();
    expect(countLine(REFUSED.findings, r.unchecked)).toContain("We couldn't see your site.");
    expect(countLine(REFUSED.findings, r.unchecked)).not.toContain("no issues");
  });
  it("still grades a site it read", () => {
    const r = { merged: { ...REFUSED, challenge: undefined, findings: [] } };
    gradeArea(r);
    expect(r.grade).toBe("A");
  });
});

describe("the brief on a challenge", () => {
  it("names what it couldn't read", () => {
    const b = buildBrief(REFUSED);
    expect(b.not_checked.join(" ")).toContain("Cloudflare answered instead of the site");
    expect(b.not_checked.join(" ")).not.toContain("reported nothing it skipped");
  });
});

describe("a project with code findings and an unread site", () => {
  const unread = { text: "Cloudflare answered instead of the site, so this says nothing about it, good or bad." };
  it.each([[{ critical: 2 }], [{ high: 1 }]])("names the unread site with %j", (counts) => {
    const v = verdict({ scanned: true, when: "now", counts, open: 2, unread });
    expect(v.sub).toContain("We couldn't see your site.");
    expect(v.sub).toContain(unread.text);
  });
  it("doesn't say the site was checked", () => {
    expect(checkedWhat("url+repo", unread)).toBe("your code, not your site");
    expect(checkedWhat("url", unread)).toBe("site not read");
    expect(checkedWhat("url+repo")).toBe("your site and code");
  });
});

describe("the end of a check", () => {
  it("says the project has more when this check found nothing", () => {
    expect(alsoOpen(0, 2)).toBe("Your project still has 2 problems from its other checks.");
    expect(alsoOpen(0, 1)).toBe("Your project still has 1 problem from its other checks.");
  });
  it("says nothing more otherwise", () => {
    expect(alsoOpen(1, 2)).toBe("");
    expect(alsoOpen(0, 0)).toBe("");
  });
});

describe("the check window", () => {
  it("has a button label for every kind, in both modes", () => {
    for (const k of [...SIMPLE_KINDS, ...KINDS]) expect(k.button, k.kind).toBeTruthy();
  });
});

describe("a URL and folder project", () => {
  const key = "http://127.0.0.1:4602 + /code/app";
  it("owns its runs", () => {
    expect(runBelongs(key, "/code/app", "http://127.0.0.1:4602")).toBe(true);
    expect(runBelongs(key, "/code/app", null)).toBe(true);
    expect(runBelongs(key, "/code/other", null)).toBe(false);
    expect(runBelongs("/code/app", "/code/app", null)).toBe(true);
    expect(runBelongs("http://127.0.0.1:4602", null, "http://127.0.0.1:4602")).toBe(true);
    expect(runBelongs(null, "/x", null)).toBe(true);
  });
  it("leaves no second row for its folder", () => {
    Object.assign(state, { overview: { projects: [{ key }] }, meta: { projects: ["/code/app", "/code/other"] } });
    expect(projectKeys()).toEqual([key, "/code/other"]);
  });
});

describe("a project under a symlinked path", () => {
  it("joins a deps audit to its scan", () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "penthera-ui-")));
    const app = join(root, "app"), link = join(root, "link"), reports = join(app, "reports");
    mkdirSync(reports, { recursive: true });
    symlinkSync(app, link);
    writeFileSync(join(reports, "a.json"), JSON.stringify({ target: link, mode: "repo", timestamp: "2026-11-01T10:00:00Z", findings: [] }));
    writeFileSync(join(reports, "b.json"), JSON.stringify({ target: app, folder: app, mode: "deps", deps: { total: 1, scanned: 1, direct: [], capabilityCounts: {} }, timestamp: "2026-11-01T10:01:00Z", findings: [{ severity: "critical", title: "Bad package", category: "dependency-risk" }] }));
    const src = createDataSource({ projects: [app], reportsDir: reports, home: join(root, "h"), memoryRoot: join(root, "m"), settings: { get: () => ({}) } });
    expect(src.overview().projects).toHaveLength(1);
    expect(src.overview().projects[0].counts.critical).toBe(1);
  });
});
