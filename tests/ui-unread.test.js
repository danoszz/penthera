/**
 * A site Penthera never read has no grade. A clean folder beside a dead URL, or a firewall's
 * challenge, used to read A, 100/100. The dashboard, the CLI and the brief now say the same thing.
 */
import { describe, it, expect } from "vitest";
import { cpSync, mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { siteUnread, SITE_NOT_READ } from "../src/report/unread.js";
import { buildBrief, VERDICTS } from "../src/report/brief.js";
import { buildOverview } from "../src/ui/api/summarize.js";
import * as COPY from "../src/ui/static/js/copy.js";
import { createRunManager } from "../src/ui/api/runs.js";
import { createDataSource } from "../src/ui/api/data.js";
import { folderFor, set, state } from "../src/ui/static/js/state.js";
const { SITE_NOT_READ: PAGE_WORDS, verdict } = COPY;
import { keyParts } from "../src/ui/static/js/format.js";

const URL_ = "http://127.0.0.1:4699";
const DEAD = { target: `${URL_} + /code/app`, modes: ["url", "repo"], reachable: false, timestamp: "2026-11-01T10:00:00Z", findings: [] };
const REFUSED = { target: URL_, mode: "url", reachable: true, challenge: { provider: "Cloudflare", action: "challenge" }, timestamp: "2026-11-01T10:00:00Z", findings: [{ severity: "info", title: "Cloudflare served a bot challenge instead of the site" }] };
const READ = { target: URL_, mode: "url", reachable: true, timestamp: "2026-11-01T10:00:00Z", findings: [] };
const overview = (data) => buildOverview({ scans: [{ name: "r.json", mtime: 1, data }] });

describe("siteUnread", () => {
  it("names a firewall", () => {
    expect(siteUnread(REFUSED).text).toBe("Cloudflare answered instead of the site, so this says nothing about it, good or bad.");
  });
  it("names a dead address, and a server error", () => {
    expect(siteUnread(DEAD).text).toBe("Nothing answered at that address, so this says nothing about it, good or bad.");
    expect(siteUnread({ ...DEAD, httpStatus: 503 }).text).toBe("It answered HTTP 503, so this says nothing about it, good or bad.");
  });
  it("leaves a read site, a repo scan and an old report alone", () => {
    expect(siteUnread(READ)).toBeNull();
    expect(siteUnread({ target: "/code", mode: "repo", findings: [] })).toBeNull();
    expect(siteUnread({ target: URL_, mode: "url", findings: [] })).toBeNull();
    expect(siteUnread({ target: "/code", mode: "deps", reachable: false })).toBeNull();
  });
});

describe("the dashboard's overview", () => {
  it.each([["a dead URL", DEAD], ["a firewall's challenge", REFUSED]])("gives %s no grade and no score", (_n, data) => {
    const [p] = overview(data).projects;
    expect(p.grade).toBe("–");
    expect(p.score).toBeNull();
    expect(p.unread.text).toBe(siteUnread(data).text);
  });

  it("still grades a site it read", () => {
    const [p] = overview(READ).projects;
    expect(p.grade).toBe("A");
    expect(p.unread).toBeNull();
  });

  it("keeps findings from the folder that was read", () => {
    const high = { severity: "high", title: "Secret in code", category: "secrets" };
    const [p] = overview({ ...DEAD, findings: [high] }).projects;
    expect(p.counts.high).toBe(1);
    expect(p.grade).toBe("–");
  });
});

describe("the dashboard's verdict", () => {
  const unread = { text: "Nothing answered at that address, so this says nothing about it, good or bad." };
  const base = { scanned: true, when: "just now", counts: {}, open: 0 };

  it("says the CLI's sentence, and never Nothing open", () => {
    const v = verdict({ ...base, unread });
    expect(v.text).toBe(SITE_NOT_READ);
    expect(v.sub).toBe(unread.text);
    expect(v.level).toBe("unread");
  });

  it("offers no fix when only notes are open", () => {
    expect(verdict({ ...base, unread, top: { severity: "info" } }).top).toBeUndefined();
  });

  it("keeps saying so with smaller findings open", () => {
    expect(verdict({ ...base, unread, open: 2 }).text).toBe(SITE_NOT_READ);
  });

  it("leads with a serious finding, as the brief does", () => {
    expect(verdict({ ...base, unread, counts: { high: 1 } }).level).toBe("fix");
  });

  it("is unchanged for a site it read", () => {
    expect(verdict(base).text).toBe("Nothing open. The last check found no problems.");
  });
});

describe("the CLI's brief, with a folder beside a dead URL", () => {
  it("says the site wasn't read, and the exit code doesn't move", () => {
    const b = buildBrief(DEAD);
    expect(b.verdict).toBe(VERDICTS.unread);
    expect(b.exit_code).toBe(0);
  });
});

describe("a project's key", () => {
  it("splits a URL and folder scan", () => {
    expect(keyParts("http://127.0.0.1:4601 + /code/app")).toEqual({ url: "http://127.0.0.1:4601", folder: "/code/app" });
  });
  it("reads a folder or a URL alone", () => {
    expect(keyParts("/code/app")).toEqual({ url: "", folder: "/code/app" });
    expect(keyParts("https://shop.example")).toEqual({ url: "https://shop.example", folder: "" });
    expect(keyParts(null)).toEqual({ url: "", folder: "" });
  });
  it("keeps a folder with a plus in its name", () => {
    expect(keyParts("/code/a + b")).toEqual({ url: "", folder: "/code/a + b" });
    expect(keyParts("http://x.test + /code/a + b")).toEqual({ url: "http://x.test", folder: "/code/a + b" });
  });
});

describe("a dashboard run", () => {
  const roots = [realpathSync(mkdtempSync(join(tmpdir(), "penthera-ui-")))];
  const finished = async (mgr, run) => { while (mgr.get(run.id).status === "running") await new Promise((r) => setTimeout(r, 5)); return mgr.get(run.id); };
  const loopRun = (over = {}) => ({ stopReason: "x", error: null, totals: { verified: 1 }, findings: {}, branch: {}, durationMs: 1, iterations: [{ n: 1, fixes: [{ title: "t", verify: { liveRemaining: 2 } }] }], ...over });

  it("names its project and whether it read the site", async () => {
    const mgr = createRunManager({ executeScan: async () => ({ merged: DEAD }), writeReport: () => null, settings: () => ({ offline: true }), projectRoots: roots });
    const run = await finished(mgr, mgr.start({ kind: "scan", repo: roots[0], url: URL_ }));
    expect(run.summary.project).toBe(DEAD.target);
    expect(run.summary.unread.text).toBe(siteUnread(DEAD).text);
  });

  it("rescans the same targets after a fix, so results stay on one project", async () => {
    const calls = [];
    const executeScan = async (o) => { calls.push(o); return { merged: { ...DEAD, reachable: true } }; };
    const mgr = createRunManager({ runLoop: async () => loopRun(), executeScan, writeReport: () => "r.json", settings: () => ({ offline: true }), projectRoots: roots });
    const run = await finished(mgr, mgr.start({ kind: "loop", repo: roots[0], url: URL_ }));
    expect(calls[0].url).toBe(URL_);
    expect(calls[0].repo).toBe(roots[0]);
    expect(run.summary.project).toBe(DEAD.target);
  });

  it("counts what the running app still serves, so the plain view can say so", async () => {
    const mgr = createRunManager({ runLoop: async () => loopRun(), executeScan: async () => ({ merged: DEAD }), writeReport: () => null, settings: () => ({ offline: true }), projectRoots: roots });
    expect((await finished(mgr, mgr.start({ kind: "loop", repo: roots[0] }))).summary.liveRemaining).toBe(2);
  });

  it("doesn't offer a flag the page can't pass", async () => {
    const message = "/code has uncommitted changes (a.js). Commit or stash them first, or pass --allow-dirty.";
    const mgr = createRunManager({ runLoop: async () => { throw new Error(message); }, settings: () => ({ offline: true }), projectRoots: roots });
    const run = await finished(mgr, mgr.start({ kind: "loop", repo: roots[0] }));
    const said = [];
    mgr.subscribe(run.id, -1, (e) => { if (e) said.push(JSON.stringify(e)); });
    expect(said.join()).toContain("Commit or stash them first.");
    expect(said.join()).not.toContain("--allow-dirty");
  });
});

describe("a URL and folder project on the server", () => {
  const FINDING = { severity: "medium", title: "Missing Content-Security-Policy", category: "headers", url: "http://127.0.0.1:4602", source: "header-audit" };
  const setup = () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "penthera-ui-")));
    const project = join(root, "app"), reports = join(root, "reports");
    cpSync("tests/fixtures/fix/express", project, { recursive: true });
    mkdirSync(reports);
    const target = `http://127.0.0.1:4602 + ${project}`;
    writeFileSync(join(reports, "r.json"), JSON.stringify({ target, modes: ["url", "repo"], reachable: true, timestamp: "2026-11-01T10:00:00Z", findings: [FINDING] }));
    const src = createDataSource({ projects: [project], reportsDir: reports, home: join(root, "home"), memoryRoot: join(root, "memory"), settings: { get: () => ({}) } });
    return { src, target, project };
  };

  it("previews a fix, so the page doesn't say it can't", async () => {
    const { src, target } = setup();
    const row = src.findings().find((f) => f.title === FINDING.title);
    expect(row.project).toBe(target);
    expect((await src.finding(row.id, target)).fix?.recipe).toBeTruthy();
  });

  it("finds the project's folder for the environment card", () => {
    const { src, target, project } = setup();
    expect(src.env(target).folder).toBe(project);
  });
});

describe("the page's project state", () => {
  it("drops a finding from another project", () => {
    Object.assign(state, { finding: { id: "x", project: "/a" }, right: "finding" });
    set({ sel: { kind: "project", key: "/b" } });
    expect(state.finding).toBeNull();
    expect(state.right).toBe("none");
  });

  it("keeps a finding of the same project", () => {
    Object.assign(state, { finding: { id: "x", project: "/a" }, right: "finding" });
    set({ sel: { kind: "project", key: "/a" } });
    expect(state.finding).toEqual({ id: "x", project: "/a" });
  });

  it("takes the folder out of a URL and folder project", () => {
    Object.assign(state, { meta: { projects: ["/other"] } });
    expect(folderFor("http://127.0.0.1:4601 + /code/app")).toBe("/code/app");
    expect(folderFor("http://127.0.0.1:4601")).toBe("/other");
  });
});

describe("the page's words", () => {
  it("match the CLI's", () => {
    expect(PAGE_WORDS).toBe(SITE_NOT_READ);
  });
});

describe("the welcome text", () => {
  it("doesn't promise that nothing leaves the computer", () => {
    expect(JSON.stringify(COPY)).not.toContain("Nothing is sent anywhere");
    expect(JSON.stringify(COPY)).toContain("only to a site you name");
  });
});

describe("suppressed findings in the dashboard", () => {
  const hidden = (severity) => ({ target: "/code/app", mode: "repo", timestamp: "2026-11-01T10:00:00Z", findings: [], suppressed: [{ severity, title: "x" }] });

  it("gives no grade while a critical or high finding is suppressed", () => {
    const [p] = overview(hidden("critical")).projects;
    expect(p).toMatchObject({ grade: "–", score: null, suppressed: 1, open: 0 });
  });

  it("keeps the grade when only smaller findings are suppressed, and still counts them", () => {
    const [p] = overview(hidden("low")).projects;
    expect(p.grade).toBe("A");
    expect(p.suppressed).toBe(1);
  });

  it("never says nothing is open, or calls it clear", () => {
    const v = verdict({ counts: {}, open: 0, scanned: true, when: "now", suppressed: 3 });
    expect(v.text).toBe("3 suppressed.");
    expect(v.level).not.toBe("clear");
  });
});
