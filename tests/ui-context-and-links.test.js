/**
 * Approval needs some context to judge a change, on the local screen only. Symlinks can neither
 * redirect the dashboard's one settings write nor empty a project's tabs.
 */
import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { redactPlan } from "../lib/fix/index.js";
import { runLoop } from "../src/agent/loop.js";
import { createDataSource } from "../src/ui/api/data.js";
import { createRunManager } from "../src/ui/api/runs.js";
import { createSettings } from "../src/ui/server.js";

const DIFF = ["--- a/x.js", "+++ b/x.js", "@@ -1,3 +1,3 @@", " const a = 1;", '-const key = "s3cret-value-1234";', '+const key = process.env.KEY;', " const b = 2;"].join("\n");
const PLAN = { title: "t", recipe: "r", files: ["x.js"], diff: DIFF, redactions: ["s3cret-value-1234"] };
const temp = () => realpathSync(mkdtempSync(join(tmpdir(), "penthera-ui-")));

describe("redactPlan", () => {
  it("shows changed lines only by default, with no context field", () => {
    const p = redactPlan(PLAN);
    expect(p.diff).not.toContain("const a = 1;");
    expect(p).not.toHaveProperty("contextDiff");
  });
  it("masks a context line that looks like a diff header, and doesn't call a line ending masked", () => {
    const framed = (line) => redactPlan({ diff: `@@ -1 +1 @@\n ${line}\n+a`, redactions: ["s3cret-value-1234"] }, { context: true });
    expect(framed("++ s3cret-value-1234").contextDiff).not.toContain("s3cret-value-1234");
    expect(redactPlan({ diff: "@@ -1 +1 @@\n+++ s3cret-value-1234", redactions: ["s3cret-value-1234"] }).diff).not.toContain("s3cret-value-1234");
    expect(framed("const a = 1;\r").redacted).toBe(false);
    expect(redactPlan({ diff: "+const a = 1;\r", redactions: [] }).redacted).toBe(false);
  });

  it("adds masked context only when asked", () => {
    const p = redactPlan(PLAN, { context: true });
    expect(p.contextDiff).toContain(" const a = 1;");
    expect(p.contextDiff).toContain(" const b = 2;");
    expect(p.contextDiff).not.toContain("s3cret-value-1234");
    expect(p.diff).toBe(redactPlan(PLAN).diff);
  });
  it("masks a flagged value on an unchanged line, and a key block", () => {
    const secret = { ...PLAN, diff: `@@ -1 +1 @@\n const k = "s3cret-value-1234";\n+x\n -----BEGIN PRIVATE KEY-----\n abcdef\n -----END PRIVATE KEY-----\n+y` };
    const shown = redactPlan(secret, { context: true }).contextDiff;
    expect(shown).not.toContain("s3cret-value-1234");
    expect(shown).not.toContain("abcdef");
  });
});

describe("context lines", () => {
  const frame = (line) => redactPlan({ title: "t", diff: `@@ -1,2 +1,2 @@\n ${line}\n-old\n+new`, redactions: [] }, { context: true }).contextDiff;

  it.each([
    ['const header = { Authorization: "Basic dXNlcjpwYXNz" };', "dXNlcjpwYXNz"],
    ['const encryptionKey = "enc-value-12";', "enc-value-12"],
    ["curl -u admin:pw https://x.example", "admin:pw"],
    ['const id = "4f1c2a9e-7b3d-4e21-9a50-1c2d3e4f5a6b";', "4f1c2a9e"],
    ['const k = "a3f5c8e1b2d94760a3f5c8e1b2d94760";', "a3f5c8e1"],
    ['const password = process.env.X || fallback;', "fallback"],
    ["db_password: hunter2", "hunter2"],
  ])("hides %s", (line, value) => {
    expect(frame(line)).not.toContain(value);
    expect(frame(line)).toContain("[line hidden]");
  });

  it.each(["const a = 1;", "function handler(req, res) {", 'import express from "express";', "app.use(helmet());", "  return next();"])("keeps %s", (line) => {
    expect(frame(line)).toContain(line);
  });
});

describe("the dashboard's approval window", () => {
  const start = async (plan, extra = {}) => {
    const roots = [temp()];
    let asked = null;
    const runLoop = async (o) => {
      asked = o;
      await o.ask({ plan, contextDiff: extra.contextDiff, iteration: 1, index: 1, total: 1 });
      return { stopReason: "x", error: null, totals: { verified: 0 }, findings: {}, branch: {}, durationMs: 1, iterations: [] };
    };
    const mgr = createRunManager({ runLoop, settings: () => ({ offline: true }), projectRoots: roots });
    const run = mgr.start({ kind: "loop", repo: roots[0] });
    await new Promise((r) => setTimeout(r, 20));
    return { mgr, run: mgr.get(run.id), opts: asked };
  };

  it("asks the loop for context and shows it", async () => {
    const { run, opts, mgr } = await start({ title: "t", diff: "+a" }, { contextDiff: " before\n+a" });
    expect(opts.approvalContext).toBe(true);
    const { pending } = mgr.publicRun(run);
    expect(pending.plan.diff).toBe(" before\n+a");
    mgr.stop(run.id);
  });

  it("falls back to the changed lines", async () => {
    const { run, mgr } = await start({ title: "t", diff: "+a" });
    expect(mgr.publicRun(run).pending.plan.diff).toBe("+a");
    mgr.stop(run.id);
  });

  it("binds approval to the text the window showed", async () => {
    const { run, mgr } = await start({ title: "t", diff: "+a" }, { contextDiff: " before\n+a" });
    const { approvalId } = mgr.publicRun(run).pending;
    expect(() => mgr.decide(run.id, { approvalId, answer: "approve", diffSha256: "0".repeat(64) })).toThrow(/does not match/);
    mgr.stop(run.id);
  });
});

describe("where context can go", () => {
  const MARK = "contextMarkerLine";
  const walk = (dir) => (existsSync(dir) ? readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(dir, e.name)) : [readFileSync(join(dir, e.name), "utf8")])) : []);

  it("reaches the approval and nothing else", async () => {
    const root = temp();
    const repo = join(root, "app"), memoryRoot = join(root, "memory");
    cpSync("tests/fixtures/fix/express", repo, { recursive: true });
    const server = join(repo, "server.js");
    writeFileSync(server, readFileSync(server, "utf8").replace(/(const app = express\(\);?\n)/, `$1const ${MARK} = 1;\n`));
    const git = (...a) => execFileSync("git", a, { cwd: repo, stdio: "pipe" });
    git("init", "-q");
    git("add", "-A");
    git("-c", "user.email=t@e", "-c", "user.name=t", "commit", "-qm", "i");
    const seen = [], logs = [];
    const ask = async (q) => { seen.push(q); return "n"; };
    const run = await runLoop({ repo, memoryRoot, ask, approvalContext: true, log: (l) => logs.push(l) });
    expect(seen.some((q) => q.contextDiff?.includes(MARK))).toBe(true);
    expect(seen.every((q) => !JSON.stringify(q.plan).includes(MARK))).toBe(true);
    expect(JSON.stringify(run)).not.toContain(MARK);
    expect(logs.join("\n")).not.toContain(MARK);
    expect(walk(memoryRoot).join("\n")).not.toContain(MARK);
  }, 60_000);

  it("isn't asked for anywhere but the dashboard's run manager", () => {
    const callers = execFileSync("git", ["grep", "-lE", "approvalContext|context: true|contextDiff", "--", "src", "lib", "api", "bin"], { encoding: "utf8" }).trim().split("\n").sort();
    expect(callers).toEqual(["lib/fix/index.js", "src/agent/loop.js", "src/ui/api/runs.js"]);
  });

  it("isn't printed by the CLI's plan output or stored in a plan", () => {
    const shown = redactPlan(PLAN);
    expect(JSON.stringify(shown)).not.toContain("const a = 1;");
    expect(readFileSync("src/cli/fix.js", "utf8")).not.toMatch(/contextDiff|context: true/);
    expect(readFileSync("src/mcp/tools.js", "utf8")).not.toMatch(/contextDiff/);
  });

  it("leaves the run once the decision is made", async () => {
    const roots = [temp()];
    let release;
    const runLoop2 = async (o) => { await o.ask({ plan: { title: "t", diff: "+a" }, contextDiff: " before\n+a", iteration: 1, index: 1, total: 1 }); await new Promise((r) => { release = r; }); return { stopReason: "x", error: null, totals: { verified: 0 }, findings: {}, branch: {}, durationMs: 1, iterations: [] }; };
    const mgr = createRunManager({ runLoop: runLoop2, settings: () => ({ offline: true }), projectRoots: roots });
    const run = mgr.start({ kind: "loop", repo: roots[0] });
    await new Promise((r) => setTimeout(r, 20));
    const { approvalId } = mgr.publicRun(mgr.get(run.id)).pending;
    mgr.decide(run.id, { approvalId, answer: "skip" });
    expect(JSON.stringify(mgr.publicRun(mgr.get(run.id)))).not.toContain("before");
    const replay = [];
    mgr.subscribe(run.id, -1, (e) => { if (e) replay.push(JSON.stringify(e)); })?.();
    expect(replay.join()).toContain("approval");
    expect(replay.join()).not.toContain("before");
    await new Promise((r) => setTimeout(r, 10));
    release?.();
  });
});

describe("a symlinked project", () => {
  const setup = () => {
    const root = temp();
    const app = join(root, "app"), link = join(root, "link"), reports = join(app, "reports");
    mkdirSync(reports, { recursive: true });
    symlinkSync(app, link);
    writeFileSync(join(reports, "d.json"), JSON.stringify({ target: link, mode: "deps", deps: { total: 1, scanned: 1, direct: [], capabilityCounts: {} }, timestamp: "2026-11-01T10:00:00Z", findings: [] }));
    writeFileSync(join(reports, "a.json"), JSON.stringify({ target: link, mode: "agents", agents: { grade: "A", score: 100, inventory: {} }, timestamp: "2026-11-01T10:00:00Z", findings: [] }));
    return { link, app, src: createDataSource({ projects: [link], reportsDir: reports, home: join(root, "h"), memoryRoot: join(root, "m"), settings: { get: () => ({}) } }) };
  };
  it("shows its deps and AI tabs by either path", () => {
    const { src, link, app } = setup();
    for (const key of [link, app]) {
      expect(src.deps(key).latest).not.toBeNull();
      expect(src.ai(key).latest).not.toBeNull();
    }
  });
});

describe("ui.json", () => {
  it("replaces a symlink instead of writing through it", () => {
    const root = temp();
    const victim = join(root, "victim.txt"), file = join(root, "ui.json");
    writeFileSync(victim, "keep me\n");
    symlinkSync(victim, file);
    const s = createSettings({ offline: true, file });
    s.update({ ux: "advanced" });
    expect(readFileSync(victim, "utf8")).toBe("keep me\n");
    expect(lstatSync(file).isSymbolicLink()).toBe(false);
    expect(JSON.parse(readFileSync(file, "utf8")).ux).toBe("advanced");
  });
  it("isn't stopped by a leftover temp file", () => {
    const file = join(temp(), "ui.json");
    writeFileSync(`${file}.${process.pid}.tmp`, "");
    createSettings({ offline: true, file }).update({ ux: "advanced" });
    expect(JSON.parse(readFileSync(file, "utf8")).ux).toBe("advanced");
  });

  it("still writes a plain file, private to the user", () => {
    const file = join(temp(), "home", "ui.json");
    createSettings({ offline: true, file }).update({ ux: "simple" });
    expect(existsSync(file)).toBe(true);
    expect(lstatSync(file).mode & 0o777).toBe(0o600);
  });
});
