/**
 * `penthera agent --loop` (src/agent): the local scan → fix → verify → learn loop.
 *
 * Each test copies tests/fixtures/fix/express into a fresh git repo, points the
 * loop at it (and at the mock server for the live scan), and keeps memory in a
 * temp dir. Nothing is installed; the project test script is a tiny node file.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { execFileSync, spawn } from "node:child_process";
import { cpSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, existsSync, readdirSync, chmodSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { startMockServer } from "./fixtures/mock-server.js";
import { runLoop, loopVerdict, loopEgressContext, localModelFetch, fixBranchName, LoopError, LOOP_RUN_SCHEMA } from "../src/agent/loop.js";
import { fingerprintFinding } from "../lib/audit-loop.js";
import { assertAllowed, createGit, GitPolicyError, ALLOWED_SUBCOMMANDS } from "../src/agent/git.js";
import { checkEgress, currentEgress } from "../src/utils/http.js";
import { planFixes, probeRepo, createPatch } from "../lib/fix/index.js";
import { openMemory, projectIdFor, buildViews } from "../lib/memory/index.js";

const FIXTURE = resolve("tests/fixtures/fix/express");
const temps = [];
let mock;

beforeAll(async () => { mock = await startMockServer(0); });
afterAll(() => {
  mock?.close();
  temps.forEach((d) => rmSync(d, { recursive: true, force: true }));
});

function tempDir(prefix = "penthera-agent-") {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  temps.push(dir);
  return dir;
}

function git(dir, ...args) {
  return execFileSync("git", ["-c", "user.email=t@t", "-c", "user.name=t", ...args], {
    cwd: dir, encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"],
  });
}

/** The express fixture in a committed git repo on `main`. `edit(dir)` runs before the commit. */
function fixtureRepo(edit) {
  const dir = tempDir();
  cpSync(FIXTURE, dir, { recursive: true });
  if (edit) edit(dir);
  git(dir, "init", "-q", "-b", "main");
  git(dir, "add", "-A");
  git(dir, "commit", "-qm", "fixture");
  return dir;
}

const yes = async () => "y";
const fixes = (run) => run.iterations.flatMap((it) => it.fixes);
const commitsOn = (dir, range) => git(dir, "rev-list", range).trim().split("\n").filter(Boolean);

describe("agent loop: end to end", () => {
  it("takes the fixable findings on the express fixture to zero within the iteration limit", async () => {
    const repo = fixtureRepo();
    const memoryRoot = tempDir("penthera-mem-");
    const gitCalls = [];
    const gitExec = (cmd, args, o) => {
      // `git --version` is the runner's own version check, not a subcommand.
      if (args[0] !== "--version") gitCalls.push(args.slice(args.findIndex((a) => !a.startsWith("-") && !a.includes("=")))[0]);
      return execFileSync(cmd, args, o);
    };
    const run = await runLoop({ repo, url: mock.url, memoryRoot, ask: yes, deps: { gitExec } });

    expect(run.schema).toBe(LOOP_RUN_SCHEMA);
    expect(run.error).toBeNull();
    expect(run.stopReason).toBe("no-fixable-findings");
    expect(run.iterations.length).toBeLessThanOrEqual(5);
    expect(run.totals).toMatchObject({ applied: 5, verified: 5, failed: 0 });
    expect(fixes(run).map((f) => f.recipe).sort()).toEqual(
      ["auth-rate-limit", "cookie-flags", "cors-allowlist", "secret-to-env", "security-headers"],
    );

    // Zero fixable findings left: a fresh static scan plans nothing.
    const { plans } = await planFixes(repo, probeRepo(repo));
    expect(plans).toEqual([]);

    // Left on the fix branch with one verified commit per fix and a clean tree.
    expect(run.branch.fix).toMatch(/^penthera\/fix-\d{8}-\d{4}(-\d+)?$/);
    expect(git(repo, "rev-parse", "--abbrev-ref", "HEAD").trim()).toBe(run.branch.fix);
    expect(git(repo, "status", "--porcelain")).toBe("");
    expect(commitsOn(repo, `main..${run.branch.fix}`).reverse()).toEqual(run.totals.commits);
    expect(git(repo, "log", "-1", "--format=%B")).toMatch(/Nothing was pushed/);

    // Every step is timed, for W6's timeline.
    for (const it of run.iterations) for (const s of it.steps) expect(s).toMatchObject({ step: expect.any(String), startedAt: expect.any(String), durationMs: expect.any(Number) });
    expect(fixes(run)[0].steps.map((s) => s.step)).toEqual(["approve", "patch", "learn", "verify", "commit", "learn"]);

    // Memory got the scans, the fixes and the run itself.
    const mem = openMemory(projectIdFor({ repo }).id, { root: memoryRoot });
    expect(mem.verify().ok).toBe(true);
    const types = mem.events().map((e) => e.type);
    expect(types.filter((t) => t === "fix_applied")).toHaveLength(5);
    expect(types.filter((t) => t === "fix_verified")).toHaveLength(5);
    expect(types).toContain("scan");
    expect(types.at(-1)).toBe("loop_run");
    expect(mem.events().at(-1).data.id).toBe(run.id);

    // Only allow-listed, local git ran.
    expect(gitCalls.length).toBeGreaterThan(0);
    for (const sub of gitCalls) expect(ALLOWED_SUBCOMMANDS).toContain(sub);
  });

  it("ranks recipes from memory on a later run and auto-applies only proven ones with --auto low", async () => {
    const repo = fixtureRepo();
    const memoryRoot = tempDir("penthera-mem-");
    // Three approved runs build a verified history for every recipe.
    for (let i = 0; i < 3; i++) {
      const r = await runLoop({ repo, memoryRoot, ask: yes });
      expect(r.totals.verified).toBe(5);
      git(repo, "checkout", "-q", "main");
    }
    // One failure on cookie-flags: no longer eligible for --auto, and ranked below its peers.
    const mem = openMemory(projectIdFor({ repo }).id, { root: memoryRoot });
    mem.append({ type: "fix_failed", data: { id: "0000000000000000", recipe: "cookie-flags", framework: "express" } });

    const asked = [];
    const run = await runLoop({
      repo, memoryRoot, auto: "low",
      ask: async ({ plan }) => { asked.push(plan.recipe); return "y"; },
    });
    expect(run.stopReason).toBe("no-fixable-findings");
    const byRecipe = Object.fromEntries(fixes(run).map((f) => [f.recipe, f]));
    expect(asked).toEqual(["cookie-flags"]);
    expect(byRecipe["cookie-flags"].decision).toBe("approved");
    for (const r of ["security-headers", "cors-allowlist", "auth-rate-limit", "secret-to-env"]) {
      expect(byRecipe[r].decision).toBe("auto");
      expect(byRecipe[r].memory).toEqual({ verified: 3, failed: 0 });
    }
    expect(byRecipe["cookie-flags"].memory).toEqual({ verified: 3, failed: 1 });
    // Same severity (medium): proven recipes first, the one with a failure last.
    const medium = fixes(run).filter((f) => f.findings.some((x) => x.severity === "medium")).map((f) => f.recipe);
    expect(medium.at(-1)).toBe("cookie-flags");
    // Auto-approved fixes never waited on a prompt.
    expect(byRecipe["security-headers"].steps.map((s) => s.step)).not.toContain("approve");
  });
});

describe("agent loop: no remote operations", () => {
  it("rejects push, fetch, pull, remote, clone, ls-remote, submodule and other non-local git", () => {
    for (const sub of ["push", "fetch", "pull", "remote", "clone", "ls-remote", "submodule", "request-pull", "send-email", "daemon", "bundle"]) {
      expect(() => assertAllowed([sub, "origin"]), sub).toThrow(GitPolicyError);
    }
    expect(() => assertAllowed(["checkout", "https://example.com/repo.git"])).toThrow(/not allowed/);
    expect(() => assertAllowed(["log", "git@github.com:a/b.git"])).toThrow(/not allowed/);
    expect(() => assertAllowed(["status", "-c", "core.sshCommand=evil"])).toThrow(/not allowed/);
    expect(() => assertAllowed(["checkout", "--recurse-submodules", "main"])).toThrow(/not allowed/);
    expect(() => assertAllowed(["config", "remote.origin.url", "x"])).toThrow(/config --get/);
    expect(() => assertAllowed(["config", "--get", "user.email"])).not.toThrow();
    // A commit message may mention a URL; it is text, not an option.
    expect(() => assertAllowed(["commit", "-m", "see https://example.com", "--", "a.js"])).not.toThrow();
  });

  it("never spawns git for a forbidden subcommand, and hardens the ones it runs", () => {
    const calls = [];
    const exec = (cmd, args) => { calls.push([cmd, args]); return args[0] === "--version" ? "git version 2.54.0\n" : ""; };
    const g = createGit("/nowhere", { exec });
    expect(() => g.run("push", "origin", "HEAD")).toThrow(GitPolicyError);
    expect(() => g.tryRun("fetch")).toThrow(GitPolicyError);
    expect(calls).toEqual([]);
    g.run("commit", "-m", "x", "--", "a.js");
    const [cmd, args] = calls.at(-1);
    expect(cmd).toBe("git");
    expect(args).toEqual(expect.arrayContaining(["protocol.allow=never", "core.hooksPath=/dev/null", "core.fsmonitor=false"]));
    expect(args.slice(args.indexOf("commit"))).toEqual(["commit", "--no-verify", "-m", "x", "--", "a.js"]);
  });

  it("does not run the scanned repo's git hooks", async () => {
    const repo = fixtureRepo();
    const marker = join(tempDir(), "hook-ran");
    const hook = join(repo, ".git", "hooks", "pre-commit");
    writeFileSync(hook, `#!/bin/sh\ntouch ${JSON.stringify(marker)}\n`);
    chmodSync(hook, 0o755);
    const run = await runLoop({ repo, memoryRoot: tempDir("penthera-mem-"), ask: yes, maxIterations: 1 });
    expect(run.totals.verified).toBeGreaterThan(0);
    expect(existsSync(marker)).toBe(false);
  });

  it("has no code path that spawns anything but git and the project's test script", () => {
    const dir = resolve("src/agent");
    for (const file of [...readdirSync(dir).map((f) => join(dir, f)), resolve("src/cli/agent.js")]) {
      const src = readFileSync(file, "utf-8");
      const spawns = /child_process/.test(src);
      if (spawns) expect(["git.js", "tests.js"]).toContain(file.split("/").pop());
      expect(src).not.toMatch(/["'`]gh["'`]/);
      expect(src).not.toMatch(/["'](push|fetch|pull|remote|clone)["'],/);
    }
  });
});

describe("agent loop: network", () => {
  it("limits egress to the URL target and allows loopback only with --fix-model", () => {
    const ctx = loopEgressContext({ url: "http://localhost:3000" });
    expect(ctx.offline).toBe(true);
    expect(checkEgress("http://localhost:3000/x", {}, ctx).allowed).toBe(true);
    expect(checkEgress("https://example.com/", {}, ctx).allowed).toBe(false);
    expect(checkEgress("http://127.0.0.1:11434/api/generate", {}, ctx).allowed).toBe(false);

    const withModel = loopEgressContext({ url: "http://localhost:3000", fixModel: "qwen2.5-coder" });
    expect(checkEgress("http://127.0.0.1:11434/api/generate", {}, withModel).allowed).toBe(true);
    expect(checkEgress("https://example.com/", {}, withModel).allowed).toBe(false);

    const repoOnly = loopEgressContext({});
    expect(checkEgress("https://registry.npmjs.org/", {}, repoOnly).allowed).toBe(false);
  });

  it("sends the model call only to Ollama on 127.0.0.1:11434", async () => {
    expect(() => localModelFetch("https://api.example.com/api/generate", {})).toThrow(/Refusing to contact/);
    expect(() => localModelFetch("http://127.0.0.1:8080/api/generate", {})).toThrow(/Refusing to contact/);
  });

  it("runs every scan inside the offline egress context", async () => {
    const repo = fixtureRepo();
    const seen = [];
    const { scanRepo } = await import("../src/scan-repo.js");
    const run = await runLoop({
      repo, url: "http://localhost:9", memoryRoot: tempDir("penthera-mem-"), ask: async () => "n", maxIterations: 1,
      deps: {
        scanRepo: (p, o) => { seen.push(["repo", currentEgress()?.offline, currentEgress()?.targetHost]); return scanRepo(p, o); },
        scanUrl: async (u, o) => { seen.push(["url", o.offline, currentEgress()?.offline]); return { findings: [] }; },
      },
    });
    expect(run.error).toBeNull();
    expect(seen.length).toBeGreaterThan(0);
    for (const s of seen) expect(s[1]).toBe(true);
    expect(seen.find((s) => s[0] === "repo")[2]).toBe("localhost");
  });
});

describe("agent loop: clean start", () => {
  it("refuses a dirty tree, including untracked files", async () => {
    const repo = fixtureRepo();
    writeFileSync(join(repo, "server.js"), readFileSync(join(repo, "server.js"), "utf-8") + "\n// wip\n");
    await expect(runLoop({ repo, memoryRoot: tempDir(), ask: yes })).rejects.toMatchObject({ code: "DIRTY" });
    expect(git(repo, "rev-parse", "--abbrev-ref", "HEAD").trim()).toBe("main");

    const repo2 = fixtureRepo();
    writeFileSync(join(repo2, "notes.txt"), "scratch\n");
    await expect(runLoop({ repo: repo2, memoryRoot: tempDir(), ask: yes })).rejects.toBeInstanceOf(LoopError);
  });

  it("does not count Penthera's own untracked reports/ as uncommitted work (e2e 2026-10-22)", async () => {
    // The dashboard's "Check my app" writes reports/<host>_<time>.json into the project;
    // "Fix problems for me" right after it refused with DIRTY.
    const repo = fixtureRepo();
    mkdirSync(join(repo, "reports"), { recursive: true });
    writeFileSync(join(repo, "reports", "www.example.com_2026-10-22-12-40-29.json"), "{}\n");
    const run = await runLoop({ repo, memoryRoot: tempDir(), ask: async () => "n", maxIterations: 1 });
    expect(run.error).toBeNull();
    expect(existsSync(join(repo, "reports", "www.example.com_2026-10-22-12-40-29.json"))).toBe(true);
    expect(git(repo, "status", "--porcelain", "--", "reports").trim()).toBe("?? reports/");
  });

  it("refuses a detached HEAD and a directory that is not a git repo", async () => {
    const repo = fixtureRepo();
    git(repo, "checkout", "-q", "--detach");
    await expect(runLoop({ repo, memoryRoot: tempDir(), ask: yes })).rejects.toMatchObject({ code: "DETACHED" });

    const plain = tempDir();
    cpSync(FIXTURE, plain, { recursive: true });
    await expect(runLoop({ repo: plain, memoryRoot: tempDir(), ask: yes })).rejects.toMatchObject({ code: "NOT_GIT" });
  });

  it("with --allow-dirty, never patches a file that had uncommitted changes", async () => {
    const repo = fixtureRepo();
    const wip = readFileSync(join(repo, "routes/auth.js"), "utf-8") + "\n// my work in progress\n";
    writeFileSync(join(repo, "routes/auth.js"), wip);
    const run = await runLoop({ repo, memoryRoot: tempDir(), ask: yes, allowDirty: true });
    const byRecipe = Object.fromEntries(fixes(run).map((f) => [f.recipe, f]));
    expect(byRecipe["cookie-flags"].status).toBe("not-applied");
    expect(byRecipe["cookie-flags"].reason).toMatch(/uncommitted changes/);
    expect(readFileSync(join(repo, "routes/auth.js"), "utf-8")).toBe(wip);
    expect(byRecipe["security-headers"].status).toBe("verified");
  });
});

describe("agent loop: verification", () => {
  it("reverts a fix whose verification fails and records fix_failed", async () => {
    // The project's tests reject any Content-Security-Policy, so the headers fix must fail.
    const repo = fixtureRepo((dir) => {
      const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf-8"));
      pkg.scripts = { test: "node check.js" };
      writeFileSync(join(dir, "package.json"), JSON.stringify(pkg, null, 2));
      writeFileSync(join(dir, "check.js"), `import { readFileSync } from "node:fs";\nprocess.exit(readFileSync("server.js", "utf-8").includes("Content-Security-Policy") ? 1 : 0);\n`);
    });
    const original = readFileSync(join(repo, "server.js"), "utf-8");
    const memoryRoot = tempDir("penthera-mem-");
    const run = await runLoop({ repo, memoryRoot, ask: yes, runTests: true });

    const headers = fixes(run).find((f) => f.recipe === "security-headers");
    expect(headers.status).toBe("failed");
    expect(headers.reason).toMatch(/project tests failed/);
    expect(headers.verify.tests).toMatchObject({ ok: false, exitCode: 1 });
    expect(headers.commit).toBeNull();
    expect(headers.steps.map((s) => s.step)).toContain("revert");
    expect(readFileSync(join(repo, "server.js"), "utf-8")).not.toContain("Content-Security-Policy");
    expect(git(repo, "status", "--porcelain")).toBe("");
    // The other fixes still verified (with passing tests) and were committed.
    expect(run.totals.verified).toBe(4);
    expect(run.totals.failed).toBe(1);
    expect(run.stopReason).toBe("declined-or-failed-left");
    for (const f of fixes(run).filter((x) => x.status === "verified")) expect(f.verify.tests).toMatchObject({ ok: true });
    expect(git(repo, "show", "main:server.js")).toBe(original);

    const events = openMemory(projectIdFor({ repo }).id, { root: memoryRoot }).events();
    const failed = events.filter((e) => e.type === "fix_failed");
    expect(failed).toHaveLength(1);
    expect(failed[0].data.recipe).toBe("security-headers");
  });

  it("reverts a fix that introduces a new finding", async () => {
    const repo = fixtureRepo();
    const { scanRepo } = await import("../src/scan-repo.js");
    let calls = 0;
    const run = await runLoop({
      repo, memoryRoot: tempDir(), ask: yes, maxIterations: 1,
      deps: {
        // The second scan (verifying the first fix) reports a finding that was not there before.
        scanRepo: async (p, o) => {
          const r = await scanRepo(p, o);
          if (++calls === 2) r.findings.push({ severity: "high", category: "injection", title: "New SQL injection", url: "db.js" });
          return r;
        },
      },
    });
    const first = fixes(run)[0];
    expect(first.status).toBe("failed");
    expect(first.reason).toMatch(/new finding/);
    expect(git(repo, "status", "--porcelain")).toBe("");
    expect(fixes(run).slice(1).every((f) => f.status === "verified")).toBe(true);
  });
});

describe("agent loop: approval and interruption", () => {
  it("asks for every diff by default: n declines for the run, quit stops", async () => {
    const repo = fixtureRepo();
    const answers = ["n", "y", "quit"];
    const run = await runLoop({ repo, memoryRoot: tempDir(), ask: async () => answers.shift() });
    expect(fixes(run).map((f) => f.decision)).toEqual(["declined", "approved", "quit"]);
    expect(run.stopReason).toBe("user-quit");
    expect(run.totals.commits).toHaveLength(1);
    expect(git(repo, "status", "--porcelain")).toBe("");
  });

  it("refuses to apply anything without a prompt unless --auto qualifies", async () => {
    const repo = fixtureRepo();
    const run = await runLoop({ repo, memoryRoot: tempDir(), auto: "low" });
    expect(run.stopReason).toBe("error");
    expect(run.error).toMatch(/needs a y\/n answer/);
    expect(run.totals.applied).toBe(0);
    expect(git(repo, "status", "--porcelain")).toBe("");
  });

  it("on interrupt, finishes the fix in flight and leaves only verified commits on the fix branch", async () => {
    const repo = fixtureRepo();
    const controller = new AbortController();
    let urlScans = 0;
    const run = await runLoop({
      repo, url: "http://localhost:9", memoryRoot: tempDir(), ask: yes, signal: controller.signal,
      deps: {
        // Ctrl-C arrives while the second fix is being verified.
        scanUrl: async () => { if (++urlScans === 3) controller.abort(); return { findings: [] }; },
      },
    });
    expect(run.stopReason).toBe("interrupted");
    expect(run.totals.verified).toBe(2);
    expect(fixes(run)).toHaveLength(2);
    expect(git(repo, "rev-parse", "--abbrev-ref", "HEAD").trim()).toBe(run.branch.fix);
    expect(git(repo, "status", "--porcelain")).toBe("");
    expect(commitsOn(repo, `main..${run.branch.fix}`)).toHaveLength(2);
  });

  it("on interrupt at the prompt, applies nothing more", async () => {
    const repo = fixtureRepo();
    const controller = new AbortController();
    let n = 0;
    const run = await runLoop({
      repo, memoryRoot: tempDir(), signal: controller.signal,
      ask: async () => { if (++n === 2) { controller.abort(); return "quit"; } return "y"; },
    });
    expect(run.stopReason).toBe("interrupted");
    expect(run.totals.commits).toHaveLength(1);
    expect(git(repo, "status", "--porcelain")).toBe("");
  });
});

describe("agent loop: helpers", () => {
  it("names the fix branch penthera/fix-<yyyymmdd-hhmm>", () => {
    expect(fixBranchName(new Date(2026, 9, 19, 9, 5))).toBe("penthera/fix-20261019-0905");
  });

  it("keeps a second same-minute run on its own branch", async () => {
    const repo = fixtureRepo();
    const memoryRoot = tempDir();
    const a = await runLoop({ repo, memoryRoot, ask: yes, maxIterations: 1 });
    git(repo, "checkout", "-q", "main");
    const b = await runLoop({ repo, memoryRoot, ask: async () => "n", maxIterations: 1 });
    expect(b.branch.fix).not.toBe(a.branch.fix);
  });
});

describe("agent loop: the tree under a fix", () => {
  it("applies every approved fix with an untracked reports/ folder beside them", async () => {
    const repo = fixtureRepo();
    mkdirSync(join(repo, "reports"));
    writeFileSync(join(repo, "reports/scan.json"), "{}\n");
    const run = await runLoop({ repo, memoryRoot: tempDir(), ask: yes, maxIterations: 2 });
    expect(run.totals.verified).toBeGreaterThan(0);
    expect(run.gaveUp).toEqual([]);
    expect(git(repo, "status", "--porcelain").trim()).toBe("?? reports/");
  });

  it("stops at the first fix when the tree went dirty, not after more approvals", async () => {
    const repo = fixtureRepo();
    let asked = 0;
    const run = await runLoop({
      repo, memoryRoot: tempDir(), maxIterations: 2,
      ask: async () => { asked++; writeFileSync(join(repo, "scratch.js"), "mine\n"); return "y"; },
    });
    expect(asked).toBe(1);
    expect(run.stopReason).toBe("error");
    expect(run.error).toMatch(/uncommitted changes/);
    expect(run.totals.verified).toBe(0);
  });
});

describe("agent loop: how a run ends", () => {
  const run = (stopReason, left, verified = 0) => ({ stopReason, findings: { left }, totals: { verified } });
  const none = { critical: 0, high: 0, medium: 0, low: 0 };

  it("is clean only when it finished with no critical or high left", () => {
    expect(loopVerdict(run("no-fixable-findings", none, 3))).toMatchObject({ clean: true, headline: "3 fixed, no critical or high left." });
    expect(loopVerdict(run("no-fixable-findings", { ...none, medium: 2 }))).toMatchObject({ clean: true, headline: "0 fixed, no critical or high left, 2 lower." });
    expect(loopVerdict(run("no-fixable-findings", { ...none, critical: 8 }, 1))).toMatchObject({ clean: false, headline: "1 fixed, 8 critical left." });
    expect(loopVerdict(run("no-fixable-findings", { ...none, high: 2 }))).toMatchObject({ clean: false, headline: "0 fixed, 2 high left." });
  });

  it("never reads a partial run as clean", () => {
    for (const stop of ["declined-or-failed-left", "max-iterations", "user-quit", "interrupted", "error"]) {
      expect(loopVerdict(run(stop, none)).clean, stop).toBe(false);
    }
    expect(loopVerdict(run("user-quit", none)).headline).toMatch(/^Stopped early/);
    expect(loopVerdict(run("no-fixable-findings", none)).headline).not.toContain("suppressed");
    expect(loopVerdict(run("error", null))).toMatchObject({ clean: false, headline: "0 fixed. The run ended before a final scan." });
  });

  it("counts same-titled findings in different files, and suppressed ones as a scan does", async () => {
    const repo = fixtureRepo();
    const bug = (file) => ({ severity: "critical", title: "eval in source", category: "code-pattern", file });
    const hidden = { severity: "critical", title: "Hidden", category: "code-pattern", url: "x.js" };
    writeFileSync(join(repo, "penthera.suppress.json"), JSON.stringify({ version: 1, suppress: [{ fingerprint: fingerprintFinding(hidden), severity: "critical", reason: "false positive here" }] }));
    git(repo, "add", "-A");
    git(repo, "commit", "-qm", "suppress");
    const run = await runLoop({ repo, memoryRoot: tempDir(), ask: async () => "n", maxIterations: 1, deps: { scanRepo: async () => ({ findings: [bug("a.js"), bug("b.js"), hidden] }) } });
    expect(run.findings.left.critical).toBe(3);
    expect(Object.values(run.findings.left).reduce((a, b) => a + b)).toBe(run.findings.final + 1);
    expect(run.findings.suppressed).toBe(1);
    expect(loopVerdict(run).headline).toContain("(1 suppressed by you).");
    expect(loopVerdict(run).headline).not.toContain("penthera ");
    expect(loopVerdict(run).next).toBe("Review them with penthera memory show --repo . and penthera.suppress.json.");
    expect(loopVerdict(run).clean).toBe(false);
  });

  it("says when --run-tests has no test script to run", async () => {
    const said = [];
    await runLoop({ repo: fixtureRepo(), memoryRoot: tempDir(), ask: async () => "n", maxIterations: 1, runTests: true, log: (l) => said.push(l) });
    expect(said.join("\n")).toMatch(/no test script/);
  });

  it.each([["skip", "n"], ["stop", "quit"]])("leaves no empty branch after %s", async (_, answer) => {
    const repo = fixtureRepo();
    const run = await runLoop({ repo, memoryRoot: tempDir(), ask: async () => answer, maxIterations: 1 });
    expect(run.branch.left).toBe(true);
    expect(run.branch.removed).toBe(true);
    expect(git(repo, "rev-parse", "--abbrev-ref", "HEAD").trim()).toBe("main");
    expect(git(repo, "branch", "--list", "penthera/*").trim()).toBe("");
  });

  it("names the fixes you skipped in the ending, with no markup", () => {
    const t = { verified: 1, declined: 2, skipped: 1 };
    const none = { critical: 1, high: 0, medium: 0, low: 0 };
    const v = loopVerdict({ stopReason: "declined-or-failed-left", findings: { left: none, suppressed: 1 }, totals: t });
    expect(v.headline).toContain("1 fixed, 3 skipped, 1 critical left (1 suppressed by you).");
    expect(v.headline).not.toContain("`");
  });

  it("does not count a suppressed finding twice in the ending", () => {
    const left = { critical: 1, high: 0, medium: 0, low: 0 };
    const v = loopVerdict({ stopReason: "no-fixable-findings", findings: { left, suppressed: 1 }, totals: { verified: 0 } });
    expect(v.headline).toBe("0 fixed, 1 critical left (1 suppressed by you).");
    expect(v.next).toMatch(/penthera memory show/);
  });

  it("continues on a fix branch instead of starting a new one", async () => {
    const repo = fixtureRepo();
    const a = await runLoop({ repo, memoryRoot: tempDir(), ask: yes, maxIterations: 1 });
    const said = [];
    const b = await runLoop({ repo, memoryRoot: tempDir(), ask: async () => "n", maxIterations: 1, log: (l) => said.push(l) });
    expect(b.branch.fix).toBe(a.branch.fix);
    expect(b.branch.left).toBeFalsy();
    expect(git(repo, "rev-parse", "--abbrev-ref", "HEAD").trim()).toBe(a.branch.fix);
    expect(said.join("\n")).toMatch(/continuing on penthera\/fix-/);
    expect(git(repo, "branch", "--list", "penthera/*").trim().split("\n")).toHaveLength(1);
  });

  it("never reads as done when the site was not read", async () => {
    const repo = fixtureRepo();
    const run = await runLoop({
      repo, url: "http://127.0.0.1:9", memoryRoot: tempDir(), ask: async () => "n", maxIterations: 1,
      deps: { scanRepo: async () => ({ findings: [] }), scanUrl: async () => ({ mode: "url", reachable: false, findings: [] }) },
    });
    const v = loopVerdict(run);
    expect(v.clean).toBe(false);
    expect(v.headline).toMatch(/couldn't see your site/);
  });

  it("prints a real range when it continues on a fix branch", () => {
    const repo = fixtureRepo();
    const run = (args) => execFileSync(process.execPath, [resolve("bin/penthera.js"), "agent", "--loop", "--repo", repo, "--max-iterations", "1", ...args], {
      input: "y\n".repeat(20), encoding: "utf-8", env: { ...process.env, NO_COLOR: "1", PENTHERA_HOME: tempDir() },
    });
    const safe = () => { try { return run([]); } catch (e) { return e.stdout; } };
    safe();
    const fix = git(repo, "rev-parse", "--abbrev-ref", "HEAD").trim();
    expect(safe()).not.toContain(`${fix}..${fix}`);
  }, 30_000);

  it("says its counts differ from a scan's, and that a live scan needs repeating", () => {
    const left = { critical: 0, high: 0, medium: 0, low: 0 };
    const repoOnly = loopVerdict({ stopReason: "no-fixable-findings", findings: { left, suppressed: 0 }, totals: { verified: 2 }, target: {} });
    expect(repoOnly.next).toMatch(/scan the URL again/);
    expect(repoOnly.next).toMatch(/checks only penthera fix runs/);
    expect(loopVerdict({ stopReason: "no-fixable-findings", findings: { left, suppressed: 0 }, totals: { verified: 0 }, target: {} }).next).toBeNull();
  });

  it("offers no branch to merge when no fix landed", () => {
    const repo = fixtureRepo();
    let out = "";
    try {
      out = execFileSync(process.execPath, [resolve("bin/penthera.js"), "agent", "--loop", "--repo", repo, "--max-iterations", "1"], {
        input: "n\n".repeat(20), encoding: "utf-8", env: { ...process.env, NO_COLOR: "1", PENTHERA_HOME: tempDir() },
      });
    } catch (e) { out = e.stdout; }
    expect(out).toMatch(/you are back on main/);
    expect(out).not.toMatch(/Merge or push/);
  }, 30_000);

  it("says how to fix a folder with no git", async () => {
    const dir = tempDir();
    await expect(runLoop({ repo: dir, memoryRoot: tempDir(), ask: yes })).rejects.toThrow(/git init/);
  });

  it("tells a suite that was already failing from a fix that broke it", async () => {
    const repo = fixtureRepo((d) => writeFileSync(join(d, "package.json"), JSON.stringify({ ...JSON.parse(readFileSync(join(d, "package.json"), "utf-8")), scripts: { test: "x" } })));
    const said = [];
    const run = await runLoop({
      repo, memoryRoot: tempDir(), ask: yes, maxIterations: 2, runTests: true, log: (l) => said.push(l),
      deps: { runTests: async () => ({ ok: false, exitCode: 1, durationMs: 1, output: "red" }) },
    });
    expect(run.testsBefore).toMatchObject({ ok: false });
    expect(run.totals.verified).toBeGreaterThan(0);
    expect(run.totals.failed).toBe(0);
    expect(said.join("\n")).toMatch(/already fail/);
    expect(loopVerdict(run).headline).toMatch(/already failing/);
  });

  it("does not teach memory that an interrupted fix failed", async () => {
    const repo = fixtureRepo((d) => writeFileSync(join(d, "package.json"), JSON.stringify({ ...JSON.parse(readFileSync(join(d, "package.json"), "utf-8")), scripts: { test: "x" } })));
    const stop = new AbortController();
    const memoryRoot = tempDir();
    let calls = 0;
    const run = await runLoop({
      repo, memoryRoot, ask: yes, maxIterations: 1, runTests: true, signal: stop.signal,
      deps: { runTests: async () => {
        if (++calls === 1) return { ok: true, exitCode: 0, durationMs: 1, output: "" };
        stop.abort();
        return { ok: false, exitCode: null, durationMs: 1, output: "killed" };
      } },
    });
    expect(run.totals.failed).toBe(0);
    expect(fixes(run)[0].status).toBe("interrupted");
    expect(run.gaveUp).toEqual([]);
    const events = openMemory(projectIdFor({ repo }).id, { root: memoryRoot }).events().map((e) => e.type);
    expect(events).not.toContain("fix_failed");
    expect(git(repo, "status", "--porcelain").trim()).toBe("");
  });

  it("restores the tree on SIGTERM during the tests", async () => {
    const repo = fixtureRepo((d) => {
      writeFileSync(join(d, "package.json"), JSON.stringify({ ...JSON.parse(readFileSync(join(d, "package.json"), "utf-8")), scripts: { test: "node t.cjs" } }));
      writeFileSync(join(d, "t.cjs"), 'const fs = require("node:fs"); fs.appendFileSync(process.env.PENTHERA_T_LOG, "x"); if (fs.readFileSync(process.env.PENTHERA_T_LOG, "utf-8").length > 1) setTimeout(() => {}, 60000);\n');
    });
    const log = join(tempDir(), "runs");
    const child = spawn(process.execPath, [resolve("bin/penthera.js"), "agent", "--loop", "--repo", repo, "--run-tests", "--max-iterations", "1"], {
      stdio: ["pipe", "ignore", "ignore"], env: { ...process.env, NO_COLOR: "1", PENTHERA_HOME: tempDir(), PENTHERA_T_LOG: log },
    });
    child.stdin.write("y\n".repeat(10));
    for (let i = 0; i < 300; i++) {
      if (existsSync(log) && readFileSync(log, "utf-8").length > 1) break;
      await new Promise((r) => setTimeout(r, 50));
    }
    expect(readFileSync(log, "utf-8").length).toBeGreaterThan(1); // the kill lands during a fix's test run
    child.kill("SIGTERM");
    await new Promise((r) => child.on("close", r));
    expect(git(repo, "status", "--porcelain").trim()).toBe("");
  }, 30_000);

  it("exits 1 from the CLI when a critical stays after every fix", () => {
    const repo = fixtureRepo((dir) => writeFileSync(join(dir, "tool.js"), [
      'import { exec } from "node:child_process";',
      'export const run = (req) => exec("ls " + req.query.dir);',
      "",
    ].join("\n")));
    let status = 0;
    let stdout = "";
    try {
      stdout = execFileSync(process.execPath, [resolve("bin/penthera.js"), "agent", "--loop", "--repo", repo], {
        input: "y\n".repeat(20), encoding: "utf-8", env: { ...process.env, NO_COLOR: "1", PENTHERA_HOME: tempDir() },
      });
    } catch (e) { status = e.status; stdout = e.stdout; }
    expect(stdout).toMatch(/Not done: \d+ fixed, .*critical.* left\./);
    expect(stdout).toMatch(/You are on branch penthera\/fix-/);
    expect(status).toBe(1);
  });
});

describe("penthera agent CLI", () => {
  it("runs the loop from the command line with piped answers and writes the loopRun", () => {
    const repo = fixtureRepo();
    const out = join(tempDir(), "run.json");
    const stdout = execFileSync(process.execPath, [resolve("bin/penthera.js"), "agent", "--loop", "--repo", repo, "-o", out, "--max-iterations", "2"], {
      input: "y\ny\ny\ny\ny\n", encoding: "utf-8", env: { ...process.env, NO_COLOR: "1", PENTHERA_HOME: tempDir() },
    });
    expect(stdout).toMatch(/iteration 1\/2/);
    expect(stdout).toMatch(/Nothing was pushed/);
    const { loopRun } = JSON.parse(readFileSync(out, "utf-8"));
    expect(loopRun.schema).toBe(LOOP_RUN_SCHEMA);
    expect(loopRun.totals.verified).toBe(5);
    expect(loopRun.stopReason).toBe("no-fixable-findings");
  });

  it("answers n when input runs out, so nothing is applied unattended", () => {
    const repo = fixtureRepo();
    let status = 0;
    try {
      execFileSync(process.execPath, [resolve("bin/penthera.js"), "agent", "--loop", "--repo", repo], {
        input: "", encoding: "utf-8", env: { ...process.env, NO_COLOR: "1", PENTHERA_HOME: tempDir() },
      });
    } catch (e) {
      status = e.status;
    }
    expect(status).toBe(1);
    expect(git(repo, "rev-list", "--count", "HEAD").trim()).toBe("1");
    expect(git(repo, "status", "--porcelain")).toBe("");
  });
});

describe("agent loop: verifier integrity and the safe exit", () => {
  const BODY = { severity: "critical", category: "dos", title: "Unbounded request body", url: "server.js" };
  /** scanRepo that always reports BODY, which no recipe fixes. */
  const withBody = async () => {
    const { scanRepo } = await import("../src/scan-repo.js");
    return async (p, o) => {
      const r = await scanRepo(p, o);
      r.findings.push({ ...BODY });
      return r;
    };
  };
  const onlyModel = async ({ plan }) => (plan.source === "local-model" ? "y" : "n");
  const withTest = (dir) => {
    mkdirSync(join(dir, "tests"), { recursive: true });
    writeFileSync(join(dir, "tests/app.test.js"), "expect(bodyLimit()).toBe(true);\n");
  };

  it("refuses a model diff that edits a test file to make it pass, gives the finding up and records gave_up", async () => {
    const repo = fixtureRepo(withTest);
    const memoryRoot = tempDir("penthera-mem-");
    const diff = "--- a/tests/app.test.js\n+++ b/tests/app.test.js\n@@ -1,1 +1,1 @@\n-expect(bodyLimit()).toBe(true);\n+expect(true).toBe(true);\n";
    let calls = 0;
    const model = { plan: async () => { calls++; return { diff, files: ["tests/app.test.js"], confidence: "needs-human-review", source: "local-model" }; } };
    const run = await runLoop({ repo, memoryRoot, ask: onlyModel, fixModel: "m", deps: { model, scanRepo: await withBody() } });

    const m = fixes(run).filter((f) => f.source === "local-model");
    expect(m).toHaveLength(1);
    expect(m[0].status).toBe("not-applied");
    expect(m[0].reason).toMatch(/never edit tests.*by hand/);
    expect(readFileSync(join(repo, "tests/app.test.js"), "utf-8")).toBe("expect(bodyLimit()).toBe(true);\n");
    expect(calls).toBe(1); // not asked again in later iterations
    expect(run.gaveUp).toEqual([expect.objectContaining({ title: BODY.title, reason: expect.stringMatching(/PROTECTED|never edit tests/) })]);
    const events = openMemory(projectIdFor({ repo }).id, { root: memoryRoot }).events();
    expect(events.filter((e) => e.type === "gave_up").map((e) => e.data.reason)).toEqual([m[0].reason]);
    expect(events.some((e) => e.type === "fix_failed")).toBe(false);
  });

  it("does not retry a finding after one honest failure in a run", async () => {
    const repo = fixtureRepo();
    const before = readFileSync(join(repo, "server.js"), "utf-8");
    let calls = 0;
    // A real edit that does not fix anything: verification fails because BODY is still reported.
    const model = { plan: async () => { calls++; return { diff: createPatch("server.js", before, `${before}// bounded\n`), files: ["server.js"], confidence: "needs-human-review", source: "local-model" }; } };
    const run = await runLoop({ repo, memoryRoot: tempDir(), ask: onlyModel, fixModel: "m", deps: { model, scanRepo: await withBody() } });

    expect(run.iterations.length).toBeGreaterThan(1);
    expect(calls).toBe(1);
    expect(fixes(run).filter((f) => f.source === "local-model").map((f) => f.status)).toEqual(["failed"]);
    expect(run.gaveUp).toEqual([expect.objectContaining({ title: BODY.title, reason: expect.stringMatching(/still reported/) })]);
    expect(run.stopReason).toBe("declined-or-failed-left");
  });

  it("records a model that gives no usable fix as gave_up, once", async () => {
    const repo = fixtureRepo();
    const memoryRoot = tempDir("penthera-mem-");
    const model = { plan: async () => null }; // NO_FIX
    const run = await runLoop({ repo, memoryRoot, ask: async () => "n", fixModel: "m", maxIterations: 2, deps: { model, scanRepo: await withBody() } });
    expect(run.gaveUp).toEqual([expect.objectContaining({ title: BODY.title, reason: expect.stringMatching(/no usable fix/) })]);
    const events = openMemory(projectIdFor({ repo }).id, { root: memoryRoot }).events();
    expect(events.filter((e) => e.type === "gave_up")).toHaveLength(1);
  });

  it("never counts a give-up as a recipe failure in memory", async () => {
    // The project's tests reject any Content-Security-Policy, so the headers fix fails once and is given up.
    const repo = fixtureRepo((dir) => {
      const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf-8"));
      pkg.scripts = { test: "node check.js" };
      writeFileSync(join(dir, "package.json"), JSON.stringify(pkg, null, 2));
      writeFileSync(join(dir, "check.js"), `import { readFileSync } from "node:fs";\nprocess.exit(readFileSync("server.js", "utf-8").includes("Content-Security-Policy") ? 1 : 0);\n`);
    });
    const memoryRoot = tempDir("penthera-mem-");
    const run = await runLoop({ repo, memoryRoot, ask: yes, runTests: true });
    expect(run.gaveUp.length).toBeGreaterThan(0);
    expect(run.gaveUp.every((g) => /project tests failed/.test(g.reason))).toBe(true);

    const events = openMemory(projectIdFor({ repo }).id, { root: memoryRoot }).events();
    const headers = buildViews(events).recipeSuccess.find((r) => r.recipe === "security-headers");
    expect(headers.failed).toBe(1); // the one fix_failed; the gave_up events add nothing
    const onlyGiveUps = events.filter((e) => e.type === "gave_up");
    expect(onlyGiveUps.length).toBe(run.gaveUp.length);
    expect(buildViews(onlyGiveUps).recipeSuccess).toEqual([]);
  });

  it("does not verify a fix when tests changed during the run, and never runs them", async () => {
    const repo = fixtureRepo((dir) => {
      withTest(dir);
      const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf-8"));
      pkg.scripts = { test: "node tests/app.test.js" };
      writeFileSync(join(dir, "package.json"), JSON.stringify(pkg, null, 2));
    });
    let testRuns = 0;
    let n = 0;
    const run = await runLoop({
      repo, memoryRoot: tempDir(), runTests: true, allowDirty: true, maxIterations: 1,
      // Something rewrites the test while the first fix is being approved.
      ask: async () => {
        if (++n === 1) { writeFileSync(join(repo, "tests/app.test.js"), "// passes\n"); return "y"; }
        return "n";
      },
      deps: { runTests: async () => { testRuns++; return { ok: true, exitCode: 0, durationMs: 0, output: "" }; } },
    });
    const first = fixes(run)[0];
    expect(first.status).toBe("failed");
    expect(first.reason).toMatch(/tests, test config or Penthera's own files changed/);
    expect(first.commit).toBeNull();
    expect(testRuns).toBe(1); // the run before any fix, not after the change
    expect(readFileSync(join(repo, "tests/app.test.js"), "utf-8")).toBe("// passes\n");
  });

  it("prints what it gave up and why in the run summary", () => {
    const repo = fixtureRepo((dir) => {
      const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf-8"));
      pkg.scripts = { test: "node check.js" };
      writeFileSync(join(dir, "package.json"), JSON.stringify(pkg, null, 2));
      writeFileSync(join(dir, "check.js"), `import { readFileSync } from "node:fs";\nprocess.exit(readFileSync("server.js", "utf-8").includes("Content-Security-Policy") ? 1 : 0);\n`);
    });
    let stdout = "";
    try {
      execFileSync(process.execPath, [resolve("bin/penthera.js"), "agent", "--loop", "--repo", repo, "--run-tests", "--max-iterations", "2"], {
        input: "y\ny\ny\ny\ny\ny\n", encoding: "utf-8", env: { ...process.env, NO_COLOR: "1", PENTHERA_HOME: tempDir() },
      });
    } catch (e) {
      stdout = e.stdout;
    }
    expect(stdout).toMatch(/gave up on \d+ \(not retried this run; fix by hand\): .*project tests failed/);
  });
});
