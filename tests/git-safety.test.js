/**
 * The agent loop's git runner and its revert/commit path, against repos that
 * carry their own git config and against users who keep working while the
 * loop runs. Every repo is built at runtime in a temp dir; marker scripts
 * record whether git ran anything the repo configured.
 */
import { describe, it, expect, afterAll } from "vitest";
import { execFileSync } from "node:child_process";
import {
  mkdtempSync, mkdirSync, writeFileSync, readFileSync, appendFileSync, rmSync, existsSync, utimesSync, readdirSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createGit, parseGitVersion, parseScopedConfig } from "../src/agent/git.js";
import { runLoop, parseStatusZ } from "../src/agent/loop.js";
import { assertCleanTree } from "../lib/fix/apply.js";
import { gitInfo } from "../src/report/evidence.js";

const temps = [];
afterAll(() => temps.forEach((d) => rmSync(d, { recursive: true, force: true })));

function tempDir(prefix = "penthera-gitsafety-") {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  temps.push(dir);
  return dir;
}

const git = (dir, ...args) => execFileSync("git", args, { cwd: dir, encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] });

function repoWith(files) {
  const dir = tempDir();
  for (const [rel, content] of Object.entries(files)) {
    mkdirSync(join(dir, rel, ".."), { recursive: true });
    writeFileSync(join(dir, rel), content);
  }
  git(dir, "init", "-q", "-b", "main");
  git(dir, "add", "-A");
  git(dir, "commit", "-qm", "init");
  return dir;
}

/** A shell script that records it ran in `markers`, then passes stdin through. */
function marker(markers, name) {
  const f = join(markers, `${name}.sh`);
  writeFileSync(f, `#!/bin/sh\ntouch ${JSON.stringify(join(markers, `RAN-${name}`))}\ncat\n`, { mode: 0o755 });
  return f;
}
const ran = (markers) => readdirSync(markers).filter((f) => f.startsWith("RAN-"));

/** Make git re-read every tracked file on the next status (as after an extract or an editor save). */
function touchAll(dir, files) {
  const later = new Date(Date.now() + 5_000);
  for (const f of files) utimesSync(join(dir, f), later, later);
}

const unix = process.platform !== "win32";

describe("git runner: config the scanned repo sets never runs", () => {
  it.skipIf(!unix)("filters, signing and include.path in .git/config: reads neutralised, the loop refuses to write", async () => {
    const markers = tempDir("penthera-markers-");
    const dir = repoWith({
      "server.js": 'import express from "express";\nconst app = express();\napp.listen(3000);\n',
      "package.json": JSON.stringify({ name: "x", type: "module", dependencies: { express: "^5" } }),
      ".gitattributes": "*.js filter=ev\n",
      // Committed, so the tree stays clean; .git/config includes it.
      "team.gitconfig": `[filter "inc"]\n\tclean = ${marker(markers, "include-clean")}\n\tsmudge = ${marker(markers, "include-smudge")}\n`,
    });
    writeFileSync(join(dir, ".git", "info", "attributes"), "*.json filter=inc\n");
    git(dir, "config", "filter.ev.clean", marker(markers, "filter-clean"));
    git(dir, "config", "filter.ev.smudge", marker(markers, "filter-smudge"));
    git(dir, "config", "filter.ev.process", marker(markers, "filter-process"));
    git(dir, "config", "commit.gpgsign", "true");
    git(dir, "config", "gpg.program", marker(markers, "gpg-program"));
    git(dir, "config", "include.path", "../team.gitconfig");
    touchAll(dir, ["server.js", "package.json"]);

    // Read paths: penthera fix --apply's clean-tree check and the evidence bundle's git info.
    expect(() => assertCleanTree(dir)).not.toThrow();
    expect(gitInfo(dir)).toMatchObject({ dirty: false });
    // The loop reads, then refuses its first write with a clear reason.
    await expect(runLoop({ repo: dir, memoryRoot: tempDir(), ask: async () => "y", maxIterations: 1 }))
      .rejects.toMatchObject({ code: "GIT_UNSAFE_CONFIG", message: expect.stringMatching(/filter\.ev\.clean.*can run programs/) });
    expect(git(dir, "rev-parse", "--abbrev-ref", "HEAD").trim()).toBe("main");
    expect(ran(markers)).toEqual([]);
  });

  it.skipIf(!unix)("ssh signing's defaultKeyCommand in .git/config: the loop refuses to write", async () => {
    const markers = tempDir("penthera-markers-");
    const dir = repoWith({ "server.js": 'import express from "express";\nconst app = express();\n' });
    git(dir, "config", "commit.gpgsign", "true");
    git(dir, "config", "gpg.format", "ssh");
    git(dir, "config", "gpg.ssh.defaultKeyCommand", marker(markers, "ssh-keycmd"));
    const g = createGit(dir);
    expect(g.run("status", "--porcelain")).toBe("");
    expect(() => g.run("checkout", "-b", "x")).toThrow(/gpg\.format.*can run programs/);
    expect(ran(markers)).toEqual([]);
  });

  it.skipIf(!unix)("the refusal names the repo's key and says how to go on", () => {
    const dir = repoWith({ "server.js": "x\n" });
    git(dir, "config", "gpg.format", "ssh");
    const g = createGit(dir);
    let message = "";
    try { g.run("checkout", "-b", "x"); } catch (e) { message = e.message; }
    expect(message).toMatch(/sets gpg\.format,/);
    expect(message).toContain("git config --global gpg.format");
    expect(message).toContain("git config --unset gpg.format");
    expect(message).toMatch(/penthera fix --plan/);
    expect(message).toMatch(/Scans and reports still work/);
  });

  it.skipIf(!unix)("commit, add, checkout and status never run a filter or signer, wherever it is configured", () => {
    const markers = tempDir("penthera-markers-");
    const dir = repoWith({ "app.js": "x\n", ".gitattributes": "*.js filter=gl\n" });
    writeFileSync(join(dir, ".git", "info", "attributes"), "*.js filter=gl\n");
    // Outside the repo's own config, so writes are allowed: the overrides alone must hold.
    const globalCfg = join(tempDir(), "gitconfig");
    writeFileSync(globalCfg, [
      `[filter "gl"]`, `\tclean = ${marker(markers, "clean")}`, `\tsmudge = ${marker(markers, "smudge")}`, `\trequired = true`,
      `[commit]`, `\tgpgsign = true`, `[tag]`, `\tgpgsign = true`,
      `[gpg]`, `\tformat = ssh`, `\tprogram = ${marker(markers, "gpg")}`,
      `[gpg "ssh"]`, `\tprogram = ${marker(markers, "ssh-program")}`, `\tdefaultKeyCommand = ${marker(markers, "ssh-keycmd")}`,
      `[log]`, `\tshowSignature = true`, "",
    ].join("\n"));
    const g = createGit(dir, { env: { ...process.env, GIT_CONFIG_GLOBAL: globalCfg } });
    touchAll(dir, ["app.js"]);
    expect(g.run("status", "--porcelain")).toBe("");
    g.run("checkout", "-b", "fix");
    writeFileSync(join(dir, "app.js"), "y\n");
    writeFileSync(join(dir, "new.js"), "n\n");
    g.run("add", "--", "new.js");
    g.run("commit", "-q", "--only", "-m", "fix", "--", "app.js", "new.js");
    g.run("log", "-1", "--format=%H");
    writeFileSync(join(dir, "app.js"), "z\n");
    g.run("checkout", "--", "app.js");
    expect(readFileSync(join(dir, "app.js"), "utf-8")).toBe("y\n");
    expect(git(dir, "show", "--name-only", "--format=", "HEAD").trim().split("\n").sort()).toEqual(["app.js", "new.js"]);
    expect(ran(markers)).toEqual([]);
  });

  /** The real git, reporting an older version, as Xcode's git (2.39) or Ubuntu 22.04's (2.34) would. */
  const fakeVersion = (version) => (cmd, args, o) => (args[0] === "--version" ? `git version ${version}\n` : execFileSync(cmd, args, o));

  it.skipIf(!unix)("git 2.31-2.39 (no --attr-source): writes refused because of the repo's config, not the version", () => {
    const markers = tempDir("penthera-markers-");
    const dir = repoWith({ "app.js": "x\n", ".gitattributes": "*.js filter=ev\n" });
    git(dir, "config", "filter.ev.clean", marker(markers, "clean"));
    git(dir, "config", "filter.ev.smudge", marker(markers, "smudge"));
    const exec = fakeVersion("2.39.5 (Apple Git-154)");
    const g = createGit(dir, { exec });
    touchAll(dir, ["app.js"]);
    expect(g.run("status", "--porcelain")).toBe("");
    expect(() => g.run("checkout", "-b", "x")).toThrow(expect.objectContaining({ code: "GIT_UNSAFE_CONFIG", message: expect.stringMatching(/filter\.ev\.clean/) }));
    expect(git(dir, "rev-parse", "--abbrev-ref", "HEAD").trim()).toBe("main");
    expect(ran(markers)).toEqual([]);
  });

  it.skipIf(!unix)("git 2.31-2.39: a filter defined only globally and applied by .git/info/attributes is emptied", () => {
    const markers = tempDir("penthera-markers-");
    const dir = repoWith({ "app.js": "x\n" });
    writeFileSync(join(dir, ".git", "info", "attributes"), "*.js filter=gl\n");
    const globalCfg = join(tempDir(), "gitconfig");
    writeFileSync(globalCfg, `[filter "gl"]\n\tclean = ${marker(markers, "clean")}\n\tsmudge = ${marker(markers, "smudge")}\n\trequired = true\n`);
    const calls = [];
    const real = fakeVersion("2.34.1");
    const exec = (cmd, args, o) => { calls.push(args); return real(cmd, args, o); };
    const g = createGit(dir, { exec, env: { ...process.env, GIT_CONFIG_GLOBAL: globalCfg } });
    touchAll(dir, ["app.js"]);
    expect(g.run("status", "--porcelain")).toBe("");
    g.run("checkout", "-b", "fix");
    writeFileSync(join(dir, "app.js"), "y\n");
    g.run("commit", "-q", "--only", "-m", "fix", "--", "app.js");
    writeFileSync(join(dir, "app.js"), "z\n");
    g.run("checkout", "--", "app.js");
    expect(readFileSync(join(dir, "app.js"), "utf-8")).toBe("y\n");
    expect(git(dir, "show", "HEAD:app.js")).toBe("y\n");
    expect(calls.flat().some((a) => a.startsWith("--attr-source"))).toBe(false);
    expect(ran(markers)).toEqual([]);
  });

  it("refuses to write below git 2.31, and parses version and config output", () => {
    const exec = (cmd, args) => (args[0] === "--version" ? "git version 2.30.9\n" : "");
    const g = createGit("/nowhere", { exec });
    expect(() => g.run("commit", "-m", "x", "--", "a.js")).toThrow(expect.objectContaining({ code: "GIT_TOO_OLD", message: expect.stringMatching(/git 2\.30 is older than 2\.31.*Upgrade git/) }));
    expect(() => g.run("status", "--porcelain")).not.toThrow();
    expect(parseGitVersion("git version 2.43.0.windows.1")).toEqual([2, 43]);
    expect(parseScopedConfig("local\0filter.a.b.clean\nx\0global\0include.path\n~/x\0local\0gpg.bare\0"))
      .toEqual([{ scope: "local", key: "filter.a.b.clean" }, { scope: "global", key: "include.path" }, { scope: "local", key: "gpg.bare" }]);
  });
});

describe("git runner: paths are literal", () => {
  it("a fix to pages/api/[id].js commits and reverts only that file, never i.js or d.js", () => {
    const dir = repoWith({ "pages/api/[id].js": "orig\n", "pages/api/i.js": "orig\n", "pages/api/d.js": "orig\n" });
    const g = createGit(dir);
    writeFileSync(join(dir, "pages/api/i.js"), "USER WORK i\n");
    writeFileSync(join(dir, "pages/api/d.js"), "USER WORK d\n");
    writeFileSync(join(dir, "pages/api/[id].js"), "fix\n");
    g.run("commit", "-q", "--only", "-m", "fix", "--", "pages/api/[id].js");
    expect(git(dir, "show", "--name-only", "--format=", "HEAD").trim().split("\n")).toEqual(["pages/api/[id].js"]);
    writeFileSync(join(dir, "pages/api/[id].js"), "again\n");
    g.run("checkout", "--", "pages/api/[id].js");
    expect(readFileSync(join(dir, "pages/api/[id].js"), "utf-8")).toBe("fix\n");
    expect(readFileSync(join(dir, "pages/api/i.js"), "utf-8")).toBe("USER WORK i\n");
    expect(readFileSync(join(dir, "pages/api/d.js"), "utf-8")).toBe("USER WORK d\n");
  });

  it("parses -z status verbatim, including non-ASCII names and renames", () => {
    expect(parseStatusZ(" M src/configuração.js\0?? a b.js\0R  new.js\0old.js\0", "")).toEqual([
      { xy: " M", path: "src/configuração.js" }, { xy: "??", path: "a b.js" }, { xy: "R ", path: "new.js" }, { xy: "R ", path: "old.js" },
    ]);
    expect(parseStatusZ(" M sub/x.js\0", "sub/")).toEqual([{ xy: " M", path: "x.js" }]);
  });
});

// A repo whose only finding is a hardcoded key, so the secret-to-env recipe edits `file`.
const SECRET = ["sk", "live", "51HxQyZJk2mN8pQrStUvWxYz"].join("_");
const USER_WORK = "\n// the user's uncommitted work\n";
function secretRepo(file) {
  return repoWith({
    "package.json": JSON.stringify({ name: "x", type: "module", scripts: { test: "node -e 0" } }),
    [file]: `const stripeKey = "${SECRET}";\nexport default stripeKey;\n`,
  });
}
const testsFail = async () => ({ ok: false, exitCode: 1, durationMs: 1, output: "fail" });
// Green before any fix, red after: the suite the fix broke.
const failsAfterFirst = () => { let calls = 0; return async () => ({ ok: ++calls === 1, exitCode: calls === 1 ? 0 : 1, durationMs: 1, output: "fail" }); };
const testsPass = async () => ({ ok: true, exitCode: 0, durationMs: 1, output: "" });
const secretFix = (run) => run.iterations.flatMap((i) => i.fixes).find((f) => f.recipe === "secret-to-env");
const loopOpts = (repo, extra) => ({ repo, memoryRoot: tempDir(), maxIterations: 1, runTests: true, ask: async () => "y", ...extra });

describe("agent loop: the user's uncommitted work survives", () => {
  it("(A) --allow-dirty with a dirty non-ASCII file: the fix is not applied to it", async () => {
    const file = "src/configuração.js";
    const repo = secretRepo(file);
    appendFileSync(join(repo, file), USER_WORK);
    const before = readFileSync(join(repo, file), "utf-8");
    const run = await runLoop(loopOpts(repo, { allowDirty: true, deps: { runTests: failsAfterFirst() } }));
    expect(secretFix(run)).toMatchObject({ status: "not-applied", reason: expect.stringMatching(/uncommitted changes/) });
    expect(readFileSync(join(repo, file), "utf-8")).toBe(before);
  });

  it("(B) --allow-dirty, file saved while the prompt was open: the fix is not applied to it", async () => {
    const file = "src/config.js";
    const repo = secretRepo(file);
    const ask = async () => { appendFileSync(join(repo, file), USER_WORK); return "y"; };
    const run = await runLoop(loopOpts(repo, { allowDirty: true, ask, deps: { runTests: failsAfterFirst() } }));
    expect(secretFix(run)).toMatchObject({ status: "not-applied", reason: expect.stringMatching(/uncommitted changes/) });
    expect(readFileSync(join(repo, file), "utf-8")).toContain(USER_WORK);
  });

  it("(C) file saved during verification: a failing fix is not reverted over it", async () => {
    const file = "src/config.js";
    const repo = secretRepo(file);
    let runs = 0;
    const runTests = async () => { if (++runs === 1) return { ok: true, exitCode: 0, durationMs: 1, output: "" }; appendFileSync(join(repo, file), USER_WORK); return testsFail(); };
    const run = await runLoop(loopOpts(repo, { deps: { runTests } }));
    expect(secretFix(run)).toMatchObject({ status: "conflict", reason: expect.stringMatching(/changed after the fix was written: src\/config\.js/) });
    expect(readFileSync(join(repo, file), "utf-8")).toContain(USER_WORK);
    expect(run.totals.conflicts).toBe(1);
  });

  it("(C) file saved during verification: a passing fix is not committed with it", async () => {
    const file = "src/config.js";
    const repo = secretRepo(file);
    let runs = 0;
    const runTests = async () => { if (++runs === 1) return { ok: true, exitCode: 0, durationMs: 1, output: "" }; appendFileSync(join(repo, file), USER_WORK); return testsPass(); };
    const run = await runLoop(loopOpts(repo, { deps: { runTests } }));
    expect(secretFix(run)).toMatchObject({ status: "conflict", commit: null });
    expect(run.totals.commits).toEqual([]);
    expect(readFileSync(join(repo, file), "utf-8")).toContain(USER_WORK);
    expect(git(repo, "show", `HEAD:${file}`)).not.toContain("user's uncommitted work");
  });

  it("never edits a git-ignored file, which git could neither commit nor restore", async () => {
    const repo = repoWith({ ".gitignore": "config.local.js\n", "app.js": "export const x = 1;\n" });
    const local = `export const stripeKey = "${SECRET}";\n`;
    writeFileSync(join(repo, "config.local.js"), local);
    const run = await runLoop({ repo, memoryRoot: tempDir(), maxIterations: 1, ask: async () => "y" });
    expect(run.error).toBeNull();
    expect(secretFix(run)).toMatchObject({ status: "not-applied", reason: expect.stringMatching(/git-ignored/) });
    expect(readFileSync(join(repo, "config.local.js"), "utf-8")).toBe(local);
    expect(existsSync(join(repo, ".env.example"))).toBe(false);
    expect(git(repo, "status", "--porcelain")).toBe("");
  });
});
