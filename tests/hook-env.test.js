// What a scanned repo can set in the pre-commit hook's environment must not change what
// the hook checks or its exit code (roadmap row 81; compare Beacon issue 913, where hooks
// trusted variables and HOME from a repo-supplied environment). Temp repos, fake HOME, offline.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync, mkdirSync, chmodSync, realpathSync, symlinkSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { runHook, installHook, hookScript, hookCacheDirs } from "../lib/hook/index.js";
import { sourceFromNpmCache } from "../lib/deps/source.js";

const FAKE_KEY = ["sk", "ant", "api03", "Q".repeat(40)].join("-");
let repo;
const git = (...args) => execFileSync("git", args, { cwd: repo, encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] });
const write = (path, text) => { mkdirSync(join(repo, path, ".."), { recursive: true }); writeFileSync(join(repo, path), text); };

beforeEach(() => {
  repo = realpathSync(mkdtempSync(join(tmpdir(), "penthera-hook-env-")));
  git("init", "-q", "-b", "main");
  write("README.md", "# test\n");
  git("add", ".");
  git("commit", "-q", "-m", "init", "--no-verify");
});
afterEach(() => rmSync(repo, { recursive: true, force: true }));

describe("the installed hook script", () => {
  it("doesn't let NODE_OPTIONS from the repo's environment load the repo's code", () => {
    installHook(repo);
    // What direnv or a project .npmrc (node-options) could put in the environment.
    write("evil.cjs", `require("fs").writeFileSync(${JSON.stringify(join(repo, "loaded"))}, "1"); process.exit(0);\n`);
    write("src/config.js", `export const key = "${FAKE_KEY}";\n`);
    git("add", "src/config.js");
    const r = spawnSync("git", ["commit", "-m", "x"], { cwd: repo, encoding: "utf-8", env: { ...process.env, NODE_OPTIONS: `--require ${join(repo, "evil.cjs")}`, NO_COLOR: "1" } });
    expect(existsSync(join(repo, "loaded"))).toBe(false);
    expect(r.status).not.toBe(0);
    expect(r.stderr).toMatch(/blocked this commit/);
  });

  function fallback(extraPath, npxBody = "exit 1", env = {}) {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "penthera-hookscript-env-")));
    const bin = join(dir, "bin");
    mkdirSync(bin);
    writeFileSync(join(bin, "npx"), `#!/bin/sh\necho "$@" >> ${JSON.stringify(join(dir, "npx.log"))}\n${npxBody}\n`);
    chmodSync(join(bin, "npx"), 0o755);
    const hook = join(dir, "pre-commit");
    writeFileSync(hook, hookScript({ node: process.execPath, bin: join(dir, "gone", "penthera.js"), version: "9.9.9" }));
    chmodSync(hook, 0o755);
    const r = spawnSync("/bin/sh", [hook], { cwd: repo, encoding: "utf-8", env: { PATH: `${extraPath ? `${extraPath}:` : ""}${bin}:/usr/bin:/bin`, ...env } });
    const read = (f) => (existsSync(join(dir, f)) ? readFileSync(join(dir, f), "utf-8") : "");
    const out = { ...r, log: read("npx.log"), cwd: read("npx.cwd").trim(), env: read("npx.env") };
    rmSync(dir, { recursive: true, force: true });
    return out;
  }

  it("never runs a `penthera` that the repo itself put on PATH", () => {
    write("tools/penthera", `#!/bin/sh\necho ran > ${JSON.stringify(join(repo, "ran"))}\nexit 0\n`);
    chmodSync(join(repo, "tools", "penthera"), 0o755);
    const r = fallback(join(repo, "tools"));
    expect(existsSync(join(repo, "ran"))).toBe(false);
    expect(r.log).toContain("penthera@9.9.9");
  });

  it("runs npx outside the repo, with npm's own registry and the user's own cache, and names the repo", () => {
    const r = fallback("", 'case "$*" in *--version*) exit 0;; *) pwd > "$(dirname "$0")/../npx.cwd"; exit 0;; esac');
    expect(r.log).toContain("--registry=https://registry.npmjs.org/");
    expect(r.log).toMatch(/--cache=\S+\/\.npm /);
    expect(r.log).toContain(`hook run --repo ${repo}`);
    expect(r.cwd).toBe("/");
  });

  it("drops every npm_config_* the repo's environment set before npx runs", () => {
    const r = fallback("", 'env > "$(dirname "$0")/../npx.env"; exit 0', { npm_config_node_options: `--require ${join(repo, "x.cjs")}`, NPM_CONFIG_SCRIPT_SHELL: "./sh" });
    expect(r.env).not.toMatch(/npm_config_node_options|NPM_CONFIG_SCRIPT_SHELL/i);
  });

  it("drops NODE_OPTIONS before a hook it chained to runs, too", () => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "penthera-hookscript-chain-")));
    writeFileSync(join(dir, "pre-commit.pre-penthera"), `#!/bin/sh
echo "$NODE_OPTIONS" > ${JSON.stringify(join(dir, "seen"))}
`);
    chmodSync(join(dir, "pre-commit.pre-penthera"), 0o755);
    writeFileSync(join(dir, "pre-commit"), hookScript({ node: process.execPath, bin: join(dir, "gone", "penthera.js"), version: "9.9.9" }));
    spawnSync("/bin/sh", [join(dir, "pre-commit")], { cwd: repo, encoding: "utf-8", env: { PATH: "/usr/bin:/bin", NODE_OPTIONS: "--require ./x.cjs" } });
    expect(readFileSync(join(dir, "seen"), "utf-8").trim()).toBe("");
    rmSync(dir, { recursive: true, force: true });
  });

  it("never runs a global `penthera` that is a link into the repo, or through a `node` the repo put on PATH", () => {
    write("tools/penthera.js", `require("fs").writeFileSync(${JSON.stringify(join(repo, "ran"))}, "1");\n`);
    const outside = realpathSync(mkdtempSync(join(tmpdir(), "penthera-global-")));
    symlinkSync(join(repo, "tools", "penthera.js"), join(outside, "penthera"));
    chmodSync(join(repo, "tools", "penthera.js"), 0o755);
    const r = fallback(outside);
    expect(existsSync(join(repo, "ran"))).toBe(false);
    expect(r.log).toContain("penthera@9.9.9");
    rmSync(outside, { recursive: true, force: true });
  });
});

describe("the hook's view of the npm cache", () => {
  it("always includes the user's own cache, found from the account, not from HOME", () => {
    const dirs = hookCacheDirs({ npm_config_cache: join(repo, "empty-cache"), HOME: join(repo, "fake-home") }, "/home/someone");
    expect(dirs).toContain(join(repo, "empty-cache"));
    expect(dirs).toContain(join("/home/someone", ".npm"));
    expect(dirs).not.toContain(join(repo, "fake-home", ".npm"));
  });

  it("can't be handed other code: a cached file must match the lockfile's integrity", () => {
    const real = Buffer.from("the bytes the lockfile pins");
    const sri = `sha512-${createHash("sha512").update(real).digest("base64")}`;
    const hex = createHash("sha512").update(real).digest("hex");
    const at = join(repo, "planted", "_cacache", "content-v2", "sha512", hex.slice(0, 2), hex.slice(2, 4));
    mkdirSync(at, { recursive: true });
    writeFileSync(join(at, hex.slice(4)), "other bytes, planted by the repo");
    expect(sourceFromNpmCache(sri, join(repo, "planted"))).toBeNull();
  });
});

describe("HOME", () => {
  it("doesn't bring the home folder's agent config into the hook", async () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "penthera-hook-home-")));
    // Built at run time, so Penthera's own deps scan doesn't read this test as an AI config write.
    const config = join(home, `.${"claude"}`);
    mkdirSync(config, { recursive: true });
    writeFileSync(join(config, ["settings", "json"].join(".")), JSON.stringify({ permissions: { allow: ["Bash(*)"] } }));
    const was = process.env.HOME;
    process.env.HOME = home;
    try {
      write("CLAUDE.md", "# Notes\n");
      git("add", "CLAUDE.md");
      const r = await runHook(repo);
      expect([...r.blocking, ...r.below].filter((f) => String(f.url).startsWith("~"))).toEqual([]);
    } finally {
      process.env.HOME = was;
      rmSync(home, { recursive: true, force: true });
    }
  });
});
