import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, realpathSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";
import { detectProject, projectGitRoot } from "../src/cli/detect.js";

// Issue 341: `penthera init` in an empty folder crashed with mkdir ENOENT on
// /reports/penthera-<date>: git found a repository at the filesystem root and the
// wizard took it for the project.
const dirs = [];
const tmp = () => { const d = realpathSync(mkdtempSync(join(tmpdir(), "penthera-init-root-"))); dirs.push(d); return d; };
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
const gitInit = (d) => execFileSync("git", ["init", "-q", d], { stdio: "ignore" });

describe("issue 341: a stray repository above the project is not the project", () => {
  it("a repository at the filesystem root or in home counts only when init runs in it", () => {
    expect(projectGitRoot("/", "/Users/me/app", "/Users/me")).toBe(null);
    expect(projectGitRoot("/Users/me", "/Users/me/app", "/Users/me")).toBe(null);
    expect(projectGitRoot("/Users/me", "/Users/me", "/Users/me")).toBe("/Users/me");
    expect(projectGitRoot("/Users/me/work", "/Users/me/work/app", "/Users/me")).toBe("/Users/me/work");
    expect(projectGitRoot(null, "/Users/me/app", "/Users/me")).toBe(null);
  });
  it("a dotfiles repo in home: the wizard works in the new project folder, not home", async () => {
    const home = tmp();
    gitInit(home);
    const app = join(home, "new-app");
    mkdirSync(app);
    const found = await detectProject(app, { ports: [], home });
    expect(found.root).toBe(app);
    expect(found.git).toBe(false);
  });
  it("a project inside a real repository still uses that repository's root", async () => {
    const repo = tmp();
    gitInit(repo);
    const sub = join(repo, "packages", "web");
    mkdirSync(sub, { recursive: true });
    const found = await detectProject(sub, { ports: [], home: tmp() });
    expect(found.root).toBe(repo);
  });
});
