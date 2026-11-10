/**
 * `penthera diff [ref]`: only the findings this branch added against the
 * merge-base with main (src/cli/diff.js). Each test builds its own repo in a
 * temp folder; nothing leaves this machine.
 */
import { describe, it, expect, afterAll } from "vitest";
import { mkdtempSync, writeFileSync, rmSync, mkdirSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { diffScan, mergeBaseOf, DIFF_SCHEMA } from "../src/cli/diff.js";

const BIN = join(import.meta.dirname, "..", "bin", "penthera.js");
const temps = [];
afterAll(() => { for (const d of temps) rmSync(d, { recursive: true, force: true }); });

const tempDir = () => { const d = mkdtempSync(join(tmpdir(), "penthera-diff-test-")); temps.push(d); return d; };
const git = (dir, ...args) => execFileSync("git", ["-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...args], { cwd: dir, encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] });
// Built from parts, so this file holds no whole key.
const AWS = "AK" + "IA" + "Z7X3Q9P2M4N6B8V1";
const STRIPE = "sk_" + "live_" + "aB3dE6gH9jK2mN5pQ8sT1vW4";
const STRIPE_2 = "sk_" + "live_" + "Zy8xW7vU6tS5rQ4pO3nM2lK1";

/** main: old.js with an AWS key. feat: the key moved down two lines, and new.js with a Stripe key. */
function branchRepo() {
  const dir = tempDir();
  git(dir, "init", "-q", "-b", "main");
  writeFileSync(join(dir, "old.js"), `const a = "${AWS}";\n`);
  writeFileSync(join(dir, ".gitignore"), ".env\n");
  git(dir, "add", "-A");
  git(dir, "commit", "-qm", "base");
  git(dir, "checkout", "-qb", "feat");
  writeFileSync(join(dir, "old.js"), `\n\nconst a = "${AWS}";\n`);
  writeFileSync(join(dir, "new.js"), `const k = "${STRIPE}";\n`);
  git(dir, "add", "-A");
  git(dir, "commit", "-qm", "feat");
  return dir;
}

describe("penthera diff: what counts as new", () => {
  it("keeps a new key, and leaves out a key that only moved", async () => {
    const dir = branchRepo();
    const { result, diff, limits } = await diffScan(dir);
    expect(diff).toMatchObject({ schema: DIFF_SCHEMA, ref: "main", new: 1, fixed: 0, unchanged: 1, localOnly: 0 });
    expect(diff.mergeBase).toBe(git(dir, "merge-base", "HEAD", "main").trim());
    expect(result.findings.map((f) => f.title)).toEqual(["Stripe secret key in source"]);
    expect(limits[0]).toMatch(/^Only what this branch added against main \(merge-base [0-9a-f]{7}\): 1 found there too and 0 fixed since/);
  });

  it("counts uncommitted work, sees a second key in the same file, and counts what was fixed", async () => {
    const dir = branchRepo();
    writeFileSync(join(dir, "new.js"), `const k = "${STRIPE}";\nconst k2 = "${STRIPE_2}";\n`);
    writeFileSync(join(dir, "old.js"), "const a = process.env.AWS_KEY;\n");
    const { result, diff } = await diffScan(dir);
    expect(diff).toMatchObject({ new: 1, fixed: 1, unchanged: 0 });
    expect(result.findings[0].title).toBe("Stripe secret key in source");
    expect(result.resolved.map((f) => f.title)).toEqual(["AWS access key in source"]);
  });

  it("leaves out files git ignores: a local .env is on no branch", async () => {
    const dir = branchRepo();
    writeFileSync(join(dir, ".env"), `STRIPE_SECRET_KEY=${STRIPE_2}\n`);
    const { result, diff, limits } = await diffScan(dir);
    expect(diff.localOnly).toBe(1);
    expect(result.findings.every((f) => !f.localOnly)).toBe(true);
    expect(limits[1]).toMatch(/1 finding in files git ignores left out/);
  });

  it("scans a subfolder against the same subfolder at the merge-base", async () => {
    const dir = tempDir();
    git(dir, "init", "-q", "-b", "main");
    mkdirSync(join(dir, "app"));
    writeFileSync(join(dir, "app", "a.js"), `const a = "${AWS}";\n`);
    writeFileSync(join(dir, "root.js"), `const k = "${STRIPE}";\n`);
    git(dir, "add", "-A");
    git(dir, "commit", "-qm", "base");
    git(dir, "checkout", "-qb", "feat");
    writeFileSync(join(dir, "app", "b.js"), `const k = "${STRIPE_2}";\n`);
    const { diff } = await diffScan(join(dir, "app"));
    expect(diff).toMatchObject({ new: 1, unchanged: 1 });
  });

  it("changes nothing in the repo", async () => {
    const dir = branchRepo();
    writeFileSync(join(dir, "wip.js"), "// not committed\n");
    const before = [git(dir, "status", "--porcelain"), git(dir, "rev-parse", "HEAD"), git(dir, "stash", "list"), git(dir, "worktree", "list")];
    await diffScan(dir);
    expect([git(dir, "status", "--porcelain"), git(dir, "rev-parse", "HEAD"), git(dir, "stash", "list"), git(dir, "worktree", "list")]).toEqual(before);
  });
});

describe("penthera diff: unpacking the base", () => {
  // Git for Windows ships GNU tar, which reads "C:\\..." as host:path and fails
  // (seen in the install matrix on windows-latest). This stand-in tar refuses
  // absolute paths and drive-style names the same way, then runs the real tar.
  it.skipIf(process.platform === "win32")("passes tar only relative names, so a drive letter can't read as a host", async () => {
    const bin = tempDir();
    const fake = join(bin, "tar");
    writeFileSync(fake, `#!/bin/sh
for a in "$@"; do
  case "$a" in /*|*:*) echo "tar: Cannot connect to $a: resolve failed" >&2; exit 2;; esac
done
exec /usr/bin/tar "$@"
`);
    chmodSync(fake, 0o755);
    const dir = branchRepo();
    const path = process.env.PATH;
    process.env.PATH = `${bin}:${path}`;
    try {
      const { diff } = await diffScan(dir);
      expect(diff).toMatchObject({ new: 1, unchanged: 1 });
    } finally {
      process.env.PATH = path;
    }
  });
});

describe("penthera diff: refs", () => {
  it("falls back to master, takes a named ref, and refuses what is not one", () => {
    const dir = tempDir();
    git(dir, "init", "-q", "-b", "master");
    writeFileSync(join(dir, "a.js"), "1\n");
    git(dir, "add", "-A");
    git(dir, "commit", "-qm", "one");
    git(dir, "tag", "v1");
    expect(mergeBaseOf(dir, null).ref).toBe("master");
    expect(mergeBaseOf(dir, "v1").ref).toBe("v1");
    expect(mergeBaseOf(dir, "nope").error).toMatch(/nope is not a branch, tag or commit/);
    expect(mergeBaseOf(dir, "--output=x").error).toMatch(/Not a git ref/);
    expect(mergeBaseOf(dir, "").error).toMatch(/Not a git ref/);
  });

  it("says so when there is nothing to compare", async () => {
    const plain = tempDir();
    expect((await diffScan(plain)).error).toMatch(/is not in a git repository/);
    const empty = tempDir();
    git(empty, "init", "-q", "-b", "main");
    expect((await diffScan(empty)).error).toMatch(/no commits yet/);
    const lonely = tempDir();
    git(lonely, "init", "-q", "-b", "dev");
    writeFileSync(join(lonely, "a.js"), "1\n");
    git(lonely, "add", "-A");
    git(lonely, "commit", "-qm", "one");
    expect((await diffScan(lonely)).error).toMatch(/No main, origin\/main, master or origin\/master here/);
  });
});

describe("penthera diff: the command", () => {
  const run = (cwd, ...args) => spawnSync(process.execPath, [BIN, "diff", ...args], {
    cwd, encoding: "utf-8", env: { ...process.env, HOME: cwd, PENTHERA_NO_ONBOARDING: "1", NO_COLOR: "1", CI: "", PENTHERA_BRIEF: "1" },
  });

  it("prints JSON, exits 1 on a new critical, and writes the reports", () => {
    const dir = branchRepo();
    const r = run(dir, "--json", "--sarif", "new.sarif", "-o", "new.json");
    expect(r.status).toBe(1);
    const out = JSON.parse(r.stdout);
    expect(out.diff).toMatchObject({ schema: DIFF_SCHEMA, new: 1, unchanged: 1 });
    expect(out.findings).toHaveLength(1);
    expect(out.brief.not_checked[0]).toMatch(/^Only what this branch added against main/);
    // The reports hold the masked key only.
    expect(r.stdout).not.toContain(STRIPE);
    expect(execFileSync("cat", [join(dir, "new.sarif"), join(dir, "new.json"), join(dir, "new.md")], { encoding: "utf-8" })).not.toContain(STRIPE);
  });

  it("prints the brief to a pipe, and exits 0 when nothing new is severe", () => {
    const dir = branchRepo();
    git(dir, "rm", "-q", "new.js");
    git(dir, "commit", "-qm", "drop");
    const r = run(dir);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/^\*\*Penthera: Nothing to fix\.\*\*/);
    expect(r.stdout).toContain("Only what this branch added against main");
  });

  it("exits 2 with a reason, and has its own help", () => {
    const dir = branchRepo();
    const bad = run(dir, "no-such-branch");
    expect(bad.status).toBe(2);
    expect(bad.stderr).toMatch(/no-such-branch is not a branch, tag or commit/);
    const help = run(dir, "--help");
    expect(help.status).toBe(0);
    expect(help.stdout).toMatch(/penthera diff \[<ref>\]/);
  });
});
