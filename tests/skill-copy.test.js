import { describe, it, expect } from "vitest";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { VERDICTS } from "../src/report/brief.js";
import { INSTRUCTIONS } from "../src/mcp/server.js";
import { REPLY_CONTRACT } from "../src/mcp/results.js";

const ROOT = join(import.meta.dirname, "..");

const walk = (dir) => readdirSync(dir, { withFileTypes: true, recursive: true })
  .filter((e) => e.isFile())
  .map((e) => relative(dir, join(e.parentPath, e.name)))
  .sort();

/** Paths that are missing from one folder, or differ between the two. */
function folderDiff(a, b) {
  const left = walk(a), right = walk(b);
  return [...new Set([...left, ...right])].sort().filter((f) => {
    if (!left.includes(f) || !right.includes(f)) return true;
    return !readFileSync(join(a, f)).equals(readFileSync(join(b, f)));
  });
}

describe("the plugin's copy of the skill", () => {
  it("is the same as skills/penthera, file for file, except scripts/ (the directory takes no code files)", () => {
    const src = join(ROOT, "skills", "penthera");
    expect(walk(src).length).toBeGreaterThan(5);
    expect(folderDiff(src, join(ROOT, "plugin", "skills", "penthera")).filter((f) => !f.startsWith("scripts/"))).toEqual([]);
  });

  it("names a changed, a missing and an extra file", () => {
    const dir = mkdtempSync(join(tmpdir(), "penthera-skill-copy-"));
    const put = (f, text) => { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), text); };
    try {
      put("a/same.md", "x");
      put("b/same.md", "x");
      expect(folderDiff(join(dir, "a"), join(dir, "b"))).toEqual([]);
      put("a/changed.md", "1");
      put("b/changed.md", "2");
      put("a/refs/missing.md", "x");
      put("b/extra.md", "x");
      expect(folderDiff(join(dir, "a"), join(dir, "b"))).toEqual(["changed.md", "extra.md", "refs/missing.md"]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("agents know every verdict", () => {
  const skill = readFileSync(join(ROOT, "skills", "penthera", "SKILL.md"), "utf8");

  it("the skill explains each verdict the brief can give", () => {
    expect(Object.keys(VERDICTS).length).toBeGreaterThanOrEqual(5);
    for (const v of Object.values(VERDICTS)) expect(skill, v).toContain(`| \`${v}\` |`);
    expect(skill).toContain("| `N suppressed` |");
  });

  it("MCP clients are told the unread verdicts aren't clean", () => {
    for (const text of [INSTRUCTIONS, REPLY_CONTRACT]) {
      for (const v of ["Site not read", "Nothing to assess", "N suppressed"]) expect(text, v).toContain(v);
    }
  });
});
