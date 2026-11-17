/**
 * Keeps the repository clean for the scanners that read it.
 *
 * Skill registries (skills.sh and its Gen and Snyk audits) scan this whole
 * repository, not only skills/penthera. In November 2026 they failed Penthera
 * as malware because a test fixture, a fake poisoned skill, sat in the tree as
 * plain files. Attack samples a test needs are built at run time instead (see
 * tests/fixtures/agents/malicious.js and tests/fixtures/deps/build.js).
 *
 * These checks fail when a tracked file brings that back.
 */
import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dirname, "..");
const ls = spawnSync("git", ["ls-files", "-z"], { cwd: ROOT, encoding: "utf-8", maxBuffer: 64 * 1024 * 1024 });
const tracked = ls.status === 0 ? ls.stdout.split("\0").filter(Boolean) : [];
const read = (rel) => { try { return readFileSync(join(ROOT, rel), "utf-8"); } catch { return ""; } };
const j = (...p) => p.join("");

// The only skills in the tree: ours, its plugin copy, and two harmless fixtures.
const SKILLS = [
  "plugin/skills/penthera/SKILL.md",
  "skills/penthera/SKILL.md",
  "tests/fixtures/agents/clean/skills/release-notes/SKILL.md",
  "tests/fixtures/aibom/app/.claude/skills/triage/SKILL.md",
];

// A download piped to a shell, or run through eval, with a real URL in it.
const DOWNLOAD_AND_RUN = new RegExp(j(
  "(?:cur", "l|wge", "t)\\b[^|\\n]*https?://[^|\\n]*\\|\\s*(?:sudo\\s+)?(?:ba|z)?sh\\b",
  "|eval\\s+\"\\$\\((?:cur", "l|wge", "t)",
));

// Hosts the skill may name: reserved example names, loopback, and our own.
const SKILL_HOSTS = /^(?:(?:[\w-]+\.)?example\.(?:com|org|net)|localhost|127\.0\.0\.1|\[::1\]|github\.com|docs\.penthera\.org|penthera\.org|nodejs\.org)$/;

describe.skipIf(tracked.length === 0)("the tree holds nothing a registry scanner reads as an attack", () => {
  it("has no skill beyond the known ones", () => {
    expect(tracked.filter((f) => /(?:^|\/)SKILL\.md$/.test(f)).sort()).toEqual(SKILLS);
  });

  // Docs and test code may spell the pattern out to explain or test a rule.
  // What must stay clean is what a scanner reads as runnable or as agent
  // config: scripts, skills, agent instruction and config files, and fixtures.
  it("has no script, skill, agent config or fixture that downloads a script and runs it", () => {
    const runnable = (f) =>
      /\.(?:sh|bash|zsh|ps1|bat|cmd)$/.test(f) ||
      /^(?:skills|plugin|tests\/fixtures)\//.test(f) && !/\.(?:js|mjs|cjs|ts)$/.test(f) ||
      /(?:^|\/)(?:SKILL|AGENTS|CLAUDE|GEMINI)\.md$/.test(f) ||
      /(?:^|\/)(?:\.mcp\.json|mcp\.json|settings(?:\.local)?\.json|hooks\.json|marketplace\.json|plugin\.json)$/.test(f);
    const hits = tracked.filter((f) => runnable(f) && DOWNLOAD_AND_RUN.test(read(f)));
    expect(hits, "build attack samples at run time, as tests/fixtures/agents/malicious.js does").toEqual([]);
  });

  it("names only reserved, loopback or our own hosts in the skill", () => {
    const bad = [];
    for (const f of tracked.filter((p) => /^(?:skills|plugin\/skills)\//.test(p))) {
      for (const m of read(f).matchAll(/https?:\/\/(\[[^\]]+\]|[A-Za-z0-9.-]+)/g)) {
        const host = m[1].replace(/\.$/, "");
        if (!SKILL_HOSTS.test(host)) bad.push(`${f}: ${host}`);
      }
    }
    expect(bad, "use example.com in skill examples, never a real third-party domain").toEqual([]);
  });

  it("links the docs-site skill copy to a release tag, not a moving branch", () => {
    expect(read("docs/skill.md")).not.toMatch(/github\.com\/danoszz\/penthera\/blob\/main\/skills\/penthera\//);
  });
});
