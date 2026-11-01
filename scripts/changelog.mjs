#!/usr/bin/env node
/**
 * CHANGELOG fragments: each pull request adds one file to changelog.d/
 * instead of editing CHANGELOG.md, so parallel PRs never conflict there.
 *
 *   node scripts/changelog.mjs                       check every fragment
 *   node scripts/changelog.mjs --release 1.9.0 2026-11-01
 *                                                    move fragments into CHANGELOG.md
 *
 * A fragment is `changelog.d/<short-name>.md`:
 *
 *   section: Fixed
 *
 *   - **What changed for users.** One or more bullets in the voice guide.
 *
 * A `docs: none, <reason>` line right under `section:` tells the docs gate
 * (scripts/ci/docs-gate.mjs) why a change to the public surface needs no doc.
 * It never reaches CHANGELOG.md.
 *
 * On release, fragments are grouped by section under `## [version] - date`,
 * after any notes already under [Unreleased], and the fragment files are removed.
 */
import { readFileSync, writeFileSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";

export const SECTIONS = ["Security", "Added", "Detection", "Changed", "Fixed", "Removed", "Site", "Docs"];
const ROOT = new URL("..", import.meta.url).pathname;

/** Parses one fragment's text into { section, docsNone, body }, or throws with a reason. */
export function parseFragment(text, name = "fragment") {
  const m = /^section:\s*(\S.*?)\s*\n(?:docs:(.*)\n)?\s*\n([\s\S]*\S)\s*$/.exec(text);
  if (!m) throw new Error(`${name}: expected "section: <name>", a blank line, then the notes`);
  const section = m[1];
  const docsNone = m[2] === undefined ? null : /^\s*none,\s*(\S.{7,}?)\s*$/.exec(m[2])?.[1];
  if (docsNone === undefined) throw new Error(`${name}: expected "docs: none, <reason>", with a reason of 8 characters or more`);
  if (!SECTIONS.includes(section)) throw new Error(`${name}: unknown section "${section}" (use one of ${SECTIONS.join(", ")})`);
  if (!/^- /m.test(m[3])) throw new Error(`${name}: the notes should be "- " bullets`);
  return { section, docsNone, body: m[3] };
}

/** Reads every fragment in `dir`, sorted by file name. */
export function readFragments(dir) {
  let files = [];
  try { files = readdirSync(dir).filter((f) => f.endsWith(".md") && f !== "README.md").sort(); } catch { return []; }
  return files.map((f) => ({ file: f, ...parseFragment(readFileSync(join(dir, f), "utf8"), f) }));
}

/** Returns `changelog` with a new release section built from `[Unreleased]` notes plus `fragments`. */
export function release(changelog, fragments, version, date) {
  const start = changelog.indexOf("## [Unreleased]");
  if (start < 0) throw new Error("CHANGELOG.md has no [Unreleased] section");
  const next = changelog.indexOf("\n## [", start + 1);
  const end = next < 0 ? changelog.length : next + 1;
  const groups = new Map();
  let current = null;
  for (const line of changelog.slice(start + "## [Unreleased]".length, end).split("\n")) {
    const h = /^### (.+)$/.exec(line);
    if (h) { current = h[1].trim(); if (!groups.has(current)) groups.set(current, []); continue; }
    if (current && line.trim()) groups.get(current).push(line);
  }
  for (const f of fragments) {
    if (!groups.has(f.section)) groups.set(f.section, []);
    groups.get(f.section).push(...f.body.split("\n"));
  }
  const order = [...SECTIONS, ...[...groups.keys()].filter((k) => !SECTIONS.includes(k))];
  let out = `## [Unreleased]\n\n## [${version}] - ${date}\n`;
  for (const name of order) {
    const lines = groups.get(name);
    if (lines?.length) out += `\n### ${name}\n\n${lines.join("\n")}\n`;
  }
  return changelog.slice(0, start) + out + "\n" + changelog.slice(end);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const dir = join(ROOT, "changelog.d");
  const args = process.argv.slice(2);
  try {
    const fragments = readFragments(dir);
    if (args[0] === "--release") {
      const [, version, date] = args;
      if (!/^\d+\.\d+\.\d+(-[\w.]+)?$/.test(version || "") || !/^\d{4}-\d{2}-\d{2}$/.test(date || "")) {
        throw new Error("usage: changelog.mjs --release <version> <YYYY-MM-DD>");
      }
      const path = join(ROOT, "CHANGELOG.md");
      writeFileSync(path, release(readFileSync(path, "utf8"), fragments, version, date));
      for (const f of fragments) rmSync(join(dir, f.file));
      console.log(`CHANGELOG.md: ${version} with ${fragments.length} fragment(s) folded in`);
    } else {
      console.log(`changelog.d: ${fragments.length} fragment(s), all valid`);
    }
  } catch (e) {
    console.error(e.message);
    process.exit(1);
  }
}
