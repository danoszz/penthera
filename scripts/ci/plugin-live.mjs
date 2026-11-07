#!/usr/bin/env node
/**
 * Moves the `plugin-claude-live` branch, which Anthropic's plugin directory follows,
 * to the newest commit on main whose plugin skill pins the version npm serves as
 * `latest`. A release PR bumps the pin before the maintainer approves the
 * version on npm, so main can point at a version that doesn't exist yet; this
 * branch never does. It only moves forward (a fast-forward), never rewrites.
 *
 *   node scripts/ci/plugin-live.mjs            find the target and push it
 *   node scripts/ci/plugin-live.mjs --dry-run  print what it would do
 *
 * It moves only when the plugin folder itself changed. Every move is a new
 * version in the directory, which waits for an Anthropic reviewer again, so a
 * merge that leaves plugin/ as it was must not move the branch.
 */
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const BRANCH = "plugin-claude-live";
// The plugin is skill-only: the skill runs `npx -y penthera@<pin>`, so its pin is
// the version the plugin runs. (Until 2.3.2 the plugin also had a .mcp.json with
// the same pin; Anthropic's directory refuses local MCP servers from unverified
// publishers, so it was removed. Every earlier commit's skill carries that pin too.)
const SKILL = "plugin/skills/penthera/SKILL.md";
// The folder the directory reads (its fetch shows only these files).
const PLUGIN_DIR = "plugin";
// How far back on main to look for a commit with the published pin.
const MAX_COMMITS = 500;

/**
 * The penthera version the plugin's skill pins, or null. Every `penthera@<version>`
 * in it must be the same plain x.y.z; a release candidate or two different pins
 * give null. `penthera@next` and `penthera@latest` are not pins and are ignored.
 */
export function pinOf(text) {
  const pins = new Set();
  for (const m of String(text).matchAll(/\bpenthera@(\d[0-9A-Za-z.+-]*)/g)) pins.add(m[1].replace(/[.,;:]+$/, ""));
  if (pins.size !== 1) return null;
  const [pin] = pins;
  return /^\d+\.\d+\.\d+$/.test(pin) ? pin : null;
}

/**
 * The newest commit (commits come newest first) whose pin is `latest`, or
 * null. Release candidates never match: `latest` is a plain x.y.z.
 */
export function chooseTarget(commits, latest) {
  if (!/^\d+\.\d+\.\d+$/.test(latest)) return null;
  return commits.find((c) => c.pin === latest)?.sha ?? null;
}

/**
 * True when `a` and `b` hold the same plugin folder (the same git tree hash),
 * so moving the branch from one to the other would change nothing the
 * directory reads. A missing folder on either side is never "the same".
 */
export function samePlugin(a, b, run = git) {
  const tree = (sha) => { try { return run("rev-parse", `${sha}:${PLUGIN_DIR}`); } catch { return null; } };
  const ta = tree(a);
  return ta !== null && ta === tree(b);
}

const git = (...args) => execFileSync("git", args, { encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] }).trim();

/**
 * Commits on `ref`'s first-parent line, newest first, with their plugin pin,
 * stopping at the first that pins `latest`. First parent only: a merge's side
 * branch holds a contributor's intermediate commits, which nobody reviewed as
 * a snapshot, so a plugin that a PR added and then removed is never a candidate.
 */
export function candidates(ref, latest, run = git) {
  const shas = run("rev-list", "--first-parent", `--max-count=${MAX_COMMITS}`, ref).split("\n").filter(Boolean);
  const commits = [];
  for (const sha of shas) {
    let text = "";
    try { text = run("show", `${sha}:${SKILL}`); } catch { /* no plugin folder in this commit */ }
    commits.push({ sha, pin: pinOf(text) });
    if (commits.at(-1).pin === latest) break;
  }
  return commits;
}

function main() {
  const dry = process.argv.includes("--dry-run");
  const latest = execFileSync("npm", ["view", "penthera", "version"], { encoding: "utf-8" }).trim();
  const target = chooseTarget(candidates("origin/main", latest), latest);
  if (!target) {
    console.error(`No commit in the last ${MAX_COMMITS} on main's first-parent line pins penthera@${latest}; ${BRANCH} stays where it is.`);
    process.exit(1);
  }
  let current = null;
  try { current = git("rev-parse", `origin/${BRANCH}`); } catch { /* the branch doesn't exist yet */ }
  if (current === target) {
    console.log(`${BRANCH} is at ${target.slice(0, 7)} (penthera@${latest}); nothing to do.`);
    return;
  }
  if (current && samePlugin(current, target)) {
    console.log(`${BRANCH} stays at ${current.slice(0, 7)}: the plugin folder at ${target.slice(0, 7)} is the same, so no new version for the directory.`);
    return;
  }
  if (current) {
    try { git("merge-base", "--is-ancestor", current, target); } catch {
      console.error(`${target.slice(0, 7)} is not ahead of ${BRANCH} (${current.slice(0, 7)}); refusing to move it backwards or sideways.`);
      process.exit(1);
    }
  }
  console.log(`${dry ? "Would move" : "Moving"} ${BRANCH} ${current ? current.slice(0, 7) : "(new)"} → ${target.slice(0, 7)} (penthera@${latest}).`);
  if (!dry) git("push", "origin", `${target}:refs/heads/${BRANCH}`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
