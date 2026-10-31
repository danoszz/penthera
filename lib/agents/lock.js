/**
 * penthera.lock: SHA-256 pins for skills, MCP server definitions, hooks and
 * installed plugins. A skill or server that changes after you reviewed it (a
 * "rug pull") shows up as a changed entry on the next run.
 *
 * The file is deterministic (sorted keys, no timestamps) so it diffs cleanly
 * in git.
 */
import { createHash } from "node:crypto";
import { closeSync, constants, lstatSync, openSync, readFileSync, readlinkSync, readSync, writeFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { walk, SKILL_SKIP_DIRS, LOCK_V1_SKIP_DIRS } from "./discover.js";

export const LOCK_FILENAME = "penthera.lock";
/**
 * 2: skills are hashed whole except `node_modules` and `.git`: `dist`,
 *    `build`, `.next`, `__pycache__` and virtual environments are pinned too.
 *    Bytecode and a venv's files are code that runs, and a decoy `pyvenv.cfg`
 *    must not take a folder out of the pin. Python writing a new cache after
 *    the pin shows up as a change; delete `__pycache__` before pinning.
 * 1: 2.0.0, which skipped `.venv`, `venv`, `__pycache__`, `dist`, `build`
 *    and `.next`. A version 1 lock is still compared the version 1 way, so
 *    upgrading never reports a changed skill.
 */
export const LOCK_VERSION = 2;

/** Folders left out of a skill's hash, per lock version. */
function lockSkip(version) {
  return version === 1 ? LOCK_V1_SKIP_DIRS : SKILL_SKIP_DIRS;
}

function sha256(data) {
  return createHash("sha256").update(data).digest("hex");
}

/**
 * Stable JSON: object keys sorted at every level.
 *
 * Iterative (an explicit stack, not recursion) so a config nested hundreds of
 * thousands of levels deep hashes instead of overflowing the call stack.
 */
export function canonicalJson(value) {
  const out = [];
  // Pending work, popped from the end: a string is emitted as is, a
  // { v } is a value still to serialise.
  const stack = [{ v: value }];
  while (stack.length) {
    const item = stack.pop();
    if (typeof item === "string") { out.push(item); continue; }
    const v = item.v;
    if (Array.isArray(v)) {
      out.push("[");
      stack.push("]");
      for (let i = v.length - 1; i >= 0; i--) {
        stack.push({ v: v[i] });
        if (i > 0) stack.push(",");
      }
    } else if (v && typeof v === "object") {
      const keys = Object.keys(v).sort();
      out.push("{");
      stack.push("}");
      for (let i = keys.length - 1; i >= 0; i--) {
        stack.push({ v: v[keys[i]] });
        stack.push(`${i > 0 ? "," : ""}${JSON.stringify(keys[i])}:`);
      }
    } else {
      out.push(JSON.stringify(v ?? null));
    }
  }
  return out.join("");
}

let chunk = null;

/** SHA-256 of a file, read in chunks so a huge file cannot fill memory. An unreadable file hashes as empty. */
function sha256File(path) {
  const hash = createHash("sha256");
  chunk ??= Buffer.alloc(1 << 20);
  let fd;
  try {
    fd = openSync(path, "r");
    let pos = 0;
    for (let n = readSync(fd, chunk, 0, chunk.length, pos); n > 0; n = readSync(fd, chunk, 0, chunk.length, pos)) {
      hash.update(Buffer.from(chunk.subarray(0, n))); // a copy: the browser check's hash keeps what it is given
      pos += n;
    }
    return hash.digest("hex");
  } catch {
    return sha256(Buffer.alloc(0));
  } finally {
    if (fd !== undefined) try { closeSync(fd); } catch { /* ignore */ }
  }
}

/** Hash a folder: every file's path and content hash, plus symlink targets. */
export function hashDir(dir, { version = LOCK_VERSION, ignore = null } = {}) {
  const { files, symlinks } = walk(dir, { maxDepth: 12, maxFiles: 20000, skipDirs: lockSkip(version) });
  const lines = [];
  for (const f of files) {
    if (f === ignore) continue;
    lines.push(`${relative(dir, f).split(sep).join("/")}\0${sha256File(f)}`);
  }
  for (const l of symlinks) {
    let target = "";
    try { target = readlinkSync(l); } catch { /* broken */ }
    lines.push(`${relative(dir, l).split(sep).join("/")}\0link:${target}`);
  }
  lines.sort();
  return sha256(lines.join("\n"));
}

function scopeOf(display) {
  return display.startsWith("~/") || display.startsWith("/") ? "home" : "repo";
}

/** Compute the current lock entries for an inventory. */
export function computeLockEntries(inv, { version = LOCK_VERSION, lockFile = null } = {}) {
  const entries = {};
  for (const s of inv.skills) {
    // --pin on a skill folder writes the lock into that folder. It must not
    // hash itself, or the next run reports the skill as changed.
    entries[`skill:${s.display}`] = { kind: "skill", scope: scopeOf(s.display), sha256: hashDir(s.dir, { version, ignore: s.target ? lockFile : null }) };
  }
  for (const m of inv.mcpServers) {
    entries[`mcp:${m.file}#${m.name}`] = { kind: "mcp", scope: scopeOf(m.file), sha256: sha256(canonicalJson(m.def)) };
  }
  for (const h of inv.hooks) {
    entries[h.key] = { kind: "hook", scope: scopeOf(h.file), sha256: sha256(canonicalJson({ event: h.event, matcher: h.matcher, hook: h.hook })) };
  }
  for (const p of inv.plugins) {
    entries[`plugin:${p.id}`] = { kind: "plugin", scope: "home", sha256: sha256(canonicalJson({ version: p.version, gitCommitSha: p.gitCommitSha })) };
  }
  return entries;
}

export function serializeLock(entries) {
  const sorted = {};
  for (const k of Object.keys(entries).sort()) sorted[k] = entries[k];
  return JSON.stringify({
    lockfileVersion: LOCK_VERSION,
    generator: "penthera agents --pin",
    note: "SHA-256 pins for agent skills, MCP servers, hooks and plugins. Review changes before re-pinning. Version 2 pins every file in a skill except node_modules and .git; re-pin a version 1 file after upgrading.",
    entries: sorted,
  }, null, 2) + "\n";
}

export function lockPath(root) {
  return join(root, LOCK_FILENAME);
}

function lstatOrNull(path) {
  try { return lstatSync(path); } catch { return null; }
}

/** Read a lock file. Returns null when absent; throws on a corrupt file or a link. */
export function readLock(path) {
  const st = lstatOrNull(path);
  if (!st) return null;
  if (st.isSymbolicLink()) throw new Error(`${LOCK_FILENAME} is a symbolic link, so it was not read`);
  const json = JSON.parse(readFileSync(path, "utf-8"));
  if (!json || typeof json.entries !== "object") throw new Error("missing `entries`");
  return json;
}

/** Never through a link: a skill folder could point penthera.lock at any file you can write. */
export function writeLock(path, entries) {
  if (lstatOrNull(path)?.isSymbolicLink()) throw new Error(`${path} is a symbolic link. Remove it, then pin again.`);
  const flag = constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | (constants.O_NOFOLLOW ?? 0);
  writeFileSync(path, serializeLock(entries), { flag });
}

/**
 * Diff a lock against current entries. Entries for a scope that wasn't scanned
 * this run (home, without --home) are not reported as removed.
 */
export function diffLock(lock, current, { scopes = ["repo"] } = {}) {
  const pinned = lock?.entries || {};
  const changed = [];
  const added = [];
  const removed = [];
  for (const [key, cur] of Object.entries(current)) {
    const old = pinned[key];
    if (!old) added.push({ key, ...cur });
    else if (old.sha256 !== cur.sha256) changed.push({ key, ...cur, previous: old.sha256 });
  }
  for (const [key, old] of Object.entries(pinned)) {
    if (!current[key] && scopes.includes(old.scope || "repo")) removed.push({ key, ...old });
  }
  return { changed, added, removed };
}
