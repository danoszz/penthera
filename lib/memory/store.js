/**
 * Local learning store: an append-only, hash-chained event log per project.
 *
 *   ~/.penthera/memory/<project-id>/events.jsonl   one event per line
 *   ~/.penthera/memory/<project-id>/head.json      { count, hash } of the tip
 *   ~/.penthera/memory/<project-id>/meta.json      human label for `memory show`
 *
 * Each line is { v, ts, type, data, prev, hash } with
 *   hash = sha256(prev + canonicalJson({ v, ts, type, data }))
 * and the first event's prev bound to the project id, so a log copied from
 * another project does not verify either.
 *
 * Safety rules (see docs/local-loop.md):
 * - Memory is data. Nothing read from it is executed, evaluated, imported, or
 *   used as a file path or shell command. Views only re-order and suppress.
 * - Memory lives under the user's home (or PENTHERA_HOME), never in the
 *   scanned repo, so a repo cannot ship pre-poisoned memory.
 * - Writes take an exclusive lock file, then append one line with a single
 *   O_APPEND write, so concurrent scans neither interleave nor fork the chain.
 */
import { createHash } from "node:crypto";
import {
  openSync, writeSync, closeSync, readFileSync, writeFileSync, renameSync,
  mkdirSync, existsSync, rmSync, statSync, unlinkSync, constants as FS,
} from "node:fs";
import { join, resolve, dirname } from "node:path";
import { homedir } from "node:os";
import { readRepoFile } from "../fs-safe.js";

export const EVENT_VERSION = 1;
export const EVENT_TYPES = Object.freeze([
  "scan", "fix_applied", "fix_verified", "fix_failed", "fp_suppressed", "probe_yield", "loop_run", "gave_up",
]);
const MAX_LINE_BYTES = 256 * 1024;
const LOCK_STALE_MS = 30_000;
const LOCK_TIMEOUT_MS = 10_000;

export function sha256(s) {
  return createHash("sha256").update(s).digest("hex");
}

/**
 * Deterministic JSON: object keys sorted, no whitespace. Only plain JSON values
 * are accepted (no functions, symbols, undefined, NaN, class instances), so the
 * same event always hashes the same way.
 */
export function canonicalJson(value) {
  if (value === null) return "null";
  switch (typeof value) {
    case "string": return JSON.stringify(value);
    case "boolean": return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) throw new TypeError("canonicalJson: non-finite number");
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
      const proto = Object.getPrototypeOf(value);
      if (proto !== Object.prototype && proto !== null) {
        throw new TypeError("canonicalJson: only plain objects are allowed");
      }
      const keys = Object.keys(value).sort();
      return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(",")}}`;
    }
    default:
      throw new TypeError(`canonicalJson: unsupported type ${typeof value}`);
  }
}

export function hashEvent(prev, { v, ts, type, data }) {
  return sha256(prev + canonicalJson({ v, ts, type, data }));
}

/** The chain's genesis value: binds line 1 to this project. */
export function genesisHash(projectId) {
  return sha256(`penthera-memory-v1:${projectId}`);
}

/** Memory root: $PENTHERA_HOME/memory, else ~/.penthera/memory. */
export function memoryRoot(env = process.env) {
  const base = env.PENTHERA_HOME ? resolve(env.PENTHERA_HOME) : join(homedir(), ".penthera");
  return join(base, "memory");
}

/** Remove credentials from a URL-ish string before it is hashed or shown. */
export function stripCredentials(u) {
  const s = String(u || "").trim();
  try {
    const url = new URL(s);
    url.username = "";
    url.password = "";
    return url.toString();
  } catch {
    return s.replace(/\/\/[^@/]+@/, "//"); // scp-like or odd remotes
  }
}

/**
 * Read the origin remote URL from .git/config without running git. Running git
 * inside an untrusted repo can execute its hooks or core.fsmonitor, so we parse
 * the config text ourselves. Worktrees (.git is a file) follow gitdir/commondir.
 */
/** A git metadata file of the scanned repo: a regular file up to 1 MiB, never a FIFO or a device. */
const readGit = (p) => readRepoFile(p, { followLinks: true, maxBytes: 1024 * 1024 });

export function readGitRemote(repoPath) {
  try {
    let gitDir = join(repoPath, ".git");
    if (!existsSync(gitDir)) return null;
    if (statSync(gitDir).isFile()) {
      const m = readGit(gitDir).match(/^gitdir:[ \t]*(\S.*)$/m);
      if (!m) return null;
      gitDir = resolve(repoPath, m[1].trim());
      const common = join(gitDir, "commondir");
      if (existsSync(common)) gitDir = resolve(gitDir, readGit(common).trim());
    }
    const cfg = readGit(join(gitDir, "config"));
    let section = null;
    let first = null;
    for (const raw of cfg.split(/\r?\n/)) {
      const line = raw.trim();
      const sec = line.match(/^\[\s*remote\s+"([^"]+)"\s*\]$/);
      if (sec) { section = sec[1]; continue; }
      if (line.startsWith("[")) { section = null; continue; }
      const kv = section && line.match(/^url\s*=[ \t]*(\S.*)$/);
      if (kv) {
        if (section === "origin") return stripCredentials(kv[1]);
        first ??= stripCredentials(kv[1]);
      }
    }
    return first;
  } catch {
    return null;
  }
}

/**
 * Project id: sha256 of the repo's absolute path + git remote, or of the
 * target origin for URL-only scans. Returns { id, label }.
 */
export function projectIdFor({ repo, url } = {}) {
  if (repo) {
    const abs = resolve(repo);
    const remote = readGitRemote(abs) || "";
    return { id: sha256(`repo\n${abs}\n${remote}`), label: remote ? `${abs} (${remote})` : abs };
  }
  if (url) {
    const origin = new URL(stripCredentials(url)).origin;
    return { id: sha256(`url\n${origin}`), label: origin };
  }
  throw new Error("projectIdFor: need a repo path or a URL");
}

function sleepMs(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function withLock(dir, fn) {
  const lock = join(dir, "events.lock");
  // The timeout is per holder: while other writers keep taking and releasing
  // the lock we are queued behind progress, not stuck, however long that takes
  // on a loaded machine. Only one holder keeping it for LOCK_TIMEOUT_MS is busy.
  let holder = null;
  let waitingSince = Date.now();
  let fd;
  for (;;) {
    try {
      fd = openSync(lock, FS.O_CREAT | FS.O_EXCL | FS.O_WRONLY, 0o600);
      break;
    } catch (e) {
      if (e.code !== "EEXIST") throw e;
      try {
        const st = statSync(lock);
        if (Date.now() - st.mtimeMs > LOCK_STALE_MS) { unlinkSync(lock); continue; }
        const id = `${st.ino}:${st.mtimeMs}`;
        if (id !== holder) { holder = id; waitingSince = Date.now(); }
      } catch { continue; } // lock vanished between calls: retry
      if (Date.now() - waitingSince > LOCK_TIMEOUT_MS) throw new Error(`memory: lock busy (${lock})`);
      sleepMs(5 + Math.floor(Math.random() * 20));
    }
  }
  try {
    writeSync(fd, String(process.pid));
    return fn();
  } finally {
    closeSync(fd);
    try { unlinkSync(lock); } catch { /* already gone */ }
  }
}

function readJson(path) {
  try { return JSON.parse(readFileSync(path, "utf-8")); } catch { return null; }
}

function writeJsonAtomic(path, obj) {
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(obj, null, 2) + "\n", { mode: 0o600 });
  renameSync(tmp, path);
}

/** Split the log into lines, keeping a trailing partial line visible to verify(). */
function readLines(file) {
  if (!existsSync(file)) return [];
  const text = readFileSync(file, "utf-8");
  const lines = text.split("\n");
  if (lines[lines.length - 1] === "") lines.pop();
  return lines;
}

function isPlainObject(x) {
  return x !== null && typeof x === "object" && !Array.isArray(x)
    && (Object.getPrototypeOf(x) === Object.prototype || Object.getPrototypeOf(x) === null);
}

/** Walk a list of raw lines and check every link. */
export function verifyLines(lines, projectId) {
  let prev = genesisHash(projectId);
  for (let i = 0; i < lines.length; i++) {
    const lineNo = i + 1;
    let ev;
    try { ev = JSON.parse(lines[i]); } catch {
      return { ok: false, count: i, brokenAt: lineNo, reason: "line is not valid JSON" };
    }
    if (!isPlainObject(ev) || ev.v !== EVENT_VERSION || typeof ev.ts !== "string"
      || !EVENT_TYPES.includes(ev.type) || !isPlainObject(ev.data)
      || typeof ev.prev !== "string" || typeof ev.hash !== "string") {
      return { ok: false, count: i, brokenAt: lineNo, reason: "malformed event" };
    }
    if (ev.prev !== prev) {
      return { ok: false, count: i, brokenAt: lineNo, reason: "prev does not match the previous line's hash (line removed, reordered, or inserted)" };
    }
    let expect;
    try { expect = hashEvent(prev, ev); } catch {
      return { ok: false, count: i, brokenAt: lineNo, reason: "event is not canonical JSON" };
    }
    if (ev.hash !== expect) {
      return { ok: false, count: i, brokenAt: lineNo, reason: "hash mismatch (line edited)" };
    }
    prev = ev.hash;
  }
  return { ok: true, count: lines.length, tip: prev };
}

/**
 * Open (lazily create) the memory for a project. Nothing touches disk until the
 * first append, so read-only commands on an unknown project leave no trace.
 */
export function openMemory(projectId, { root = memoryRoot(), label = null, now = () => new Date().toISOString() } = {}) {
  if (!/^[0-9a-f]{64}$/.test(String(projectId))) throw new Error("openMemory: project id must be a sha256 hex string");
  const dir = join(root, projectId);
  const file = join(dir, "events.jsonl");
  const headFile = join(dir, "head.json");
  const metaFile = join(dir, "meta.json");

  function ensureDir() {
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      writeJsonAtomic(metaFile, { projectId, label, createdAt: now() });
    }
  }

  /** Validated, parsed events (only call after verify() says ok). */
  function events() {
    return readLines(file).map((l) => JSON.parse(l));
  }

  function verify() {
    const lines = readLines(file);
    const res = verifyLines(lines, projectId);
    if (!res.ok) return res;
    // The chain alone cannot see the tail being cut off; head.json can.
    const head = readJson(headFile);
    if (lines.length === 0) {
      if (head && head.count > 0) return { ok: false, count: 0, brokenAt: 1, reason: `log is empty but head.json records ${head.count} events (lines deleted)` };
      return res;
    }
    if (!head || !Number.isInteger(head.count) || head.count < 1 || typeof head.hash !== "string") {
      return { ok: false, count: lines.length, brokenAt: lines.length, reason: "head.json missing or malformed" };
    }
    if (head.count > lines.length) {
      return { ok: false, count: lines.length, brokenAt: lines.length + 1, reason: `head.json records ${head.count} events, log has ${lines.length} (lines deleted from the end)` };
    }
    const atHead = JSON.parse(lines[head.count - 1]).hash;
    if (atHead !== head.hash) {
      return { ok: false, count: lines.length, brokenAt: head.count, reason: "head.json hash does not match the log (log rewritten)" };
    }
    return { ...res, headStale: head.count < lines.length };
  }

  /**
   * Append one event. `event` is { type, data, ts? }. Returns the stored line
   * object. Refuses unknown types, non-plain data, and oversized lines.
   */
  function append(event) {
    const type = event?.type;
    if (!EVENT_TYPES.includes(type)) throw new Error(`memory: unknown event type "${type}"`);
    const data = event.data ?? {};
    if (!isPlainObject(data)) throw new Error("memory: event data must be a plain object");
    const ts = typeof event.ts === "string" ? event.ts : now();
    canonicalJson(data); // throws on anything that is not plain JSON
    ensureDir();
    return withLock(dir, () => {
      const lines = readLines(file);
      const prev = lines.length ? JSON.parse(lines[lines.length - 1]).hash : genesisHash(projectId);
      const body = { v: EVENT_VERSION, ts, type, data };
      const rec = { ...body, prev, hash: hashEvent(prev, body) };
      const line = JSON.stringify(rec) + "\n";
      if (Buffer.byteLength(line) > MAX_LINE_BYTES) throw new Error("memory: event too large");
      const fd = openSync(file, FS.O_CREAT | FS.O_APPEND | FS.O_WRONLY, 0o600);
      try { writeSync(fd, line); } finally { closeSync(fd); }
      writeJsonAtomic(headFile, { count: lines.length + 1, hash: rec.hash });
      return rec;
    });
  }

  function meta() {
    return readJson(metaFile);
  }

  /** Delete this project's memory. */
  function forget() {
    const existed = existsSync(dir);
    rmSync(dir, { recursive: true, force: true });
    return existed;
  }

  return { projectId, dir, file, append, verify, events, meta, forget, exists: () => existsSync(file) };
}

/** Delete every project's memory under the root. */
export function forgetAll({ root = memoryRoot() } = {}) {
  const existed = existsSync(root);
  // Only ever remove the memory/ directory itself, never its parent.
  if (dirname(root) === root) throw new Error("refusing to remove a filesystem root");
  rmSync(root, { recursive: true, force: true });
  return existed;
}
