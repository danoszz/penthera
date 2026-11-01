/**
 * applyDiff: the one place fix recipes' diffs get written to disk.
 *
 * Planning never writes. Applying is a separate, explicit step that refuses to
 * write outside the repo, into any .git (any case, any depth, any NTFS alias),
 * to a protected file (tests, test config, Penthera's own files, CI, hooks,
 * lockfiles, .gitmodules: see PROTECTED_FILES), through a symlink anywhere in the path, or into a dirty git
 * tree (unless the caller passes allowDirty). It refuses added lines carrying
 * control characters a terminal would act on, and it is all-or-nothing: every
 * hunk must apply, and if a write fails the files already written are put back.
 *
 * Each file is written to a temp file in its directory and moved into place, so
 * a hard link is replaced rather than written through, and an edit is refused
 * if the file changed since it was read.
 */
import { createHash, randomBytes } from "node:crypto";
import {
  existsSync, readFileSync, mkdirSync, realpathSync, lstatSync, fstatSync, openSync, writeSync, closeSync,
  renameSync, linkSync, unlinkSync, rmdirSync, chmodSync, constants,
} from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { createGit, isOwnReport, parseStatusZ } from "../../src/agent/git.js";
import { parsePatch, applyHunks } from "./diff.js";

export class FixError extends Error {
  constructor(message, code) {
    super(message);
    this.name = "FixError";
    this.code = code;
  }
}

function inside(root, p) {
  const rel = relative(root, p);
  return rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel));
}

export const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");

// Code points HFS+ ignores in names, so ".g‌it" is ".git" on macOS (CVE-2014-9390).
const IGNORABLE = /[​-‏‪-‮⁠-⁤⁪-⁯﻿]/g;

/**
 * The name a path segment resolves to on case-insensitive file systems
 * (macOS, Windows): case folded, ignorable code points dropped, and the
 * trailing dots and spaces Windows strips removed.
 */
export function canonicalSegment(seg) {
  return String(seg).normalize("NFC").replace(IGNORABLE, "").replace(/[. ]+$/, "").toLowerCase();
}

/** True for a segment that names the git directory: .git, .GIT, .Git., or the 8.3 alias GIT~1. */
export function isGitDirSegment(seg) {
  const c = canonicalSegment(seg);
  return c === ".git" || /^git~\d+$/.test(c);
}

const LOCKFILES = new Set([
  "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb", "deno.lock",
  "poetry.lock", "pipfile.lock", "uv.lock", "pdm.lock", "cargo.lock", "go.sum", "gemfile.lock", "composer.lock",
]);
const TEST_CONFIG = new Set(["package.json", "pytest.ini", "tox.ini", "setup.cfg", "pyproject.toml"]);

/**
 * Paths a fix diff may never touch even though they live in the work tree: the
 * judge that verifies a fix (tests, test runner config, Penthera's own policy,
 * suppressions, baseline and memory), CI, git hooks and lockfiles. A fix may not
 * pass by editing its own checker. Each entry is [what, test(segments, basename)]
 * on canonical segments, so case and Windows aliases do not slip past.
 */
const PROTECTED_FILES = [
  ["Windows 8.3 short names (they can alias a protected file)", (s) => s.some((d) => /~\d+(\.[^.]*)?$/.test(d))],
  [".gitmodules (it can point git at other repositories)", (s, b) => b === ".gitmodules"],
  ["tests", (s, b) => s.some((d) => d === "test" || d === "tests" || d === "__tests__") || /\.(test|spec)\./.test(b) || b === "conftest.py"],
  ["test runner config or the test script", (s, b) => /^(vitest|jest|playwright)\./.test(b) || TEST_CONFIG.has(b)],
  ["Penthera's own policy, suppressions, baseline, lock or memory", (s, b) => b.startsWith("penthera.") || s.includes(".penthera") || s.join("/").endsWith("audit/baseline.json")],
  ["CI workflows", (s) => s.some((d, i) => d === ".github" && s[i + 1] === "workflows")],
  ["git hooks", (s, b) => s.includes(".husky") || s.includes(".githooks") || /^(lefthook\.ya?ml|\.pre-commit-config\.ya?ml)$/.test(b)],
  ["lockfiles", (s, b) => LOCKFILES.has(b)],
];

/** What protected kind of file `file` (repo-relative) is, or null if a fix may edit it. */
export function protectedReason(file) {
  const segs = String(file).split(/[\\/]/).filter((x) => x && x !== ".").map(canonicalSegment);
  const hit = PROTECTED_FILES.find(([, test]) => test(segs, segs[segs.length - 1] || ""));
  return hit ? hit[0] : null;
}

// C0 controls (tab aside), DEL and C1 controls: a terminal acts on them instead of showing them.
const CONTROL = /[\u0000-\u0008\u000a-\u001f\u007f-\u009f]/;

/**
 * Throws unless no component of `target` below `root` is a symlink, and no
 * component above the file itself is something other than a directory. Every
 * existing component is lstat-ed, so neither a symlinked directory nor a
 * dangling symlink at the file itself can redirect a write.
 */
function assertNoSymlinks(root, target, file) {
  let cur = root;
  const segs = relative(root, target).split(sep);
  for (let i = 0; i < segs.length; i++) {
    cur = join(cur, segs[i]);
    let st;
    try {
      st = lstatSync(cur);
    } catch (e) {
      if (e.code === "ENOENT") return;
      throw e;
    }
    if (st.isSymbolicLink()) {
      throw new FixError(`Refusing to write ${file}: ${relative(root, cur)} is a symlink, and fix diffs never write through symlinks`, "SYMLINK");
    }
    if (i < segs.length - 1 && !st.isDirectory()) {
      throw new FixError(`Refusing to write ${file}: ${relative(root, cur)} is not a directory`, "CONFLICT");
    }
  }
}

/** Resolve a diff path to an absolute path inside the repo, or throw. */
function safeTarget(root, file) {
  if (!file || isAbsolute(file) || CONTROL.test(file) || file.includes("\0") || /^[a-zA-Z]:/.test(file)) {
    throw new FixError(`Refusing to write ${JSON.stringify(file)}: paths in a diff must be relative to the repo`, "OUTSIDE_REPO");
  }
  const segs = file.split(/[\\/]/);
  if (segs.includes("..")) throw new FixError(`Refusing to write ${file}: it is outside the repo`, "OUTSIDE_REPO");
  // NTFS alternate data streams (".git::$INDEX_ALLOCATION") name the same directory or file.
  if (segs.some((s) => s.includes(":"))) throw new FixError(`Refusing to write ${JSON.stringify(file)}: path segments may not contain ":"`, "OUTSIDE_REPO");
  // Any .git at any depth, in any case: on macOS .GIT/hooks/pre-commit is .git/hooks/pre-commit.
  if (segs.some(isGitDirSegment)) throw new FixError(`Refusing to write ${file}: it is inside .git`, "OUTSIDE_REPO");
  const why = protectedReason(file);
  if (why) {
    throw new FixError(`Refusing to write ${file}: fix diffs never edit ${why}, so the checks that verify a fix stay as they were. If the real fix needs this file changed, make that change by hand and review it.`, "PROTECTED");
  }
  const target = resolve(root, file);
  if (!inside(root, target) || target === root) throw new FixError(`Refusing to write ${file}: it is outside the repo`, "OUTSIDE_REPO");
  assertNoSymlinks(root, target, file);
  return target;
}

/**
 * Throws unless repoPath is in a git work tree with no uncommitted changes
 * under it, Penthera's own untracked reports aside (isOwnReport).
 * @returns {string[]} those reports, relative to repoPath
 */
export function assertCleanTree(repoPath) {
  let entries;
  try {
    // The hardened runner: no fsmonitor, no hooks, no filters, no transports (src/agent/git.js).
    const git = createGit(repoPath);
    git.run("rev-parse", "--is-inside-work-tree");
    const prefix = git.run("rev-parse", "--show-prefix").replace(/\n$/, "");
    entries = parseStatusZ(git.run("status", "--porcelain=v1", "-z", "--untracked-files=all", "--", "."), prefix);
  } catch {
    throw new FixError(`${repoPath} is not a git work tree, so a fix could not be reviewed or reverted. Commit it to git first, or pass --allow-dirty.`, "NOT_GIT");
  }
  if (entries.some((e) => !isOwnReport(e))) {
    throw new FixError(`${repoPath} has uncommitted changes. Commit or stash them first so the fix is its own reviewable change, or pass --allow-dirty.`, "DIRTY");
  }
  return entries.map((e) => e.path);
}

const NOFOLLOW = constants.O_NOFOLLOW || 0;

/** Current bytes of a regular file, null if it does not exist; throws on anything else. */
function readCurrent(target, file) {
  let st;
  try {
    st = lstatSync(target);
  } catch (e) {
    if (e.code === "ENOENT") return null;
    throw e;
  }
  if (!st.isFile()) throw new FixError(`Refusing to write ${file}: it is not a regular file`, "CONFLICT");
  const fd = openSync(target, constants.O_RDONLY | NOFOLLOW);
  try {
    return readFileSync(fd);
  } finally {
    closeSync(fd);
  }
}

function assertDirInside(root, dir, file) {
  const real = realpathSync(dir);
  if (!inside(root, real)) throw new FixError(`Refusing to write ${file}: its directory resolves outside the repo`, "OUTSIDE_REPO");
}

/**
 * Put `data` at `target`, but only if the file currently holds `expect`
 * (a Buffer), or does not exist (expect === null). The bytes go to a temp file
 * in the same directory first, then are moved into place: rename for an edit
 * (which replaces a hard link instead of writing through it), link for a new
 * file (which fails if something appeared there meanwhile).
 *
 * @returns {{ madeDir: string|undefined }} the first directory mkdir created, if any
 */
function replaceFile(root, file, target, data, expect) {
  assertNoSymlinks(root, target, file);
  const dir = dirname(target);
  const madeDir = mkdirSync(dir, { recursive: true });
  assertNoSymlinks(root, target, file);
  assertDirInside(root, dir, file);

  const current = readCurrent(target, file);
  const unchanged = expect === null ? current === null : current !== null && current.equals(expect);
  if (!unchanged) throw new FixError(`${file} changed on disk since the fix was planned; nothing was written to it`, "CHANGED");
  const mode = current === null ? 0o644 : lstatSync(target).mode & 0o7777;

  const tmp = join(dir, `.${basename(target)}.penthera-${randomBytes(6).toString("hex")}.tmp`);
  const fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NOFOLLOW, 0o600);
  try {
    let off = 0;
    while (off < data.length) off += writeSync(fd, data, off, data.length - off);
    // The temp file we wrote must be the one at that path, in a directory inside the repo.
    const a = fstatSync(fd);
    const b = lstatSync(tmp);
    if (a.dev !== b.dev || a.ino !== b.ino) throw new FixError(`Refusing to write ${file}: its directory changed while writing`, "RACE");
  } catch (e) {
    closeSync(fd);
    try { unlinkSync(tmp); } catch { /* best effort */ }
    throw e;
  }
  closeSync(fd);
  try {
    chmodSync(tmp, mode);
    assertDirInside(root, dir, file);
    if (expect === null) {
      try {
        linkSync(tmp, target);
      } catch (e) {
        if (e.code === "EEXIST") throw new FixError(`${file} appeared on disk while the fix was being written; nothing was written to it`, "CHANGED");
        // File systems without hard links: exclusive create, never through a symlink.
        const out = openSync(target, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NOFOLLOW, mode);
        try {
          let off = 0;
          while (off < data.length) off += writeSync(out, data, off, data.length - off);
        } finally {
          closeSync(out);
        }
      }
    } else {
      const again = readCurrent(target, file);
      if (!again || !again.equals(expect)) throw new FixError(`${file} changed on disk while the fix was being written; nothing was written to it`, "CHANGED");
      renameSync(tmp, target);
    }
  } finally {
    try { unlinkSync(tmp); } catch { /* already renamed */ }
  }
  return { madeDir };
}

/** Remove the directories a write created (deepest first), as long as they are empty. */
function removeMadeDirs(target, madeDir) {
  if (!madeDir) return;
  for (let d = dirname(target); d.length >= madeDir.length; d = dirname(d)) {
    try { rmdirSync(d); } catch { return; }
    if (d === madeDir) return;
  }
}

/**
 * Put files written by applyDiff back the way they were, one by one, never
 * over somebody else's edit: a file is restored (or, if the fix created it,
 * removed) only while it still holds exactly what applyDiff wrote. A file that
 * changed since is left alone and reported as a conflict. Every file is tried
 * even if an earlier one fails.
 *
 * @param {string} repoPath
 * @param {{ path: string, created: boolean, before: Buffer|null, sha256: string }[]} files - applyDiff's result
 * @returns {{ restored: string[], conflicts: string[], errors: { path: string, message: string }[] }}
 */
export function restoreFiles(repoPath, files) {
  const root = realpathSync(resolve(repoPath));
  const out = { restored: [], conflicts: [], errors: [] };
  for (const f of files) {
    try {
      const target = safeTarget(root, f.path);
      const current = readCurrent(target, f.path);
      const original = f.created ? null : f.before;
      if (current === null ? original === null : original !== null && current.equals(original)) {
        out.restored.push(f.path); // already as it was
      } else if (current === null || sha256(current) !== f.sha256) {
        out.conflicts.push(f.path);
      } else if (original === null) {
        unlinkSync(target);
        out.restored.push(f.path);
      } else {
        replaceFile(root, f.path, target, original, current);
        out.restored.push(f.path);
      }
    } catch (e) {
      if (e.code === "CHANGED") out.conflicts.push(f.path);
      else out.errors.push({ path: f.path, message: e.message });
    }
  }
  return out;
}

/** Throws if an added line carries a control character (a trailing CR of a CRLF line is fine). */
function assertPrintable(f) {
  for (const h of f.hunks) {
    for (const op of h.ops) {
      if (op.t !== "+") continue;
      const line = op.line.replace(/\u0000$/, "").replace(/\r$/, "");
      if (CONTROL.test(line)) {
        throw new FixError(`Refusing to write ${f.newPath}: an added line contains a control character (${JSON.stringify(line.match(CONTROL)[0])}), which can hide code in a terminal`, "CONTROL_CHARS");
      }
    }
  }
}

/** Throws on two entries for one file, or one file that is another's directory. */
function assertDistinctPaths(parsed) {
  const keys = parsed.map((f) => String(f.newPath).split(/[\\/]/).map(canonicalSegment).join("/"));
  for (let i = 0; i < keys.length; i++) {
    for (let j = 0; j < keys.length; j++) {
      if (i === j) continue;
      if (keys[i] === keys[j]) throw new FixError(`Refusing the diff: it changes ${parsed[i].newPath} more than once`, "DUPLICATE");
      if (keys[j].startsWith(`${keys[i]}/`)) throw new FixError(`Refusing the diff: ${parsed[i].newPath} is both a file and the directory of ${parsed[j].newPath}`, "CONFLICT");
    }
  }
}

/**
 * Apply a unified diff to files under repoPath.
 *
 * @param {string} repoPath
 * @param {string} diff
 * @param {{ dryRun?: boolean, allowDirty?: boolean }} [opts]
 * @returns {{ applied: boolean, files: { path: string, created: boolean, before: Buffer|null, sha256: string }[] }}
 *   before is the file's bytes before the write; sha256 is the hash of what was written.
 */
export function applyDiff(repoPath, diff, opts = {}) {
  const root = realpathSync(resolve(repoPath));
  const parsed = parsePatch(diff);
  if (parsed.length === 0) throw new FixError("The diff contains no file changes", "EMPTY");
  const ownReports = opts.allowDirty ? [] : assertCleanTree(root);

  const writes = [];
  for (const f of parsed) {
    if (ownReports.includes(f.newPath)) throw new FixError(`Refusing to write ${f.newPath}: it is an uncommitted scan report`, "DIRTY");
    if (!f.newPath) throw new FixError(`Refusing to delete ${f.oldPath}: fix diffs never delete files`, "DELETE");
    if (f.oldPath && f.oldPath !== f.newPath) throw new FixError(`Refusing to rename ${f.oldPath}: fix diffs never rename files`, "RENAME");
    assertPrintable(f);
  }
  assertDistinctPaths(parsed);
  for (const f of parsed) {
    const target = safeTarget(root, f.newPath);
    const exists = existsSync(target);
    if (exists && !lstatSync(target).isFile()) throw new FixError(`Refusing to write ${f.newPath}: it is not a regular file`, "CONFLICT");
    if (!f.oldPath && exists) throw new FixError(`${f.newPath} already exists; the plan expected to create it`, "CONFLICT");
    if (f.oldPath && !exists) throw new FixError(`${f.newPath} does not exist; the plan expected to edit it`, "CONFLICT");
    const before = exists ? readCurrent(target, f.newPath) : null;
    let after;
    try {
      after = Buffer.from(applyHunks(before === null ? null : before.toString("utf-8"), f.hunks), "utf-8");
    } catch (e) {
      throw new FixError(`${f.newPath}: ${e.message}`, "CONFLICT");
    }
    writes.push({ path: f.newPath, target, before, after, created: !exists });
  }

  if (!opts.dryRun) {
    const done = [];
    try {
      for (const w of writes) {
        const { madeDir } = replaceFile(root, w.path, w.target, w.after, w.before);
        done.push({ ...w, madeDir });
      }
    } catch (e) {
      // All or nothing: put back what was written, newest first.
      for (const w of done.reverse()) {
        try {
          if (w.created) unlinkSync(w.target);
          else replaceFile(root, w.path, w.target, w.before, w.after);
          removeMadeDirs(w.target, w.madeDir);
        } catch { /* reported through the original error */ }
      }
      throw e;
    }
  }
  return {
    applied: !opts.dryRun,
    files: writes.map((w) => ({ path: w.path, created: w.created, before: w.before, sha256: sha256(w.after) })),
  };
}
