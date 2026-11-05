/**
 * `penthera hook`: a git pre-commit hook that runs the checks that matter most
 * before code leaves the laptop, on staged content only.
 *
 *   - secrets in staged files (lib/whitebox/secrets.js, AI provider keys included)
 *   - `penthera agents` rules on staged agent config (.mcp.json, CLAUDE.md, skills/, ...)
 *   - a staged package-lock.json: the capability diff against HEAD's lockfile,
 *     plus the license policy when penthera.policy.json has one
 *
 * Everything is read from the git index (what will be committed), never the
 * working tree, so a half-staged file is judged by its staged half. That
 * includes penthera.policy.json and penthera.suppress.json: an unstaged edit
 * to either cannot loosen the check. Staged symlinks are never followed.
 * Offline, no telemetry. Findings use the standard shape, so ids match a full
 * scan and penthera.suppress.json works here too.
 */
import { existsSync, lstatSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync, chmodSync } from "node:fs";
import { join, posix, resolve } from "node:path";
import { homedir, userInfo } from "node:os";
import { fileURLToPath } from "node:url";
import { git, gitSpawn, gitToplevel } from "../git.js";
import { withTempDir } from "../tmp.js";
import { findSecretsInText, isSecretScanTarget, isShapesOnlyFile, maskMatch } from "../whitebox/secrets.js";
import { loadPolicy, normalizePolicy, POLICY_FILE } from "../install/policy.js";
import { parseRepoSuppressions, REPO_SUPPRESS_FILE } from "../memory/repo-suppress.js";
import { findingId, suppressionCovers } from "../memory/views.js";
import { fingerprintFinding } from "../audit-loop.js";
import { npmCacheDir } from "../deps/source.js";
import { globToRegExp, isAtLeast, SEVERITIES } from "./policy.js";
import { parseJson } from "../json-text.js";

export const HOOK_MARKER = "# penthera-hook";
export const BACKUP_NAME = "pre-commit.pre-penthera";
// Staged files larger than this are not read. They never pass silently: by
// default they block the commit (policy "largeFiles": "warn" only warns).
// Large enough for the package-lock.json of a big monorepo.
export const MAX_BLOB_BYTES = 16 * 1024 * 1024;
const REGULAR = new Set(["100644", "100755"]);

// ── git plumbing ──────────────────────────────────────────────────────────

export function repoRoot(cwd) {
  const root = gitToplevel(cwd);
  if (!root) throw new Error(`Not inside a git repository: ${cwd}`);
  return root;
}

/**
 * Index entries this commit adds: added, copied, modified, renamed or
 * type-changed (a symlink that became a file). `{ path, mode, oid }`, read
 * NUL-separated so any byte in a name survives, with the object id of the
 * staged blob, so content is always read by id and never by a path git
 * might parse as revision syntax.
 */
export function stagedEntries(root) {
  const parts = git(root, ["diff", "--cached", "--raw", "-z", "--no-abbrev", "--no-renames", "--diff-filter=ACMRT"]).split("\0");
  const out = [];
  for (let i = 0; i < parts.length - 1; i += 2) {
    const m = /^:\d{6} (\d{6}) [0-9a-f]+ ([0-9a-f]+) [A-Z]\d*$/.exec(parts[i]);
    if (!m) throw new Error(`unexpected git diff --raw output: ${JSON.stringify(parts[i].slice(0, 200))}`);
    out.push({ path: parts[i + 1], mode: m[1], oid: m[2] });
  }
  return out;
}

function catFile(root, mode, oids) {
  const r = gitSpawn(root, ["cat-file", mode], { input: oids.map((o) => `${o}\n`).join("") });
  if (r.status !== 0) throw new Error(`git cat-file failed: ${String(r.stderr).trim()}`);
  return r.stdout;
}

/**
 * Read staged blobs by object id. Only regular files (mode 100644/100755):
 * a staged symlink or submodule has no content of its own to check.
 * @param {{ path: string, mode: string, oid: string }[]} entries
 * @returns {{ blobs: Map<string, Buffer>, oversized: { path: string, size: number }[] }}
 */
export function readStaged(root, entries, { maxBytes = MAX_BLOB_BYTES } = {}) {
  const blobs = new Map();
  const oversized = [];
  const files = entries.filter((e) => REGULAR.has(e.mode));
  if (!files.length) return { blobs, oversized };
  const sizes = catFile(root, "--batch-check", files.map((e) => e.oid)).toString().split("\n");
  const wanted = [];
  files.forEach((e, i) => {
    const m = /^([0-9a-f]+) blob (\d+)$/.exec(sizes[i] || "");
    if (!m || m[1] !== e.oid) throw new Error(`git cat-file: staged blob for ${JSON.stringify(e.path)} not found`);
    const size = Number(m[2]);
    if (size > maxBytes) oversized.push({ path: e.path, size });
    else wanted.push(e);
  });
  if (!wanted.length) return { blobs, oversized };
  const buf = catFile(root, "--batch", wanted.map((e) => e.oid));
  let pos = 0;
  for (const e of wanted) {
    const nl = buf.indexOf(10, pos);
    const m = nl === -1 ? null : /^([0-9a-f]+) blob (\d+)$/.exec(buf.subarray(pos, nl).toString());
    if (!m || m[1] !== e.oid) throw new Error(`git cat-file: unexpected output for ${JSON.stringify(e.path)}`);
    const size = Number(m[2]);
    blobs.set(e.path, buf.subarray(nl + 1, nl + 1 + size));
    pos = nl + 1 + size + 1;
  }
  return { blobs, oversized };
}

// ── Checks ────────────────────────────────────────────────────────────────

function checkSecrets(files, blobs) {
  const findings = [];
  for (const path of files) {
    if (!isSecretScanTarget(path)) continue;
    const buf = blobs.get(path);
    if (!buf) continue;
    // Read as text even when it holds NUL bytes: a NUL does not stop a key
    // from being a key, and the extension already says this is a text file.
    const text = buf.toString("utf-8");
    const hits = findSecretsInText(text, { shapesOnly: isShapesOnlyFile(path), path }).sort((a, b) => a.index - b.index);
    let line = 1;
    let at = 0;
    for (const hit of hits) {
      for (; at < hit.index; at++) if (text.charCodeAt(at) === 10) line++;
      // Same title/url/category/source as the repo scan, so finding ids match.
      findings.push({
        severity: hit.severity,
        title: `${hit.name} in source`,
        description: `Possible secret in \`${path}\`: \`${maskMatch(hit.match)}\``,
        url: path,
        line,
        evidence: maskMatch(hit.match),
        category: "secrets",
        source: "secret-scan",
      });
    }
  }
  return findings;
}

const AGENT_FILES = new Set([
  "AGENTS.md", "CLAUDE.md", "CLAUDE.local.md", "GEMINI.md", ".cursorrules", ".windsurfrules", ".mcp.json", ".github/copilot-instructions.md",
  ".vscode/mcp.json", ".vscode/tasks.json", ".vscode/settings.json", ".gemini/settings.json",
]);
const AGENT_DIRS = [".claude/", ".cursor/", ".agents/", ".codex/", ".clinerules/", ".claude-plugin/", ".github/instructions/", ".roo/", "skills/", "plugins/"];

/** Is this repo path agent configuration that `penthera agents` reads? */
export function isAgentConfig(path) {
  return AGENT_FILES.has(path) || AGENT_DIRS.some((d) => path.startsWith(d));
}

/**
 * Agent rules on the staged view of the agent config. The whole agent config
 * in the index is checked out to a temp folder (a skill is judged as a folder,
 * not file by file); only findings that touch a staged path are kept.
 */
async function checkAgents(root, staged) {
  const touched = staged.filter(isAgentConfig);
  if (!touched.length) return { findings: [], files: 0 };
  // Regular files only (mode 100644/100755): a staged symlink would be checked
  // out as a symlink and the scan would read whatever it points at.
  const all = git(root, ["ls-files", "-z", "--cached", "--stage"]).split("\0")
    .map((l) => /^(\d{6}) [0-9a-f]+ \d\t(.*)$/s.exec(l))
    .filter((m) => m && (m[1] === "100644" || m[1] === "100755") && isAgentConfig(m[2]))
    .map((m) => m[2]);
  return withTempDir("penthera-hook-", async (tmp) => {
    const r = gitSpawn(root, ["checkout-index", "-z", "--stdin", `--prefix=${tmp}/`], { input: all.join("\0") });
    if (r.status !== 0) throw new Error(`git checkout-index failed: ${String(r.stderr).trim()}`);
    const { scanAgents } = await import("../agents/index.js");
    const result = await scanAgents(tmp, { lockPath: join(tmp, ".penthera-hook-no-lock") });
    const relates = (url) => touched.some((s) => url === s || s.startsWith(`${url}/`) || url.startsWith(`${s}/`));
    const findings = result.findings
      .filter((f) => !String(f.templateId).startsWith("agents/lock-") && relates(f.url))
      .map((f) => {
        const m = /\(line (\d+)\)/.exec(f.description || "");
        return m ? { ...f, line: Number(m[1]) } : f;
      });
    return { findings, files: touched.length };
  });
}

const EMPTY_LOCK = { lockfileVersion: 3, packages: {} };

/**
 * npm caches the hook reads package code from. npm exports a project .npmrc's `cache=`
 * as npm_config_cache when it runs the hook (husky, lefthook, npx), so a repo could point
 * that at an empty folder and hide the code it adds. The user's own cache is always read
 * too. A cache can't hand over other code: each file must match the lockfile's integrity.
 */
export function hookCacheDirs(env = process.env, home = accountHome()) {
  return [...new Set([npmCacheDir(env), join(home, ".npm")])];
}

/** The user's home from the system account: HOME is the environment's, so the repo's to set. */
function accountHome() {
  try { return userInfo().homedir || homedir(); } catch { return homedir(); }
}

/** Capability diff (and license policy) for each staged lockfile, against HEAD. */
async function checkLockfiles(root, staged, blobs, { licensePolicy }) {
  const locks = staged.filter((p) => ["package-lock.json", "npm-shrinkwrap.json"].includes(posix.basename(p)));
  if (!locks.length) return { findings: [], files: 0 };
  const { scanDeps } = await import("../deps/index.js");
  const findings = [];
  for (const path of locks) {
    const buf = blobs.get(path);
    if (!buf) continue;
    let lock;
    try { lock = parseJson(buf.toString("utf-8")); } catch (e) {
      findings.push({ severity: "high", title: `${path} is not valid JSON`, description: e.message, url: path, category: "dependency-risk", source: "deps-scan" });
      continue;
    }
    let baseLock = EMPTY_LOCK;
    try { baseLock = parseJson(git(root, ["show", `HEAD:${path}`])); } catch { /* new lockfile or first commit */ }
    const dir = posix.dirname(path);
    const result = await scanDeps(join(root, dir), { lock, baseLock, baseLabel: "HEAD", changedOnly: true, licensePolicy, cacheDir: hookCacheDirs() });
    const prefix = dir === "." ? "" : `${dir}/`;
    for (const f of result.findings) findings.push({ ...f, url: f.url ? `${prefix}${f.url}` : path });
  }
  return { findings, files: locks.length };
}

// ── Run ───────────────────────────────────────────────────────────────────

function suppressedBy(entries, f) {
  if (!entries.length) return null;
  const id = findingId(f);
  const fp = fingerprintFinding(f);
  return entries.find((e) => (e.id === id || e.fingerprint === fp) && suppressionCovers(e, f)) || null;
}

const bySeverity = (a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || String(a.url).localeCompare(String(b.url)) || (a.line || 0) - (b.line || 0);

/** One regular file as staged (stage 0), or null when it is not in the index. */
function stagedBlob(root, path) {
  const line = git(root, ["--literal-pathspecs", "ls-files", "-s", "-z", "--", path]).split("\0")
    .map((l) => /^(\d{6}) ([0-9a-f]+) 0\t(.*)$/s.exec(l))
    .find((m) => m && m[3] === path);
  if (!line) return null;
  const { blobs, oversized } = readStaged(root, [{ path, mode: line[1], oid: line[2] }]);
  if (oversized.length) throw new Error(`${path} (staged) is too large to read`);
  return blobs.get(path) || null;
}

/** The policy: an explicit --policy file, else penthera.policy.json as staged, else defaults. */
function stagedPolicy(root, explicitPath) {
  if (explicitPath) return loadPolicy(root, explicitPath);
  const buf = stagedBlob(root, POLICY_FILE);
  if (!buf) return { policy: normalizePolicy({}), path: null };
  let raw;
  try {
    raw = parseJson(buf.toString("utf-8"));
  } catch (e) {
    throw new Error(`${POLICY_FILE} (staged): ${e.message}`);
  }
  return { policy: normalizePolicy(raw, `${POLICY_FILE} (staged)`), path: join(root, POLICY_FILE) };
}

/**
 * Check what is staged. Never writes to the repo.
 * @param {string} cwd anywhere inside the repo
 * @param {{ policyPath?: string, now?: string, maxBlobBytes?: number }} opts
 * @returns {Promise<{ root, staged, checked, blocking, below, suppressed, blockOn, policyPath, warnings, duration }>}
 */
export async function runHook(cwd, opts = {}) {
  const started = Date.now();
  const root = repoRoot(cwd);
  const { policy, path: policyPath } = stagedPolicy(root, opts.policyPath || null);
  const { blockOn, checks, ignore, largeFiles } = policy.hook;
  const ignored = ignore.map(globToRegExp);
  const entries = stagedEntries(root).filter((e) => !ignored.some((re) => re.test(e.path)));
  const staged = entries.map((e) => e.path);

  const isLock = (p) => /(^|\/)(package-lock|npm-shrinkwrap)\.json$/.test(p);
  const wantBlobs = entries.filter((e) => (checks.secrets && isSecretScanTarget(e.path)) || (checks.deps && isLock(e.path)));
  const { blobs, oversized } = readStaged(root, wantBlobs, { maxBytes: opts.maxBlobBytes ?? MAX_BLOB_BYTES });
  const warnings = [];
  const unchecked = [];
  for (const o of oversized) {
    const limit = `${Math.round((opts.maxBlobBytes ?? MAX_BLOB_BYTES) / 1024 / 1024 * 10) / 10} MB`;
    warnings.push(`${o.path} is ${o.size} bytes, over the ${limit} limit, so it was not checked${largeFiles === "block" ? " (this blocks the commit)" : ""}`);
    if (largeFiles === "block") {
      unchecked.push({
        severity: "critical",
        title: "Staged file too large to check",
        description: `\`${o.path}\` is ${o.size} bytes, over the ${limit} the hook reads, so it could hold a secret nobody checked.`,
        url: o.path,
        category: "unchecked",
        source: "hook",
      });
    }
  }

  const secrets = checks.secrets ? [...checkSecrets(staged, blobs), ...unchecked] : unchecked;
  const agents = checks.agents ? await checkAgents(root, staged) : { findings: [], files: 0 };
  const deps = checks.deps ? await checkLockfiles(root, staged, blobs, { licensePolicy: checks.licenses ? policy.licenses : null }) : { findings: [], files: 0 };

  const supBuf = stagedBlob(root, REPO_SUPPRESS_FILE);
  const sup = supBuf ? parseRepoSuppressions(supBuf, { now: opts.now }) : { entries: [], warnings: [] };
  for (const f of [POLICY_FILE, REPO_SUPPRESS_FILE]) {
    if (f === POLICY_FILE && opts.policyPath) continue;
    const disk = join(root, f);
    const staged = f === POLICY_FILE ? policyPath : supBuf;
    if (existsSync(disk) && !staged) sup.warnings.push(`${f} is not staged, so this check ignores it (git add it to apply it)`);
  }
  const all = [...secrets, ...agents.findings, ...deps.findings].map((f) => ({ ...f, id: findingId(f) }));
  const suppressed = [];
  const kept = [];
  for (const f of all) {
    const s = suppressedBy(sup.entries, f);
    if (s) suppressed.push({ ...f, suppression: { reason: s.reason } });
    else kept.push(f);
  }
  kept.sort(bySeverity);
  return {
    root,
    staged: staged.length,
    checked: { secrets: checks.secrets ? staged.filter(isSecretScanTarget).length : 0, agents: agents.files, lockfiles: deps.files },
    blockOn,
    policyPath,
    blocking: kept.filter((f) => isAtLeast(f.severity, blockOn)),
    below: kept.filter((f) => !isAtLeast(f.severity, blockOn)),
    suppressed,
    warnings: [...warnings, ...sup.warnings],
    duration: Date.now() - started,
  };
}

/** One short "how to fix" line per finding. */
export function fixHint(f) {
  if (f.category === "secrets") return "Load it from an env var or secret store and unstage the file; rotate it if it was ever pushed or shared.";
  if (f.category === "license") return `Replace ${f.package}, or add it to "allowPackages" in the licenses section of penthera.policy.json.`;
  if (f.category === "dependency-risk") return `Review it before committing the lockfile: \`penthera deps --base HEAD -v\` shows the evidence.`;
  if (f.category === "unchecked") return `If it holds no secrets, add it to "ignore" (or set "largeFiles": "warn") in the hook section of penthera.policy.json.`;
  return firstSentence(f.description) || "See `penthera agents` for details.";
}

/**
 * The description's first sentence, without a trailing `[...]` tag or a
 * `(line N)` note. Only the first line, capped, is looked at, and nothing
 * here backtracks: descriptions quote agent config, which anyone can write.
 */
function firstSentence(description) {
  let s = String(description || "");
  const nl = s.indexOf("\n");
  s = (nl === -1 ? s : s.slice(0, nl)).slice(0, 2000);
  if (s.endsWith("]")) {
    const open = s.lastIndexOf("[");
    if (open !== -1 && !s.slice(open, -1).includes("]")) s = s.slice(0, open).trimEnd();
  }
  const line = /\(line \d+\)/.exec(s);
  if (line) s = s.slice(0, line.index).trimEnd() + s.slice(line.index + line[0].length);
  const stop = /\.\s/.exec(s);
  return stop ? s.slice(0, stop.index + 1) : s;
}

// ── Install / uninstall ───────────────────────────────────────────────────

const BIN = fileURLToPath(new URL("../../bin/penthera.js", import.meta.url));
const VERSION = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf-8")).version;
const sq = (s) => `'${String(s).replace(/'/g, "'\\''")}'`;

/**
 * The pre-commit script. It runs the Penthera that installed it; when that copy
 * is gone (an npx cache cleaned, a version change), a global `penthera`, then
 * the same version through npx, pinned so a hook never upgrades itself. Only
 * when none of them can run does it skip the check, with a warning.
 *
 * The repo being committed can shape this environment (direnv, a project .npmrc), so
 * the script drops NODE_OPTIONS and NODE_PATH before anything runs, since they would load
 * the repo's code into Node. A global `penthera` runs only when its real path is outside
 * the repo, and through the installing Node. npx runs from /, with every npm_config_*
 * dropped, npm's own registry and the account's own home and cache, so no project .npmrc
 * steers it, and `--repo` names the repo to check.
 */
export function hookScript({ node = process.execPath, bin = BIN, version = VERSION } = {}) {
  const pkg = sq(`penthera@${version}`);
  return `#!/bin/sh
${HOOK_MARKER}: pre-commit hook installed by \`penthera hook install\`.
# Remove it with \`penthera hook uninstall\`, which restores any hook it replaced.
# Skip it for one commit with \`git commit --no-verify\`.
# The repo being committed can shape this environment: nothing it sets may load its code.
unset NODE_OPTIONS NODE_PATH
hook_dir=$(dirname "$0")
if [ -x "$hook_dir/${BACKUP_NAME}" ]; then
  "$hook_dir/${BACKUP_NAME}" "$@" || exit $?
fi
node=${sq(node)}
top=$(git rev-parse --show-toplevel 2>/dev/null || pwd -P)
if [ -f ${sq(bin)} ] && [ -x "$node" ]; then
  exec "$node" ${sq(bin)} hook run
fi
# A global penthera, by its real path, and only from outside the repo.
global=$(command -v penthera 2>/dev/null || true)
if [ -n "$global" ] && [ -x "$node" ]; then
  global=$("$node" -e 'process.stdout.write(require("fs").realpathSync(process.argv[1]))' "$global" 2>/dev/null || true)
fi
case "$global" in "$top"/*) global="" ;; esac
case "$global" in
  "") ;;
  *.js) [ -x "$node" ] && exec "$node" "$global" hook run ;;
  *) exec "$global" hook run ;;
esac
if command -v npx >/dev/null 2>&1; then
  # Not from inside the repo, and with nothing the repo's environment says about npm.
  for v in $(env | sed -n 's/^\\([Nn][Pp][Mm]_[Cc][Oo][Nn][Ff][Ii][Gg]_[A-Za-z0-9_]*\\)=.*/\\1/p'); do unset "$v"; done
  user=$(id -un 2>/dev/null || true)
  account_home=$(eval "printf '%s' ~$user" 2>/dev/null || true)
  [ -d "$account_home" ] || account_home=/nonexistent
  cd /
  if HOME="$account_home" npx --registry=https://registry.npmjs.org/ --cache="$account_home/.npm" -y ${pkg} --version >/dev/null 2>&1; then
    HOME="$account_home" exec npx --registry=https://registry.npmjs.org/ --cache="$account_home/.npm" -y ${pkg} hook run --repo "$top"
  fi
fi
echo "penthera: WARNING: pre-commit check SKIPPED. The Penthera that installed this hook is gone and ${pkg} could not run through npx (offline?). Install it with npm install -g penthera, then run penthera hook install." >&2
exit 0
`;
}

/** Where git looks for hooks (honours core.hooksPath and worktrees). */
export function hooksDir(root) {
  // raw: the repo's real core.hooksPath, which the safe config overrides.
  return resolve(root, git(root, ["rev-parse", "--git-path", "hooks"], { raw: true }).trim());
}

function hooksPathSetting(root) {
  try { return git(root, ["config", "--get", "core.hooksPath"], { raw: true }).trim() || null; } catch { return null; }
}

/** lstat, or null when nothing is there (a dangling symlink is something). */
function lstatOrNull(path) {
  try { return lstatSync(path); } catch (e) { if (e.code === "ENOENT") return null; throw e; }
}

// Ours only when it is a regular file with our marker: a symlink is never
// ours, even when it points at a file that carries the marker.
const isOurs = (path) => !!lstatOrNull(path)?.isFile() && readFileSync(path, "utf-8").includes(HOOK_MARKER);

/**
 * Write .git/hooks/pre-commit. An existing hook that is not ours is kept as
 * pre-commit.pre-penthera and runs first.
 * @returns {{ path, chained: string|null, updated: boolean }}
 */
export function installHook(cwd, { force = false, script = hookScript() } = {}) {
  const root = repoRoot(cwd);
  const custom = hooksPathSetting(root);
  if (custom && !force) {
    const err = new Error(`core.hooksPath is set to "${custom}" (husky, lefthook or similar manage hooks here). Add \`penthera hook run\` to that tool's pre-commit config instead, or rerun with --force to write ${join(custom, "pre-commit")}.`);
    err.code = "HOOKS_PATH";
    throw err;
  }
  const dir = hooksDir(root);
  const path = join(dir, "pre-commit");
  const backup = join(dir, BACKUP_NAME);
  let updated = false;
  const st = lstatOrNull(path);
  if (st) {
    // Anything that is not our own regular file (another hook, a symlink to a
    // shared or not-yet-created hook) is moved aside as it is, never written through.
    if (isOurs(path)) {
      updated = true;
      unlinkSync(path);
    } else if (st.isDirectory()) throw new Error(`${path} is a directory. Move it away, then run \`penthera hook install\` again.`);
    else if (lstatOrNull(backup)) throw new Error(`Both ${path} and ${backup} exist. Merge them by hand, then run \`penthera hook install\` again.`);
    else renameSync(path, backup);
  }
  mkdirSync(dir, { recursive: true });
  // "wx": create a new file, and fail rather than follow anything that
  // appeared at this path in the meantime.
  writeFileSync(path, script, { flag: "wx", mode: 0o755 });
  chmodSync(path, 0o755);
  return { path, chained: lstatOrNull(backup) ? backup : null, updated };
}

/**
 * Remove our hook and put back the one it replaced.
 * @returns {{ path, removed: boolean, restored: string|null }}
 */
export function uninstallHook(cwd) {
  const root = repoRoot(cwd);
  const dir = hooksDir(root);
  const path = join(dir, "pre-commit");
  const backup = join(dir, BACKUP_NAME);
  if (!lstatOrNull(path)) return { path, removed: false, restored: null };
  if (!isOurs(path)) throw new Error(`${path} was not installed by penthera; left untouched.`);
  unlinkSync(path);
  if (lstatOrNull(backup)) {
    renameSync(backup, path);
    return { path, removed: true, restored: path };
  }
  return { path, removed: true, restored: null };
}
