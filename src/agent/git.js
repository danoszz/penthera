/**
 * The agent loop's only way to run git: an allow-list of local subcommands.
 *
 * The loop branches, commits and reverts, and nothing else. Anything that can
 * reach a remote (push, fetch, pull, remote, clone, ls-remote, submodule, ...)
 * is not on the list, so it is refused before a process is spawned. On top of
 * that every call runs with:
 *   - protocol.allow=never, so no transport works even if a subcommand tried one;
 *   - GIT_NO_LAZY_FETCH=1, so a partial clone cannot fetch missing objects;
 *   - core.hooksPath=/dev/null, core.fsmonitor=false and commit --no-verify, so
 *     the scanned repo's hooks never run (a repo can ship hooks that do anything);
 *   - signing off (commit/tag.gpgsign=false, every gpg.*.program and
 *     gpg.ssh.defaultKeyCommand overridden), so a repo cannot name a signer;
 *   - no attributes from the user's attributes file (core.attributesFile=/dev/null)
 *     or, on git >= 2.40, from the work tree (--attr-source=<empty tree>), and
 *     every filter driver the config defines emptied, so no clean/smudge/process
 *     filter runs whatever selects it ($GIT_DIR/info/attributes is always read);
 *   - GIT_LITERAL_PATHSPECS=1, so a file named `[id].js` or `:(glob)x` is only
 *     ever that file;
 *   - GIT_TERMINAL_PROMPT=0 and an empty credential helper, so nothing asks for
 *     or hands out credentials.
 * Subcommands that write (checkout, add, commit, reset) also need git >= 2.31
 * (for GIT_CONFIG_KEY_n, which empties the filters) and are refused while the
 * repo's own config sets any filter.*, gpg.*, include.* or includeIf.* key.
 */
import { execFileSync } from "node:child_process";
import { safeEnv, SAFE_CONFIG } from "../../lib/git.js";

export const ALLOWED_SUBCOMMANDS = Object.freeze([
  "rev-parse", "symbolic-ref", "status", "diff", "log", "show-ref", "checkout", "add", "commit", "config",
  "check-ignore", "reset", "branch",
]);

/** Subcommands that change the work tree, the index or refs. */
export const WRITE_SUBCOMMANDS = Object.freeze(["checkout", "add", "commit", "reset", "branch"]);

/** GIT_CONFIG_COUNT/KEY_n/VALUE_n arrived in git 2.31: below it, filters cannot be emptied. */
export const MIN_WRITE_VERSION = Object.freeze([2, 31]);

/** --attr-source arrived in git 2.40; older git still reads the work tree's .gitattributes. */
export const ATTR_SOURCE_VERSION = Object.freeze([2, 40]);

/** The empty tree: as an attribute source it means "no .gitattributes anywhere". */
export const EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";

/** Arguments that would make an allowed subcommand reach outside the repo. */
const FORBIDDEN_ARGS = [
  /^-c$/, /^--config/, /^--git-dir/, /^--work-tree/, /^--exec-path/, /^--upload-pack/, /^--receive-pack/,
  /^--exec\b/, /^--recurse-submodules/, /^--remote/, /:\/\//, /^[^/\s@]+@[^/\s]+:/,
];

export class GitPolicyError extends Error {
  constructor(message, code = "GIT_FORBIDDEN") {
    super(message);
    this.name = "GitPolicyError";
    this.code = code;
  }
}

/** Throws GitPolicyError unless `args` is a local-only git invocation. */
export function assertAllowed(args) {
  if (!Array.isArray(args) || args.length === 0) throw new GitPolicyError("git: no subcommand");
  const [sub, ...rest] = args;
  if (!ALLOWED_SUBCOMMANDS.includes(sub)) {
    throw new GitPolicyError(`git ${sub} is not allowed: the agent loop only runs local git (${ALLOWED_SUBCOMMANDS.join(", ")})`);
  }
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (typeof a !== "string") throw new GitPolicyError("git: arguments must be strings");
    if (sub === "commit" && rest[i - 1] === "-m") continue; // a commit message is text, not an option
    if (FORBIDDEN_ARGS.some((re) => re.test(a))) throw new GitPolicyError(`git ${sub}: argument ${JSON.stringify(a)} is not allowed`);
  }
  // `branch` only removes a merged branch: the loop's own, when it stayed empty.
  if (sub === "branch" && !(rest.length === 2 && rest[0] === "-d" && !rest[1].startsWith("-"))) {
    throw new GitPolicyError("git branch: only `branch -d <name>` is allowed");
  }
  // `config` may only read one key; it never writes repo or global config.
  if (sub === "config" && !(rest.length === 2 && rest[0] === "--get" && /^[\w.-]+$/.test(rest[1]))) {
    throw new GitPolicyError("git config: only `config --get <key>` is allowed");
  }
  // `reset` may only unstage paths: no --hard, no commit-ish.
  if (sub === "reset" && !(rest.length >= 3 && rest[0] === "-q" && rest[1] === "--")) {
    throw new GitPolicyError("git reset: only `reset -q -- <paths>` is allowed");
  }
  return true;
}


/** "git version 2.43.0.windows.1" -> [2, 43], or null. */
export function parseGitVersion(text) {
  const m = /git version (\d+)\.(\d+)/.exec(String(text || ""));
  return m ? [Number(m[1]), Number(m[2])] : null;
}

const atLeast = (v, min) => Boolean(v) && (v[0] > min[0] || (v[0] === min[0] && v[1] >= min[1]));

const versionCache = new WeakMap(); // exec -> [major, minor] | null

/** How to get past a GIT_UNSAFE_CONFIG refusal. */
const WAY_FORWARD = "Move the setting to your global config (`git config --global <key> ...`) and remove it here (`git config --unset <key>`), or apply fixes by hand from the report (`penthera fix --plan` prints each diff). Scans and reports still work.";

/** Keys in the repo's own config that make a write unsafe. */
const UNSAFE_REPO_KEY = /^(filter|gpg)\.|^include(if)?\./i;
const FILTER_KEY = /^filter\.(.+)\.(clean|smudge|process|required)$/i;

/**
 * Parse `git config --show-scope -z --get-regexp` output into [{ scope, key }].
 * Each record is "scope\0key\nvalue\0" (or "scope\0key\0" for a bare boolean).
 */
export function parseScopedConfig(out) {
  const parts = String(out || "").split("\0");
  const entries = [];
  for (let i = 0; i + 1 < parts.length; i += 2) {
    const scope = parts[i];
    const nl = parts[i + 1].indexOf("\n");
    entries.push({ scope, key: nl < 0 ? parts[i + 1] : parts[i + 1].slice(0, nl) });
  }
  return entries;
}

/**
 * Bind a git runner to a work tree.
 *
 * @param {string} cwd
 * @param {{ exec?: typeof execFileSync, env?: object }} [opts] - exec is injectable for tests
 * @returns {{ run(...args: string[]): string, tryRun(...args: string[]): string|null }}
 */
export function createGit(cwd, { exec = execFileSync, env = process.env } = {}) {
  const baseEnv = { ...safeEnv(env), GIT_OPTIONAL_LOCKS: "0", GIT_LITERAL_PATHSPECS: "1" };
  const opts = (extra = {}) => ({
    cwd, encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"], maxBuffer: 32 * 1024 * 1024, ...extra,
  });

  const version = () => {
    if (!versionCache.has(exec)) {
      let v = null;
      try { v = parseGitVersion(exec("git", ["--version"], opts({ env: baseEnv, timeout: 10_000 }))); } catch { v = null; }
      versionCache.set(exec, v);
    }
    return versionCache.get(exec);
  };

  // Read the config git will see (includes followed: reading config runs nothing).
  // Exit 1 means no key matched; anything else fails closed.
  const probe = () => {
    let out;
    try {
      out = exec("git", ["config", "--show-scope", "-z", "--get-regexp", "^(filter|gpg|include|includeif)\\."],
        opts({ env: baseEnv, timeout: 10_000 }));
    } catch (e) {
      if (e?.status === 1) out = "";
      else throw new GitPolicyError(`git: could not read this repo's git config safely (${String(e?.stderr || e?.message || e).trim().split("\n")[0]})`, "GIT_UNSAFE_CONFIG");
    }
    const entries = parseScopedConfig(out);
    const filters = new Set();
    for (const { key } of entries) {
      const m = FILTER_KEY.exec(key);
      if (m) filters.add(m[1]);
    }
    const repoKeys = entries.filter((e) => (e.scope === "local" || e.scope === "worktree") && UNSAFE_REPO_KEY.test(e.key)).map((e) => e.key);
    return { filters: [...filters], repoKeys: [...new Set(repoKeys)] };
  };
  let probed = null;

  // Every filter driver any config defines is emptied for this call, through
  // GIT_CONFIG_KEY_n (a driver name may contain "=", which `-c` cannot carry).
  const envFor = (filters) => {
    if (!filters.length) return baseEnv;
    const childEnv = { ...baseEnv };
    let n = /^\d+$/.test(String(env.GIT_CONFIG_COUNT || "")) ? Number(env.GIT_CONFIG_COUNT) : 0;
    for (const name of filters) {
      for (const [k, v] of [["clean", ""], ["smudge", ""], ["process", ""], ["required", "false"]]) {
        childEnv[`GIT_CONFIG_KEY_${n}`] = `filter.${name}.${k}`;
        childEnv[`GIT_CONFIG_VALUE_${n}`] = v;
        n++;
      }
    }
    childEnv.GIT_CONFIG_COUNT = String(n);
    return childEnv;
  };

  const run = (...args) => {
    assertAllowed(args);
    const sub = args[0];
    const v = version();
    if (WRITE_SUBCOMMANDS.includes(sub)) {
      probed = probe(); // fresh before every write
      if (probed.repoKeys.length) {
        const keys = probed.repoKeys.slice(0, 5).join(", ") + (probed.repoKeys.length > 5 ? ", ..." : "");
        throw new GitPolicyError(
          `penthera won't write in this repo: its own git config sets ${keys}, and repo-level git config can run programs during checkout and commit. ${WAY_FORWARD.replaceAll("<key>", probed.repoKeys[0])}`,
          "GIT_UNSAFE_CONFIG",
        );
      }
      if (!atLeast(v, MIN_WRITE_VERSION)) {
        throw new GitPolicyError(
          `penthera won't write in this repo: git ${v ? v.join(".") : "(unknown version)"} is older than ${MIN_WRITE_VERSION.join(".")}, the minimum it needs to switch off filters the repo configures. Upgrade git, or apply fixes by hand from the report (\`penthera fix --plan\` prints each diff). Scans and reports still work.`,
          "GIT_TOO_OLD",
        );
      }
    } else if (!probed) {
      probed = probe();
    }
    if (probed.filters.length && !atLeast(v, MIN_WRITE_VERSION)) {
      throw new GitPolicyError(`git: this repo's config defines filter drivers, and git older than ${MIN_WRITE_VERSION.join(".")} cannot switch them off. Upgrade git.`, "GIT_TOO_OLD");
    }
    const pre = atLeast(v, ATTR_SOURCE_VERSION) ? [...SAFE_CONFIG, `--attr-source=${EMPTY_TREE}`] : SAFE_CONFIG;
    const full = sub === "commit" ? ["commit", "--no-verify", ...args.slice(1)] : args;
    let childEnv = envFor(probed.filters);
    // check-ignore takes paths, not pathspecs, and rejects the literal flag; callers pass "./<path>".
    if (sub === "check-ignore") childEnv = { ...childEnv, GIT_LITERAL_PATHSPECS: "0" };
    return exec("git", [...pre, ...full], opts({ env: childEnv }));
  };
  const tryRun = (...args) => {
    try {
      return run(...args);
    } catch (e) {
      // A forbidden call is a bug in the caller; an unreadable config or an old git is just "no answer".
      if (e instanceof GitPolicyError && e.code === "GIT_FORBIDDEN") throw e;
      return null;
    }
  };
  return { run, tryRun };
}

/**
 * Parse `git status --porcelain=v1 -z` into [{ xy, path }]. Paths are taken
 * verbatim (no C-quoting in -z mode), made relative to `prefix` when the repo
 * is a subdirectory of the work tree; a rename lists both of its paths.
 */
export function parseStatusZ(out, prefix = "") {
  const parts = String(out || "").split("\0");
  const entries = [];
  const rel = (p) => (prefix && p.startsWith(prefix) ? p.slice(prefix.length) : p);
  for (let i = 0; i < parts.length; i++) {
    const e = parts[i];
    if (e.length < 4) continue;
    const xy = e.slice(0, 2);
    entries.push({ xy, path: rel(e.slice(3)) });
    if (/[RC]/.test(xy) && i + 1 < parts.length) entries.push({ xy, path: rel(parts[++i]) });
  }
  return entries;
}

/**
 * Penthera's own untracked scan reports (reports/, where `penthera ui` and a
 * scan write them) are not the user's work in progress: a fix commits only the
 * files it changes, so they can stay.
 */
export function isOwnReport({ xy, path }) {
  return xy === "??" && path.startsWith("reports/");
}
