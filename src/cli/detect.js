/**
 * What `penthera init` finds in a project before it asks anything. Read-only:
 * files under the project, `git` plumbing, and TCP connects to 127.0.0.1 / ::1.
 */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { readRepoFile } from "../../lib/fs-safe.js";

/** A file of the project: a regular file inside it, up to 1 MiB. */
const readProjectFile = (root, path) => readRepoFile(path, { root, maxBytes: 1024 * 1024 });
import { join } from "node:path";
import { createConnection } from "node:net";
import { detectProjectFramework } from "../../lib/whitebox/frameworks.js";
import { HOOK_MARKER } from "../../lib/hook/index.js";
import { git as runGit, gitToplevel } from "../../lib/git.js";

export const DEV_PORTS = [3000, 5173, 8000, 8080];
export const NPM_LOCKFILES = ["package-lock.json", "npm-shrinkwrap.json"];
export const PY_LOCKFILES = ["uv.lock", "poetry.lock", "pdm.lock", "Pipfile.lock", "requirements.txt"];
export const AGENT_CONFIG = [".mcp.json", ".claude", ".cursor", "CLAUDE.md", "AGENTS.md", "skills"];

function git(cwd, args, opts) {
  return runGit(cwd, args, { stdio: ["ignore", "pipe", "ignore"], ...opts }).trim();
}

/**
 * The git toplevel for `cwd`, or null outside a repo (or without git). Git
 * prints forward slashes on Windows (D:/a/app); resolve() makes it a native
 * path so prefix checks against resolve()d paths hold.
 */
export function gitRoot(cwd) {
  return gitToplevel(cwd);
}

/** True when something accepts a TCP connection on host:port within `timeout` ms. */
function listening(host, port, timeout) {
  return new Promise((resolve) => {
    const sock = createConnection({ host, port });
    const done = (ok) => { sock.destroy(); resolve(ok); };
    // On a starved machine the timer and a connect that already completed can
    // be ready in the same loop turn, and timers run first. setImmediate runs
    // after pending I/O, so a connection made within the deadline still wins.
    sock.setTimeout(timeout, () => setImmediate(() => done(false)));
    sock.once("connect", () => done(true));
    sock.once("error", () => done(false));
  });
}

/**
 * The first dev-server port that answers on localhost. Vite and others bind
 * ::1 only, so both loopback addresses are tried. Never contacts another host.
 * @returns {Promise<string|null>} e.g. "http://localhost:3000"
 */
export async function detectDevServer(ports = DEV_PORTS, timeout = 300) {
  const hits = await Promise.all(ports.map(async (port) =>
    (await listening("127.0.0.1", port, timeout)) || (await listening("::1", port, timeout)) ? port : null));
  const port = hits.find((p) => p != null);
  return port == null ? null : `http://localhost:${port}`;
}

/** Ports to probe: PENTHERA_INIT_PORTS (comma list, "" for none) overrides DEV_PORTS. */
export function portsFromEnv(env = process.env) {
  if (env.PENTHERA_INIT_PORTS == null) return DEV_PORTS;
  return env.PENTHERA_INIT_PORTS.split(",").map((p) => Number(p.trim())).filter((p) => Number.isInteger(p) && p > 0 && p < 65536);
}

function hookInstalled(root) {
  try {
    const path = join(git(root, ["rev-parse", "--path-format=absolute", "--git-path", "hooks"], { raw: true }), "pre-commit");
    return existsSync(path) && readFileSync(path, "utf-8").includes(HOOK_MARKER);
  } catch { return false; }
}

/** Workflow files under .github/workflows that already use the Penthera action or CLI. */
function pentheraWorkflows(root) {
  const dir = join(root, ".github", "workflows");
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => /\.ya?ml$/i.test(f))
    .filter((f) => {
      try { return /danoszz\/penthera|\bpenthera\b/.test(readProjectFile(root, join(dir, f))); } catch { return false; }
    })
    .map((f) => `.github/workflows/${f}`);
}

function reportsIgnored(root, isGit) {
  if (isGit) {
    try { git(root, ["check-ignore", "-q", "reports/penthera.json"]); return true; } catch { return false; }
  }
  try {
    return readProjectFile(root, join(root, ".gitignore")).split(/\r?\n/).some((l) => /^\/?reports\/?$/.test(l.trim()));
  } catch { return false; }
}

function hasCode(root) {
  try {
    return readdirSync(root).some((f) => {
      if (f === "node_modules" || f.startsWith(".")) return false;
      if (/\.(js|ts|mjs|cjs|jsx|tsx|py|go|rb|php|java|rs)$/.test(f)) return true;
      return ["src", "app", "pages", "api", "lib", "server"].includes(f) && statSync(join(root, f)).isDirectory();
    }) || existsSync(join(root, "package.json"));
  } catch { return false; }
}

/**
 * Everything the wizard shows under "Found".
 * @param {string} cwd
 * @param {{ ports?: number[] }} [opts]
 */
export async function detectProject(cwd, opts = {}) {
  const top = gitRoot(cwd);
  const root = top || cwd;
  const isGit = !!top;
  let clean = null;
  let branch = null;
  if (isGit) {
    try { clean = git(root, ["status", "--porcelain"]) === ""; } catch { clean = null; }
    try { branch = git(root, ["symbolic-ref", "-q", "--short", "HEAD"]) || null; } catch { branch = null; }
  }
  return {
    root,
    git: isGit,
    clean,
    branch,
    framework: detectProjectFramework(root),
    code: hasCode(root),
    lockfiles: {
      npm: NPM_LOCKFILES.filter((f) => existsSync(join(root, f))),
      python: PY_LOCKFILES.filter((f) => existsSync(join(root, f))),
    },
    agentConfig: AGENT_CONFIG.filter((f) => existsSync(join(root, f))),
    devServer: await detectDevServer(opts.ports ?? DEV_PORTS),
    hook: isGit && hookInstalled(root),
    workflows: pentheraWorkflows(root),
    reportsIgnored: reportsIgnored(root, isGit),
  };
}
