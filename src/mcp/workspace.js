/**
 * Where an MCP tool may read and which hosts it may contact. Both are decided
 * by the user (the client's roots, or the server's launch arguments), never by
 * a tool argument, so a model cannot widen them.
 *
 *   Paths  A tool's `path` is resolved against the first root, realpath'd
 *          (symlinks followed) and must land inside a root's realpath.
 *   Hosts  scan_url may contact loopback, or a host listed exactly with
 *          --allow-host. http and https only, no credentials in the URL.
 *          The scan's egress context holds that line on every redirect hop.
 */
import { realpathSync, statSync } from "node:fs";
import { basename, dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

export class ToolInputError extends Error {}

/** Realpath'd directories from paths; missing or non-directory entries are dropped. */
export function normalizeRoots(paths) {
  const out = [];
  for (const p of paths) {
    try {
      const real = realpathSync(resolve(p));
      if (statSync(real).isDirectory() && !out.includes(real)) out.push(real);
    } catch {
      // A root that does not exist grants nothing.
    }
  }
  return out;
}

/** Local directories from MCP roots (file:// URIs only). */
export function rootsFromClient(list) {
  if (!Array.isArray(list)) return [];
  const paths = [];
  for (const r of list.slice(0, 64)) {
    if (typeof r?.uri !== "string" || !r.uri.startsWith("file://")) continue;
    try {
      paths.push(fileURLToPath(r.uri));
    } catch {
      // Not a local file URI (file://host/...): ignore.
    }
  }
  return normalizeRoots(paths);
}

function inside(root, real) {
  const rel = relative(root, real);
  return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

/**
 * Resolve a tool's `path` inside the workspace roots. With `skillFile`, a
 * SKILL.md resolves to its folder. The check runs on the file's real path
 * first, so a link cannot pull a folder outside the roots into the scan.
 * `named`: the caller pointed at something other than the root itself.
 * @returns {{ real: string, root: string, display: string, named: boolean }}
 */
export function confinePath(path, roots, { skillFile = false } = {}) {
  if (!roots.length) throw new ToolInputError("No workspace root is available. Start the server in your project folder or pass --root <dir>.");
  const asked = path === undefined || path === "" ? roots[0] : isAbsolute(path) ? path : resolve(roots[0], path);
  let real;
  try {
    real = realpathSync(asked);
  } catch {
    throw new ToolInputError(`Path not found: ${path ?? "."}`);
  }
  const root = roots.find((r) => inside(r, real));
  if (!root) {
    throw new ToolInputError(`${path} is outside the workspace this server may read (${roots.join(", ")}). Ask the user to add it as a root (--root) if it should be scanned.`);
  }
  if (!statSync(real).isDirectory()) {
    if (!skillFile) throw new ToolInputError(`${path} is not a directory. Pass the project folder.`);
    if (basename(real).toLowerCase() !== "skill.md") throw new ToolInputError(`${path} is not a directory or a SKILL.md file. Pass the project folder or the skill folder.`);
    real = dirname(real);
    return { real, root, display: relative(root, real) || ".", named: true };
  }
  return { real, root, display: relative(root, real) || ".", named: real !== root };
}

const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;

export function isLoopbackHost(hostname) {
  const h = hostname.toLowerCase();
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  if (h === "[::1]" || h === "::1") return true;
  return IPV4.test(h) && h.split(".")[0] === "127" && h.split(".").every((o) => Number(o) <= 255);
}

/** Lower-cased hostnames from --allow-host values; rejects anything that is not a bare host. */
export function parseAllowHosts(values) {
  const out = [];
  for (const v of values || []) {
    const h = String(v).trim().toLowerCase();
    if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$|^\[[0-9a-f:.]+\]$/.test(h)) {
      throw new Error(`--allow-host takes a hostname (staging.example.com), got: ${v}`);
    }
    if (!out.includes(h)) out.push(h);
  }
  return out;
}

/**
 * Check a scan_url target against the host policy.
 * @returns {URL}
 */
export function checkTarget(raw, allowHosts) {
  let u;
  try {
    u = new URL(raw);
  } catch {
    throw new ToolInputError(`Not a URL: ${raw}`);
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new ToolInputError("Only http and https URLs can be scanned.");
  if (u.username || u.password) throw new ToolInputError("Remove the credentials from the URL. This server does not send them.");
  const host = u.hostname.toLowerCase();
  if (isLoopbackHost(host) || allowHosts.includes(host)) return u;
  throw new ToolInputError(
    `${host} is not a target this server may contact. Loopback is allowed; any other host must be listed by the user in the server's launch arguments (--allow-host ${host}), and only for a target they are authorized to test.`,
  );
}
