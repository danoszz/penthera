/**
 * Shared helpers for Penthera Bench v1 (E1): cache location, manifest
 * validation, hashing, seeded ordering and JSONL files.
 *
 * Third-party code only ever lives in the cache, never in this repository.
 */
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync, appendFileSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

export const BENCH_DIR = dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = resolve(BENCH_DIR, "..", "..");

/** Licences accepted by the E1 inclusion criteria (§ 3.2), as SPDX ids. */
export const LICENCES = new Set(["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD", "Unlicense"]);
export const FRAMEWORKS = ["nextjs", "express", "fastify", "hono", "fastapi"];
export const STRATA = [...FRAMEWORKS, "agents"];
export const CATEGORIES = ["secrets", "route", "code-pattern", "dependency", "agent-config"];

export const sha256 = (data) => createHash("sha256").update(data).digest("hex");

/** True when `child` is `parent` or inside it (after resolving symlinks where possible). */
function isInside(child, parent) {
  const real = (p) => { try { return realpathSync(p); } catch { return resolve(p); } };
  const c = real(child);
  const p = real(parent);
  return c === p || c.startsWith(p + sep);
}

/**
 * The cache folder for clones, package sources, scan output and labels.
 * Refuses any folder inside this repository, so third-party code can never be
 * committed by accident.
 */
export function cacheDir(explicit, env = process.env) {
  const dir = resolve(explicit || env.PENTHERA_BENCH_CACHE || join(homedir(), ".cache", "penthera-bench"));
  if (isInside(dir, REPO_ROOT)) {
    throw new Error(`Cache ${dir} is inside the Penthera repository. Third-party code must stay outside it; pick another --cache or PENTHERA_BENCH_CACHE.`);
  }
  mkdirSync(dir, { recursive: true });
  return dir;
}

/** A stable, filesystem-safe id for a project: owner__repo. */
export function projectId(url) {
  const m = String(url).match(/([^/:]+)\/([^/]+?)(?:\.git)?\/?$/);
  if (!m) throw new Error(`Cannot derive a project id from ${url}`);
  return `${m[1]}__${m[2]}`.replace(/[^A-Za-z0-9._-]/g, "_");
}

/**
 * Validate a corpus manifest. Returns a list of problems (empty when valid).
 * `allowFile` admits file:// URLs, for the hermetic tests only.
 */
export function validateManifest(m, { allowFile = false } = {}) {
  const errs = [];
  if (!m || typeof m !== "object") return ["manifest is not an object"];
  if (m.version !== 1) errs.push("version must be 1");
  if (!["pilot", "e1", "test"].includes(m.set)) errs.push('set must be "pilot", "e1" or "test"');
  if (!Array.isArray(m.projects)) return [...errs, "projects must be an array"];
  const seen = new Set();
  m.projects.forEach((p, i) => {
    const at = `projects[${i}]`;
    const urlOk = /^https:\/\/github\.com\/[A-Za-z0-9-]+\/[A-Za-z0-9._-]+$/.test(p.url || "") || (allowFile && /^file:\/\//.test(p.url || ""));
    if (!urlOk) errs.push(`${at}.url must be https://github.com/<owner>/<repo>`);
    if (!/^[0-9a-f]{40}$/.test(p.commit || "")) errs.push(`${at}.commit must be a full 40-character SHA`);
    if (!LICENCES.has(p.license)) errs.push(`${at}.license ${p.license} is not an accepted SPDX id`);
    if (!STRATA.includes(p.stratum)) errs.push(`${at}.stratum must be one of ${STRATA.join(", ")}`);
    if (p.stratum !== "agents" && p.framework !== p.stratum) errs.push(`${at}.framework must equal the stratum for web-app strata`);
    if (p.excluded != null && typeof p.excluded !== "string") errs.push(`${at}.excluded must be a reason string`);
    if (p.url && seen.has(p.url)) errs.push(`${at}.url is listed twice`);
    seen.add(p.url);
  });
  return errs;
}

export function readManifest(path, opts) {
  const m = JSON.parse(readFileSync(path, "utf8"));
  const errs = validateManifest(m, opts);
  if (errs.length) throw new Error(`Invalid manifest ${path}:\n  ${errs.join("\n  ")}`);
  return m;
}

/** Projects that take part: not excluded. */
export const included = (m) => m.projects.filter((p) => !p.excluded);

/** Deterministic order of items by sha256(seed + key), as in E1 § 3.6. */
export function seededOrder(items, seed, key = (x) => String(x)) {
  return items
    .map((x) => [sha256(`${seed}:${key(x)}`), x])
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
    .map(([, x]) => x);
}

export function readJsonl(path) {
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8").split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
}

export function writeJsonl(path, rows) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, rows.map((r) => JSON.stringify(r)).join("\n") + (rows.length ? "\n" : ""));
}

export function appendJsonl(path, row) {
  mkdirSync(dirname(path), { recursive: true });
  appendFileSync(path, JSON.stringify(row) + "\n");
}

export function readJson(path, fallback) {
  if (!existsSync(path)) return fallback;
  return JSON.parse(readFileSync(path, "utf8"));
}

export function writeJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(value, null, 2) + "\n");
}

/** Minimal argv parser: --flag value, --flag (boolean), positional args. */
export function parseArgs(argv, booleans = []) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) { out._.push(a); continue; }
    const key = a.slice(2);
    if (booleans.includes(key)) out[key] = true;
    else out[key] = argv[++i];
  }
  return out;
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Study folder inside the cache for one corpus set. */
export const studyDir = (cache, set) => join(cache, "study", set);

/** True when the module at `metaUrl` is the script node was started with. */
export function isMain(metaUrl) {
  if (!process.argv[1]) return false;
  const real = (p) => { try { return realpathSync(p); } catch { return resolve(p); } };
  return real(fileURLToPath(metaUrl)) === real(process.argv[1]);
}
