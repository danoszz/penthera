#!/usr/bin/env node
/**
 * Penthera Bench v1: fetch the corpus into the cache (E1 § 6.1, steps 1 and 2).
 *
 *   node bench/real-world/fetch.js --corpus bench/real-world/pilot/corpus.json
 *
 * For each project in the manifest:
 *   1. Clone it at the pinned commit into <cache>/repos/<id>. Only git runs:
 *      no hooks, no submodules, no LFS smudge, symlinks checked out as plain
 *      files, and the checked-out commit is verified against the manifest.
 *   2. With --deps, fetch dependency sources so `penthera deps` can read them:
 *      npm tarballs into an isolated npm cache with `npm cache add` (run from
 *      an empty folder with an empty config, so no project .npmrc is read; it
 *      runs no package code), and Python wheels pinned by lockfile hashes,
 *      downloaded from PyPI, sha256-checked, and stored in an isolated pip
 *      cache folder. Nothing is installed and no sdist is built.
 *   3. With --scanner <version>, fetch the frozen Penthera release from npm
 *      into <cache>/scanner/<version> and record its integrity.
 *
 * Requests are sequential with a delay (--delay, default 1500 ms between
 * projects) and back off on 403/429 with Retry-After. GH_TOKEN is never
 * needed for public clones and is not read.
 */
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { createHash } from "node:crypto";
import { cacheDir, isMain, included, parseArgs, projectId, readManifest, sleep, writeJson, readJson } from "./lib.js";
import { parseLockfile, findLockfile, readLockfile } from "../../lib/deps/lockfile.js";
import { parseIntegrity } from "../../lib/deps/source.js";
import { readPythonInputs } from "../../lib/deps/python/lockfiles.js";

const NPM_REGISTRY = "https://registry.npmjs.org/";
const PYPI = "https://pypi.org";

const gitEnv = () => ({
  ...process.env,
  GIT_TERMINAL_PROMPT: "0",
  GIT_LFS_SKIP_SMUDGE: "1",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: "/dev/null",
});

function git(args, cwd, { allowFile = false } = {}) {
  const safety = [
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.symlinks=false",
    "-c", "submodule.recurse=false",
    "-c", `protocol.file.allow=${allowFile ? "always" : "never"}`,
    "-c", "advice.detachedHead=false",
  ];
  return execFileSync("git", [...safety, ...args], { cwd, env: gitEnv(), stdio: ["ignore", "pipe", "pipe"], timeout: 15 * 60 * 1000 }).toString().trim();
}

/** Clone one project at its pinned commit. Returns { id, dir, status }. */
export function cloneProject(p, cache, opts = {}) {
  const id = projectId(p.url);
  const dir = join(cache, "repos", id);
  if (existsSync(join(dir, ".git"))) {
    try {
      if (git(["rev-parse", "HEAD"], dir, opts) === p.commit) return { id, dir, status: "cached" };
    } catch { /* re-clone below */ }
    rmSync(dir, { recursive: true, force: true });
  }
  mkdirSync(dir, { recursive: true });
  git(["init", "-q"], dir, opts);
  git(["remote", "add", "origin", p.url], dir, opts);
  git(["fetch", "-q", "--depth", "1", "--no-tags", "origin", p.commit], dir, opts);
  git(["checkout", "-q", "--detach", "FETCH_HEAD"], dir, opts);
  const head = git(["rev-parse", "HEAD"], dir, opts);
  if (head !== p.commit) {
    rmSync(dir, { recursive: true, force: true });
    throw new Error(`${id}: checked out ${head}, manifest pins ${p.commit}`);
  }
  return { id, dir, status: "cloned" };
}

/** Path of a tarball in npm's content-addressed cache, if present. */
function inNpmCache(integrity, npmCache) {
  return parseIntegrity(integrity).some(({ algo, hex }) =>
    existsSync(join(npmCache, "_cacache", "content-v2", algo, hex.slice(0, 2), hex.slice(2, 4), hex.slice(4))));
}

/** Registry packages of a package-lock.json that are not yet cached. */
export function npmSpecsToFetch(repoDir, npmCache) {
  const lockPath = findLockfile(repoDir);
  if (!lockPath) return { lockfile: null, specs: [], skipped: [] };
  const pkgs = parseLockfile(readLockfile(lockPath));
  const specs = [];
  const skipped = [];
  const seen = new Set();
  for (const p of pkgs) {
    if (p.link || !p.version || !p.integrity) { skipped.push(`${p.name}@${p.version || "?"} (no registry integrity)`); continue; }
    if (p.resolved && !p.resolved.startsWith(NPM_REGISTRY)) { skipped.push(`${p.name}@${p.version} (not from the npm registry)`); continue; }
    const spec = `${p.name}@${p.version}`;
    if (seen.has(spec) || inNpmCache(p.integrity, npmCache)) continue;
    seen.add(spec);
    specs.push(spec);
  }
  return { lockfile: lockPath, specs, skipped };
}

function npmCacheAdd(specs, npmCache, scratch) {
  // An empty working folder and empty configs: no project .npmrc can redirect
  // the registry or add credentials. `npm cache add` downloads and verifies
  // tarballs; it never runs lifecycle scripts.
  const cfg = join(scratch, "empty.npmrc");
  writeFileSync(cfg, "");
  execFileSync("npm", ["cache", "add", ...specs, "--cache", npmCache, "--registry", NPM_REGISTRY, "--ignore-scripts", "--no-audit", "--no-fund"], {
    cwd: scratch,
    env: { ...process.env, NPM_CONFIG_USERCONFIG: cfg, NPM_CONFIG_GLOBALCONFIG: cfg },
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 30 * 60 * 1000,
  });
}

/** Fetch npm tarballs for a cloned project into the isolated npm cache. */
export function fetchNpmSources(repoDir, npmCache, scratch, { batch = 40 } = {}) {
  const { lockfile, specs, skipped } = npmSpecsToFetch(repoDir, npmCache);
  const failed = [];
  for (let i = 0; i < specs.length; i += batch) {
    const chunk = specs.slice(i, i + batch);
    try {
      npmCacheAdd(chunk, npmCache, scratch);
    } catch {
      // One bad spec fails the batch; retry singly so the rest still arrive.
      for (const s of chunk) {
        try { npmCacheAdd([s], npmCache, scratch); } catch { failed.push(s); }
      }
    }
  }
  return { lockfile: !!lockfile, fetched: specs.length - failed.length, failed, skipped };
}

async function getWithBackoff(url, { tries = 5 } = {}) {
  for (let i = 0; i < tries; i++) {
    const res = await fetch(url, { headers: { "user-agent": "penthera-bench (+https://github.com/danoszz/penthera)" } });
    if (res.status === 429 || res.status === 403 || res.status >= 500) {
      const wait = Number(res.headers.get("retry-after")) * 1000 || 2000 * 2 ** i;
      await sleep(Math.min(wait, 120000));
      continue;
    }
    return res;
  }
  throw new Error(`gave up on ${url} after ${tries} tries`);
}

/** Fetch hash-pinned Python wheels for a cloned project into the isolated pip cache. */
export async function fetchPythonSources(repoDir, pipCache, { delay = 300, get = getWithBackoff } = {}) {
  let inputs;
  try { inputs = readPythonInputs(repoDir); } catch { inputs = null; }
  if (!inputs) return { lockfile: false, fetched: 0, failed: [], skipped: [] };
  const store = join(pipCache, "http-v2", "penthera-bench");
  mkdirSync(store, { recursive: true });
  const have = new Set(readdirSync(store).map((f) => f.replace(/\.body$/, "")));
  let fetched = 0;
  const failed = [];
  const skipped = [];
  for (const p of inputs.packages) {
    const wanted = (p.hashes || []).filter((h) => h.startsWith("sha256:")).map((h) => h.slice(7));
    if (!p.version || !wanted.length) { skipped.push(`${p.name}@${p.version || "?"} (no pinned hash)`); continue; }
    if (wanted.some((h) => have.has(h))) continue;
    try {
      const meta = await (await get(`${PYPI}/pypi/${encodeURIComponent(p.name)}/${encodeURIComponent(p.version)}/json`)).json();
      const wheels = (meta.urls || []).filter((u) => u.packagetype === "bdist_wheel" && wanted.includes(u.digests?.sha256));
      wheels.sort((a, b) => /none-any\.whl$/.test(b.filename) - /none-any\.whl$/.test(a.filename));
      const w = wheels[0];
      if (!w) { skipped.push(`${p.name}@${p.version} (no wheel matching the lockfile hashes)`); continue; }
      const bytes = Buffer.from(await (await get(w.url)).arrayBuffer());
      const digest = createHash("sha256").update(bytes).digest("hex");
      if (digest !== w.digests.sha256) throw new Error("sha256 mismatch");
      writeFileSync(join(store, `${digest}.body`), bytes);
      have.add(digest);
      fetched++;
    } catch (e) {
      failed.push(`${p.name}@${p.version} (${e.message})`);
    }
    await sleep(delay);
  }
  return { lockfile: true, fetched, failed, skipped };
}

/**
 * Fetch the frozen Penthera release from npm (E1 § 6.3), unpack it, and install
 * its runtime dependencies with scripts disabled. Returns { bin, version, integrity }.
 */
export function fetchScanner(version, cache) {
  const dir = join(cache, "scanner", version);
  const meta = join(dir, "scanner.json");
  if (existsSync(meta)) return readJson(meta);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  const cfg = join(dir, "empty.npmrc");
  writeFileSync(cfg, "");
  const env = { ...process.env, NPM_CONFIG_USERCONFIG: cfg, NPM_CONFIG_GLOBALCONFIG: cfg };
  const out = JSON.parse(execFileSync("npm", ["pack", `penthera@${version}`, "--json", "--pack-destination", dir, "--registry", NPM_REGISTRY], { cwd: dir, env }).toString());
  const tgz = join(dir, out[0].filename);
  execFileSync("tar", ["-xzf", tgz, "-C", dir]);
  const pkgDir = join(dir, "package");
  execFileSync("npm", ["install", "--omit=dev", "--ignore-scripts", "--no-audit", "--no-fund", "--registry", NPM_REGISTRY], { cwd: pkgDir, env, stdio: ["ignore", "pipe", "pipe"] });
  const info = { version, integrity: out[0].integrity, shasum: out[0].shasum, bin: join(pkgDir, "bin", "penthera.js") };
  writeJson(meta, info);
  return info;
}

async function main() {
  const args = parseArgs(process.argv.slice(2), ["deps", "allow-file"]);
  if (!args.corpus) {
    console.error("usage: node bench/real-world/fetch.js --corpus <manifest.json> [--cache <dir>] [--deps] [--scanner <version>] [--delay <ms>]");
    process.exit(2);
  }
  const cache = cacheDir(args.cache);
  const manifest = readManifest(resolve(args.corpus), { allowFile: !!args["allow-file"] });
  const delay = Number(args.delay ?? 1500);
  const npmCache = join(cache, "npm-cache");
  const pipCache = join(cache, "pip-cache");
  const scratch = join(cache, "scratch");
  mkdirSync(scratch, { recursive: true });
  const logPath = join(cache, "fetch-log.json");
  const log = readJson(logPath, {});

  if (args.scanner) {
    const s = fetchScanner(args.scanner, cache);
    console.log(`scanner penthera@${s.version} ${s.integrity}`);
  }
  const projects = included(manifest);
  for (const [i, p] of projects.entries()) {
    const id = projectId(p.url);
    try {
      const c = cloneProject(p, cache, { allowFile: !!args["allow-file"] });
      const entry = { url: p.url, commit: p.commit, clone: c.status };
      if (args.deps) {
        entry.npm = fetchNpmSources(c.dir, npmCache, scratch);
        entry.python = await fetchPythonSources(c.dir, pipCache);
      }
      log[id] = entry;
      console.log(`[${i + 1}/${projects.length}] ${id}: ${c.status}${entry.npm ? `, npm ${entry.npm.fetched} fetched, ${entry.npm.failed.length} failed` : ""}${entry.python?.lockfile ? `, python ${entry.python.fetched} fetched` : ""}`);
      if (c.status === "cloned") await sleep(delay);
    } catch (e) {
      log[id] = { url: p.url, commit: p.commit, error: e.message.split("\n")[0] };
      console.error(`[${i + 1}/${projects.length}] ${id}: FAILED ${e.message.split("\n")[0]}`);
    }
    writeJson(logPath, log);
  }
}

if (isMain(import.meta.url)) main().catch((e) => { console.error(e.message); process.exit(1); });
