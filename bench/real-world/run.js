#!/usr/bin/env node
/**
 * Penthera Bench v1: scan the fetched corpus statically (E1 § 6.1, step 3).
 *
 *   node bench/real-world/run.js --corpus bench/real-world/pilot/corpus.json --scanner 1.7.0
 *
 * For each cloned project it runs, as child processes of the frozen scanner:
 *   penthera --repo <clone> --offline --json
 *   penthera deps <clone> --json
 *   penthera agents <clone> --json
 * with HOME set to an empty temporary folder (no memory store, no user
 * config), npm, pip and uv caches pointed at the bench's isolated caches, and
 * no-network.mjs preloaded so any non-loopback connection is refused and
 * logged. It never installs anything into a project, never runs project code,
 * and never contacts a deployment. Output goes to <cache>/scans/<set>/<id>/.
 *
 * --scanner-bin <path> runs another Penthera build instead (tests, development).
 * Results from it are marked as not from the frozen release.
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { BENCH_DIR, cacheDir, included, isMain, parseArgs, projectId, readJson, readManifest, writeJson } from "./lib.js";

const GUARD = join(BENCH_DIR, "no-network.mjs");

/** Resolve the scanner: the frozen npm release fetched by fetch.js, or an explicit bin. */
export function resolveScanner({ scanner, scannerBin }, cache) {
  if (scannerBin) {
    const bin = resolve(scannerBin);
    const pkg = readJson(join(bin, "..", "..", "package.json"), {});
    return { bin, version: pkg.version || "unknown", integrity: null, frozen: false };
  }
  const meta = readJson(join(cache, "scanner", scanner || "", "scanner.json"), null);
  if (!meta) throw new Error(`Scanner penthera@${scanner} is not fetched. Run fetch.js --scanner ${scanner} first.`);
  return { ...meta, frozen: true };
}

function runOne(scanner, args, env, timeoutMs) {
  const t0 = Date.now();
  const r = spawnSync(process.execPath, ["--import", GUARD, scanner.bin, ...args], {
    env, encoding: "utf8", maxBuffer: 512 * 1024 * 1024, timeout: timeoutMs, stdio: ["ignore", "pipe", "pipe"],
  });
  const ms = Date.now() - t0;
  let json = null;
  try { json = JSON.parse(r.stdout); } catch { /* not JSON: failure below */ }
  return { status: r.status, ms, json, stderr: (r.stderr || "").slice(-2000), timedOut: r.error?.code === "ETIMEDOUT" };
}

/** Scan one cloned project. Returns its meta record. */
export function scanProject(p, { cache, set, scanner, timeoutMs = 10 * 60 * 1000 }) {
  const id = projectId(p.url);
  const repo = join(cache, "repos", id);
  if (!existsSync(repo)) return { id, error: "not fetched" };
  const out = join(cache, "scans", set, id);
  mkdirSync(out, { recursive: true });
  const home = mkdtempSync(join(tmpdir(), "penthera-bench-home-"));
  const netLog = join(out, "network-refusals.jsonl");
  rmSync(netLog, { force: true });
  const uvCache = join(cache, "uv-cache-empty");
  mkdirSync(uvCache, { recursive: true });
  const env = {
    PATH: process.env.PATH,
    HOME: home,
    USERPROFILE: home,
    TMPDIR: home,
    LANG: "C.UTF-8",
    NO_COLOR: "1",
    npm_config_cache: join(cache, "npm-cache"),
    PIP_CACHE_DIR: join(cache, "pip-cache"),
    UV_CACHE_DIR: uvCache,
    PENTHERA_BENCH_NET_LOG: netLog,
  };
  const meta = { id, url: p.url, commit: p.commit, stratum: p.stratum, framework: p.framework || null, scanner: { version: scanner.version, integrity: scanner.integrity, frozen: scanner.frozen }, node: process.version, scans: {} };
  const jobs = {
    repo: ["--repo", repo, "--offline", "--json", "--quiet"],
    deps: ["deps", repo, "--json"],
    agents: ["agents", repo, "--json"],
  };
  try {
    for (const [name, args] of Object.entries(jobs)) {
      const r = runOne(scanner, args, env, timeoutMs);
      const ok = r.json && !r.timedOut && r.status !== 2;
      // `deps` exits 2 when a project has no lockfile; that is "no input", not a failure.
      const noInput = name === "deps" && !r.json && /No package-lock\.json/.test(r.stderr);
      meta.scans[name] = { status: r.status, ms: r.ms, ok: !!ok, noInput, findings: r.json?.findings?.length ?? null, error: ok || noInput ? null : (r.timedOut ? "timeout" : r.stderr.split("\n").filter(Boolean).slice(-1)[0] || `exit ${r.status}`) };
      if (r.json) writeJson(join(out, `${name}.json`), r.json);
    }
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
  meta.networkRefusals = existsSync(netLog) ? readFileSync(netLog, "utf8").split("\n").filter(Boolean).length : 0;
  meta.ok = Object.values(meta.scans).every((s) => s.ok || s.noInput);
  writeJson(join(out, "meta.json"), meta);
  return meta;
}

async function main() {
  const args = parseArgs(process.argv.slice(2), ["allow-file"]);
  if (!args.corpus || (!args.scanner && !args["scanner-bin"])) {
    console.error("usage: node bench/real-world/run.js --corpus <manifest.json> (--scanner <version> | --scanner-bin <path>) [--cache <dir>]");
    process.exit(2);
  }
  const cache = cacheDir(args.cache);
  const manifest = readManifest(resolve(args.corpus), { allowFile: !!args["allow-file"] });
  const scanner = resolveScanner({ scanner: args.scanner, scannerBin: args["scanner-bin"] }, cache);
  const projects = included(manifest);
  let refusals = 0;
  for (const [i, p] of projects.entries()) {
    const m = scanProject(p, { cache, set: manifest.set, scanner });
    refusals += m.networkRefusals || 0;
    const counts = m.scans ? Object.entries(m.scans).map(([k, s]) => `${k} ${s.ok ? s.findings : s.noInput ? "-" : "FAIL"}`).join(", ") : m.error;
    console.log(`[${i + 1}/${projects.length}] ${m.id}: ${counts}`);
  }
  console.log(`Network connections refused: ${refusals}`);
  if (refusals > 0) process.exitCode = 1;
}

if (isMain(import.meta.url)) main().catch((e) => { console.error(e.message); process.exit(1); });
