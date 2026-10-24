/**
 * Shared helpers for E11 (bench/public): paths, seeded sampling, downloads,
 * and the offline child process that does every scan.
 */
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, existsSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { mulberry32 } from "../prng.js";
import { wilson } from "../known-vuln/score.mjs";

export { wilson };
export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
export const CACHE = join(process.env.PENTHERA_BENCH_CACHE || join(homedir(), ".cache", "penthera-bench"), "public");
export const RESULTS = join(CACHE, "results");
// Malware samples live here and nowhere else (protocol § 10).
export const MALWARE_DIR = "/private/tmp/penthera-e11-malware";
export const SEED = 20261024;
export const PENTHERA = join(ROOT, "bin", "penthera.js");
export const GUARD = join(ROOT, "scripts", "ci", "net-guard.cjs");

export const sh = (cmd, args, opts = {}) =>
  (execFileSync(cmd, args, { encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"], maxBuffer: 1 << 30, ...opts }) ?? "").trim();

/** Fisher–Yates shuffle of a sorted copy, seeded (protocol § 5.3). */
export function shuffled(items, seed = SEED) {
  const rng = mulberry32(seed);
  const a = [...items].sort();
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return { list: a, rng };
}

/** "0.42 [0.37, 0.48] (126/300)" */
export function fmt(k, n) {
  const w = wilson(k, n);
  if (!w) return `n/a (0/0)`;
  return `${w.p.toFixed(2)} [${w.lo.toFixed(2)}, ${w.hi.toFixed(2)}] (${k}/${n})`;
}

export async function fetchBuf(url, headers = {}, tries = 3) {
  for (let i = 1; ; i++) {
    try {
      const r = await fetch(url, { headers: { "user-agent": "penthera-bench-e11", ...headers } });
      if (r.status === 404) return null;
      if (!r.ok) throw new Error(`${r.status} ${url}`);
      return Buffer.from(await r.arrayBuffer());
    } catch (e) {
      if (i >= tries) throw e;
      await new Promise((res) => setTimeout(res, 1000 * i));
    }
  }
}

export async function fetchJson(url, headers = {}) {
  const b = await fetchBuf(url, { accept: "application/json", ...headers });
  return b ? JSON.parse(b.toString("utf-8")) : null;
}

/** Clone a repository once and check out a pinned commit; refuse a mismatch. */
export function cloneAt(url, dir, commit) {
  if (!existsSync(join(dir, ".git"))) sh("git", ["clone", "-q", url, dir]);
  if (sh("git", ["-C", dir, "rev-parse", "HEAD"]) !== commit) {
    sh("git", ["-C", dir, "fetch", "-q", "origin", commit]);
    sh("git", ["-C", dir, "checkout", "-q", commit]);
  }
  const head = sh("git", ["-C", dir, "rev-parse", "HEAD"]);
  if (head !== commit) throw new Error(`${dir} is at ${head}, expected ${commit}`);
  return head;
}

/**
 * Run this benchmark's scan step in a child process with the network guard
 * preloaded (into it and every node process it starts) and an empty HOME.
 * Returns the child's JSON result and the guard's blocked-connection lines.
 */
export function runOffline(bench) {
  const home = mkdtempSync(join(tmpdir(), "penthera-e11-home-"));
  const log = join(home, "guard.log");
  const out = join(home, "result.json");
  try {
    execFileSync(process.execPath, [join(ROOT, "bench", "public", "run.mjs"), "--child", bench, "--out", out], {
      stdio: ["ignore", "inherit", "inherit"],
      env: {
        PATH: process.env.PATH, HOME: home, NO_COLOR: "1",
        // The child has an empty HOME, so pass the cache base resolved here.
        PENTHERA_BENCH_CACHE: dirname(CACHE),
        PENTHERA_E11_SPLIT: process.env.PENTHERA_E11_SPLIT || "all",
        NODE_OPTIONS: `--require ${GUARD}`, PENTHERA_NET_GUARD_LOG: log,
      },
    });
    const blocked = existsSync(log) ? readFileSync(log, "utf-8").split("\n").filter(Boolean) : [];
    return { result: JSON.parse(readFileSync(out, "utf-8")), blocked };
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}

/** Run the Penthera CLI repo scan on a folder (inside the offline child). */
export function pentheraRepo(dir) {
  // Exits non-zero when it finds something; the JSON on stdout is what counts.
  const r = spawnSync(process.execPath, [PENTHERA, "--repo", dir, "--offline", "--json"], {
    encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"], maxBuffer: 1 << 30, env: process.env, timeout: 600_000,
  });
  const i = (r.stdout || "").indexOf("{");
  if (i === -1) throw new Error(`no JSON from penthera --repo ${dir} (exit ${r.status})`);
  return JSON.parse(r.stdout.slice(i));
}

export function ensureDir(d) {
  mkdirSync(d, { recursive: true });
  return d;
}
