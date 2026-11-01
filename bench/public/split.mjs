/**
 * E11b dev/test split (amendment E11b § 2). Seeded, stratified, 50/50.
 * The manifests hold ids and hashes only, no data. They are release files, not
 * part of the repo: bench/public/split.sha256 pins each one, and every read
 * checks that hash. Only this benchmark fetches them, and only when asked.
 *
 *   npm run bench:public -- --fetch-split    # download and verify the manifests
 *   npm run bench:public -- --split dev      # run and score the dev half only
 *
 * The test half is sealed: it is scored once, at the end of the study.
 */
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { CACHE, ROOT, SEED, shuffled, ensureDir, fetchBuf } from "./common.mjs";

export const SPLIT_DIR = join(ROOT, "bench", "public", "split");
const HASH_FILE = join(ROOT, "bench", "public", "split.sha256");
const FETCHED_DIR = join(CACHE, "split");
/** The GitHub Release that carries the manifests as assets. */
export const SPLIT_RELEASE = "v2.2.0";
export const SPLIT_URL = `https://github.com/danoszz/penthera/releases/download/${SPLIT_RELEASE}`;
const sha = (buf) => createHash("sha256").update(buf).digest("hex");

/** Reads split.sha256 (the format of `shasum -a 256`): { benchmark: hash }. */
export function parseHashes(text) {
  return Object.fromEntries(text.trim().split("\n").map((l) => {
    const [hash, file] = l.trim().split(/\s+/);
    return [file.replace(/\.json$/, ""), hash];
  }));
}

/** Throws unless `buf` is the manifest the repo pinned for `bench`. */
export function verifyManifest(bench, buf, hashes) {
  if (!hashes[bench]) throw new Error(`${bench}: not in bench/public/split.sha256`);
  const got = sha(buf);
  if (got !== hashes[bench]) throw new Error(`${bench}: SHA-256 is ${got}, expected ${hashes[bench]}. Refusing this manifest`);
  return buf;
}

/** The verified manifest from the first folder that has it. */
export function readManifest(bench, { dirs = [SPLIT_DIR, FETCHED_DIR], hashes = parseHashes(readFileSync(HASH_FILE, "utf-8")) } = {}) {
  const file = dirs.map((d) => join(d, `${bench}.json`)).find(existsSync);
  if (!file) throw new Error(`${bench}: no split manifest here. Run: npm run bench:public -- --fetch-split`);
  return JSON.parse(verifyManifest(bench, readFileSync(file), hashes).toString("utf-8"));
}

/**
 * Downloads each manifest not already here, and keeps it only if its hash
 * matches. `fetcher` returns a Buffer, or null for a 404.
 */
export async function fetchSplit({ fetcher = fetchBuf, dirs = [SPLIT_DIR, FETCHED_DIR], url = SPLIT_URL, hashes = parseHashes(readFileSync(HASH_FILE, "utf-8")) } = {}) {
  const to = dirs.at(-1);
  const out = {};
  for (const bench of Object.keys(hashes)) {
    const here = dirs.map((d) => join(d, `${bench}.json`)).find(existsSync);
    if (here) { verifyManifest(bench, readFileSync(here), hashes); out[bench] = "here"; continue; }
    const buf = await fetcher(`${url}/${bench}.json`);
    if (!buf) throw new Error(`${bench}: not on the ${SPLIT_RELEASE} release (${url}/${bench}.json)`);
    verifyManifest(bench, buf, hashes);
    ensureDir(to);
    writeFileSync(join(to, `${bench}.json`), buf);
    out[bench] = "fetched";
  }
  return out;
}

/** The split this process runs on: "all" (E11 as registered), "dev" or "test". */
export function currentSplit() {
  const s = process.env.PENTHERA_E11_SPLIT || "all";
  if (!["all", "dev", "test"].includes(s)) throw new Error(`--split must be dev, test or all, not ${s}`);
  return s;
}

const cache = {};
/** A predicate: is this id in the current split? */
export function inSplit(bench) {
  const s = currentSplit();
  if (s === "all") return () => true;
  cache[bench] ||= readManifest(bench);
  const { dev, test } = cache[bench].ids;
  const side = new Map([...dev.map((id) => [id, "dev"]), ...test.map((id) => [id, "test"])]);
  // An id the manifest does not list (a CredData file with no labelled line)
  // goes by the parity of its SHA-256, so it too lands on one fixed side.
  return (id) => (side.get(id) || (parseInt(sha(id).slice(0, 2), 16) % 2 ? "test" : "dev")) === s;
}

/** Split each stratum's ids in half, seeded; odd strata give the extra id to dev or test alternately. */
function halve(strata, seed) {
  const dev = [], test = [];
  let odd = 0;
  for (const key of Object.keys(strata).sort()) {
    const { list } = shuffled(strata[key], seed);
    let half = Math.floor(list.length / 2);
    if (list.length % 2) half += odd++ % 2 === 0 ? 1 : 0;
    dev.push(...list.slice(0, half));
    test.push(...list.slice(half));
  }
  return { dev: dev.sort(), test: test.sort() };
}

/**
 * CredData at the file level, so no file's lines land on both sides. (The
 * repository level was tried first and rejected: single repositories hold
 * most of some strata, for example 786 of 786 private keys in .txt files.)
 * Greedy balance: files in seeded order, largest first, each to the side that
 * leaves the per-stratum counts (family x extension of T rows, plus F and X
 * totals) closest to equal.
 */
async function creddataSplit() {
  const { loadMeta, family } = await import("./creddata.mjs");
  const rows = loadMeta();
  const TOP = [".txt", ".json", ".go", ".yml", ".md", ".js", ".py", ".java", ".rb", ".ts"];
  const stratum = (r) => {
    if (r.gt !== "T") return `neg:${r.gt}`;
    const base = r.file.split("/").pop();
    const ext = base.includes(".") ? base.slice(base.lastIndexOf(".")) : "";
    return `${family(r.cats)}|${TOP.includes(ext) ? ext : "other"}`;
  };
  const vec = {};
  const totals = {};
  for (const r of rows) {
    const s = stratum(r);
    (vec[r.file] ||= {})[s] = (vec[r.file][s] || 0) + 1;
    totals[s] = (totals[s] || 0) + 1;
  }
  const size = (r) => Object.values(vec[r]).reduce((a, b) => a + b, 0);
  const order = shuffled(Object.keys(vec), SEED).list;
  order.sort((a, b) => size(b) - size(a)); // stable: seeded order breaks ties
  const side = { dev: {}, test: {} };
  const ids = { dev: [], test: [] };
  const cost = () => Object.keys(totals).reduce((c, k) => c + ((side.dev[k] || 0) - (side.test[k] || 0)) ** 2 / totals[k] ** 2, 0);
  for (const repo of order) {
    let best = null;
    for (const to of ["dev", "test"]) {
      for (const [k, n] of Object.entries(vec[repo])) side[to][k] = (side[to][k] || 0) + n;
      const c = cost() + 0.01 * Math.abs(ids.dev.length + (to === "dev") - ids.test.length - (to === "test"));
      for (const [k, n] of Object.entries(vec[repo])) side[to][k] -= n;
      if (!best || c < best.c) best = { to, c };
    }
    for (const [k, n] of Object.entries(vec[repo])) side[best.to][k] = (side[best.to][k] || 0) + n;
    ids[best.to].push(repo);
  }
  const rowsOf = {};
  for (const r of rows) (rowsOf[r.file] ||= []).push(`${r.id},${r.ls},${r.le},${r.gt},${r.cats.join(":")}`);
  const hashes = Object.fromEntries(Object.entries(rowsOf).map(([f, rs]) => [f, sha(rs.sort().join("\n"))]));
  const fam = (side) => Object.entries(side).reduce((o, [k, n]) => ({ ...o, [k.split("|")[0]]: (o[k.split("|")[0]] || 0) + n }), {});
  return { unit: "file (CredData FilePath); hash = SHA-256 of its labelled rows (Id, LineStart, LineEnd, GroundTruth, Category); unlisted files by SHA-256 parity of the path", ids: { dev: ids.dev.sort(), test: ids.test.sort() }, hashes, balance: { dev: fam(side.dev), test: fam(side.test) } };
}

async function secbenchSplit() {
  const { entries, CLASSES } = await import("./secbench.mjs");
  const list = entries().filter((e) => CLASSES[e.cls]);
  const strata = {};
  for (const e of list) (strata[e.cls] ||= []).push(`${e.cls}/${e.folder}`);
  const hashes = {};
  for (const e of list) {
    const id = `${e.cls}/${e.folder}`;
    const tgz = join(CACHE, "secbench-pkgs", `${id}.tgz`);
    hashes[id] = existsSync(tgz) ? sha(readFileSync(tgz)) : sha(readFileSync(join(CACHE, "secbench", id, "package.json")));
  }
  return { unit: "vulnerability folder; hash = SHA-256 of the npm tarball (or of its package.json when not on the registry)", ids: halve(strata, SEED), hashes };
}

function malwareSplit() {
  const { sample } = JSON.parse(readFileSync(join(CACHE, "malware-sample.json"), "utf-8"));
  const strata = {};
  for (const s of sample) (strata[`${s.eco}/${s.cat}`] ||= []).push(s.path);
  return { unit: "sample archive path in the dataset; hash = SHA-256 of the archive", ids: halve(strata, SEED), hashes: Object.fromEntries(sample.map((s) => [s.path, s.sha256])) };
}

function benignSplit() {
  const list = JSON.parse(readFileSync(join(CACHE, "benign", "list.json"), "utf-8"));
  const strata = {};
  const hashes = {};
  for (const eco of ["npm", "pypi"]) {
    for (const b of list[eco]) {
      const id = `${eco}/${b.name}@${b.version}`;
      (strata[eco] ||= []).push(id);
      hashes[id] = b.sha256;
    }
  }
  return { unit: "ecosystem/name@version; hash = SHA-256 of the artifact", ids: halve(strata, SEED), hashes };
}

export async function makeSplit() {
  // The manifests can leave this folder, so their absence must not reopen the draw.
  if (existsSync(HASH_FILE)) throw new Error("bench/public/split.sha256 exists: the split is sealed, do not redraw it");
  ensureDir(SPLIT_DIR);
  const made = { creddata: await creddataSplit(), secbench: await secbenchSplit(), malware: malwareSplit(), benign: benignSplit() };
  const out = {};
  for (const [name, m] of Object.entries(made)) {
    const file = join(SPLIT_DIR, `${name}.json`);
    if (existsSync(file)) throw new Error(`${file} exists: the split is sealed, do not redraw it`);
    const { balance, ...keep } = m;
    const body = JSON.stringify({ benchmark: name, seed: SEED, method: "seeded, stratified 50/50 (bench/public/split.mjs)", ...keep }, null, 1) + "\n";
    writeFileSync(file, body);
    out[name] = { sha256: sha(body), dev: m.ids.dev.length, test: m.ids.test.length, ...(balance ? { balance } : {}) };
  }
  return out;
}
