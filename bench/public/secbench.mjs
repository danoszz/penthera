/**
 * E11 benchmark 2: Penthera's code-execution sink check on SecBench.js
 * (protocol § 4.2, § 6.2). Packages are fetched from the npm registry and
 * unpacked as files; nothing is installed or run.
 */
import { readFileSync, readdirSync, existsSync, writeFileSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { CACHE, cloneAt, fetchJson, fetchBuf, ensureDir, pentheraRepo, fmt } from "./common.mjs";
import { verifyIntegrity, unpackTgz, MapSource } from "../../lib/deps/source.js";
import { inSplit } from "./split.mjs";

export const PIN = "5d362353550a8baa42bba34edd26e5fb86d41b60";
const DIR = join(CACHE, "secbench");
const PKGS = join(CACHE, "secbench-pkgs");
const SRC = join(CACHE, "secbench-src");

export const CLASSES = { "command-injection": "command-injection", "code-injection": "eval" };
export const OUT_OF_SCOPE = ["path-traversal", "prototype-pollution", "redos"];

/** The package and version a SecBench.js folder names. */
export function target(folder, meta) {
  const ver = folder.slice(folder.lastIndexOf("_") + 1);
  const deps = Object.entries(meta.dependencies || {});
  // The folder name pins the version; a few package.json files write it as "^x.y.z".
  const hit = deps.find(([, v]) => v.replace(/^[\^~=]/, "") === ver) || (deps.length === 1 ? deps[0] : null);
  return hit ? { name: hit[0], version: hit[1].replace(/^[\^~=]/, "") === ver ? ver : hit[1] } : null;
}

/** "lib/x.js:47:23" -> "lib/x.js", with package-root prefixes removed. */
export function sinkFile(sink, name) {
  if (!sink) return null;
  let f = String(sink).replace(/:\d+(?::\d+)?$/, "").replace(/^\.?\//, "").replace(/^package\//, "");
  const nm = `node_modules/${name}/`;
  if (f.includes(nm)) f = f.slice(f.indexOf(nm) + nm.length);
  return f;
}

export function entries(dir = DIR) {
  const out = [];
  for (const cls of [...Object.keys(CLASSES), ...OUT_OF_SCOPE]) {
    for (const folder of readdirSync(join(dir, cls)).sort()) {
      const pj = join(dir, cls, folder, "package.json");
      if (!existsSync(pj)) continue;
      let meta;
      try { meta = JSON.parse(readFileSync(pj, "utf-8")); } catch { out.push({ cls, folder, bad: true }); continue; }
      const t = target(folder, meta);
      out.push({ cls, folder, id: meta.id || null, ...(t || {}), sink: meta.sink || null, sinkFile: t ? sinkFile(meta.sink, t.name) : null });
    }
  }
  return out;
}

const regUrl = (name) => `https://registry.npmjs.org/${name.startsWith("@") ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name)}`;

export async function fetchData() {
  const head = cloneAt("https://github.com/cristianstaicu/SecBench.js", DIR, PIN);
  const list = entries().filter((e) => CLASSES[e.cls]);
  const status = {};
  for (const e of list) {
    const key = `${e.cls}/${e.folder}`;
    const tgzPath = join(PKGS, `${key}.tgz`);
    if (existsSync(tgzPath)) { status[key] = "ok"; continue; }
    if (!e.name || !/^\d+\.\d+\.\d+/.test(e.version || "")) { status[key] = "no exact version"; continue; }
    const m = await fetchJson(`${regUrl(e.name)}/${e.version}`).catch(() => null);
    if (!m?.dist?.tarball) { status[key] = "not on the registry"; continue; }
    const tgz = await fetchBuf(m.dist.tarball).catch(() => null);
    if (!tgz) { status[key] = "tarball not downloadable"; continue; }
    if (m.dist.integrity && !verifyIntegrity(tgz, m.dist.integrity)) { status[key] = "integrity mismatch"; continue; }
    ensureDir(dirname(tgzPath));
    writeFileSync(tgzPath, tgz);
    status[key] = "ok";
  }
  writeFileSync(join(CACHE, "secbench-status.json"), JSON.stringify(status, null, 2));
  return { commit: head };
}

/** Offline step: unpack, repo-scan, capability-scan. */
export async function scan() {
  const { scanPackage } = await import("../../lib/deps/capabilities.js");
  const status = JSON.parse(readFileSync(join(CACHE, "secbench-status.json"), "utf-8"));
  const results = [];
  const keep = inSplit("secbench");
  for (const e of entries().filter((x) => CLASSES[x.cls] && keep(`${x.cls}/${x.folder}`))) {
    const key = `${e.cls}/${e.folder}`;
    if (status[key] !== "ok") { results.push({ ...e, status: status[key] || "not fetched" }); continue; }
    const files = unpackTgz(readFileSync(join(PKGS, `${key}.tgz`)));
    const dir = join(SRC, key);
    rmSync(dir, { recursive: true, force: true });
    for (const [rel, buf] of files) {
      const p = join(dir, rel);
      if (!p.startsWith(dir + "/")) continue;
      ensureDir(dirname(p));
      writeFileSync(p, buf);
    }
    const report = pentheraRepo(dir);
    const sinks = (report.findings || []).filter((f) => f.category === "code-pattern").map((f) => ({ pattern: f.pattern, file: f.file, line: f.line, confidence: f.confidence || null, source: f.source }));
    const other = (report.findings || []).filter((f) => f.category !== "code-pattern" && f.severity !== "info").length;
    const caps = scanPackage(new MapSource(files)).capabilities;
    const capFiles = Object.fromEntries(["shell", "eval"].map((c) => [c, [...new Set((caps[c]?.evidence || []).map((x) => x.file))]]));
    results.push({ ...e, status: "ok", sinkInTarball: e.sinkFile ? files.has(e.sinkFile) : null, sinks, otherFindings: other, capFiles });
  }
  return { results };
}

export function score(raw) {
  const per = {};
  for (const cls of Object.keys(CLASSES)) {
    const pat = CLASSES[cls];
    const all = raw.results.filter((r) => r.cls === cls);
    const ok = all.filter((r) => r.status === "ok");
    const withSink = ok.filter((r) => r.sinkFile);
    const strictHits = withSink.filter((r) => r.sinks.some((s) => s.pattern === pat && s.file === r.sinkFile));
    const lenient = ok.filter((r) => r.sinks.some((s) => s.pattern === pat));
    const cap = cls === "command-injection" ? "shell" : "eval";
    const capStrict = withSink.filter((r) => r.capFiles[cap].includes(r.sinkFile));
    const capAny = ok.filter((r) => r.capFiles[cap].length);
    const conf = {};
    for (const r of strictHits) {
      const s = r.sinks.find((x) => x.pattern === pat && x.file === r.sinkFile);
      conf[s.confidence || "none"] = (conf[s.confidence || "none"] || 0) + 1;
    }
    const excluded = {};
    for (const r of all.filter((x) => x.status !== "ok")) excluded[r.status] = (excluded[r.status] || 0) + 1;
    per[cls] = {
      total: all.length, fetched: ok.length, withSink: withSink.length,
      sinkNotInTarball: withSink.filter((r) => !r.sinkInTarball).length,
      strict: [strictHits.length, withSink.length], lenient: [lenient.length, ok.length],
      capStrict: [capStrict.length, withSink.length], capAny: [capAny.length, ok.length],
      strictByConfidence: conf, excluded,
      otherFindings: ok.reduce((a, r) => a + r.otherFindings, 0),
      wrongPattern: ok.filter((r) => r.sinks.length && !r.sinks.some((s) => s.pattern === pat)).length,
      found: strictHits.map((r) => r.folder),
    };
  }
  const sum = (k) => Object.values(per).reduce((a, v) => [a[0] + v[k][0], a[1] + v[k][1]], [0, 0]);
  return { per, pooled: { strict: sum("strict"), lenient: sum("lenient"), capStrict: sum("capStrict"), capAny: sum("capAny") } };
}

export function markdown(s) {
  const L = ["| Class | Vulns | Fetched | Strict recall (sink file) | Lenient recall (anywhere) | Capability at sink file | Capability anywhere |", "|---|---:|---:|---|---|---|---|"];
  for (const [cls, v] of Object.entries(s.per)) {
    L.push(`| ${cls} | ${v.total} | ${v.fetched} | ${fmt(...v.strict)} | ${fmt(...v.lenient)} | ${fmt(...v.capStrict)} | ${fmt(...v.capAny)} |`);
  }
  const P = s.pooled;
  L.push(`| **pooled** | | | ${fmt(...P.strict)} | ${fmt(...P.lenient)} | ${fmt(...P.capStrict)} | ${fmt(...P.capAny)} |`, "");
  for (const [cls, v] of Object.entries(s.per)) {
    L.push(`- ${cls}: excluded ${JSON.stringify(v.excluded)}; sink file not in the tarball: ${v.sinkNotInTarball}; strict hits by confidence ${JSON.stringify(v.strictByConfidence)}; packages with only the other sink pattern: ${v.wrongPattern}; other non-info findings: ${v.otherFindings}; found: ${v.found.join(", ") || "none"}.`);
  }
  return L.join("\n");
}
