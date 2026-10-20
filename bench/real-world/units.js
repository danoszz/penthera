#!/usr/bin/env node
/**
 * Penthera Bench v1: turn scan output into labelling units and draw the
 * samples (E1 § 4 and § 5).
 *
 *   node bench/real-world/units.js --corpus bench/real-world/pilot/corpus.json
 *
 * Writes into <cache>/study/<set>/:
 *   population.json   flagged and unflagged unit counts per project and category
 *   units-key.jsonl   every sampled unit with its truth from Penthera's side
 *                     (flagged, confidence, rules). Labellers never open this.
 *   queue-A.jsonl     the blind queue for labeller A: unit id, category,
 *   queue-B.jsonl     question, and what to show. Same units, different order.
 *   packages/         unpacked sources of sampled dependency units
 *
 * Unit ids are hashes, flagged and unflagged units of a category are asked
 * the same way, and both are shuffled into one queue, so a labeller cannot tell
 * which units Penthera flagged.
 */
import { existsSync, lstatSync, mkdirSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, normalize, relative, resolve, sep } from "node:path";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { CATEGORIES, cacheDir, included, isMain, parseArgs, projectId, readJson, readJsonl, readManifest, seededOrder, sha256, studyDir, writeJson, writeJsonl } from "./lib.js";
import { isSecretScanTarget } from "../../lib/whitebox/secrets.js";
import { discoverAgentConfig } from "../../lib/agents/discover.js";
import { CAPABILITIES, capabilityWhy } from "../../lib/deps/capabilities.js";
import { parseLockfile, findLockfile, readLockfile } from "../../lib/deps/lockfile.js";
import { sourceFromNpmCache } from "../../lib/deps/source.js";
import { readPythonInputs, normalizeName } from "../../lib/deps/python/lockfiles.js";
import { sourceFromPipCache } from "../../lib/deps/python/source.js";

export const DEFAULTS = {
  flaggedCap: 3,           // § 4.2: flagged units per project per category
  unflaggedCap: 2,         // § 4.4: unflagged units per project per category
  unflaggedPerCategory: 80,
  calibrationPerCategory: 12,
  maxPackageBytes: 200 * 1024, // § 5: dependency recall only for packages ≤ 200 KB
};

const STRENGTH = { confirmed: 3, likely: 2, potential: 1, "needs-human-review": 0 };
const strongest = (a, b) => ((STRENGTH[b] ?? -1) > (STRENGTH[a] ?? -1) ? b : a);

/** The question a labeller answers. Identical for flagged and unflagged units of a category. */
export function questionFor(u) {
  switch (u.category) {
    case "secrets":
      return "Does this file contain a hardcoded credential: a real-looking secret value (key, token, password), not a placeholder, documented example, test value or environment lookup?";
    case "route":
      return "Does this route have an access-control or abuse-protection weakness: reachable without authentication although it handles user data or privileged actions, or public and calling external or paid services with no rate limiting?";
    case "code-pattern":
      return "Does this route file contain a risky code pattern: CORS that allows any origin with credentials, eval or command execution on request input, SQL or NoSQL built from request strings, an unvalidated redirect, or a similar CWE-listed weakness?";
    case "agent-config":
      return "Does this agent configuration file contain a security problem: hidden or scanner-directed instructions, an MCP server or plugin that is unpinned or downloads and runs code, a hook that runs remote code or auto-approves tools, over-broad permissions, or an inline secret?";
    case "dependency":
      if (u.capability === "typosquat") return `Is the name of ${u.package}@${u.version} a lookalike of a popular package (a typosquat or hallucinated name), rather than a legitimate, distinct package?`;
      if (CAPABILITIES[u.capability]) return `Does ${u.package}@${u.version} have this capability: ${CAPABILITIES[u.capability].label}? (${capabilityWhy(u.capability, u.ecosystem)})`;
      return `Does ${u.package}@${u.version} show this risk: ${u.capability}?`;
    default:
      return "Is there a security problem here?";
  }
}

const nonInfo = (f) => f && f.severity && f.severity !== "info";

function addFlagged(map, key, base, f) {
  const u = map.get(key) || { ...base, key, flagged: true, confidence: null, rules: [] };
  u.confidence = strongest(u.confidence, f.confidence);
  const rule = f.templateId || f.method || f.source || "?";
  if (!u.rules.includes(rule)) u.rules.push(rule);
  map.set(key, u);
}

function walkFiles(root, accept, limit = 50000) {
  const out = [];
  const walk = (d) => {
    if (out.length >= limit) return;
    if (d !== root && existsSync(join(d, ".git"))) return; // nested repo
    let entries;
    try { entries = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (e.name === ".git") continue;
      const p = join(d, e.name);
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) walk(p);
      else if (e.isFile()) {
        const rel = relative(root, p).split(sep).join("/");
        if (accept(rel)) out.push(rel);
      }
    }
  };
  walk(root);
  return out;
}

/** Catalogue capabilities that apply to an ecosystem. */
export function catalogue(ecosystem) {
  const pyOnly = new Set(["startup-hook", "deserialize"]);
  const npmOnly = new Set(["ai-config-write", "token-harvest", "fs-write"]);
  return Object.keys(CAPABILITIES).filter((c) => (ecosystem === "pypi" ? !npmOnly.has(c) : !pyOnly.has(c)));
}

/**
 * All units of one project: flagged ones (from Penthera's findings) and the
 * candidates for the unflagged sample, per category.
 */
export function projectUnits(p, { cache, set }) {
  const id = projectId(p.url);
  const repoDir = join(cache, "repos", id);
  const scanDir = join(cache, "scans", set, id);
  const repo = readJson(join(scanDir, "repo.json"), { findings: [], attackSurface: [] });
  const deps = readJson(join(scanDir, "deps.json"), null);
  const agents = readJson(join(scanDir, "agents.json"), { findings: [] });
  const base = { project: id, stratum: p.stratum, framework: p.framework || null };
  const flagged = new Map();
  const candidates = Object.fromEntries(CATEGORIES.map((c) => [c, new Map()]));
  let other = 0;

  // Routes and code patterns: findings carry the route URL; map it to its file.
  const surface = repo.attackSurface || [];
  const byUrl = new Map();
  for (const r of surface) if (!byUrl.has(r.url)) byUrl.set(r.url, r);
  const routeKey = (r) => `route:${r.filePath}#${r.url}`;
  for (const r of surface) {
    candidates.route.set(routeKey(r), { ...base, key: routeKey(r), category: "route", show: { kind: "route", path: r.filePath, route: r.url, methods: r.methods } });
    const ck = `code-pattern:${r.filePath}`;
    candidates["code-pattern"].set(ck, { ...base, key: ck, category: "code-pattern", show: { kind: "file", path: r.filePath } });
  }

  for (const f of (repo.findings || []).filter(nonInfo)) {
    if (f.category === "secrets") {
      const k = `secrets:${f.url}`;
      addFlagged(flagged, k, { ...base, category: "secrets", show: { kind: "file", path: f.url } }, f);
    } else if (f.category === "code-pattern" && byUrl.has(f.url)) {
      const r = byUrl.get(f.url);
      addFlagged(flagged, `code-pattern:${r.filePath}`, { ...base, category: "code-pattern", show: { kind: "file", path: r.filePath } }, f);
    } else if (byUrl.has(f.url)) {
      const r = byUrl.get(f.url);
      addFlagged(flagged, routeKey(r), { ...base, category: "route", show: { kind: "route", path: r.filePath, route: r.url, methods: r.methods } }, f);
    } else {
      other++;
    }
  }

  // Secrets candidates: every file the secret scan reads.
  if (existsSync(repoDir)) {
    for (const rel of walkFiles(repoDir, isSecretScanTarget)) {
      const k = `secrets:${rel}`;
      candidates.secrets.set(k, { ...base, key: k, category: "secrets", show: { kind: "file", path: rel } });
    }
  }

  // Dependencies.
  for (const f of (deps?.findings || []).filter(nonInfo)) {
    if (!f.package) { other++; continue; }
    const cap = f.capabilities?.[0] || (f.method || "deps").replace(/^deps-/, "");
    const k = `dependency:${f.package}@${f.version}:${cap}`;
    addFlagged(flagged, k, { ...base, category: "dependency", package: f.package, version: f.version, capability: cap, ecosystem: deps.deps?.ecosystem === "pypi" ? "pypi" : guessEcosystem(f), show: { kind: "package", package: f.package, version: f.version } }, f);
  }
  for (const pkg of deps?.deps?.packages || []) {
    if (!pkg.source || pkg.source === "unavailable" || pkg.unreadable) continue;
    const ecosystem = pkg.ecosystem || (deps.deps.ecosystem === "pypi" ? "pypi" : "npm");
    const caps = [...catalogue(ecosystem), ...(pkg.direct ? ["typosquat"] : [])];
    for (const cap of caps) {
      if (pkg.capabilities && pkg.capabilities[cap]) continue; // in the inventory: neither flagged nor unflagged (§ 5)
      const k = `dependency:${pkg.name}@${pkg.version}:${cap}`;
      candidates.dependency.set(k, { ...base, key: k, category: "dependency", package: pkg.name, version: pkg.version, capability: cap, ecosystem, show: { kind: "package", package: pkg.name, version: pkg.version } });
    }
  }

  // Agent configuration.
  for (const f of (agents.findings || []).filter(nonInfo)) {
    const k = `agent-config:${f.url}`;
    addFlagged(flagged, k, { ...base, category: "agent-config", show: { kind: "file", path: f.url } }, f);
  }
  if (existsSync(repoDir)) {
    const emptyHome = mkdtempSync(join(tmpdir(), "penthera-bench-nohome-"));
    try {
      const inv = discoverAgentConfig(repoDir, { homeDir: emptyHome });
      const files = new Set([...inv.configFiles, ...inv.instructionFiles].map((x) => x.display));
      for (const s of inv.skills) {
        if (s.dir && s.scope === "repo") for (const rel of walkFiles(s.dir, () => true, 50)) files.add(relative(repoDir, join(s.dir, rel)).split(sep).join("/"));
      }
      for (const rel of files) {
        if (rel.startsWith("~") || rel.startsWith("/")) continue;
        const k = `agent-config:${rel}`;
        candidates["agent-config"].set(k, { ...base, key: k, category: "agent-config", show: { kind: "file", path: rel } });
      }
    } finally {
      rmSync(emptyHome, { recursive: true, force: true });
    }
  }

  // Candidates exclude anything flagged.
  for (const c of CATEGORIES) for (const k of flagged.keys()) candidates[c].delete(k);
  return { id, base, flagged: [...flagged.values()], candidates: Object.fromEntries(CATEGORIES.map((c) => [c, [...candidates[c].values()]])), other };
}

function guessEcosystem(f) {
  return /site-packages|\.dist-info|\.py$/.test(f.url || "") ? "pypi" : "npm";
}

/**
 * Unpack a dependency unit's package source into the study folder so a
 * labeller can read it. Returns { dir, bytes } or null when not readable.
 */
export function materializePackage(u, { cache, out }) {
  const dest = join(out, "packages", `${u.ecosystem}__${u.package.replace(/[/@]/g, "_")}@${u.version}`);
  const meta = join(dest, ".bench.json");
  if (existsSync(meta)) return readJson(meta);
  const repoDir = join(cache, "repos", u.project);
  let src = null;
  if (u.ecosystem === "pypi") {
    const inputs = (() => { try { return readPythonInputs(repoDir); } catch { return null; } })();
    const pkg = inputs?.packages.find((x) => normalizeName(x.name) === normalizeName(u.package) && x.version === u.version);
    if (pkg) src = sourceFromPipCache(pkg, join(cache, "pip-cache"));
  } else {
    const lock = findLockfile(repoDir);
    const entry = lock && parseLockfile(readLockfile(lock)).find((x) => x.name === u.package && x.version === u.version && x.integrity);
    if (entry) src = sourceFromNpmCache(entry.integrity, join(cache, "npm-cache"));
  }
  if (!src || src.anomaly || typeof src.files !== "function") return null;
  let bytes = 0;
  rmSync(dest, { recursive: true, force: true });
  for (const rel of src.files()) {
    const target = normalize(join(dest, rel));
    if (!target.startsWith(dest + sep)) continue; // never write outside the package folder
    const data = src.read(rel);
    if (!data) continue;
    bytes += data.length;
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, data);
  }
  const info = { dir: dest, bytes };
  writeJson(meta, info);
  return info;
}

const opaqueId = (seed, key) => sha256(`unit:${seed}:${key}`).slice(0, 12);

/**
 * Draw the analysis and calibration samples from all projects' units.
 * @param {ReturnType<typeof projectUnits>[]} all
 * @param {{ seed: string, readable?: (u) => boolean }} opts
 */
export function drawSample(all, { seed, readable = () => true, ...cfg } = {}) {
  const c = { ...DEFAULTS, ...cfg };
  const analysis = [];
  const leftover = { flagged: Object.fromEntries(CATEGORIES.map((k) => [k, []])), unflagged: Object.fromEntries(CATEGORIES.map((k) => [k, []])) };
  const skippedUnreadable = Object.fromEntries(CATEGORIES.map((k) => [k, 0]));

  // Flagged: up to flaggedCap per project per category.
  for (const pr of all) {
    for (const cat of CATEGORIES) {
      const units = seededOrder(pr.flagged.filter((u) => u.category === cat), `${seed}:flagged:${pr.id}:${cat}`, (u) => u.key);
      analysis.push(...units.slice(0, c.flaggedCap));
      leftover.flagged[cat].push(...units.slice(c.flaggedCap));
    }
  }

  // Unflagged: round-robin over projects (seeded order) until the target per category.
  for (const cat of CATEGORIES) {
    const queues = seededOrder(all, `${seed}:projects:${cat}`, (pr) => pr.id)
      .map((pr) => ({ pr, q: seededOrder(pr.candidates[cat], `${seed}:unflagged:${pr.id}:${cat}`, (u) => u.key), taken: 0 }));
    let taken = 0;
    let progress = true;
    while (taken < c.unflaggedPerCategory && progress) {
      progress = false;
      for (const s of queues) {
        if (taken >= c.unflaggedPerCategory) break;
        if (s.taken >= c.unflaggedCap) continue;
        while (s.q.length) {
          const u = s.q.shift();
          if (!readable(u)) { skippedUnreadable[cat]++; continue; }
          analysis.push({ ...u, flagged: false, confidence: null, rules: [] });
          s.taken++;
          taken++;
          progress = true;
          break;
        }
      }
    }
    for (const s of queues) leftover.unflagged[cat].push(...s.q);
  }

  const calibration = drawCalibration(leftover, { seed, readable, perCategory: c.calibrationPerCategory });
  return { analysis: analysis.map((u) => tag(u, "analysis", seed)), calibration: calibration.map((u) => tag(u, "calibration", seed, 1)), skippedUnreadable, config: c };
}

const tag = (u, set, seed, round) => ({ ...u, set, ...(round ? { round } : {}), id: opaqueId(seed, `${u.project}:${u.key}`), question: questionFor(u) });

/** Calibration units: half flagged, half unflagged per category, from the leftover pools. */
function drawCalibration(leftover, { seed, readable, perCategory }) {
  const out = [];
  const half = Math.floor(perCategory / 2);
  for (const cat of CATEGORIES) {
    const f = seededOrder(leftover.flagged[cat], `${seed}:cal:f:${cat}`, (u) => `${u.project}:${u.key}`).slice(0, half);
    const unf = [];
    for (const u of seededOrder(leftover.unflagged[cat], `${seed}:cal:u:${cat}`, (x) => `${x.project}:${x.key}`)) {
      if (unf.length >= perCategory - f.length) break;
      if (readable(u)) unf.push({ ...u, flagged: false, confidence: null, rules: [] });
    }
    out.push(...f, ...unf);
  }
  return out;
}

/**
 * A further calibration round (E1 § 6.2): a fresh set drawn from units that are
 * in neither the analysis set nor an earlier calibration round.
 */
export function drawCalibrationRound(all, existing, { seed, round, readable = () => true, perCategory = DEFAULTS.calibrationPerCategory }) {
  const used = new Set(existing.map((u) => `${u.project}:${u.key}`));
  const leftover = { flagged: Object.fromEntries(CATEGORIES.map((k) => [k, []])), unflagged: Object.fromEntries(CATEGORIES.map((k) => [k, []])) };
  for (const pr of all) {
    for (const u of pr.flagged) if (!used.has(`${pr.id}:${u.key}`)) leftover.flagged[u.category].push(u);
    for (const cat of CATEGORIES) for (const u of pr.candidates[cat]) if (!used.has(`${pr.id}:${u.key}`)) leftover.unflagged[cat].push(u);
  }
  return drawCalibration(leftover, { seed: `${seed}:round${round}`, readable, perCategory }).map((u) => tag(u, "calibration", seed, round));
}

/** The blind view of a unit: nothing about Penthera's verdict. */
export const blind = (u) => ({ id: u.id, set: u.set, ...(u.round ? { round: u.round } : {}), category: u.category, question: u.question, project: u.project, show: u.show });

/** One labeller's queue: calibration first, then analysis, each shuffled with the labeller's seed. */
export function queueFor(units, seed, labeller) {
  const rounds = [...new Set(units.filter((u) => u.set === "calibration").map((u) => u.round || 1))].sort((a, b) => a - b);
  const cal = rounds.flatMap((r) => seededOrder(units.filter((u) => u.set === "calibration" && (u.round || 1) === r), `${seed}:queue:${labeller}:cal:${r}`, (u) => u.id));
  const ana = seededOrder(units.filter((u) => u.set === "analysis"), `${seed}:queue:${labeller}:ana`, (u) => u.id);
  return [...cal, ...ana].map(blind);
}

export function buildStudy({ manifest, cache, seed, config = {}, calibrationRound = 1 }) {
  const out = studyDir(cache, manifest.set);
  mkdirSync(out, { recursive: true });
  if (calibrationRound > 1) return addCalibrationRound({ manifest, cache, out, round: calibrationRound, config });
  if (existsSync(join(out, "units-key.jsonl"))) throw new Error(`A study already exists in ${out}. Units are drawn once; use --calibration-round <n> for a further calibration set.`);
  const all = included(manifest).filter((p) => existsSync(join(cache, "scans", manifest.set, projectId(p.url), "meta.json"))).map((p) => projectUnits(p, { cache, set: manifest.set }));
  const c = { ...DEFAULTS, ...config };
  const readable = (u) => {
    if (u.category !== "dependency") return true;
    const m = materializePackage(u, { cache, out });
    return !!m && m.bytes <= c.maxPackageBytes;
  };
  const sample = drawSample(all, { seed, readable, ...config });
  // Flagged dependency units must be readable too, so the labeller can see them.
  for (const u of [...sample.analysis, ...sample.calibration]) if (u.category === "dependency" && u.flagged) materializePackage(u, { cache, out });
  const population = {
    set: manifest.set,
    seed,
    config: sample.config,
    skippedUnreadable: sample.skippedUnreadable,
    projects: Object.fromEntries(all.map((pr) => [pr.id, {
      stratum: pr.base.stratum,
      framework: pr.base.framework,
      flagged: Object.fromEntries(CATEGORIES.map((c) => [c, pr.flagged.filter((u) => u.category === c).length])),
      unflagged: Object.fromEntries(CATEGORIES.map((c) => [c, pr.candidates[c].length])),
      other: pr.other,
    }])),
  };
  const units = [...sample.calibration, ...sample.analysis];
  writeJson(join(out, "population.json"), population);
  writeJsonl(join(out, "units-key.jsonl"), units);
  writeJsonl(join(out, "queue-A.jsonl"), queueFor(units, seed, "A"));
  writeJsonl(join(out, "queue-B.jsonl"), queueFor(units, seed, "B"));
  return { out, population, units };
}

function addCalibrationRound({ manifest, cache, out, round, config }) {
  const existing = readJsonl(join(out, "units-key.jsonl"));
  const population = readJson(join(out, "population.json"), null);
  if (!existing.length || !population) throw new Error(`No study in ${out} yet. Run units.js without --calibration-round first.`);
  if (existing.some((u) => u.round === round)) throw new Error(`Calibration round ${round} already exists.`);
  const seed = population.seed;
  const c = { ...DEFAULTS, ...population.config, ...config };
  const all = included(manifest).filter((p) => existsSync(join(cache, "scans", manifest.set, projectId(p.url), "meta.json"))).map((p) => projectUnits(p, { cache, set: manifest.set }));
  const readable = (u) => {
    if (u.category !== "dependency") return true;
    const m = materializePackage(u, { cache, out });
    return !!m && m.bytes <= c.maxPackageBytes;
  };
  const fresh = drawCalibrationRound(all, existing, { seed, round, readable, perCategory: c.calibrationPerCategory });
  for (const u of fresh) if (u.category === "dependency" && u.flagged) materializePackage(u, { cache, out });
  const units = [...existing, ...fresh];
  writeJsonl(join(out, "units-key.jsonl"), units);
  writeJsonl(join(out, "queue-A.jsonl"), queueFor(units, seed, "A"));
  writeJsonl(join(out, "queue-B.jsonl"), queueFor(units, seed, "B"));
  return { out, population, units };
}

async function main() {
  const args = parseArgs(process.argv.slice(2), ["allow-file"]);
  if (!args.corpus) {
    console.error("usage: node bench/real-world/units.js --corpus <manifest.json> [--cache <dir>] [--seed <s>] [--unflagged-per-category <n>] [--calibration-per-category <n>] [--calibration-round <n>]");
    process.exit(2);
  }
  const cache = cacheDir(args.cache);
  const manifest = readManifest(resolve(args.corpus), { allowFile: !!args["allow-file"] });
  // Default seed: the manifest's own hash, so the draw is fixed by the corpus.
  const seed = args.seed || sha256(JSON.stringify(manifest));
  const config = {};
  if (args["unflagged-per-category"]) config.unflaggedPerCategory = Number(args["unflagged-per-category"]);
  if (args["calibration-per-category"]) config.calibrationPerCategory = Number(args["calibration-per-category"]);
  const round = Number(args["calibration-round"] || 1);
  const { out, units } = buildStudy({ manifest, cache, seed, config, calibrationRound: round });
  if (round > 1) {
    const fresh = units.filter((u) => u.round === round).length;
    console.log(`Calibration round ${round}: ${fresh} fresh units${fresh ? "" : " (nothing left to draw; the corpus is too small for another round)"}.`);
  }
  const count = (set) => CATEGORIES.map((c) => `${c} ${units.filter((u) => u.set === set && u.category === c && u.flagged).length}+${units.filter((u) => u.set === set && u.category === c && !u.flagged).length}`).join(", ");
  console.log(`Study folder: ${out}`);
  console.log(`Analysis (flagged+unflagged): ${count("analysis")}`);
  console.log(`Calibration: ${count("calibration")}`);
}

if (isMain(import.meta.url)) main().catch((e) => { console.error(e.message); process.exit(1); });
