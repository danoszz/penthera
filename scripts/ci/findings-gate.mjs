#!/usr/bin/env node
/**
 * The findings gate: no finding the base branch reports may be gone, or lower,
 * on this branch.
 *
 * It writes each case of the rule corpus (tests/corpus/) to a temp folder,
 * scans it with the base branch's scanner and with this tree's, and compares.
 * A finding the base reports and this tree does not is "lost"; one this tree
 * reports at a lower severity is "lowered". Either fails the gate, unless
 * tests/corpus/findings-gate.allow.json names it with a reason (a false alarm
 * removed on purpose). New findings on this tree are fine.
 *
 * The corpus holds every case once more per decoy: a harmless line named like
 * a check. So a change that lets a look-alike silence a rule fails here.
 *
 *   node scripts/ci/findings-gate.mjs                    # against the merge-base with origin/main
 *   node scripts/ci/findings-gate.mjs --base v2.4.0
 *   node scripts/ci/findings-gate.mjs --target-dir /path/to/other/tree
 *
 * Both scanners run in this process, offline, and read only the temp folders.
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/** What a finding is, apart from its wording: the rule and the file. */
export function findingKey(f) {
  const rule = f.templateId || f.pattern || `${f.category || "finding"}:${String(f.title || "").split(":")[0]}`;
  return `${rule} in ${f.file || f.url || "?"}`;
}

/** Findings as Map(key -> highest severity rank). */
function byKey(findings) {
  const m = new Map();
  for (const f of findings) {
    const k = findingKey(f);
    m.set(k, Math.max(m.get(k) ?? -1, RANK[f.severity] ?? 0));
  }
  return m;
}
const nameOf = (rank) => Object.keys(RANK).find((k) => RANK[k] === rank) || "info";

/** What `target` lost or lowered against `base`: [{ kind, key, was, now }]. */
export function compareFindings(base, target) {
  const b = byKey(base);
  const t = byKey(target);
  const out = [];
  for (const [key, was] of b) {
    if (!t.has(key)) out.push({ kind: "lost", key, was: nameOf(was), now: null });
    else if (t.get(key) < was) out.push({ kind: "lowered", key, was: nameOf(was), now: nameOf(t.get(key)) });
  }
  return out;
}

/** The scanners of the tree at `dir`: { scanRepo, scanAgents }. */
export async function loadScanners(dir) {
  const load = (rel) => import(pathToFileURL(join(dir, rel)).href);
  const [{ scanRepo }, { scanAgents }] = await Promise.all([load("src/scan-repo.js"), load("lib/agents/index.js")]);
  return {
    scanRepo: async (d) => (await scanRepo(d, { onPhase: () => {} })).findings,
    scanAgents: async (d) => (await scanAgents(d, { home: false })).findings,
  };
}

/** The corpus of the tree at `dir`: [{ name, kind: "repo" | "agents", files }]. */
export async function loadCorpus(dir = ROOT) {
  const load = (rel) => import(pathToFileURL(join(dir, rel)).href);
  const [{ SECRET_CASES, AGENT_CASES }, { codeCases }] = await Promise.all([load("tests/corpus/cases.js"), load("tests/corpus/code-cases.js")]);
  return [
    // Every secret in one repo: the secret rules read a file at a time.
    { name: "secrets", kind: "repo", files: Object.fromEntries(SECRET_CASES.map((c) => [c.path, c.text])) },
    ...AGENT_CASES.map((c) => ({ name: `agents: ${c.name}`, kind: "agents", files: c.files })),
    ...codeCases().map((c) => ({ name: `code: ${c.name}`, kind: "repo", files: c.files })),
  ];
}

function materialize(parent, i, files) {
  const dir = join(parent, `case-${i}`);
  for (const [path, text] of Object.entries(files)) {
    const file = join(dir, path);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, text);
  }
  return dir;
}

/**
 * Run the corpus through both scanners. Returns { cases, problems, allowed }:
 * `problems` are losses no allow entry covers, `allowed` those one does.
 */
export async function runGate({ base, target, corpus, allow = [] }) {
  const work = mkdtempSync(join(tmpdir(), "penthera-findings-gate-"));
  const problems = [];
  const allowed = [];
  try {
    for (const [i, c] of corpus.entries()) {
      const dir = materialize(work, i, c.files);
      const scan = c.kind === "agents" ? "scanAgents" : "scanRepo";
      const was = await base[scan](dir);
      let now;
      try {
        now = await target[scan](dir);
      } catch (e) {
        // A scan that throws reports nothing: everything the base found is lost.
        now = [];
        if (!was.length) problems.push({ case: c.name, kind: "crashed", key: String(e?.message || e), was: null, now: null });
      }
      for (const d of compareFindings(was, now)) {
        const rule = d.key.split(" in ")[0];
        const entry = allow.find((a) => a.case === c.name && a.rule === rule);
        (entry ? allowed : problems).push({ case: c.name, ...d, ...(entry ? { reason: entry.reason } : {}) });
      }
    }
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
  return { cases: corpus.length, problems, allowed };
}

/** The allow list, checked: every entry names a case, a rule and a reason of 20 characters or more. */
export function readAllow(file = join(ROOT, "tests/corpus/findings-gate.allow.json")) {
  if (!existsSync(file)) return [];
  const list = JSON.parse(readFileSync(file, "utf-8"));
  for (const a of list) {
    if (!a.case || !a.rule || String(a.reason || "").trim().length < 20) throw new Error(`findings-gate.allow.json: each entry needs a case, a rule and a reason of 20 characters or more (${JSON.stringify(a)})`);
  }
  return list;
}

const git = (args) => {
  const r = spawnSync("git", args, { cwd: ROOT, encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] });
  return r.status === 0 ? r.stdout.trim() : null;
};

/** The base tree's scanner files, unpacked under `dir`. Returns the commit, or null. */
function extractBase(ref, dir) {
  const sha = git(["merge-base", "HEAD", ref]) || git(["rev-parse", "--verify", `${ref}^{commit}`]);
  if (!sha) return null;
  // Relative names, run from `dir`: GNU tar (Git for Windows) reads "C:\..." as host:path.
  const a = spawnSync("git", ["archive", "--format=tar", "-o", join(dir, "base.tar"), sha, "bin", "src", "lib", "package.json"], { cwd: ROOT, stdio: "ignore" });
  if (a.status !== 0) return null;
  const t = spawnSync("tar", ["-xf", "base.tar"], { cwd: dir, stdio: "ignore" });
  return t.status === 0 ? sha : null;
}

async function main(argv) {
  const arg = (name) => (argv.includes(name) ? argv[argv.indexOf(name) + 1] : null);
  const targetDir = resolve(arg("--target-dir") || ROOT);
  const ref = arg("--base") || (process.env.GITHUB_BASE_REF ? `origin/${process.env.GITHUB_BASE_REF}` : "origin/main");
  const work = mkdtempSync(join(tmpdir(), "penthera-findings-base-"));
  try {
    const baseDir = arg("--base-dir") ? resolve(arg("--base-dir")) : work;
    const sha = arg("--base-dir") ? "a folder" : extractBase(ref, work);
    if (!sha) {
      console.error(`findings gate: ${ref} is not a commit here. Fetch it (git fetch origin main), or name one: --base <ref>.`);
      return 2;
    }
    const [base, target, corpus] = await Promise.all([loadScanners(baseDir), loadScanners(targetDir), loadCorpus(ROOT)]);
    const { cases, problems, allowed } = await runGate({ base, target, corpus, allow: readAllow() });
    const from = sha === "a folder" ? baseDir : `${ref} (${sha.slice(0, 8)})`;
    for (const p of allowed) console.log(`allowed  ${p.case}: ${p.kind} ${p.key} (${p.reason})`);
    if (!problems.length) {
      console.log(`findings gate: ${cases} cases, nothing ${from} reports is lost or lowered here.`);
      return 0;
    }
    console.error(`findings gate: ${problems.length} finding${problems.length === 1 ? "" : "s"} that ${from} reports ${problems.length === 1 ? "is" : "are"} lost or lowered here.\n`);
    for (const p of problems) {
      console.error(p.kind === "lowered" ? `  lowered  ${p.case}: ${p.key}, ${p.was} -> ${p.now}` : `  ${p.kind.padEnd(7)}  ${p.case}: ${p.key}${p.was ? ` (${p.was})` : ""}`);
    }
    console.error(`\nA rule that stopped firing on a real case is a bypass. Fix the rule, or, if the base was wrong to report it, add { case, rule, reason } to tests/corpus/findings-gate.allow.json.`);
    return 1;
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exit(await main(process.argv.slice(2)));
}
