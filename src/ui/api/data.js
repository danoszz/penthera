/**
 * The dashboard's data source for a real machine: report JSON files in the
 * chosen reports dir, evidence bundles below it, and the local learning store.
 *
 * File access rule: only paths inside the chosen roots (project dirs, reports
 * dir, Penthera home) are ever read. Symlinks are skipped, every path is
 * realpath'd and re-checked, and no API takes a file path from the browser:
 * findings and bundles are addressed by ids this module hands out.
 */
import { readdirSync, readFileSync, lstatSync, realpathSync, existsSync, statSync, mkdirSync, openSync, writeSync, closeSync, constants as FS } from "node:fs";
import { join, resolve, relative, sep, isAbsolute, dirname } from "node:path";
import { createHash } from "node:crypto";
import { openMemory, buildViews, buildHistory } from "../../../lib/memory/index.js";
import { referencesFor } from "../../../lib/references.js";
import { planFixes, redactPlan } from "../../../lib/fix/index.js";
import { verifyEvidence, MANIFEST, SIGNATURE, SCHEMA as EVIDENCE_SCHEMA } from "../../report/evidence.js";
import { writeEvidence } from "../../cli/report-outputs.js";
import { formatAudienceReport, AUDIENCES } from "../../report/audience.js";
import {
  classify, buildOverview, buildFindings, locateFinding, findingDetail, buildDeps, buildAi, memoryStats, loopSummary,
  explainFinding, buildScanHistory, latestScan, slug,
} from "./summarize.js";

const MAX_REPORT_BYTES = 25 * 1024 * 1024;
const MAX_FILES = 400;
const CACHE_MS = 1500;

/** True when `p` is `root` or inside it (both absolute, already resolved). */
export function isInside(root, p) {
  const rel = relative(root, p);
  return rel === "" || (!!rel && !rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel));
}

/** Resolve real paths for the allowed roots (missing roots are kept as given). */
export function realRoots(paths) {
  return [...new Set(paths.filter(Boolean).map((p) => {
    const abs = resolve(p);
    try { return realpathSync(abs); } catch { return abs; }
  }))];
}

/**
 * Resolve a user-supplied directory against the allowed roots. Returns the
 * real path, or throws with a message that names the fix.
 */
export function confineDir(input, roots) {
  if (typeof input !== "string" || !input.trim() || input.length > 4096 || input.includes("\0")) {
    throw new Error("Enter a project folder path.");
  }
  let real;
  try {
    real = realpathSync(resolve(roots[0] || ".", input.trim()));
  } catch {
    throw new Error(`Folder not found: ${input}`);
  }
  if (!statSync(real).isDirectory()) throw new Error(`Not a folder: ${input}`);
  if (!roots.some((r) => isInside(r, real))) {
    throw new Error("That folder is outside the project folders this dashboard was started with. Restart with `penthera ui --project <dir>`.");
  }
  return real;
}

/**
 * Throws unless no existing component of `target` below `root` is a symlink.
 * The same rule lib/fix/apply.js applies to fix diffs: a planted symlink
 * (reports/evidence -> ~/.ssh) must never redirect a write out of the folder.
 */
export function assertNoSymlinks(root, target) {
  const rel = relative(root, target);
  if (rel.startsWith("..") || isAbsolute(rel)) throw new Error(`Refusing to write ${target}: it is outside ${root}`);
  let cur = root;
  for (const seg of rel.split(sep).filter(Boolean)) {
    cur = join(cur, seg);
    let st;
    try { st = lstatSync(cur); } catch (e) { if (e.code === "ENOENT") return; throw e; }
    if (st.isSymbolicLink()) throw new Error(`Refusing to write through a symlink: ${relative(root, cur)}`);
  }
}

/**
 * Write a new file in `dir` (which must be `root` or below it): exclusive
 * create, never through a symlink, never over an existing file. A name is a
 * single path segment.
 */
export function writeNewFile(root, dir, name, content) {
  if (typeof name !== "string" || !name || name.includes("/") || name.includes("\\") || name.includes("\0") || name === "." || name === "..") {
    throw new Error(`Bad file name ${JSON.stringify(name)}`);
  }
  const target = join(dir, name);
  assertNoSymlinks(root, target);
  mkdirSync(dir, { recursive: true });
  assertNoSymlinks(root, target); // again, after mkdir
  const fd = openSync(target, FS.O_WRONLY | FS.O_CREAT | FS.O_EXCL | (FS.O_NOFOLLOW || 0), 0o644);
  try {
    const buf = Buffer.from(content, "utf-8");
    let off = 0;
    while (off < buf.length) off += writeSync(fd, buf, off, buf.length - off);
  } finally {
    closeSync(fd);
  }
  return target;
}

const idFor = (s) => createHash("sha256").update(s).digest("hex").slice(0, 16);

export function createDataSource({ projects, reportsDir, home, memoryRoot, settings, version = "dev" }) {
  const projectRoots = realRoots(projects);
  const reportsReal = realRoots([reportsDir])[0];
  const roots = realRoots([...projects, reportsDir, home]);
  let cache = null;

  function safeRead(path) {
    let real;
    try { real = realpathSync(path); } catch { return null; }
    if (!roots.some((r) => isInside(r, real))) return null;
    const st = lstatSync(real);
    if (!st.isFile() || st.size > MAX_REPORT_BYTES) return null;
    return readFileSync(real);
  }

  /** Report files (top level of the reports dir) and evidence bundles (up to two levels down). */
  function scan() {
    if (cache && Date.now() - cache.at < CACHE_MS) return cache;
    const out = { scans: [], deps: [], agents: [], installs: [], loops: [], bundles: [], at: Date.now() };
    if (!existsSync(reportsReal)) { cache = out; return out; }
    let seen = 0;
    const walk = (dir, depth) => {
      let entries;
      try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
      if (entries.some((e) => e.isFile() && e.name === MANIFEST) && depth > 0) {
        out.bundles.push(dir);
        return;
      }
      for (const e of entries) {
        if (seen >= MAX_FILES) return;
        if (e.isSymbolicLink()) continue;
        const p = join(dir, e.name);
        if (e.isDirectory() && depth < 2 && !e.name.startsWith(".") && e.name !== "node_modules") walk(p, depth + 1);
        else if (e.isFile() && depth === 0 && e.name.endsWith(".json")) {
          seen++;
          const buf = safeRead(p);
          if (!buf) continue;
          let data;
          try { data = JSON.parse(buf.toString("utf-8")); } catch { continue; }
          const kind = classify(data);
          if (!kind) continue;
          const rec = { name: e.name, mtime: statSync(p).mtimeMs, data };
          ({ scan: out.scans, deps: out.deps, agents: out.agents, install: out.installs, loop: out.loops })[kind].push(rec);
        }
      }
    };
    walk(reportsReal, 0);
    const byTime = (a, b) => (Date.parse(a.data.timestamp || a.data.loopRun?.startedAt) || a.mtime) - (Date.parse(b.data.timestamp || b.data.loopRun?.startedAt) || b.mtime);
    for (const k of ["scans", "deps", "agents", "installs", "loops"]) out[k].sort(byTime);
    cache = out;
    return out;
  }

  /** Every memory project under the memory root, verified; a broken chain shows as broken, never as data. */
  function memory() {
    if (!existsSync(memoryRoot)) return [];
    const list = [];
    for (const e of readdirSync(memoryRoot, { withFileTypes: true })) {
      if (!e.isDirectory() || !/^[0-9a-f]{64}$/.test(e.name)) continue;
      const mem = openMemory(e.name, { root: memoryRoot });
      const chain = mem.verify();
      const events = chain.ok ? mem.events() : [];
      list.push(memoryStats({
        id: e.name,
        label: mem.meta()?.label,
        chain,
        views: chain.ok ? buildViews(events) : null,
        history: chain.ok ? buildHistory(events) : null,
      }));
    }
    return list;
  }

  return {
    demo: false,
    roots,
    projectRoots,

    meta() {
      return { reportsDir: reportsReal, projects: projectRoots, memoryRoot };
    },

    overview() {
      const s = scan();
      return buildOverview({ scans: s.scans, memory: memory(), runs: [...s.loops].reverse() });
    },

    findings() {
      return buildFindings(scan().scans);
    },

    async finding(id, project) {
      const hit = locateFinding(scan().scans, id, project);
      if (!hit) return null;
      const detail = findingDetail(hit.finding);
      const sources = referencesFor(hit.finding).map((r) => ({ cite: r.cite, url: r.url }));
      let fix = null;
      // A fix preview needs the repo the finding came from, and only inside a chosen project dir.
      const target = typeof hit.report.data.target === "string" ? hit.report.data.target : null;
      const repo = hit.report.data.repo || (target && !/^https?:/i.test(target) ? target : null);
      if (repo) {
        try {
          const dir = confineDir(repo, projectRoots);
          const { plans } = await planFixes(dir, [hit.finding]);
          if (plans[0]) {
            const p = redactPlan(plans[0]);
            fix = { recipe: p.recipe, title: p.title, confidence: p.confidence, files: p.files, diff: p.diff.slice(0, 20000) };
          }
        } catch { /* no preview outside the project dirs */ }
      }
      return { ...detail, id, project, sources, fix, file: hit.report.name, explain: explainFinding(hit.finding, hit.report.data) };
    },

    history(project, a, b) {
      return buildScanHistory(scan().scans, project, a, b);
    },

    /** "Export evidence for an auditor": a bundle from the latest report of a project, into <reports>/evidence/. */
    createEvidence(project) {
      const latest = latestScan(scan().scans, project);
      if (!latest) return null;
      const dir = join(reportsReal, "evidence", `${slug(project)}-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}`);
      if (dirname(dirname(dir)) !== reportsReal) return null;
      assertNoSymlinks(reportsReal, dir); // reports/evidence must not be a planted symlink
      writeEvidence(latest.data, { evidence: dir }, { version, mdOpts: { version }, argv: ["ui", "evidence", "create"] });
      cache = null;
      return { id: idFor(dir), path: relative(reportsReal, dir) };
    },

    /** The developer, owner or auditor report for the latest scan of a project, as Markdown. */
    audienceReport(project, audience) {
      if (!AUDIENCES.includes(audience)) return null;
      const latest = latestScan(scan().scans, project);
      return latest ? formatAudienceReport(latest.data, audience, { version }) : null;
    },

    deps() {
      const s = scan();
      return buildDeps({ deps: s.deps, installs: s.installs });
    },

    ai() {
      return buildAi(scan().agents);
    },

    memory,

    runs() {
      return [...scan().loops].reverse().slice(0, 20).map((r) => loopSummary(r.data));
    },

    evidence() {
      return scan().bundles.map((dir) => {
        let manifest = null;
        try { manifest = JSON.parse(safeRead(join(dir, MANIFEST))?.toString("utf-8") || "null"); } catch { /* shown as unreadable */ }
        const ok = manifest?.schema === EVIDENCE_SCHEMA;
        return {
          id: idFor(dir),
          path: relative(reportsReal, dir) || ".",
          target: ok ? String(manifest.target ?? "").slice(0, 500) : null,
          generatedAt: ok ? manifest.generated_at || null : null,
          tool: ok ? `${manifest.tool?.name || "penthera"} ${manifest.tool?.version || ""}`.trim() : null,
          artifacts: ok && Array.isArray(manifest.artifacts) ? manifest.artifacts.length : 0,
          signed: existsSync(join(dir, SIGNATURE)),
          readable: ok,
        };
      });
    },

    verifyEvidence(id) {
      const dir = scan().bundles.find((d) => idFor(d) === id);
      if (!dir) return null;
      const r = verifyEvidence(dir);
      return {
        id,
        ok: r.ok,
        problems: r.problems.slice(0, 50),
        files: r.files.slice(0, 200).map((f) => ({ path: f.path, ok: f.ok, reason: f.reason || null })),
        signature: r.signature ? { ok: r.signature.ok, status: r.signature.status, detail: r.signature.detail } : null,
      };
    },

    /** Persist a finished loop run next to the other reports. */
    saveLoopRun(loopRun) {
      try {
        const name = `loop-${String(loopRun.startedAt || new Date().toISOString()).replace(/[:.]/g, "-")}.json`;
        writeNewFile(reportsReal, reportsReal, name, JSON.stringify({ loopRun }, null, 2) + "\n");
        cache = null;
        return name;
      } catch {
        return null;
      }
    },

    /** A scan, deps or agents report from a run started here: a new file, never through a symlink. */
    writeReport(name, result) {
      writeNewFile(reportsReal, reportsReal, name, JSON.stringify(result, null, 2) + "\n");
      cache = null;
      return name;
    },

    settings,
  };
}
