/**
 * E11 benchmark 1: Penthera's secret rules on Samsung CredData (protocol § 4.1, § 6.1).
 */
import { readFileSync, readdirSync, lstatSync, existsSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { CACHE, cloneAt, sh, pentheraRepo, fmt } from "./common.mjs";
import { inSplit } from "./split.mjs";

export const PIN = "c49ed10629d9139eb88b71b6b7ab4054fff806ea";
const DIR = join(CACHE, "creddata");

// § 4.1: first family whose categories a row carries.
const PROVIDER = new Set(["AWS Client ID", "AWS Multi", "Github Classic Token", "Google API Key", "Stripe Credentials", "Anthropic API Key", "Perplexity API Key"]);
const PROVIDER_RE = /OpenAI|Hugging ?Face|Groq|Replicate|xAI|LangSmith|Pinecone|OpenRouter/i;
export function family(cats) {
  if (cats.some((c) => PROVIDER.has(c) || PROVIDER_RE.test(c))) return "provider";
  if (cats.includes("PEM Private Key")) return "private-key";
  if (cats.includes("Password")) return "password";
  if (cats.includes("API")) return "api-key";
  if (cats.includes("Key") || cats.includes("Secret")) return "partial";
  return "out";
}
export const PRIMARY = ["provider", "private-key", "password", "api-key"];

/** Minimal RFC 4180 CSV parser (quoted fields, doubled quotes). */
export function parseCsv(text) {
  const rows = [];
  let row = [], field = "", q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"' && text[i + 1] === '"') { field += '"'; i++; }
      else if (c === '"') q = false;
      else field += c;
    } else if (c === '"') q = true;
    else if (c === ",") { row.push(field); field = ""; }
    else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(field); field = "";
      if (row.length > 1 || row[0] !== "") rows.push(row);
      row = [];
    } else field += c;
  }
  if (field !== "" || row.length) { row.push(field); rows.push(row); }
  const [head, ...body] = rows;
  return body.map((r) => Object.fromEntries(head.map((h, i) => [h, r[i] ?? ""])));
}

export function loadMeta(dir = DIR) {
  const out = [];
  for (const f of readdirSync(join(dir, "meta")).filter((x) => x.endsWith(".csv")).sort()) {
    for (const r of parseCsv(readFileSync(join(dir, "meta", f), "utf-8"))) {
      out.push({ id: r.Id, file: r.FilePath, repo: r.RepoName, ls: +r.LineStart, le: +r.LineEnd, gt: r.GroundTruth, cats: r.Category.split(":").filter(Boolean) });
    }
  }
  return out;
}

export async function fetchData() {
  const head = cloneAt("https://github.com/Samsung/CredData", DIR, PIN);
  if (!existsSync(join(DIR, "data"))) {
    // CredData's own procedure (its README): a virtualenv with its requirements, then download_data.py.
    const py = process.env.PYTHON || "python3";
    if (!existsSync(join(DIR, ".venv"))) sh(py, ["-m", "venv", join(DIR, ".venv")]);
    sh(join(DIR, ".venv", "bin", "pip"), ["install", "-q", "-r", "requirements.txt"], { cwd: DIR });
    sh(join(DIR, ".venv", "bin", "python"), ["download_data.py", "--data_dir", "data", "--jobs", "8"], { cwd: DIR, stdio: ["ignore", "inherit", "inherit"] });
  }
  return { commit: head };
}

function walk(dir, out = []) {
  for (const e of readdirSync(dir).sort()) {
    const p = join(dir, e);
    const st = lstatSync(p);
    if (st.isSymbolicLink()) continue;
    if (st.isDirectory()) walk(p, out);
    else if (st.isFile()) out.push(p);
  }
  return out;
}

function lineIndex(text) {
  const starts = [0];
  for (let i = text.indexOf("\n"); i !== -1; i = text.indexOf("\n", i + 1)) starts.push(i + 1);
  return (idx) => {
    let lo = 0, hi = starts.length - 1;
    while (lo < hi) { const m = (lo + hi + 1) >> 1; if (starts[m] <= idx) lo = m; else hi = m - 1; }
    return lo + 1;
  };
}

// Which rules the repo scan runs on a file, from the engine itself when it
// says (E11b pass 1 onward: "all", "shapes" or null); older engines read a
// file by its path only and run every rule on it.
async function rulesFor() {
  const m = await import("../../lib/whitebox/secrets.js");
  if (m.secretRulesFor) return (inRepo, abs) => m.secretRulesFor(inRepo, head(abs));
  return (inRepo) => (m.isSecretScanTarget(inRepo) ? "all" : null);
}
function head(abs) {
  try { return readFileSync(abs, "utf-8").slice(0, 256); } catch { return ""; }
}

/** Offline step: rule hits on every file, and the CLI's reported findings per repo. */
export async function scan() {
  const { findSecretsInText } = await import("../../lib/whitebox/secrets.js");
  const scopeOf = await rulesFor();
  const data = join(DIR, "data");
  const hits = [];
  const keep = inSplit("creddata");
  const repos = readdirSync(data).filter((r) => lstatSync(join(data, r)).isDirectory()).sort();
  let files = 0;
  for (const repo of repos) {
    for (const p of walk(join(data, repo))) {
      const rel = relative(DIR, p).split(sep).join("/");
      if (!keep(rel)) continue;
      files++;
      const inRepo = relative(join(data, repo), p).split(sep).join("/");
      const scope = scopeOf(inRepo, p);
      let text;
      try { text = readFileSync(p, "utf-8"); } catch { continue; }
      const lineOf = lineIndex(text);
      // rulesOnly replays every rule on every file; the primary run keeps the
      // hits the scan itself would report (read, and the rule allowed there).
      const shapes = new Set(scope === "shapes" ? findSecretsInText(text, { shapesOnly: true, path: inRepo }).map((h) => h.index) : []);
      for (const h of findSecretsInText(text, { path: inRepo })) hits.push({ file: rel, line: lineOf(h.index), rule: h.name, read: scope === "all" || (scope === "shapes" && shapes.has(h.index)) });
    }
  }
  const cli = [];
  const cliErrors = [];
  for (const repo of repos) {
    try {
      const r = pentheraRepo(join(data, repo));
      for (const f of r.findings || []) {
        if (f.category !== "secrets" || f.severity === "info" || !f.line) continue;
        const file = `data/${repo}/${f.url}`;
        // Since E11b pass 1 (A6) a finding lists every line its rule hit in the file.
        if (keep(file)) for (const line of f.lines || [f.line]) cli.push({ file, line, rule: f.title.replace(/ in source$/, "") });
      }
    } catch (e) {
      cliErrors.push(`${repo}: ${e.message}`);
    }
  }
  return { repos: repos.length, files, hits, cli, cliErrors };
}

/** Score one set of hits against the labelled rows (§ 6.1). */
export function scoreHits(rows, hits) {
  const byFile = new Map();
  for (const r of rows) {
    if (!byFile.has(r.file)) byFile.set(r.file, []);
    byFile.get(r.file).push(r);
  }
  const units = new Map();
  for (const h of hits) {
    const k = `${h.file}:${h.line}`;
    if (!units.has(k)) units.set(k, { file: h.file, line: h.line, rules: new Set() });
    units.get(k).rules.add(h.rule);
  }
  const prec = { all: { labelled: 0, correct: 0, units: 0 } };
  const hitLines = new Map();
  for (const u of units.values()) {
    if (!hitLines.has(u.file)) hitLines.set(u.file, new Set());
    hitLines.get(u.file).add(u.line);
    const m = (byFile.get(u.file) || []).filter((r) => u.line >= r.ls && u.line <= r.le);
    const labelled = m.length > 0;
    const correct = m.some((r) => r.gt === "T");
    for (const key of ["all", ...[...u.rules].map((r) => `rule:${r}`)]) {
      prec[key] ||= { labelled: 0, correct: 0, units: 0 };
      prec[key].units++;
      if (labelled) prec[key].labelled++;
      if (correct) prec[key].correct++;
    }
  }
  const rec = {};
  const bump = (key, found) => {
    rec[key] ||= { n: 0, found: 0 };
    rec[key].n++;
    if (found) rec[key].found++;
  };
  // Units (E11b § 3). Row: one labelled credential, a multi-line range (a PEM
  // block) counted once; E11's unit. Line: every labelled line of a T row, so a
  // 30-line key is 30 units and only lines with a hit count as found. File: a
  // file with at least one in-scope T row; "any" = some secret hit anywhere in
  // the file (what a user of the CLI sees), "matched" = a hit on one of its T rows.
  const files = new Map();
  for (const r of rows) {
    if (r.gt !== "T") continue;
    const lines = hitLines.get(r.file);
    let found = false;
    if (lines) for (let l = r.ls; l <= r.le && !found; l++) found = lines.has(l);
    const fam = family(r.cats);
    bump(`family:${fam}`, found);
    if (PRIMARY.includes(fam)) {
      bump("primary", found);
      if (r.read) bump("primary:read", found);
      else bump("primary:unread", found);
      for (const c of r.cats) bump(`category:${c}`, found);
      bump(`ext:${r.ext}`, found);
      for (let l = r.ls; l <= r.le; l++) {
        const hit = !!lines?.has(l);
        bump("line:primary", hit);
        bump(`line:family:${fam}`, hit);
      }
      const f = files.get(r.file) || { fams: new Set(), matched: new Set() };
      f.fams.add(fam);
      if (found) f.matched.add(fam);
      files.set(r.file, f);
    }
  }
  for (const [file, f] of files) {
    const any = hitLines.has(file);
    bump("file:any", any);
    bump("file:matched", f.matched.size > 0);
    for (const fam of f.fams) {
      bump(`file:any:${fam}`, any);
      bump(`file:matched:${fam}`, f.matched.has(fam));
    }
  }
  // File-level precision: a file with a hit is correct when it holds any T row.
  const tFiles = new Set(rows.filter((r) => r.gt === "T").map((r) => r.file));
  prec.file = { units: hitLines.size, labelled: hitLines.size, correct: [...hitLines.keys()].filter((f) => tFiles.has(f)).length };
  return { prec, rec };
}

export async function score(raw) {
  const scopeOf = await rulesFor();
  const rows = loadMeta().map((r) => {
    const inRepo = r.file.split("/").slice(2).join("/");
    const base = inRepo.split("/").pop();
    return { ...r, read: !!scopeOf(inRepo, join(DIR, r.file)), ext: base.includes(".") ? base.slice(base.lastIndexOf(".")) : "(none)" };
  });
  const keep = inSplit("creddata");
  const rowsIn = rows.filter((r) => keep(r.file));
  const missing = rowsIn.filter((r) => !existsSync(join(DIR, r.file)));
  const kept = rowsIn.filter((r) => existsSync(join(DIR, r.file)));
  const runs = {
    primary: scoreHits(kept, raw.hits.filter((h) => h.read)),
    rulesOnly: scoreHits(kept, raw.hits),
    asReported: scoreHits(kept, raw.cli),
  };
  const gt = (g) => kept.filter((r) => r.gt === g).length;
  const fams = {};
  for (const r of kept.filter((x) => x.gt === "T")) fams[family(r.cats)] = (fams[family(r.cats)] || 0) + 1;
  const outCats = {};
  for (const r of kept.filter((x) => x.gt === "T" && family(x.cats) === "out")) for (const c of r.cats) outCats[c] = (outCats[c] || 0) + 1;
  return {
    rows: rowsIn.length, missingRows: missing.length, missingFiles: new Set(missing.map((r) => r.file)).size,
    T: gt("T"), F: gt("F"), X: gt("X"), families: fams, outCategories: outCats,
    extRead: Object.fromEntries([...new Set(kept.map((x) => x.ext))].map((e) => [e, kept.find((x) => x.ext === e).read])),
    repos: raw.repos, files: raw.files, cliErrors: raw.cliErrors, runs,
  };
}

const p = (o) => fmt(o.correct, o.labelled);
const lower = (o) => fmt(o.correct, o.units);
const r = (o) => (o ? fmt(o.found, o.n) : "n/a");

export function markdown(s) {
  const L = [];
  L.push(`Rows: ${s.rows} labelled (${s.T} T, ${s.F} F, ${s.X} X after dropping ${s.missingRows} rows in ${s.missingFiles} files that did not download). Repos scanned: ${s.repos}, files: ${s.files}. CLI errors: ${s.cliErrors.length}.`, "");
  L.push("| Run | Precision (labelled units) | Strict precision (all units) | Recall, primary scope | Recall, files the scan reads |", "|---|---|---|---|---|");
  for (const [name, run] of Object.entries(s.runs)) {
    L.push(`| ${name} | ${p(run.prec.all)} | ${lower(run.prec.all)} | ${r(run.rec.primary)} | ${r(run.rec["primary:read"])} |`);
  }
  const P = s.runs.primary;
  L.push("", "Recall by unit (in scope):", "", "| Run | Row (one credential) | Line | File, hit on a T row | File, any hit | File precision |", "|---|---|---|---|---|---|");
  for (const [name, run] of Object.entries(s.runs)) L.push(`| ${name} | ${r(run.rec.primary)} | ${r(run.rec["line:primary"])} | ${r(run.rec["file:matched"])} | ${r(run.rec["file:any"])} | ${p(run.prec.file)} |`);
  L.push("", "Recall by family and unit (primary run; last column: the CLI as reported):", "", "| Family | In scope | Row | Line | File, hit on a T row | File, any hit (CLI) |", "|---|---|---|---|---|---|");
  for (const f of [...PRIMARY, "partial", "out"]) L.push(`| ${f} | ${PRIMARY.includes(f) ? "yes" : "no"} | ${r(P.rec[`family:${f}`])} | ${r(P.rec[`line:family:${f}`])} | ${r(P.rec[`file:matched:${f}`])} | ${r(s.runs.asReported.rec[`file:any:${f}`])} |`);
  L.push("", "Precision by Penthera rule (primary run):", "", "| Rule | Precision (labelled) | Strict precision | Units |", "|---|---|---|---:|");
  for (const [k, v] of Object.entries(P.prec).filter(([k]) => k.startsWith("rule:")).sort((a, b) => b[1].units - a[1].units)) {
    L.push(`| ${k.slice(5)} | ${p(v)} | ${lower(v)} | ${v.units} |`);
  }
  L.push("", "Recall by CredData category, in-scope rows (primary run; a row with several categories counts under each):", "", "| Category | Recall |", "|---|---|");
  for (const [k, v] of Object.entries(P.rec).filter(([k]) => k.startsWith("category:")).sort((a, b) => b[1].n - a[1].n)) L.push(`| ${k.slice(9)} | ${r(v)} |`);
  L.push("", "Recall by file extension, in-scope rows, top 15 (primary run):", "", "| Extension | Read by the scan | Recall |", "|---|---|---|");
  for (const [k, v] of Object.entries(P.rec).filter(([k]) => k.startsWith("ext:")).sort((a, b) => b[1].n - a[1].n).slice(0, 15)) L.push(`| ${k.slice(4)} | ${s.extRead[k.slice(4)] ? "yes" : "no"} | ${r(v)} |`);
  L.push("", "Out-of-scope true rows by category (top 20):", "", "| Category | T rows |", "|---|---:|");
  for (const [k, v] of Object.entries(s.outCategories).sort((a, b) => b[1] - a[1]).slice(0, 20)) L.push(`| ${k} | ${v} |`);
  return L.join("\n");
}
