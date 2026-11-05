/**
 * Python dependency inputs for `penthera deps`, read offline.
 *
 * Turns requirements*.txt, poetry.lock, uv.lock, Pipfile.lock and pdm.lock into
 * the same flat package list the npm lockfile reader produces: name (PEP 503
 * normalised), exact version when pinned, artifact hashes (the key into pip's
 * and uv's caches), dev flag, and a local path for path dependencies. Nothing
 * here runs pip, resolves ranges or touches the network.
 */
import { readFileSync, existsSync, readdirSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { parseToml } from "./toml.js";
import { assertSafeRef, readOnlyGit } from "../lockfile.js";
import { parseJson } from "../../json-text.js";

/** PEP 503 name normalisation: runs of -, _ and . become -, lower case. */
export const normalizeName = (n) => String(n || "").trim().replace(/[-_.]+/g, "-").toLowerCase();

const LOCKFILES = ["uv.lock", "poetry.lock", "pdm.lock", "Pipfile.lock"];

/** Requirements files in a folder, most specific lock-like name first. */
function requirementsFiles(dir) {
  let names;
  try { names = readdirSync(dir); } catch { return []; }
  return names.filter((f) => /^requirements.*\.txt$/i.test(f)).sort((a, b) => a.length - b.length || a.localeCompare(b));
}

/**
 * Find the Python dependency inputs in a folder.
 * @returns {{ lockfile: string|null, kind: string|null, requirements: string[] }}
 */
export function findPythonInputs(dir) {
  for (const f of LOCKFILES) {
    const p = join(dir, f);
    if (existsSync(p)) return { lockfile: p, kind: f, requirements: [] };
  }
  const reqs = requirementsFiles(dir).map((f) => join(dir, f));
  if (reqs.length) return { lockfile: reqs[0], kind: "requirements.txt", requirements: reqs };
  return { lockfile: null, kind: null, requirements: [] };
}

/** True when a folder looks like a Python project (lockfile, requirements, pyproject or a venv). */
export function looksLikePythonProject(dir) {
  if (findPythonInputs(dir).lockfile) return true;
  return ["pyproject.toml", "setup.py", "setup.cfg", "Pipfile"].some((f) => existsSync(join(dir, f)));
}

const pkg = (o) => ({
  name: normalizeName(o.name),
  displayName: o.name,
  version: o.version || null,
  path: o.path,
  hashes: [...new Set((o.hashes || []).filter(Boolean).map((h) => String(h).toLowerCase()))].sort(),
  files: o.files || [],
  dev: !!o.dev,
  optional: false,
  local: o.local || null,
  link: false,
  ecosystem: "pypi",
});

// ── requirements.txt ──────────────────────────────────────────────────────

/** Join backslash continuations, keep the first line number of each logical line. */
function logicalLines(text) {
  const out = [];
  let buf = "";
  let start = 0;
  text.replace(/\r\n/g, "\n").split("\n").forEach((line, i) => {
    if (!buf) start = i + 1;
    if (/\\\s*$/.test(line)) { buf += line.replace(/\\\s*$/, " "); return; }
    out.push({ text: buf + line, line: start });
    buf = "";
  });
  if (buf) out.push({ text: buf, line: start });
  return out;
}

/**
 * Parse a requirements file. Pinned lines (`name==1.2.3`) get a version;
 * `--hash=sha256:...` options are kept; ranges get version null (the venv, if
 * any, supplies the installed version). `-r other.txt` is followed once.
 */
export function parseRequirements(text, { file = "requirements.txt", baseDir = ".", seen = new Set() } = {}) {
  const out = [];
  const direct = new Set();
  // pip-compile and `uv export` annotate each pin with "# via <parents>". A pin
  // whose parents include something that is not another pin here (the
  // project itself, or "-r requirements.in") is a direct dependency.
  let compiled = false;
  const via = new Map();
  let lastPin = null;
  const lines = logicalLines(text);
  for (let k = 0; k < lines.length; k++) {
    const { text: raw, line } = lines[k];
    const v = raw.match(/^\s*#\s+via\b\s*(.*)$/) || (lastPin && via.has(lastPin) && raw.match(/^\s*#\s{2,}(\S.*)$/));
    if (v) {
      compiled = true;
      if (lastPin) {
        if (!via.has(lastPin)) via.set(lastPin, []);
        if (v[1].trim()) via.get(lastPin).push(v[1].trim());
      }
      continue;
    }
    const s = raw.replace(/(^|\s)#.*$/, "").trim();
    if (!s) continue;
    const inc = s.match(/^(?:-r|--requirement)\s*=?\s*(\S+)/);
    if (inc) {
      const p = resolve(baseDir, inc[1]);
      if (!seen.has(p) && existsSync(p)) {
        seen.add(p);
        const sub = parseRequirements(readFileSync(p, "utf-8"), { file: inc[1], baseDir: dirname(p), seen });
        out.push(...sub.packages);
        for (const n of sub.direct) direct.add(n);
      }
      continue;
    }
    if (/^-/.test(s) && !/^(?:-e|--editable)\b/.test(s)) continue; // --index-url, -c, --find-links...
    const hashes = [...s.matchAll(/--hash[=\s]+(sha256|sha384|sha512):([0-9a-fA-F]+)/g)].map((m) => `${m[1]}:${m[2]}`);
    const spec = s.replace(/\s--\S+(?:[=\s]+\S+)?/g, "").replace(/^(?:-e|--editable)\s+/, "").trim();
    // Local path or file URL dependency.
    if (/^(?:\.{1,2}[\\/]|\/|file:)/.test(spec)) {
      const local = resolve(baseDir, spec.replace(/^file:(?:\/\/)?/, "").replace(/[#[].*$/, ""));
      const egg = spec.match(/#egg=([\w.-]+)/);
      out.push(pkg({ name: egg ? egg[1] : local.split(/[\\/]/).pop(), version: null, path: `${file}:${line}`, local }));
      lastPin = out[out.length - 1].name;
      continue;
    }
    const m = spec.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(?:@\s*(\S+)|(===?)\s*([^\s;,]+)|[^;]*)?/);
    if (!m) continue;
    const version = m[4] && !/[*]/.test(m[5]) ? m[5] : null;
    const p = pkg({ name: m[1], version, path: `${file}:${line}`, hashes });
    p.line = line;
    p.url = m[3] || null;
    out.push(p);
    lastPin = p.name;
  }
  const pinned = new Set(out.map((p) => p.name));
  for (const p of out) {
    const parents = via.get(p.name) || [];
    if (!compiled || parents.length === 0 || parents.some((x) => /^-[rc]\s/.test(x) || !pinned.has(normalizeName(x.split(/\s/)[0])))) direct.add(p.name);
  }
  return { packages: out, direct: [...direct].sort() };
}

// ── TOML lockfiles ────────────────────────────────────────────────────────

function lineIndex(text, re) {
  const lines = text.split("\n");
  const idx = new Map();
  let current = null;
  for (let i = 0; i < lines.length; i++) {
    if (/^\[\[package\]\]/.test(lines[i])) current = i + 1;
    const m = lines[i].match(re);
    if (m && current) idx.set(normalizeName(m[1]), current);
  }
  return idx;
}

function pyprojectDirect(dir) {
  const p = join(dir, "pyproject.toml");
  if (!existsSync(p)) return { names: [], dev: [] };
  let t;
  try { t = parseToml(readFileSync(p, "utf-8")); } catch { return { names: [], dev: [] }; }
  const reqName = (s) => normalizeName(String(s).match(/^\s*([A-Za-z0-9][A-Za-z0-9._-]*)/)?.[1] || "");
  const names = new Set();
  const dev = new Set();
  for (const s of t.project?.dependencies || []) names.add(reqName(s));
  for (const list of Object.values(t.project?.["optional-dependencies"] || {})) for (const s of list || []) names.add(reqName(s));
  for (const list of Object.values(t["dependency-groups"] || {})) for (const s of list || []) if (typeof s === "string") dev.add(reqName(s));
  const poetry = t.tool?.poetry || {};
  for (const n of Object.keys(poetry.dependencies || {})) if (n !== "python") names.add(normalizeName(n));
  for (const n of Object.keys(poetry["dev-dependencies"] || {})) dev.add(normalizeName(n));
  for (const g of Object.values(poetry.group || {})) for (const n of Object.keys(g?.dependencies || {})) dev.add(normalizeName(n));
  for (const list of Object.values(t.tool?.pdm?.["dev-dependencies"] || {})) for (const s of list || []) dev.add(reqName(s));
  names.delete("");
  dev.delete("");
  return { names: [...names], dev: [...dev] };
}

const hashOf = (f) => (typeof f === "string" ? f : f?.hash);

function parseUvLock(text, dir) {
  const t = parseToml(text);
  const lines = lineIndex(text, /^name\s*=\s*"([^"]+)"/);
  const all = Array.isArray(t.package) ? t.package : [];
  const roots = all.filter((p) => p.source && (p.source.virtual !== undefined || p.source.editable !== undefined) && (p.source.virtual === "." || p.source.editable === "."));
  const direct = new Set();
  const devNames = new Set();
  for (const r of roots) {
    for (const d of r.dependencies || []) direct.add(normalizeName(d.name));
    for (const list of Object.values(r["optional-dependencies"] || {})) for (const d of list) direct.add(normalizeName(d.name));
    for (const list of Object.values(r["dev-dependencies"] || {})) for (const d of list) { direct.add(normalizeName(d.name)); devNames.add(normalizeName(d.name)); }
  }
  // Dev-only: reachable from dev roots but not from the main dependencies.
  const byName = new Map(all.map((p) => [normalizeName(p.name), p]));
  const reach = (starts) => {
    const seen = new Set();
    const stack = [...starts];
    while (stack.length) {
      const n = stack.pop();
      if (seen.has(n)) continue;
      seen.add(n);
      const p = byName.get(n);
      for (const d of p?.dependencies || []) stack.push(normalizeName(d.name));
      for (const list of Object.values(p?.["optional-dependencies"] || {})) for (const d of list) stack.push(normalizeName(d.name));
    }
    return seen;
  };
  const prodSet = reach([...direct].filter((n) => !devNames.has(n)));
  const packages = [];
  for (const p of all) {
    if (roots.includes(p)) continue;
    const src = p.source || {};
    const local = src.path || src.directory || src.editable || src.virtual;
    const files = [...(p.wheels || []), ...(p.sdist ? [p.sdist] : [])].map((f) => ({ url: f.url || null, file: f.path || f.filename || (f.url ? f.url.split("/").pop() : null), hash: f.hash || null }));
    packages.push(pkg({
      name: p.name, version: p.version, path: `uv.lock:${lines.get(normalizeName(p.name)) || 1}`,
      hashes: files.map((f) => f.hash), files,
      dev: devNames.size > 0 && !prodSet.has(normalizeName(p.name)),
      local: local ? resolve(dir, local) : null,
    }));
  }
  return { packages, direct: [...direct].sort(), version: t.version ?? null };
}

function parsePoetryLock(text, dir) {
  const t = parseToml(text);
  const lines = lineIndex(text, /^name\s*=\s*"([^"]+)"/);
  const meta = t.metadata || {};
  const legacyHashes = meta.files || {}; // lock-version 1.x keeps hashes here
  const pp = pyprojectDirect(dir);
  const devOnly = new Set(pp.dev.filter((n) => !pp.names.includes(n)));
  const packages = (Array.isArray(t.package) ? t.package : []).map((p) => {
    const files = (p.files || legacyHashes[p.name] || []).map((f) => ({ file: f.file || null, hash: hashOf(f), url: null }));
    const src = p.source || {};
    const local = (src.type === "directory" || src.type === "file") && src.url ? resolve(dir, src.url) : null;
    const groups = p.groups || (p.category ? [p.category === "dev" ? "dev" : "main"] : ["main"]);
    return pkg({
      name: p.name, version: p.version, path: `poetry.lock:${lines.get(normalizeName(p.name)) || 1}`,
      hashes: files.map((f) => f.hash), files,
      dev: !groups.includes("main") || devOnly.has(normalizeName(p.name)),
      local,
    });
  });
  return { packages, direct: [...new Set([...pp.names, ...pp.dev])].sort(), version: meta["lock-version"] ?? null };
}

function parsePdmLock(text, dir) {
  const t = parseToml(text);
  const lines = lineIndex(text, /^name\s*=\s*"([^"]+)"/);
  const pp = pyprojectDirect(dir);
  const packages = (Array.isArray(t.package) ? t.package : []).map((p) => {
    const files = (p.files || []).map((f) => ({ file: f.file || f.url || null, hash: hashOf(f), url: f.url || null }));
    const groups = p.groups || ["default"];
    return pkg({
      name: p.name, version: p.version, path: `pdm.lock:${lines.get(normalizeName(p.name)) || 1}`,
      hashes: files.map((f) => f.hash), files,
      dev: !groups.includes("default"),
      local: p.path ? resolve(dir, p.path) : null,
    });
  });
  return { packages, direct: [...new Set([...pp.names, ...pp.dev])].sort(), version: t.metadata?.lock_version ?? null };
}

function parsePipfileLock(text, dir) {
  const lock = parseJson(text);
  if (!lock || typeof lock !== "object" || Array.isArray(lock)) throw new Error("Pipfile.lock: not a JSON object");
  const lines = text.split("\n");
  const lineOf = (name) => {
    const i = lines.findIndex((l) => l.includes(`"${name}": {`));
    return i === -1 ? 1 : i + 1;
  };
  const packages = [];
  for (const [section, dev] of [["default", false], ["develop", true]]) {
    for (const [name, v] of Object.entries(lock[section] || {})) {
      if (!v) continue;
      const version = typeof v.version === "string" ? v.version.replace(/^===?/, "") : null;
      const local = v.path ? resolve(dir, v.path) : null;
      const existing = packages.find((p) => p.name === normalizeName(name));
      if (existing) { if (!dev) existing.dev = false; continue; }
      packages.push(pkg({ name, version, path: `Pipfile.lock:${lineOf(name)}`, hashes: v.hashes || [], dev, local }));
    }
  }
  let direct = [];
  const pipfile = join(dir, "Pipfile");
  if (existsSync(pipfile)) {
    try {
      const t = parseToml(readFileSync(pipfile, "utf-8"));
      direct = [...Object.keys(t.packages || {}), ...Object.keys(t["dev-packages"] || {})].map(normalizeName);
    } catch { /* unreadable Pipfile: no direct list */ }
  }
  return { packages, direct: [...new Set(direct)].sort(), version: lock._meta?.["pipfile-spec"] ?? null };
}

/**
 * Parse a Python dependency input by kind.
 * @returns {{ packages, direct: string[], version, kind }}
 */
export function parsePythonInput(text, kind, dir, file = kind) {
  let r;
  try {
    if (kind === "uv.lock") r = parseUvLock(text, dir);
    else if (kind === "poetry.lock") r = parsePoetryLock(text, dir);
    else if (kind === "pdm.lock") r = parsePdmLock(text, dir);
    else if (kind === "Pipfile.lock") r = parsePipfileLock(text, dir);
    else r = { ...parseRequirements(text, { file, baseDir: dir }), version: null };
  } catch (e) {
    // One clear error naming the file, whatever the parser hit (malformed or
    // hostile input): the tree cannot be read, so nothing is reported clean.
    throw new Error(`${file} could not be parsed: ${e.message}`);
  }
  // One entry per name@version (requirements files can repeat a name across -r includes).
  const seen = new Set();
  const packages = r.packages.filter((p) => {
    const k = `${p.name}@${p.version}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  }).sort((a, b) => a.name.localeCompare(b.name) || String(a.version).localeCompare(String(b.version)));
  return { ...r, packages, kind };
}

/** Read and parse the Python inputs found in a folder; null when there are none. */
export function readPythonInputs(dir) {
  const found = findPythonInputs(dir);
  if (!found.lockfile) return null;
  if (found.kind !== "requirements.txt") {
    return { ...parsePythonInput(readFileSync(found.lockfile, "utf-8"), found.kind, dir), file: found.lockfile };
  }
  // Several requirements files (requirements.txt, requirements-dev.txt): merge, dev by file name.
  const packages = [];
  const direct = new Set();
  for (const f of found.requirements) {
    const name = f.slice(dirname(f).length + 1);
    const r = parsePythonInput(readFileSync(f, "utf-8"), "requirements.txt", dir, name);
    const isDev = /dev|test|lint|doc/i.test(name);
    for (const p of r.packages) {
      const existing = packages.find((x) => x.name === p.name && x.version === p.version);
      if (existing) { if (!isDev) existing.dev = false; continue; }
      packages.push({ ...p, dev: isDev });
    }
    for (const n of r.direct) direct.add(n);
  }
  return { packages, direct: [...direct].sort(), version: null, kind: "requirements.txt", file: found.lockfile, files: found.requirements };
}

/**
 * Read the Python inputs at a git ref (for `--base <ref>`). Only `git show`.
 * @returns parsed inputs, or null when the ref has none
 */
export function readPythonInputsAtRef(dir, ref) {
  assertSafeRef(ref);
  const git = readOnlyGit(dir);
  const prefix = git(["rev-parse", "--show-prefix"]).trim();
  const show = (f) => { try { return git(["show", "--end-of-options", `${ref}:${prefix}${f}`]); } catch { return null; } };
  for (const f of LOCKFILES) {
    const text = show(f);
    if (text != null) return { ...parsePythonInput(text, f, dir), file: f };
  }
  let names = [];
  try { names = git(["ls-tree", "--name-only", "--end-of-options", ref, `./${prefix}`]).split("\n").map((s) => s.slice(prefix.length)); } catch { /* not a tree */ }
  const req = names.filter((f) => /^requirements.*\.txt$/i.test(f)).sort((a, b) => a.length - b.length)[0];
  if (req) return { ...parsePythonInput(show(req) || "", "requirements.txt", dir, req), file: req };
  return null;
}
