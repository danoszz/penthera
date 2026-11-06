/**
 * Python dependency trees for `penthera deps`.
 *
 * Loads what a Python project depends on (a lockfile or requirements file, a
 * virtualenv, or both), finds each package's files offline (the venv, pip's
 * and uv's caches, local path dependencies) and scans them with the Python
 * capability scanner. lib/deps/index.js turns the result into findings,
 * diffs and reports exactly as it does for npm.
 */
import { existsSync, statSync, realpathSync } from "node:fs";
import { join, relative, resolve, dirname, basename } from "node:path";
import { readPythonInputs, readPythonInputsAtRef, parsePythonInput, findPythonInputs, normalizeName, looksLikePythonProject } from "./lockfiles.js";
import { findVenv, sitePackagesDirs, listInstalled, sourceFromPipCache, sourceFromUvCache, sourceFromLocalPath, pipCacheDir, uvCacheDir, readRegular } from "./source.js";
import { scanPythonPackage, pthImportLines, scanPythonSource } from "./capabilities.js";
import { parseToml } from "./toml.js";
import { RISKY_FOR_INSTALL } from "../capabilities.js";
import { loadIocs } from "../iocs.js";

export { looksLikePythonProject };

/** True when a folder has something `penthera deps` can read for Python. */
export function hasPythonInputs(root, venvOpt) {
  return !!(findPythonInputs(root).lockfile || venvOpt || findVenv(root, null));
}

const relTo = (root, p) => {
  const r = relative(root, p).split("\\").join("/");
  return r === "" ? "." : r;
};
/** Display path: relative to the working directory unless that climbs out of it. */
const display = (p) => {
  const r = relTo(process.cwd(), p);
  return r.startsWith("..") ? p : r;
};

/** The project's own name (so a venv-only scan does not list the project as a dependency). */
function projectName(root) {
  try {
    const t = parseToml(readRegular(join(root, "pyproject.toml"), "utf-8"));
    const n = t.project?.name || t.tool?.poetry?.name;
    return n ? normalizeName(n) : null;
  } catch {
    return null;
  }
}

/** Every installed distribution in a venv, with Requires-Dist names. */
function installedDists(venv, root) {
  const dists = [];
  const unownedPth = [];
  const refused = [];
  // site-packages paths are real paths; compare like with like (macOS /var -> /private/var).
  try { root = realpathSync(root); } catch { /* keep as given */ }
  for (const site of sitePackagesDirs(venv)) {
    const list = listInstalled(site);
    const r = relTo(root, site);
    const prefix = `${r.startsWith("..") ? site : r}/`;
    for (const d of list) {
      let requires = [];
      try {
        const md = readRegular(join(site, d.distInfo, d.distInfo.endsWith(".dist-info") ? "METADATA" : "PKG-INFO"), "utf-8");
        const head = md.replace(/\r\n/g, "\n").split("\n\n")[0];
        requires = [...head.matchAll(/^Requires-Dist:\s*([A-Za-z0-9][A-Za-z0-9._-]*)([^\n]*)$/gm)]
          .filter((m) => !/extra\s*==/.test(m[2])).map((m) => normalizeName(m[1]));
      } catch { /* no metadata */ }
      dists.push({ ...d, site, prefix, requires });
    }
    for (const f of list.unownedPth) unownedPth.push({ site, prefix, file: f });
    refused.push(...list.refused);
  }
  return { dists, unownedPth, refused };
}

/** Distributions nobody else requires: the closest thing a bare venv has to direct dependencies. */
function venvRoots(dists) {
  const required = new Set(dists.flatMap((d) => d.requires));
  return dists.filter((d) => !required.has(d.name)).map((d) => d.name);
}

/**
 * Scan one Python package list. Results are cached by name@version+hashes.
 * @param {object[]} pkgs from the lockfile reader (or venv listing)
 * @param {{ dists: object[] }|null} env installed distributions to read from
 */
function scanPyTree(pkgs, env, ctx) {
  const installed = new Map();
  for (const d of env?.dists || []) {
    if (!installed.has(d.name)) installed.set(d.name, d);
  }
  return pkgs.map((p) => {
    const inst = installed.get(p.name);
    const version = p.version || inst?.version || null;
    const key = `${p.name}@${version}#${p.hashes.join(",")}#${p.local || ""}#${env?.id || ""}`;
    if (!ctx.cache.has(key)) {
      let src = null;
      let prefix = `${p.name}-${version}/`;
      if (p.local && existsSync(p.local)) {
        src = sourceFromLocalPath(p.local);
        prefix = `${relTo(ctx.root, p.local)}/`;
      } else if (inst?.unscanned && (!p.version || inst.version === p.version)) {
        ctx.cache.set(key, { unscanned: inst.unscanned, source: "installed" });
      } else if (inst && (!p.version || inst.version === p.version)) {
        src = inst.source;
        prefix = inst.prefix;
      } else if (version) {
        const q = { ...p, version };
        src = sourceFromPipCache(q, ctx.pipCache) || sourceFromUvCache(q, ctx.uvCache);
      }
      if (!ctx.cache.has(key)) ctx.cache.set(key, src ? { ...scanPythonPackage(src, { prefix, iocs: ctx.iocs }), source: src.kind } : null);
    }
    const r = ctx.cache.get(key);
    // Fail closed: a package that could not be fully read has unknown
    // capabilities (null), not an empty set.
    const unscanned = r?.unscanned || null;
    return {
      ...p,
      version,
      source: r?.source || null,
      capabilities: r && !unscanned ? r.capabilities : null,
      unscanned,
      installScripts: r?.installScripts || {},
      installRisk: r?.installRisk || [],
      exfil: r?.exfil || [],
      importRun: r?.importRun || [],
      chatKey: r?.chatKey || [],
      remoteCode: r?.remoteCode || [],
      startupHooks: r?.startupHooks || [],
      modified: r?.modified || [],
      iocHits: r?.iocHits || [],
      filesScanned: r?.filesScanned || 0,
    };
  });
}

/** Python inputs for a path passed to --diff: a folder, a lockfile or a requirements file. */
function inputsFromPath(p) {
  if (statSync(p).isDirectory()) return readPythonInputs(p);
  const name = basename(p);
  const kind = ["uv.lock", "poetry.lock", "pdm.lock", "Pipfile.lock"].includes(name) ? name : "requirements.txt";
  return { ...parsePythonInput(readRegular(p, "utf-8"), kind, dirname(p), name), file: p };
}

/** Packages from a venv listing, shaped like lockfile entries. */
function packagesFromVenv(env, root, skipName) {
  return env.dists.filter((d) => d.name !== skipName).map((d) => ({
    name: d.name,
    displayName: d.displayName,
    version: d.version,
    path: `${d.prefix}${d.distInfo}`,
    hashes: [],
    files: [],
    dev: false,
    optional: false,
    local: null,
    link: false,
    ecosystem: "pypi",
  }));
}

/** Findings-ready info about .pth files no installed distribution owns. */
function unownedStartupHooks(env) {
  const out = [];
  for (const u of env?.unownedPth || []) {
    let text;
    try { text = readRegular(join(u.site, u.file), "utf-8"); } catch { continue; }
    for (const l of pthImportLines(text)) {
      const caps = Object.keys(scanPythonSource(l.text, `${u.prefix}${u.file}`).caps).filter((c) => RISKY_FOR_INSTALL.includes(c) || c === "shell");
      out.push({ file: `${u.prefix}${u.file}`, line: l.line, snippet: l.text.slice(0, 160), risk: caps });
    }
  }
  return out;
}

/**
 * Load and scan the Python tree of a project.
 * @returns {{ lockfile, format, lockfileVersion, tree, direct, venv, unownedHooks, ctx }}
 */
export function loadPythonTree(root, opts = {}) {
  const refused = [];
  const inputs = readPythonInputs(root, { refused });
  const venv = findVenv(root, opts.venv || null);
  if (!inputs && !venv && !refused.length) {
    throw new Error(`No Python lockfile, requirements*.txt or virtualenv in ${root}. penthera deps reads uv.lock, poetry.lock, pdm.lock, Pipfile.lock or requirements*.txt, or an installed .venv (pass another with --venv).`);
  }
  const env = venv ? { id: venv, ...installedDists(venv, root) } : null;
  // A METADATA or PKG-INFO that was not read keeps its package (unscanned) and makes the scan incomplete.
  if (env) refused.push(...env.refused);
  const ctx = {
    root,
    cache: new Map(),
    pipCache: opts.pipCacheDir || pipCacheDir(),
    uvCache: opts.uvCacheDir || uvCacheDir(),
    iocs: loadIocs(),
  };
  const self = projectName(root);
  // Every input refused and no venv: an empty tree, and the refusals are said.
  const pkgs = inputs ? inputs.packages : env ? packagesFromVenv(env, root, self) : [];
  const tree = scanPyTree(pkgs, env, ctx);
  let direct = inputs?.direct || [];
  if (!direct.length && env) direct = venvRoots(env.dists.filter((d) => d.name !== self));
  const format = inputs ? `${inputs.kind}${inputs.version != null ? ` v${inputs.version}` : ""}${venv ? " + venv" : ""}` : venv ? "virtualenv" : "nothing read";
  return {
    lockfile: display(inputs ? inputs.file : venv || refused[0].skipped),
    lockfiles: inputs?.files?.map(display) || null,
    format,
    lockfileVersion: inputs?.version ?? null,
    venv: venv ? display(venv) : null,
    tree,
    direct,
    unownedHooks: unownedStartupHooks(env),
    refused,
    ctx,
  };
}

/**
 * Load and scan the base tree for --diff (path) or --base (git ref), reusing
 * scans of versions both trees share. Old versions come from the base
 * folder's venv when --diff points at one, else pip's or uv's cache by hash.
 */
export function loadPythonBase(root, opts, current) {
  let inputs = null;
  let env = null;
  let label;
  if (opts.base) {
    inputs = readPythonInputsAtRef(root, opts.base);
    label = opts.base;
    // No Python inputs at the base: every Python package is new in this change.
    if (!inputs) return { tree: [], label, needOld: 0 };
  } else {
    const p = resolve(opts.diff);
    if (!existsSync(p)) throw new Error(`--diff path not found: ${opts.diff}`);
    inputs = inputsFromPath(p);
    const dir = statSync(p).isDirectory() ? p : dirname(p);
    // A venv beside the project's own lockfile is the new tree, not the old one.
    const venv = resolve(dir) === resolve(root) ? null : findVenv(dir, null);
    if (venv) env = { id: venv, ...installedDists(venv, root) };
    label = opts.diff;
    if (!inputs && !env) return { tree: [], label, needOld: 0 };
  }
  const oldPkgs = inputs ? inputs.packages : packagesFromVenv(env, root, projectName(root));
  const byVersion = new Map(current.tree.map((p) => [`${p.name}@${p.version}`, p]));
  const newNames = new Set(current.tree.map((p) => p.name));
  const needOld = oldPkgs.filter((p) => !byVersion.has(`${p.name}@${p.version}`) && newNames.has(p.name));
  const scanned = new Map(scanPyTree(needOld, env, current.ctx).map((p) => [`${p.name}@${p.version}`, p]));
  const tree = oldPkgs.map((p) => {
    const k = `${p.name}@${p.version}`;
    if (scanned.has(k)) return scanned.get(k);
    const same = byVersion.get(k);
    return { ...p, capabilities: same?.capabilities || {}, installScripts: same?.installScripts || {} };
  });
  return { tree, label, needOld: needOld.length };
}
