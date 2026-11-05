/**
 * `penthera deps`: offline, deterministic dependency risk scanning for npm and
 * Python (PyPI). The Python side (lib/deps/python) loads uv/poetry/pdm/Pipfile
 * lockfiles, requirements files and virtualenvs; everything below the tree
 * loaders (findings, diff, typosquats, reports) is shared.
 *
 * Reads package-lock.json, statically scans every installed package for what
 * it can do (lib/deps/capabilities.js), checks names for typosquats against a
 * vendored list, and, with --diff / --base, reports packages that are new or
 * that gained capabilities in an upgrade. Results are ordinary Penthera
 * findings (category "dependency-risk", source "deps-scan"), so the terminal,
 * Markdown, JSON and SARIF outputs all work unchanged.
 *
 * Offline by default. Old versions for the diff come from the base tree's
 * node_modules or npm's local content cache, verified against the lockfile
 * integrity. `--online` is the only network use (lib/deps/online.js).
 */
import { existsSync, readFileSync, statSync } from "node:fs";
import { join, dirname, relative, resolve, basename } from "node:path";
import { findLockfile, readLockfile, parseLockfile, directDependencies, readLockfileAtRef } from "./lockfile.js";
import { DirSource, sourceFromNpmCache, npmCacheDir } from "./source.js";
import { scanPackage, CAPABILITY_ORDER } from "./capabilities.js";
import { diffTrees } from "./diff.js";
import { findTyposquats, loadPopular } from "./typosquat.js";
import { checkLicenses } from "./license.js";
import { hasPythonInputs, loadPythonTree, loadPythonBase } from "./python/index.js";
import { loadIocs } from "./iocs.js";
import { riskFindings, unownedHookFindings, diffFindings, typosquatFindings, iocFindings, registryFindings } from "./findings.js";
import { parseJson } from "../json-text.js";

// ── Resolving package contents ────────────────────────────────────────────

function installedVersion(dir) {
  try {
    return parseJson(readFileSync(join(dir, "package.json"), "utf-8")).version || null;
  } catch {
    return null;
  }
}

/**
 * Find a package's files offline: the tree's node_modules (when the installed
 * version matches the lockfile), else npm's cache by integrity.
 */
function resolveSource(pkg, treeRoot, cacheDirs) {
  if (treeRoot) {
    const dir = join(treeRoot, pkg.path);
    if (existsSync(dir) && installedVersion(dir) === pkg.version) return new DirSource(dir);
  }
  if (!pkg.integrity) return null;
  for (const d of cacheDirs) {
    const src = sourceFromNpmCache(pkg.integrity, d);
    if (src) return src;
  }
  return null;
}

/** Scan a list of lockfile packages. Results cached by name@version+integrity. */
function scanTree(pkgs, treeRoot, ctx) {
  return pkgs.map((p) => {
    const key = `${p.name}@${p.version}#${p.integrity || ""}`;
    if (!ctx.cache.has(key)) {
      const src = resolveSource(p, treeRoot, ctx.cacheDirs);
      ctx.cache.set(key, src ? { ...scanPackage(src, { prefix: `${p.path}/`, iocs: ctx.iocs }), source: src.kind } : null);
    }
    const r = ctx.cache.get(key);
    // Fail closed: a package that could not be fully read has unknown
    // capabilities (null), not an empty set.
    const unscanned = r?.unscanned || null;
    const installScripts = r?.installScripts || {};
    // npm records hasInstallScript from the registry manifest. If it says there
    // is a script and the files we read have none, the scan saw different files
    // than npm will install (or the lockfile was edited): never "clean". One
    // known, benign cause is exempt: a native package that had binding.gyp when
    // it was published (so the registry added the implicit node-gyp install)
    // but ships only prebuilt .node binaries without it, like fsevents 2.x.
    // With no binding.gyp and no script in the files, npm runs nothing there.
    const prebuiltOnly = !!r?.capabilities?.native;
    const scriptMismatch = !!(r && !unscanned && p.hasInstallScript && Object.keys(installScripts).length === 0 && !prebuiltOnly);
    return {
      ...p,
      source: r?.source || null,
      capabilities: r && !unscanned ? r.capabilities : null,
      unscanned,
      partlyRead: r?.partlyRead || [],
      scriptMismatch,
      installScripts,
      installRisk: r?.installRisk || [],
      exfil: r?.exfil || [],
      remoteCode: r?.remoteCode || [],
      sendsOut: r?.sendsOut || [],
      remoteDeps: r?.remoteDeps || [],
      filesScanned: r?.filesScanned || 0,
      iocHits: r?.iocHits || [],
    };
  });
}

// ── Entry point ───────────────────────────────────────────────────────────

function summarize(tree) {
  const counts = {};
  for (const id of CAPABILITY_ORDER) counts[id] = 0;
  for (const p of tree) for (const id of Object.keys(p.capabilities || {})) counts[id]++;
  return counts;
}

/** Load the old tree for --diff (lockfile path or project folder) or --base (git ref). */
function loadBase(root, opts) {
  if (opts.baseLock) return { lock: opts.baseLock, treeRoot: null, label: opts.baseLabel || "base" };
  if (opts.base) {
    return { lock: readLockfileAtRef(root, opts.base), treeRoot: null, label: opts.base };
  }
  const p = resolve(opts.diff);
  if (!existsSync(p)) throw new Error(`--diff path not found: ${opts.diff}`);
  const isDir = statSync(p).isDirectory();
  const lockPath = isDir ? findLockfile(p) : p;
  if (!lockPath) throw new Error(`No package-lock.json in ${opts.diff}`);
  const treeRoot = dirname(lockPath);
  // A lockfile beside the project's own node_modules describes another tree;
  // only trust node_modules that sit next to the old lockfile.
  return { lock: readLockfile(lockPath), treeRoot: treeRoot === resolve(root) ? null : treeRoot, label: opts.diff };
}

/**
 * npm: package-lock.json plus node_modules or npm's cache.
 * @param {string} root project folder containing package-lock.json
 * @param {object} opts see scanDeps(). lock / baseLock: lockfile objects to use
 *   instead of reading them (the pre-commit hook passes the staged and HEAD
 *   lockfiles); changedOnly: in diff mode, scan only packages that changed (fast
 *   path); licensePolicy: from normalizeLicensePolicy(), adds category "license"
 *   findings
 */
async function scanNpm(root, opts = {}) {
  const started = Date.now();
  const onPhase = opts.onPhase || (() => {});
  const lockPath = opts.lock ? join(root, "package-lock.json") : findLockfile(root);
  if (!lockPath) throw new Error(`No package-lock.json in ${root}. penthera deps reads the lockfile; run \`npm install --package-lock-only\` first.`);
  const lock = opts.lock || readLockfile(lockPath);
  const ctx = { cache: new Map(), cacheDirs: [].concat(opts.cacheDir || npmCacheDir()), iocs: loadIocs() };
  const keep = (p) => !p.link && p.version && (!opts.prod || !p.dev);

  const diffing = !!(opts.diff || opts.base || opts.baseLock);
  const base = diffing ? loadBase(root, opts) : null;
  let pkgs = parseLockfile(lock).filter(keep);
  if (diffing && opts.changedOnly) {
    const before = new Set(parseLockfile(base.lock).map((p) => `${p.name}@${p.version}`));
    pkgs = pkgs.filter((p) => !before.has(`${p.name}@${p.version}`));
  }
  onPhase(`Scanning ${pkgs.length} packages from ${basename(lockPath)} (offline)`);
  const tree = scanTree(pkgs, opts.treeRoot || root, ctx);
  const direct = new Set(directDependencies(lock));

  let diff = null;
  if (diffing) {
    const oldPkgs = parseLockfile(base.lock).filter(keep);
    const byVersion = new Map(tree.map((p) => [`${p.name}@${p.version}`, p]));
    const newNames = new Set(tree.map((p) => p.name));
    // Only old versions that are gone but whose name remains need inspecting:
    // a version present in both trees has the same contents (same lockfile
    // integrity), and a removed name is not compared.
    const needOld = oldPkgs.filter((p) => !byVersion.has(`${p.name}@${p.version}`) && newNames.has(p.name));
    onPhase(`Comparing against ${base.label}: ${needOld.length} replaced version(s) to inspect`);
    const oldScanned = new Map(scanTree(needOld, base.treeRoot, ctx).map((p) => [p.path, p]));
    const oldTree = oldPkgs.map((p) => oldScanned.get(p.path)
      || { ...p, capabilities: byVersion.get(`${p.name}@${p.version}`)?.capabilities || {}, installScripts: byVersion.get(`${p.name}@${p.version}`)?.installScripts || {} });
    diff = diffTrees(oldTree, tree);
  }

  // --online: registry metadata, and old tarballs the cache did not have.
  let online = null;
  const findings = [];
  if (opts.online) {
    const { checkRegistry, fetchTarballSource } = await import("./online.js");
    const changed = diff ? [...diff.added.map((a) => a.pkg), ...diff.upgraded.map((u) => ({ ...u.pkg, previous: u.from }))] : [];
    const items = diff ? changed : tree.filter((p) => direct.has(p.name));
    onPhase(`--online: fetching registry metadata for ${items.length} package(s) (the only network use)`);
    const results = await checkRegistry(items.map((p) => ({ name: p.name, version: p.version, previous: p.previous })), { fetchImpl: opts.fetchImpl, now: opts.now });
    online = { checked: items.length, unreachable: [...results.values()].filter((r) => !r.reachable).length, fetchedTarballs: 0 };
    if (diff) {
      const oldPkgs = parseLockfile(base.lock);
      for (const u of diff.upgraded.filter((x) => x.unavailable === "old")) {
        const oldPkg = oldPkgs.find((p) => p.name === u.name && p.version === u.from);
        // Verified against the base lockfile's integrity before anything is read.
        const src = await fetchTarballSource(oldPkg?.resolved, oldPkg?.integrity, { fetchImpl: opts.fetchImpl });
        if (!src) continue;
        const old = scanPackage(src, { prefix: `${oldPkg.path}/` });
        if (old.unscanned) continue; // still not comparable
        online.fetchedTarballs++;
        const o = new Set(Object.keys(old.capabilities));
        const n = new Set(Object.keys(u.pkg.capabilities || {}));
        u.gained = CAPABILITY_ORDER.filter((id) => n.has(id) && !o.has(id));
        u.lost = CAPABILITY_ORDER.filter((id) => o.has(id) && !n.has(id));
        u.unavailable = null;
      }
    }
    findings.push(...registryFindings(results, new Map(tree.map((p) => [`${p.name}@${p.version}`, p]))));
  }

  // In diff mode, report on what changed; otherwise on the whole tree.
  const inScope = diff
    ? new Set([...diff.added.map((a) => a.pkg), ...diff.upgraded.map((u) => u.pkg)])
    : new Set(tree);
  for (const p of tree) if (inScope.has(p)) findings.push(...riskFindings(p));
  // A known-bad package is reported wherever it sits, diff or not.
  findings.push(...iocFindings(tree, ctx.iocs));
  if (diff) findings.push(...diffFindings(diff));

  // Names you chose (direct deps), or names that are new in this change. A
  // transitive dependency of an unchanged tree was picked by its parent's
  // maintainers long ago; flagging those is mostly noise.
  const nameScope = diff ? diff.added.map((a) => a.name) : tree.filter((p) => direct.has(p.name)).map((p) => p.name);
  const typos = findTyposquats(nameScope);
  findings.push(...typosquatFindings(typos, new Map(tree.map((p) => [p.name, p])), direct));

  // License policy: the whole tree, or in diff mode only what changed.
  let licenses = null;
  if (opts.licensePolicy) {
    const scope = tree.filter((p) => inScope.has(p));
    onPhase(`Checking ${scope.length} package license(s) against the policy`);
    const r = checkLicenses(scope, opts.licensePolicy, { treeRoot: opts.treeRoot || root, lockfileHasLicenses: (lock.lockfileVersion || 1) >= 2 });
    findings.push(...r.findings);
    licenses = r.summary;
  }

  // Optional packages for other platforms (esbuild-style binaries) are expected to be absent.
  const unavailable = tree.filter((p) => !p.capabilities && !p.unscanned && !p.optional);
  const skippedOptional = tree.filter((p) => !p.capabilities && !p.unscanned && p.optional).length;
  const rel = (p) => {
    const r = relative(process.cwd(), p);
    return r === "" ? "." : r.startsWith("..") ? p : r;
  };
  return {
    target: rel(root),
    mode: "deps",
    local: true,
    reachable: true,
    timestamp: new Date(started).toISOString(),
    duration: Date.now() - started,
    deps: {
      ecosystem: "npm",
      lockfile: rel(lockPath),
      lockfileVersion: lock.lockfileVersion || 1,
      format: `package-lock.json v${lock.lockfileVersion || 1}`,
      prod: !!opts.prod,
      network: opts.online ? "online (registry metadata only)" : "offline",
      total: tree.length,
      scanned: tree.filter((p) => p.capabilities).length,
      skippedOptional,
      direct: [...direct],
      notInstalled: unavailable.map((p) => `${p.name}@${p.version}`),
      unscanned: tree.filter((p) => p.unscanned).map((p) => ({ package: `${p.name}@${p.version}`, reason: p.unscanned })),
      scriptMismatch: tree.filter((p) => p.scriptMismatch).map((p) => `${p.name}@${p.version}`),
      capabilityCounts: summarize(tree),
      popularList: loadPopular().source,
      packages: tree.map((p) => ({
        name: p.name,
        version: p.version,
        path: p.path,
        dev: p.dev,
        license: p.license,
        direct: direct.has(p.name),
        source: p.source,
        capabilities: p.capabilities,
      })),
      typosquats: typos,
      licenses,
      online,
      diff: diff ? {
        base: base.label,
        added: diff.added.map(({ pkg, ...a }) => ({ ...a, installScripts: pkg.installScripts, unscanned: pkg.unscanned || null, scriptMismatch: !!pkg.scriptMismatch })),
        upgraded: diff.upgraded.map(({ pkg, prev, ...u }) => ({ ...u, installScripts: pkg.installScripts, previousInstallScripts: prev?.installScripts || null, unscanned: pkg.unscanned || null, scriptMismatch: !!pkg.scriptMismatch })),
        removed: diff.removed,
        evidence: Object.fromEntries([...diff.added, ...diff.upgraded].map((x) => {
          const ids = x.gained || x.capabilities || [];
          return [`${x.name}@${x.version || x.to}`, Object.fromEntries(ids.map((id) => [id, x.pkg.capabilities?.[id]?.evidence || []]))];
        })),
      } : null,
    },
    findings,
  };
}

const relCwd = (p) => {
  const r = relative(process.cwd(), p);
  return r === "" ? "." : r.startsWith("..") ? p : r;
};

/** Python: uv/poetry/pdm/Pipfile lockfiles, requirements files, a virtualenv. */
async function scanPython(root, opts = {}) {
  const started = Date.now();
  const onPhase = opts.onPhase || (() => {});
  const cur = loadPythonTree(root, opts);
  const keep = (p) => !opts.prod || !p.dev;
  onPhase(`Scanning ${cur.tree.length} Python packages from ${cur.format} (offline)`);
  const tree = cur.tree.filter(keep);
  const direct = new Set(cur.direct);

  let diff = null;
  let base = null;
  if (opts.diff || opts.base) {
    base = loadPythonBase(root, opts, { ...cur, tree });
    onPhase(`Comparing against ${base.label}: ${base.needOld} replaced version(s) to inspect`);
    diff = diffTrees(base.tree.filter(keep), tree);
    diff.lockfile = cur.lockfile;
  }

  const findings = [];
  const inScope = diff
    ? new Set([...diff.added.map((a) => a.pkg), ...diff.upgraded.map((u) => u.pkg)])
    : new Set(tree);
  for (const p of tree) if (inScope.has(p)) findings.push(...riskFindings(p));
  // A known-bad package is reported wherever it sits, diff or not.
  findings.push(...iocFindings(tree, cur.ctx.iocs, "pypi"));
  if (diff) findings.push(...diffFindings(diff, "pypi"));
  if (!diff) findings.push(...unownedHookFindings(cur.unownedHooks));

  const nameScope = diff ? diff.added.map((a) => a.name) : tree.filter((p) => direct.has(p.name)).map((p) => p.name);
  const typos = findTyposquats(nameScope, "pypi");
  findings.push(...typosquatFindings(typos, new Map(tree.map((p) => [p.name, p])), direct));

  let online = null;
  if (opts.online) {
    // Registry checks are npm-only for now; say so instead of silently skipping.
    online = { checked: 0, unreachable: 0, fetchedTarballs: 0, note: "--online registry checks cover npm only; PyPI packages were scanned offline." };
  }

  const unavailable = tree.filter((p) => !p.capabilities && !p.unscanned);
  return {
    target: relCwd(root),
    mode: "deps",
    local: true,
    reachable: true,
    timestamp: new Date(started).toISOString(),
    duration: Date.now() - started,
    deps: {
      ecosystem: "pypi",
      lockfile: cur.lockfile,
      lockfileVersion: cur.lockfileVersion,
      format: cur.format,
      venv: cur.venv,
      prod: !!opts.prod,
      network: "offline",
      total: tree.length,
      scanned: tree.filter((p) => p.capabilities).length,
      skippedOptional: 0,
      direct: [...direct],
      notInstalled: unavailable.map((p) => (p.version ? `${p.name}@${p.version}` : `${p.name} (unpinned, not installed)`)),
      unscanned: tree.filter((p) => p.unscanned).map((p) => ({ package: `${p.name}@${p.version}`, reason: p.unscanned })),
      capabilityCounts: summarize(tree),
      popularList: loadPopular("pypi").source,
      packages: tree.map((p) => ({
        name: p.name,
        version: p.version,
        path: p.path,
        dev: p.dev,
        direct: direct.has(p.name),
        source: p.source,
        ecosystem: "pypi",
        capabilities: p.capabilities,
      })),
      typosquats: typos,
      online,
      diff: diff ? {
        base: base.label,
        added: diff.added.map(({ pkg, ...a }) => ({ ...a, installScripts: pkg.installScripts, unscanned: pkg.unscanned || null })),
        upgraded: diff.upgraded.map(({ pkg, prev, ...u }) => ({ ...u, installScripts: pkg.installScripts, previousInstallScripts: prev?.installScripts || null, unscanned: pkg.unscanned || null })),
        removed: diff.removed,
        evidence: Object.fromEntries([...diff.added, ...diff.upgraded].map((x) => {
          const ids = x.gained || x.capabilities || [];
          return [`${x.name}@${x.version || x.to}`, Object.fromEntries(ids.map((id) => [id, x.pkg.capabilities?.[id]?.evidence || []]))];
        })),
      } : null,
    },
    findings,
  };
}

/** One result for a project with both npm and Python dependencies. */
function combineResults(results) {
  const [first] = results;
  const ds = results.map((r) => r.deps);
  const sum = (k) => ds.reduce((n, d) => n + (d[k] || 0), 0);
  const counts = {};
  for (const id of CAPABILITY_ORDER) counts[id] = ds.reduce((n, d) => n + (d.capabilityCounts[id] || 0), 0);
  const diffs = ds.map((d) => d.diff).filter(Boolean);
  return {
    ...first,
    duration: Math.max(...results.map((r) => r.duration)),
    deps: {
      ...ds[0],
      ecosystem: ds.map((d) => d.ecosystem).join("+"),
      ecosystems: ds.map((d) => d.ecosystem),
      lockfile: ds.map((d) => d.lockfile).join(" + "),
      format: ds.map((d) => d.format).join(" + "),
      venv: ds.find((d) => d.venv)?.venv || null,
      network: ds.map((d) => d.network).find((n) => n !== "offline") || "offline",
      total: sum("total"),
      scanned: sum("scanned"),
      skippedOptional: sum("skippedOptional"),
      direct: ds.flatMap((d) => d.direct),
      notInstalled: ds.flatMap((d) => d.notInstalled),
      unscanned: ds.flatMap((d) => d.unscanned || []),
      capabilityCounts: counts,
      popularList: ds.map((d) => d.popularList).join(", "),
      packages: ds.flatMap((d) => d.packages.map((p) => ({ ecosystem: d.ecosystem, ...p }))),
      typosquats: ds.flatMap((d) => d.typosquats),
      online: ds.find((d) => d.online)?.online || null,
      diff: diffs.length ? {
        base: diffs[0].base,
        added: diffs.flatMap((d) => d.added),
        upgraded: diffs.flatMap((d) => d.upgraded),
        removed: diffs.flatMap((d) => d.removed),
        evidence: Object.assign({}, ...diffs.map((d) => d.evidence)),
      } : null,
      parts: ds,
    },
    findings: results.flatMap((r) => r.findings),
  };
}

/**
 * Scan a project's dependencies: npm (package-lock.json), Python (uv.lock,
 * poetry.lock, pdm.lock, Pipfile.lock, requirements*.txt, a virtualenv), or both.
 * @param {string} root project folder
 * @param {{ diff?: string, base?: string, online?: boolean, prod?: boolean,
 *           onPhase?: Function, cacheDir?: string|string[], now?: number, fetchImpl?: Function,
 *           treeRoot?: string, ecosystem?: "npm"|"python"|"auto", venv?: string,
 *           pipCacheDir?: string, uvCacheDir?: string, lock?: object, baseLock?: object,
 *           baseLabel?: string, changedOnly?: boolean, licensePolicy?: object }} opts
 *           lock, baseLock, changedOnly, licensePolicy: npm only, see scanNpm(). treeRoot: where installed
 *           packages live, when the lockfile describes a tree that is not installed beside
 *           it (penthera install). venv: the Python virtualenv to read (default .venv or venv).
 */
export async function scanDeps(root, opts = {}) {
  // Lockfile objects passed in (the pre-commit hook) are npm lockfiles.
  if (opts.lock || opts.baseLock) return scanNpm(root, opts);
  const eco = opts.ecosystem || "auto";
  const npm = eco !== "python" && !!findLockfile(root);
  const python = eco === "python" || (eco !== "npm" && hasPythonInputs(root, opts.venv));
  if (!npm && !python) {
    throw new Error(`No package-lock.json in ${root}. penthera deps reads the lockfile; run \`npm install --package-lock-only\` first. For Python it reads uv.lock, poetry.lock, pdm.lock, Pipfile.lock, requirements*.txt or a .venv.`);
  }
  const results = [];
  if (npm) results.push(await scanNpm(root, opts));
  if (python) results.push(await scanPython(root, opts));
  return results.length === 1 ? results[0] : combineResults(results);
}
