/**
 * `penthera install`: an install firewall on top of the `penthera deps` engine.
 *
 *   1. Resolve. `npm install --package-lock-only --ignore-scripts [pkg...]` runs
 *      in a temporary copy of package.json / package-lock.json / .npmrc. Not in
 *      place: npm rewrites node_modules/.package-lock.json even in lock-only
 *      mode, and an abort must leave the project byte for byte as it was.
 *   2. Fetch. `npm cache add --ignore-scripts` puts each new tarball in npm's
 *      cache; nothing is unpacked into node_modules and no package code runs
 *      (git dependencies would run `prepare` here without --ignore-scripts, so
 *      they are refused unless --allow-non-registry is passed). The deps engine
 *      reads tarballs back from the cache only after verifying them against
 *      the proposed lockfile's integrity (lib/deps/source.js).
 *   3. Diff. lib/deps scans the proposed tree against the current lockfile:
 *      new packages, capabilities gained, install scripts, typosquats.
 *   4. Decide. lib/install/policy.js turns that into deny / needs-approval.
 *   5. Apply (only when allowed). The vetted package.json and lockfile are
 *      written into the project and `npm ci` installs exactly that tree (it
 *      fails rather than re-resolve), with `--ignore-scripts` unless the new
 *      install scripts were approved.
 *
 * Penthera makes no network calls here. npm talks to its configured registry
 * (resolve and fetch); that is the one expected egress.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { existsSync, readFileSync, writeFileSync, copyFileSync, rmSync, mkdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { withTempDir } from "../tmp.js";
import { scanDeps } from "../deps/index.js";
import { parseLockfile } from "../deps/lockfile.js";
import { sourceFromNpmCache, npmCacheDir } from "../deps/source.js";
import { evaluatePolicy, normalizePolicy } from "./policy.js";
import { parseJson } from "../json-text.js";

const run = promisify(execFile);
const NPM = process.platform === "win32" ? "npm.cmd" : "npm";
const LOCKFILES = ["package-lock.json", "npm-shrinkwrap.json"];
const COPY = ["package.json", ...LOCKFILES, ".npmrc"];
const QUIET = ["--no-audit", "--no-fund", "--no-update-notifier"];
const LOCAL_SPEC = /^(file:|link:|portal:|\.{1,2}\/|\/)/;
// Specs npm resolves outside the registry: git, tarball URLs, hosted-git shorthands.
const REMOTE_SPEC = /^(?:git\+|git:|github:|gitlab:|bitbucket:|gist:|https?:|ssh:)|^[^@][^/@:]*\/[^/]+$|^[^@]+@(?:git\+|git:|github:|gitlab:|bitbucket:|gist:|https?:|ssh:|file:)|\.(?:tgz|tar\.gz|tar)$/i;

async function npm(args, opts) {
  try {
    return await run(NPM, args, { maxBuffer: 64 * 1024 * 1024, shell: process.platform === "win32", ...opts });
  } catch (e) {
    const msg = String(e.stderr || e.message).trim().split("\n").filter((l) => !/^npm (verbose|silly|timing)/.test(l)).slice(-8).join("\n");
    throw new Error(`npm ${args[0]} failed:\n${msg}`);
  }
}

/** npm's version and registries (default and @scope:registry), as npm sees them from the project. */
export async function npmInfo(root, env = process.env) {
  const [version, config] = await Promise.all([
    npm(["--version"], { cwd: root, env }).then((r) => r.stdout.trim()),
    npm(["config", "list", "--json"], { cwd: root, env }).then((r) => JSON.parse(r.stdout), () => ({})),
  ]);
  const registry = typeof config.registry === "string" ? config.registry : "the configured npm registry";
  const registries = Object.entries(config)
    .filter(([k, v]) => (k === "registry" || /^@[^:]+:registry$/.test(k)) && typeof v === "string")
    .map(([, v]) => v);
  const major = parseInt(version, 10) || 0;
  // npm 12 blocks dependency install scripts unless package.json allowScripts lists them.
  return { version, major, registry, registries, allowScriptsPolicy: major >= 12 };
}

const origin = (u) => {
  try {
    const x = new URL(u);
    return /^https?:$/.test(x.protocol) ? x.origin : null;
  } catch {
    return null;
  }
};

/**
 * Lockfile entries that would come from somewhere other than a configured
 * registry: git repositories, tarball URLs on other hosts. Their contents are
 * not what a registry name and version promise, and git ones run `prepare`.
 */
export function nonRegistryPackages(pkgs, registries) {
  const allowed = new Set((registries || []).map(origin).filter(Boolean));
  return pkgs.filter((p) => p.resolved && !p.link && !allowed.has(origin(p.resolved)));
}

const key = (p) => `${p.path}@${p.version}#${p.integrity || ""}`;
const scriptsOf = (s) => (s && Object.keys(s).length ? s : null);

/** The rule ids a change raises (see lib/install/policy.js). */
function flagsFor(caps, { newScripts, typosquat, unscanned, scriptMismatch }) {
  const flags = [...(caps || [])].filter((id) => id !== "install-scripts");
  if (newScripts) flags.unshift("install-scripts");
  if (typosquat) flags.push("typosquat");
  if (unscanned) flags.push("unscanned");
  if (scriptMismatch) flags.push("script-mismatch");
  return flags;
}

/**
 * Turn the deps diff into one change per new or upgraded package.
 * `packages` is result.deps.packages, for the capabilities of an upgrade whose
 * old version could not be read.
 */
export function changesFromDiff(diff, typosquats = [], packages = []) {
  const typo = new Map(typosquats.map((t) => [t.name, t]));
  const capsOf = (name, version) => {
    const c = packages.find((p) => p.name === name && p.version === version)?.capabilities;
    return c ? Object.keys(c) : null;
  };
  const out = [];
  for (const a of diff.added) {
    const scripts = scriptsOf(a.installScripts);
    out.push({
      change: "added",
      name: a.name,
      version: a.version,
      capabilities: a.capabilities || [],
      installScripts: scripts,
      typosquatOf: typo.get(a.name)?.target || null,
      unscanned: a.unscanned || null,
      flags: flagsFor(a.capabilities, { newScripts: !!scripts, typosquat: typo.has(a.name), unscanned: a.capabilities === null, scriptMismatch: !!a.scriptMismatch }),
    });
  }
  for (const u of diff.upgraded) {
    const scripts = scriptsOf(u.installScripts);
    const before = scriptsOf(u.previousInstallScripts);
    // A hook that is new, or whose command changed, is new code at install time.
    const newScripts = !!scripts && JSON.stringify(scripts) !== JSON.stringify(before);
    // Old version unreadable: judge the new version on everything it can do.
    const gained = u.gained ?? (u.unavailable === "old" ? capsOf(u.name, u.to) : null);
    out.push({
      change: "upgraded",
      name: u.name,
      version: u.to,
      from: u.from,
      capabilities: gained || [],
      installScripts: scripts,
      previousInstallScripts: before,
      compared: u.unavailable == null,
      typosquatOf: null,
      unscanned: u.unscanned || null,
      flags: flagsFor(gained, { newScripts, typosquat: false, unscanned: u.unavailable === "new" || !!u.unscanned, scriptMismatch: !!u.scriptMismatch }),
    });
  }
  return out;
}

function readIfExists(p) {
  return existsSync(p) ? readFileSync(p) : null;
}

function checkProject(root, pkgJson) {
  if (pkgJson.workspaces) throw new Error("npm workspaces are not supported by `penthera install` yet. Run `npm install --package-lock-only --ignore-scripts` and review with `penthera deps --base HEAD`.");
  const local = Object.entries({ ...pkgJson.dependencies, ...pkgJson.devDependencies, ...pkgJson.optionalDependencies })
    .filter(([, spec]) => LOCAL_SPEC.test(String(spec)));
  if (local.length) throw new Error(`Local path dependencies (${local.map(([n]) => n).join(", ")}) cannot be resolved from a temporary copy. Run \`npm install --package-lock-only --ignore-scripts\` and review with \`penthera deps --base HEAD\`.`);
}

/**
 * Work out what `npm install [specs]` would change, without running any
 * package code and without writing to the project.
 * @param {string} root project folder (has package.json)
 * @param {string[]} specs packages as npm accepts them (name, name@range, ...)
 * @param {{ policy?: object, saveDev?: boolean, saveExact?: boolean, offline?: boolean,
 *           env?: object, onPhase?: Function, info?: object }} opts
 */
export async function planInstall(root, specs, opts = {}) {
  root = resolve(root);
  const env = opts.env || process.env;
  const onPhase = opts.onPhase || (() => {});
  const pkgPath = join(root, "package.json");
  if (!existsSync(pkgPath)) throw new Error(`No package.json in ${root}`);
  checkProject(root, parseJson(readFileSync(pkgPath, "utf-8")));
  const bad = specs.filter((s) => s.startsWith("-") || LOCAL_SPEC.test(s));
  if (bad.length) throw new Error(`Unsupported package spec(s): ${bad.join(", ")}. Pass registry names (name, name@version, name@range).`);
  const remote = specs.filter((s) => REMOTE_SPEC.test(s));
  if (remote.length && !opts.allowNonRegistry) {
    throw new Error(`Non-registry package spec(s): ${remote.join(", ")}. Git and tarball-URL installs bypass the registry's name and version, and git ones run \`prepare\` while being fetched. Pass --allow-non-registry if you mean it.`);
  }

  const info = opts.info || await npmInfo(root, env);
  const original = Object.fromEntries(COPY.map((f) => [f, readIfExists(join(root, f))]));
  const lockName = LOCKFILES.find((f) => original[f]) || "package-lock.json";

  return withTempDir("penthera-install-", async (tmp) => {
    const work = join(tmp, "project");
    mkdirSync(work);
    for (const f of COPY) if (original[f]) copyFileSync(join(root, f), join(work, f));

    const flags = [...(opts.saveDev ? ["--save-dev"] : []), ...(opts.saveExact ? ["--save-exact"] : []), ...(opts.offline ? ["--offline"] : [])];
    onPhase(`Resolving in a temporary copy: npm install --package-lock-only --ignore-scripts${specs.length ? ` ${specs.join(" ")}` : ""}`);
    await npm(["install", "--package-lock-only", "--ignore-scripts", ...QUIET, ...flags, ...specs], { cwd: work, env });

    const proposedLockPath = join(work, lockName);
    if (!existsSync(proposedLockPath)) throw new Error("npm did not write a lockfile");
    const proposedLock = parseJson(readFileSync(proposedLockPath, "utf-8"));

    // Base: the project's current lockfile, or an empty tree for a first install.
    let baseLockPath = original[lockName] ? join(root, lockName) : null;
    if (!baseLockPath) {
      mkdirSync(join(tmp, "base"));
      baseLockPath = join(tmp, "base", "package-lock.json");
      writeFileSync(baseLockPath, JSON.stringify({ lockfileVersion: 3, packages: { "": {} } }));
    }
    const oldKeys = new Set(parseLockfile(parseJson(readFileSync(baseLockPath, "utf-8"))).map(key));
    const fresh = parseLockfile(proposedLock).filter((p) => !p.link && p.version && !oldKeys.has(key(p)));
    const offRegistry = nonRegistryPackages(fresh, info.registries || [info.registry]);
    if (offRegistry.length && !opts.allowNonRegistry) {
      throw new Error(`The resolved tree pulls ${offRegistry.length} package(s) from outside the configured registry: ${offRegistry.slice(0, 5).map((p) => `${p.name} (${p.resolved})`).join(", ")}. Nothing was fetched or installed. Pass --allow-non-registry to review them anyway.`);
    }

    // New tarballs go into a private npm cache (npm cache add): nothing is
    // unpacked or run. Private because npm will not reliably say where its own
    // cache is (`npm config get cache` refuses some paths), and because the
    // scan must not depend on what else that cache holds.
    const userCache = npmCacheDir(env);
    const fetchCache = join(tmp, "cache");
    const toFetch = fresh.filter((p) => !p.integrity || !sourceFromNpmCache(p.integrity, userCache));
    if (toFetch.length) {
      onPhase(`Fetching ${toFetch.length} tarball(s) with npm cache add (nothing is unpacked or run)`);
      const fetchSpecs = [...new Set(toFetch.map((p) => (p.resolved && !/^https?:/.test(p.resolved) ? p.resolved : `${p.name}@${p.version}`)))];
      await npm(["cache", "add", "--ignore-scripts", ...QUIET, "--cache", fetchCache, ...(opts.offline ? ["--offline"] : []), ...fetchSpecs], { cwd: tmp, env });
    }

    onPhase("Comparing capabilities with the current tree (offline, integrity-verified)");
    const result = await scanDeps(work, { diff: baseLockPath, treeRoot: root, cacheDir: [fetchCache, userCache], ecosystem: "npm" });
    // A refused proposed lockfile scans as an empty tree: no changes, so the policy
    // would pass it. Fail closed instead (Vercel Security Review C, 2.3.2).
    if (result.incomplete?.length) {
      throw new Error(`The proposed lockfile was not read (${result.incomplete.map((x) => x.reason).join("; ")}). Nothing was installed.`);
    }
    const changes = changesFromDiff(result.deps.diff, result.deps.typosquats, result.deps.packages);
    const verdict = evaluatePolicy(changes, opts.policy || normalizePolicy({}));

    return {
      root,
      specs,
      npm: info,
      lockName,
      original,
      proposed: {
        "package.json": readFileSync(join(work, "package.json")),
        [lockName]: readFileSync(proposedLockPath),
      },
      changes,
      removed: result.deps.diff.removed,
      verdict,
      findings: result.findings,
      typosquats: result.deps.typosquats,
      evidence: result.deps.diff.evidence,
    };
  });
}

/** Packages whose new or changed install scripts would run. */
export const scriptChanges = (plan) => plan.verdict.items.filter((i) => i.flags.includes("install-scripts"));

/**
 * Pin approved packages in package.json allowScripts (npm >= 12 runs a
 * dependency's install scripts only when listed there). Returns new bytes.
 */
export function withAllowScripts(pkgJsonBuf, items) {
  const text = pkgJsonBuf.toString("utf-8");
  const pkg = parseJson(text);
  const allow = { ...(pkg.allowScripts || {}) };
  for (const i of items) {
    if (allow[i.name] === false) continue; // an explicit denial in the project wins
    allow[`${i.name}@${i.version}`] = true;
  }
  pkg.allowScripts = Object.fromEntries(Object.entries(allow).sort((a, b) => a[0].localeCompare(b[0])));
  const indent = text.match(/^\{\r?\n([ \t]+)"/)?.[1] || "  ";
  return Buffer.from(JSON.stringify(pkg, null, indent) + (text.endsWith("\n") ? "\n" : ""));
}

function restore(root, original) {
  for (const [f, buf] of Object.entries(original)) {
    const p = join(root, f);
    if (buf) writeFileSync(p, buf);
    else rmSync(p, { force: true });
  }
}

/**
 * Install the vetted tree. Writes the proposed package.json and lockfile,
 * then runs `npm ci`, which installs exactly that lockfile and fails instead
 * of re-resolving, so what runs is what was reviewed (`npm install` could
 * resolve something new and only be caught afterwards, once its scripts ran).
 * Restores both files if npm fails.
 * @param {{ runScripts: boolean, env?: object, stdio?: string, offline?: boolean }} opts
 */
export async function applyInstall(plan, opts) {
  const { root, original } = plan;
  const env = opts.env || process.env;
  let pkgJson = plan.proposed["package.json"];
  const approved = scriptChanges(plan);
  if (opts.runScripts && plan.npm.allowScriptsPolicy && approved.length) pkgJson = withAllowScripts(pkgJson, approved);

  writeFileSync(join(root, "package.json"), pkgJson);
  writeFileSync(join(root, plan.lockName), plan.proposed[plan.lockName]);
  const args = ["ci", ...QUIET, ...(opts.runScripts ? [] : ["--ignore-scripts"]), ...(opts.offline ? ["--offline"] : [])];
  try {
    await npm(args, { cwd: root, env });
  } catch (e) {
    restore(root, original);
    throw new Error(`${e.message}\npackage.json and ${plan.lockName} were restored; node_modules may be partly updated (run \`npm ci --ignore-scripts\` to reset it).`);
  }

  // npm ci never rewrites the lockfile; check anyway.
  const want = new Set(parseLockfile(parseJson(plan.proposed[plan.lockName])).map(key));
  const got = parseLockfile(parseJson(readFileSync(join(root, plan.lockName), "utf-8"))).map(key);
  const drift = got.filter((k) => !want.has(k));
  return { args, scriptsRan: opts.runScripts, allowScriptsAdded: pkgJson !== plan.proposed["package.json"] ? approved.map((i) => `${i.name}@${i.version}`) : [], drift };
}
