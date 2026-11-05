/**
 * Software Bill of Materials (CycloneDX) generator.
 *
 * Parses a repo's dependency manifests offline (no network, no API keys) and
 * emits a CycloneDX 1.5 SBOM, the artifact enterprises increasingly demand of
 * their suppliers, and direct evidence for NIS2 supply-chain security (d).
 *
 * Supports npm (package-lock.json, then package.json) and Python
 * (requirements.txt). Resolved lockfile versions are preferred; where only a
 * range is known it is recorded as-is and marked.
 *
 * `buildAiBom` (lib/whitebox/aibom.js) extends this into an AI-BOM: AI SDKs,
 * model identifiers, MCP servers, skills and prompt files.
 */
import { existsSync } from "node:fs";
import { join } from "node:path";
import { classifyLicense, licenseField } from "../deps/license.js";
import { readRepoFile } from "../fs-safe.js";

/**
 * A manifest inside the repo: a regular file under 64 MiB, never a link out,
 * a device or a FIFO (a package.json linked to /dev/zero hung the SBOM).
 * A refused file throws, and is left out like a malformed one.
 */
const readManifest = (repoPath, path) => readRepoFile(path, { root: repoPath, maxBytes: 64 * 1024 * 1024 });

function cleanRange(range) {
  // Strip a leading range operator for a best-effort version; keep the rest.
  return String(range).replace(/^[\^~>=<\s]+/, "").trim() || String(range);
}

export function purl(ecosystem, name, version) {
  return `pkg:${ecosystem}/${encodeURIComponent(name)}@${encodeURIComponent(version)}`;
}

function parseNpmLock(lock) {
  const comps = [];
  if (lock.packages) { // lockfile v2/v3
    for (const [k, v] of Object.entries(lock.packages)) {
      if (k === "" || !v || !v.version) continue; // "" is the root project
      const name = k.split("node_modules/").pop();
      if (!name) continue;
      comps.push({ name, version: v.version, scope: v.dev ? "optional" : "required", resolved: true, license: v.license || null, path: k });
    }
  } else if (lock.dependencies) { // lockfile v1
    const walk = (deps) => {
      for (const [name, v] of Object.entries(deps)) {
        if (v?.version) comps.push({ name, version: v.version, scope: v.dev ? "optional" : "required", resolved: true, license: null, path: `node_modules/${name}` });
        if (v?.dependencies) walk(v.dependencies);
      }
    };
    walk(lock.dependencies);
  }
  return comps;
}

function parsePackageJson(pkg) {
  const comps = [];
  for (const [name, range] of Object.entries(pkg.dependencies || {})) {
    comps.push({ name, version: cleanRange(range), scope: "required", resolved: false });
  }
  for (const [name, range] of Object.entries(pkg.devDependencies || {})) {
    comps.push({ name, version: cleanRange(range), scope: "optional", resolved: false });
  }
  return comps;
}

function parseRequirements(text) {
  const comps = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith("-")) continue;
    const m = line.match(/^([A-Za-z0-9._-]+)\s*(?:==|>=|~=|<=|!=)?\s*([\w.*+!-]+)?/);
    if (!m) continue;
    comps.push({ name: m[1], version: m[2] || "unknown", scope: "required", resolved: !!m[2] && line.includes("=="), ecosystem: "pypi" });
  }
  return comps;
}

/** CycloneDX `licenses`: one SPDX id, an SPDX expression, or a free-text name. */
function cdxLicenses(raw) {
  if (!raw) return undefined;
  const c = classifyLicense(raw);
  if (c.kind === "spdx" && c.tree.type === "license" && !c.tree.plus && !c.tree.exception && !c.tree.ref) return [{ license: { id: c.tree.id } }];
  if (c.kind === "spdx") return [{ expression: c.expression }];
  return [{ license: { name: raw } }];
}

/** An installed package's license, for lockfiles that do not record it (v1). */
function installedLicense(repoPath, path) {
  try {
    return licenseField(JSON.parse(readManifest(repoPath, join(repoPath, path, "package.json"))));
  } catch {
    return null;
  }
}

function dedupe(comps) {
  const seen = new Set();
  return comps.filter((c) => {
    const key = `${c.ecosystem || "npm"}:${c.name}@${c.version}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * Collect a repo's declared dependencies from its manifests. Returns
 * { components, sources, rootName, rootVersion } (sources is empty when no
 * manifest was found). Shared by the SBOM and the AI-BOM.
 */
export function collectDependencies(repoPath) {
  let components = [];
  let rootName = "application";
  let rootVersion = "0.0.0";
  const sources = [];

  const pkgJsonPath = join(repoPath, "package.json");
  const lockPath = join(repoPath, "package-lock.json");
  const reqPath = join(repoPath, "requirements.txt");

  if (existsSync(pkgJsonPath)) {
    try {
      const pkg = JSON.parse(readManifest(repoPath, pkgJsonPath));
      rootName = pkg.name || rootName;
      rootVersion = pkg.version || rootVersion;
    } catch { /* ignore malformed */ }
  }

  if (existsSync(lockPath)) {
    try {
      const npm = parseNpmLock(JSON.parse(readManifest(repoPath, lockPath)))
        .map((c) => ({ ...c, ecosystem: "npm", license: c.license || installedLicense(repoPath, c.path) }));
      if (npm.length) { components.push(...npm); sources.push("package-lock.json"); }
    } catch { /* ignore */ }
  }
  if (components.length === 0 && existsSync(pkgJsonPath)) {
    try {
      const npm = parsePackageJson(JSON.parse(readManifest(repoPath, pkgJsonPath))).map((c) => ({ ...c, ecosystem: "npm" }));
      if (npm.length) { components.push(...npm); sources.push("package.json"); }
    } catch { /* ignore */ }
  }
  if (existsSync(reqPath)) {
    try {
      const py = parseRequirements(readManifest(repoPath, reqPath));
      if (py.length) { components.push(...py); sources.push("requirements.txt"); }
    } catch { /* ignore */ }
  }

  return { components: dedupe(components), sources, rootName, rootVersion };
}

/**
 * Build a CycloneDX SBOM for a repo. Returns null if no manifest is found.
 * @param {string} repoPath
 * @param {object} opts - { serialNumber, timestamp } (injected for reproducibility/testing)
 */
export function buildSbom(repoPath, opts = {}) {
  const { components, sources, rootName, rootVersion } = collectDependencies(repoPath);
  if (sources.length === 0) return null;

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: opts.serialNumber || undefined,
    version: 1,
    metadata: {
      timestamp: opts.timestamp || undefined,
      tools: [{ vendor: "Penthera", name: "penthera", components: [] }],
      component: { type: "application", name: rootName, version: rootVersion },
      properties: [{ name: "penthera:sources", value: sources.join(", ") }],
    },
    components: components.map((c) => ({
      type: "library",
      name: c.name,
      version: c.version,
      scope: c.scope,
      licenses: cdxLicenses(c.license),
      purl: purl(c.ecosystem || "npm", c.name, c.version),
      properties: c.resolved ? undefined : [{ name: "penthera:version-note", value: "declared range, not a resolved version" }],
    })),
  };
}

