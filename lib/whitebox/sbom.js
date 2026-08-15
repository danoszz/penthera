/**
 * Software Bill of Materials (CycloneDX) generator.
 *
 * Parses a repo's dependency manifests offline (no network, no API keys) and
 * emits a CycloneDX 1.5 SBOM — the artifact enterprises increasingly demand of
 * their suppliers, and direct evidence for NIS2 supply-chain security (d).
 *
 * Supports npm (package-lock.json, then package.json) and Python
 * (requirements.txt). Resolved lockfile versions are preferred; where only a
 * range is known it is recorded as-is and marked.
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

function cleanRange(range) {
  // Strip a leading range operator for a best-effort version; keep the rest.
  return String(range).replace(/^[\^~>=<\s]+/, "").trim() || String(range);
}

function purl(ecosystem, name, version) {
  return `pkg:${ecosystem}/${encodeURIComponent(name)}@${encodeURIComponent(version)}`;
}

function parseNpmLock(lock) {
  const comps = [];
  if (lock.packages) { // lockfile v2/v3
    for (const [k, v] of Object.entries(lock.packages)) {
      if (k === "" || !v || !v.version) continue; // "" is the root project
      const name = k.split("node_modules/").pop();
      if (!name) continue;
      comps.push({ name, version: v.version, scope: v.dev ? "optional" : "required", resolved: true });
    }
  } else if (lock.dependencies) { // lockfile v1
    const walk = (deps) => {
      for (const [name, v] of Object.entries(deps)) {
        if (v?.version) comps.push({ name, version: v.version, scope: v.dev ? "optional" : "required", resolved: true });
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
 * Build a CycloneDX SBOM for a repo. Returns null if no manifest is found.
 * @param {string} repoPath
 * @param {object} opts - { serialNumber, timestamp } (injected for reproducibility/testing)
 */
export function buildSbom(repoPath, opts = {}) {
  let components = [];
  let rootName = "application";
  let rootVersion = "0.0.0";
  const sources = [];

  const pkgJsonPath = join(repoPath, "package.json");
  const lockPath = join(repoPath, "package-lock.json");
  const reqPath = join(repoPath, "requirements.txt");

  if (existsSync(pkgJsonPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgJsonPath, "utf-8"));
      rootName = pkg.name || rootName;
      rootVersion = pkg.version || rootVersion;
    } catch { /* ignore malformed */ }
  }

  if (existsSync(lockPath)) {
    try {
      const npm = parseNpmLock(JSON.parse(readFileSync(lockPath, "utf-8"))).map((c) => ({ ...c, ecosystem: "npm" }));
      if (npm.length) { components.push(...npm); sources.push("package-lock.json"); }
    } catch { /* ignore */ }
  }
  if (components.length === 0 && existsSync(pkgJsonPath)) {
    try {
      const npm = parsePackageJson(JSON.parse(readFileSync(pkgJsonPath, "utf-8"))).map((c) => ({ ...c, ecosystem: "npm" }));
      if (npm.length) { components.push(...npm); sources.push("package.json"); }
    } catch { /* ignore */ }
  }
  if (existsSync(reqPath)) {
    try {
      const py = parseRequirements(readFileSync(reqPath, "utf-8"));
      if (py.length) { components.push(...py); sources.push("requirements.txt"); }
    } catch { /* ignore */ }
  }

  if (sources.length === 0) return null;

  components = dedupe(components);

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
      purl: purl(c.ecosystem || "npm", c.name, c.version),
      properties: c.resolved ? undefined : [{ name: "penthera:version-note", value: "declared range, not a resolved version" }],
    })),
  };
}
