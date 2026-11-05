/**
 * Discover API routes in Express, Hono, and Fastify projects.
 */
import { readdirSync, lstatSync, existsSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { readRepoFile, isRefused } from "../fs-safe.js";

/** Source and manifest files are read up to 5 MiB, never through a link out, a device or a FIFO. */
const SOURCE_MAX_BYTES = 5 * 1024 * 1024;

/**
 * A file's text, or null when it is absent or refused. A refusal goes into
 * `refused` (a RefusedFileError naming the repo-relative path) for the caller
 * to report.
 */
function readSource(full, repoPath, refused) {
  try {
    return readRepoFile(full, { root: repoPath, label: relative(repoPath, full).split(sep).join("/"), maxBytes: SOURCE_MAX_BYTES });
  } catch (e) {
    if (isRefused(e) && refused && !refused.some((r) => r.path === e.path)) refused.push(e);
    return null;
  }
}

const SKIP = new Set(["node_modules", ".git", "dist", "build", ".next", "coverage", "vendor"]);
const CODE_EXT = /\.(js|ts|mjs|cjs)$/;

const ROUTE_DIRS = ["routes", "src/routes", "api", "src/api", "server/routes", "src/server/routes"];

// Express / Hono / Fastify route patterns. A registration passes a handler
// after the path, so the path must be followed by a comma: `map.get("/x")`
// and `params.delete("/x")` are lookups, not routes.
const ROUTE_RES = [
  /(?:app|router|server|api|hono)\.(get|post|put|patch|delete|options)\s*\(\s*['"`]([^'"`]+)['"`]\s*,/gi,
  /fastify\.(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]\s*,/gi,
  /\.(get|post|put|patch|delete)\s*\(\s*['"`](\/[^'"`]+)['"`]\s*,/gi,
  /method:\s*['"](GET|POST|PUT|PATCH|DELETE)['"]\s*,\s*url:\s*['"`]([^'"`]+)['"`]/gi,
];

/**
 * A shell exec: bare exec/execSync (destructured from child_process), a
 * child_process, cp or shelljs receiver, spawn, or execSync anywhere. Any other
 * `.exec(` is a method call, usually RegExp.prototype.exec, and not a shell.
 */
export const SHELL_EXEC_RE = /(?<![\w.$])exec(?:Sync)?\s*\(|\b(?:child_process|childProcess|cp|shell)\.exec\w*\s*\(|require\(\s*['"](?:node:)?child_process['"]\s*\)\.exec\w*\s*\(|spawn\s*\(|execSync/;

function walkCodeFiles(dir, files = [], root = dir) {
  // Nested repos and worktrees are separate projects; symlinks are not
  // followed, the top folder's included (routes -> / would walk the disk).
  let top;
  try { top = lstatSync(dir); } catch { return files; }
  if (!top.isDirectory() || (dir !== root && existsSync(join(dir, ".git")))) return files;
  for (const entry of readdirSync(dir)) {
    if (SKIP.has(entry)) continue;
    const full = join(dir, entry);
    const st = lstatSync(full);
    if (st.isSymbolicLink()) continue;
    if (st.isDirectory()) {
      walkCodeFiles(full, files, root);
    } else if (st.isFile() && CODE_EXT.test(entry)) {
      files.push(full);
    }
  }
  return files;
}

function extractRoutesFromSource(source, filePath, repoPath) {
  const routes = [];
  const seen = new Set();

  for (const re of ROUTE_RES) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(source)) !== null) {
      const method = m[1].toUpperCase();
      let path = m[2];
      if (!path.startsWith("/")) path = `/${path}`;
      const key = `${method}:${path}`;
      if (seen.has(key)) continue;
      seen.add(key);

      routes.push({
        url: path,
        filePath: relative(repoPath, filePath),
        methods: [method],
        auth: classifyAuth(source),
        inputs: [],
        externalCalls: [],
        securityPatterns: detectRisk(source),
        hasParams: path.includes(":") || path.includes("*"),
        framework: detectFramework(source),
        sourceLength: source.length,
      });
    }
  }

  return routes;
}

export function detectFramework(source) {
  if (/from\s+['"]hono['"]|new Hono/.test(source)) return "hono";
  if (/from\s+['"]fastify['"]|fastify\(/.test(source)) return "fastify";
  if (/from\s+['"]express['"]|require\s*\(\s*['"]express['"]\)/.test(source)) return "express";
  return "node";
}

function classifyAuth(source) {
  const auth = [];
  if (/verifyAdmin|isAdmin|requireAdmin/.test(source)) auth.push("admin");
  if (/requireAuth|getSession|verifyToken|jwt\.verify/.test(source)) auth.push("user");
  if (/CRON_SECRET|verifyCron/.test(source)) auth.push("cron");
  if (auth.length === 0) auth.push("public");
  return auth;
}

const MOUNT_RE = /\.(?:use|route)\s*\(\s*['"`](\/[^'"`]*)['"`]\s*,\s*(?:require\(\s*['"`](\.[^'"`]+)['"`]\s*\)|(\w+))/g;
const IMPORT_RES = [
  /import\s+(\w+)\s+from\s+['"`](\.[^'"`]+)['"`]/g,
  /(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*['"`](\.[^'"`]+)['"`]\s*\)/g,
];

const NAMED_IMPORT_RE = /import\s+(?:\w+\s*,\s*)?\{([^{}]{1,2048})\}\s+from\s+['"`](\.[^'"`]+)['"`]/g;

/** The file an import names: `./tools.js` may be tools.ts on disk, `./tools` may be tools/index.js. */
function resolveLocal(from, spec) {
  const base = resolve(dirname(from), spec);
  const bare = base.replace(/\.[cm]?[jt]s$/, "");
  return [base, ...[".js", ".ts", ".mjs", ".cjs", "/index.js", "/index.ts"].map((e) => bare + e)].find((f) => CODE_EXT.test(f) && existsSync(f)) || null;
}

/** Routers a file mounts: `app.use("/api", tools)`, Hono's `app.route("/api", tools)`, each as [router file, prefix, mounting file]. */
function findMounts(source, file) {
  const imports = new Map();
  for (const re of IMPORT_RES) for (const m of source.matchAll(re)) imports.set(m[1], m[2]);
  for (const m of source.matchAll(NAMED_IMPORT_RE)) {
    for (const name of m[1].split(",")) imports.set(name.trim().split(/\s+as\s+/).pop(), m[2]);
  }
  const mounts = [];
  for (const m of source.matchAll(MOUNT_RE)) {
    const spec = m[2] || imports.get(m[3]);
    const target = spec && resolveLocal(file, spec);
    if (target) mounts.push([target, m[1].replace(/\/+$/, ""), resolve(file)]);
  }
  return mounts;
}

/** The full path of a route, with the prefixes of every router above it. */
function withMounts(route, file, mounts) {
  let url = route;
  const seen = new Set();
  for (let at = mounts.get(file); at && !seen.has(at.parent); at = mounts.get(at.parent)) {
    seen.add(at.parent);
    url = at.prefix + (url === "/" ? "" : url);
  }
  return url || "/";
}

function detectRisk(source) {
  const patterns = [];
  if (/eval\s*\(/.test(source)) patterns.push("RISK:eval");
  if (/innerHTML/.test(source)) patterns.push("RISK:innerHTML");
  if (SHELL_EXEC_RE.test(source)) patterns.push("RISK:command-injection");
  return patterns;
}

/**
 * @param {string} repoPath
 * @param {{ refused?: Error[] }} [opts] - refused: collects the files that
 *   were not read (a link out of the repo, a device, a FIFO, too large)
 * @returns {object[]} routes in attack-surface shape
 */
export function discoverFrameworkRoutes(repoPath, { refused = [] } = {}) {
  const all = [];
  const seen = new Set();
  const mounts = new Map(); // router file -> { prefix, parent }
  const noteMounts = (source, file) => {
    for (const [target, prefix, parent] of findMounts(source, file)) {
      if (!mounts.has(target)) mounts.set(target, { prefix, parent });
    }
  };

  const scanFiles = (dir) => {
    for (const file of walkCodeFiles(dir)) {
      const source = readSource(file, repoPath, refused);
      if (source == null) continue;
      if (!/(express|hono|fastify|Router|\.get\s*\(|\.post\s*\()/i.test(source)) continue;
      noteMounts(source, file);

      for (const route of extractRoutesFromSource(source, file, repoPath)) {
        const key = `${route.methods[0]}:${route.url}:${route.filePath}`;
        if (seen.has(key)) continue;
        seen.add(key);
        all.push(route);
      }
    }
  };

  for (const dir of ROUTE_DIRS) {
    scanFiles(join(repoPath, dir));
  }

  // Also scan top-level server entry files
  for (const entry of ["server.js", "server.ts", "index.js", "index.ts", "app.js", "app.ts", "src/index.ts"]) {
    const full = join(repoPath, entry);
    const source = readSource(full, repoPath, refused);
    if (source == null) continue;
    noteMounts(source, full);
    for (const route of extractRoutesFromSource(source, full, repoPath)) {
      const key = `${route.methods[0]}:${route.url}:${route.filePath}`;
      if (seen.has(key)) continue;
      seen.add(key);
      all.push(route);
    }
  }

  for (const route of all) {
    route.url = withMounts(route.url, resolve(repoPath, route.filePath), mounts);
    route.hasParams = route.url.includes(":") || route.url.includes("*");
  }
  return all.sort((a, b) => a.url.localeCompare(b.url));
}

// Web frameworks by manifest dependency, most specific first (Next.js ships React,
// SvelteKit ships Vite). Python names are matched in requirements/pyproject text.
const NPM_FRAMEWORKS = [
  ["next", "Next.js"], ["nuxt", "Nuxt"], ["@remix-run/node", "Remix"], ["@sveltejs/kit", "SvelteKit"],
  ["astro", "Astro"], ["@nestjs/core", "NestJS"], ["hono", "Hono"], ["fastify", "Fastify"],
  ["express", "Express"], ["koa", "Koa"], ["vite", "Vite"],
];
const PY_FRAMEWORKS = [["django", "Django"], ["fastapi", "FastAPI"], ["flask", "Flask"]];
const SOURCE_NAMES = { express: "Express", hono: "Hono", fastify: "Fastify" };

/**
 * Name the project's web framework from its manifests, offline. Falls back to
 * detectFramework() on the server entry files.
 * @param {string} repoPath
 * @param {{ refused?: Error[] }} [opts] - refused: collects the files that were not read
 * @returns {string|null} e.g. "Next.js", "Express", "FastAPI"
 */
export function detectProjectFramework(repoPath, { refused = [] } = {}) {
  try {
    const pkg = JSON.parse(readSource(join(repoPath, "package.json"), repoPath, refused) ?? "null");
    const deps = { ...pkg?.dependencies, ...pkg?.devDependencies };
    for (const [dep, name] of NPM_FRAMEWORKS) if (deps[dep]) return name;
  } catch { /* unparseable package.json */ }
  let py = "";
  for (const f of ["requirements.txt", "pyproject.toml", "Pipfile"]) {
    py += (readSource(join(repoPath, f), repoPath, refused) ?? "").toLowerCase() + "\n";
  }
  for (const [dep, name] of PY_FRAMEWORKS) if (new RegExp(`(^|[^a-z0-9_-])${dep}([^a-z0-9_-]|$)`, "m").test(py)) return name;
  for (const entry of ["server.js", "server.ts", "index.js", "index.ts", "app.js", "app.ts", "src/index.ts"]) {
    const source = readSource(join(repoPath, entry), repoPath, refused);
    const name = source == null ? null : SOURCE_NAMES[detectFramework(source)];
    if (name) return name;
  }
  return null;
}
