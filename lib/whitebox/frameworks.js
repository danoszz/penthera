/**
 * Discover API routes in Express, Hono, and Fastify projects.
 */
import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { join, relative } from "node:path";

const SKIP = new Set(["node_modules", ".git", "dist", "build", ".next", "coverage", "vendor"]);
const CODE_EXT = /\.(js|ts|mjs|cjs)$/;

const ROUTE_DIRS = ["routes", "src/routes", "api", "src/api", "server/routes", "src/server/routes"];

// Express / Hono / Fastify route patterns
const ROUTE_RES = [
  /(?:app|router|server|api|hono)\.(get|post|put|patch|delete|options)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
  /(?:app|router|server|api|hono)\.(get|post|put|patch|delete|options)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
  /fastify\.(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
  /\.(get|post|put|patch|delete)\s*\(\s*['"`](\/[^'"`]+)['"`]/gi,
  /method:\s*['"](GET|POST|PUT|PATCH|DELETE)['"]\s*,\s*url:\s*['"`]([^'"`]+)['"`]/gi,
];

function walkCodeFiles(dir, files = []) {
  if (!existsSync(dir)) return files;
  for (const entry of readdirSync(dir)) {
    if (SKIP.has(entry)) continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      walkCodeFiles(full, files);
    } else if (CODE_EXT.test(entry)) {
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

function detectFramework(source) {
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

function detectRisk(source) {
  const patterns = [];
  if (/eval\s*\(/.test(source)) patterns.push("RISK:eval");
  if (/innerHTML/.test(source)) patterns.push("RISK:innerHTML");
  if (/exec\s*\(|spawn\s*\(/.test(source)) patterns.push("RISK:command-injection");
  return patterns;
}

/**
 * @param {string} repoPath
 * @returns {object[]} routes in attack-surface shape
 */
export function discoverFrameworkRoutes(repoPath) {
  const all = [];
  const seen = new Set();

  const scanFiles = (dir) => {
    for (const file of walkCodeFiles(dir)) {
      let source;
      try {
        source = readFileSync(file, "utf-8");
      } catch {
        continue;
      }
      if (!/(express|hono|fastify|Router|\.get\s*\(|\.post\s*\()/i.test(source)) continue;

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
    if (!existsSync(full)) continue;
    try {
      const source = readFileSync(full, "utf-8");
      for (const route of extractRoutesFromSource(source, full, repoPath)) {
        const key = `${route.methods[0]}:${route.url}:${route.filePath}`;
        if (seen.has(key)) continue;
        seen.add(key);
        all.push(route);
      }
    } catch { /* skip */ }
  }

  return all.sort((a, b) => a.url.localeCompare(b.url));
}
