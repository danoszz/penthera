/**
 * Recipe: a rate-limit stub on login/auth routes. Express (express-rate-limit
 * when installed, otherwise an in-memory limiter), Fastify (preHandler), Hono
 * (middleware) and Next.js App Router route handlers. Guidance: remediation
 * rules "rate-limiting" and "auth", references/remediation.md#rate-limiting.
 *
 * The stub is per-process and in memory: it stops naive brute force against a
 * single instance, and the owner action says to move to a shared store.
 */
import { detectFramework as detectSourceFramework } from "../../whitebox/frameworks.js";
import { detectFramework, hasDep, readText, walkCodeFiles, insertAfterImports, addImport, isTypeScript, toDiff } from "../util.js";
import { worstKeeper } from "../probe-cap.js";

const AUTH_SEGMENT = /^(?:login|log-in|logon|signin|sign-in|signup|sign-up|register|auth|session|sessions|forgot-password|reset-password|password-reset|otp|mfa|2fa|verify-otp|magic-link)$/i;
const ROUTE_LINE = /^(\s*)(\w+)\.(post|put|all)\(\s*(['"`])([^'"`]+)\4\s*,[ \t]*(\S.*|)$/;
const LIMITED = /rateLimit|limiter|throttle/i;

export function isAuthPath(path) {
  if (!path || /\[\.\.\./.test(path)) return false; // catch-alls such as NextAuth's [...nextauth]
  return path.split("/").filter(Boolean).some((seg) => AUTH_SEGMENT.test(seg));
}

function nextRoutePath(file) {
  const m = file.match(/(?:^|\/)app\/(.*\/)?route\.(?:js|ts|mjs)$/);
  if (!m) return null;
  const dirs = (m[1] || "").split("/").filter((d) => d && !/^\(.*\)$/.test(d));
  return "/" + dirs.join("/");
}

/** Unprotected auth routes in one file: [{ method, path, line, framework }]. */
function authRoutes(file, source, repoFramework) {
  return [...eachAuthRoute(file, source, repoFramework)];
}

/** authRoutes, one at a time: a file with many routes never holds them all. */
function* eachAuthRoute(file, source, repoFramework) {
  const nextPath = nextRoutePath(file);
  if (nextPath) {
    if (!isAuthPath(nextPath) || LIMITED.test(source)) return;
    const lines = source.split("\n");
    const line = lines.findIndex((l) => /^export\s+(?:async\s+)?function\s+POST\s*\(/.test(l));
    if (line >= 0) yield { method: "POST", path: nextPath, line, framework: "next" };
    return;
  }
  const fileFw = detectSourceFramework(source);
  const framework = fileFw !== "node" ? fileFw : repoFramework;
  if (!["express", "fastify", "hono"].includes(framework)) return;
  if (/\.(?:use|register)\([^)\n]{0,256}(?:rateLimit|limiter|throttle|rate-limit)/i.test(source)) return; // a global limiter
  let line = 0;
  for (let start = 0; start <= source.length; line++) {
    const nl = source.indexOf("\n", start);
    const l = source.slice(start, nl < 0 ? undefined : nl);
    start = nl < 0 ? source.length + 1 : nl + 1;
    const m = l.match(ROUTE_LINE);
    if (!m || !isAuthPath(m[5]) || LIMITED.test(m[6])) continue;
    yield { method: m[3].toUpperCase(), path: m[5], line, framework };
  }
}

function coreLines(ts) {
  return [
    "// Login rate limit (added by penthera fix): at most LOGIN_MAX_ATTEMPTS per client",
    "// per window, kept in memory. Use a shared store (Redis, your edge or WAF) when",
    "// you run more than one instance.",
    "const LOGIN_WINDOW_MS = 15 * 60 * 1000;",
    "const LOGIN_MAX_ATTEMPTS = 10;",
    `const loginAttempts = new Map${ts ? "<string, { count: number; reset: number }>" : ""}();`,
    `function loginLimitExceeded(key${ts ? ": string" : ""})${ts ? ": boolean" : ""} {`,
    "  const now = Date.now();",
    "  if (loginAttempts.size > 10000) {",
    "    for (const [k, v] of loginAttempts) if (now > v.reset) loginAttempts.delete(k);",
    "  }",
    "  const entry = loginAttempts.get(key);",
    "  if (!entry || now > entry.reset) {",
    "    loginAttempts.set(key, { count: 1, reset: now + LOGIN_WINDOW_MS });",
    "    return false;",
    "  }",
    "  entry.count += 1;",
    "  return entry.count > LOGIN_MAX_ATTEMPTS;",
    "}",
  ];
}

const TOO_MANY = '{ error: "Too many attempts, try again later" }';

function wrapperLines(framework, ts) {
  const any = ts ? ": any" : "";
  if (framework === "express") {
    return [
      `function rateLimitLogin(req${any}, res${any}, next${any}) {`,
      `  if (loginLimitExceeded(req.ip || "unknown")) return res.status(429).json(${TOO_MANY});`,
      "  next();",
      "}",
    ];
  }
  if (framework === "fastify") {
    return [
      `async function rateLimitLogin(request${any}, reply${any}) {`,
      `  if (loginLimitExceeded(request.ip)) return reply.code(429).send(${TOO_MANY});`,
      "}",
    ];
  }
  if (framework === "hono") {
    return [
      `async function rateLimitLogin(c${any}, next${any}) {`,
      '  const ip = c.req.header("x-forwarded-for")?.split(",")[0].trim() || "unknown";',
      `  if (loginLimitExceeded(ip)) return c.json(${TOO_MANY}, 429);`,
      "  await next();",
      "}",
    ];
  }
  return [
    `function rateLimitLogin(request${ts ? ": Request" : ""})${ts ? ": Response | null" : ""} {`,
    '  const ip = request.headers.get("x-forwarded-for")?.split(",")[0].trim() || "unknown";',
    "  if (!loginLimitExceeded(ip)) return null;",
    `  return Response.json(${TOO_MANY}, { status: 429 });`,
    "}",
  ];
}

function fixFile(repoPath, file, source, routes) {
  const lines = source.split("\n");
  const framework = routes[0].framework;
  const useExpressRateLimit = framework === "express" && hasDep(repoPath, "express-rate-limit");
  for (const r of [...routes].reverse()) {
    const l = lines[r.line];
    if (framework === "next") {
      const m = l.match(/^export\s+(?:async\s+)?function\s+POST\s*\(\s*(\w+)/);
      if (!m || !/\{\s*$/.test(l)) return null;
      lines.splice(r.line + 1, 0, `  const limited = rateLimitLogin(${m[1]});`, "  if (limited) return limited;");
      continue;
    }
    const m = l.match(ROUTE_LINE);
    if (framework === "fastify") {
      if (!m[6] || /^\{/.test(m[6])) return null; // options object (or unseen next line): merge by hand
      lines[r.line] = l.slice(0, l.length - m[6].length) + `{ preHandler: rateLimitLogin }, ${m[6]}`;
    } else {
      lines[r.line] = l.slice(0, l.length - m[6].length) + `rateLimitLogin, ${m[6]}`;
    }
  }
  let after = lines.join("\n");
  if (!/\brateLimitLogin\s*=|function\s+rateLimitLogin\b/.test(source)) {
    const ts = isTypeScript(file);
    if (useExpressRateLimit) {
      after = insertAfterImports(after, [
        "// Login rate limit (added by penthera fix): 10 attempts per client per 15 minutes.",
        'const rateLimitLogin = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: "draft-7", legacyHeaders: false });',
      ]);
      after = addImport(after, { name: "rateLimit", module: "express-rate-limit", named: true });
    } else {
      after = insertAfterImports(after, [...coreLines(ts), "", ...wrapperLines(framework, ts)]);
    }
  }
  return { file, before: source, after };
}

function routeFiles(repoPath) {
  const framework = detectFramework(repoPath);
  const out = [];
  for (const file of walkCodeFiles(repoPath)) {
    const source = readText(repoPath, file);
    const routes = source ? authRoutes(file, source, framework) : [];
    if (routes.length) out.push({ file, source, routes });
  }
  return out;
}

/** Login and auth routes in one file with no rate limit. At most PROBE_CAP per file, the worst kept as it goes. */
export function probeRateLimit(file, source, repoFramework) {
  const worst = worstKeeper(file);
  for (const r of eachAuthRoute(file, source, repoFramework)) {
    // A hardening hint, not a proven vulnerability: low, so it never fails CI on its own.
    worst.add({
      severity: "low",
      title: `Login route without rate limiting: ${r.method} ${r.path}`,
      description: `Defined in ${file}:${r.line + 1}`,
      url: file,
      file,
      line: r.line + 1,
      route: r.path,
      category: "rate-limiting",
      source: "fix-probe:rate-limit",
    }, r.line);
  }
  return worst.result();
}

function routeOf(finding) {
  return finding.route || (finding.title || "").match(/(?:rate limiting|rate limit)[^/]*?(?:(?:POST|PUT|ALL)\s+)?(\/\S*)/i)?.[1] || finding.url || "";
}

export default {
  id: "auth-rate-limit",
  title: "Rate-limit login and auth routes",
  matches(finding) {
    const isRate = finding.category === "rate-limiting" || /rate limit/i.test(finding.title || "");
    if (!isRate) return false;
    const route = routeOf(finding);
    try {
      return isAuthPath(route.startsWith("http") ? new URL(route).pathname : route);
    } catch {
      return false;
    }
  },
  detect(repoPath) {
    const fw = detectFramework(repoPath);
    return ["next", "express", "fastify", "hono"].includes(fw) ? fw : null;
  },
  plan(repoPath, finding) {
    let route = routeOf(finding);
    try {
      if (route.startsWith("http")) route = new URL(route).pathname;
    } catch { /* keep as-is */ }
    const target = routeFiles(repoPath).find((f) => f.routes.some((r) => r.path === route));
    if (!target) return null;
    const change = toDiff([fixFile(repoPath, target.file, target.source, target.routes)]);
    if (!change) return null;
    return {
      ...change,
      ownerActions: [
        "The limiter is in memory and per process. Move it to a shared store (Redis, your platform's limiter, or a WAF rule) before you run more than one instance.",
        "Make sure the client IP is the real one: set Express `trust proxy` behind a proxy, and only trust X-Forwarded-For from your own edge. Consider also limiting per account.",
      ],
      confidence: "medium",
    };
  },
  /** ctx.framework: the repo's framework, detected once per scan. */
  probeSource(file, source, ctx = {}) {
    return probeRateLimit(file, source, ctx.framework);
  },
  probe(repoPath) {
    const framework = detectFramework(repoPath);
    const findings = [];
    for (const file of walkCodeFiles(repoPath)) {
      const source = readText(repoPath, file);
      if (source) findings.push(...probeRateLimit(file, source, framework));
    }
    return findings;
  },
};
