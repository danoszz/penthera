/**
 * Penthera, URL Scanner (black-box)
 *
 * Multi-phase scanning against a live target:
 *
 *   Default phases (fast, non-intrusive):
 *     1. Reachability check
 *     2. TLS/SSL certificate & cipher audit
 *     3. Tech fingerprinting (httpx-style)
 *     4. Endpoint brute-force with auto-calibration (ffuf-style)
 *     5. Nuclei-style template scanning (14 built-in templates)
 *     6. Supplementary sensitive file checks
 *     7. CORS validation
 *     8. Framework-specific checks (CVEs)
 *     9. Cookie security audit (HttpOnly, Secure, SameSite)
 *    10. Retire.js, vulnerable JS library detection
 *    10b. Secrets in client JS bundles (same-origin scripts only)
 *    11. Arjun-style batched HTTP parameter discovery
 *
 *   --recon (passive OSINT, skipped for localhost):
 *    12. Subdomain discovery via Certificate Transparency (crt.sh)
 *    13. Historical URL mining (Wayback Machine + AlienVault OTX)
 *
 *   --deep (active injection probes, sends attack payloads):
 *    13b. Login rate-limit burst (8 POSTs) and an SQL error smoke string on /api/login
 *    14. SQL injection (error-based + time-based blind)
 *    15. Server-Side Template Injection (SSTI)
 *    16. Server-Side Request Forgery (SSRF)
 *    17. Open redirect detection
 *    18. Command injection
 *    19. Reflected XSS (Dalfox-style context-aware)
 *
 *   --fuzz (property-based API fuzzing):
 *    20. Fuzz discovered POST endpoints with edge-case payloads
 *
 *   --nuclei <path> (community templates):
 *    21. Load and execute YAML templates from nuclei-templates
 *
 *   Localhost support:
 *     Auto-detects localhost/private IPs. Skips OSINT recon,
 *     suppresses irrelevant findings (e.g. missing Secure flag on http://),
 *     and handles http:// gracefully (no TLS check).
 */
import { fingerprint, discoverEndpoints, autoCalibrate } from "../lib/crawler.js";
import { runBuiltInTemplates, headerChangesAnswer } from "../lib/templates.js";
import { fuzzEndpoint } from "../lib/fuzzer.js";
import { checkTls } from "../lib/tls.js";
import { runRecon, extractDomain } from "../lib/recon.js";
import { injectionTargets, runInjectionProbes } from "../lib/injections.js";
import { scanJsLibraries } from "../lib/retirejs.js";
import { discoverAllParams } from "../lib/params.js";
import { scanOpenApi, probeAuthEndpoints } from "../lib/blackbox/openapi.js";
import { blockWarning, botChallenge, challengeFinding } from "../lib/blackbox/challenge.js";
import { probeIdorBola } from "../lib/blackbox/idor.js";
import { probeOAuthMisconfig } from "../lib/blackbox/oauth.js";
import { auditSecurityHeaders } from "../lib/blackbox/headers.js";
import { runtimeAdvisoriesForResponse } from "../lib/advisories/index.js";
import { probeClientSideAuth } from "../lib/blackbox/client-auth.js";
import { probeJwt } from "../lib/blackbox/jwt.js";
import { probeEmailDns, sharedHostDomain } from "../lib/blackbox/email-dns.js";
import { probeBundleSecrets } from "../lib/blackbox/bundle-secrets.js";
import { resolveAuth } from "./utils/auth.js";
import { normalizeBaseUrl, isPrivateHost, joinUrl } from "./utils/url.js";
import { safeFetch, readBody, createEgressContext, runWithEgress, egressSummary, probeErrors } from "./utils/http.js";
import { RECON_HOSTS } from "../lib/recon.js";
import { dedupeFindings } from "./cli/merge-results.js";

const SENSITIVE_RE = /private_key|SECRET|PASSWORD|API_KEY|FIREBASE_|STRIPE_|DATABASE_URL|client_email|\[core\]|\[remote/i;
// A single-page app answers every path with its index.html, whose scripts often
// say "API_KEY". That page is not a leaked file, so HTML never trips SENSITIVE_RE.
// Leading comments are skipped with indexOf, not a regex: a repeated
// (<!--...-->)* group backtracks exponentially on "<!---->" runs.
function isHtmlPage(body) {
  let i = 0;
  for (;;) {
    while (i < body.length && /\s/.test(body[i])) i++;
    if (!body.startsWith("<!--", i)) break;
    const end = body.indexOf("-->", i + 4);
    if (end === -1) return false;
    i = end + 3;
  }
  return /^<(?:!doctype html|html)/i.test(body.slice(i, i + 15));
}
// phpinfo() and mod_status are HTML pages, so they are known by their own text.
const PHPINFO_RE = /<title>[^<]{0,80}phpinfo\(\)[^<]{0,80}<\/title>/i;
const SERVER_STATUS_RE = /Apache Server Status for|Server uptime:|Total accesses:/i;

/**
 * Run a full black-box scan against a URL.
 *
 * @param {string} target - Base URL to scan
 * @param {object} opts - { timeout, concurrency, fuzz, recon, deep, nucleiPath, onPhase }
 * @returns {object} Scan result with findings
 */
export async function scanUrl(rawTarget, opts = {}) {
  const target = normalizeBaseUrl(rawTarget);
  const bypass = vercelBypass(target, opts);
  // Every request in this scan goes through one egress context: it enforces
  // --offline or the MCP scope, sets the User-Agent, applies --rate, and records hosts contacted and probe errors.
  const ctx = createEgressContext({
    target,
    offline: opts.offline,
    scoped: opts.scoped,
    userAgent: opts.userAgent,
    allowHosts: opts.allowHosts,
    rateLimit: opts.rateLimit,
    targetHeaders: bypass.header ? { [VERCEL_BYPASS_HEADER]: bypass.header } : {},
  });
  const result = await runWithEgress(ctx, () => scanUrlInContext(target, opts));
  result.egress = egressSummary(ctx);
  result.errors = probeErrors(ctx);
  if (bypass.note) result.egress.vercelBypass = bypass.note;
  return bypass.secret ? scrubSecret(result, bypass.secret) : result;
}

/** PENTHERA_VERCEL_BYPASS: sent only to an https *.vercel.app target, never from MCP. */
export const VERCEL_BYPASS_HEADER = "x-vercel-protection-bypass";
export function vercelBypass(target, opts = {}, env = process.env) {
  const secret = env.PENTHERA_VERCEL_BYPASS ?? "";
  if (!secret) return { secret, header: "", note: null };
  // URL-safe: no header injection or encoded copy.
  if (!/^[\w.~-]{16,128}$/.test(secret)) throw new Error("PENTHERA_VERCEL_BYPASS: 16-128 of A-Za-z0-9._~- only; nothing scanned");
  const u = new URL(target);
  const no = opts.scoped ? "MCP scan" : u.protocol !== "https:" || !/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.vercel\.app$/.test(u.hostname) ? "not *.vercel.app" : "";
  return { secret, header: no ? "" : secret, note: no ? `not sent: ${no}` : "sent to target only" };
}

/** Deep copy, every `secret` redacted. */
export function scrubSecret(v, secret) {
  const s = (x) => scrubSecret(x, secret);
  if (!secret) return v;
  if (typeof v === "string") return v.split(secret).join("[redacted]");
  if (Array.isArray(v)) return v.map(s);
  return v && [Object.prototype, null].includes(Object.getPrototypeOf(v)) ? Object.fromEntries(Object.entries(v).map(([k, x]) => [s(k), s(x)])) : v;
}

async function scanUrlInContext(target, opts) {
  const timeout = opts.timeout || 10_000;
  const concurrency = opts.concurrency || 15;
  const progress = opts.onPhase || (() => {});
  const startTime = Date.now();

  const local = isPrivateHost(target);
  // Set false when the Retire.js database can't load, so we don't claim the probe ran.
  let retireJsRan = false;
  // Set true once the bundle secret scan has run, for executedProbes
  let bundleScanRan = false;
  const hostname = new URL(target).hostname;
  const isIpHost = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.includes(":");
  const sharedHost = sharedHostDomain(hostname);

  const result = {
    target,
    mode: "url",
    local,
    timestamp: new Date().toISOString(),
    duration: 0,
    reachable: false,
    tls: null,
    fingerprint: null,
    openapi: null,
    recon: null,
    endpoints: { total: 0, discovered: 0, byStatus: {}, list: [] },
    cookies: null,
    jsLibraries: null,
    paramDiscovery: null,
    emailAuth: null,
    executedProbes: [],
    findings: [],
  };

  // ── Phase 1: Reachability ──────────────────────────────────────────────
  progress("Checking target reachability...");
  try {
    const res = await safeFetch(target, { timeout, probe: "reachability" });
    result.httpStatus = res?.status;
    const blocked = res ? blockWarning(res.status, res.headers, target) : null;
    if (blocked) result.findings.push(blocked);
    // A firewall's 503 is a refusal, handled below. The server's own 5xx means the app is down.
    result.reachable = res != null && (res.status < 500 || botChallenge(res.headers) != null);
  } catch {
    result.reachable = false;
  }

  if (!result.reachable) {
    result.duration = Date.now() - startTime;
    return result;
  }

  // ── Phase 2: TLS/SSL audit ─────────────────────────────────────────────
  const parsedUrl = new URL(target);
  if (parsedUrl.protocol === "https:") {
    progress("Auditing TLS certificate and ciphers...");
    try {
      const tlsResult = await checkTls(parsedUrl.hostname, parseInt(parsedUrl.port) || 443);
      result.tls = tlsResult;
      // Add TLS findings
      for (const f of tlsResult.findings || []) {
        result.findings.push({
          ...f,
          url: target,
          category: "tls",
          source: "tls-check",
        });
      }
    } catch {
      // TLS check failed, not critical
    }
  }

  // DNS TXT/MX queries go to resolvers, not the target, so --offline skips them.
  const checkEmailAuth = async () => {
    if (local || isIpHost) return;
    if (opts.offline) {
      progress("Skipping email authentication (--offline: no DNS lookups for SPF, DMARC, MX)...");
      return;
    }
    if (sharedHost) {
      result.findings.push({
        severity: "info",
        title: "Mail checks skipped on a shared domain",
        description: `${sharedHost} is the platform's domain, so its SPF and DMARC say nothing about ${hostname}. Check the domain you send mail from.`,
        url: target,
        category: "scan",
        source: "email-dns-probe",
        confidence: "confirmed",
      });
      return;
    }
    progress("Checking email authentication (SPF, DMARC)...");
    try {
      const emailResult = await probeEmailDns(extractDomain(target));
      result.emailAuth = {
        spf: emailResult.spf,
        dmarc: emailResult.dmarc,
        dmarcPolicy: emailResult.dmarcPolicy,
        mxCount: emailResult.mxCount,
      };
      result.findings.push(...emailResult.findings);
    } catch { /* DNS failure, non-critical */ }
  };

  // ── Phase 3: Fingerprint ───────────────────────────────────────────────
  progress("Fingerprinting target...");
  result.fingerprint = await fingerprint(target);

  // A firewall challenging the scanner: everything after this would measure
  // the challenge page, so stop and say so instead of reporting its headers.
  const challenge = botChallenge(result.fingerprint?.headers);
  if (challenge) {
    result.challenge = challenge;
    result.findings.push(challengeFinding(challenge, target));
    // A firewall guards the site, not its DNS, so the mail checks still mean what they say. They
    // stay out of executedProbes: a refused scan must never read as covered.
    await checkEmailAuth();
    result.duration = Date.now() - startTime;
    return result;
  }

  // ── Phase 4: Endpoint discovery ────────────────────────────────────────
  progress("Discovering endpoints (brute-force)...");
  const isInteresting = await autoCalibrate(target);
  const raw = await discoverEndpoints(target, { concurrency, timeout });

  const filtered = raw.filter((ep) => {
    if (ep.status === 404) return false;
    if (ep.status === 405) return true;
    if (!isInteresting) return ep.status !== 404;
    return isInteresting(ep);
  });

  result.endpoints.total = raw.length;
  result.endpoints.discovered = filtered.length;
  result.endpoints.list = filtered;
  for (const ep of filtered) {
    result.endpoints.byStatus[ep.status] = (result.endpoints.byStatus[ep.status] || 0) + 1;
  }

  // ── Phase 4b: Security headers ─────────────────────────────────────────
  progress("Auditing security headers...");
  if (result.fingerprint?.headers) {
    result.findings.push(...auditSecurityHeaders(result.fingerprint.headers, target, { local, liveResponse: true }));
  }

  // ── Phase 4b2: Runtime advisories (PHP, nginx, Apache, ... versions) ───
  progress("Checking runtime and server versions against advisories...");
  if (result.fingerprint?.headers) {
    const phpPaths = filtered.filter((ep) => ep.status >= 200 && ep.status < 400 && /\.php(?:$|[?#])/i.test(ep.path)).map((ep) => ep.path);
    result.findings.push(...runtimeAdvisoriesForResponse(result.fingerprint, { phpPaths, url: target }));
  }

  // ── Phase 4c: OpenAPI / auth probes ────────────────────────────────────
  progress("Scanning OpenAPI spec and auth endpoints...");
  const openApiResult = await scanOpenApi(target, { timeout });
  result.openapi = {
    specUrl: openApiResult.specUrl,
    pathCount: openApiResult.paths.length,
    unprotectedRoutes: openApiResult.unprotectedRoutes?.length || 0,
  };
  result.findings.push(...openApiResult.findings);

  // Login probes: none in quick, one invalid-credential POST in standard, the
  // rate-limit burst and SQLi smoke string only with --deep (profiles.js).
  const loginProbe = opts.loginProbe || (opts.deep ? "full" : opts.profile === "quick" ? "none" : "single");
  if (loginProbe !== "none") {
    const authFindings = await probeAuthEndpoints(target, { timeout, level: loginProbe });
    result.findings.push(...authFindings);
  }

  const clientAuthFindings = await probeClientSideAuth(target, { timeout });
  result.findings.push(...clientAuthFindings);

  const auth = resolveAuth(opts);
  if (auth.bearer) {
    const jwtFindings = await probeJwt(target, {
      timeout,
      bearerToken: auth.bearer.replace(/^Bearer\s+/i, ""),
      testPath: opts.authTestPath || "/api/user/profile",
    });
    result.findings.push(...jwtFindings);
  }

  progress("Probing IDOR/BOLA on parameterized routes...");
  const idorFindings = await probeIdorBola(target, {
    timeout,
    spec: openApiResult.spec,
    paths: openApiResult.paths,
    authHeaders: auth.headers,
  });
  result.findings.push(...idorFindings);

  progress("Checking OAuth misconfigurations...");
  result.findings.push(...await probeOAuthMisconfig(target, { timeout }));

  // ── Phase 5: Template scanning ─────────────────────────────────────────
  progress("Running template scan (built-in templates)...");
  const templateFindings = await runBuiltInTemplates(target);
  for (const f of templateFindings) {
    result.findings.push({
      severity: f.severity,
      title: f.name,
      description: f.description || "",
      url: f.matchedUrl,
      status: f.status,
      category: f.tags?.[0] || "template",
      source: "template",
      templateId: f.templateId,
    });
  }

  // ── Phase 6: Supplementary sensitive file checks ───────────────────────
  progress("Checking sensitive files...");
  const extraFiles = [
    { path: "/.env.production", severity: "critical", desc: "Production environment secrets" },
    { path: "/service-account.json", severity: "critical", desc: "GCP service account key" },
    { path: "/firebase.json", severity: "medium", desc: "Firebase project config" },
    { path: "/firestore.rules", severity: "medium", desc: "Firestore security rules" },
    { path: "/storage.rules", severity: "medium", desc: "Firebase Storage rules" },
    { path: "/.htaccess", severity: "medium", desc: "Apache configuration" },
    { path: "/web.config", severity: "medium", desc: "IIS configuration" },
    { path: "/phpinfo.php", severity: "high", desc: "PHP info page", page: PHPINFO_RE },
    { path: "/server-status", severity: "medium", desc: "Apache server status", page: SERVER_STATUS_RE },
    { path: "/actuator", severity: "high", desc: "Spring Boot actuator" },
    { path: "/actuator/env", severity: "critical", desc: "Spring Boot environment" },
    { path: "/wp-login.php", severity: "info", desc: "WordPress login page" },
    { path: "/robots.txt", severity: "info", desc: "Robots configuration" },
    { path: "/.well-known/security.txt", severity: "info", desc: "Security contact" },
  ];

  const checkedPaths = new Set(templateFindings.map((f) => new URL(f.matchedUrl).pathname));
  const unchecked = extraFiles.filter((f) => !checkedPaths.has(f.path));

  await Promise.allSettled(
    unchecked.map(async (file) => {
      const res = await safeFetch(joinUrl(target, file.path), { timeout: 5_000, probe: "sensitive-files" });
      if (!res || res.status !== 200) return;
      const text = await readBody(res).catch(() => "");

      if (file.severity === "info") {
        result.findings.push({
          severity: "info",
          title: `${file.path} accessible`,
          description: file.desc,
          url: joinUrl(target, file.path),
          status: 200,
          category: "exposure",
          source: "sensitive-file-check",
        });
        return;
      }

      const exposed = file.page ? file.page.test(text) : !isHtmlPage(text) && SENSITIVE_RE.test(text);
      if (exposed) {
        result.findings.push({
          severity: file.severity,
          title: `${file.path} contains sensitive data`,
          description: file.desc,
          url: joinUrl(target, file.path),
          status: 200,
          category: "exposure",
          source: "sensitive-file-check",
        });
      }
    }),
  );

  // ── Phase 7: CORS spot-check ───────────────────────────────────────────
  progress("Testing CORS policy...");
  const corsEndpoint = filtered.find((ep) => ep.path.includes("/api/"))?.path || "/";
  for (const evilOrigin of ["https://evil-attacker.com", "null"]) {
    const res = await safeFetch(joinUrl(target, corsEndpoint), {
      headers: { Origin: evilOrigin },
      timeout: 5_000,
      probe: "cors",
    });
    if (!res) continue;
    const acao = res.headers.get("access-control-allow-origin");
    if (acao === evilOrigin) {
      result.findings.push({
        severity: evilOrigin === "null" ? "high" : "medium",
        title: `CORS reflects ${evilOrigin === "null" ? "null" : "arbitrary"} origin`,
        description: `${corsEndpoint} reflects Origin: ${evilOrigin}`,
        url: joinUrl(target, corsEndpoint),
        status: res.status,
        category: "cors",
        source: "cors-check",
      });
    }
  }

  // ── Phase 8: Framework-specific checks ─────────────────────────────────
  progress("Running framework-specific checks...");
  const adminEndpoints = filtered.filter(
    (ep) => ep.path.includes("/admin") || ep.path.includes("/api/admin"),
  );
  for (const ep of adminEndpoints.slice(0, 3)) {
    const headers = { "x-middleware-subrequest": "middleware:middleware:middleware:middleware:middleware" };
    const res = await safeFetch(`${target}${ep.path}`, { headers, timeout: 5_000, probe: "framework-check" });
    if (res && res.status === 200) {
      const changed = await headerChangesAnswer(`${target}${ep.path}`, headers, { timeout: 5_000, probe: "framework-check" }).catch(() => false);
      if (!changed) continue;
      const alreadyFound = result.findings.some(
        (f) => f.templateId === "cve-2025-29927-nextjs-middleware-bypass" && f.url?.includes(ep.path),
      );
      if (!alreadyFound) {
        result.findings.push({
          severity: "critical",
          title: `CVE-2025-29927: middleware bypass on ${ep.path}`,
          description: "x-middleware-subrequest header bypasses auth",
          url: `${target}${ep.path}`,
          status: 200,
          category: "cve",
          source: "framework-check",
        });
      }
    }
  }

  // ── Phase 9: Cookie Security Audit ──────────────────────────────────────
  progress("Auditing cookie security...");
  try {
    const cookieRes = await safeFetch(target, { timeout, probe: "cookie" });
    if (cookieRes) {
      const setCookies = cookieRes.headers.getSetCookie?.() || [];
      if (setCookies.length > 0) {
        const cookies = [];
        for (const raw of setCookies) {
          const name = raw.split("=")[0].trim();
          const lower = raw.toLowerCase();
          const flags = {
            secure: lower.includes("secure"),
            httpOnly: lower.includes("httponly"),
            sameSite: lower.match(/samesite=(strict|lax|none)/i)?.[1] || null,
          };
          cookies.push({ name, ...flags, raw });

          const issues = [];
          if (!flags.httpOnly) issues.push("missing HttpOnly");
          if (!flags.secure && !local) issues.push("missing Secure");
          if (!flags.sameSite) issues.push("missing SameSite");

          if (issues.length > 0) {
            const isSession = /sess|token|auth|jwt|sid/i.test(name);
            result.findings.push({
              severity: isSession ? "medium" : "low",
              title: `Cookie "${name}" ${issues.join(", ")}`,
              description: `Set-Cookie: ${raw.slice(0, 120)}`,
              url: target,
              category: "cookie",
              source: "cookie-audit",
            });
          }
        }
        result.cookies = cookies;
      }
    }
  } catch { /* non-critical */ }

  // ── Phase 9b: Email authentication posture (SPF/DMARC via DNS) ─────────
  await checkEmailAuth();

  // ── Phase 10: Retire.js, Vulnerable JS Libraries ─────────────────────
  if (!opts.skipRetireJs) {
    progress("Scanning for vulnerable JS libraries (Retire.js)...");
    try {
      const jsResult = await scanJsLibraries(target, { onPhase: progress });
      // Only count the probe as run when its database actually loaded, so the
      // WSTG and compliance coverage can't claim a check that was skipped.
      retireJsRan = jsResult.dbLoaded !== false;
      if (jsResult.dbSource) {
        result.retireDb = { source: jsResult.dbSource, snapshotDate: jsResult.dbSnapshotDate || null };
      }
      if (jsResult.libraries.length > 0) {
        result.jsLibraries = jsResult.libraries;
      }
      result.findings.push(...jsResult.findings);
    } catch { /* non-critical */ }
  }

  // Phase 10b: Secrets in client JS bundles 
  // same switch as Retire.js: both read the scripts the home page loads
  if (!opts.skipRetireJs) {
    progress("Scanning client JS bundles for leaked keys...");
    try {
      result.findings.push(...await probeBundleSecrets(target, { timeout }));
      bundleScanRan = true;
    } catch { /* non-critical */ }
  }

  // ── Phase 11: Parameter Discovery (Arjun-style) ───────────────────────
  if (!opts.skipParamDiscovery && filtered.length > 0) {
    progress("Discovering hidden parameters (Arjun-style)...");
    try {
      const paramResult = await discoverAllParams(target, filtered, {
        onPhase: progress,
        maxEndpoints: 5,
      });
      if (paramResult.results.length > 0) {
        result.paramDiscovery = paramResult.results.filter((r) => r.params.length > 0);
      }
      result.findings.push(...paramResult.findings);
    } catch { /* non-critical */ }
  }

  // ── Phase 12-13: OSINT Recon (--recon) ────────────────────────────────
  if (opts.recon && local) {
    progress("Skipping OSINT recon (localhost target)...");
  }
  if (opts.recon && !local && opts.offline) {
    progress(`Skipping OSINT recon (--offline: no queries to ${RECON_HOSTS.join(", ")})...`);
  }
  if (opts.recon && !local && !opts.offline) {
    const domain = extractDomain(target);
    progress(`Running OSINT recon on ${domain}...`);
    try {
      result.recon = await runRecon(domain, { onPhase: progress });

      // Add recon-discovered endpoints to the discovery pool
      if (result.recon.endpoints.length > 0) {
        progress(`Probing ${result.recon.endpoints.length} historically known endpoints...`);
        for (const path of result.recon.endpoints.slice(0, 50)) {
          const res = await safeFetch(`${target}${path}`, { timeout: 5_000, probe: "recon" });
          if (res && res.status !== 404 && res.status < 500) {
            const alreadyKnown = filtered.some((ep) => ep.path === path);
            if (!alreadyKnown) {
              filtered.push({ path, status: res.status, size: 0 });
              result.endpoints.discovered++;
            }
          }
        }
        // Update byStatus
        result.endpoints.byStatus = {};
        for (const ep of filtered) {
          result.endpoints.byStatus[ep.status] = (result.endpoints.byStatus[ep.status] || 0) + 1;
        }
      }
    } catch (e) {
      result.findings.push({
        severity: "info",
        title: "OSINT recon partially failed",
        description: e.message,
        category: "recon",
        source: "recon",
      });
    }
  }

  // ── Phase 14-19: Injection Probes (--deep) ─────────────────────────────
  if (opts.deep) {
    progress("Running active injection probes (SQLi, SSTI, SSRF, redirect, CMDi, XSS)...");
    result.deepReach = { found: filtered.length, probed: injectionTargets(filtered, 10).map((ep) => ep.path) };
    const injectionFindings = await runInjectionProbes(target, filtered, {
      onPhase: progress,
      maxEndpoints: 10,
    });
    result.findings.push(...injectionFindings);
  }

  // ── Phase 20: Fuzzing (--fuzz) ──────────────────────────────────────────
  if (opts.fuzz) {
    progress("Fuzzing discovered POST endpoints...");
    const postCandidates = filtered.filter(
      (ep) => ep.status !== 404 && (ep.path.includes("/api/") || ep.path.includes("/graphql")),
    );

    for (const ep of postCandidates.slice(0, 5)) {
      const findings = await fuzzEndpoint(
        target,
        ep.path,
        { email: "test@example.com", name: "Test", message: "Hello", id: "test-id" },
        { maxPayloads: 15, timeout: 8_000 },
      );

      for (const f of findings) {
        result.findings.push({
          severity: f.status === 500 ? "medium" : "low",
          title: `Fuzz: ${f.detail || "interesting response"}`,
          description: `field=${f.field} payload=${String(f.payload).slice(0, 60)}`,
          url: `${target}${ep.path}`,
          status: f.status,
          category: "fuzzing",
          source: "fuzzer",
        });
      }
    }
  }

  // ── Phase 21: Custom templates (--templates / --nuclei) ─────────────────
  const templatePaths = [
    ...(opts.templatePaths || []),
    ...(opts.nucleiPath ? [opts.nucleiPath] : []),
  ];

  if (templatePaths.length > 0) {
    progress(`Loading templates from ${templatePaths.length} path(s)...`);
    try {
      const { loadTemplatesFromPaths, runTemplateScan } = await import("../lib/plugins.js");
      const templates = await loadTemplatesFromPaths(templatePaths, {
        severity: ["critical", "high", "medium"],
      });
      progress(`Loaded ${templates.length} templates, scanning...`);
      // Templates needing Nuclei features this loader doesn't implement won't
      // match even against a vulnerable target. Say so rather than letting the
      // silence read as a clean result.
      const limited = templates.filter((t) => t.unsupported?.length);
      if (limited.length > 0) {
        const reasons = [...new Set(limited.flatMap((t) => t.unsupported))];
        progress(`${limited.length} template(s) use unsupported features and cannot match: ${reasons.join("; ")}`);
        result.findings.push({
          severity: "info",
          title: `${limited.length} community template(s) could not run fully`,
          description: `These templates rely on Nuclei features Penthera does not implement (${reasons.join("; ")}), so they cannot produce a match. Their silence is not a clean result. Templates affected: ${limited.slice(0, 5).map((t) => t.id).join(", ")}${limited.length > 5 ? ", ..." : ""}.`,
          category: "config",
          source: "plugin-loader",
          confidence: "confirmed",
        });
      }
      const pluginFindings = await runTemplateScan(target, templates, { onPhase: progress });
      result.findings.push(...pluginFindings);
    } catch (e) {
      result.findings.push({
        severity: "info",
        title: "Template loading failed",
        description: e.message,
        category: "config",
        source: "plugin-loader",
      });
    }
  }

  // ── Phase 22: Adaptive probes (--adaptive) ─────────────────────────────
  if (opts.adaptive) {
    progress("Running adaptive security probes...");
    try {
      const { runAdaptiveProbes } = await import("../lib/blackbox/adaptive-scan.js");
      const adaptiveFindings = await runAdaptiveProbes(target, {
        spec: openApiResult.spec,
        paths: openApiResult.paths,
        endpoints: filtered,
        onPhase: progress,
      });
      result.findings.push(...adaptiveFindings);
    } catch (e) {
      result.findings.push({
        severity: "info",
        title: "Adaptive probe phase failed",
        description: e.message,
        category: "config",
        source: "adaptive-probe",
      });
    }
  }

  // ── Record which probes actually executed ──────────────────────────────
  // Drives an honest WSTG coverage report: we only claim a probe ran when it
  // truly did. (Unreachable targets return early above with executedProbes: [].)
  const hadEndpoints = filtered.length > 0;
  result.executedProbes = [
    "reachability", "endpoint-discovery", "openapi", "auth-hardening",
    "client-auth", "idor", "oauth", "sensitive-files", "cors", "cookie",
    ...(!local && !isIpHost && !sharedHost ? ["email-dns"] : []),
    ...(result.tls ? ["tls"] : []),
    ...(result.fingerprint?.headers ? ["security-headers", "runtime-advisories"] : []),
    ...(auth.bearer ? ["jwt"] : []),
    ...(!opts.skipRetireJs && retireJsRan ? ["retirejs"] : []),
    ...(bundleScanRan ? ["bundle-scan"] : []),
    ...(!opts.skipParamDiscovery && hadEndpoints ? ["param-discovery"] : []),
    ...(opts.recon && !local && !opts.offline ? ["recon"] : []),
    ...(opts.deep && hadEndpoints ? ["sqli", "ssti", "ssrf", "xss", "cmdi", "open-redirect"] : []),
    ...(opts.fuzz && filtered.some((ep) => ep.path.includes("/api/") || ep.path.includes("/graphql")) ? ["api-fuzzing"] : []),
    ...(opts.adaptive ? ["adaptive"] : []),
  ];

  // ── Deduplicate findings ───────────────────────────────────────────────
  result.findings = dedupeFindings(result.findings);

  result.duration = Date.now() - startTime;
  return result;
}
