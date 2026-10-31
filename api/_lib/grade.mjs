/**
 * Grades one response: transport, headers, cookies and what it gives away.
 * Header rules are the CLI's own (lib/blackbox/headers.js), so the site and
 * `npx penthera <url>` agree; the rest needs the live response and lives here.
 * Each check has a weight; the score is the share of weight that passed.
 * The passive report (tier1.mjs) adds the page, DNS and security.txt checks
 * through opts.extra; a check with weight 0 is a note that does not move the
 * score (a visible version, a key that may be public by design, a DNS answer
 * that did not come).
 *
 * A failed check with severity critical caps the score at 40, high at 69.
 *
 * Weights for a site that passes everything (sum, so a clean site scores 100):
 *   transport 42 (https 22, hsts 12, tls 4, cert 4)
 *   headers   36 (csp 14, framing 8, nosniff 8, referrer 4, permissions 2) + csp-scripts 4, cors 4 when present
 *   disclosure 6, cookies 8 when cookies are set
 *   page      secrets 14, libraries 8, mixed-content 6 (https only), sri 4 and
 *             source-maps 2 (only when there is something to judge)
 *   email     dmarc 4, spf 3, caa 2;  contact: security-txt 3
 */
import { auditSecurityHeaders } from "../../lib/blackbox/headers.js";

/** The share of weight that passed, under the caps. */
export function scoreOf(checks) {
  const total = checks.reduce((n, c) => n + c.weight, 0);
  const got = checks.reduce((n, c) => n + (c.passed ? c.weight : 0), 0);
  // A failed critical or high check caps the score, so a leaked key or a
  // vulnerable library can never hide behind good headers.
  const failed = checks.filter((c) => !c.passed);
  const cap = failed.some((c) => c.severity === "critical") ? 40 : failed.some((c) => c.severity === "high") ? 69 : 100;
  return Math.min(cap, Math.round((got / total) * 100));
}

export const CATEGORIES = {
  transport: "Connection",
  headers: "Browser protections",
  cookies: "Cookies",
  disclosure: "What it gives away",
  software: "Server software",
  page: "What the page loads",
  secrets: "Secrets in the page",
  email: "Email and DNS",
  contact: "Security contact",
};

const DAY = 86_400_000;
const curl = (url, header) => `curl -sI ${url}${header ? ` | grep -i ${header}` : ""}`;

/** CLI header rules, by title, as graded checks. */
const FROM_CLI = {
  "Missing Content-Security-Policy": {
    id: "csp", weight: 14, category: "headers",
    fix: "Send a Content-Security-Policy header. Start with default-src 'self' and add only the origins the page needs; avoid 'unsafe-inline' in script-src.",
    header: "content-security-policy",
  },
  "Missing X-Frame-Options": {
    id: "framing", weight: 8, category: "headers",
    fix: "Stop other sites from framing the page: send frame-ancestors 'none' (or 'self') in the CSP, or X-Frame-Options: DENY.",
    header: "x-frame-options",
  },
  "Missing X-Content-Type-Options": {
    id: "nosniff", weight: 8, category: "headers",
    fix: "Send X-Content-Type-Options: nosniff on every response.",
    header: "x-content-type-options",
  },
  "Missing Referrer-Policy": {
    id: "referrer", weight: 4, category: "headers",
    fix: "Send Referrer-Policy: strict-origin-when-cross-origin (or no-referrer).",
    header: "referrer-policy",
  },
  "Missing Permissions-Policy": {
    id: "permissions", weight: 2, category: "headers",
    fix: "Send a Permissions-Policy that turns off what the page does not use, such as camera=(), microphone=(), geolocation=().",
    header: "permissions-policy",
  },
};

const get = (headers, name) => {
  const v = headers[name];
  return Array.isArray(v) ? v.join(", ") : v ? String(v) : "";
};

/**
 * @param {{url: string, status: number, headers: object, tls: object|null, hops: object[]}} res
 * @param {{now?: number, extra?: object[], scope?: string}} opts
 */
export function grade(res, { now = Date.now(), extra = [], scope } = {}) {
  const { headers, url } = res;
  const secure = url.startsWith("https://");
  const checks = [];
  const add = (c) => checks.push({ severity: "info", evidence: "", fix: "", verify: "", ...c });

  // ── Connection ────────────────────────────────────────────────────────
  add({
    id: "https", weight: 22, category: "transport", passed: secure,
    severity: "high", title: secure ? "Served over HTTPS" : "No HTTPS: pages travel in cleartext",
    evidence: secure ? "" : `Final address: ${url}`,
    fix: "Serve the site over HTTPS only and redirect http:// to https://. Most hosts (Vercel, Netlify, Cloudflare) do this with one setting.",
    verify: curl(url.replace(/^https?:/, "http:"), "location"),
  });
  if (secure) {
    const proto = res.tls?.protocol || "";
    const modern = /TLSv1\.[23]/.test(proto);
    add({
      id: "tls", weight: 4, category: "transport", passed: modern || !proto,
      severity: "medium", title: modern || !proto ? `TLS ${proto.replace("TLSv", "") || "negotiated"}` : `Old TLS version: ${proto}`,
      evidence: proto ? `Negotiated ${proto}` : "",
      fix: "Turn off TLS 1.0 and 1.1 on the server or CDN; keep TLS 1.2 and 1.3.",
      verify: `openssl s_client -connect ${new URL(url).host}:443 -tls1_1 </dev/null`,
    });
    const days = res.tls?.validTo ? Math.floor((Date.parse(res.tls.validTo) - now) / DAY) : null;
    add({
      id: "cert", weight: 4, category: "transport", passed: days === null || days >= 14,
      severity: "medium", title: days === null || days >= 14 ? "Certificate valid" : `Certificate expires in ${days} days`,
      evidence: res.tls?.validTo ? `Valid until ${res.tls.validTo}${res.tls.issuer ? `, issued by ${res.tls.issuer}` : ""}` : "",
      fix: "Renew the certificate now and turn on automatic renewal.",
      verify: `echo | openssl s_client -connect ${new URL(url).host}:443 2>/dev/null | openssl x509 -noout -enddate`,
    });
    const hsts = get(headers, "strict-transport-security");
    const maxAge = Number(/max-age=(\d+)/i.exec(hsts)?.[1] || 0);
    add({
      id: "hsts", weight: 12, category: "transport", passed: maxAge >= 15_552_000,
      severity: "medium",
      title: !hsts ? "No Strict-Transport-Security" : maxAge >= 15_552_000 ? "Strict-Transport-Security set" : "Strict-Transport-Security max-age under 180 days",
      evidence: hsts ? `strict-transport-security: ${hsts}` : "No strict-transport-security header",
      fix: "Send Strict-Transport-Security: max-age=63072000; includeSubDomains, so browsers never fall back to http.",
      verify: curl(url, "strict-transport-security"),
    });
  }

  // ── Browser protections and disclosure, from the CLI's rules ───────────
  const cli = auditSecurityHeaders(headers, url, {});
  for (const [title, c] of Object.entries(FROM_CLI)) {
    const missing = cli.some((f) => f.title === title);
    // A CSP frame-ancestors directive does the job of X-Frame-Options.
    const framedByCsp = c.id === "framing" && /frame-ancestors/i.test(get(headers, "content-security-policy"));
    const severity = { csp: "medium", framing: "low", nosniff: "low", referrer: "info", permissions: "info" }[c.id];
    add({
      id: c.id, weight: c.weight, category: c.category, passed: !missing || framedByCsp, severity,
      title: !missing || framedByCsp ? title.replace("Missing ", "") + " set" : title,
      evidence: !missing ? `${c.header}: ${get(headers, c.header).slice(0, 160)}` : framedByCsp ? "frame-ancestors in the CSP" : `No ${c.header} header`,
      fix: c.fix, verify: curl(url, c.header),
    });
  }
  const csp = get(headers, "content-security-policy");
  if (csp) {
    const script = /script-src([^;]*)/i.exec(csp)?.[1] ?? /default-src([^;]*)/i.exec(csp)?.[1] ?? "";
    const unsafe = /'unsafe-inline'|'unsafe-eval'/.test(script) && !/'nonce-|'sha(256|384|512)-|'strict-dynamic'/.test(script);
    add({
      id: "csp-scripts", weight: 4, category: "headers", passed: !unsafe, severity: "low",
      title: unsafe ? "CSP allows inline or eval'd scripts" : "CSP restricts scripts",
      evidence: unsafe ? `script-src${script.trim() ? " " + script.trim().slice(0, 120) : ""}` : "",
      fix: "Drop 'unsafe-inline' and 'unsafe-eval' from script-src; use nonces or hashes for the inline scripts you need.",
      verify: curl(url, "content-security-policy"),
    });
  }
  const powered = get(headers, "x-powered-by");
  const server = get(headers, "server");
  const versioned = /\d+\.\d+/.test(server);
  add({
    id: "disclosure", weight: 6, category: "disclosure", passed: !powered && !versioned, severity: "low",
    title: powered || versioned ? "Server names its software and version" : "No framework or version disclosed",
    evidence: [powered && `x-powered-by: ${powered.slice(0, 80)}`, versioned && `server: ${server.slice(0, 80)}`].filter(Boolean).join("; "),
    fix: "Remove X-Powered-By and the version from Server. Express: app.disable(\"x-powered-by\"). PHP: expose_php = Off. nginx: server_tokens off. Next.js: poweredByHeader: false.",
    verify: curl(url, "-e x-powered-by -e ^server"),
  });
  const acao = get(headers, "access-control-allow-origin");
  const acac = /true/i.test(get(headers, "access-control-allow-credentials"));
  if (acao) {
    add({
      id: "cors", weight: 4, category: "headers", passed: !(acao === "*" && acac) && acao !== "null", severity: "medium",
      title: acao === "*" && acac ? "CORS allows any origin with credentials" : acao === "null" ? "CORS allows the null origin" : "CORS policy set",
      evidence: `access-control-allow-origin: ${acao}${acac ? "; access-control-allow-credentials: true" : ""}`,
      fix: "Allow only the origins that need access, by name, and never * together with credentials.",
      verify: curl(url, "access-control"),
    });
  }

  // ── Cookies set on the first response ──────────────────────────────────
  const cookies = [].concat(headers["set-cookie"] || []);
  if (cookies.length) {
    const weak = cookies.filter((c) => (secure && !/;\s*secure/i.test(c)) || !/;\s*httponly/i.test(c) || !/;\s*samesite=/i.test(c));
    add({
      id: "cookies", weight: 8, category: "cookies", passed: weak.length === 0, severity: "medium",
      title: weak.length ? `${weak.length} of ${cookies.length} cookies miss Secure, HttpOnly or SameSite` : `${cookies.length} cookies, all flagged`,
      evidence: weak.slice(0, 3).map((c) => c.split(";")[0].split("=")[0] + ": " + c.split(";").slice(1).map((s) => s.trim()).join("; ").slice(0, 80)).join(" | "),
      fix: "Set Secure, HttpOnly and SameSite=Lax (or Strict) on session and auth cookies. Only cookies that scripts must read can skip HttpOnly.",
      verify: curl(url, "set-cookie"),
    });
  }

  for (const c of extra) add(c);

  const score = scoreOf(checks);
  return {
    url,
    status: res.status,
    redirects: (res.hops || []).slice(0, -1).map((h) => h.url),
    score,
    verdict: score >= 90 ? "Solid basics" : score >= 70 ? "A few quick fixes" : score >= 45 ? "Important gaps remain" : "Unsafe defaults",
    categories: Object.entries(CATEGORIES).map(([id, label]) => {
      const cs = checks.filter((c) => c.category === id);
      return { id, label, passed: cs.filter((c) => c.passed).length, total: cs.length };
    }).filter((c) => c.total),
    checks: checks.map(({ weight, ...c }) => ({ ...c, weight })),
    scope: scope || "One passive GET request, like a browser's. No paths probed, no payloads sent, nothing stored. For a full scan, run npx penthera on your own machine.",
  };
}
