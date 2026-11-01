/**
 * HTTP security header audit.
 */

const HEADER_CHECKS = [
  {
    header: "x-frame-options",
    severity: "low",
    title: "Missing X-Frame-Options",
    description: "Page can be embedded in iframes (clickjacking risk).",
    category: "headers",
  },
  {
    header: "content-security-policy",
    severity: "medium",
    title: "Missing Content-Security-Policy",
    description: "No CSP, inline scripts and third-party resources are unrestricted.",
    category: "headers",
  },
  {
    header: "x-content-type-options",
    severity: "low",
    title: "Missing X-Content-Type-Options",
    description: "Browser may MIME-sniff responses (XSS aid).",
    category: "headers",
  },
  {
    header: "referrer-policy",
    severity: "info",
    title: "Missing Referrer-Policy",
    description: "Referrer headers may leak internal URLs to third parties.",
    category: "headers",
  },
  {
    header: "permissions-policy",
    severity: "info",
    title: "Missing Permissions-Policy",
    description: "Browser features (camera, geolocation) are not restricted by policy header.",
    category: "headers",
  },
];

export const CSP_NO_SCRIPTS = "Content-Security-Policy does not control scripts";

/** Each policy of a CSP as directive name to sources, lower-cased. A repeated directive keeps its first value, as a browser does. */
function cspPolicies(value) {
  return String(value).split(",").map((policy) => {
    const directives = new Map();
    for (const part of policy.split(";")) {
      const [name, ...sources] = part.trim().toLowerCase().split(/\s+/);
      if (name && !directives.has(name)) directives.set(name, sources);
    }
    return directives;
  });
}

/** The sources that govern scripts, one list per policy that has any. */
export function cspScriptSources(value) {
  return cspPolicies(value).map((d) => d.get("script-src-elem") ?? d.get("script-src") ?? d.get("default-src")).filter(Boolean);
}

/** Whether a CSP limits who may frame the page, which does X-Frame-Options' job. */
export function cspLimitsFraming(value) {
  return cspPolicies(value).some((d) => d.has("frame-ancestors") && !d.get("frame-ancestors").includes("*"));
}

// A bare scheme, or a host of `*` or `*.tld`, with any scheme, port or path: all of these name no one in particular.
const ANY_HOST = /^(?:https?:|data:|(?:[a-z][a-z0-9+.-]*:\/\/)?\*(?:\.[a-z]+)?(?::(?:\*|\d+))?(?:\/.*)?)$/;
// With 'strict-dynamic', a browser ignores host sources and trusts only the nonce or hash.
const trustsTokens = (sources) => sources.includes("'strict-dynamic'") && sources.some((s) => /^'(?:nonce-|sha(?:256|384|512)-)/.test(s));

/**
 * Whether a CSP governs scripts: a policy names their sources and doesn't let any host run them.
 * Stricter than the study's rule, which only asks that a directive is named, so the study's
 * figures aren't this rule's. A policy with only `frame-ancestors` leaves every script allowed.
 */
export function cspControlsScripts(value) {
  return cspScriptSources(value).some((sources) => trustsTokens(sources) || !sources.some((s) => ANY_HOST.test(s)));
}

/** A header's value, whatever the case of its name; "" when absent. */
function headerValue(headers, name) {
  const key = Object.keys(headers).find((h) => h.toLowerCase() === name);
  return key ? String(headers[key]).trim() : "";
}

/**
 * @param {Record<string, string>} headers - lowercase header map
 * @param {string} url
 * @param {object} opts
 * @param {boolean} [opts.liveResponse] - the values are what a server sent. The fix flow's code
 *   probe knows only that a header is set, so it can't judge a value and leaves this off.
 */
export function auditSecurityHeaders(headers = {}, url, opts = {}) {
  const findings = [];
  const local = opts.local || false;
  const isHttps = url.startsWith("https://");

  for (const check of HEADER_CHECKS) {
    const present = Object.keys(headers).some((h) => h.toLowerCase() === check.header);
    if (present) continue;
    if (check.header === "x-frame-options" && cspLimitsFraming(headerValue(headers, "content-security-policy"))) continue;

    findings.push({
      severity: check.severity,
      title: check.title,
      description: check.description,
      url,
      category: check.category,
      source: "header-audit",
    });
  }

  const csp = headerValue(headers, "content-security-policy");
  if (opts.liveResponse && Object.keys(headers).some((h) => h.toLowerCase() === "content-security-policy") && !cspControlsScripts(csp)) {
    findings.push({
      severity: "medium",
      title: CSP_NO_SCRIPTS,
      description: "The policy names no script sources, or lets any host run scripts, so a browser runs them from anywhere, as it would with no CSP.",
      evidence: `content-security-policy: ${csp.slice(0, 120)}`,
      remediation: "Set default-src 'self' or a script-src, list only the origins the page needs, and drop *, http: and https:.",
      url,
      category: "headers",
      source: "header-audit",
      confidence: "confirmed",
    });
  }

  if (!isHttps && !local) {
    findings.push({
      severity: "high",
      title: "No HTTPS, traffic sent in cleartext",
      description: "Credentials and session data can be intercepted on the network. Use TLS in production.",
      url,
      category: "transport",
      source: "header-audit",
    });
  }

  // X-Powered-By names the framework (Express and PHP send it by default) and
  // serves no client. Reported on its own, since it is fixed on its own:
  // app.disable("x-powered-by"), expose_php = Off, poweredByHeader: false.
  const poweredBy = headerValue(headers, "x-powered-by");
  if (poweredBy) {
    findings.push({
      severity: "low",
      title: `X-Powered-By header discloses ${poweredBy.slice(0, 60)}`,
      description: `Responses carry \`X-Powered-By: ${poweredBy.slice(0, 120)}\`, which tells an attacker which framework to target. It serves no client; remove it.`,
      evidence: `x-powered-by: ${poweredBy.slice(0, 120)}`,
      remediation: "Express: app.disable(\"x-powered-by\") (or helmet). PHP: expose_php = Off. Next.js: poweredByHeader: false.",
      url,
      category: "headers",
      source: "header-audit",
      confidence: "confirmed",
    });
  }

  const server = headers.server || headers["x-powered-by"];
  if (server && /uvicorn|gunicorn|werkzeug/i.test(server)) {
    findings.push({
      severity: "info",
      title: "Server version disclosed",
      description: `Response exposes server header: ${server}`,
      url,
      category: "disclosure",
      source: "header-audit",
    });
  }

  return findings;
}
