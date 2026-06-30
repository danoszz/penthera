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
    description: "No CSP — inline scripts and third-party resources are unrestricted.",
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

/**
 * @param {Record<string, string>} headers - lowercase header map
 * @param {string} url
 * @param {object} opts
 */
export function auditSecurityHeaders(headers = {}, url, opts = {}) {
  const findings = [];
  const local = opts.local || false;
  const isHttps = url.startsWith("https://");

  for (const check of HEADER_CHECKS) {
    const present = Object.keys(headers).some((h) => h.toLowerCase() === check.header);
    if (present) continue;

    findings.push({
      severity: check.severity,
      title: check.title,
      description: check.description,
      url,
      category: check.category,
      source: "header-audit",
    });
  }

  if (!isHttps && !local) {
    findings.push({
      severity: "high",
      title: "No HTTPS — traffic sent in cleartext",
      description: "Credentials and session data can be intercepted on the network. Use TLS in production.",
      url,
      category: "transport",
      source: "header-audit",
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
