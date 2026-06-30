/**
 * OWASP Web Security Testing Guide (WSTG) coverage mapping.
 *
 * Maps Penthera probes and finding categories to WSTG v4.2 test IDs.
 * @see https://owasp.org/www-project-web-security-testing-guide/
 */

/** Penthera probe → WSTG tests exercised when the probe runs. */
export const PROBE_WSTG = [
  { probe: "Reachability & fingerprint", wstg: ["WSTG-INFO-02", "WSTG-INFO-04"], profiles: ["quick", "standard", "deep"], modes: ["url"] },
  { probe: "Endpoint discovery", wstg: ["WSTG-INFO-06", "WSTG-INFO-07"], profiles: ["standard", "deep"], modes: ["url"] },
  { probe: "TLS / certificate audit", wstg: ["WSTG-CRYP-01", "WSTG-CRYP-02"], profiles: ["standard", "deep"], modes: ["url"] },
  { probe: "Security headers", wstg: ["WSTG-CONF-12", "WSTG-CONF-13", "WSTG-CONF-14"], profiles: ["quick", "standard", "deep"], modes: ["url"] },
  { probe: "OpenAPI / Swagger exposure", wstg: ["WSTG-INFO-09", "WSTG-CONF-02"], profiles: ["quick", "standard", "deep"], modes: ["url"] },
  { probe: "Sensitive file templates", wstg: ["WSTG-CONF-02", "WSTG-CONF-04"], profiles: ["standard", "deep"], modes: ["url"] },
  { probe: "CORS validation", wstg: ["WSTG-CLNT-07"], profiles: ["standard", "deep"], modes: ["url"] },
  { probe: "Cookie security", wstg: ["WSTG-SESS-02"], profiles: ["standard", "deep"], modes: ["url"] },
  { probe: "Auth endpoint hardening", wstg: ["WSTG-ATHN-03", "WSTG-ATHN-10"], profiles: ["quick", "standard", "deep"], modes: ["url"] },
  { probe: "Client-side-only auth detection", wstg: ["WSTG-ATHZ-02", "WSTG-CLNT-01"], profiles: ["standard", "deep"], modes: ["url"] },
  { probe: "JWT probes", wstg: ["WSTG-ATHN-04", "WSTG-SESS-10"], profiles: ["standard", "deep"], modes: ["url"] },
  { probe: "IDOR / BOLA", wstg: ["WSTG-ATHZ-04", "WSTG-ATHZ-05"], profiles: ["standard", "deep"], modes: ["url"] },
  { probe: "OAuth open redirect", wstg: ["WSTG-ATHN-11", "WSTG-CLNT-04"], profiles: ["standard", "deep"], modes: ["url"] },
  { probe: "Adaptive escalation probes", wstg: ["WSTG-ATHZ-02", "WSTG-ATHZ-04", "WSTG-CLNT-07"], profiles: ["standard", "deep"], modes: ["url"] },
  { probe: "Retire.js (JS CVEs)", wstg: ["WSTG-CONF-04", "WSTG-CLNT-02"], profiles: ["standard", "deep"], modes: ["url"] },
  { probe: "Parameter discovery", wstg: ["WSTG-INFO-06"], profiles: ["standard", "deep"], modes: ["url"] },
  { probe: "OSINT recon", wstg: ["WSTG-INFO-01", "WSTG-INFO-07"], profiles: ["deep"], modes: ["url"] },
  { probe: "SQL injection", wstg: ["WSTG-INPV-05"], profiles: ["deep"], modes: ["url"] },
  { probe: "SSTI", wstg: ["WSTG-INPV-18"], profiles: ["deep"], modes: ["url"] },
  { probe: "SSRF", wstg: ["WSTG-INPV-19"], profiles: ["deep"], modes: ["url"] },
  { probe: "Reflected XSS", wstg: ["WSTG-INPV-01", "WSTG-CLNT-01"], profiles: ["deep"], modes: ["url"] },
  { probe: "Command injection", wstg: ["WSTG-INPV-12"], profiles: ["deep"], modes: ["url"] },
  { probe: "Open redirect (injection suite)", wstg: ["WSTG-CLNT-04"], profiles: ["deep"], modes: ["url"] },
  { probe: "API fuzzing", wstg: ["WSTG-INPV-11", "WSTG-BUSL-05"], profiles: ["deep"], modes: ["url"] },
  { probe: "Secret scanning", wstg: ["WSTG-CONF-02", "WSTG-CONF-05"], profiles: ["quick", "standard", "deep"], modes: ["repo"] },
  { probe: "Route / trust-boundary analysis", wstg: ["WSTG-ATHZ-02", "WSTG-CONF-02"], profiles: ["quick", "standard", "deep"], modes: ["repo"] },
  { probe: "Risky code patterns", wstg: ["WSTG-INPV-01", "WSTG-INPV-12"], profiles: ["standard", "deep"], modes: ["repo"] },
];

/** Finding category/source → WSTG tags for individual findings. */
export const FINDING_WSTG = {
  tls: ["WSTG-CRYP-01", "WSTG-CRYP-02"],
  exposure: ["WSTG-CONF-02", "WSTG-CONF-04"],
  cors: ["WSTG-CLNT-07"],
  cookie: ["WSTG-SESS-02"],
  auth: ["WSTG-ATHN-03", "WSTG-ATHN-04"],
  "auth-bypass": ["WSTG-ATHZ-02", "WSTG-ATHN-04"],
  secrets: ["WSTG-CONF-02", "WSTG-CONF-05"],
  sqli: ["WSTG-INPV-05"],
  ssti: ["WSTG-INPV-18"],
  ssrf: ["WSTG-INPV-19"],
  xss: ["WSTG-INPV-01", "WSTG-CLNT-01"],
  cmdi: ["WSTG-INPV-12"],
  "open-redirect": ["WSTG-CLNT-04", "WSTG-ATHN-11"],
  fuzzing: ["WSTG-INPV-11"],
  recon: ["WSTG-INFO-01"],
  cve: ["WSTG-CONF-04"],
  "rate-limiting": ["WSTG-ATHN-10"],
  "code-pattern": ["WSTG-INPV-01", "WSTG-INPV-12"],
  config: ["WSTG-CONF-02"],
};

const SOURCE_WSTG = {
  "header-audit": ["WSTG-CONF-12", "WSTG-CONF-13"],
  "openapi-scan": ["WSTG-INFO-09", "WSTG-CONF-02"],
  "auth-probe": ["WSTG-ATHN-03", "WSTG-ATHN-10"],
  "client-auth-probe": ["WSTG-ATHZ-02", "WSTG-CLNT-01"],
  "jwt-probe": ["WSTG-ATHN-04", "WSTG-SESS-10"],
  "idor-probe": ["WSTG-ATHZ-04", "WSTG-ATHZ-05"],
  "oauth-probe": ["WSTG-ATHN-11", "WSTG-CLNT-04"],
  "adaptive-probe": ["WSTG-ATHZ-02", "WSTG-ATHZ-04"],
  "secret-scan": ["WSTG-CONF-02", "WSTG-CONF-05"],
  "trust-boundary": ["WSTG-ATHZ-02"],
  "static-analysis": ["WSTG-INPV-01"],
};

const WSTG_NAMES = {
  "WSTG-INFO-01": "Conduct Search Engine Discovery",
  "WSTG-INFO-02": "Fingerprint Web Server",
  "WSTG-INFO-04": "Enumerate Applications on Webserver",
  "WSTG-INFO-06": "Identify Application Entry Points",
  "WSTG-INFO-07": "Map Execution Paths Through Application",
  "WSTG-INFO-09": "Fingerprint Web Application",
  "WSTG-CONF-02": "Test Application Platform Configuration",
  "WSTG-CONF-04": "Review Old Backup and Unreferenced Files",
  "WSTG-CONF-05": "Enumerate Infrastructure and Application Admin Interfaces",
  "WSTG-CONF-12": "Test for Content Security Policy",
  "WSTG-CONF-13": "Test for Path Confusion",
  "WSTG-CONF-14": "Test Other HTTP Security Header Misconfigurations",
  "WSTG-CRYP-01": "Testing for Weak Transport Layer Security",
  "WSTG-CRYP-02": "Testing for Padding Oracle",
  "WSTG-ATHN-03": "Testing for Weak Lock Out Mechanism",
  "WSTG-ATHN-04": "Testing for Bypassing Authentication Schema",
  "WSTG-ATHN-10": "Testing for Weaker Authentication in Alternative Channel",
  "WSTG-ATHN-11": "Testing Multi-Factor Authentication",
  "WSTG-ATHZ-02": "Testing for Bypassing Authorization Schema",
  "WSTG-ATHZ-04": "Testing for Insecure Direct Object References",
  "WSTG-ATHZ-05": "Testing for OAuth Weaknesses",
  "WSTG-SESS-02": "Testing for Cookies Attributes",
  "WSTG-SESS-10": "Testing JSON Web Tokens",
  "WSTG-INPV-01": "Testing for Reflected Cross Site Scripting",
  "WSTG-INPV-05": "Testing for SQL Injection",
  "WSTG-INPV-11": "Testing for Code Injection",
  "WSTG-INPV-12": "Testing for Command Injection",
  "WSTG-INPV-18": "Testing for Server-Side Template Injection",
  "WSTG-INPV-19": "Testing for Server-Side Request Forgery",
  "WSTG-CLNT-01": "Testing for DOM-Based Cross Site Scripting",
  "WSTG-CLNT-02": "Testing for JavaScript Execution",
  "WSTG-CLNT-04": "Testing for Client-Side URL Redirect",
  "WSTG-CLNT-07": "Testing Cross Origin Resource Sharing",
  "WSTG-BUSL-05": "Test Number of Times a Function Can Be Used Limits",
};

function unique(arr) {
  return [...new Set(arr)];
}

/** Resolve WSTG tags for a single finding. */
export function resolveWstgTags(finding) {
  const tags = [];
  if (finding?.category && FINDING_WSTG[finding.category]) {
    tags.push(...FINDING_WSTG[finding.category]);
  }
  if (finding?.source && SOURCE_WSTG[finding.source]) {
    tags.push(...SOURCE_WSTG[finding.source]);
  }
  const blob = `${finding?.title || ""} ${finding?.description || ""}`.toLowerCase();
  if (/security header|content-security-policy|x-frame-options/i.test(blob)) {
    tags.push("WSTG-CONF-12", "WSTG-CONF-14");
  }
  if (/openapi|swagger|\/docs|redoc/i.test(blob)) tags.push("WSTG-INFO-09");
  if (/idor|bola|direct object/i.test(blob)) tags.push("WSTG-ATHZ-04");
  if (/oauth|redirect_uri/i.test(blob)) tags.push("WSTG-ATHZ-05", "WSTG-CLNT-04");
  return unique(tags);
}

/** WSTG tests exercised for a given scan profile and modes. */
export function getProbesForScan(result, profile = "standard") {
  const modes = result?.modes || (result?.mode ? [result.mode] : ["url"]);
  return PROBE_WSTG.filter((p) => {
    if (!p.profiles.includes(profile)) return false;
    return p.modes.some((m) => modes.includes(m));
  });
}

/** Build coverage summary for reports. */
export function buildWstgCoverage(result, profile = "standard") {
  const probes = getProbesForScan(result, profile);
  const exercised = unique(probes.flatMap((p) => p.wstg));
  const triggered = unique(
    (result?.findings || []).flatMap((f) => resolveWstgTags(f)),
  );

  return {
    profile,
    probesRun: probes.length,
    wstgExercised: exercised.sort(),
    wstgTriggered: triggered.sort(),
    wstgNames: WSTG_NAMES,
  };
}

/** Markdown section for reports. */
export function formatWstgMarkdown(coverage) {
  const lines = [];
  lines.push("## OWASP WSTG coverage");
  lines.push("");
  lines.push(
    `This scan exercised **${coverage.probesRun}** Penthera probes mapped to ` +
    `**${coverage.wstgExercised.length}** OWASP Web Security Testing Guide (WSTG v4.2) test areas.`,
  );
  lines.push("");
  lines.push("| WSTG ID | Test name | Status |");
  lines.push("|---------|-----------|--------|");

  for (const id of coverage.wstgExercised) {
    const name = coverage.wstgNames[id] || "See OWASP WSTG";
    const status = coverage.wstgTriggered.includes(id) ? "Finding detected" : "Probed — no finding";
    lines.push(`| \`${id}\` | ${name} | ${status} |`);
  }

  lines.push("");
  lines.push(
    "> Full mapping: [docs/owasp-wstg-coverage.md](https://github.com/danoszz/penthera/blob/main/docs/owasp-wstg-coverage.md)",
  );
  lines.push("");
  return lines.join("\n");
}

/** Enrich findings with wstg tags (returns new array). */
export function enrichFindingsWithWstg(findings) {
  return (findings || []).map((f) => ({
    ...f,
    wstg: resolveWstgTags(f),
  }));
}
