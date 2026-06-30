/**
 * Property-Based Fuzzer (inspired by Schemathesis / fast-check / RESTler)
 *
 * Generates edge-case payloads for API endpoints automatically.
 * No schema needed — uses heuristics based on field names.
 *
 * Techniques borrowed from:
 *   - Schemathesis — property-based testing from API schemas
 *   - RESTler — stateful fuzzing with dependency inference
 *   - fast-check — shrinkable random generators
 */

// ── Payload Generators ────────────────────────────────────────────────────

/** Generate fuzz values for a given field name (heuristic-based) */
export function fuzzField(fieldName) {
  const name = fieldName.toLowerCase();
  const payloads = [];

  // Type confusion — always test these
  payloads.push(null, undefined, "", 0, false, [], {}, NaN);

  // Overflow / boundary
  payloads.push("x".repeat(10_000), "x".repeat(100_000));
  payloads.push(Number.MAX_SAFE_INTEGER, -1, -999999, 0.1, Infinity, -Infinity);

  // XSS / injection — always test
  payloads.push(
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "{{7*7}}", "${7*7}",                  // template injection
    "'; DROP TABLE users; --",             // SQL injection
    '{"$gt":""}',                          // NoSQL injection
    "../../../etc/passwd",                 // path traversal
    "file:///etc/passwd",                  // file URL
    "javascript:alert(1)",                 // protocol injection
  );

  // Prototype pollution
  payloads.push(
    { "__proto__": { "isAdmin": true } },
    { "constructor": { "prototype": { "isAdmin": true } } },
  );

  // Field-specific fuzz based on name heuristics
  if (name.includes("email")) {
    payloads.push(
      "@", "user@", "@domain.com", "user@.com",
      "a@b", "user @x.com", ".user@domain.com",
      "user@domain..com", `${"a".repeat(255)}@example.com`,
      "user+tag@gmail.com", "user@[127.0.0.1]",
    );
  }

  if (name.includes("url") || name.includes("link") || name.includes("href") || name.includes("src")) {
    payloads.push(
      "javascript:alert(1)",
      "data:text/html,<script>alert(1)</script>",
      "//evil.com", "https://evil.com",
      "https://localhost", "https://127.0.0.1",
      "https://169.254.169.254/latest/meta-data/", // SSRF
      "https://metadata.google.internal/computeMetadata/v1/",
      "ftp://evil.com/malware",
      `https://example.com/${"a".repeat(2048)}`, // long URL
    );
  }

  if (name.includes("id") || name.includes("Id") || name === "uid") {
    payloads.push(
      "../../../etc/passwd", "..%2f..%2f..%2f",
      "admin", "root", "0", "-1",
      "' OR '1'='1", "1; DROP TABLE users",
      "00000000-0000-0000-0000-000000000000", // nil UUID
      "a".repeat(500),
    );
  }

  if (name.includes("password") || name.includes("secret") || name.includes("token")) {
    payloads.push(
      "", " ", "password", "123456",
      "a".repeat(10_000), // password hash DoS
      "null", "undefined",
    );
  }

  if (name.includes("name") || name.includes("title") || name.includes("text")) {
    payloads.push(
      '<script>alert("xss")</script>',
      "Robert'); DROP TABLE students;--",
      "\u0000null byte",                    // null byte injection
      "Ṫ̈Ë̈S̈T̈",                         // combining diacriticals
      "🎉".repeat(1000),                   // emoji overflow
      "\r\n\r\n<html>",                    // CRLF injection
    );
  }

  if (name.includes("amount") || name.includes("price") || name.includes("quantity") || name.includes("count")) {
    payloads.push(
      -1, -0.01, 0, 0.001,
      99999999, Number.MAX_SAFE_INTEGER,
      "1e308", "NaN", "Infinity",
    );
  }

  if (name.includes("role") || name.includes("admin") || name.includes("permission")) {
    payloads.push("admin", "root", "superuser", "system", true, 1);
  }

  if (name.includes("redirect") || name.includes("return") || name.includes("next") || name.includes("callback")) {
    payloads.push(
      "https://evil.com",
      "//evil.com",
      "/\\evil.com",
      "javascript:alert(1)",
      "data:text/html,pwned",
    );
  }

  return payloads;
}

/**
 * Generate fuzzed request bodies for a route.
 * For each field, generate a fuzzed variant while keeping other fields valid.
 *
 * @param {object} validBody - A valid request body (baseline)
 * @param {object} opts - { maxPayloads: number }
 * @returns {Array<{ field, payload, body }>} Fuzzed variants
 */
export function generateFuzzedBodies(validBody, opts = {}) {
  const maxPayloads = opts.maxPayloads || 50;
  const variants = [];

  for (const [field, validValue] of Object.entries(validBody)) {
    const fuzzValues = fuzzField(field);

    // Take a sample if too many
    const sample = fuzzValues.length > maxPayloads
      ? fuzzValues.sort(() => Math.random() - 0.5).slice(0, maxPayloads)
      : fuzzValues;

    for (const fuzzValue of sample) {
      variants.push({
        field,
        payload: fuzzValue,
        body: { ...validBody, [field]: fuzzValue },
      });
    }
  }

  return variants;
}

/**
 * Run fuzz tests against an endpoint.
 *
 * @param {string} baseUrl
 * @param {string} path
 * @param {object} validBody - Known-good request body
 * @param {object} opts - { method, headers, maxPayloads, timeout }
 * @returns {Array<{ field, payload, status, interesting, detail }>}
 */
export async function fuzzEndpoint(baseUrl, path, validBody, opts = {}) {
  const method = opts.method || "POST";
  const headers = opts.headers || { "Content-Type": "application/json" };
  const timeout = opts.timeout || 10_000;
  const findings = [];

  const variants = generateFuzzedBodies(validBody, opts);

  for (const variant of variants) {
    let body;
    try {
      body = JSON.stringify(variant.body);
    } catch {
      continue; // can't serialize (e.g., circular)
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    try {
      const res = await fetch(`${baseUrl}${path}`, {
        method,
        headers,
        body,
        signal: controller.signal,
      });

      const text = await res.text().catch(() => "");
      const result = {
        field: variant.field,
        payload: typeof variant.payload === "object" ? JSON.stringify(variant.payload) : String(variant.payload).slice(0, 100),
        status: res.status,
        interesting: false,
        detail: null,
      };

      // Flag interesting responses
      if (res.status === 200 && typeof variant.payload === "object" && variant.payload?.__proto__) {
        result.interesting = true;
        result.detail = "Prototype pollution payload returned 200";
      }
      if (res.status === 500) {
        result.interesting = true;
        result.detail = "Server error — possible unhandled edge case";
      }
      if (text.includes("<script>")) {
        result.interesting = true;
        result.detail = "Response contains unescaped <script> tag (XSS)";
      }
      if (/at\s+\w+\s+\(|node_modules|\.js:\d+:\d+/.test(text)) {
        result.interesting = true;
        result.detail = "Response contains stack trace or internal path";
      }
      if (/FIREBASE_|STRIPE_|OPENAI_|DATABASE_|SECRET/.test(text)) {
        result.interesting = true;
        result.detail = "Response contains environment variable name";
      }

      if (result.interesting) {
        findings.push(result);
      }
    } catch {
      // timeout or network error — skip
    } finally {
      clearTimeout(timer);
    }
  }

  return findings;
}
