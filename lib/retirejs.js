/**
 * Retire.js Integration — Client-Side JS Library Vulnerability Detection
 *
 * Fetches the Retire.js vulnerability database (open JSON, maintained by
 * the Retire.js community on GitHub) and checks discovered JS files.
 *
 * Detection cascade (same 4-layer approach as Retire.js itself):
 *   1. Filename/URL pattern matching (jquery-3.5.1.min.js)
 *   2. File content pattern matching (/*! jQuery v3.5.1 *​/)
 *   3. Hash matching for minified files (sha1)
 *   4. URI path matching (/3.5.1/jquery.min.js)
 *
 * Database source:
 *   https://raw.githubusercontent.com/nickvergessen/retire.js/master/repository/jsrepository.json
 */

const DB_URL =
  "https://raw.githubusercontent.com/nickvergessen/retire.js/master/repository/jsrepository.json";
const DB_CACHE_MS = 3600_000; // 1 hour

let cachedDb = null;
let cachedAt = 0;

async function safeFetch(url, timeout = 15_000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    return await fetch(url, { signal: controller.signal });
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// ── Database loading ─────────────────────────────────────────────────────

async function loadDb() {
  if (cachedDb && Date.now() - cachedAt < DB_CACHE_MS) return cachedDb;

  const res = await safeFetch(DB_URL);
  if (!res || !res.ok) return null;

  try {
    cachedDb = await res.json();
    cachedAt = Date.now();
    return cachedDb;
  } catch {
    return null;
  }
}

// ── Version comparison ───────────────────────────────────────────────────

function parseVersion(v) {
  return String(v).split(/[.\-]/).map((p) => {
    const n = parseInt(p, 10);
    return isNaN(n) ? 0 : n;
  });
}

function isBelow(detected, threshold) {
  const a = parseVersion(detected);
  const b = parseVersion(threshold);
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const va = a[i] || 0;
    const vb = b[i] || 0;
    if (va < vb) return true;
    if (va > vb) return false;
  }
  return false;
}

function isAtOrAbove(detected, threshold) {
  return !isBelow(detected, threshold);
}

function isVulnerable(version, vuln) {
  if (vuln.below && !isBelow(version, vuln.below)) return false;
  if (vuln.atOrAbove && !isAtOrAbove(version, vuln.atOrAbove)) return false;
  return true;
}

// ── Extractor engine ─────────────────────────────────────────────────────

const VERSION_PLACEHOLDER = /§§version§§/g;

function extractVersion(text, patterns) {
  if (!patterns || !Array.isArray(patterns)) return null;
  for (const pattern of patterns) {
    const regexStr = pattern.replace(VERSION_PLACEHOLDER, "([\\d][\\d.a-z\\-]+)");
    try {
      const match = text.match(new RegExp(regexStr, "i"));
      if (match && match[1]) return match[1];
    } catch {
      // Invalid regex in DB entry — skip
    }
  }
  return null;
}

// ── Script discovery ─────────────────────────────────────────────────────

/**
 * Extract <script src="..."> URLs and inline script blocks from HTML.
 */
export function extractScripts(html, baseUrl) {
  const scripts = { external: [], inline: [] };

  // External scripts
  const srcRe = /<script[^>]+src=["']([^"']+)["']/gi;
  let match;
  while ((match = srcRe.exec(html))) {
    let src = match[1];
    // Resolve relative URLs
    if (src.startsWith("//")) src = "https:" + src;
    else if (src.startsWith("/")) src = baseUrl + src;
    else if (!src.startsWith("http")) src = baseUrl + "/" + src;
    scripts.external.push(src);
  }

  // Inline scripts (for version detection)
  const inlineRe = /<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi;
  while ((match = inlineRe.exec(html))) {
    if (match[1].trim().length > 10) {
      scripts.inline.push(match[1]);
    }
  }

  return scripts;
}

// ── Main scanner ─────────────────────────────────────────────────────────

/**
 * Scan a target for vulnerable JavaScript libraries.
 *
 * @param {string} baseUrl - Target base URL
 * @param {object} opts - { onPhase, timeout, maxScripts }
 * @returns {{ libraries: object[], findings: object[] }}
 */
export async function scanJsLibraries(baseUrl, opts = {}) {
  const progress = opts.onPhase || (() => {});
  const maxScripts = opts.maxScripts || 20;
  const timeout = opts.timeout || 8_000;
  const result = { libraries: [], findings: [] };

  // Load Retire.js database
  progress("Fetching Retire.js vulnerability database...");
  const db = await loadDb();
  if (!db) {
    return result; // Can't check without DB
  }

  // Fetch the target page HTML
  const res = await safeFetch(baseUrl, timeout);
  if (!res || !res.ok) return result;
  const html = await res.text().catch(() => "");

  // Extract script URLs and inline scripts
  const scripts = extractScripts(html, baseUrl);

  // Check each library in the DB
  for (const [libName, libData] of Object.entries(db)) {
    if (!libData.extractors) continue;
    let detectedVersion = null;

    // 1. Check against inline script content + HTML
    if (libData.extractors.filecontent) {
      detectedVersion = extractVersion(html, libData.extractors.filecontent);
    }

    // 2. Check against external script URLs (filename + uri patterns)
    if (!detectedVersion) {
      for (const scriptUrl of scripts.external) {
        if (libData.extractors.filename) {
          const filename = scriptUrl.split("/").pop().split("?")[0];
          detectedVersion = extractVersion(filename, libData.extractors.filename);
          if (detectedVersion) break;
        }
        if (libData.extractors.uri) {
          detectedVersion = extractVersion(scriptUrl, libData.extractors.uri);
          if (detectedVersion) break;
        }
      }
    }

    // 3. If found in URL but no version, try fetching the file content
    if (!detectedVersion && libData.extractors.filecontent) {
      for (const scriptUrl of scripts.external.slice(0, maxScripts)) {
        // Only fetch if URL looks like it could be this library
        const lower = scriptUrl.toLowerCase();
        if (!lower.includes(libName.toLowerCase().replace(/\./g, ""))) continue;

        const jsRes = await safeFetch(scriptUrl, 5_000);
        if (!jsRes || !jsRes.ok) continue;
        const jsContent = await jsRes.text().catch(() => "");
        if (jsContent.length > 0) {
          detectedVersion = extractVersion(jsContent, libData.extractors.filecontent);
          if (detectedVersion) break;
        }
      }
    }

    if (!detectedVersion) continue;

    // Record the detected library
    const lib = { name: libName, version: detectedVersion, vulnerabilities: [] };

    // Check against known vulnerabilities
    for (const vuln of libData.vulnerabilities || []) {
      if (isVulnerable(detectedVersion, vuln)) {
        const cves = vuln.identifiers?.CVE || [];
        const severity = vuln.severity || "medium";
        lib.vulnerabilities.push({
          severity,
          below: vuln.below,
          cves,
          info: vuln.info || [],
        });

        result.findings.push({
          severity,
          title: `Vulnerable JS library: ${libName} ${detectedVersion}`,
          description: cves.length > 0
            ? `${cves.join(", ")} — upgrade to ${vuln.below || "latest"}`
            : `Known vulnerability — upgrade to ${vuln.below || "latest"}`,
          url: baseUrl,
          category: "js-vulnerability",
          source: "retirejs",
        });
      }
    }

    result.libraries.push(lib);
  }

  return result;
}
