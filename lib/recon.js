/**
 * OSINT Reconnaissance Module
 *
 * Passive information gathering from public sources — no interaction with the target.
 *
 * Sources:
 *   - crt.sh (Certificate Transparency logs) — subdomain discovery
 *   - Wayback Machine CDX API — historical URL enumeration
 *   - AlienVault OTX — threat intelligence URL list
 *
 * All sources are free, require no API key, and return JSON.
 * Inspired by: subfinder, gau, waybackurls, ParamSpider
 */

const RECON_TIMEOUT = 15_000;

async function safeFetch(url, opts = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), opts.timeout || RECON_TIMEOUT);
  try {
    return await fetch(url, { signal: controller.signal, ...opts });
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

// ── Subdomain Discovery via Certificate Transparency ─────────────────────

/**
 * Query crt.sh for all certificates issued to *.domain.
 * Returns unique subdomains sorted alphabetically.
 *
 * @param {string} domain - e.g. "example.com"
 * @returns {string[]} Discovered subdomains
 */
export async function discoverSubdomains(domain) {
  const res = await safeFetch(
    `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`,
    { timeout: 20_000 },
  );
  if (!res || !res.ok) return [];

  let data;
  try {
    data = await res.json();
  } catch {
    return [];
  }

  const subdomains = new Set();
  for (const entry of data) {
    if (!entry.name_value) continue;
    for (const name of entry.name_value.split("\n")) {
      const clean = name.trim().toLowerCase().replace(/^\*\./, "");
      if (clean.endsWith(domain) && clean !== domain) {
        subdomains.add(clean);
      }
    }
  }

  return [...subdomains].sort();
}

// ── Historical URL Enumeration ───────────────────────────────────────────

/**
 * Fetch known URLs from the Wayback Machine CDX API.
 * Collapses by URL key to avoid duplicates.
 *
 * @param {string} domain - e.g. "example.com"
 * @param {object} opts - { limit }
 * @returns {string[]} Historical URLs
 */
export async function fetchWaybackUrls(domain, opts = {}) {
  const limit = opts.limit || 1000;
  const res = await safeFetch(
    `https://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(domain)}/*&output=json&fl=original&collapse=urlkey&limit=${limit}`,
    { timeout: 20_000 },
  );
  if (!res || !res.ok) return [];

  let rows;
  try {
    rows = await res.json();
  } catch {
    return [];
  }

  // First row is the header ["original"]
  return rows.slice(1).map((r) => r[0]).filter(Boolean);
}

/**
 * Fetch known URLs from AlienVault OTX.
 *
 * @param {string} domain
 * @param {object} opts - { limit }
 * @returns {string[]}
 */
export async function fetchOtxUrls(domain, opts = {}) {
  const limit = opts.limit || 200;
  const res = await safeFetch(
    `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/url_list?limit=${limit}`,
  );
  if (!res || !res.ok) return [];

  let data;
  try {
    data = await res.json();
  } catch {
    return [];
  }

  return (data.url_list || []).map((e) => e.url).filter(Boolean);
}

// ── Aggregate Recon ──────────────────────────────────────────────────────

/**
 * Run full OSINT recon for a domain.
 * Returns subdomains, historical URLs, and extracted parameters.
 *
 * @param {string} domain - Target domain (e.g. "example.com")
 * @param {object} opts - { onPhase }
 * @returns {{ subdomains, urls, parameters, endpoints }}
 */
export async function runRecon(domain, opts = {}) {
  const progress = opts.onPhase || (() => {});

  progress("Querying Certificate Transparency logs (crt.sh)...");
  const subdomains = await discoverSubdomains(domain);

  progress("Fetching historical URLs (Wayback Machine)...");
  const [waybackUrls, otxUrls] = await Promise.all([
    fetchWaybackUrls(domain),
    fetchOtxUrls(domain),
  ]);

  // Merge and deduplicate all discovered URLs
  const allUrls = [...new Set([...waybackUrls, ...otxUrls])];

  // Extract unique URL paths (for active scanning)
  const endpoints = new Set();
  const parameters = new Set();
  for (const url of allUrls) {
    try {
      const parsed = new URL(url);
      // Normalize path
      const path = parsed.pathname.replace(/\/+$/, "") || "/";
      if (path !== "/" && !path.match(/\.(css|js|png|jpg|gif|svg|ico|woff|ttf|eot)$/i)) {
        endpoints.add(path);
      }
      // Extract parameter names
      for (const key of parsed.searchParams.keys()) {
        parameters.add(key);
      }
    } catch {
      // Invalid URL — skip
    }
  }

  return {
    subdomains,
    urls: allUrls,
    endpoints: [...endpoints].sort(),
    parameters: [...parameters].sort(),
    sources: {
      crtsh: subdomains.length,
      wayback: waybackUrls.length,
      otx: otxUrls.length,
    },
  };
}

/**
 * Extract the root domain from a URL.
 * e.g. "https://app.staging.example.com/path" → "example.com"
 */
export function extractDomain(urlString) {
  try {
    const hostname = new URL(urlString).hostname;
    const parts = hostname.split(".");
    // Handle two-part TLDs like .co.uk, .com.au
    if (parts.length >= 3 && parts[parts.length - 2].length <= 3) {
      return parts.slice(-3).join(".");
    }
    return parts.slice(-2).join(".");
  } catch {
    return urlString;
  }
}
