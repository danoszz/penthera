/**
 * OSINT Reconnaissance Module
 *
 * Passive information gathering from public sources, no interaction with the target.
 *
 * Sources:
 *   - crt.sh (Certificate Transparency logs), subdomain discovery
 *   - Wayback Machine CDX API, historical URL enumeration
 *   - AlienVault OTX, threat intelligence URL list
 *
 * All sources are free, require no API key, and return JSON.
 * Inspired by: subfinder, gau, waybackurls, ParamSpider
 */

import { fetchJson } from "../src/utils/http.js";
import { registrableDomain } from "../src/utils/url.js";
import { trimEndChars } from "./linear-text.js";

const RECON_TIMEOUT = 15_000;
// Certificate-transparency answers for large domains run to megabytes.
const RECON_MAX_BODY = 20 * 1024 * 1024;

/**
 * Third-party hosts this module queries. Under --offline the scan skips recon
 * entirely, and the HTTP client would refuse these hosts anyway.
 */
export const RECON_HOSTS = ["crt.sh", "web.archive.org", "otx.alienvault.com"];

// ── Subdomain Discovery via Certificate Transparency ─────────────────────

/**
 * Query crt.sh for all certificates issued to *.domain.
 * Returns unique subdomains sorted alphabetically.
 *
 * @param {string} domain - e.g. "example.com"
 * @returns {string[]} Discovered subdomains
 */
export async function discoverSubdomains(domain) {
  const data = await fetchJson(
    `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`,
    { timeout: 20_000, probe: "recon", redirect: "follow", maxBytes: RECON_MAX_BODY },
  );
  if (!data) return [];

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
  const rows = await fetchJson(
    `https://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(domain)}/*&output=json&fl=original&collapse=urlkey&limit=${limit}`,
    { timeout: 20_000, probe: "recon", redirect: "follow", maxBytes: RECON_MAX_BODY },
  );
  if (!rows) return [];

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
  const data = await fetchJson(
    `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/url_list?limit=${limit}`,
    { timeout: RECON_TIMEOUT, probe: "recon", redirect: "follow", maxBytes: RECON_MAX_BODY },
  );
  if (!data) return [];

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
      const path = trimEndChars(parsed.pathname, "/") || "/";
      if (path !== "/" && !path.match(/\.(css|js|png|jpg|gif|svg|ico|woff|ttf|eot)$/i)) {
        endpoints.add(path);
      }
      // Extract parameter names
      for (const key of parsed.searchParams.keys()) {
        parameters.add(key);
      }
    } catch {
      // Invalid URL, skip
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
    return registrableDomain(new URL(urlString).hostname);
  } catch {
    return urlString;
  }
}
