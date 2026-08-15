const PRIVATE_HOSTS = new Set(["localhost", "127.0.0.1", "0.0.0.0", "[::1]"]);

/** Strip trailing slash so path joins do not produce double slashes. */
export function normalizeBaseUrl(url) {
  const parsed = new URL(url);
  const path = parsed.pathname.replace(/\/+$/, "") || "";
  return `${parsed.origin}${path}`;
}

/** Join base URL and path safely: `http://host` + `/api` → `http://host/api`. */
export function joinUrl(baseUrl, path = "/") {
  const base = normalizeBaseUrl(baseUrl);
  const suffix = path.startsWith("/") ? path : `/${path}`;
  return `${base}${suffix}`;
}

export function isPrivateHost(url) {
  try {
    const { hostname } = new URL(url);
    if (PRIVATE_HOSTS.has(hostname)) return true;
    if (/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(hostname)) return true;
    return false;
  } catch {
    return false;
  }
}

/**
 * True only when a redirect actually SENDS the browser to `attackerHost`, i.e.
 * the Location header resolves to that host's origin. A Location that merely
 * contains the attacker string in its path or query (e.g. an apex→www
 * canonicalization redirect that preserves the query string) is NOT an open
 * redirect, and must not be flagged as one.
 */
export function redirectsToHost(locationHeader, requestUrl, attackerHost) {
  if (!locationHeader) return false;
  try {
    const dest = new URL(locationHeader, requestUrl); // resolve relative/protocol-relative
    const host = dest.hostname.toLowerCase();
    const attacker = String(attackerHost).toLowerCase();
    return host === attacker || host.endsWith(`.${attacker}`);
  } catch {
    return false;
  }
}

/** Convert a URL into a safe filename fragment. */
export function urlToFilename(url) {
  return url
    .replace(/^https?:\/\//, "")
    .replace(/[^a-zA-Z0-9._-]+/g, "_")
    .replace(/_+/g, "_")
    .slice(0, 80);
}
