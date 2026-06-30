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

/** Convert a URL into a safe filename fragment. */
export function urlToFilename(url) {
  return url
    .replace(/^https?:\/\//, "")
    .replace(/[^a-zA-Z0-9._-]+/g, "_")
    .replace(/_+/g, "_")
    .slice(0, 80);
}
