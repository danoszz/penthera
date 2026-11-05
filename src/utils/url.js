import { isIP } from "node:net";
import { isPublicIp } from "../../lib/net/ip.js";

const PRIVATE_HOSTS = new Set(["localhost", "127.0.0.1", "0.0.0.0", "[::1]"]);

/** Strip trailing slash so path joins do not produce double slashes. */
export function normalizeBaseUrl(url) {
  const parsed = new URL(url);
  const path = parsed.pathname.replace(/\/+$/, "") || "";
  return `${parsed.origin}${path}`;
}

const HOST_LIKE = /^(?:localhost|\[[0-9a-f:.]+\]|[a-z0-9-]+(?:\.[a-z0-9-]+)+)(?::\d{1,5})?(?:[/?#].*)?$/i;
const LOCAL_LIKE = /^(?:localhost|127\.|0\.0\.0\.0|\[::1\]|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/i;

/**
 * The URL a scan's first argument names, or why it names none. A bare host
 * (`example.com`, `localhost:3000`) gets https://, or http:// when it is local;
 * a word that is neither a command nor a host is reported, not parsed.
 * @returns {{ url: string } | { error: string }}
 */
export function targetFromArg(arg) {
  const raw = String(arg || "").trim();
  let candidate = raw;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) {
    if (!HOST_LIKE.test(raw)) {
      return { error: `"${raw}" is not a penthera command or a URL. Run penthera --help for the commands; to scan a site, pass its address, e.g. https://example.com.` };
    }
    candidate = `${LOCAL_LIKE.test(raw) ? "http" : "https"}://${raw}`;
  }
  let parsed;
  try {
    parsed = new URL(candidate);
  } catch {
    return { error: `"${raw}" is not a valid URL.` };
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { error: `Penthera scans http:// and https:// URLs, not ${parsed.protocol}// ("${raw}").` };
  }
  return { url: normalizeBaseUrl(candidate) };
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
    const literal = hostname.replace(/^\[|\]$/g, "");
    return isIP(literal) ? !isPublicIp(literal) : false;
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

// Second-level labels that act as public suffixes under country TLDs
// (example.co.uk, example.com.au). Not a full public-suffix list: a miss makes
// two sibling hosts look unrelated, which errs toward blocking, not allowing.
const SECOND_LEVEL_SUFFIXES = new Set(["ac", "co", "com", "edu", "gov", "ltd", "ne", "net", "or", "org", "plc"]);

/**
 * Platforms that give each customer a host under one domain: one.vercel.app
 * and two.vercel.app belong to different people. Not the Public Suffix List,
 * and not complete: a platform missing here makes two tenants look like one
 * site, so keep adding them. lib/blackbox/email-dns.js reads the same list.
 */
export const SHARED_HOST_DOMAINS = [
  "vercel.app", "now.sh", "netlify.app", "pages.dev", "workers.dev", "github.io", "gitlab.io", "fly.dev",
  "onrender.com", "herokuapp.com", "up.railway.app", "web.app", "firebaseapp.com", "azurewebsites.net",
  "amplifyapp.com", "replit.app", "repl.co", "lovable.app", "surge.sh", "cloudfront.net",
  // Storage, functions and tunnels: also one host per customer.
  "amazonaws.com", "azurestaticapps.net", "blob.core.windows.net", "appspot.com", "storage.googleapis.com",
  "run.app", "cloudfunctions.net", "r2.dev", "deno.dev", "glitch.me", "bitbucket.io",
  "codeberg.page", "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "loca.lt",
  "supabase.co", "webflow.io", "framer.app", "wixsite.com", "myshopify.com", "pythonanywhere.com",
];

/** The shared platform a host sits on (the platform's apex included), or null. */
export function sharedPlatform(hostname) {
  const host = String(hostname).toLowerCase().replace(/\.$/, "");
  return SHARED_HOST_DOMAINS.find((d) => host === d || host.endsWith(`.${d}`)) ?? null;
}

/**
 * Registrable domain of a hostname, e.g. "app.staging.example.com" →
 * "example.com", "shop.example.co.uk" → "example.co.uk". IPs and
 * single-label hosts come back unchanged. A host on a shared platform
 * (SHARED_HOST_DOMAINS) is its own site: "one.vercel.app" comes back whole,
 * never "vercel.app", so a redirect to another tenant is not "the same site".
 */
export function registrableDomain(hostname) {
  const host = String(hostname).toLowerCase().replace(/\.$/, "");
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":") || host.startsWith("[")) return host;
  if (sharedPlatform(host)) return host;
  const parts = host.split(".");
  if (parts.length <= 2) return host;
  const tld = parts[parts.length - 1];
  const second = parts[parts.length - 2];
  if (tld.length === 2 && SECOND_LEVEL_SUFFIXES.has(second)) {
    return parts.slice(-3).join(".");
  }
  return parts.slice(-2).join(".");
}

/**
 * May a redirect from the scan target `targetHost` move to `host`? Only to the
 * same host, between the apex and its `www.` (example.com and
 * www.example.com, either way), or down to a subdomain of the target host
 * (example.com to app.example.com). Never sideways to a sibling
 * (app.example.com to api.example.com) or up to a parent (app.example.com to
 * example.com): on a platform that gives each customer a host, a sibling or
 * the parent is someone else's site, and no list of platforms is complete.
 * A shared platform's own apex (vercel.app) never moves down into a tenant.
 */
export function redirectStaysOnTarget(targetHost, host) {
  const t = String(targetHost ?? "").toLowerCase().replace(/\.$/, "");
  const h = String(host ?? "").toLowerCase().replace(/\.$/, "");
  if (!t || !h) return false;
  if (t === h) return true;
  const ipLike = (x) => /^\d{1,3}(\.\d{1,3}){3}$/.test(x) || x.includes(":") || x.startsWith("[");
  if (ipLike(t) || ipLike(h)) return false;
  const apex = (x) => x.replace(/^www\./, "");
  const isPlatformApex = (x) => SHARED_HOST_DOMAINS.includes(x);
  if ((h === `www.${t}` || t === `www.${h}`) && !isPlatformApex(apex(t))) return true;
  return h.endsWith(`.${t}`) && t.includes(".") && !isPlatformApex(t);
}

/** Convert a URL into a safe filename fragment. */
export function urlToFilename(url) {
  return url
    .replace(/^https?:\/\//, "")
    .replace(/[^a-zA-Z0-9._-]+/g, "_")
    .replace(/_+/g, "_")
    .slice(0, 80);
}
