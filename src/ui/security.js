/**
 * The dashboard's request gate. `penthera ui` is a local web server, so it is
 * an attack surface: any page the user has open in the same browser can send
 * requests to 127.0.0.1. Every request passes, in order:
 *
 *   1. Host check   Host must be 127.0.0.1:<port> or localhost:<port>. Blocks
 *                   DNS rebinding (attacker.com resolving to 127.0.0.1).
 *   2. Session      The one-time URL token is swapped for an HttpOnly,
 *                   SameSite=Strict cookie; every other request needs it.
 *   3. Origin       State-changing requests need an Origin equal to the
 *                   server's own and a JSON body (no simple cross-site POSTs).
 *
 * No CORS headers are ever sent. Every response carries a strict CSP.
 */
import { randomBytes, timingSafeEqual, createHash } from "node:crypto";

export const COOKIE_NAME = "penthera_ui";

export const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self'",
  "font-src 'self'",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "require-trusted-types-for 'script'",
].join("; ");

export const SECURITY_HEADERS = Object.freeze({
  "Content-Security-Policy": CSP,
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Cross-Origin-Embedder-Policy": "require-corp",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
  "X-Permitted-Cross-Domain-Policies": "none",
  "Cache-Control": "no-store",
});

const STATE_CHANGING = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export function randomToken() {
  return randomBytes(32).toString("base64url");
}

/** Constant-time string compare (false on any length mismatch or non-string). */
export function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

export function allowedHosts(port) {
  return new Set([`127.0.0.1:${port}`, `localhost:${port}`]);
}

export function allowedOrigins(port) {
  return new Set([`http://127.0.0.1:${port}`, `http://localhost:${port}`]);
}

/** Host header check. Exact match only: no suffixes, no default ports. */
export function hostAllowed(hostHeader, port) {
  return typeof hostHeader === "string" && allowedHosts(port).has(hostHeader.toLowerCase());
}

export function readCookie(header, name) {
  if (typeof header !== "string") return null;
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    if (part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

/**
 * Origin check for state-changing requests. Browsers always send Origin on a
 * cross-site or same-origin POST from fetch, so a missing Origin is refused.
 * Sec-Fetch-Site, when present, must say same-origin.
 */
export function originAllowed(req, port) {
  if (!STATE_CHANGING.has(req.method)) return true;
  const origin = req.headers.origin;
  if (typeof origin !== "string" || !allowedOrigins(port).has(origin.toLowerCase())) return false;
  const site = req.headers["sec-fetch-site"];
  if (site != null && site !== "same-origin") return false;
  return true;
}

export function isStateChanging(method) {
  return STATE_CHANGING.has(method);
}

/**
 * Fixed-window limiter for requests that fail the session check. A signed-in
 * browser never hits it (it always has the cookie), so anything that does is
 * another page or process guessing. Unauthenticated state-changing requests
 * have no legitimate source at all and get a much smaller budget.
 */
export function createAuthLimiter({ windowMs = 60_000, maxReads = 120, maxWrites = 5, now = () => Date.now() } = {}) {
  let start = now();
  let reads = 0;
  let writes = 0;
  return {
    /** Count one unauthenticated request; returns seconds to wait, or 0 when allowed. */
    hit(method) {
      const t = now();
      if (t - start >= windowMs) { start = t; reads = 0; writes = 0; }
      const over = isStateChanging(method) ? ++writes > maxWrites : ++reads > maxReads;
      return over ? Math.max(1, Math.ceil((start + windowMs - t) / 1000)) : 0;
    },
  };
}

/**
 * Session state: one bootstrap token (single use, printed in the URL) and the
 * session cookie. The cookie value is minted when the link is redeemed, handed
 * to the browser once in Set-Cookie, and never kept: the server holds only its
 * SHA-256, so nothing readable from this process (or a heap dump) is a
 * working session.
 */
export function createSession({ bootstrap = randomToken(), mint = () => randomBytes(32).toString("base64url") } = {}) {
  let used = false;
  let digest = null;
  const hash = (v) => createHash("sha256").update(String(v)).digest("base64url");
  return {
    bootstrap,
    /** Swap the URL token for a fresh session id. Returns null when wrong or already used. */
    redeem(token) {
      if (used || !safeEqual(token, bootstrap)) return null;
      used = true;
      const sid = mint();
      digest = hash(sid);
      return sid;
    },
    get redeemed() { return used; },
    check(cookieHeader) {
      const v = readCookie(cookieHeader, COOKIE_NAME);
      return digest != null && typeof v === "string" && safeEqual(hash(v), digest);
    },
    /** The Set-Cookie header for a session id that redeem() just returned. */
    cookie(sid) {
      return `${COOKIE_NAME}=${sid}; HttpOnly; SameSite=Strict; Path=/`;
    },
  };
}
