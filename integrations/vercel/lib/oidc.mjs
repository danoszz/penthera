/**
 * GitHub Actions OIDC tokens, checked with node:crypto only (no JWT library).
 *
 * POST /report trusts a scan result only from a token GitHub signed for this server:
 *
 * - RS256 only. `alg: none`, HS256 and every other algorithm are refused before any key is
 *   looked up, so a public key can never be used as an HMAC secret.
 * - The key comes from GitHub's JWKS at a fixed URL, by `kid`. The key set is cached for
 *   10 minutes in this function instance. Any refetch beyond that (an unknown `kid`, or a retry
 *   after a failed fetch) happens at most once a minute; in between, a stale cache answers
 *   jwks_unavailable without fetching. One fetch at a time (callers share it), 3 seconds, no
 *   redirects, at most 64 KiB read. A clock that moves backwards counts as a stale cache.
 * - `iss` must be GitHub's issuer and `aud` this server's origin, exactly.
 * - `exp`, `nbf` and `iat` must all be there, as numbers. `exp` is in the future, `nbf` and `iat` are not, with
 *   30 seconds of leeway, and a token may live at most one hour, so a token with a far-future
 *   `exp` is refused too.
 *
 * Which repository and workflow the token is for is checked by the caller (lib/app.mjs).
 */
import { createPublicKey, verify } from "node:crypto";
import { readCapped } from "./http.mjs";

export const GITHUB_ISSUER = "https://token.actions.githubusercontent.com";
export const GITHUB_JWKS_URL = `${GITHUB_ISSUER}/.well-known/jwks`;

const JWKS_TTL_MS = 10 * 60_000;
const JWKS_RETRY_MS = 60_000;
const JWKS_TIMEOUT_MS = 3_000;
const JWKS_MAX_BYTES = 64 * 1024;
const MAX_TOKEN_CHARS = 8 * 1024;
const LEEWAY_S = 30;
const MAX_LIFETIME_S = 60 * 60;
const JWT_SHAPE = /^[A-Za-z0-9_-]{1,2048}\.[A-Za-z0-9_-]{1,8192}\.[A-Za-z0-9_-]{1,2048}$/;

/** A refused token. `code` is a short, fixed string, safe to log. */
export class OidcError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

/** GitHub's signing keys, cached briefly. `get(kid)` -> KeyObject | null. */
export function jwksCache({ fetch: fetchImpl = globalThis.fetch, now = Date.now, url = GITHUB_JWKS_URL } = {}) {
  let keys = null;
  let fetchedAt = 0;
  let triedAt = -Infinity;
  let pending = null;

  async function load() {
    triedAt = now();
    let res;
    try {
      res = await fetchImpl(url, { headers: { accept: "application/json" }, redirect: "error", signal: AbortSignal.timeout(JWKS_TIMEOUT_MS) });
    } catch {
      throw new OidcError("jwks_unavailable");
    }
    if (!res.ok) throw new OidcError("jwks_unavailable");
    const raw = await readCapped(res.body, JWKS_MAX_BYTES).catch(() => null);
    const text = raw ? raw.toString("utf8") : "";
    if (!text) throw new OidcError("jwks_unavailable");
    let json;
    try {
      json = JSON.parse(text);
    } catch {
      throw new OidcError("jwks_unavailable");
    }
    const map = new Map();
    for (const jwk of Array.isArray(json?.keys) ? json.keys.slice(0, 32) : []) {
      if (jwk?.kty !== "RSA" || typeof jwk.kid !== "string" || typeof jwk.n !== "string" || typeof jwk.e !== "string") continue;
      if (jwk.use !== undefined && jwk.use !== "sig") continue;
      if (jwk.alg !== undefined && jwk.alg !== "RS256") continue;
      try {
        const key = createPublicKey({ key: { kty: "RSA", n: jwk.n, e: jwk.e }, format: "jwk" });
        if ((key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) continue;
        map.set(jwk.kid, key);
      } catch {}
    }
    keys = map;
    fetchedAt = now();
  }

  const refresh = () => (pending ??= load().finally(() => (pending = null)));

  return {
    async get(kid) {
      // A fetch already under way is shared, whatever it finds.
      if (pending) await pending.catch(() => {});
      const t = now();
      const fresh = keys !== null && t >= fetchedAt && t - fetchedAt < JWKS_TTL_MS;
      const mayFetch = t < triedAt || t - triedAt >= JWKS_RETRY_MS;
      if (!fresh) {
        // Stale and fetched (and failed) less than a minute ago: refuse without another fetch.
        if (!mayFetch) throw new OidcError("jwks_unavailable");
        await refresh();
      } else if (!keys.has(kid) && mayFetch) {
        await refresh();
      }
      return keys?.get(kid) ?? null;
    },
  };
}

function part(b64) {
  try {
    const value = JSON.parse(Buffer.from(b64, "base64url").toString("utf8"));
    return value && typeof value === "object" && !Array.isArray(value) ? value : null;
  } catch {
    return null;
  }
}

const isTime = (v) => typeof v === "number" && Number.isFinite(v);

/**
 * The verified claims of a GitHub Actions OIDC token for `audience`, or an OidcError.
 * @param {string} token
 * @param {{ audience: string, jwks: { get(kid: string): Promise<any> }, now?: () => number }} opts
 */
export async function verifyGithubToken(token, { audience, jwks, now = Date.now }) {
  if (typeof token !== "string" || token.length > MAX_TOKEN_CHARS || !JWT_SHAPE.test(token)) throw new OidcError("malformed");
  const [h, p, s] = token.split(".");
  const header = part(h);
  if (!header) throw new OidcError("malformed");
  if (header.alg !== "RS256") throw new OidcError("bad_alg");
  if (header.crit !== undefined) throw new OidcError("bad_header");
  if (header.typ !== undefined && header.typ !== "JWT") throw new OidcError("bad_header");
  if (typeof header.kid !== "string" || !/^[\x21-\x7e]{1,256}$/.test(header.kid)) throw new OidcError("bad_header");

  const key = await jwks.get(header.kid);
  if (!key) throw new OidcError("unknown_key");
  let ok = false;
  try {
    ok = verify("RSA-SHA256", Buffer.from(`${h}.${p}`, "ascii"), key, Buffer.from(s, "base64url"));
  } catch {
    ok = false;
  }
  if (!ok) throw new OidcError("bad_signature");

  const claims = part(p);
  if (!claims) throw new OidcError("malformed");
  if (claims.iss !== GITHUB_ISSUER) throw new OidcError("bad_issuer");
  if (typeof audience !== "string" || !audience || claims.aud !== audience) throw new OidcError("bad_audience");
  const t = Math.floor(now() / 1000);
  if (!isTime(claims.exp) || !isTime(claims.iat) || !isTime(claims.nbf)) throw new OidcError("bad_time");
  if (t >= claims.exp + LEEWAY_S) throw new OidcError("expired");
  if (claims.nbf > t + LEEWAY_S || claims.iat > t + LEEWAY_S) throw new OidcError("not_yet_valid");
  if (claims.exp - claims.iat > MAX_LIFETIME_S || claims.exp - t > MAX_LIFETIME_S) throw new OidcError("too_long");
  return claims;
}
