/**
 * The only crypto the integration needs, all from node:crypto.
 *
 * - Tokens at rest: AES-256-GCM, a fresh 12-byte IV per record, and the
 *   configuration id as associated data, so a ciphertext copied onto another
 *   record fails to open.
 * - Keys: PENTHERA_TOKEN_KEYS="v2:<base64 32 bytes>,v1:<base64>". The first key
 *   encrypts; any listed key decrypts, so a key can rotate without a migration.
 * - Short-lived cookies are signed with HMAC-SHA256 under a key derived from the
 *   current token key (HKDF), so there is one secret to manage, not two.
 * - Webhooks: HMAC-SHA1 of the raw body with the client secret, compared in
 *   constant time (Vercel's documented scheme).
 */
import { createCipheriv, createDecipheriv, createHmac, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto";

export class ConfigError extends Error {}

/** Parses PENTHERA_TOKEN_KEYS. Throws ConfigError, never echoing a key. */
export function parseKeys(value) {
  const keys = String(value ?? "").split(",").map((s) => s.trim()).filter(Boolean).map((entry) => {
    const m = /^([a-z0-9]{1,8}):([A-Za-z0-9+/]{43}=)$/.exec(entry);
    if (!m) throw new ConfigError("PENTHERA_TOKEN_KEYS: each entry must be <version>:<base64 of 32 bytes>");
    return { version: m[1], key: Buffer.from(m[2], "base64") };
  });
  if (!keys.length) throw new ConfigError("PENTHERA_TOKEN_KEYS is not set");
  if (new Set(keys.map((k) => k.version)).size !== keys.length) throw new ConfigError("PENTHERA_TOKEN_KEYS: versions must be unique");
  return keys;
}

/** Encrypts a token for one configuration. */
export function sealToken(token, configurationId, keys) {
  const { version, key } = keys[0];
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(configurationId, "utf8"));
  const ciphertext = Buffer.concat([cipher.update(token, "utf8"), cipher.final()]);
  return {
    ciphertext: ciphertext.toString("base64"),
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    keyVersion: version,
  };
}

/** Decrypts a sealed token. Throws on a wrong key, a tampered field or another record's ciphertext. */
export function openToken(sealed, configurationId, keys) {
  const entry = keys.find((k) => k.version === sealed.keyVersion);
  if (!entry) throw new ConfigError("no key for this record's keyVersion");
  // A full 16-byte tag only: Node 22 still accepts shorter GCM tags unless told the length.
  const tag = Buffer.from(sealed.tag, "base64");
  if (tag.length !== 16) throw new Error("bad tag length");
  const decipher = createDecipheriv("aes-256-gcm", entry.key, Buffer.from(sealed.iv, "base64"), { authTagLength: 16 });
  decipher.setAAD(Buffer.from(configurationId, "utf8"));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(Buffer.from(sealed.ciphertext, "base64")), decipher.final()]).toString("utf8");
}

/** Constant-time string compare; unequal lengths are a mismatch, not an exception. */
export function safeEqual(a, b) {
  const x = Buffer.from(String(a ?? ""), "utf8");
  const y = Buffer.from(String(b ?? ""), "utf8");
  return x.length === y.length && x.length > 0 && timingSafeEqual(x, y);
}

/** True only when `signature` is the hex HMAC-SHA1 of `rawBody` under `secret`. */
export function verifyWebhookSignature(rawBody, signature, secret) {
  if (typeof signature !== "string" || !/^[0-9a-f]{40}$/i.test(signature) || !secret) return false;
  const expected = createHmac("sha1", secret).update(rawBody).digest("hex");
  return safeEqual(expected, signature.toLowerCase());
}

/** The cookie-signing key: HKDF from the current token key, so it changes when that key rotates. */
export function cookieKey(keys) {
  return Buffer.from(hkdfSync("sha256", keys[0].key, Buffer.alloc(0), "penthera-vercel cookie v1", 32));
}

/** `base64url(json).base64url(hmac)`. */
export function signValue(data, key) {
  const body = Buffer.from(JSON.stringify(data), "utf8").toString("base64url");
  return `${body}.${createHmac("sha256", key).update(body).digest("base64url")}`;
}

/** The data inside a signed value, or null if the signature or the expiry (`e`, ms) fails. */
export function unsignValue(value, key, now = Date.now()) {
  const [body, mac, extra] = String(value ?? "").split(".");
  if (!body || !mac || extra !== undefined) return null;
  if (!safeEqual(createHmac("sha256", key).update(body).digest("base64url"), mac)) return null;
  try {
    const data = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    return typeof data?.e === "number" && data.e > now ? data : null;
  } catch {
    return null;
  }
}

export function randomToken(bytes = 32) {
  return randomBytes(bytes).toString("base64url");
}

/** HMAC-SHA256 of `text`, base64url: the form token bound to one session cookie. */
export function mac(key, text) {
  return createHmac("sha256", key).update(String(text)).digest("base64url");
}
