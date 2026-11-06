/**
 * Verify OpenSSH signatures (`ssh-keygen -Y sign`) in pure Node, so checking
 * a rule pack needs no ssh-keygen binary and spawns nothing.
 *
 * Format: PROTOCOL.sshsig in the OpenSSH source tree. A signature is an
 * armored blob:
 *   "SSHSIG" | uint32 version | string publickey | string namespace |
 *   string reserved | string hash_algorithm | string signature
 * and what the key signs is:
 *   "SSHSIG" | string namespace | string reserved | string hash_algorithm |
 *   string H(message)
 *
 * Supported keys: ssh-ed25519 and RSA (rsa-sha2-256/512 signatures). Others
 * (ECDSA, security keys, certificates) are refused with a clear reason rather
 * than half-supported.
 *
 * allowed_signers: the format ssh-keygen reads (ALLOWED SIGNERS in
 * ssh-keygen(1)): `principals [options] keytype base64-key [comment]`, with the
 * options namespaces="...", valid-after=, valid-before= honoured and
 * cert-authority refused.
 */
import { createHash, createPublicKey, verify } from "node:crypto";

const MAGIC = Buffer.from("SSHSIG");

class Reader {
  constructor(buf) { this.buf = buf; this.off = 0; }
  u32() {
    if (this.off + 4 > this.buf.length) throw new Error("truncated");
    const v = this.buf.readUInt32BE(this.off);
    this.off += 4;
    return v;
  }
  bytes() {
    const n = this.u32();
    if (n > this.buf.length - this.off) throw new Error("truncated");
    const v = this.buf.subarray(this.off, this.off + n);
    this.off += n;
    return v;
  }
  str() { return this.bytes().toString("latin1"); }
  done() { return this.off === this.buf.length; }
}

const sshString = (b) => {
  const buf = Buffer.isBuffer(b) ? b : Buffer.from(b);
  const len = Buffer.alloc(4);
  len.writeUInt32BE(buf.length);
  return Buffer.concat([len, buf]);
};
const b64url = (b) => Buffer.from(b).toString("base64url");
const stripMpint = (b) => (b[0] === 0 ? b.subarray(1) : b);

/** A KeyObject from an SSH public key blob, or throw. */
export function keyFromBlob(blob) {
  const r = new Reader(blob);
  const type = r.str();
  if (type === "ssh-ed25519") {
    const pk = r.bytes();
    if (pk.length !== 32 || !r.done()) throw new Error("malformed ed25519 key");
    return { type, key: createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: b64url(pk) }, format: "jwk" }) };
  }
  if (type === "ssh-rsa") {
    const e = stripMpint(r.bytes());
    const n = stripMpint(r.bytes());
    if (!r.done()) throw new Error("malformed RSA key");
    if (n.length * 8 < 2048) throw new Error("RSA keys under 2048 bits are not accepted");
    return { type, key: createPublicKey({ key: { kty: "RSA", n: b64url(n), e: b64url(e) }, format: "jwk" }) };
  }
  throw new Error(`unsupported key type ${type} (use ssh-ed25519 or ssh-rsa)`);
}

/** Decode an armored SSH signature into its fields, or throw. */
export function parseSignature(armored) {
  const text = String(armored);
  const m = /-----BEGIN SSH SIGNATURE-----([\s\S]*?)-----END SSH SIGNATURE-----/.exec(text);
  if (!m) throw new Error("not an SSH signature (missing armor)");
  const raw = Buffer.from(m[1].replace(/\s+/g, ""), "base64");
  if (!raw.subarray(0, 6).equals(MAGIC)) throw new Error("bad signature magic");
  const r = new Reader(raw.subarray(6));
  const version = r.u32();
  if (version !== 1) throw new Error(`unsupported signature version ${version}`);
  const publicKey = Buffer.from(r.bytes());
  const namespace = r.str();
  const reserved = Buffer.from(r.bytes());
  const hashAlg = r.str();
  const sig = new Reader(r.bytes());
  if (!r.done()) throw new Error("trailing bytes after signature");
  const sigType = sig.str();
  const sigBytes = Buffer.from(sig.bytes());
  return { publicKey, namespace, reserved, hashAlg, sigType, sigBytes };
}

/**
 * Check that `armored` is a valid signature over `message` in `namespace`.
 * Does not decide whether the key is trusted; see verifyWithSigners.
 * @returns {{ ok: true, publicKey: Buffer } | { ok: false, reason: string }}
 */
export function verifySignature(message, armored, namespace) {
  let s;
  try { s = parseSignature(armored); } catch (e) { return { ok: false, reason: e.message }; }
  if (s.namespace !== namespace) return { ok: false, reason: `signature namespace is "${s.namespace}", expected "${namespace}"` };
  if (s.hashAlg !== "sha512" && s.hashAlg !== "sha256") return { ok: false, reason: `unsupported hash ${s.hashAlg}` };
  let k;
  try { k = keyFromBlob(s.publicKey); } catch (e) { return { ok: false, reason: e.message }; }
  const digest = createHash(s.hashAlg).update(message).digest();
  const signed = Buffer.concat([MAGIC, sshString(namespace), sshString(s.reserved), sshString(s.hashAlg), sshString(digest)]);
  let good = false;
  try {
    if (k.type === "ssh-ed25519") {
      good = s.sigType === "ssh-ed25519" && verify(null, signed, k.key, s.sigBytes);
    } else if (s.sigType === "rsa-sha2-512" || s.sigType === "rsa-sha2-256") {
      good = verify(s.sigType === "rsa-sha2-512" ? "sha512" : "sha256", signed, k.key, s.sigBytes);
    } else {
      return { ok: false, reason: `unsupported signature type ${s.sigType}` };
    }
  } catch (e) {
    return { ok: false, reason: `signature check failed: ${e.message}` };
  }
  return good ? { ok: true, publicKey: s.publicKey } : { ok: false, reason: "signature does not match (file changed after signing, or wrong key)" };
}

// ── allowed_signers ───────────────────────────────────────────────────────

function tokenize(line) {
  const out = [];
  let cur = "";
  let quoted = false;
  for (const ch of line) {
    if (ch === '"') { quoted = !quoted; cur += ch; continue; }
    if (!quoted && (ch === " " || ch === "\t")) { if (cur) out.push(cur); cur = ""; continue; }
    cur += ch;
  }
  if (cur) out.push(cur);
  return out;
}

/** "20260101", "202601011200", "20260101120000Z" -> epoch ms, or NaN. */
function parseTime(s) {
  const m = /^(\d{4})(\d{2})(\d{2})(?:(\d{2})(\d{2})(\d{2})?)?(Z?)$/.exec(s);
  if (!m) return NaN;
  const [, y, mo, d, h = "00", mi = "00", se = "00", z] = m;
  const iso = `${y}-${mo}-${d}T${h}:${mi}:${se}${z ? "Z" : ""}`;
  return Date.parse(iso);
}

const KEY_TYPES = new Set(["ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com"]);

/**
 * Parse an allowed_signers file.
 * @returns {{ principals: string[], namespaces: string[]|null, validAfter?: number, validBefore?: number, keyType: string, key: Buffer, certAuthority: boolean }[]}
 */
export function parseAllowedSigners(text) {
  const out = [];
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const t = tokenize(line);
    if (t.length < 3) continue;
    const entry = { principals: t[0].split(","), namespaces: null, certAuthority: false };
    let k = 1;
    if (!KEY_TYPES.has(t[k])) {
      for (const opt of splitOutsideQuotes(t[k])) {
        const [name, ...rest] = opt.split("=");
        const value = rest.join("=").replace(/^"|"$/g, "");
        const lname = name.toLowerCase();
        if (lname === "cert-authority") entry.certAuthority = true;
        else if (lname === "namespaces") entry.namespaces = value.split(",").map((s) => s.trim()).filter(Boolean);
        else if (lname === "valid-after") entry.validAfter = parseTime(value);
        else if (lname === "valid-before") entry.validBefore = parseTime(value);
      }
      k++;
    }
    if (!KEY_TYPES.has(t[k]) || !t[k + 1]) continue;
    entry.keyType = t[k];
    entry.key = Buffer.from(t[k + 1], "base64");
    out.push(entry);
  }
  return out;
}

/**
 * Verify a signature and check its key against allowed_signers entries.
 * @param {Buffer|string} message
 * @param {string} armored
 * @param {string} namespace
 * @param {ReturnType<typeof parseAllowedSigners>} signers
 * @param {{ now?: number }} [opts]
 * @returns {{ ok: true, principal: string, keyType: string } | { ok: false, reason: string }}
 */
export function verifyWithSigners(message, armored, namespace, signers, opts = {}) {
  const v = verifySignature(message, armored, namespace);
  if (!v.ok) return v;
  const now = opts.now ?? Date.now();
  const matches = signers.filter((e) => e.key.equals(v.publicKey));
  if (matches.length === 0) return { ok: false, reason: "valid signature, but the key is not in allowed_signers" };
  for (const e of matches) {
    if (e.certAuthority) continue;
    if (e.namespaces && !e.namespaces.includes(namespace)) continue;
    if (e.validAfter !== undefined && !(now >= e.validAfter)) continue;
    if (e.validBefore !== undefined && !(now < e.validBefore)) continue;
    return { ok: true, principal: e.principals[0], keyType: e.keyType };
  }
  return { ok: false, reason: `key is in allowed_signers but not valid for namespace "${namespace}" at this time` };
}

/** `a,b="x,y",c` split at the commas outside double quotes, in one scan (a lookahead per comma was quadratic). */
function splitOutsideQuotes(s) {
  const out = [];
  let start = 0;
  let quoted = false;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '"') quoted = !quoted;
    else if (s[i] === "," && !quoted) { out.push(s.slice(start, i)); start = i + 1; }
  }
  out.push(s.slice(start));
  return out;
}
