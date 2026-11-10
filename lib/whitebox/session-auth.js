/**
 * Five session and login checks for `penthera --repo`, on lexed source
 * (lib/whitebox/js-lex.js: comments blanked, strings masked, so a name in a
 * comment or a string is not code):
 *
 *   next-middleware-no-auth        a Next.js middleware.ts or proxy.ts whose matcher or
 *                                  path checks name protected areas (/admin, /dashboard,
 *                                  /account, ...) and that never checks a session
 *   credential-in-url              a password, API key or access token read from the
 *                                  query string (CWE-598)
 *   password-encrypted-not-hashed  a password encrypted with a key (crypto-js AES,
 *                                  createCipheriv, encrypt()) instead of hashed, or
 *                                  decrypted to compare at login (CWE-257)
 *   session-cookie-insecure        Secure or HttpOnly turned off in a session library's
 *                                  cookie options, or express-session left without
 *                                  `cookie.secure` (CWE-614)
 *   oauth-callback-no-state        an OAuth callback that exchanges the `code` from the
 *                                  URL and never reads `state`, a PKCE verifier or a
 *                                  nonce (CWE-352), unless an auth library does the work
 *
 * Precision first: each rule needs a specific shape, and everything that may
 * hide the check (a spread, an options variable from another file, a helper
 * by an unknown name) makes it say nothing. The cookie calls (`res.cookie`,
 * `cookies().set`) are the fix planner's (lib/fix/recipes/cookies.js); this
 * file reads config objects only.
 *
 * Work per file is bounded: every pattern is linear (no `\w+` prefix that can
 * restart inside a long name, no pattern built from input), every read back or
 * forward has a fixed window, and the reads that depend on the input's shape
 * (call arguments, object literals, strings) are charged to a budget of 16
 * times the file's length. Past it the file is named as not fully checked and
 * the scan is incomplete (exit 2). Nothing runs.
 */
import { existsSync } from "node:fs";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { readRepoFile, isRefused } from "../fs-safe.js";
import { lexJs } from "./js-lex.js";
import { walkFiles, lineIndex, CODE_FILE, COMMON_SKIP, WALK_MAX_FILES } from "./walk.js";
import { callsAuth, authImports } from "./server-actions.js";

export const MIDDLEWARE_RULE = "next-middleware-no-auth";
export const URL_CREDENTIAL_RULE = "credential-in-url";
export const PASSWORD_ENCRYPTED_RULE = "password-encrypted-not-hashed";
export const SESSION_COOKIE_RULE = "session-cookie-insecure";
export const OAUTH_STATE_RULE = "oauth-callback-no-state";
/** Rule id → the finding category its references come from (explain_finding). */
export const SESSION_AUTH_RULES = {
  [MIDDLEWARE_RULE]: "auth",
  [URL_CREDENTIAL_RULE]: "info-leak",
  [PASSWORD_ENCRYPTED_RULE]: "auth",
  [SESSION_COOKIE_RULE]: "cookie",
  [OAUTH_STATE_RULE]: "auth",
};
export const SESSION_AUTH_MAX_BYTES = 4 * 1024 * 1024;
const WORK_FACTOR = 16;
// Windows for reads around a hit: a real statement is far shorter.
const BACK = 256;
// Members read after `req.query.` (`req.query.user.password`, qs's nested keys).
const MEMBER_DEPTH = 8;
// A file lists this many hits per rule in its finding; the count covers the rest.
const LIST_MAX = 8;
const SKIP = new Set([...COMMON_SKIP, "test", "tests", "__tests__", "spec", "e2e", "cypress", "fixtures", "__mocks__", "public", "static"]);

class OverBudget extends Error {}

/**
 * The worst LIST_MAX hits of one rule in a file, and how many there were: a
 * file of 200,000 decoy hits costs LIST_MAX entries of memory, and a harmless
 * decoy never pushes out a worse hit (lower `rank` is worse; then file order).
 */
class Worst {
  constructor(rank) { this.rank = rank; this.items = []; this.count = 0; }
  cmp(a, b) { return this.rank(a) - this.rank(b) || a.index - b.index; }
  push(h) {
    this.count++;
    const it = this.items;
    if (it.length === LIST_MAX && this.cmp(h, it[it.length - 1]) >= 0) return;
    let i = it.length;
    while (i > 0 && this.cmp(h, it[i - 1]) < 0) i--;
    it.splice(i, 0, h);
    if (it.length > LIST_MAX) it.pop();
  }
}

const ID = (c) => c !== undefined && (c === "$" || c === "_" || (c >= "0" && c <= "9") || (c >= "A" && c <= "Z") || (c >= "a" && c <= "z"));
const SP = (c) => c === " " || c === "\n" || c === "\t" || c === "\r" || c === "\f" || c === "\v";
const QUOTE = (c) => c === '"' || c === "'" || c === "`";

/** Both bracket maps in one pass: close of each opener, opener of each closer (-1 when unpaired). */
function pairs(code) {
  const close = new Int32Array(code.length).fill(-1);
  const open = new Int32Array(code.length).fill(-1);
  const stack = [];
  for (let i = 0; i < code.length; i++) {
    const c = code.charCodeAt(i);
    if (c === 40 || c === 91 || c === 123) stack.push(i);
    else if ((c === 41 || c === 93 || c === 125) && stack.length) { const o = stack.pop(); close[o] = i; open[i] = o; }
  }
  return { close, open };
}

/** One file's lexed copies, its line index, bracket maps (built on first use) and work budget. */
function context(source) {
  const { code, plain } = lexJs(source);
  let left = WORK_FACTOR * code.length + (1 << 20);
  let p = null;
  return {
    code,
    plain,
    lineAt: lineIndex(code),
    charge(n) { left -= n; if (left < 0) throw new OverBudget(); },
    /** skipSpace with no window, its length charged: padding never hides what follows. */
    skip(i) { const j = skipSpace(code, i); this.charge(j - i); return j; },
    get pairs() { return (p ??= pairs(code)); },
  };
}

function skipSpace(code, i, limit = code.length) { while (i < limit && SP(code[i])) i++; return i; }
function backSpace(code, i) { while (i >= 0 && SP(code[i])) i--; return i; }

/** The identifier that ends at `end` (inclusive), read back at most 64 characters, and where it starts. */
function identBefore(code, end) {
  let k = end;
  while (k >= 0 && end - k < 64 && ID(code[k])) k--;
  return { name: code.slice(k + 1, end + 1), start: k + 1 };
}

/** The receiver of a member access whose `.` (or `?.`) ends just before `at`: `req` in `req.query`. "" when there is none. */
function receiverBefore(code, at) {
  let k = backSpace(code, at - 1);
  if (code[k] !== ".") return null;
  k = backSpace(code, code[k - 1] === "?" ? k - 2 : k - 1);
  if (code[k] === ")") return ")";
  return identBefore(code, k).name;
}

/** A string literal's text, from its opening quote in masked code; null when it never closes. */
function stringAt(ctx, q) {
  const ch = ctx.code[q];
  if (!QUOTE(ch)) return null;
  const end = ctx.code.indexOf(ch, q + 1);
  if (end === -1) return null;
  ctx.charge(end - q);
  return ctx.plain.slice(q + 1, end);
}

/**
 * Every string literal once, in file order: visit(value, index). Masked code
 * keeps each literal's quotes and blanks what is inside, so the next quote of
 * the same kind closes it.
 */
function eachString(ctx, visit) {
  const { code, plain } = ctx;
  for (let i = 0; i < code.length; i++) {
    const c = code[i];
    if (!QUOTE(c)) continue;
    const end = code.indexOf(c, i + 1);
    if (end === -1) return; // ends inside a string: what is left is that string
    visit(plain.slice(i + 1, end), i);
    i = end;
  }
}

// ── Names read from the URL ─────────────────────────────────────────────────

// Receivers whose `.query` is a database's, not a request's (Drizzle `db.query.users`).
const DB_RECEIVERS = new Set(["db", "database", "drizzle", "tx", "trx", "prisma", "client", "pool", "conn", "connection", "knex", "sql", "orm", "em"]);
const QUERY_MEMBER = /(?<![\w$])query\s*(?:\?\.|\.)\s*([A-Za-z_$][\w$]*)/g;
// No `\s*` on both sides of an optional token: on padding the two runs split it every way (quadratic).
const QUERY_INDEX = /(?<![\w$])query\s*(?:\?\.\s*)?\[\s*(?=["'`])/g;
const QUERY_GET = /(?<![\w$])(?:searchParams|queryParams|urlParams|searchQuery|query|useSearchParams\s*\(\s*\))\s*(?:\?\.|\.)\s*get(?:All)?\s*\(\s*(?=["'`])/g;
const HONO_QUERY = /(?<![\w$])req\s*(?:\?\.|\.)\s*quer(?:y|ies)\s*\(\s*(?=["'`])/g;
const SEARCH_MEMBER = /(?<![\w$])searchParams\s*(?:\)\s*)?(?:\?\.|\.)\s*([A-Za-z_$][\w$]*)/g;
const GET_QUERY = /(?<![\w$])getQuery\s*\(/g;
const QUERY_WORD = /(?<![\w$])(?:query|searchParams)(?![\w$])/g;

/** The keys of a destructuring pattern `{ a, b: c, "d": e, f = 1, ...rest }` between `open` and `close`. */
function patternKeys(ctx, open, close) {
  const { code } = ctx;
  const keys = [];
  let depth = 0;
  let from = open + 1;
  const take = (s, e) => {
    const i = skipSpace(code, s, e);
    if (i >= e || code[i] === ".") return;
    if (QUOTE(code[i])) { const v = stringAt(ctx, i); if (v !== null) keys.push({ name: v, index: i }); return; }
    let j = i;
    while (j < e && ID(code[j])) j++;
    if (j > i) keys.push({ name: code.slice(i, j), index: i });
  };
  for (let i = open + 1; i < close; i++) {
    const c = code[i];
    if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") depth--;
    else if (c === "," && depth === 0) { take(from, i); from = i + 1; }
  }
  take(from, close);
  return keys;
}

/**
 * Every name the file reads from a request's query string: visit(name, index).
 * `req.query.x`, `req.query["x"]`, `searchParams.get("x")`, `c.req.query("x")`,
 * `searchParams.x` (a Next.js page's prop), `getQuery(event).x` (h3, Nuxt) and
 * `const { x } = req.query` (or `= await searchParams`).
 */
function urlReads(ctx, visit) {
  const { code } = ctx;
  for (const m of code.matchAll(QUERY_MEMBER)) {
    const r = receiverBefore(code, m.index);
    if (r === null || DB_RECEIVERS.has(r)) continue;
    visit(m[1], m.index);
    // Nested keys: `req.query.user.password` (`?user[password]=` with qs).
    let k = m.index + m[0].length;
    for (let d = 1; d < MEMBER_DEPTH; d++) {
      k = ctx.skip(k);
      if (code[k] === "?" && code[k + 1] === ".") k++;
      if (code[k] !== ".") break;
      k = ctx.skip(k + 1);
      const s0 = k;
      while (k < code.length && k - s0 < 128 && ID(code[k])) k++;
      if (k === s0) break;
      visit(code.slice(s0, k), s0);
    }
  }
  for (const m of code.matchAll(QUERY_INDEX)) {
    const r = receiverBefore(code, m.index);
    if (r === null || DB_RECEIVERS.has(r)) continue;
    const q = m.index + m[0].length;
    const v = stringAt(ctx, q);
    if (v !== null) visit(v, q);
  }
  for (const re of [QUERY_GET, HONO_QUERY]) {
    for (const m of code.matchAll(re)) {
      const q = m.index + m[0].length;
      const v = stringAt(ctx, q);
      if (v !== null) visit(v, q);
    }
  }
  for (const m of code.matchAll(SEARCH_MEMBER)) visit(m[1], m.index);
  for (const m of code.matchAll(GET_QUERY)) {
    const open = m.index + m[0].length - 1;
    const close = ctx.pairs.close[open];
    if (close === -1) continue;
    let k = ctx.skip(close + 1);
    if (code[k] === "?") k++;
    if (code[k] !== ".") continue;
    k = ctx.skip(k + 1);
    const s = k;
    while (k < code.length && k - s < 128 && ID(code[k])) k++;
    if (k > s) visit(code.slice(s, k), s);
  }
  // `const { password } = req.query`: from the word, forward to the statement's end
  // and back over the receiver chain to `=` and the pattern's `}`. No window: every
  // character read is charged, so padding can't hide the pattern and can't cost more
  // than the budget.
  for (const m of code.matchAll(QUERY_WORD)) {
    const after = m.index + m[0].length;
    let k = ctx.skip(after);
    if (code[k] === "(") { const c = ctx.skip(k + 1); if (code[c] === ")") k = ctx.skip(c + 1); }
    if (!(k >= code.length || code[k] === ";" || code[k] === ")" || code[k] === "," || /[\n\r]/.test(code.slice(after, k)))) continue;
    let b = m.index - 1;
    while (b >= 0 && (ID(code[b]) || SP(code[b]) || code[b] === "." || code[b] === "?")) b--;
    ctx.charge(m.index - b);
    if (code[b] !== "=" || code[b - 1] === "=" || code[b - 1] === "!" || code[b - 1] === "<" || code[b - 1] === ">") continue;
    const chain = code.slice(b + 1, m.index).replace(/\s+/g, "");
    if (chain && !/^(?:await)?(?:[\w$]+\??\.)*$/.test(chain)) continue;
    const first = chain.replace(/^await/, "").split(/\??\./)[0];
    if (DB_RECEIVERS.has(first)) continue;
    const close = backSpace(code, b - 1);
    if (code[close] !== "}") continue;
    const open = ctx.pairs.open[close];
    if (open === -1) continue;
    ctx.charge(close - open);
    for (const key of patternKeys(ctx, open, close)) visit(key.name, key.index);
  }
}

/**
 * "password", "credential" or null for a name read from the URL. A one-time
 * `token` or `code` in a link is normal, so neither counts; nor does
 * `session_id`, which is Stripe Checkout's return-URL id far more often than a
 * login session.
 */
export function credentialKind(name) {
  const n = String(name).toLowerCase().replace(/[_-]/g, "");
  if (/(?:password|passwd|passphrase)$/.test(n) || n === "pwd") return "password";
  if (CREDENTIAL_NAMES.has(n)) return "credential";
  return null;
}
const CREDENTIAL_NAMES = new Set(["apikey", "apisecret", "secret", "secretkey", "clientsecret", "accesstoken", "authtoken", "refreshtoken", "bearertoken", "idtoken", "apitoken", "sessiontoken", "privatekey", "jwt", "personalaccesstoken", "servicekey", "servicerolekey"]);

// ── Passwords encrypted instead of hashed ──────────────────────────────────

const HASHING = /\b(?:bcrypt|bcryptjs|argon2|argon2id|scrypt|scryptSync|pbkdf2|pbkdf2Sync|hashPassword|hashSync)\b|@node-rs\/(?:argon2|bcrypt)|password-hash|Bun\.password/;
const PW_IDENT = /(?<![\w$])(?:password|passwd|pwd|plainPassword|plaintextPassword|rawPassword|userPassword|newPassword)(?![\w$])/g;
// A password for another system (a mail server, a database, an integration) must be recoverable: encrypting it is right.
const THIRD_PARTY = /smtp|mail|imap|pop3|ftp|ssh|db|database|redis|proxy|wifi|vault|integration|config|env|settings|provider|connection|upstream|remote/i;
const ENCRYPT_CALL = /(?<![\w$])encrypt(?:Sync|String|Text|Data|Value)?\s*\(/g;
const DECRYPT_CALL = /(?<![\w$])decrypt(?:Sync|String|Text|Data|Value)?\s*\(/g;
const CIPHER_DECL = /(?<![\w$])(?:const|let|var)\s+([\w$]+)\s*=\s*(?:[\w$]+\s*\.\s*)?create(Cipher|Decipher)(?:iv)?\s*\(/g;
const CIPHER_CHAIN = /(?<![\w$])create(Cipher|Decipher)(?:iv)?\s*\(/g;
// From the `.update(`, the receiver read back: a pattern that starts at every identifier is slow on large bundles.
const UPDATE_CALL = /\.\s*update\s*\(/g;
const NOT_CIPHER_RECEIVERS = new Set(["bcrypt", "bcryptjs", "argon2", "hash", "hasher", "crypto"]);

/**
 * Where the member chain that ends just before `at` starts (`x` of `x.y.password`).
 * Read back in a window of BACK: cut short, it only names less of the receiver, and
 * the third-party test then reports rather than skips.
 */
function chainStart(code, at) {
  let b = at - 1;
  const stop = Math.max(-1, at - BACK);
  while (b > stop && (ID(code[b]) || SP(code[b]) || code[b] === "." || code[b] === "?")) b--;
  return skipSpace(code, b + 1, at);
}

/** The member chain that ends just before `at`, without spaces. */
function chainBefore(code, at) {
  return code.slice(chainStart(code, at), at).replace(/\s+/g, "");
}

/** The first user password among a call's arguments, `skipThirdParty` leaving out `smtp.password` and the like. */
function passwordArg(ctx, open, close, skipThirdParty) {
  ctx.charge(close - open);
  const args = ctx.code.slice(open + 1, close);
  PW_IDENT.lastIndex = 0;
  for (const m of args.matchAll(PW_IDENT)) {
    const chain = chainBefore(args, m.index);
    if (skipThirdParty && THIRD_PARTY.test(chain)) continue;
    return (chain + m[0]).slice(-80);
  }
  return null;
}

/**
 * Is the expression in [start, end] an operand of ===, !==, == or !=? The right
 * side may continue with members and calls (`decrypt(x).toString(enc.Utf8) === y`).
 * Every character read is charged: padding never hides the operator.
 */
function operandOfCompare(ctx, start, end) {
  const { code } = ctx;
  let b = start - 1;
  while (b >= 0 && SP(code[b])) b--;
  ctx.charge(start - b);
  if (code[b] === "=" && (code[b - 1] === "=" || code[b - 1] === "!")) return true;
  let k = end + 1;
  for (let d = 0; d < MEMBER_DEPTH; d++) {
    k = ctx.skip(k);
    if (code[k] === "?" && code[k + 1] === ".") k++;
    if (code[k] !== ".") break;
    k = ctx.skip(k + 1);
    while (k < code.length && ID(code[k])) k++;
    const c = ctx.skip(k);
    if (code[c] === "(") { const close = ctx.pairs.close[c]; if (close === -1) return false; k = close + 1; }
  }
  k = ctx.skip(k);
  return (code[k] === "=" || code[k] === "!") && code[k + 1] === "=";
}

/** Does the statement around [start, end] compare? As an operand, or on the same line (`timingSafeEqual(…decrypt(…)…)`). */
function compares(ctx, start, end) {
  if (operandOfCompare(ctx, start, end)) return true;
  const { code } = ctx;
  let before = code.slice(Math.max(0, start - BACK), start);
  const cut = Math.max(before.lastIndexOf(";"), before.lastIndexOf("{"), before.lastIndexOf("}"), before.lastIndexOf("\n"));
  before = before.slice(cut + 1);
  let after = code.slice(end + 1, end + 1 + BACK);
  const stop = after.search(/[;{\n]/);
  if (stop !== -1) after = after.slice(0, stop);
  const eq = /[!=]==?(?!>)|timingSafeEqual\s*\(/;
  return eq.test(before.replace(/[<>]=|=>/g, "")) || eq.test(after.replace(/[<>]=|=>/g, ""));
}

/**
 * For `const x = decrypt(...)`: is `x` compared later in the same block? The
 * block's end is found by counting brackets, its length charged; the name is
 * found by indexOf, never a pattern built from it.
 */
function comparedLater(ctx, start, end) {
  const { code } = ctx;
  const eqAt = backSpace(code, start - 1);
  if (code[eqAt] !== "=" || code[eqAt - 1] === "=" || code[eqAt - 1] === "!") return false;
  const { name } = identBefore(code, backSpace(code, eqAt - 1));
  if (!name || !/^[A-Za-z_$]/.test(name)) return false;
  let stop = end + 1;
  for (let depth = 0; stop < code.length; stop++) {
    const c = code[stop];
    if (c === "{" || c === "(" || c === "[") depth++;
    else if ((c === "}" || c === ")" || c === "]") && --depth < 0) break;
  }
  ctx.charge(stop - end);
  for (let i = code.indexOf(name, end + 1); i !== -1 && i < stop; i = code.indexOf(name, i + 1)) {
    if (ID(code[i - 1]) || ID(code[i + name.length]) || code[i - 1] === ".") continue;
    if (operandOfCompare(ctx, i, i + name.length - 1)) return true;
  }
  return false;
}

/**
 * Passwords stored so they can be read back. Two shapes:
 *   compare: a decrypted password compared at login (likely)
 *   encrypt: a user's password passed to encrypt(), AES.encrypt() or a
 *            createCipheriv cipher's update(), in a file that never hashes one (potential)
 */
function encryptedPasswords(ctx, hits = []) {
  const { code, plain } = ctx;
  const ciphers = new Map(); // name -> "Cipher" | "Decipher"
  const usesCiphers = /create(?:Cipher|Decipher)/.test(code);
  if (usesCiphers) for (const m of code.matchAll(CIPHER_DECL)) ciphers.set(m[1], m[2]);
  const hashes = HASHING.test(plain);
  // A call the file never closes reads to the end of the file: it ends inside the call, so all of it is the arguments.
  const callAt = (open) => { const c = ctx.pairs.close[open]; return c === -1 ? code.length : c; };
  const decrypted = (open, start, close) => {
    // `CryptoJS.AES.decrypt(`: the operand is the whole chain, read back with no window, charged.
    let b = start - 1;
    while (b >= 0 && (ID(code[b]) || SP(code[b]) || code[b] === "." || code[b] === "?")) b--;
    ctx.charge(start - b);
    start = skipSpace(code, b + 1, start);
    const pw = passwordArg(ctx, open, close, false);
    if (pw && (compares(ctx, start, close) || comparedLater(ctx, start, close))) hits.push({ kind: "compare", index: start, what: pw });
  };
  const encrypted = (open, start, close) => {
    if (hashes) return;
    const pw = passwordArg(ctx, open, close, true);
    if (pw) hits.push({ kind: "encrypt", index: start, what: pw });
  };
  for (const m of code.matchAll(DECRYPT_CALL)) {
    const open = m.index + m[0].length - 1;
    const close = callAt(open);
    decrypted(open, m.index, close);
  }
  for (const m of code.matchAll(ENCRYPT_CALL)) {
    const r = receiverBefore(code, m.index);
    if (r && NOT_CIPHER_RECEIVERS.has(r)) continue;
    const open = m.index + m[0].length - 1;
    const close = callAt(open);
    encrypted(open, m.index, close);
  }
  const update = (kind, open, start) => {
    const close = callAt(open);
    if (kind === "Decipher") decrypted(open, start, close);
    else encrypted(open, start, close);
  };
  if (ciphers.size) {
    for (const m of code.matchAll(UPDATE_CALL)) {
      const { name, start } = identBefore(code, backSpace(code, m.index - 1));
      const kind = ciphers.get(name);
      if (kind && !ID(code[start - 1]) && code[start - 1] !== ".") update(kind, m.index + m[0].length - 1, start);
    }
  }
  // `crypto.createCipheriv(alg, key, iv).update(password)`: the call right after the factory's ")".
  for (const m of usesCiphers ? code.matchAll(CIPHER_CHAIN) : []) {
    const close = callAt(m.index + m[0].length - 1);
    if (close === -1) continue;
    let k = ctx.skip(close + 1);
    if (code[k] !== ".") continue;
    k = ctx.skip(k + 1);
    if (code.startsWith("update", k) && !ID(code[k + 6])) {
      const open = ctx.skip(k + 6);
      if (code[open] === "(") update(m[1], open, m.index);
    }
  }
  return hits;
}

// ── Session cookie options ──────────────────────────────────────────────────

const EXPRESS_SESSION = /^express-session$/;
// Libraries whose cookie options switch Secure or HttpOnly off only when told to.
const SESSION_LIBS = /^(?:express-session|cookie-session|koa-session|@fastify\/session|@fastify\/secure-session|iron-session|next-iron-session|next-auth(?:\/.*)?|@auth\/.+|better-auth(?:\/.*)?|lucia|@lucia-auth\/.+|hono-sessions|@hono\/session)$/;
// The keys under which these libraries take cookie attributes. `options` and
// `attributes` are too common to count alone: only under next-auth's cookie
// names (`cookies.sessionToken.options`) or Lucia's `sessionCookie.attributes`.
const COOKIE_KEYS = new Set(["cookie", "cookies", "cookieOptions", "cookieAttributes", "defaultCookieAttributes", "sessionCookie", "sessionCookieOptions"]);
const NESTED_COOKIE_KEYS = { options: new Set(["sessionToken", "callbackUrl", "csrfToken", "pkceCodeVerifier", "state", "nonce"]), attributes: new Set(["sessionCookie"]) };
// Remix and React Router export much more than sessions: they count only with a cookie session factory in the file.
const COOKIE_FACTORY_LIBS = /^(?:@remix-run\/(?:node|cloudflare|deno)|react-router|@react-router\/(?:node|cloudflare))$/;
const COOKIE_FACTORY = /(?<![\w$.])create(?:Cookie|CookieSessionStorage)\s*\(/;
// express-session's docs set `sess.cookie.secure = true` later, for production only.
const SECURE_ASSIGNED = /(?:\.\s*cookie\s*\.\s*secure|\[\s*["']secure["']\s*\])\s*=(?!=)/;
const FLAG_OFF = /(?<![\w$])(secure|httpOnly|useSecureCookies)\s*:\s*false(?![\w$])/g;
const DEFAULT_IMPORT = /(?<![\w$.])import\s+([\w$]+)\s*(?:,\s*\{[^}]{0,512}\}\s*)?from\s*(?=["'])/g;
const REQUIRE_BIND = /(?<![\w$.])(?:const|let|var)\s+([\w$]+)\s*=\s*require\s*\(\s*(?=["'])/g;
const OBJECT_DECL = /(?<![\w$])(?:const|let|var)\s+([\w$]+)\s*(?::\s*[\w$.]{1,80}(?:<[\w$.,\s]{0,80}>)?\s*)?=\s*(?=\{)/g;

/** Local names bound to a module's default export: `import session from "express-session"`, `const session = require(...)`. */
function defaultBindings(ctx, test) {
  const names = new Set();
  for (const re of [DEFAULT_IMPORT, REQUIRE_BIND]) {
    for (const m of ctx.code.matchAll(re)) {
      const spec = stringAt(ctx, m.index + m[0].length);
      if (spec !== null && test(spec)) names.add(m[1]);
    }
  }
  return names;
}

/** The top-level keys of the object literal `{ ... }` at `open`: Map key → index of its value, and whether it spreads. */
function objectKeys(ctx, open) {
  const { code } = ctx;
  // No window: the read is charged before it starts. An object the file never closes runs to the end.
  const c0 = ctx.pairs.close[open];
  const close = c0 === -1 ? code.length : c0;
  ctx.charge(close - open);
  const keys = new Map();
  let spread = false;
  let depth = 0;
  let expectKey = true;
  for (let i = open + 1; i < close; i++) {
    const c = code[i];
    if (c === "(" || c === "[" || c === "{") { depth++; continue; }
    if (c === ")" || c === "]" || c === "}") { depth--; continue; }
    if (depth) continue;
    if (c === ",") { expectKey = true; continue; }
    if (!expectKey || SP(c)) continue;
    expectKey = false;
    if (c === "." && code[i + 1] === "." && code[i + 2] === ".") { spread = true; continue; }
    let key = null;
    let j = i;
    if (QUOTE(c)) { const end = code.indexOf(c, i + 1); if (end === -1 || end > close) break; key = ctx.plain.slice(i + 1, end); j = end + 1; } else {
      while (j < close && ID(code[j])) j++;
      key = code.slice(i, j);
    }
    const colon = skipSpace(code, j, close);
    if (code[colon] === ":") keys.set(key, skipSpace(code, colon + 1, close));
    else if (key) keys.set(key, -1); // shorthand `{ secure }` or a method: set to something
    i = Math.max(i, j - 1);
  }
  return { keys, spread, close };
}

/**
 * Insecure session cookie options in one file: [{ what, index, explicit }].
 *   explicit: `secure: false`, `httpOnly: false` or `useSecureCookies: false` in a
 *             session library's cookie options (the file imports one)
 *   missing:  express-session called with options that set no `cookie.secure`
 *             (it then sends the session cookie without Secure)
 */
function insecureSessionCookies(ctx, hits = []) {
  const { code } = ctx;
  // Which session libraries the file imports, read from its string literals.
  let libs = false;
  let express = false;
  let factory = false;
  eachString(ctx, (v) => {
    if (SESSION_LIBS.test(v)) { libs = true; if (EXPRESS_SESSION.test(v)) express = true; }
    if (COOKIE_FACTORY_LIBS.test(v)) factory = true;
  });
  if (!libs && !(factory && COOKIE_FACTORY.test(code))) return hits;
  // The key an object literal at `open` is the value of: `cookie` in `cookie: {`, or null.
  const keyOf = (open) => {
    if (open === undefined || open < 0) return null;
    const colon = backSpace(code, open - 1);
    if (code[colon] !== ":") return null;
    const k = backSpace(code, colon - 1);
    if (QUOTE(code[k])) { const q = code.lastIndexOf(code[k], k - 1); return q !== -1 && k - q < 64 ? ctx.plain.slice(q + 1, k) : null; }
    return identBefore(code, k).name || null;
  };
  // explicit: one pass over the code keeps the open braces, so each `false` flag
  // learns its enclosing object, and that object's key, in linear time.
  const flags = [...code.matchAll(FLAG_OFF)];
  if (flags.length) {
    const stack = [];
    let f = 0;
    for (let i = 0; i < code.length && f < flags.length; i++) {
      while (f < flags.length && flags[f].index === i) {
        const m = flags[f++];
        if (m[1] === "useSecureCookies") { hits.push({ what: "useSecureCookies: false", index: m.index, explicit: true }); continue; }
        const key = keyOf(stack[stack.length - 1]);
        const cookieish = key && (COOKIE_KEYS.has(key) || NESTED_COOKIE_KEYS[key]?.has(keyOf(stack[stack.length - 2])));
        if (cookieish) hits.push({ what: `${m[1]}: false`, index: m.index, explicit: true });
      }
      const c = code[i];
      if (c === "{") stack.push(i);
      else if (c === "}") stack.pop();
    }
  }
  // missing: express-session's options, inline or in a `const` of this file.
  if (express && !SECURE_ASSIGNED.test(code)) {
    const names = defaultBindings(ctx, (s) => EXPRESS_SESSION.test(s));
    if (names.size) {
      const decls = new Map();
      for (const m of code.matchAll(OBJECT_DECL)) if (!decls.has(m[1])) decls.set(m[1], m.index + m[0].length);
      // The object literal at `i`, or the one a `const` of this file binds to the name at `i`; -1 when not seen.
      const objectAt = (i) => {
        if (code[i] === "{") return i;
        let k = i;
        while (k < code.length && k - i < 64 && ID(code[k])) k++;
        const name = code.slice(i, k);
        return name && decls.has(name) ? decls.get(name) : -1;
      };
      for (const m of code.matchAll(/(?<![\w$.])([\w$]+)\s*\(/g)) {
        if (!names.has(m[1])) continue;
        const arg = ctx.skip(m.index + m[0].length);
        const at = objectAt(arg);
        if (at === -1) continue; // options from another file: not seen
        const opts = objectKeys(ctx, at);
        if (!opts || opts.spread) continue;
        const cookie = opts.keys.get("cookie");
        if (cookie === undefined) { hits.push({ what: "no cookie options (Secure is off by default)", index: m.index, explicit: false }); continue; }
        if (cookie === -1) continue;
        const inner = objectAt(cookie);
        if (inner === -1) continue;
        const c = objectKeys(ctx, inner);
        if (!c || c.spread) continue;
        if (!c.keys.has("secure")) hits.push({ what: "cookie options without secure (off by default)", index: m.index, explicit: false });
      }
    }
  }
  return hits;
}

// ── OAuth callbacks ─────────────────────────────────────────────────────────

// Libraries that create and check `state` themselves (or keep the code bound to the session by PKCE).
const OAUTH_LIBS = /^(?:next-auth|@auth\/|passport|openid-client|oauth4webapi|@fastify\/oauth2|@supabase\/|better-auth|@clerk\/|@auth0\/|auth0|@workos-inc\/|@kinde-oss\/|grant|@hono\/oauth-providers|@logto\/|lucia)/;
const STATE_WORD = /(?<![A-Za-z])state(?![a-z])|(?<!use|set)State(?![a-z])|code_?verifier|codeVerifier|nonce/i;
const EXCHANGES = [
  /(?<![\w$])validateAuthorizationCode\s*\(/, // arctic
  /(?<![\w$.])(?:[\w$]+\s*\.\s*)?getToken\s*\(\s*(?:\{[^{}()]{0,200}(?<![\w$])code(?![\w$])|code\s*[,)])/, // googleapis, simple-oauth2
];

/**
 * An OAuth callback in one file that exchanges the code without a state check:
 * { index } of the exchange, or null. It needs the `code` read from the URL, a
 * code exchange (an `authorization_code` grant, arctic's
 * validateAuthorizationCode, an OAuth client's getToken(code)), and no
 * `state`, PKCE `code_verifier` or `nonce` anywhere in the file, and no import
 * of a library that checks state for you.
 */
function uncheckedOAuthCallback(ctx) {
  const { code, plain } = ctx;
  if (STATE_WORD.test(plain)) return null;
  let grant = -1;
  let lib = false;
  eachString(ctx, (v, i) => {
    if (grant === -1 && /\bauthorization_code\b/.test(v)) grant = i;
    if (OAUTH_LIBS.test(v)) lib = true;
  });
  if (lib) return null;
  let exchange = grant;
  for (const re of EXCHANGES) {
    if (exchange !== -1) break;
    const m = re.exec(code);
    if (m) exchange = m.index;
  }
  if (exchange === -1) return null;
  let readsCode = false;
  urlReads(ctx, (name) => { if (name === "code") readsCode = true; });
  return readsCode ? { index: exchange } : null;
}

// ── Next.js middleware and proxy ────────────────────────────────────────────

const MIDDLEWARE_FILE = /^(?:middleware|proxy)\.(?:[cm]?js|[cm]?ts)$/;
// A first path segment that is usually behind a login.
// Segments that are often public (/app, /team, /user/:name, /profile/:name) are left out.
const PROTECTED_PATH = /^\/(?:\([\w-]+\)\/)?(?:admin|dashboard|account|accounts|settings|billing|private|protected|internal|manage|panel|workspace|workspaces)(?=$|[/?:(*.])/i;
const LOGIN_PATH = /^(?:https?:\/\/[^/]*)?\/(?:[\w-]+\/)?(?:login|log-in|signin|sign-in|sign_in|auth|sso|unauthorized|403)(?=$|[/?#])/i;
const NEXT_IMPORT = /^next(?:\/server)?$/;
// A middleware that reads a session cookie or a credential header checks something, if only optimistically.
const SESSION_READ = /(?<![\w$])cookies\s*(?:\(\s*\)\s*)?(?:\?\.|\.)\s*(?:get|has|getAll)\s*\(|(?<![\w$])headers\s*(?:\(\s*\)\s*)?(?:\?\.|\.)\s*get\s*\(\s*["'](?:authorization|cookie|x-api-key)/i;
const EXPORTS_MIDDLEWARE = /\bexport\s+(?:default\b|(?:async\s+)?function\s+(?:middleware|proxy)\b|(?:const|let|var)\s+(?:middleware|proxy)\b)/;
const EXPORT_LIST = /\bexport\s*\{/g;

/** Does the file export a middleware: `export default`, `export function middleware`, or `middleware`, `proxy` or `default` in an `export { ... }` list (read up to 1,024 characters)? */
function exportsMiddleware(code) {
  if (EXPORTS_MIDDLEWARE.test(code)) return true;
  for (const m of code.matchAll(EXPORT_LIST)) {
    const from = m.index + m[0].length;
    let e = from;
    while (e < code.length && e - from < 1024 && code[e] !== "}") e++;
    if (code[e] === "}" && /(?<![\w$])(?:middleware|proxy|default)(?![\w$])/.test(code.slice(from, e))) return true;
  }
  return false;
}

/** Is this file a Next.js middleware or proxy (by name, export and a Next.js import, matcher or config next to it)? */
function isNextMiddleware(full, code, sawNext) {
  if (!exportsMiddleware(code)) return false;
  if (sawNext || /(?<![\w$])matcher\s*:/.test(code)) return true;
  let dir = dirname(full);
  if (basename(dir) === "src") dir = dirname(dir);
  return ["next.config.js", "next.config.mjs", "next.config.ts", "next.config.cjs", "next.config.mts"].some((n) => existsSync(join(dir, n)));
}

/**
 * A middleware that names protected paths and checks no session: { paths, index } or null.
 * Any of these counts as a check: an auth call by name (the Server Actions
 * check's list), anything imported or re-exported from an auth module, a
 * cookie or Authorization header read, or a redirect target such as /login.
 */
function unguardedMiddleware(ctx) {
  const { code, plain } = ctx;
  if (callsAuth(code) || SESSION_READ.test(plain) || authImports(code, plain).size) return null;
  const paths = [];
  let first = -1;
  let login = false;
  let sawNext = false;
  eachString(ctx, (v, i) => {
    if (LOGIN_PATH.test(v)) login = true;
    if (NEXT_IMPORT.test(v)) sawNext = true;
    if (PROTECTED_PATH.test(v)) { if (first === -1) first = i; if (paths.length < LIST_MAX && !paths.includes(v)) paths.push(v.slice(0, 80)); }
  });
  ctx.sawNext = sawNext;
  if (login || first === -1) return null;
  return { paths, index: first };
}

// ── The scan ────────────────────────────────────────────────────────────────

/**
 * The five checks on one file's source. `opts.middleware(sawNext, code)`, given
 * for a file named middleware or proxy, says whether it is a Next.js one (it
 * needs the string pass to decide); without it the middleware check is skipped.
 * @returns {{ hits: object, incomplete: boolean }}
 */
export function sessionAuthHits(source, { middleware = null } = {}) {
  const hits = {
    middleware: null,
    url: new Worst((h) => (h.kind === "password" ? 0 : 1)),
    encrypted: new Worst((h) => (h.kind === "compare" ? 0 : 1)),
    cookies: new Worst((h) => (h.explicit ? 0 : 1)),
    oauth: null,
  };
  const quick = {
    url: /query|searchparams/i.test(source),
    pw: /pass(?:word|wd)|pwd/i.test(source) && /encrypt|decrypt|createCipher|createDecipher/i.test(source),
    cookie: /secure|httpOnly|session/i.test(source),
    oauth: /authorization_code|validateAuthorizationCode|getToken/.test(source),
  };
  const ctx = context(source);
  try {
    if (quick.url) {
      urlReads(ctx, (name, index) => { const kind = credentialKind(name); if (kind) hits.url.push({ name, kind, index }); });
    }
    // Each collector pushes as it goes: what it found before a budget stop is kept.
    if (quick.pw) encryptedPasswords(ctx, hits.encrypted);
    if (quick.cookie) insecureSessionCookies(ctx, hits.cookies);
    if (quick.oauth) hits.oauth = uncheckedOAuthCallback(ctx);
    if (middleware) {
      const mw = unguardedMiddleware(ctx);
      if (mw && middleware(ctx.sawNext, ctx.code)) hits.middleware = mw;
    }
  } catch (e) {
    if (!(e instanceof OverBudget)) throw e;
    return { hits, incomplete: true, lineAt: ctx.lineAt };
  }
  return { hits, incomplete: false, lineAt: ctx.lineAt };
}

function findingsFor(rel, hits, lineAt) {
  const out = [];
  const base = { url: rel, file: rel, source: "static-analysis" };
  if (hits.middleware) {
    const { paths, index } = hits.middleware;
    out.push({
      ...base,
      severity: "medium",
      confidence: "potential",
      title: `Next.js ${/proxy\.[cm]?[jt]s$/.test(rel) ? "proxy" : "middleware"} names protected paths but checks no session: ${rel}`,
      description: `\`${rel}\` runs on ${paths.map((p) => `\`${p}\``).join(", ")}, but it calls no auth function, imports nothing from an auth module, reads no session cookie or Authorization header and redirects nowhere like /login. If these pages rely on it to keep visitors out, anyone can open them.`,
      remediation: "Check the session in the middleware (read and verify the session cookie, or call your auth library's helper such as `auth()`, `clerkMiddleware()` or `updateSession()`) and redirect to the login page when it is missing. Check it again in each page, route handler and Server Action: middleware is an optimistic first check, not the only one.",
      line: lineAt(index),
      templateId: MIDDLEWARE_RULE,
      category: "auth",
      cwe: "CWE-306",
    });
  }
  if (hits.url.count) {
    const list = hits.url.items;
    const pw = list[0].kind === "password";
    out.push({
      ...base,
      severity: pw ? "medium" : "low",
      confidence: pw ? "likely" : "potential",
      title: `${pw ? "Password" : "Credential"} read from the URL in ${rel}`,
      description: `${list.map((h) => `\`${h.name}\` (line ${lineAt(h.index)})`).join(", ")}${hits.url.count > LIST_MAX ? ` and ${hits.url.count - LIST_MAX} more` : ""} ${hits.url.count === 1 ? "is" : "are"} read from the query string. A URL ends up in browser history, server and proxy logs, analytics and the Referer header sent to other sites, so a ${pw ? "password" : "secret"} in it leaks to all of them.`,
      remediation: pw
        ? "Send the password in a POST body (a form with method=\"post\", or JSON) and read it from there. Never put it in a link or a GET form."
        : "Take the secret from a header (`Authorization: Bearer …`, or a custom header for webhooks and cron jobs) or a POST body instead of the query string, and rotate any value that was sent in a URL.",
      line: lineAt(list[0].index),
      templateId: URL_CREDENTIAL_RULE,
      category: "info-leak",
      cwe: "CWE-598",
      names: [...new Set(list.map((h) => h.name))],
    });
  }
  if (hits.encrypted.count) {
    const list = hits.encrypted.items;
    const compare = list[0].kind === "compare";
    out.push({
      ...base,
      severity: "high",
      confidence: compare ? "likely" : "potential",
      title: `Password ${compare ? "decrypted to compare" : "encrypted instead of hashed"} in ${rel}`,
      description: `${list.map((h) => `\`${h.what}\` (line ${lineAt(h.index)}, ${h.kind === "compare" ? "decrypted and compared" : "encrypted"})`).join(", ")}${hits.encrypted.count > LIST_MAX ? ` and ${hits.encrypted.count - LIST_MAX} more` : ""}. An encrypted password can be turned back into the password by anyone who gets the key, and the key sits next to the data. Leaked once, every user's password is readable, and people reuse them.${compare ? "" : " If this is a password for another system (a mail server, an integration), encrypting it is right and this finding does not apply."}`,
      remediation: "Hash passwords with a slow, salted password hash (argon2id, scrypt or bcrypt) and check a login with the library's verify function (`argon2.verify`, `bcrypt.compare`). Never decrypt a password. Migrate stored ones by rehashing each at the next successful login, then delete the encrypted column.",
      line: lineAt(list[0].index),
      templateId: PASSWORD_ENCRYPTED_RULE,
      category: "auth",
      cwe: "CWE-257",
    });
  }
  if (hits.cookies.count) {
    const list = hits.cookies.items;
    const explicit = list[0].explicit;
    out.push({
      ...base,
      severity: "medium",
      confidence: explicit ? "likely" : "potential",
      title: `Session cookie options turn off Secure or HttpOnly in ${rel}`,
      description: `${list.map((h) => `\`${h.what}\` (line ${lineAt(h.index)})`).join(", ")}${hits.cookies.count > LIST_MAX ? ` and ${hits.cookies.count - LIST_MAX} more` : ""}. Without Secure the session cookie also goes out over plain HTTP, where anyone on the network can read it and take over the session; without HttpOnly any script on the page, an XSS payload included, can read it.`,
      remediation: "Set `secure: true` (or `secure: process.env.NODE_ENV === \"production\"`, and `app.set(\"trust proxy\", 1)` behind a proxy for express-session), keep `httpOnly: true` and set `sameSite: \"lax\"`. For next-auth and better-auth, remove `useSecureCookies: false`.",
      line: lineAt(list[0].index),
      templateId: SESSION_COOKIE_RULE,
      category: "cookie",
      cwe: "CWE-614",
    });
  }
  if (hits.oauth) {
    out.push({
      ...base,
      severity: "medium",
      confidence: "potential",
      title: `OAuth callback exchanges the code without checking state: ${rel}`,
      description: `\`${rel}\` reads \`code\` from the URL and exchanges it for tokens (line ${lineAt(hits.oauth.index)}), but never reads a \`state\` value, a PKCE \`code_verifier\` or a \`nonce\`. An attacker can send a victim a callback link with the attacker's own code and log the victim into the attacker's account (login CSRF), or link the attacker's identity to the victim's account.`,
      remediation: "Before redirecting to the provider, store a random `state` in an HttpOnly cookie; in the callback compare the `state` from the URL with the cookie and stop when they differ. Use PKCE (`code_verifier`) as well, or let an auth library (Auth.js, arctic with its state helpers, openid-client) run the flow.",
      line: lineAt(hits.oauth.index),
      templateId: OAUTH_STATE_RULE,
      category: "auth",
      cwe: "CWE-352",
    });
  }
  return out;
}

/**
 * Findings for a repository, at most one per rule and file.
 * @param {string} repoPath
 * @param {{ refused?: object[], ignoredDirs?: Set<string> }} [opts] files that could not be read, or
 *   not checked to the end, go to `refused` (the scan is then incomplete); `ignoredDirs` are not entered
 */
export function scanSessionAuth(repoPath, { refused = [], ignoredDirs = null } = {}) {
  const root = resolve(repoPath);
  const skipDirs = ignoredDirs ? new Set([...ignoredDirs].map((d) => resolve(d))) : null;
  const { files, truncated } = walkFiles(root, { wants: (name) => CODE_FILE.test(name), skip: SKIP, ignoredDirs: skipDirs });
  if (truncated) refused.push({ path: join(root, "(repository)"), reason: `it has more than ${WALK_MAX_FILES} files, so the session and login checks stopped reading` });
  const findings = [];
  for (const full of files) {
    const rel = relative(root, full).split(sep).join("/");
    let source;
    try {
      source = readRepoFile(full, { root, label: rel, maxBytes: SESSION_AUTH_MAX_BYTES });
    } catch (e) {
      if (isRefused(e)) { refused.push(e); continue; }
      if (e.code === "ENOENT") continue; // gone since the walk
      refused.push({ path: full, reason: `it could not be read (${e.code || e.message})` });
      continue;
    }
    const middleware = MIDDLEWARE_FILE.test(basename(full)) ? (sawNext, code) => isNextMiddleware(full, code, sawNext) : null;
    const { hits, incomplete, lineAt } = sessionAuthHits(source, { middleware });
    // What was found before the budget ran out is kept; the file is named as not fully checked.
    if (incomplete) refused.push({ path: full, reason: `the session and login checks read ${WORK_FACTOR} times its size and stopped`, partial: true });
    for (const f of findingsFor(rel, hits, lineAt)) findings.push(f);
  }
  return findings;
}
