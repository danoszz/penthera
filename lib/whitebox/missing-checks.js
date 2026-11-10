/**
 * Missing checks: five places where vibe-coded server code skips the one
 * standard check that makes it safe.
 *
 *   webhook-signature-missing         a webhook handler that writes data, sends
 *                                     mail or calls a payment API, and never
 *                                     verifies the provider's signature
 *   jwt-decode-unverified             a token from the request read with
 *                                     jwt.decode / decodeJwt / jwtDecode in a
 *                                     file that never verifies one
 *   secret-compare-not-constant-time  a secret, an API key or an HMAC compared
 *                                     with === or !== instead of
 *                                     crypto.timingSafeEqual
 *   reset-token-no-expiry             a password-reset token looked up and the
 *                                     password changed, with no expiry check
 *   client-trusted-value              a payment amount, or a role, plan or
 *                                     credit balance, taken from the request
 *                                     body into Stripe or the user record
 *                                     (CWE-472, mass assignment)
 *
 * Each rule reads lexed source (lib/whitebox/js-lex.js: comments blanked,
 * strings masked in `code`, template expressions kept in `expr`), so a name in
 * a comment or a string is not a call. Each looks for the check, not for the
 * bug: wherever a file holds anything that could be the check (a verify call,
 * a webhook secret, an expiry word, an admin check), the rule stays quiet.
 * Precision first; the gaps are in docs/commands/scan.md.
 *
 * Work is bounded. A file is read whole under a 4 MiB cap (larger: named, the
 * scan is incomplete). Every regex here is linear (no nested or overlapping
 * quantifiers); operand and initializer reads stop at fixed windows; bracket
 * pairs come from one stack pass. All per-match work is charged to one budget
 * of 16 times the file's length: past it the file is named as not fully
 * checked (exit 2), keeping the findings already made. Nothing runs.
 */
import { join, relative, resolve, sep } from "node:path";
import { readRepoFile, isRefused } from "../fs-safe.js";
import { lexJs } from "./js-lex.js";
import { walkFiles, lineIndex, CODE_FILE, COMMON_SKIP, WALK_MAX_FILES } from "./walk.js";

export const WEBHOOK_RULE = "webhook-signature-missing";
export const JWT_DECODE_RULE = "jwt-decode-unverified";
export const TIMING_RULE = "secret-compare-not-constant-time";
export const RESET_EXPIRY_RULE = "reset-token-no-expiry";
export const CLIENT_VALUE_RULE = "client-trusted-value";
/** Rule id -> the category its references come from (explain_finding reads this). */
export const MISSING_CHECK_RULES = {
  [WEBHOOK_RULE]: "auth-bypass",
  [JWT_DECODE_RULE]: "auth-bypass",
  [TIMING_RULE]: "timing",
  [RESET_EXPIRY_RULE]: "auth",
  [CLIENT_VALUE_RULE]: "auth",
};

export const MISSING_CHECK_MAX_BYTES = 4 * 1024 * 1024;
export const MISSING_CHECK_BUDGET_FACTOR = 16;
// An operand of a comparison is read at most this many steps from the
// operator (a bracket pair is one step), and its text at most this long.
const OPERAND_STEPS = 128;
const OPERAND_TEXT = 600;
// An initializer, a property value or a string is read at most this far.
const INIT_MAX = 300;
// A call's argument list is read at most this far; past it, the first part.
const ARGS_MAX = 8192;
const LIST_MAX = 8;
const SKIP = new Set([...COMMON_SKIP, "test", "tests", "__tests__", "spec", "e2e", "cypress", "fixtures", "__mocks__", "public", "static"]);
const TEST_FILE = /\.(?:test|spec)\.[cm]?[jt]sx?$|\.d\.[cm]?ts$/;

// ── shared reading helpers ────────────────────────────────────────────────

const isId = (c) => (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95 || c === 36 || c > 127;
const isSp = (c) => c === 32 || c === 10 || c === 13 || c === 9 || c === 11 || c === 12 || c === 0xa0 || c === 0xfeff || c === 0x2028 || c === 0x2029;

/** Both directions of every bracket pair in masked text, from one stack pass. */
function pairArrays(text) {
  const close = new Int32Array(text.length).fill(-1);
  const open = new Int32Array(text.length).fill(-1);
  const stack = [];
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c === 40 || c === 91 || c === 123) stack.push(i);
    else if ((c === 41 || c === 93 || c === 125) && stack.length) { const o = stack.pop(); close[o] = i; open[i] = o; }
  }
  return { close, open };
}

/** A per-file work budget; spend() is false once it is used up. */
function makeBudget(n) {
  let left = MISSING_CHECK_BUDGET_FACTOR * n + (1 << 20);
  return { spend(k = 1) { left -= k; return left >= 0; }, get over() { return left < 0; } };
}

/** camelCase, snake_case and kebab-case words of a name, lowercased, digits dropped. */
function words(name) {
  return String(name).slice(0, 200).replace(/([a-z0-9])([A-Z])/g, "$1 $2").toLowerCase().split(/[^a-z]+/).filter(Boolean);
}

/** Index of the first non-space character at or after `i`. */
function skipSpace(text, i, limit = text.length) {
  while (i < limit && isSp(text.charCodeAt(i))) i++;
  return i;
}

/**
 * Called names in masked code, one pass: [{ name, at, member }]. `member` is
 * true for `x.name(` (and `x?.name(`). Each identifier is tried once from its
 * start (the lookbehind), so the scan is linear.
 */
function calledNames(code, budget) {
  const out = [];
  for (const m of code.matchAll(/(?<![\w$])([A-Za-z_$][\w$]*)\s*\(/g)) {
    if (!budget.spend(m[0].length)) break;
    let k = m.index - 1;
    while (k >= 0 && isSp(code.charCodeAt(k))) k--;
    out.push({ name: m[1], at: m.index, member: code[k] === "." });
  }
  return out;
}

// A database write, a mail send or a payment call, on masked code (the shapes
// of lib/whitebox/server-actions.js, plus line breaks around the dots of a
// chain: a receiver at the start of a member chain, calls allowed in it; each
// iteration is anchored at a ".", so the chain cannot backtrack across itself).
const WRITE_SINKS = [
  /(?<![\w$.])(?:this\.)?(?:prisma|db|database|tx|trx|client|drizzle|kysely|knex|sequelize|supabase|supabaseAdmin|admin|firestore|collection|repo|repository|orm|em|store|pool|conn|sql)\w*(?:\s*\.\s*\w+(?:\([^()]*\))?)*\s*\.\s*(?:create|createMany|insert|insertInto|insertMany|insertOne|update|updateMany|updateOne|upsert|delete|deleteFrom|deleteMany|deleteOne|destroy|remove|save|findOneAndUpdate|findByIdAndUpdate|bulkWrite|increment|decrement|set|add)\s*\(/,
  /(?<![\w$.])(?:setDoc|updateDoc|deleteDoc|addDoc|writeBatch|runTransaction)\s*\(/,
  /(?<![\w$.])(?:[A-Z]\w*)\.(?:create|insertMany|updateOne|updateMany|findOneAndUpdate|findByIdAndUpdate|deleteOne|deleteMany)\s*\(/,
  /(?<![\w$.])(?:this\.)?(?:emails?|mailer|transporter|transport|resend|sendgrid|postmark|ses|mailgun)\w*(?:\.\w+)*\.(?:send|sendMail|sendEmail)\s*\(|(?<![\w$.])send(?:Mail|Email)\s*\(/,
  /(?<![\w$.])(?:this\.)?stripe\w*(?:\s*\.\s*\w+)*\s*\.\s*(?:create|update|cancel|capture|confirm|refund|del)\s*\(/,
];
const RAW_SQL_WRITE = /\b(?:INSERT\s+INTO|UPDATE\s+[\w."`]+\s+SET|DELETE\s+FROM)\b/i;
/** Index of the first write in `code` (or `plain` for raw SQL) between from and to, or -1. */
function firstWrite(code, plain, from, to) {
  const body = code.slice(from, to);
  let best = -1;
  for (const re of WRITE_SINKS) {
    const m = re.exec(body);
    if (m && (best === -1 || m.index < best)) best = m.index;
  }
  const s = RAW_SQL_WRITE.exec(plain.slice(from, to));
  if (s && (best === -1 || s.index < best)) best = s.index;
  return best === -1 ? -1 : from + best;
}

// Calls that check who is calling by a user session: a webhook from a
// provider never carries one, so a file with one is a user-facing route.
const SESSION_CALLS = new Set("auth|getServerSession|getSession|getUser|currentUser|getCurrentUser|requireUser|requireAuth|requireSession|getAuth|withAuth|validateRequest|verifySession|getKindeServerSession|getServerAuthSession".split("|"));

// ── 1. webhook handlers without a signature check ─────────────────────────

const STRIPE_EVENTS = /["'`](?:checkout\.session\.(?:completed|async_payment_succeeded|expired)|payment_intent\.(?:succeeded|payment_failed)|invoice\.(?:paid|payment_succeeded|payment_failed)|customer\.subscription\.(?:created|updated|deleted))["'`]/;
const PROVIDER_IMPORT = /\bfrom\s*["'](?:stripe|svix|@clerk\/[\w/-]*|@octokit\/webhooks|@lemonsqueezy\/[\w/-]*|@paddle\/[\w/-]*|razorpay|@polar-sh\/[\w/-]*|twilio|@slack\/[\w/-]*|resend|@shopify\/[\w/-]*|standardwebhooks)["']|\brequire\s*\(\s*["'](?:stripe|svix|razorpay|twilio)["']\s*\)|\bnew\s+Stripe\s*\(/;
const EVENT_READ = /\b(?:event|evt|payload|body|data|json|webhook|hook|msg|message|notification|req\.body|request\.body)\s*\??\.\s*(?:type|event_type|eventType|event_name|eventName|event|topic|action|object|meta)\b/;
const REQUEST_READ = /\breq(?:uest)?\s*\.\s*(?:body|json|text|formData|arrayBuffer|rawBody|blob)\b|\bevent\s*\.\s*body\b|\bc\s*\.\s*req\s*\.\s*(?:json|text|raw|parseBody|arrayBuffer)\b|\bctx\s*\.\s*request\s*\.\s*(?:body|rawBody)\b|\b(?:buffer|getRawBody|rawBody|readBody|readRawBody)\s*\(\s*(?:req|request|event)\b/;
// Anything in the file that can be the signature check: a verify or validate
// call, Stripe's constructEvent, an HMAC, a constant-time compare, a provider
// helper, or a re-fetch of the event from the provider.
const VERIFY_CALL = /verif|constructevent|createhmac|timingsafeequal|validatesignature|validatewebhook|validateevent|validaterequest|issignaturevalid|checksignature|unmarshal|unwrap/;
// A webhook or signing secret by name: passed to a verifier, so the check is somewhere.
const SIGNING_SECRET = /(?:webhook|signing|signature|endpoint|hmac)_?(?:secret|key|token)|CRON_SECRET/i;
// A registered Express/Hono/Fastify route whose path names a webhook.
const ROUTE_CALL = /\.(?:post|all|put|route|use)\s*\(\s*(["'`])/g;

function webhookHits(ctx) {
  const { rel, code, plain, calls, pairs, budget } = ctx;
  // Spans to read for writes: the registered webhook routes' argument lists,
  // or the whole file for a file whose path or content says it is a webhook.
  const spans = [];
  let wholeFile = false;
  for (const m of code.matchAll(ROUTE_CALL)) {
    const q = m.index + m[0].length - 1;
    let e = q + 1;
    while (e < code.length && e - q < INIT_MAX && code[e] !== m[1] && code[e] !== "\n") e++;
    if (!budget.spend(e - q + 8)) return [];
    if (code[e] !== m[1] || !/webhook|\/hooks?\b/i.test(plain.slice(q + 1, e))) continue;
    const open = code.indexOf("(", m.index);
    const close = pairs.close[open];
    const end = close === -1 ? code.length : close;
    // A handler passed by name lives elsewhere in the file: read the whole file, once.
    const head = Math.min(end, e + ARGS_MAX);
    if (!budget.spend(head - e)) return [];
    if (/=>|\bfunction\b/.test(code.slice(e, head))) spans.push([m.index, end]);
    else wholeFile = true;
  }
  if (wholeFile) spans.splice(0, spans.length, [0, code.length]);
  const pathSays = /webhook/i.test(rel);
  const stripeEvents = STRIPE_EVENTS.test(plain);
  if (!spans.length && !pathSays && !stripeEvents) return [];
  if (!REQUEST_READ.test(code)) return [];
  const provider = PROVIDER_IMPORT.test(plain) || stripeEvents;
  if (!provider && !EVENT_READ.test(code)) return [];
  // The check, anywhere in the file.
  for (const c of calls) {
    const lower = c.name.toLowerCase();
    if (VERIFY_CALL.test(lower)) return [];
    if (c.member && (c.name === "webhook" || c.name === "verify" || c.name === "validate")) return [];
    if (c.member && c.name === "retrieve" && /events\s*\.\s*$/.test(code.slice(Math.max(0, c.at - 16), c.at))) return [];
    if (!c.member && SESSION_CALLS.has(c.name)) return []; // a user-facing route, not a provider's webhook
  }
  if (SIGNING_SECRET.test(plain)) return [];
  if (!spans.length) spans.push([0, code.length]);
  const hits = [];
  for (const [from, to] of spans) {
    if (!budget.spend(to - from)) break;
    const at = firstWrite(code, plain, from, to);
    if (at === -1) continue;
    const read = REQUEST_READ.exec(code.slice(from, to));
    hits.push({ at, read: read ? from + read.index : at });
    break; // one per file
  }
  if (!hits.length) return [];
  const readsSignature = /signature|svix-|x-hub-|hmac/i.test(plain);
  return [{ ...hits[0], provider, readsSignature }];
}

// ── 2. jwt.decode where jwt.verify belongs ────────────────────────────────

const DECODE_FN = new Set(["jwtDecode", "jwt_decode", "decodeJwt", "decodeJWT"]);
const JWT_RECEIVERS = new Set(["jwt", "jsonwebtoken", "JWT", "Jwt", "jose", "jwtLib", "jsonWebToken"]);

/** The identifier before the `.` of a member call at `at` (`jwt` in `jwt /* c *\/ .decode(`), or "". Reads at most 256 characters back. */
function receiverName(code, at) {
  let k = at - 1;
  const stop = Math.max(0, at - 256);
  while (k >= stop && isSp(code.charCodeAt(k))) k--;
  if (code[k] !== ".") return "";
  k--;
  if (code[k] === "?") k--;
  while (k >= stop && isSp(code.charCodeAt(k))) k--;
  const end = k + 1;
  while (k >= stop && isId(code.charCodeAt(k))) k--;
  return code.slice(k + 1, end);
}
// A verification anywhere in the file: the decode may be the `kid` lookup before it.
const VERIFIED_BY = /verif|^getToken$|^getServerSession$|^getClaims$|^getUser$|^validate(?:Token|Jwt|JWT)|^check(?:Token|Jwt|JWT)|^createRemoteJWKSet$|^jwtVerify$/;
// The token comes from the request: an Authorization header, a cookie, a query token.
const REQUEST_TOKEN = /authorization|\bbearer\b|\bcookies?\b|getCookie|x-access-token|x-auth-token|searchParams\s*\.\s*get\s*\(\s*["'](?:token|jwt|access_token)["']|\breq(?:uest)?\s*\.\s*query\s*\.\s*(?:token|jwt)\b/i;

function jwtHits(ctx) {
  const { code, plain, calls, pairs, budget } = ctx;
  const decodes = [];
  for (const c of calls) {
    if (VERIFIED_BY.test(c.name)) return [];
    let isDecode = false;
    if (!c.member && DECODE_FN.has(c.name)) isDecode = true;
    else if (c.member && (c.name === "decode" || c.name === "decodeJwt")) isDecode = JWT_RECEIVERS.has(receiverName(code, c.at));
    if (!isDecode) continue;
    // jwt-simple's decode(token, secret) and next-auth's decode({ token, secret }) verify:
    // a second argument that is not an options object, or a `secret` key, is a check.
    const open = code.indexOf("(", c.at);
    const close = pairs.close[open];
    if (close !== -1) {
      if (!budget.spend(Math.min(close - open, ARGS_MAX))) break;
      const args = code.slice(open + 1, Math.min(close, open + ARGS_MAX));
      if (/\bsecret\b/i.test(args)) continue;
      const comma = topLevelComma(code, pairs, open + 1, Math.min(close, open + ARGS_MAX));
      if (comma !== -1 && code[skipSpace(code, comma + 1)] !== "{" && skipSpace(code, comma + 1) < close) continue;
    }
    decodes.push(c.at);
  }
  if (!decodes.length || !REQUEST_TOKEN.test(plain)) return [];
  return decodes.map((at) => ({ at }));
}

/** Index of the first comma at depth 0 between from and to, jumping bracket pairs, or -1. */
function topLevelComma(code, pairs, from, to) {
  for (let i = from; i < to; i++) {
    const c = code.charCodeAt(i);
    if (c === 44) return i;
    if ((c === 40 || c === 91 || c === 123) && pairs.close[i] !== -1) i = pairs.close[i];
  }
  return -1;
}

// ── declarations ──────────────────────────────────────────────────────────

// A line break ends a statement unless the line before ends, or the next
// begins, with something that continues an expression.
const CONTINUES_AFTER = new Set([..."=+-*/%&|^!?:,.([{<>~"]);
const CONTINUES_BEFORE = new Set([..."=+-*/%&|^?:,.)]}>"]);

/**
 * End of the initializer starting at `from`: a `;`, a `,` or a closing bracket
 * at its depth, or a line break that ends the statement. One forward pass of
 * at most INIT_MAX characters (a bracket pair is one step): the last solid
 * character is carried, so a line break looks neither back nor ahead twice.
 */
function statementEnd(text, pairs, from) {
  let i = from;
  let lastSolid = -1;
  const stop = Math.min(text.length, from + INIT_MAX);
  while (i < stop) {
    const c = text[i];
    if (c === "\n" || c === "\r") {
      const n = skipSpace(text, i, stop);
      if (lastSolid !== -1 && !CONTINUES_AFTER.has(text[lastSolid]) && !CONTINUES_BEFORE.has(text[n])) return i;
      i = n;
      continue;
    }
    if (isSp(text.charCodeAt(i))) { i++; continue; }
    if (c === ";" || c === "," || c === ")" || c === "]" || c === "}") return i;
    if ((c === "(" || c === "[" || c === "{") && pairs.close[i] !== -1) { lastSolid = pairs.close[i]; i = lastSolid + 1; continue; }
    lastSolid = i++;
  }
  return i;
}

/**
 * Every `const|let|var` declaration with an initializer, in one pass:
 * { name } for `const x = …`, { bound, rest } for a destructuring pattern,
 * and `init`, the initializer's plain text (strings kept, at most INIT_MAX).
 * `view` "code" gives the initializer with strings masked instead.
 */
function* declarations(ctx, view = "plain") {
  const { code, pairs, budget } = ctx;
  const text = view === "code" ? code : ctx.plain;
  for (const m of code.matchAll(/\b(?:const|let|var)\s+(?=[{[A-Za-z_$])/g)) {
    if (!budget.spend(16)) return;
    let k = m.index + m[0].length;
    let name = null;
    const bound = [];
    const rest = [];
    if (code[k] === "{" || code[k] === "[") {
      const close = pairs.close[k];
      if (close === -1) continue;
      if (!budget.spend(Math.min(close - k, ARGS_MAX))) return;
      // Destructured names: `{ amount, plan: chosen, ...rest }`, `[a, b]`.
      for (const part of code.slice(k + 1, Math.min(close, k + ARGS_MAX)).split(",")) {
        const t = part.trim();
        const r = /^\.\.\.\s*([A-Za-z_$][\w$]*)/.exec(t);
        if (r) { rest.push(r[1]); continue; }
        const kv = /^([A-Za-z_$][\w$]*)\s*(?::\s*([A-Za-z_$][\w$]*))?/.exec(t);
        if (kv) bound.push(kv[2] || kv[1]);
      }
      k = close + 1;
    } else {
      let e = k;
      while (e < code.length && e - k < 200 && isId(code.charCodeAt(e))) e++;
      if (e === k) continue;
      name = code.slice(k, e);
      k = e;
    }
    k = skipSpace(code, k);
    if (code[k] === "!") k = skipSpace(code, k + 1);
    if (code[k] === ":") { // a TypeScript annotation, kept short
      let j = k + 1;
      while (j < code.length && j - k < 120 && code[j] !== "=" && code[j] !== ";" && code[j] !== "\n") j++;
      k = j;
    }
    if (code[k] !== "=" || code[k + 1] === "=" || code[k + 1] === ">") continue;
    const end = Math.min(statementEnd(code, pairs, k + 1), k + 1 + INIT_MAX);
    if (!budget.spend(2 * (end - k))) return;
    yield { name, bound, rest, init: text.slice(k + 1, end) };
  }
}

// ── 3. secrets compared with === ──────────────────────────────────────────

// In an env name or a constant: the value is a secret.
const SECRET_UPPER = /SECRET|TOKEN|API_?KEY|APIKEY|PASSWORD|PASSPHRASE|SIGNATURE|SIGNING|HMAC|PRIVATE_KEY|ACCESS_KEY|ADMIN_KEY|MASTER_KEY|AUTH_KEY/;
const ENV_NAME = /\benv\s*(?:\.\s*|\[\s*["'`]|\.\s*get\s*\(\s*["'`]|\(\s*["'`])([A-Za-z_][\w]*)/g;
const UPPER_NAME = /(?<![\w$])[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+(?![\w$])|(?<![\w$.])(?:SECRET|APIKEY|TOKEN)(?![\w$])/g;
const IDENT = /[A-Za-z_$][\w$]*/g;
const TOKEN_PREFIX = new Set("auth access bearer csrf xsrf reset verification verify invite magic session refresh api provided expected stored received incoming request header secret cron webhook signup confirm confirmation email otp admin".split(" "));
const KEY_PREFIX = new Set("api secret signing webhook admin master access auth cron".split(" "));
const NAMED_LAST = new Set(["secret", "signature", "sig", "hmac", "otp", "apikey", "authorization"]);
// The last word of an operand that is not the secret itself: a length, a type, a flag.
const BORING_LAST = new Set("length size type kind status name version alg algorithm method mode prefix scheme format encoding count index id ids enabled exists valid".split(" "));
const BORING_FIRST = new Set(["is", "has", "should", "can", "use", "typeof"]);

/** Read an operand leftwards from `end`: [start, end] in expr, or null when there is none. */
function operandLeft(expr, pairs, end) {
  let k = end;
  while (k >= 0 && isSp(expr.charCodeAt(k))) k--;
  const last = k;
  if (k < 0) return null;
  const ch = expr[k];
  if (ch === "`") {
    let s = k - 1;
    while (s >= 0 && last - s < OPERAND_TEXT && expr[s] !== "`") s--;
    return s >= 0 && expr[s] === "`" ? { start: s, end: last, template: true, steps: end - s } : null;
  }
  if (ch === '"' || ch === "'") return { start: k, end: last, literal: true };
  for (let steps = 0; k >= 0 && steps < OPERAND_STEPS; steps++) {
    const c = expr.charCodeAt(k);
    if (isId(c)) { k--; continue; }
    if (c === 46) { k--; if (expr[k] === "?") k--; while (k >= 0 && isSp(expr.charCodeAt(k))) k--; continue; }
    if ((c === 41 || c === 93) && pairs.open[k] !== -1) { k = pairs.open[k] - 1; continue; }
    if (c === 33 && k === last) { k--; continue; } // TypeScript's non-null `x!`
    break;
  }
  if (k === last) return null;
  return { start: k + 1, end: last, steps: end - k };
}

/** Read an operand rightwards from `from`: [start, end] in expr, or null. */
function operandRight(expr, pairs, from) {
  let k = skipSpace(expr, from);
  if (expr.startsWith("await", k) && !isId(expr.charCodeAt(k + 5))) k = skipSpace(expr, k + 5);
  if (expr.startsWith("typeof", k) && !isId(expr.charCodeAt(k + 6))) return { start: k, end: k + 5, literal: true };
  const start = k;
  const ch = expr[k];
  if (ch === undefined) return null;
  if (ch === "`") {
    let e = k + 1;
    while (e < expr.length && e - k < OPERAND_TEXT && expr[e] !== "`") e++;
    return expr[e] === "`" ? { start, end: e, template: true, steps: e - from } : null;
  }
  if (ch === '"' || ch === "'") return { start, end: k, literal: true };
  for (let steps = 0; k < expr.length && steps < OPERAND_STEPS; steps++) {
    const c = expr.charCodeAt(k);
    if (isId(c)) { k++; continue; }
    if (c === 46 || (c === 63 && expr[k + 1] === ".")) { k += c === 63 ? 2 : 1; k = skipSpace(expr, k); continue; }
    if ((c === 40 || c === 91) && pairs.close[k] !== -1) { k = pairs.close[k] + 1; continue; }
    if (c === 33 && expr[k + 1] === ".") { k++; continue; }
    // A chain that continues on the next line: `foo\n  .bar`.
    if (isSp(c)) { const n = skipSpace(expr, k); if (expr[n] === "." && expr[n + 1] !== ".") { k = n; continue; } }
    break;
  }
  if (k === start) return null;
  return { start, end: k - 1, steps: k - from };
}

/** Bounded text of an operand: whole up to OPERAND_TEXT, else its two ends. */
function operandText(text, op) {
  const len = op.end + 1 - op.start;
  if (len <= OPERAND_TEXT) return text.slice(op.start, op.end + 1);
  const h = OPERAND_TEXT / 2;
  return `${text.slice(op.start, op.start + h)} … ${text.slice(op.end + 1 - h, op.end + 1)}`;
}

/** The operand's final name: the last identifier, or the string inside a final `[...]` or `.get(...)`. */
function finalName(exprText, plainText) {
  let t = exprText.trimEnd();
  let p = plainText.slice(0, t.length);
  if (t.endsWith(")") || t.endsWith("]")) {
    const closeCh = t[t.length - 1];
    const openCh = closeCh === ")" ? "(" : "[";
    const o = t.lastIndexOf(openCh);
    const inner = o === -1 ? "" : p.slice(o + 1, -1).trim();
    const str = /^["'`]([^"'`]{1,120})["'`]$/.exec(inner);
    if (str && (closeCh === "]" || /\.\s*get\s*$/.test(t.slice(0, o)))) return str[1];
    if (o !== -1) t = t.slice(0, o);
  }
  // The identifier at the end, read backwards (at most 200 characters).
  let s = t.length;
  while (s > 0 && t.length - s < 200 && isId(t.charCodeAt(s - 1))) s--;
  return t.slice(s);
}

function classifyOperand(ctx, op) {
  if (op.literal) return { literal: true };
  const e = operandText(ctx.expr, op);
  const p = operandText(ctx.plain, op);
  const trimmed = e.trim();
  if (/^(?:null|undefined|true|false|NaN|Infinity|void\s+0|-?\d[\w.]*)$/.test(trimmed)) return { literal: true };
  if (/\btypeof\s*$/.test(ctx.expr.slice(Math.max(0, op.start - 8), op.start))) return { literal: true };
  let strong = false;
  let hmac = /createHmac\b/.test(e);
  for (const m of p.matchAll(ENV_NAME)) if (SECRET_UPPER.test(m[1].toUpperCase())) strong = true;
  for (const m of e.matchAll(UPPER_NAME)) if (SECRET_UPPER.test(m[0])) strong = true;
  let request = REQUEST_VALUE.test(p);
  for (const m of e.matchAll(IDENT)) {
    if (ctx.hmacNames.has(m[0])) { hmac = true; strong = true; }
    else if (ctx.strongNames.has(m[0])) strong = true;
    else if (ctx.requestNames.has(m[0])) request = true;
  }
  if (hmac) strong = true;
  if (op.template) return { strong, hmac, request, named: false };
  const name = finalName(e, p);
  const w = words(name);
  const lastW = w[w.length - 1] || "";
  if (BORING_LAST.has(lastW) || BORING_FIRST.has(w[0]) || /\.\s*(?:length|size)\s*$/.test(trimmed)) return { boring: true };
  const prev = w[w.length - 2] || "";
  const named = NAMED_LAST.has(lastW) || (lastW === "token" && TOKEN_PREFIX.has(prev)) || (lastW === "key" && KEY_PREFIX.has(prev));
  return { strong, hmac, request, named, sig: lastW === "signature" || lastW === "sig" || lastW === "hmac" };
}

// A value read from the request: a header, the query, the body, a cookie.
const REQUEST_VALUE = /\b(?:headers|query|body|params|cookies|searchParams|formData)\b|\bget(?:Header|Cookie)\s*\(|\.\s*header\s*\(/;

/**
 * Names assigned from an env secret (strong), an HMAC (hmac) or a request
 * value (request), one pass over the file's declarations.
 */
function secretNames(ctx) {
  const strong = new Set();
  const hmac = new Set();
  const request = new Set();
  for (const d of declarations(ctx)) {
    const init = d.init;
    // Names under 3 characters are reused all over minified code: not tracked.
    const add = (set) => { for (const n of d.name ? [d.name] : d.bound) if (n.length >= 3) set.add(n); };
    if (/createHmac\b|\.\s*hmac\s*\(|\bhmac(?:Sha256|SHA256)?\s*\(/.test(init)) { add(hmac); continue; }
    let s = false;
    for (const e of init.matchAll(ENV_NAME)) if (SECRET_UPPER.test(e[1].toUpperCase())) s = true;
    if (s) add(strong);
    else if (REQUEST_VALUE.test(init)) add(request);
  }
  return { strong, hmac, request };
}

function timingHits(ctx) {
  const { expr, pairs, budget } = ctx;
  const { strong, hmac, request } = secretNames(ctx);
  const c2 = { ...ctx, strongNames: strong, hmacNames: hmac, requestNames: request };
  const hits = [];
  for (const m of expr.matchAll(/[!=]==?/g)) {
    const before = expr[m.index - 1];
    if (before === "=" || before === "!" || before === "<" || before === ">") continue;
    // Charged what it reads: the walk (each step at most a bracket jump) and
    // the operand text the classifier reads (capped at OPERAND_TEXT).
    if (!budget.spend(2 * OPERAND_STEPS)) break;
    const left = operandLeft(expr, pairs, m.index - 1);
    const right = operandRight(expr, pairs, m.index + m[0].length);
    if (!left || !right) continue;
    const span = (o) => Math.min(o.end + 1 - o.start, OPERAND_TEXT);
    if (!budget.spend(4 * (span(left) + span(right)))) break;
    const a = classifyOperand(c2, left);
    if (a.literal || a.boring) continue;
    const b = classifyOperand(c2, right);
    if (b.literal || b.boring) continue;
    // An HMAC checks something from outside, whatever the other side is called.
    // Otherwise one side comes from the request and the other is a secret: a
    // cache key, a config diff or a UI state named "signature" is not a check.
    const hmacSide = a.hmac || b.hmac;
    if (!hmacSide && !((a.request && (b.strong || b.named)) || (b.request && (a.strong || a.named)))) continue;
    hits.push({ at: m.index, op: m[0], severity: hmacSide || a.sig || b.sig ? "medium" : "low" });
  }
  return hits;
}

// ── 4. password-reset tokens with no expiry check ─────────────────────────

const RESET_TOKEN = /(?:password_?)?(?:reset|recovery)_?(?:password_?)?token|forgot_?password_?token/i;
const PASSWORD_WRITE = /\b(?:password|passwordHash|password_hash|hashedPassword|hashed_password|encryptedPassword|encrypted_password|passwordDigest|password_digest)\s*:|\.\s*(?:password|passwordHash|hashedPassword)\s*=(?!=)|\b(?:updatePassword|setPassword|changePassword)\s*\(|\.\s*auth\s*\.\s*(?:admin\s*\.\s*)?updateUser(?:ById)?\s*\(/;
// Anything that can be an expiry check: an expiry field or word, a time
// comparison, a date filter in a query, or a signed token (verify checks exp).
const EXPIRY = /expir|\bttl\b|valid_?until|\bexp\b|max_?age|isAfter|isBefore|isPast|isFuture|differenceIn|\$gte?\b|\$lte?\b|\b[gl]te?\s*:|\bnow\s*\(\s*\)|CURRENT_TIMESTAMP|\binterval\b|verify|getTime\s*\(\s*\)\s*[<>]|[<>]=?\s*(?:Date\.now|new\s+Date|now\b)|(?:Date\.now\s*\(\s*\)|new\s+Date\s*\(\s*\))\s*[<>-]/i;
// A token kept in a key-value store expires by its TTL there.
const KV_STORE = /\b(?:redis|kv|upstash|ioredis|memcached|keyv)\b/i;

function resetHits(ctx) {
  const { code, plain } = ctx;
  const m = RESET_TOKEN.exec(plain);
  if (!m) return [];
  if (!PASSWORD_WRITE.test(code) || EXPIRY.test(plain) || KV_STORE.test(plain)) return [];
  return [{ at: m.index }];
}

// ── 5. price, amount, plan or role taken from the client ──────────────────

// The request body, a form, or a query: what the client chose.
const CLIENT_SOURCE = /\b(?:req|request|ctx\s*\.\s*request|c\s*\.\s*req|event)\s*\.\s*(?:body|query)\b|\b(?:req|request|c\s*\.\s*req)\s*\.\s*(?:json|formData|parseBody)\s*\(\s*\)|\bformData\s*\.\s*get\s*\(|\bObject\s*\.\s*fromEntries\s*\(\s*(?:await\s+)?(?:formData|form)\b|\b(?:readBody|readValidatedBody|getQuery)\s*\(/;
const PAY_RECEIVER = /stripe|paymentintents|checkout|razorpay|mollie|paypal|lemon|paddle|invoiceitems|charges|braintree|square/i;
const PAY_KEYS = /(?<![\w$.])(amount|unit_amount|unit_amount_decimal|amount_cents|amount_total)\s*:\s*/g;
const PRIV_KEYS = /(?<![\w$.])(role|roles|isAdmin|is_admin|admin|isSuperuser|is_superuser|plan|tier|credits|balance|isPro|is_pro|isPremium|is_premium|subscriptionStatus|subscription_status|permissions|emailVerified|email_verified)\s*:\s*/g;
const SHORTHAND_PAY = /[{,]\s*(amount|unit_amount|amount_cents)(?=\s*[,}])/g;
const SHORTHAND_PRIV = /[{,]\s*(role|roles|isAdmin|is_admin|plan|tier|credits|balance|isPro|isPremium|permissions|emailVerified)(?=\s*[,}])/g;
const WRITE_METHOD = /\.\s*(create|createMany|update|updateMany|updateOne|upsert|insert|insertOne|insertMany|values|set|findByIdAndUpdate|findOneAndUpdate)\s*\(/g;
const WRITE_METHOD_ANY = new RegExp(WRITE_METHOD.source);
const DB_RECEIVER = /prisma|\bdb\b|database|\btx\b|supabase|knex|drizzle|kysely|sequelize|mongoose|collection|firestore|repo|repository|\bmodel\b|^[A-Z]|\.\s*[A-Z]\w*\s*$|\.from\(/;
const USER_TARGET = /user|account|profile|member|customer|subscri|\borg\b|organi[sz]ation|team|tenant|workspace/i;
// A model class for a user record (`new User(body)`), not a service or a client.
const USER_MODEL = /^(?:User|Users|Account|Profile|Member|Customer|Tenant|Team|Org|Organization|Workspace|Subscription)(?:Model|Doc|Document|Entity|Schema)?$/;
// An admin route may set roles and plans: a check by name, a role comparison, or an admin path.
// The named check (`requireAdmin(`, `user.hasRole(`) is read from the called
// names, one bounded name at a time (adminCheck below), never by a regex with
// two unbounded word spans: those backtrack quadratically on a long name.
const ROLE_COMPARE = /\.\s*role\s*[!=]==?|[!=]==?\s*[\w$.]*\.\s*role\b|\bisAdmin\b\s*(?:\)|&&|\|\||\?)/;
const CHECK_PREFIXES = ["require", "assert", "ensure", "check", "is", "verify", "has", "can"];
const ADMIN_MARKERS = ["Admin", "Role", "Permission", "Owner", "Staff", "Superuser"];

/**
 * True when the word run of a called name holds a check prefix with an admin
 * marker after it (`requireAdmin`, `hasRole`, `canEditAsOwner`): the
 * earliest prefix end is at or before the last marker start. Case-sensitive,
 * linear in the name.
 */
function namesAdminCheck(name) {
  const run = name.slice(name.lastIndexOf("$") + 1);
  let firstEnd = Infinity;
  for (const p of CHECK_PREFIXES) {
    const i = run.indexOf(p);
    if (i !== -1) firstEnd = Math.min(firstEnd, i + p.length);
  }
  if (firstEnd === Infinity) return false;
  return ADMIN_MARKERS.some((m) => run.lastIndexOf(m) >= firstEnd);
}

/** An admin check in the file: a check called by name, or a role comparison. */
function adminCheck(ctx) {
  const { code, budget } = ctx;
  const calls = ctx.calls.length ? ctx.calls : calledNames(code, budget);
  for (const c of calls) {
    if (!budget.spend(c.name.length)) return false;
    if (namesAdminCheck(c.name)) return true;
  }
  // ROLE_COMPARE is linear: each repetition is bounded by a "." or an "=".
  if (!budget.spend(code.length)) return false;
  return ROLE_COMPARE.test(code);
}
// Amounts the payer picks on purpose: donations, tips, top-ups.
const PAYER_CHOOSES = /donat|\btips?\b|tip_?amount|tipAmount|pay[-_ ]?what|custom[-_ ]?amount|top[-_ ]?up|topup|deposit|wallet/i;

const VALIDATES = /\.\s*(?:parse|safeParse|parseAsync|safeParseAsync|validate|validateSync|validateAsync|cast)\s*\(|\breadValidatedBody\s*\(|\bvalidator\s*\(/;

/** Names that hold the client's input: whole objects (body) and fields destructured from it. */
function clientNames(ctx) {
  const whole = new Set();
  const validated = new Set();
  const fields = new Set();
  const isSource = (init) => {
    if (CLIENT_SOURCE.test(init)) return true;
    const t = init.replace(/^\s*(?:await\s+)?/, "");
    // body, body.data, Schema.parse(body), JSON.parse(body), schema.safeParse(body).data
    const id = /^(?:[\w$.]+\s*\.\s*(?:parse|safeParse|parseAsync|validate|cast)\s*\(\s*(?:await\s+)?([A-Za-z_$][\w$]*)|([A-Za-z_$][\w$]*)(?:\s*\.\s*(?:data|body|fields|values))?\s*(?:[;,)\n]|$))/.exec(t);
    const name = id && (id[1] || id[2]);
    return !!name && (whole.has(name) || validated.has(name));
  };
  for (const d of declarations(ctx, "code")) {
    if (!isSource(d.init)) continue;
    // A schema parse keeps only the keys it names: still the client's values,
    // but no longer any column the client likes.
    const checked = VALIDATES.test(d.init);
    if (d.name) (checked ? validated : whole).add(d.name);
    for (const n of d.bound) fields.add(n);
    for (const n of d.rest) (checked ? validated : whole).add(n);
  }
  return { whole, validated, fields };
}

/** Does a value expression carry the client's input? */
function fromClient(value, names) {
  if (CLIENT_SOURCE.test(value)) return true;
  for (const m of value.matchAll(/(?<![\w$.])([A-Za-z_$][\w$]*)/g)) {
    if (names.fields.has(m[1]) || names.whole.has(m[1]) || names.validated.has(m[1])) return true;
  }
  return false;
}

/** The value after `key:` at `from` up to the next top-level `,` or `}`, bounded. */
function valueAt(code, pairs, from, limit) {
  let i = from;
  const stop = Math.min(limit, from + INIT_MAX);
  for (; i < stop; i++) {
    const c = code.charCodeAt(i);
    if (c === 44 || c === 125 || c === 41 || c === 93 || c === 59) break;
    if ((c === 40 || c === 91 || c === 123) && pairs.close[i] !== -1) i = Math.min(pairs.close[i], stop);
  }
  return code.slice(from, i);
}

function clientValueHits(ctx) {
  const { rel, code, plain, expr, pairs, budget } = ctx;
  const names = clientNames(ctx);
  const anySource = CLIENT_SOURCE.test(code);
  if (!anySource && !names.whole.size && !names.validated.size && !names.fields.size) return [];
  const admin = /(?:^|\/)admin(?:\/|$)|(?:^|\/)\(admin\)/i.test(rel) || adminCheck(ctx);
  const payerChooses = PAYER_CHOOSES.test(plain) || PAYER_CHOOSES.test(rel);
  // An unclosed call (a file that ends mid-statement) is read to the end, never dropped.
  const closeOf = (open) => (pairs.close[open] === -1 ? code.length : pairs.close[open]);
  const hits = [];
  for (const m of code.matchAll(WRITE_METHOD)) {
    if (!budget.spend(OPERAND_STEPS)) break;
    const open = m.index + m[0].length - 1;
    const recv = operandLeft(expr, pairs, m.index - 1);
    if (!recv) continue;
    const recvText = operandText(plain, recv);
    const argsEnd = Math.min(closeOf(open), open + ARGS_MAX);
    if (!budget.spend(argsEnd - open)) break;
    const payment = PAY_RECEIVER.test(recvText) && !/refund/i.test(recvText) && (m[1] === "create" || (m[1] === "update" && /paymentIntents|checkout/i.test(recvText)));
    if (payment) {
      if (admin || payerChooses) continue;
      const hit = keyFromClient(code, pairs, open + 1, argsEnd, PAY_KEYS, SHORTHAND_PAY, names, budget);
      if (hit) hits.push({ at: hit.at, kind: "amount", key: hit.key, severity: "high", confidence: "likely" });
      continue;
    }
    if (!DB_RECEIVER.test(recvText) || !USER_TARGET.test(recvText) || admin) continue;
    const hit = keyFromClient(code, pairs, open + 1, argsEnd, PRIV_KEYS, SHORTHAND_PRIV, names, budget);
    if (hit) { hits.push({ at: hit.at, kind: "privilege", key: hit.key, severity: "high", confidence: "potential" }); continue; }
    // Mass assignment: the whole body as the data, an argument, or spread into it.
    const mass = massAssigned(code, pairs, open + 1, argsEnd, names, budget);
    if (mass !== -1) hits.push({ at: mass, kind: "mass", key: null, severity: "medium", confidence: "potential" });
  }
  if (!admin) {
    // `new User(req.body)`, `Object.assign(user, req.body)`.
    for (const m of code.matchAll(/\bnew\s+([A-Z][\w$]*)\s*\(|\bObject\s*\.\s*assign\s*\(\s*([A-Za-z_$][\w$.]*)\s*,/g)) {
      if (!budget.spend(OPERAND_STEPS)) break;
      const target = m[1] || m[2];
      if (m[1] ? !USER_MODEL.test(target) : !USER_TARGET.test(target)) continue;
      const open = code.indexOf("(", m.index);
      const argsEnd = Math.min(closeOf(open), open + ARGS_MAX);
      const at = massAssigned(code, pairs, m[2] ? m.index + m[0].length : open + 1, argsEnd, names, budget);
      if (at !== -1) hits.push({ at, kind: "mass", key: null, severity: "medium", confidence: "potential" });
    }
  }
  return hits;
}

/** Ranges [open, close] of `metadata: { … }` objects in code[from, to): what goes there is a label, not a price. */
function metadataRanges(code, pairs, from, to) {
  const out = [];
  for (const m of code.slice(from, to).matchAll(/(?<![\w$.])metadata\s*:\s*\{/g)) {
    const open = from + m.index + m[0].length - 1;
    // Found in order, so a range inside the last one kept is covered already:
    // the kept ranges are disjoint and sorted.
    if (out.length && open < out[out.length - 1][1]) continue;
    out.push([open, pairs.close[open] === -1 ? to : pairs.close[open]]);
  }
  return out;
}

/** A test for "inside a metadata range" for positions asked in increasing order (one moving pointer). */
function insideRanges(ranges) {
  let r = 0;
  return (at) => {
    while (r < ranges.length && ranges[r][1] < at) r++;
    return r < ranges.length && at > ranges[r][0] && at < ranges[r][1];
  };
}

/**
 * The first `key: <client value>` or `{ key }` shorthand of a client field in
 * the argument list code[from, to): { at, key }, or null. Values are read on
 * the file's code with its bracket pairs, so a nested object or call is one step.
 */
function keyFromClient(code, pairs, from, to, keyRe, shortRe, names, budget) {
  const args = code.slice(from, to);
  const meta = metadataRanges(code, pairs, from, to);
  let inMeta = insideRanges(meta);
  for (const k of args.matchAll(keyRe)) {
    if (!budget.spend(INIT_MAX)) return null;
    const at = from + k.index;
    if (inMeta(at)) continue;
    const value = valueAt(code, pairs, at + k[0].length, to);
    if (fromClient(value, names)) return { at, key: k[1] };
  }
  inMeta = insideRanges(meta);
  for (const k of args.matchAll(shortRe)) {
    const at = from + k.index + k[0].length - k[1].length;
    if ((names.fields.has(k[1]) || names.whole.has(k[1]) || names.validated.has(k[1])) && !inMeta(at)) return { at, key: k[1] };
  }
  return null;
}

/** Is this expression the client's whole object: `req.body`, `await req.json()`, or a name holding it? */
function isWholeClient(text, names) {
  let t = text.trim();
  if (t.startsWith("(") && t.endsWith(")")) t = t.slice(1, -1).trim();
  t = t.replace(/^await\s+/, "");
  if (/^(?:req|request|ctx\s*\.\s*request|c\s*\.\s*req)\s*\.\s*(?:body|json\s*\(\s*\)|parseBody\s*\(\s*\))$/.test(t)) return true;
  if (/^Object\s*\.\s*fromEntries\s*\(\s*(?:await\s+)?(?:formData|form)\b/.test(t)) return true;
  const id = /^([A-Za-z_$][\w$]*)(?:\s*\.\s*(?:body|data))?$/.exec(t);
  return !!id && names.whole.has(id[1]);
}

/**
 * Where in code[from, to) the client's whole object is written: as a `data:`
 * value, as a top-level argument, or spread into an object. Index, or -1.
 */
function massAssigned(code, pairs, from, to, names, budget) {
  const pieces = [];
  // Top-level arguments, and the top-level keys of an object argument, by one walk.
  let start = from;
  for (let i = from; i <= to; i++) {
    const c = code[i];
    if (i === to || c === ",") { pieces.push([start, i]); start = i + 1; continue; }
    if ((c === "(" || c === "[" || c === "{") && pairs.close[i] !== -1) i = Math.min(pairs.close[i], to - 1);
  }
  for (const [s, e] of pieces) {
    if (!budget.spend(Math.min(e - s, INIT_MAX))) return -1;
    if (isWholeClient(code.slice(s, Math.min(e, s + INIT_MAX)), names)) return skipSpace(code, s);
  }
  const args = code.slice(from, to);
  const data = /(?<![\w$.])data\s*:\s*/.exec(args);
  if (data) {
    const v = valueAt(code, pairs, from + data.index + data[0].length, to);
    if (isWholeClient(v, names)) return from + data.index;
  }
  for (const sp of args.matchAll(/\.\.\.\s*/g)) {
    if (!budget.spend(INIT_MAX)) return -1;
    const at = from + sp.index + sp[0].length;
    if (isWholeClient(valueAt(code, pairs, at, to), names)) return from + sp.index;
  }
  return -1;
}

// ── the scan ──────────────────────────────────────────────────────────────

/**
 * Hits of all five rules in one file's source.
 * @returns {{ hits: Record<string, object[]>, incomplete: boolean, lineAt: (i: number) => number }}
 */
export function missingCheckHits(source, rel = "") {
  const empty = { hits: {}, incomplete: false, lineAt: () => 1 };
  const wants = {
    // Each test is a superset of what its rule needs (checklist row 18): the raw
    // text holds everything the lexed copies do.
    webhook: /webhook/i.test(rel) || /webhook|\/hooks?\b|checkout\.session\.|payment_intent\.|customer\.subscription\.|invoice\.pa/i.test(source),
    jwt: /decode/i.test(source) && /jwt|jose|jsonwebtoken/i.test(source),
    timing: /[!=]==?/.test(source) && /secret|sig|hmac|key|token|otp|authorization|pass/i.test(source),
    reset: /reset|recover|forgot/i.test(source) && /token/i.test(source),
    client: CLIENT_SOURCE.test(source) && (WRITE_METHOD_ANY.test(source) || /\bObject\s*\.\s*assign\s*\(|\bnew\s+[A-Z]/.test(source)),
  };
  if (!Object.values(wants).some(Boolean)) return empty;
  const budget = makeBudget(source.length);
  const { code, plain, expr } = lexJs(source);
  // Browser code holds no webhook, token check or database write of its own.
  const first = skipSpace(code, 0);
  if (/^["']use client["']/.test(plain.slice(first, first + 12))) return empty;
  const pairs = pairArrays(expr);
  const ctx = { rel, code, plain, expr, pairs, budget, calls: wants.webhook || wants.jwt ? calledNames(code, budget) : [] };
  const hits = {};
  const run = (key, rule, fn) => { if (wants[key] && !budget.over) { const h = fn(ctx); if (h.length) hits[rule] = h; } };
  run("webhook", WEBHOOK_RULE, webhookHits);
  run("jwt", JWT_DECODE_RULE, jwtHits);
  run("timing", TIMING_RULE, timingHits);
  run("reset", RESET_EXPIRY_RULE, resetHits);
  run("client", CLIENT_VALUE_RULE, clientValueHits);
  return { hits, incomplete: budget.over, lineAt: lineIndex(code) };
}

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function lines(list, lineAt) {
  const ls = [...new Set(list.map((h) => lineAt(h.at)))];
  return `line${ls.length === 1 ? "" : "s"} ${ls.slice(0, LIST_MAX).join(", ")}${ls.length > LIST_MAX ? ` and ${ls.length - LIST_MAX} more` : ""}`;
}

/** One finding per rule per file, at the worst hit (count caps keep the worst: checklist row 13). */
function toFinding(rule, list, rel, lineAt) {
  const sorted = [...list].sort((a, b) => (SEV_RANK[a.severity || "high"] - SEV_RANK[b.severity || "high"]) || a.at - b.at);
  const worst = sorted[0];
  const line = lineAt(worst.at);
  const base = { url: rel, file: rel, line, templateId: rule, category: MISSING_CHECK_RULES[rule], source: "static-analysis" };
  if (rule === WEBHOOK_RULE) {
    const readLine = lineAt(worst.read);
    return {
      ...base,
      severity: "high",
      confidence: worst.readsSignature ? "potential" : "likely",
      title: `Webhook handler acts without verifying the signature in ${rel}`,
      description: `\`${rel}\` takes a webhook's body (line ${readLine}) and writes data, sends mail or calls a payment API (line ${line}), but nothing in the file verifies the provider's signature: no \`stripe.webhooks.constructEvent\`, no HMAC of the raw body, no verify call and no webhook secret. Anyone who finds the URL can post a fake event, such as a paid checkout.${worst.readsSignature ? " The file reads a signature header, so the check may sit in a helper this rule does not follow." : ""}`,
      remediation: "Verify before you act: for Stripe, `const event = stripe.webhooks.constructEvent(rawBody, req.headers[\"stripe-signature\"], process.env.STRIPE_WEBHOOK_SECRET)` on the raw body (`await req.text()` in a route handler, `express.raw()` in Express). For other providers, use their SDK's verify call (svix, @octokit/webhooks, Clerk's verifyWebhook) or compare an HMAC of the raw body with `crypto.timingSafeEqual`. Reject the request when the check fails.",
      line,
    };
  }
  if (rule === JWT_DECODE_RULE) {
    return {
      ...base,
      severity: "high",
      confidence: "likely",
      title: `JWT decoded without verifying it in ${rel}`,
      description: `\`${rel}\` reads a token from the request and decodes it with \`jwt.decode\`, \`decodeJwt\` or \`jwtDecode\` (${lines(sorted, lineAt)}), and nothing in the file verifies a token. Decoding only reads the payload: anyone can write a token that says \`"role": "admin"\` or any user id, and it decodes the same.`,
      remediation: "Verify the signature and expiry before you trust a claim: `jwt.verify(token, secret, { algorithms: [\"HS256\"] })` with jsonwebtoken, or `await jwtVerify(token, key)` with jose. Keep decode for reading a header (such as `kid`) before the verify.",
    };
  }
  if (rule === TIMING_RULE) {
    const sev = worst.severity;
    return {
      ...base,
      severity: sev,
      confidence: "likely",
      title: `Secret compared with ${worst.op} instead of a constant-time compare in ${rel}`,
      description: `\`${rel}\` compares a secret, an API key or a signature with \`===\` or \`!==\` (${lines(sorted, lineAt)}). A string compare stops at the first different character, so the time it takes tells an attacker how much of a guess was right, one character at a time.${sev === "medium" ? " One side is an HMAC or a signature, which is what a webhook or a signed link relies on." : ""}`,
      remediation: "Compare with `crypto.timingSafeEqual` on equal-length buffers: `const a = Buffer.from(given), b = Buffer.from(expected); if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return unauthorized()`. Hashing both sides first (`createHash(\"sha256\")`) gives equal lengths.",
    };
  }
  if (rule === RESET_EXPIRY_RULE) {
    return {
      ...base,
      severity: "medium",
      confidence: "potential",
      title: `Password-reset token used with no expiry check in ${rel}`,
      description: `\`${rel}\` looks up a password-reset token (line ${line}) and changes the password, but nothing in the file checks when the token expires: no expiry field, no date filter in the query, no time comparison. A reset link that never expires works for whoever finds it in an old email, a log or a browser history.`,
      remediation: "Store an expiry with the token (for example 30 to 60 minutes) and check it in the lookup: `where: { token, expiresAt: { gt: new Date() } }` in Prisma, `{ resetToken, resetExpires: { $gt: Date.now() } }` in Mongoose. Delete the token once it is used.",
    };
  }
  const amounts = sorted.filter((h) => h.kind === "amount");
  const privs = sorted.filter((h) => h.kind === "privilege");
  const parts = [];
  if (amounts.length) parts.push(`a payment amount (\`${amounts[0].key}\`, ${lines(amounts, lineAt)}) goes to the payment API as the client sent it`);
  if (privs.length) parts.push(`\`${privs[0].key}\` is written to the user record from the request (${lines(privs, lineAt)})`);
  const mass = sorted.filter((h) => h.kind === "mass");
  if (mass.length) parts.push(`the request body is written to a user record whole (${lines(mass, lineAt)}), so the client can set any column, such as a role or a plan`);
  return {
    ...base,
    severity: worst.severity,
    confidence: worst.confidence,
    title: amounts.length ? `Payment amount taken from the client in ${rel}` : `Role, plan or account fields taken from the client in ${rel}`,
    description: `In \`${rel}\`, ${parts.join("; and ")}. The client chooses this value, so anyone can pay one cent or make themselves an admin by changing the request.`,
    remediation: amounts.length
      ? "Look the price up on the server: pass a Stripe Price id from your own catalogue (`line_items: [{ price: PRICES[plan], quantity: 1 }]`), or compute the amount from the product record, never from the request body."
      : "Pick the fields you write (`data: { name: body.name }`), never the whole body, and set roles, plans and credits only from server-side state: an admin check, or a payment webhook that verified its signature.",
  };
}

/**
 * Findings for a repository: one per rule per file.
 * @param {string} repoPath
 * @param {{ refused?: object[], ignoredDirs?: Set<string> }} [opts] - files that could not be read, or not
 *   read to the end, go to `refused`; `ignoredDirs` (absolute, from gitIgnored) are not entered
 */
export function scanMissingChecks(repoPath, { refused = [], ignoredDirs = null } = {}) {
  const root = resolve(repoPath);
  const skipDirs = ignoredDirs ? new Set([...ignoredDirs].map((d) => resolve(d))) : null;
  const { files, truncated } = walkFiles(root, { wants: (name) => CODE_FILE.test(name) && !TEST_FILE.test(name), skip: SKIP, ignoredDirs: skipDirs });
  // Past the file cap the rest is not read: named, and the scan is incomplete.
  if (truncated) refused.push({ path: join(root, "(repository)"), reason: `it has more than ${WALK_MAX_FILES} files, so the missing-check rules stopped reading` });
  const findings = [];
  for (const full of files) {
    const rel = relative(root, full).split(sep).join("/");
    let source;
    try {
      source = readRepoFile(full, { root, label: rel, maxBytes: MISSING_CHECK_MAX_BYTES });
    } catch (e) {
      if (isRefused(e)) { refused.push(e); continue; }
      if (e.code === "ENOENT") continue; // gone since the walk
      // Unreadable (EACCES, EIO, ...): named, and the scan is incomplete, never a crash or a silent pass.
      refused.push({ path: full, reason: `it could not be read (${e.code || e.message})` });
      continue;
    }
    const { hits, incomplete, lineAt } = missingCheckHits(source, rel);
    // Over the work budget: the findings made so far are kept, and the file is named.
    if (incomplete) refused.push({ path: full, reason: `the missing-check rules read ${MISSING_CHECK_BUDGET_FACTOR} times its length and stopped`, partial: true });
    for (const [rule, list] of Object.entries(hits)) findings.push(toFinding(rule, list, rel, lineAt));
  }
  return findings;
}
