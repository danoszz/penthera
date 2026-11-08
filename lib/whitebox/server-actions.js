/**
 * Next.js Server Actions that write data without checking who is calling.
 *
 * Every exported async function in a file that starts with `"use server"`,
 * and every function whose body starts with it, is a public POST endpoint:
 * the client bundle holds its id, and anyone can call it with any arguments,
 * whether or not the page that uses it was ever shown to them. Route
 * discovery reads `route.js/ts` only, so these never appeared as routes, and
 * `deleteProject(id)` with no session check scanned clean.
 *
 * The rule, on lexed source (lib/whitebox/js-lex.js, comments blanked and
 * strings masked, so a name in a comment or a string is not a call):
 *   - an action is an exported function in a file-level `"use server"` file
 *     (`export async function`, `export const x = …`, a function in an
 *     `export { … }` list, `export default`), or any function whose body
 *     begins with `"use server"`;
 *   - it writes when its body calls a database write (Prisma, Drizzle,
 *     Supabase, Mongoose, Kysely, Knex, Firestore, raw INSERT/UPDATE/DELETE),
 *     sends mail or calls a payment API;
 *   - it is checked when its body, or the wrapper it is passed to
 *     (`export const x = authAction(async () => …)`), calls an auth function
 *     by name (auth, getServerSession, getUser, currentUser, verifySession,
 *     requireUser, …, or any name that starts with require/verify/assert/
 *     ensure/check and names auth, a session, a user, an admin or a permission),
 *     or calls anything imported from an auth module (next-auth, @clerk/*,
 *     @supabase/ssr, lucia, @kinde-oss/*, @workos-inc/*, auth0, iron-session,
 *     or a local module whose path names auth or a session).
 * A writing action with no check is reported, one finding per file at
 * `potential` confidence: the check may live in middleware or in a helper this
 * rule does not know. With a root middleware file that itself calls an auth
 * function the finding is medium, since every action is behind it; otherwise
 * high. Nothing runs.
 *
 * Work per file is bounded: every lookup is by index or a Map, receivers are
 * matched only at the start of a member chain, and the bodies read (nested
 * actions read the same text per level) are charged to a budget of 16 times
 * the file's length; past it the file is named and the scan is incomplete.
 */
import { existsSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { readRepoFile, isRefused } from "../fs-safe.js";
import { lexJs } from "./js-lex.js";
import { functionRanges, namedFunctions } from "./library.js";
import { walkFiles, lineIndex, CODE_FILE, COMMON_SKIP, WALK_MAX_FILES } from "./walk.js";

export const SERVER_ACTION_RULE = "server-action-no-auth";
export const SERVER_ACTION_MAX_BYTES = 4 * 1024 * 1024;
const BODY_BUDGET_FACTOR = 16;
const SKIP = new Set([...COMMON_SKIP, "test", "tests", "__tests__", "spec", "e2e", "cypress", "fixtures", "__mocks__", "public", "static"]);

// Side effects an unauthenticated caller must not reach: [label, pattern on masked code].
// A receiver is matched at the start of a member chain only (`this.` allowed), and the
// chain may hold calls: `supabase.from("todos").insert(` (strings are masked, so an
// argument holds no brackets). Raw SQL reads the plain text.
const WRITE_SINKS = [
  ["a database write", /(?<![\w$.])(?:this\.)?(?:prisma|db|database|tx|trx|client|drizzle|kysely|knex|sequelize|supabase|supabaseAdmin|admin|firestore|collection|repo|repository|orm|em|store|pool|conn|sql)\w*(?:\.\w+(?:\([^()]*\))?)*\.(?:create|createMany|createManyAndReturn|insert|insertInto|insertMany|insertOne|update|updateMany|updateOne|upsert|delete|deleteFrom|deleteMany|deleteOne|destroy|remove|save|truncate|findOneAndUpdate|findOneAndDelete|findByIdAndUpdate|findByIdAndDelete|bulkWrite|increment|decrement|set|add)\s*\(/],
  ["a database write", /(?<![\w$.])(?:setDoc|updateDoc|deleteDoc|addDoc|writeBatch|runTransaction)\s*\(/],
  ["a mail send", /(?<![\w$.])(?:this\.)?(?:emails?|mailer|transporter|transport|resend|sendgrid|postmark|ses|mailgun)\w*(?:\.\w+)*\.(?:send|sendMail|sendEmail|sendBatch|send_email)\s*\(|(?<![\w$.])send(?:Mail|Email|Magic\w*|Invite\w*|Otp|OTP)\s*\(/],
  ["a payment call", /(?<![\w$.])(?:this\.)?stripe\w*(?:\.\w+)*\.(?:create|update|cancel|capture|confirm|refund|del)\s*\(|(?<![\w$.])(?:paymentIntents|checkout\.sessions|subscriptions|refunds|transfers|payouts|charges)\.(?:create|update|cancel|capture|confirm)\s*\(/],
];
const RAW_SQL = /\b(?:INSERT\s+INTO|UPDATE\s+[\w."`]+\s+SET|DELETE\s+FROM|TRUNCATE\s+TABLE|DROP\s+TABLE)\b/i;

// A call that checks who is calling, by name.
const AUTH_CALL = /(?<![\w$.])(?:auth|getServerSession|getSession|getUser|getCurrentUser|currentUser|getCurrentSession|verifySession|validateSession|validateRequest|requireUser|requireAuth|requireSession|requireAdmin|getToken|getAuth|protect|authorize|authenticate|isAuthenticated|isAuthorized|checkAuth|assertAuth|assertSession|ensureAuth|ensureUser|verifyToken|verifyJwt|verifyIdToken|getUserId|getAuthUser|getSessionUser|withAuth|withSession|withUser|safeAction|authAction|authedAction|authenticatedAction|protectedAction|actionClient|authActionClient|createSafeActionClient|getKindeServerSession|getLoginUrl|getServerAuthSession)\s*\(|\b(?:require|verify|assert|ensure|check|validate|get|with|is)\w*(?:Auth|Session|User|Admin|Permission|Owner|Member|Role|Login|Account|Tenant|Workspace)\w*\s*\(|\.auth\s*\(\s*\)|\.auth\.(?:getUser|getSession|getClaims|api\.getUser)\s*\(/;
// Modules whose imports are auth: anything called that came from one of these counts as a check.
const AUTH_MODULE = /(?:^|\/)(?:auth|session|sessions|authz|authn|access|permissions?|guard|guards|protect|protected|middleware)(?:\.[cm]?[jt]sx?)?$|next-auth|@auth\/|@clerk\/|@supabase\/(?:ssr|auth-helpers)|lucia|@kinde-oss|@workos-inc|auth0|iron-session|firebase-admin|@logto\/|better-auth|supertokens|@descope|@propelauth|@hanko|@passlock/;
const AUTH_MIDDLEWARE_FILES = ["middleware.ts", "middleware.js", "middleware.mjs", "src/middleware.ts", "src/middleware.js", "src/middleware.mjs", "proxy.ts", "proxy.js", "src/proxy.ts", "src/proxy.js"];
// Every called name in a body, for the Set lookup of imported auth names (linear, no pattern per name).
const CALLED = /(?<![\w$.])([A-Za-z_$][\w$]*)\s*(?:\(|\.\s*[\w$]+\s*\()/g;

/** Index of the first character after whitespace and semicolons from `i`. */
function firstCodeFrom(code, i) {
  while (i < code.length && /[\s;]/.test(code[i])) i++;
  return i;
}

/** Index of the last non-space character before `i`, or -1. */
function lastSolidBefore(code, i) {
  let k = i - 1;
  while (k >= 0 && /\s/.test(code[k])) k--;
  return k;
}

/** Names imported from auth modules: default, named (`as` honoured) and namespace imports; `require` too. */
function authImports(code, plain) {
  const names = new Set();
  const take = (clause) => {
    clause = clause.trim();
    if (!clause) return;
    const ns = /^\*\s+as\s+([\w$]+)/.exec(clause);
    if (ns) { names.add(ns[1]); return; }
    const braces = clause.indexOf("{");
    const head = braces === -1 ? clause : clause.slice(0, braces);
    const def = /^([\w$]+)/.exec(head.replace(/,\s*$/, ""));
    if (def) names.add(def[1]);
    if (braces !== -1) {
      for (const part of clause.slice(braces + 1, clause.indexOf("}", braces)).split(",")) {
        const words = part.trim().split(/\s+/);
        const local = words.length >= 3 && words[1] === "as" ? words[2] : words[0];
        if (/^[\w$]+$/.test(local)) names.add(local);
      }
    }
  };
  for (const m of code.matchAll(/\bimport\s+([^;]*?)\s+from\s*(["'])(\s*)\2/g)) {
    const spec = plain.slice(m.index + m[0].length - m[3].length - 1, m.index + m[0].length - 1);
    if (AUTH_MODULE.test(spec)) take(m[1]);
  }
  for (const m of code.matchAll(/\b(?:const|let|var)\s+(\{[^}]*\}|[\w$]+)\s*=\s*require\s*\(\s*(["'])(\s*)\2\s*\)/g)) {
    const spec = plain.slice(m.index + m[0].length - m[3].length - 2, m.index + m[0].length - 2);
    if (AUTH_MODULE.test(spec)) take(m[1]);
  }
  return names;
}

/** The first function in `sorted` (by start) whose start is at or after `from`, by binary search. */
function firstFrom(sorted, from) {
  let lo = 0, hi = sorted.length - 1, k = -1;
  while (lo <= hi) { const mid = (lo + hi) >> 1; if (sorted[mid].start >= from) { k = mid; hi = mid - 1; } else lo = mid + 1; }
  return k === -1 ? null : sorted[k];
}

/**
 * The actions in one file's source: [{ name, line, bodyStart, bodyEnd, head }].
 * `head` is the masked text between the export statement's start and the
 * function (the wrapper call, if any).
 */
export function serverActions(source) {
  const { code, plain } = lexJs(source);
  const fns = functionRanges(code);
  if (!fns.length) return { actions: [], code, plain, fileLevel: false };
  const byBodyStart = new Map(fns.map((f) => [f.bodyStart, f]));
  const first = firstCodeFrom(code, 0);
  const lineAt = lineIndex(code);
  let fileLevel = false;
  const actions = new Map(); // bodyStart -> action
  const add = (f, name, head = "") => {
    if (!actions.has(f.bodyStart)) actions.set(f.bodyStart, { name: name || f.name || "(anonymous)", line: lineAt(f.start), bodyStart: f.bodyStart, bodyEnd: f.bodyEnd, head });
  };
  for (const m of plain.matchAll(/(["'])use server\1/g)) {
    // In masked code the string is blanked: a directive is a string statement, not a comment or a name.
    if (code[m.index] !== m[1]) continue;
    if (m.index === first) { fileLevel = true; continue; }
    // A function whose body starts with the directive is an action wherever it sits: the
    // text before the directive, back over blank space, is that body's "{".
    const brace = lastSolidBefore(code, m.index);
    const f = brace >= 0 && code[brace] === "{" ? byBodyStart.get(brace) : null;
    if (f) add(f, f.name);
  }
  if (fileLevel) {
    const byStart = [...fns].sort((a, b) => a.start - b.start);
    const fnByStart = new Map(byStart.map((f) => [f.start, f]));
    const named = namedFunctions(code, fns);
    for (const m of code.matchAll(/\bexport\s+(?:default\s+)?(?:async\s+)?(function)\b/g)) {
      const f = fnByStart.get(m.index + m[0].length - m[1].length);
      if (f) add(f, f.name || "default");
    }
    for (const m of code.matchAll(/\bexport\s+(?:const|let|var)\s+([\w$]+)\s*(?::[^=;]{0,300})?=\s*/g)) {
      const from = m.index + m[0].length;
      // The first function after the "=" in this statement; the text before it is the wrapper.
      const f = firstFrom(byStart, from);
      if (f && f.start - from <= 400 && !code.slice(from, f.start).includes(";")) add(f, m[1], code.slice(from, f.start));
    }
    for (const m of code.matchAll(/\bexport\s+default\s+([\w$]+)\s*;/g)) { const f = named.get(m[1]); if (f) add(f, m[1]); }
    for (const m of code.matchAll(/\bexport\s*\{([^}]*)\}/g)) {
      for (const part of m[1].split(",")) {
        const local = part.trim().split(/\s+/)[0];
        const f = named.get(local);
        if (f) add(f, local);
      }
    }
  }
  return { actions: [...actions.values()].sort((a, b) => a.line - b.line), code, plain, fileLevel };
}

/**
 * The unchecked writing actions of one file.
 * @returns {{ hits: { name, line, writes: string[] }[], incomplete: boolean }}
 *   incomplete: the bodies to read went over the budget (deeply nested actions), so the rest was not checked
 */
export function uncheckedActions(source) {
  const { actions, code, plain } = serverActions(source);
  if (!actions.length) return { hits: [], incomplete: false };
  const imported = authImports(code, plain);
  const callsImported = (text) => {
    if (!imported.size) return false;
    for (const m of text.matchAll(CALLED)) if (imported.has(m[1])) return true;
    return false;
  };
  let budget = BODY_BUDGET_FACTOR * code.length + (1 << 20);
  const hits = [];
  for (const a of actions) {
    budget -= a.bodyEnd + 1 - a.bodyStart;
    if (budget < 0) return { hits, incomplete: true };
    const body = code.slice(a.bodyStart, a.bodyEnd + 1);
    const text = plain.slice(a.bodyStart, a.bodyEnd + 1);
    const writes = [...new Set(WRITE_SINKS.filter(([, re]) => re.test(body)).map(([label]) => label))];
    if (RAW_SQL.test(text) && !writes.includes("a database write")) writes.push("a database write");
    if (!writes.length) continue;
    const checked = AUTH_CALL.test(body) || AUTH_CALL.test(a.head) || callsImported(body) || callsImported(a.head);
    if (!checked) hits.push({ name: a.name, line: a.line, writes });
  }
  return { hits, incomplete: false };
}

/** Does a root middleware file call an auth function? Then every action sits behind it. */
function authMiddleware(root) {
  for (const f of AUTH_MIDDLEWARE_FILES) {
    const path = join(root, f);
    if (!existsSync(path)) continue;
    try {
      const { code, plain } = lexJs(readRepoFile(path, { root, label: f, maxBytes: SERVER_ACTION_MAX_BYTES }));
      if (AUTH_CALL.test(code) || authImports(code, plain).size) return f;
    } catch { /* unreadable: no downgrade */ }
  }
  return null;
}

/**
 * Findings for a repository, one per file with unchecked writing actions.
 * @param {string} repoPath
 * @param {{ refused?: object[], ignoredDirs?: Set<string> }} [opts] - files that could not be read, or
 *   not read to the end, go to `refused`; `ignoredDirs` (absolute, from gitIgnored) are not entered
 */
export function scanServerActions(repoPath, { refused = [], ignoredDirs = null } = {}) {
  const root = resolve(repoPath);
  const skipDirs = ignoredDirs ? new Set([...ignoredDirs].map((d) => resolve(d))) : null;
  const { files, truncated } = walkFiles(root, { wants: (name) => CODE_FILE.test(name), skip: SKIP, ignoredDirs: skipDirs });
  // Past the file cap the rest is not read: named, and the scan is incomplete.
  if (truncated) refused.push({ path: join(root, "(repository)"), reason: `it has more than ${WALK_MAX_FILES} files, so the Server Action check stopped reading` });
  const findings = [];
  let middleware;
  for (const full of files) {
    const rel = relative(root, full).split(sep).join("/");
    let source;
    try {
      source = readRepoFile(full, { root, label: rel, maxBytes: SERVER_ACTION_MAX_BYTES });
    } catch (e) {
      if (isRefused(e)) { refused.push(e); continue; }
      if (e.code === "ENOENT") continue;
      throw e;
    }
    if (!source.includes("use server")) continue;
    const { hits, incomplete } = uncheckedActions(source);
    if (incomplete) refused.push({ path: full, reason: `its Server Actions nest so deeply that the check read ${BODY_BUDGET_FACTOR} times the file and stopped` });
    if (!hits.length) continue;
    middleware ??= authMiddleware(root);
    const list = hits.slice(0, 8).map((h) => `\`${h.name}\` (line ${h.line}, ${h.writes.join(", ")})`).join(", ");
    findings.push({
      severity: middleware ? "medium" : "high",
      title: `Server Action writes data without an auth check in ${rel}`,
      description: `${hits.length === 1 ? "One Server Action writes" : `${hits.length} Server Actions write`} data and never check who is calling: ${list}${hits.length > 8 ? ` and ${hits.length - 8} more` : ""}. A Server Action is a public POST endpoint: anyone can call it with any arguments, whether or not they can see the page that uses it.${middleware ? ` \`${middleware}\` calls an auth function, so the check may sit there; confirm its matcher covers every page that uses these actions.` : ""}`,
      remediation: "Check the session at the top of each action (for example `const session = await auth(); if (!session) throw new Error(\"Unauthorized\")`), and check that the caller owns the record it changes. A wrapper such as next-safe-action's authActionClient makes the check hard to forget.",
      url: rel,
      file: rel,
      line: hits[0].line,
      templateId: SERVER_ACTION_RULE,
      actions: hits.map((h) => h.name),
      category: "auth",
      source: "static-analysis",
      confidence: "potential",
    });
  }
  return findings;
}
