/**
 * One reader for "does this code check who is calling?", shared by the Server
 * Action check, the session-auth check, the webhook check and the route
 * records (Mythos D, 12 Nov 2026: four copies disagreed, and each loose copy
 * silenced findings).
 *
 * A call counts as an auth check when it is:
 *   - a known auth function by exact name, called on its own (`auth()`,
 *     `getServerSession(...)`, `requireUser()`), or Supabase's verifying
 *     `auth.getUser()` / `auth.getClaims()`, Auth.js `.auth()`, `jwt.verify(`;
 *   - or a name of the shape <strong prefix><marker>: require, verify, assert,
 *     ensure, check, validate, authorize, authenticate, then Auth, Session,
 *     User, Admin, Permission, Owner, Member, Role, Login, Account, Tenant or
 *     Workspace (`requireOrgMember`, `verifyAdminSession`);
 *   - or get/is/with followed by Session, Current or Auth(enticated|orized)
 *     (`getCurrentUser`, `getSessionUser`, `withAuth`, `isAuthenticated`).
 *
 * isX also counts with a role word: `isWorkspaceMember(id)`, `isOwner(u)`.
 *
 * Not a check (Mythos A2): `getUserById(id)`, `getAccountSettings(id)`,
 * `isLoginEnabled()`, `db.getUserCount()`, `getUserLocale(req)`,
 * `isLoginPage(p)`, `getAuthorName()`. Supabase's `auth.getSession()` reads
 * the cookie without asking the auth server, so it is never a check.
 *
 * Linear: one identifier pass, each called name classified with bounded
 * string checks (Vercel DoS 01M6YHCR21FSCGD1SSF0WVKJ8H).
 */

export const AUTH_NAMES = new Set("auth|getServerSession|getSession|getUser|getCurrentUser|currentUser|getCurrentSession|verifySession|validateSession|validateRequest|requireUser|requireAuth|requireSession|requireAdmin|getToken|getAuth|protect|authorize|authenticate|isAuthenticated|isAuthorized|checkAuth|assertAuth|assertSession|ensureAuth|ensureUser|verifyToken|verifyJwt|verifyIdToken|getUserId|getAuthUser|getSessionUser|withAuth|withSession|withUser|safeAction|authAction|authedAction|authenticatedAction|protectedAction|actionClient|authActionClient|createSafeActionClient|getKindeServerSession|getLoginUrl|getServerAuthSession|jwtVerify|jwtDecrypt|unsealData|clerkMiddleware|authMiddleware|withMiddlewareAuthRequired".split("|"));

// Exact names that are a check only with no arguments or a request/options
// argument: `getUser()` is the signed-in user, `getUser(id)` is a lookup.
const MEMBER_NAMES = new Set(["getSession", "getUser", "getClaims", "verifyIdToken", "getCurrentUser", "currentUser", "validateSession", "validateRequest"]);
const LOOKUP_NAMES = new Set(["getUser", "getUserId", "currentUser", "getCurrentUser", "getSessionUser", "getAuthUser", "ensureUser", "withUser"]);
// The argument is exactly the request, its cookies or headers, or auth options: `getUser(req)`,
// `getSession({ req })`; not a property of it (`getUser(req.body.id)`, `getUser(ctx.userId)`).
const REQUEST_ARG = /^\s*(?:\)|(?:req|request|ctx|context|event|headers|cookies|cookieStore|options|opts|config|authOptions|authConfig)\s*[,)]|\{\s*(?:req|request|headers|cookies)\b[^}]{0,60}\}\s*[,)]|(?:await\s+)?(?:headers|cookies)\s*\(\s*\)\s*[,)])/;

const STRONG_PREFIX = /^(?:require|verify|assert|ensure|check|validate|authorize|authenticate)/;
const WEAK_PREFIX = /^(?:get|is|with)/;
const MARKER = /Auth|Session|User|Admin|Permission|Owner|Member|Role|Login|Account|Tenant|Workspace/;
// After get/is/with: a session, the current caller, or an auth word (not "Author").
// After get/is/with: a session, the current or signed-in caller, an auth word (not "Author"),
// or a user-from-request helper (`getUserFromRequest`, `getLoggedInUser`, `getUserRole`).
const WEAK_MARKER = /Session|Current(?:User|Session|Viewer|Member|Account)|Auth(?:$|[A-Z_]|enticat|oriz)|(?:LoggedIn|SignedIn|Server|Authed|Authenticated|Request)User|User(?:From[A-Z]\w*|OrRedirect|OrThrow|Roles?|Permissions?)$|^(?:Permissions?|Roles?|UserRoles?)$/;
const IS_ROLE = /Admin|Owner|Member|Role|Permission|Authorized/;
const WITH_ROLE = /^(?:Role|Roles|Permission|Permissions|User|Admin)$/;

const CALLED_NAME = /(?<![\w$])([A-Za-z_$][\w$]*)\s*\(/g;
export const DOT_AUTH = /\.auth\s*\(\s*\)|\.auth\.(?:getUser|getClaims|api\.getUser)\s*\(|(?<![\w$.])jwt\.verify\s*\(/;

/**
 * Is the call whose name starts at `i` a member of an object named `auth`:
 * `supabase.auth.getSession(`, `supabase?.auth?.getSession(`, `auth.getSession(`?
 * Reads back over whitespace (comments are blanked) once per call, so a walk stays linear.
 */
export function onAuthMember(text, i) {
  let k = i - 1;
  while (k >= 0 && /\s/.test(text[k])) k--;
  if (text[k] !== ".") return false;
  k--;
  if (text[k] === "?") k--;
  while (k >= 0 && /\s/.test(text[k])) k--;
  // `auth!.`, `(supabase.auth).`, `supabase['auth'].`: one closing bracket, one quote, one `!`.
  if (text[k] === ")" || text[k] === "]") k--;
  if (text[k] === "'" || text[k] === '"' || text[k] === "`") k--;
  if (text[k] === "!") k--;
  if (k < 3 || text.slice(k - 3, k + 1) !== "auth") return false;
  return k < 4 || !/[\w$]/.test(text[k - 4]);
}

/** Is a name of the auth shape (the part after the last `$`, as a `\b` read it)? */
export function authShaped(name) {
  const tail = name.slice(name.lastIndexOf("$") + 1);
  const s = STRONG_PREFIX.exec(tail);
  if (s) return MARKER.test(tail.slice(s[0].length));
  const w = WEAK_PREFIX.exec(tail);
  if (!w) return false;
  const rest = tail.slice(w[0].length);
  // `isWorkspaceMember`, `isOwner`, `isAdmin`: an "is" question about the caller's role.
  return WEAK_MARKER.test(rest) || (w[0] === "is" && IS_ROLE.test(rest)) || (w[0] === "with" && WITH_ROLE.test(rest));
}

/**
 * Is the call named `name` at `at` in `text` an auth check? `open` is the
 * index just after its "(" (for the lookup-name argument test).
 */
export function isAuthCall(text, name, at, open) {
  const member = memberAt(text, at);
  // Supabase's unverified cookie read is no check, by name or by shape.
  if (name === "getSession" && onAuthMember(text, at)) return false;
  if (AUTH_NAMES.has(name)) {
    const lookupOk = !LOOKUP_NAMES.has(name) || REQUEST_ARG.test(text.slice(open, open + 80));
    // On an object only these count, with the same argument test: `ctx.getUser()`,
    // `sessionStore.getSession()`. Not `csrf.getToken()`, `messaging.getToken()`,
    // `turnstile.verifyToken(id)` or `obj.auth(id)` (an empty `.auth()` is DOT_AUTH).
    if (!member) return lookupOk;
    if (MEMBER_NAMES.has(name)) return lookupOk;
    return false;
  }
  if (!authShaped(name)) return false;
  // A shaped get/is name on a data object (`db.getUserCount()`) is a query, not a check.
  return !(member && WEAK_PREFIX.test(name) && !/Session|Current/.test(name));
}

function memberAt(text, at) {
  let k = at - 1;
  while (k >= 0 && /\s/.test(text[k])) k--;
  return text[k] === ".";
}

/** Does `text` (masked code) call an auth function? */
export function callsAuth(text) {
  if (DOT_AUTH.test(text)) return true;
  for (const m of text.matchAll(CALLED_NAME)) {
    if (isAuthCall(text, m[1], m.index, m.index + m[0].length)) return true;
  }
  return false;
}

// ── Route records (attack surface, framework routes) ─────────────────────────
// Read on lexed code, so `requireAuth` in a comment or an `isAdmin` field is no
// check (Mythos B6), and with the same reader as the findings, so Clerk's or
// Auth.js's `auth()`, Lucia's `validateRequest()` and a bare `getUser()` count.
const ADMIN_CALL = /(?<![\w$.])(?:verifyAdmin|isAdmin|requireAdmin|adminAuth|assertAdmin|ensureAdmin|checkAdmin)\s*\(/;
const USER_CALL_EXTRA = /(?<![\w$.])(?:verifyUser|verifyIdToken|getAdminAuth)\s*\(|(?<![\w$])jwt\s*\.\s*verify\s*\(/;

/** { admin, user } for one route file's source: does it call an admin check, a user check? */
export function routeAuth(source, lex) {
  let code;
  try { ({ code } = lex(source)); } catch { code = source; }
  const admin = ADMIN_CALL.test(code);
  const user = admin || USER_CALL_EXTRA.test(code) || callsAuth(code);
  return { admin, user };
}

// Calls that read or enforce a user session: the webhook check's "this is a user route".
// Main's exact list, not every auth name: `createSafeActionClient()` and `getLoginUrl()` read
// no session (Vercel 01M81DE1ZQ25A0CTBBY691821B).
const SESSION_CALLS = new Set("auth|getServerSession|getSession|getUser|currentUser|getCurrentUser|requireUser|requireAuth|requireSession|getAuth|withAuth|validateRequest|verifySession|getKindeServerSession|getServerAuthSession".split("|"));

/** An exact session call, not on an object, with the lookup argument test: the webhook check's "this is a user route". */
export function isSessionCall(text, name, at, open) {
  if (!SESSION_CALLS.has(name) || memberAt(text, at)) return false;
  if (name === "getSession" && onAuthMember(text, at)) return false;
  return !LOOKUP_NAMES.has(name) || REQUEST_ARG.test(text.slice(open, open + 80));
}
