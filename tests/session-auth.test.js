/**
 * The five session and login checks (lib/whitebox/session-auth.js): a match
 * and a no-match case per form, refusals and the work budget (incomplete,
 * never silent), linear time on crafted input by the doubling method, and a
 * run through scanRepo. Offline: temp folders only.
 */
import { describe, it, expect, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";
import { scanRepo } from "../src/scan-repo.js";
import { exitCodeOf } from "../src/report/exit.js";
import { sessionAuthHits, scanSessionAuth, credentialKind, SESSION_AUTH_RULES } from "../lib/whitebox/session-auth.js";
import { authImports, uncheckedActions } from "../lib/whitebox/server-actions.js";
import { lexJs } from "../lib/whitebox/js-lex.js";
import { TOOL_BY_NAME } from "../src/mcp/tools.js";
import cookieRecipe from "../lib/fix/recipes/cookies.js";

const temps = [];
afterAll(() => temps.forEach((d) => rmSync(d, { recursive: true, force: true })));
function repo(files) {
  const dir = mkdtempSync(join(tmpdir(), "penthera-session-"));
  temps.push(dir);
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), text);
  }
  return dir;
}
const hits = (src, middleware = false) => sessionAuthHits(src, { middleware: middleware ? () => true : null }).hits;
const urlNames = (src) => hits(src).url.items.map((h) => `${h.name}:${h.kind}`);
const encrypted = (src) => hits(src).encrypted.items.map((h) => `${h.kind}:${h.what}`);
const cookies = (src) => hits(src).cookies.items.map((h) => h.what);
const oauth = (src) => !!hits(src).oauth;
const middleware = (src) => hits(src, true).middleware?.paths ?? null;

describe("credential-in-url", () => {
  it("reads every form of a query read", () => {
    expect(urlNames(`app.get("/x", (req, res) => { const p = req.query.password; const k = req?.query?.apiKey; })`)).toEqual(["password:password", "apiKey:credential"]);
    expect(urlNames(`const p = req.query["password"]`)).toEqual(["password:password"]);
    expect(urlNames(`export async function GET(request) { const u = new URL(request.url); u.searchParams.get("password"); request.nextUrl.searchParams.get('client_secret') }`)).toEqual(["password:password", "client_secret:credential"]);
    expect(urlNames(`app.get("/", (c) => c.req.query("api_key"))`)).toEqual(["api_key:credential"]);
    expect(urlNames(`const { password, user: u, "access_token": at, ...rest } = req.query;`)).toEqual(["password:password", "access_token:credential"]);
    expect(urlNames(`export default async function Page({ searchParams }) {\n  const { newPassword } = await searchParams\n  return null\n}`)).toEqual(["newPassword:password"]);
    expect(urlNames(`export default async function Page({ searchParams }) { return (await searchParams).password }`)).toEqual(["password:password"]);
    expect(urlNames(`export default defineEventHandler((event) => getQuery(event).password)`)).toEqual(["password:password"]);
    expect(urlNames(`const p = useSearchParams().get("password")`)).toEqual(["password:password"]);
  });
  it("leaves out one-time tokens, codes, database queries, comments and strings", () => {
    expect(urlNames(`const t = req.query.token; const c = searchParams.get("code"); const k = req.query.key`)).toEqual([]);
    expect(urlNames(`const r = await db.query.password.findMany(); const { password } = db.query;`)).toEqual([]);
    expect(urlNames(`// req.query.password\nconst s = "req.query.password"; const b = req.body.password;`)).toEqual([]);
    expect(urlNames(`function f({ searchParams }: { searchParams: { password?: string } }) {}`)).toEqual([]);
    expect(urlNames(`const { password } = req.query.filters.length`)).toEqual([]);
  });
  it("names password-like and credential-like keys only", () => {
    expect(["password", "PASSWORD", "new_password", "confirmPassword", "passwd", "pwd", "passphrase"].map(credentialKind)).toEqual(Array(7).fill("password"));
    expect(["apiKey", "api-key", "access_token", "refreshToken", "client_secret", "secret", "jwt", "session_token"].map(credentialKind)).toEqual(Array(8).fill("credential"));
    // session_id: Stripe Checkout's `?session_id={CHECKOUT_SESSION_ID}` return URL (seen in a maker app, 10 Nov).
    expect(["token", "code", "key", "state", "pass", "passwordReset", "id", "session_id", "sessionId"].map(credentialKind)).toEqual(Array(9).fill(null));
  });
});

describe("password-encrypted-not-hashed", () => {
  it("finds a password encrypted with a key", () => {
    expect(encrypted(`import CryptoJS from "crypto-js"; await db.user.create({ data: { email, password: CryptoJS.AES.encrypt(password, KEY).toString() } })`)).toEqual(["encrypt:password"]);
    expect(encrypted(`const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);\nlet e = cipher.update(password, "utf8", "hex")`)).toEqual(["encrypt:password"]);
    expect(encrypted(`const e = crypto.createCipheriv("aes-256-cbc", key, iv).update(user.password)`)).toEqual(["encrypt:user.password"]);
    expect(encrypted(`const stored = encrypt(req.body.password)`)).toEqual(["encrypt:req.body.password"]);
  });
  it("finds a password decrypted to compare at login, even next to bcrypt", () => {
    expect(encrypted(`import bcrypt from "bcrypt"; if (decrypt(user.password) !== req.body.password) throw new Error("bad")`)).toEqual(["compare:user.password"]);
    expect(encrypted(`const plain = CryptoJS.AES.decrypt(user.password, KEY).toString(enc.Utf8);\nif (plain === input) ok()`)).toEqual(["compare:user.password"]);
    expect(encrypted(`const d = crypto.createDecipheriv(a, k, iv); const out = d.update(row.password, "hex", "utf8"); return out === password`)).toEqual(["compare:row.password"]);
  });
  it("leaves out hashing files, other systems' passwords and decryption without a compare", () => {
    expect(encrypted(`import bcrypt from "bcrypt"; const h = await bcrypt.hash(password, 10); const enc = encrypt(password)`)).toEqual([]);
    expect(encrypted(`const enc = encrypt(config.smtp.password); const d = encrypt(integration.password)`)).toEqual([]);
    expect(encrypted(`const smtpPass = decrypt(row.password); transporter.login(smtpPass)`)).toEqual([]);
    expect(encrypted(`const hashed = encryptPassword(password)`)).toEqual([]); // a common name for a bcrypt wrapper
    expect(encrypted(`const h = crypto.createHash("sha256").update(password)`)).toEqual([]);
    expect(encrypted(`// encrypt(password)\nconst s = "decrypt(user.password) === password"`)).toEqual([]);
  });
});

describe("session-cookie-insecure", () => {
  it("finds Secure or HttpOnly turned off in a session library's cookie options", () => {
    expect(cookies(`import { getIronSession } from "iron-session";\nexport const sessionOptions = { password: P, cookieName: "s", cookieOptions: { secure: false, httpOnly: false } }`)).toEqual(["secure: false", "httpOnly: false"]);
    expect(cookies(`import NextAuth from "next-auth";\nexport default NextAuth({ useSecureCookies: false, cookies: { sessionToken: { name: "s", options: { secure: false } } } })`)).toEqual(["useSecureCookies: false", "secure: false"]);
    expect(cookies(`import { Lucia } from "lucia"; new Lucia(adapter, { sessionCookie: { attributes: { secure: false } } })`)).toEqual(["secure: false"]);
    expect(cookies(`import { createCookieSessionStorage } from "@remix-run/node"; createCookieSessionStorage({ cookie: { name: "__s", httpOnly: false } })`)).toEqual(["httpOnly: false"]);
  });
  it("finds express-session without cookie.secure, inline or in a const", () => {
    expect(cookies(`import session from "express-session"; app.use(session({ secret: s, resave: false }))`)).toEqual(["no cookie options (Secure is off by default)"]);
    expect(cookies(`const session = require("express-session"); app.use(session({ secret: s, cookie: { httpOnly: true } }))`)).toEqual(["cookie options without secure (off by default)"]);
    expect(cookies(`import session from "express-session"; const opts = { secret: s, cookie: { secure: false } }; app.use(session(opts))`)).toEqual(["secure: false"]);
  });
  it("leaves out set or unknown flags and other libraries' options", () => {
    expect(cookies(`import session from "express-session"; app.use(session({ secret: s, cookie: { secure: process.env.NODE_ENV === "production" } }))`)).toEqual([]);
    expect(cookies(`import session from "express-session"; const sess = { secret: s, cookie: {} };\nif (prod) { sess.cookie.secure = true }\napp.use(session(sess))`)).toEqual([]);
    expect(cookies(`import session from "express-session"; app.use(session({ ...base })); app.use(session(fromAnotherFile))`)).toEqual([]);
    expect(cookies(`import NextAuth from "next-auth"; const t = nodemailer.createTransport({ host, secure: false, mail: { options: { secure: false } } })`)).toEqual([]);
    expect(cookies(`const t = { cookie: { secure: false } }`)).toEqual([]); // no session library in the file
    expect(cookies(`import { useNavigate } from "react-router"; const o = { cookie: { secure: false } }`)).toEqual([]);
  });
  it("is left out of the cookie-call fix recipe", () => {
    expect(cookieRecipe.matches({ category: "cookie", templateId: "session-cookie-insecure" })).toBe(false);
    expect(cookieRecipe.matches({ category: "cookie", title: 'Cookie "sid" missing Secure' })).toBe(true);
  });
});

describe("oauth-callback-no-state", () => {
  const exchange = `const r = await fetch("https://github.com/login/oauth/access_token", { method: "POST", body: JSON.stringify({ client_id, client_secret, code, grant_type: "authorization_code" }) })`;
  it("finds a code exchange with no state, verifier or nonce", () => {
    expect(oauth(`export async function GET(req) { const code = req.nextUrl.searchParams.get("code"); ${exchange} }`)).toBe(true);
    expect(oauth(`const { code } = req.query; const { tokens } = await oauth2Client.getToken(code)`)).toBe(true);
    expect(oauth(`const code = url.searchParams.get("code"); const tokens = await github.validateAuthorizationCode(code)`)).toBe(true);
  });
  it("leaves out a callback that reads state, uses PKCE or a nonce, or an auth library", () => {
    expect(oauth(`const code = searchParams.get("code"); const s = searchParams.get("state"); ${exchange}`)).toBe(false);
    expect(oauth(`const code = searchParams.get("code"); if (cookies().get("oauth_state")?.value !== expected) throw 1; ${exchange}`)).toBe(false);
    expect(oauth(`const { code } = req.query; await fetch(u, { body: qs({ grant_type: "authorization_code", code, code_verifier: v }) })`)).toBe(false);
    expect(oauth(`import passport from "passport"; const { code } = req.query; ${exchange}`)).toBe(false);
    expect(oauth(`const code = req.body.code; ${exchange}`)).toBe(false); // not from the URL
    expect(oauth(`const code = searchParams.get("code"); await fetch(u, { body: qs({ grant_type: "client_credentials" }) })`)).toBe(false);
  });
});

describe("next-middleware-no-auth", () => {
  it("finds a middleware that names protected paths and checks nothing", () => {
    expect(middleware(`import { NextResponse } from "next/server";\nexport function middleware(req) { return NextResponse.next() }\nexport const config = { matcher: ["/dashboard/:path*", "/admin/:path*"] }`)).toEqual(["/dashboard/:path*", "/admin/:path*"]);
    expect(middleware(`export default function proxy(req) { if (req.nextUrl.pathname.startsWith("/settings")) return NextResponse.rewrite(new URL("/x", req.url)) }`)).toEqual(["/settings"]);
  });
  it("counts a session cookie, an auth call, an auth module, a re-export or a /login redirect as a check", () => {
    const cfg = `export const config = { matcher: ["/dashboard/:path*"] }`;
    for (const src of [
      `export function middleware(req) { if (!req.cookies.get("session")) return NextResponse.next() }\n${cfg}`,
      `export function middleware(req) { if (!req.headers.get("authorization")) return new Response(null, { status: 401 }) }\n${cfg}`,
      `export function middleware(req) { return NextResponse.redirect(new URL("/login", req.url)) }\n${cfg}`,
      `export { auth as middleware } from "@/auth";\n${cfg}`,
      `export { default } from "next-auth/middleware";\n${cfg}`,
      `export * from "@/lib/auth";\n${cfg}`,
      `import { clerkMiddleware } from "@clerk/nextjs/server"; export default clerkMiddleware();\n${cfg}`,
      `import { updateSession } from "@/utils/supabase/middleware"; export async function middleware(r) { return await updateSession(r) }\n${cfg}`,
      `import { jwtVerify } from "jose"; export async function middleware(req) { await jwtVerify(t, k) }\n${cfg}`,
    ]) expect(middleware(src), src).toBeNull();
  });
  it("leaves out middleware for public paths (i18n, multi-tenant rewrites)", () => {
    expect(middleware(`import createMiddleware from "next-intl/middleware"; export default createMiddleware(routing);\nexport const config = { matcher: ["/", "/(de|en)/:path*"] }`)).toBeNull();
    expect(middleware(`export function middleware(req) { return NextResponse.rewrite(new URL("/app" + req.nextUrl.pathname, req.url)) }\nexport const config = { matcher: ["/((?!api|_next).*)", "/team", "/user/:name"] }`)).toBeNull();
  });
  it("reads re-exports from auth modules, so the Server Actions check sees the auth middleware too", () => {
    const names = (src) => { const { code, plain } = lexJs(src); return [...authImports(code, plain)].sort(); };
    expect(names(`export { auth as middleware } from "@/auth"`)).toEqual(["middleware"]);
    expect(names(`export { default } from "next-auth/middleware"`)).toEqual(["default"]);
    expect(names(`export * from "@/lib/auth"`)).toEqual(["*"]);
    expect(names(`export { helper } from "./utils"; export const x = 1; export function f() {}`)).toEqual([]);
  });
  it("counts jwtVerify and jwt.verify as checks in a Server Action", () => {
    const unchecked = (body) => uncheckedActions(`'use server';\nexport async function a(id) { ${body}; await db.delete(id); }\n`).hits.length;
    expect(unchecked("await jwtVerify(t, key)")).toBe(0);
    expect(unchecked("jwt.verify(t, key)")).toBe(0);
    expect(unchecked("x.jwt.verify(t, key)")).toBe(1);
  });
});

describe("session and login checks in a repo", () => {
  const app = {
    "package.json": JSON.stringify({ dependencies: { next: "15.5.9" } }),
    "next.config.mjs": "export default {}\n",
    "middleware.ts": `import { NextResponse } from "next/server";\nexport function middleware() { return NextResponse.next() }\nexport const config = { matcher: ["/admin/:path*"] }\n`,
    "app/api/reset/route.ts": `export async function GET(request) {\n  const pw = request.nextUrl.searchParams.get("password");\n  return Response.json({ ok: !!pw });\n}\n`,
    "lib/users.ts": `import CryptoJS from "crypto-js";\nexport const save = (password) => db.user.create({ data: { password: CryptoJS.AES.encrypt(password, KEY).toString() } });\n`,
    "server.js": `const session = require("express-session");\napp.use(session({ secret: process.env.S, cookie: { secure: false } }));\n`,
    "app/api/callback/route.ts": `export async function GET(req) {\n  const code = req.nextUrl.searchParams.get("code");\n  await fetch(TOKEN_URL, { method: "POST", body: new URLSearchParams({ code, grant_type: "authorization_code" }) });\n}\n`,
    "tests/fixture.ts": `const p = req.query.password;\n`,
  };
  it("reports each rule once with file:line evidence, and explain_finding knows each id", async () => {
    const r = await scanRepo(repo(app));
    expect(r.executedProbes).toContain("session-auth");
    const ours = r.findings.filter((f) => f.templateId in SESSION_AUTH_RULES).map((f) => [f.templateId, f.file, f.line, f.severity, f.confidence]);
    expect(ours.sort()).toEqual([
      ["credential-in-url", "app/api/reset/route.ts", 2, "medium", "likely"],
      ["next-middleware-no-auth", "middleware.ts", 3, "medium", "potential"],
      ["oauth-callback-no-state", "app/api/callback/route.ts", 3, "medium", "potential"],
      ["password-encrypted-not-hashed", "lib/users.ts", 2, "high", "potential"],
      ["session-cookie-insecure", "server.js", 2, "medium", "likely"],
    ]);
    for (const id of Object.keys(SESSION_AUTH_RULES)) {
      const { structured } = await TOOL_BY_NAME.get("explain_finding").run({ id });
      expect(structured.known, id).toBe(true);
      expect(structured.action, id).not.toMatch(/review/i);
    }
  });
  it("finds nothing in a clean app", async () => {
    const r = await scanRepo(repo({
      "next.config.mjs": "export default {}\n",
      "middleware.ts": `export { auth as middleware } from "@/auth";\nexport const config = { matcher: ["/admin/:path*"] }\n`,
      "app/api/login/route.ts": `import bcrypt from "bcrypt";\nexport async function POST(req) { const { password } = await req.json(); return bcrypt.compare(password, hash); }\n`,
      "server.js": `const session = require("express-session");\napp.use(session({ secret: process.env.S, cookie: { secure: true, httpOnly: true, sameSite: "lax" } }));\n`,
    }));
    expect(r.findings.filter((f) => f.templateId in SESSION_AUTH_RULES)).toEqual([]);
    expect(exitCodeOf(r)).not.toBe(2);
  });
  it("does not take a middleware.js outside a Next.js app for one", () => {
    const dir = repo({ "server/middleware.js": `export default function (req, res, next) { next() }\nconst p = ["/admin"]\n` });
    expect(scanSessionAuth(dir).filter((f) => f.templateId === "next-middleware-no-auth")).toEqual([]);
  });
  it.skipIf(process.platform === "win32")("names a file it may not read, and the scan is incomplete (exit 2)", async () => {
    const dir = repo({ "app/page.ts": "export default 1\n" });
    const outside = repo({ "secret.ts": "const p = req.query.password\n" });
    symlinkSync(join(outside, "secret.ts"), join(dir, "app/linked.ts"));
    try { execFileSync("mkfifo", [join(dir, "app/pipe.ts")]); } catch { /* no mkfifo */ }
    const refused = [];
    scanSessionAuth(dir, { refused });
    expect(refused.map((e) => e.path || e.label).join(" ")).toMatch(/linked\.ts/);
    const r = await scanRepo(dir);
    expect(r.incomplete?.some((i) => /linked\.ts/.test(i.file))).toBe(true);
    expect(exitCodeOf(r)).toBe(2);
  });
  it("past the work budget keeps what it found and marks the file not fully checked", async () => {
    // Each encrypt( reads its own arguments, which hold every deeper call: quadratic, so the budget stops it.
    const depth = 3000;
    const src = `const a = req.query.password;\nconst e = ${"encrypt(".repeat(depth)}password${")".repeat(depth)};\n`;
    const one = sessionAuthHits(src);
    expect(one.incomplete).toBe(true);
    expect(one.hits.url.items.map((h) => h.name)).toEqual(["password"]);
    const dir = repo({ "app/x.ts": src });
    const refused = [];
    const found = scanSessionAuth(dir, { refused });
    // The outermost call was read before the budget ran out: that finding stays too.
    expect(found.map((f) => f.templateId)).toEqual(["credential-in-url", "password-encrypted-not-hashed"]);
    expect(refused).toEqual([expect.objectContaining({ partial: true })]);
    const r = await scanRepo(dir);
    expect(r.incomplete?.some((i) => /x\.ts/.test(i.file))).toBe(true);
    expect(exitCodeOf(r)).toBe(2);
  });
  it("finds a hit in the last line with no newline, and survives a file that ends inside a string", () => {
    expect(urlNames(`const p = req.query.password`)).toEqual(["password:password"]);
    expect(() => sessionAuthHits(`import session from "express-session"; app.use(session({ secret: "x`)).not.toThrow();
    expect(() => sessionAuthHits(`const p = searchParams.get("password`)).not.toThrow();
  });
  it("keeps the worst hits when a file has many", () => {
    const src = `${Array.from({ length: 50 }, (_, i) => `const a${i} = req.query.apiKey;`).join("\n")}\nconst p = req.query.password;\n`;
    const dir = repo({ "app/x.ts": src });
    const [f] = scanSessionAuth(dir);
    expect(f).toMatchObject({ severity: "medium", confidence: "likely", line: 51 });
    expect(f.description).toMatch(/^`password` \(line 51\)/);
    expect(f.description).toMatch(/and 43 more/);
  });
});

// Bypass checklist rows that found something while these rules were built: each reproduction is a case.
describe("session and login checks: bypass checklist cases", () => {
  const pad = " ".repeat(70000);
  it("row 1: padding past any window still finds the hit", () => {
    expect(urlNames(`const {${pad}password } = req.query;`)).toEqual(["password:password"]);
    expect(urlNames(`const { password } =${pad}req.query;`)).toEqual(["password:password"]);
    expect(urlNames(`const { password } = req.query${pad};`)).toEqual(["password:password"]);
    expect(cookies(`import session from "express-session"; app.use(session({ secret: s,${pad} resave: false }))`)).toEqual(["no cookie options (Secure is off by default)"]);
    expect(cookies(`import session from "express-session"; app.use(session(${pad}{ secret: s }))`)).toEqual(["no cookie options (Secure is off by default)"]);
    expect(encrypted(`if (decrypt(user.password)${pad}!== password) fail()`)).toEqual(["compare:user.password"]);
    expect(encrypted(`const p = decrypt(user.password);\n${pad}\nif (p === input) ok()`)).toEqual(["compare:user.password"]);
  });
  it("row 8: nested query keys and spelled-out names", () => {
    expect(urlNames(`const p = req.query.user.password; const k = req?.query?.auth?.apiKey`)).toEqual(["password:password", "apiKey:credential"]);
    expect(urlNames(`const p = req.query["Pass-Word"]; const k = req.query["API_KEY"]`)).toEqual(["Pass-Word:password", "API_KEY:credential"]);
  });
  it("row 12 and 19: a call the file never closes is read to the end", () => {
    expect(encrypted(`const e = encrypt(password`)).toEqual(["encrypt:password"]);
    expect(encrypted(`if (decrypt(user.password) !== password`)).toEqual(["compare:user.password"]);
    expect(cookies(`import session from "express-session"; app.use(session({ secret: s`)).toEqual(["no cookie options (Secure is off by default)"]);
  });
  it("comparisons written over several lines, either side", () => {
    expect(encrypted(`const ok =\n  CryptoJS.AES.decrypt(user.password, KEY).toString(CryptoJS.enc.Utf8) ===\n  password;`)).toEqual(["compare:user.password"]);
    expect(encrypted(`const ok =\n  password ===\n  CryptoJS.AES.decrypt(user.password, KEY).toString(CryptoJS.enc.Utf8);`)).toEqual(["compare:user.password"]);
    expect(encrypted(`const p = await decrypt(user.password)\nreturn p !== input`)).toEqual(["compare:user.password"]);
    expect(encrypted(`return crypto.timingSafeEqual(Buffer.from(decrypt(user.password)), Buffer.from(pw))`)).toEqual(["compare:user.password"]);
  });
  it("row 13: decoys never push out the worst hit", () => {
    const h = hits(`${"encrypt(password);\n".repeat(500)}if (decrypt(user.password) !== pw) x()`).encrypted;
    expect([h.count, h.items.length, h.items[0].kind]).toEqual([501, 8, "compare"]);
  });
  it("row 20: nested calls that reread each other end as incomplete, quickly", () => {
    const src = `import session from "express-session";\n${"session({ a: ".repeat(20000)}`;
    const t = Date.now();
    expect(sessionAuthHits(src).incomplete).toBe(true);
    expect(Date.now() - t).toBeLessThan(5000);
  });
});

// Measured by the doubling method (8x the input, linear is ~8x) so they don't flake under parallel CI.
describe("session and login checks stay linear on crafted input", () => {
  // The fastest of seven runs at 16k and 128k characters: below that, one run takes
  // well under a millisecond, and a garbage collection in the lexer's buffers can
  // land in any one run, so the minimum is the steady figure. A quadratic path
  // grows ~64x here, a linear one ~8x.
  const grows = (gen, opts = {}) => {
    const run = (s) => sessionAuthHits(s, opts);
    const ms = (n) => {
      const src = gen(n);
      run(src);
      let best = Infinity;
      for (let k = 0; k < 7; k++) { const s = process.hrtime.bigint(); run(src); best = Math.min(best, Number(process.hrtime.bigint() - s) / 1e6); }
      return best;
    };
    const small = Math.max(ms(16000), 1);
    return ms(128000) / small;
  };
  const mw = { middleware: () => true };
  const cases = {
    "a long name before each .query": (n) => `${"a".repeat(n)}.query.password;\n`.repeat(4),
    "many query words with long receiver chains": (n) => `x = ${"a.".repeat(60)}query\n`.repeat(n / 64),
    "many destructurings that never close": (n) => `} = req.query\n`.repeat(n / 14),
    "many unclosed getQuery calls": (n) => `getQuery(\n`.repeat(n / 10),
    "many encrypt calls on long argument lists": (n) => `encrypt(password, ${"x, ".repeat(20)})\n`.repeat(n / 80),
    "many decrypts with long statements around them": (n) => `const v = decrypt(user.password)${" ".repeat(200)}\n`.repeat(n / 240),
    "deeply nested objects with secure: false": (n) => `import s from "iron-session";\n${"{ cookieOptions: ".repeat(n / 20)}{ secure: false }`,
    "many express-session calls without a closing brace": (n) => `import session from "express-session";\n${"session({ cookie: \n".repeat(n / 20)}`,
    "many unterminated strings after searchParams.get": (n) => `searchParams.get("password\n`.repeat(n / 26),
    "an OAuth file full of getToken({": (n) => `const code = req.query.code; ${"getToken({ ".repeat(n / 10)}`,
    // Whitespace on both sides of an optional token (`query\s*(?:\?\.)?\s*\[`) took 57 s on 70,000 spaces.
    "padding after req.query": (n) => `const { password } = req.query${" ".repeat(n)};`,
    "padding after searchParams": (n) => `const p = searchParams${" ".repeat(n)}x`,
    "padding inside a session call": (n) => `import session from "express-session"; app.use(session(${" ".repeat(n)}{ secret: s }))`,
    "padding before a compare": (n) => `if (decrypt(user.password)${" ".repeat(n)}x) fail()`,
  };
  for (const [name, gen] of Object.entries(cases)) it(name, () => expect(grows(gen)).toBeLessThan(24));
  it("a middleware with many export lists that never close", () => expect(grows((n) => `export {\n${"export { a\n".repeat(n / 12)}`, mw)).toBeLessThan(24));
  it("a middleware with many re-exports padded with long comments", () => expect(grows((n) => `export * /*${"x".repeat(n)}*/ from "./x";\n`.repeat(3), mw)).toBeLessThan(24));
  it("a middleware padded after cookies and headers", () => expect(grows((n) => `export default function middleware(r) { r.cookies${" ".repeat(n)}x; r.headers${" ".repeat(n)}x }`, mw)).toBeLessThan(24));
  it("a middleware with many protected path strings", () => expect(grows((n) => `export default function middleware() {}\nconst p = [${'"/admin", '.repeat(n / 10)}]`, mw)).toBeLessThan(24));
});
