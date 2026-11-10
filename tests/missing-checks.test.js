/**
 * The five missing-check rules (lib/whitebox/missing-checks.js): a webhook
 * without a signature check, jwt.decode where jwt.verify belongs, a secret
 * compared with ===, a reset token with no expiry, and a price or role taken
 * from the client. Each has match and no-match cases per form, metamorphic
 * variants (comments, line breaks, no semicolons, TypeScript), refusals
 * (incomplete, never silent), end-of-input cases, and doubling-method timing
 * on crafted worst cases. Offline: temp folders only, no key-shaped strings.
 */
import { describe, it, expect, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync, chmodSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { scanRepo } from "../src/scan-repo.js";
import { exitCodeOf } from "../src/report/exit.js";
import { TOOL_BY_NAME } from "../src/mcp/tools.js";
import { buildActionPlan } from "../lib/remediation/index.js";
import {
  missingCheckHits, scanMissingChecks, MISSING_CHECK_RULES, MISSING_CHECK_MAX_BYTES,
  WEBHOOK_RULE, JWT_DECODE_RULE, TIMING_RULE, RESET_EXPIRY_RULE, CLIENT_VALUE_RULE,
} from "../lib/whitebox/missing-checks.js";

const temps = [];
afterAll(() => temps.forEach((d) => rmSync(d, { recursive: true, force: true })));
function repo(files) {
  const dir = mkdtempSync(join(tmpdir(), "penthera-missing-"));
  temps.push(dir);
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), text);
  }
  return dir;
}
/** The rules that fire on one file, with the 1-based line of each hit. */
function fired(src, rel = "app/api/x/route.ts") {
  const { hits, lineAt } = missingCheckHits(src, rel);
  return Object.fromEntries(Object.entries(hits).map(([k, v]) => [k, v.map((h) => lineAt(h.at))]));
}
const rules = (src, rel) => Object.keys(fired(src, rel)).sort();

// ── 1. webhooks ───────────────────────────────────────────────────────────

const STRIPE_UNVERIFIED = `import Stripe from "stripe";
export async function POST(req: Request) {
  const event = await req.json();
  if (event.type === "checkout.session.completed") {
    await prisma.order.update({ where: { id: event.data.object.metadata.orderId }, data: { paid: true } });
  }
  return new Response("ok");
}
`;

describe("webhook-signature-missing", () => {
  it("reports a Stripe route handler that writes from the parsed body", () => {
    expect(fired(STRIPE_UNVERIFIED, "app/api/webhooks/stripe/route.ts")).toEqual({ [WEBHOOK_RULE]: [5] });
  });
  it("reports a Stripe event handler wherever it lives, by its event names", () => {
    expect(rules(STRIPE_UNVERIFIED, "app/api/payments/route.ts")).toEqual([WEBHOOK_RULE]);
  });
  it("reports an Express webhook route and a Supabase write", () => {
    const src = `const app = express();
app.post("/api/webhook", express.json(), async (req, res) => {
  const event = req.body;
  if (event.type === "invoice.paid") await supabase.from("subs").update({ active: true }).eq("id", event.data.object.id);
  res.sendStatus(200);
});
`;
    expect(fired(src, "server/index.js")).toEqual({ [WEBHOOK_RULE]: [4] });
  });
  it("reports a Lemon Squeezy-style handler that never checks the HMAC", () => {
    const src = `export async function POST(request) {
  const payload = await request.json();
  if (payload.meta.event_name === "order_created") await db.insert(orders).values({ id: payload.data.id });
}
`;
    expect(rules(src, "app/api/lemon/webhook/route.ts")).toEqual([WEBHOOK_RULE]);
  });
  it("is quiet with constructEvent, constructEventAsync, an HMAC, svix, a verify helper or a webhook secret", () => {
    const checks = [
      `const event = stripe.webhooks.constructEvent(await req.text(), req.headers.get("stripe-signature"), secret);`,
      `const event = await stripe.webhooks.constructEventAsync(body, sig, key);`,
      `const digest = crypto.createHmac("sha256", key).update(raw).digest("hex");`,
      `const evt = new Webhook(key).verify(payload, headers);`,
      `const evt = await verifyWebhook(req);`,
      `if (!isValidSignature(raw, sig)) return new Response(null, { status: 401 }); verifyStripeSignature(raw);`,
      `const s = process.env.STRIPE_WEBHOOK_SECRET;`,
      `const endpointSecret = cfg.endpoint;`,
      `const event = await stripe.events.retrieve(body.id);`,
    ];
    for (const c of checks) {
      const src = `export async function POST(req) {\n  const body = await req.json();\n  ${c}\n  if (body.type === "checkout.session.completed") await prisma.order.update({ where: { id: 1 }, data: { paid: true } });\n}\n`;
      expect(rules(src, "app/api/webhooks/stripe/route.ts"), c).toEqual([]);
    }
  });
  it("is quiet on a handler that writes nothing, a webhook sender, and a user's webhook settings route", () => {
    expect(rules(`export async function POST(req) { const e = await req.json(); console.log(e.type); return Response.json({}); }\n`, "app/api/webhooks/route.ts")).toEqual([]);
    expect(rules(`export async function sendWebhook(url, data) { await fetch(url, { method: "POST", body: JSON.stringify(data) }); await db.log.create({ data: { url } }); }\n`, "lib/webhooks/send.ts")).toEqual([]);
    expect(rules(`export async function POST(req) { const session = await auth(); const body = await req.json(); await prisma.webhook.create({ data: { url: body.url, userId: session.user.id, type: body.type } }); }\n`, "app/api/webhooks/route.ts")).toEqual([]);
  });
  it("many webhook routes with handlers passed by name read the file once, not once per route", () => {
    const src = `const e = req.body; e.type;\n${Array.from({ length: 400 }, (_, i) => `app.post("/webhook/${i}", handler${i});`).join("\n")}\n${"// padding\n".repeat(4000)}`;
    const r = missingCheckHits(src, "server/routes.js");
    expect(r.incomplete).toBe(false);
    expect(r.hits).toEqual({});
  });
  it("is potential when the file reads a signature header it may pass to a helper", async () => {
    const dir = repo({ "app/api/webhooks/stripe/route.ts": STRIPE_UNVERIFIED.replace("const event = await req.json();", "const event = await req.json(); const sig = req.headers.get(\"stripe-signature\"); await handle(sig);") });
    const [f] = scanMissingChecks(dir);
    expect(f).toMatchObject({ templateId: WEBHOOK_RULE, confidence: "potential", severity: "high", file: "app/api/webhooks/stripe/route.ts" });
  });
});

// ── 2. jwt.decode ─────────────────────────────────────────────────────────

describe("jwt-decode-unverified", () => {
  it("reports decodeJwt, jwt.decode and jwtDecode on a token from the request", () => {
    expect(fired(`import { decodeJwt } from "jose";\nexport function middleware(request) {\n  const token = request.cookies.get("token")?.value;\n  const payload = decodeJwt(token);\n  if (payload.role !== "admin") return Response.redirect("/");\n}\n`, "middleware.ts")).toEqual({ [JWT_DECODE_RULE]: [4] });
    expect(rules(`const jwt = require("jsonwebtoken");\nmodule.exports = (req, res, next) => { const t = req.headers.authorization.split(" ")[1]; req.user = jwt.decode(t); next(); };\n`, "server/auth.js")).toEqual([JWT_DECODE_RULE]);
    expect(rules(`import { jwtDecode } from "jwt-decode";\nexport async function GET(req) { const { sub } = jwtDecode(req.headers.get("Authorization")); return Response.json(await db.user.findUnique({ where: { id: sub } })); }\n`)).toEqual([JWT_DECODE_RULE]);
    expect(rules(`const claims = jwt.decode(token, { complete: true }); const t = req.cookies.session;\n`, "lib/session.ts")).toEqual([JWT_DECODE_RULE]);
  });
  it("is quiet when the file verifies, when decode takes a secret, and when no request token is read", () => {
    expect(rules(`const { header } = jwt.decode(t, { complete: true }); const key = await getKey(header.kid); return jwt.verify(t, key); // req.headers.authorization\n`, "lib/a.ts")).toEqual([]);
    expect(rules(`const p = await jwtVerify(req.cookies.get("t").value, key); const x = decodeJwt(other);\n`, "lib/b.ts")).toEqual([]);
    expect(rules(`import * as jwt from "next-auth/jwt"; const s = await jwt.decode({ token: req.cookies.t, secret });\n`, "lib/c.ts")).toEqual([]);
    expect(rules(`const jwt = require("jwt-simple"); const p = jwt.decode(req.headers.authorization, secret);\n`, "lib/d.js")).toEqual([]);
    expect(rules(`const claims = jwtDecode(tokens.id_token); console.log(claims.email);\n`, "lib/e.ts")).toEqual([]);
  });
  it("is quiet in browser code", () => {
    expect(rules(`"use client";\nimport { jwtDecode } from "jwt-decode";\nconst t = document.cookie; const u = jwtDecode(t);\n`, "components/User.tsx")).toEqual([]);
  });
});

// ── 3. timing-safe compares ───────────────────────────────────────────────

describe("secret-compare-not-constant-time", () => {
  it("reports an HMAC compared with !== (medium) and a cron bearer secret (low)", async () => {
    const dir = repo({
      "lib/sig.ts": `export function check(body, signature) {\n  const expected = crypto.createHmac("sha256", key).update(body).digest("hex");\n  return signature === expected;\n}\n`,
      "app/api/cron/route.ts": "export async function GET(request) {\n  const authHeader = request.headers.get(\"authorization\");\n  if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) return new Response(null, { status: 401 });\n}\n",
    });
    const f = scanMissingChecks(dir).map((x) => [x.file, x.severity, x.line]).sort();
    expect(f).toEqual([["app/api/cron/route.ts", "low", 3], ["lib/sig.ts", "medium", 3]]);
  });
  it("reports a header API key, a query token and a CSRF token against a secret", () => {
    expect(rules(`if (req.headers["x-api-key"] !== process.env.API_KEY) return res.status(401).end();\n`, "server/mw.js")).toEqual([TIMING_RULE]);
    expect(rules(`const { token } = req.query;\nif (token == user.resetToken) ok();\n`, "server/r.js")).toEqual([TIMING_RULE]);
    expect(rules(`const headerToken = c.req.header("x-csrf-token");\nif (cookieToken !== headerToken) fail();\nconst cookieToken = getCookie(c, "csrfToken");\n`, "server/csrf.ts")).toEqual([TIMING_RULE]);
  });
  it("is quiet on lengths, types, literals, a constant-time compare and non-secret names", () => {
    const quiet = [
      `if (signature.length !== expected.length) return false; return crypto.timingSafeEqual(a, b);`,
      `if (typeof req.headers.authorization === "string") x();`,
      `if (process.env.API_KEY === undefined) throw new Error("missing");`,
      `if (req.headers["x-api-key"] === "") fail();`,
      `if (token === prevToken) next(); if (tokens.type === token.type) next();`,
      `if (next.embedding.apiKey !== before.config.embedding.apiKey) reindex();`,
      `if (cached.signature === signature && cached.expiresAt > Date.now()) return cached;`,
      `if (incoming.chat?.apiKey === MASKED_API_KEY) keep();`,
      `if (req.body.password === req.body.confirmPassword) ok();`,
      `if (process.env.NODE_ENV === "production") x();`,
      `const isSecret = req.query.secret === undefined;`,
    ];
    for (const q of quiet) expect(rules(q + "\n", "server/q.js"), q).toEqual([]);
  });
  it("keeps the worst hit: an HMAC compare after many low ones sets the severity and line", async () => {
    const lows = Array.from({ length: 30 }, () => "if (req.headers.authorization !== process.env.API_TOKEN) deny();").join("\n");
    const dir = repo({ "server/many.js": `${lows}\nconst mac = createHmac("sha256", k).update(b).digest("hex");\nif (mac !== given) deny();\n` });
    const [f] = scanMissingChecks(dir);
    expect(f).toMatchObject({ severity: "medium", line: 32 });
    expect(f.description).toMatch(/and \d+ more/);
  });
});

// ── 4. reset tokens ───────────────────────────────────────────────────────

const RESET_NO_EXPIRY = `export async function POST(req) {
  const { token, password } = await req.json();
  const user = await prisma.user.findFirst({ where: { resetToken: token } });
  await prisma.user.update({ where: { id: user.id }, data: { password: await bcrypt.hash(password, 10), resetToken: null } });
}
`;

describe("reset-token-no-expiry", () => {
  it("reports a lookup by reset token that changes the password with no expiry check", () => {
    expect(fired(RESET_NO_EXPIRY)).toEqual({ [RESET_EXPIRY_RULE]: [3] });
    expect(rules(`router.post("/reset/:token", async (req, res) => {\n  const user = await User.findOne({ resetPasswordToken: req.params.token });\n  user.password = req.body.password;\n  await user.save();\n});\n`, "routes/auth.js")).toEqual([RESET_EXPIRY_RULE]);
    expect(rules(`const row = await sql\`SELECT * FROM password_reset_tokens WHERE token = \${t}\`;\nawait sql\`UPDATE users SET password_hash = \${h}\`; const x = { passwordHash: h };\n`, "lib/reset.ts")).toEqual([RESET_EXPIRY_RULE]);
  });
  it("is quiet with an expiry field, a date filter, a time comparison, a signed token or a key-value store", () => {
    const checks = [
      RESET_NO_EXPIRY.replace("resetToken: token }", "resetToken: token, resetTokenExpiry: { gt: new Date() } }"),
      RESET_NO_EXPIRY.replace("resetToken: token }", "resetToken: token, createdAt: { gte: cutoff } }"),
      RESET_NO_EXPIRY.replace("const user", "if (Date.now() > rec.created.getTime() + HOUR) throw new Error();\n  const user"),
      RESET_NO_EXPIRY.replace("const user", "const { sub } = jwt.verify(token, key);\n  const user"),
      RESET_NO_EXPIRY.replace("const user", "const id = await redis.get(`reset:${token}`);\n  const user"),
      RESET_NO_EXPIRY.replace("const user", "if (rec.expires_at < now()) fail();\n  const user"),
    ];
    for (const c of checks) expect(rules(c), c.slice(0, 120)).toEqual([]);
  });
  it("is quiet on the side that creates the token (no password write)", () => {
    expect(rules(`const resetToken = crypto.randomBytes(32).toString("hex");\nawait prisma.user.update({ where: { email }, data: { resetToken } });\nawait sendMail(email, link);\n`)).toEqual([]);
  });
});

// ── 5. client-trusted values ──────────────────────────────────────────────

describe("client-trusted-value", () => {
  it("reports an amount from the body sent to Stripe", () => {
    const src = `export async function POST(req) {
  const { amount, name } = await req.json();
  const session = await stripe.checkout.sessions.create({ mode: "payment", line_items: [{ quantity: 1, price_data: { currency: "usd", unit_amount: Math.round(amount * 100), product_data: { name } } }] });
}
`;
    expect(fired(src)).toEqual({ [CLIENT_VALUE_RULE]: [3] });
    expect(rules(`app.post("/pay", async (req, res) => { const pi = await stripe.paymentIntents.create({ amount: req.body.amount, currency: "eur" }); res.json(pi); });\n`, "server.js")).toEqual([CLIENT_VALUE_RULE]);
    expect(rules(`export async function createIntent(formData) {\n  "use server";\n  const amount = Number(formData.get("amount"));\n  return stripe.paymentIntents.create({ amount, currency: "usd" });\n}\n`, "app/actions.ts")).toEqual([CLIENT_VALUE_RULE]);
  });
  it("reports a role or plan from the body, and the whole body into a user record", () => {
    expect(rules(`export async function POST(req) { const body = await req.json(); await prisma.user.create({ data: { email: body.email, role: body.role } }); }\n`)).toEqual([CLIENT_VALUE_RULE]);
    expect(rules(`export async function POST(req) { const { plan } = await req.json(); await supabase.from("profiles").update({ plan }).eq("id", uid); }\n`)).toEqual([CLIENT_VALUE_RULE]);
    expect(rules(`router.put("/me", async (req, res) => { await User.findByIdAndUpdate(req.user.id, req.body); res.end(); });\n`, "routes/me.js")).toEqual([CLIENT_VALUE_RULE]);
    expect(rules(`export async function POST(req) { await prisma.user.update({ where: { id }, data: { ...(await req.json()) } }); }\n`)).toEqual([CLIENT_VALUE_RULE]);
    expect(rules(`app.post("/signup", async (req, res) => { const user = new User(req.body); await user.save(); });\n`, "server.js")).toEqual([CLIENT_VALUE_RULE]);
  });
  it("is quiet on a Price id, a server-side amount, chosen fields, a validated body, metadata, donations and admin routes", () => {
    const quiet = [
      `export async function POST(req) { const { priceId } = await req.json(); await stripe.checkout.sessions.create({ line_items: [{ price: priceId, quantity: 1 }] }); }`,
      `export async function POST(req) { const { productId } = await req.json(); const p = await db.product.findUnique({ where: { id: productId } }); await stripe.paymentIntents.create({ amount: p.price, currency: "usd" }); }`,
      `export async function POST(req) { const body = await req.json(); await prisma.user.update({ where: { id }, data: { name: body.name, bio: body.bio } }); }`,
      `export async function POST(req) { const data = Schema.parse(await req.json()); await prisma.user.update({ where: { id }, data: data }); }`,
      `export async function POST(req) { const { note } = await req.json(); await stripe.checkout.sessions.create({ line_items, metadata: { amount: note } }); }`,
      `export async function POST(req) { const { amount } = await req.json(); await stripe.paymentIntents.create({ amount, currency: "usd", description: "Donation" }); }`,
      `export async function POST(req) { await requireAdmin(); const body = await req.json(); await prisma.user.update({ where: { id: body.id }, data: { role: body.role } }); }`,
      `export async function POST(req) { if (session.user.role !== "admin") return deny(); const body = await req.json(); await prisma.user.update({ where: { id: body.id }, data: { role: body.role } }); }`,
      `export async function POST(req) { const body = await req.json(); await prisma.post.create({ data: body }); }`,
      `export async function POST(req) { const body = await req.json(); await stripe.refunds.create({ payment_intent: body.pi, amount: body.amount }); }`,
    ];
    for (const q of quiet) expect(rules(q + "\n"), q.slice(0, 120)).toEqual([]);
    expect(rules(`export async function POST(req) { const body = await req.json(); await prisma.user.update({ where: { id: body.id }, data: { role: body.role } }); }\n`, "app/admin/users/route.ts")).toEqual([]);
  });
});

// ── metamorphic variants (checklist row 21) ───────────────────────────────

describe("client-trusted-value: what counts as an admin check", () => {
  const write = `const body = await req.json();\nawait prisma.user.update({ where: { id }, data: { role: body.role } });\n`;
  it("a check called by name, or a role comparison, marks an admin route", () => {
    for (const check of ["await requireAdmin();", "if (!hasRole(session, 'admin')) return;", "assertIsOwner (team);", "if (session.user.role !== 'admin') return;", "if (!isAdmin) return;", "await $checkIsStaff(user);"]) {
      expect(rules(`${check}\n${write}`), check).toEqual([]);
    }
  });
  it("a name that is not called, a marker before the prefix, or a lower-case marker is not a check", () => {
    for (const notCheck of ["const isAdminPage = true;", "adminIs(x);", "isadmin(x);", "// requireAdmin()", "const s = \"requireAdmin()\";", "requireAdmin$x(y);"]) {
      expect(rules(`${notCheck}\n${write}`), notCheck).toEqual([CLIENT_VALUE_RULE]);
    }
  });
});

describe("the rules survive behaviour-preserving rewrites", () => {
  it("comments between tokens, chains across lines, no semicolons, TypeScript annotations, renamed names", () => {
    const variants = [
      // webhook: comments and line-broken chains
      [WEBHOOK_RULE, "app/api/webhooks/stripe/route.ts", `export async function POST(req: Request) /* stripe */ {\n  const evt: any = await req\n    .json()\n  if (evt.type === "invoice.paid") {\n    await prisma\n      .subscription\n      .update({ where: { id: evt.id }, data: { active: true } })\n  }\n}\n`],
      // jwt: aliased receiver name, a long comment before the dot, no semicolons
      [JWT_DECODE_RULE, "server/mw.ts", `import JWT from "jsonwebtoken"\nexport const mw = (req, _res, next) => {\n  const claims = JWT /* read the claims; this comment is longer than the old window */ .decode(req.headers.authorization)\n  req.user = claims\n  next()\n}\n`],
      // timing: annotated declaration, no semicolons
      [TIMING_RULE, "server/sig.ts", `const digest: string = crypto\n  .createHmac("sha256", key)\n  .update(raw)\n  .digest("hex")\nif (given !== digest) throw new Error("bad")\n`],
      // reset: snake_case columns
      [RESET_EXPIRY_RULE, "server/reset.js", `const row = await knex("users").where({ password_reset_token: req.body.token }).first()\nawait knex("users").update({ password_hash: await hash(req.body.password) })\n`],
      // client value: renamed destructuring
      [CLIENT_VALUE_RULE, "app/api/buy/route.ts", `export async function POST(req: Request) {\n  const { total: chosen } = (await req.json()) as { total: number }\n  await stripe.paymentIntents.create({ amount: chosen /* cents */, currency: "usd" })\n}\n`],
    ];
    for (const [rule, rel, src] of variants) expect(rules(src, rel), rule).toContain(rule);
  });
  // Known gap: the body read is recognised by the request's usual names (req,
  // request, event, c.req, ctx.request), not by the handler's first parameter.
  it.fails("a webhook handler whose request parameter has another name", () => {
    expect(rules(STRIPE_UNVERIFIED.replace("(req: Request)", "(r: Request)").replace("req.json()", "r.json()"), "app/api/webhooks/stripe/route.ts")).toEqual([WEBHOOK_RULE]);
  });
  it("a call or a name inside a comment or a string is not one", () => {
    expect(rules(`// stripe.webhooks.constructEvent(body, sig, secret)\n${STRIPE_UNVERIFIED}`, "app/api/webhooks/stripe/route.ts")).toEqual([WEBHOOK_RULE]);
    expect(rules(`const msg = "jwt.verify(token)";\nconst u = jwt.decode(req.headers.authorization);\n`, "server/x.js")).toEqual([JWT_DECODE_RULE]);
  });
});

// ── end of input (checklist row 12) ───────────────────────────────────────

describe("end of input", () => {
  it("a last line with no newline, a file ending inside a string, a comment or an unclosed call", () => {
    expect(rules(RESET_NO_EXPIRY.trimEnd())).toEqual([RESET_EXPIRY_RULE]);
    expect(rules(`if (req.headers["x-api-key"] !== process.env.API_KEY) deny()`, "server/a.js")).toEqual([TIMING_RULE]);
    expect(rules(`const { role } = await req.json(); await prisma.user.update({ where: { id }, data: { role }`, "server/b.js")).toEqual([CLIENT_VALUE_RULE]);
    for (const tail of ["", "\n/* open comment", "\nconst s = \"open string", "\nconst t = `open template"]) {
      expect(() => missingCheckHits(STRIPE_UNVERIFIED + tail, "app/api/webhooks/stripe/route.ts")).not.toThrow();
    }
    expect(missingCheckHits("", "a.ts").hits).toEqual({});
  });
});

// ── refusals (checklist rows 1 and 2) ─────────────────────────────────────

describe("refusals make the scan incomplete, never a silent pass", () => {
  it("names an oversized file, padded past the cap, and the repo scan exits 2", async () => {
    const big = STRIPE_UNVERIFIED + " ".repeat(MISSING_CHECK_MAX_BYTES);
    const dir = repo({ "app/api/webhooks/stripe/route.ts": big });
    const refused = [];
    expect(scanMissingChecks(dir, { refused })).toEqual([]);
    expect(refused.map((e) => String(e.reason))).toEqual([expect.stringMatching(/over the \d+-byte limit/)]);
    const r = await scanRepo(dir);
    expect(r.incomplete.map((x) => x.file)).toContain("app/api/webhooks/stripe/route.ts");
    expect(exitCodeOf(r)).toBe(2);
  });
  it("names a linked-out file", () => {
    const dir = repo({ "app/page.tsx": "" });
    const outside = repo({ "route.ts": STRIPE_UNVERIFIED });
    mkdirSync(join(dir, "app/api/webhooks"), { recursive: true });
    symlinkSync(join(outside, "route.ts"), join(dir, "app/api/webhooks/route.ts"));
    const refused = [];
    expect(scanMissingChecks(dir, { refused })).toEqual([]);
    expect(refused.map((e) => e.reason)).toEqual([expect.stringMatching(/outside the project/)]);
  });
  it.skipIf(process.platform === "win32")("names a FIFO without blocking on it", () => {
    const dir = repo({ "app/page.tsx": "" });
    if (spawnSync("mkfifo", [join(dir, "app/pipe.ts")]).status !== 0) return;
    const refused = [];
    scanMissingChecks(dir, { refused });
    expect(refused.map((e) => e.reason)).toEqual([expect.stringMatching(/not a regular file/)]);
  });
  const isRoot = typeof process.getuid === "function" && process.getuid() === 0;
  it.skipIf(isRoot || process.platform === "win32")("names an unreadable file", () => {
    const dir = repo({ "app/api/webhooks/route.ts": STRIPE_UNVERIFIED });
    chmodSync(join(dir, "app/api/webhooks/route.ts"), 0o000);
    try {
      const refused = [];
      expect(() => scanMissingChecks(dir, { refused })).not.toThrow();
      expect(String(refused[0]?.reason || refused[0]?.message)).toMatch(/could not be read|EACCES|refus/i);
    } finally {
      chmodSync(join(dir, "app/api/webhooks/route.ts"), 0o644);
    }
  });
  it("over the work budget: the file is named as not fully checked, and hits found so far are kept", () => {
    // Deeply nested writes: each call's arguments are read again per level.
    const depth = 3000;
    const src = `${STRIPE_UNVERIFIED}\nexport async function POST2(req) { const body = await req.json(); ${"x.create(".repeat(depth)}${")".repeat(depth)} }\n`;
    const r = missingCheckHits(src, "app/api/webhooks/stripe/route.ts");
    expect(r.incomplete).toBe(true);
    expect(Object.keys(r.hits)).toContain(WEBHOOK_RULE);
    const dir = repo({ "app/api/webhooks/stripe/route.ts": src });
    const refused = [];
    const f = scanMissingChecks(dir, { refused });
    expect(f.map((x) => x.templateId)).toContain(WEBHOOK_RULE);
    expect(refused).toEqual([expect.objectContaining({ partial: true, reason: expect.stringMatching(/16 times its length/) })]);
  });
  it("skips test folders, test files and browser code", () => {
    const dir = repo({
      "tests/webhook.ts": STRIPE_UNVERIFIED,
      "app/api/webhooks/route.test.ts": STRIPE_UNVERIFIED,
      "app/components/Webhook.tsx": `"use client";\n${STRIPE_UNVERIFIED}`,
    });
    expect(scanMissingChecks(dir)).toEqual([]);
  });
});

// ── in a repo scan, explain_finding and the plan ──────────────────────────

describe("in a repo scan", () => {
  it("runs, names the probe, and reports each rule with file:line evidence", async () => {
    const r = await scanRepo(repo({
      "app/api/webhooks/stripe/route.ts": STRIPE_UNVERIFIED,
      "app/api/reset/route.ts": RESET_NO_EXPIRY,
      "app/page.tsx": "export default function P() { return null; }\n",
    }));
    expect(r.executedProbes).toContain("missing-checks");
    const ours = r.findings.filter((f) => f.templateId in MISSING_CHECK_RULES).map((f) => [f.templateId, f.file, f.line, f.confidence]).sort();
    expect(ours).toEqual([
      [RESET_EXPIRY_RULE, "app/api/reset/route.ts", 3, "potential"],
      [WEBHOOK_RULE, "app/api/webhooks/stripe/route.ts", 5, "likely"],
    ]);
    expect(exitCodeOf(r)).toBe(1);
    expect(r.incomplete).toBeUndefined();
  });
  it("explain_finding knows all five ids, and the plan has a specific fix for each", async () => {
    const tool = TOOL_BY_NAME.get("explain_finding");
    for (const [id, category] of Object.entries(MISSING_CHECK_RULES)) {
      const r = (await tool.run({ id })).structured;
      expect(r.known, id).toBe(true);
      expect(r.category).toBe(category);
      expect(r.limits).toEqual([]);
      expect(r.references.length).toBeGreaterThan(0);
      expect(buildActionPlan([{ severity: "high", templateId: id, category, title: "x" }])[0].id).toBe(id);
    }
  });
});

// ── linear time on crafted input (checklist rows 4, 15, 17, 20) ───────────
// Measured by the doubling method: 8x the input should cost about 8x the time;
// the bound is loose so parallel CI does not flake.

describe("the rules stay linear on crafted input", () => {
  // Two warm-up runs (so both sizes run optimized code), then the fastest of five.
  const grows = (gen) => {
    const ms = (n) => {
      const src = gen(n);
      for (let k = 0; k < 2; k++) missingCheckHits(src, "app/api/webhooks/route.ts");
      let best = Infinity;
      for (let k = 0; k < 5; k++) { const s = process.hrtime.bigint(); missingCheckHits(src, "app/api/webhooks/route.ts"); best = Math.min(best, Number(process.hrtime.bigint() - s) / 1e6); }
      return best;
    };
    // The best of three attempts: a GC pause or a busy CI core inflates one, never all three.
    let ratio = Infinity;
    for (let a = 0; a < 3 && ratio >= 24; a++) ratio = Math.min(ratio, ms(32000) / Math.max(ms(4000), 0.5));
    return ratio;
  };
  const cases = {
    "nested comparisons": (n) => `if (${"(req.headers.authorization === ".repeat(n)}apiSecret${")".repeat(n)}) x();\n`,
    "a long chain of comparisons": (n) => `if (req.headers.authorization ${"=== apiSecret ".repeat(n / 4)}) x();\n`,
    "comparisons with long bracketed operands": (n) => `${"f(" + "a,".repeat(50) + ") === g(" + "b,".repeat(50) + ")\n"}`.repeat(n / 20),
    "declarations without semicolons or line ends": (n) => `${"const a = b + \n".repeat(n)}`,
    "declarations with whitespace runs": (n) => `const x =${" \n".repeat(n)}1\n`,
    "long identifiers": (n) => `const ${"k".repeat(n * 4)} = req.body.${"v".repeat(n * 4)};\nif (${"s".repeat(n * 4)}Secret === ${"t".repeat(n * 4)}) x();\n`,
    "many writes with many keys": (n) => `const body = await req.json();\n${"prisma.user.update({ data: { name: x, plan: y, metadata: { a: 1 }, ...z } });\n".repeat(n / 20)}prisma.user.update({ data: { role: body.role } });\n${""}`,
    "nested metadata objects": (n) => `const { amount } = await req.json();\nstripe.checkout.sessions.create({ ${"metadata: { ".repeat(n / 4)}${"}".repeat(n / 4)}, ${"amount: 1, ".repeat(n / 4)} });\n`,
    "many webhook route registrations": (n) => `${"app.post(\"/webhook\", h);\n".repeat(n / 10)}const e = req.body; e.type; db.order.update({});\n`,
    "many decode calls": (n) => `${"jwt.decode(req.headers.authorization);\n".repeat(n / 10)}`,
    "many spreads in one call": (n) => `const body = await req.json();\nprisma.user.update({ data: { ${"...a, ".repeat(n / 2)} } });\n`,
    "a long spaced member chain with no write at its end": (n) => `const e = await req.json(); e.type;\n${"prisma" + " .\n a".repeat(n / 2)} ;\n`,
    "a long uncalled name with repeated admin markers": (n) => `const body = await req.json();\nprisma.user.update({ data: { role: body.role } });\nconst x = is${"Admin".repeat(n / 5)};\nconst y = require${"RoleOwner".repeat(n / 9)} ;\n`,
    "many short calls that are not admin checks": (n) => `const body = await req.json();\nprisma.user.update({ data: { role: body.role } });\n${"isReady(a); hasItems(b);\n".repeat(n / 25)}`,
    "an unclosed destructuring and call at the end": (n) => `const body = await req.json();\n${"const { a, b\n".repeat(n / 4)}prisma.user.create({ data: body `,
  };
  for (const [name, gen] of Object.entries(cases)) {
    it(name, () => {
      expect(grows(gen)).toBeLessThan(24);
    });
  }
  it("the crafted cases above are still read: findings, or an incomplete mark", () => {
    expect(missingCheckHits(cases["a long uncalled name with repeated admin markers"](4000), "server/c.js").hits[CLIENT_VALUE_RULE]).toBeDefined();
    expect(missingCheckHits(cases["nested comparisons"](200), "server/a.js").hits[TIMING_RULE]).toBeDefined();
    expect(missingCheckHits(cases["many writes with many keys"](200), "server/b.js").hits[CLIENT_VALUE_RULE]).toBeDefined();
  });
});
