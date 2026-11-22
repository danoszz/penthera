/**
 * Mythos deep assessment for 2.5 (12 Nov 2026), batch 2: one shared auth reader.
 *   A2  any get/is/with + User/Account/... call counted as an auth check
 *   A3  a middleware helper named like a check lowered every Server Action to medium
 *   A7  webhook and JWT silencers fired on unrelated names (checklist row 24)
 *   B6  route records read auth from raw text (comments, fields) with their own list
 * Every snippet is inert text; nothing runs.
 */
import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { callsAuth, authShaped } from "../lib/whitebox/auth-calls.js";
import { uncheckedActions, scanServerActions } from "../lib/whitebox/server-actions.js";
import { missingCheckHits } from "../lib/whitebox/missing-checks.js";
import { routeRecord } from "../lib/attack-surface.js";

const unchecked = (src) => uncheckedActions(src).hits.map((h) => h.name);
const repo = (files) => {
  const dir = mkdtempSync(join(tmpdir(), "penthera-mythos2-"));
  for (const [rel, text] of Object.entries(files)) { mkdirSync(dirname(join(dir, rel)), { recursive: true }); writeFileSync(join(dir, rel), text); }
  return dir;
};
const ruleIds = (src, rel) => Object.keys(missingCheckHits(src, rel).hits || {});

describe("A2: a lookup named like a user is not an auth check", () => {
  for (const call of ["await getUserById(id)", "await getAccountSettings(id)", "isLoginEnabled()", "await db.getUserCount()", "getUserLocale(req)", "isLoginPage(p)", "getAuthorName()"]) {
    it(`${call} does not silence a delete`, () => {
      expect(unchecked(`"use server";\nexport async function wipe(id) { ${call}; await db.user.delete({ where: { id } }); }\n`)).toEqual(["wipe"]);
    });
  }
  for (const call of ["await auth()", "await getServerSession(authOptions)", "await getUser()", "await currentUser()", "await requireOrgMember(id)", "await getCurrentUser()", "await getSessionUser()", "await validateRequest()", "await ctx.getUser()", "await supabase.auth.getUser()", "isAuthenticated()"]) {
    it(`${call} still counts`, () => expect(callsAuth(call)).toBe(true));
  }
  it("supabase.auth.getSession() is still no check", () => expect(callsAuth("await supabase.auth.getSession()")).toBe(false));
  it("shapes", () => {
    expect(authShaped("verifyAdminSession")).toBe(true);
    expect(authShaped("getUserById")).toBe(false);
    expect(authShaped("withAuth")).toBe(true);
    expect(authShaped("getAuthorName")).toBe(false);
  });
});

describe("A3: middleware never lowers a Server Action finding", () => {
  const action = `"use server";\nexport async function wipe(id) { await db.user.delete({ where: { id } }); }\n`;
  for (const mw of ["export function middleware(req) { const l = getUserLocale(req); }", "export function middleware(req) { if (isLoginPage(req.nextUrl.pathname)) return; }", 'import { auth } from "@/auth";\nexport default auth((req) => {});\n']) {
    it(`stays high next to: ${mw.slice(0, 50)}`, () => {
      expect(scanServerActions(repo({ "app/actions.ts": action, "middleware.ts": mw })).map((f) => f.severity)).toEqual(["high"]);
    });
  }
});

describe("A7: silencers are tied to the protected value (row 24)", () => {
  const webhook = (extra) => `export async function POST(req) {\n  const body = await req.json();\n  ${extra}\n  if (body.type === "checkout.session.completed") await prisma.order.update({ where: { id: 1 }, data: { plan: "pro" } });\n}\n`;
  for (const decoy of ["await sendVerificationEmail(u);", "const r = result.unwrap();", "const s = process.env.STRIPE_WEBHOOK_SECRET;", "const endpointSecret = cfg.endpoint;", "const u = await getUser(id);", "await verifyCaptcha(x);"]) {
    it(`webhook still reported next to: ${decoy}`, () => {
      expect(ruleIds(webhook(decoy), "app/api/webhooks/stripe/route.ts")).toContain("webhook-signature-missing");
    });
  }
  for (const check of ['stripe.webhooks.constructEvent(raw, req.headers.get("stripe-signature"), secret);', "await verifyWebhook(req);", "const evt = new Webhook(key).verify(payload, headers);", 'if (req.headers.get("x-sig") !== process.env.WEBHOOK_SECRET) return;']) {
    it(`webhook quiet with: ${check.slice(0, 50)}`, () => {
      expect(ruleIds(webhook(check), "app/api/webhooks/stripe/route.ts")).not.toContain("webhook-signature-missing");
    });
  }
  const jwtRoute = (extra) => `import jwt from "jsonwebtoken";\nexport async function GET(req) {\n  const token = req.headers.get("authorization");\n  const p = jwt.decode(token);\n  ${extra}\n  return Response.json(p);\n}\n`;
  for (const decoy of ["await verifyCaptcha(x);", "const u = await getUser(p.sub);"]) {
    it(`jwt.decode still reported next to: ${decoy}`, () => {
      expect(ruleIds(jwtRoute(decoy), "app/api/me/route.ts")).toContain("jwt-decode-unverified");
    });
  }
  it("jwt.decode quiet when the token is verified", () => {
    expect(ruleIds(jwtRoute("jwt.verify(token, process.env.JWT_SECRET);"), "app/api/me/route.ts")).not.toContain("jwt-decode-unverified");
  });
});

describe("the relay's no-loss gate (22 Nov): a client builder and a login URL are no check", () => {
  for (const l of ["createSafeActionClient()", "getLoginUrl()"]) {
    it(`a Server Action with ${l} is still reported`, () => expect(unchecked(`"use server";\nexport async function wipe(id) { ${l}; await db.post.delete({ where: { id } }); }\n`)).toEqual(["wipe"]));
  }
  it("a route that only builds a client or a login URL stays public", () => {
    for (const l of ["const actionClient = createSafeActionClient();", "const loginUrl = getLoginUrl();"]) {
      expect(routeRecord("/api/stripe", "app/api/stripe/route.ts", `export async function POST(req) { ${l} const event = await req.json(); }`, ["POST"]).auth, l).toContain("public");
    }
  });
});

describe("B6: route records read auth from code, with the shared reader", () => {
  const rec = (src) => routeRecord("/api/x", "app/api/x/route.ts", src, ["POST"]).auth;
  it("Clerk's auth(), Lucia's validateRequest() and a bare getUser() are user routes", () => {
    for (const c of ["const { userId } = await auth();", "const { user } = await validateRequest();", "const u = await getUser();"]) {
      expect(rec(`export async function POST(req) { ${c} return Response.json(1); }`), c).toContain("user");
    }
  });
  it("a comment saying requireAuth or a field named isAdmin is no check", () => {
    expect(rec("// TODO: requireAuth\nexport async function POST(req) { const { isAdmin } = await req.json(); return Response.json(isAdmin); }")).toEqual(["public"]);
  });
});

// The blind review of the first draft (22 Nov): the shared reader must not be looser than main.
describe("blind review: no new silencers, and real helpers still count", () => {
  const act = (l) => uncheckedActions(`"use server";\nexport async function deletePost(id) { ${l}; await db.post.delete({ where: { id } }); }\n`).hits.length;
  const wh = (l) => ruleIds(`export async function POST(req) {\n  const body = await req.json();\n  ${l}\n  if (body.type === "checkout.session.completed") await prisma.order.update({ where: { id: 1 }, data: { plan: "pro" } });\n}\n`, "app/api/webhooks/stripe/route.ts").includes("webhook-signature-missing");
  const jwt = (l) => ruleIds(`export async function GET(req) {\n  const t = req.headers.get("authorization");\n  const p = jwtDecode(t);\n  ${l}\n  return Response.json(p);\n}\n`, "app/api/me/route.ts").includes("jwt-decode-unverified");
  for (const l of ["getCurrentTime()", "getCurrentLocale()", "isAllowedFileType(id)", "csrf.getToken()", "turnstile.verifyToken(id)", "messaging.getToken()", "getUser(req.body.id)", "getUser(ctx.userId)"]) {
    it(`action still reported with ${l}`, () => expect(act(l)).toBe(1));
  }
  for (const l of ["await getLoggedInUser()", "await getUserFromRequest()", "await getServerUser()", "await getUserRole()", "await getPermissions()", "await withRole('admin')", "await getUserOrRedirect()", "await getUser(cookieStore)", "await getSession({ req })", "await sessionStore.getSession(id)", "await lucia.validateSession(sid)", "await getUser(cookies())"]) {
    it(`action quiet with ${l}`, () => expect(act(l)).toBe(0));
  }
  for (const l of ["validateSchema(body);", "isAllowedEvent(body.type);", "ensureAccount(cust);", "messaging.getToken();", "if (!process.env.STRIPE_WEBHOOK_SECRET) throw new Error('x');", "console.log(process.env.STRIPE_WEBHOOK_SECRET);", "if (process.env.STRIPE_WEBHOOK_SECRET === undefined) throw new Error('x');", "const s = 'STRIPE_WEBHOOK_SECRET !== x';"]) {
    it(`webhook still reported with ${l}`, () => expect(wh(l)).toBe(true));
  }
  // Vercel review of PR 336 (rows 37 and 38 of VERCEL-FINDINGS).
  for (const l of ["const sig = getSignature(req.headers);", "const h = parseHmac(req.headers);", "const c = createSafeActionClient();", "const u = getLoginUrl();"]) {
    it(`webhook still reported with ${l} (Vercel)`, () => expect(wh(l)).toBe(true));
  }
  for (const l of ["schema.validateRequest(body, rules);", "parser.unmarshal(body, Type);", "ajv.verify(body, schema);", "verify(body, schema);"]) {
    it(`webhook still reported with a non-provider ${l} (Vercel 01M81FRYFRKZAB8Q9RW8QKF81Z)`, () => expect(wh(l)).toBe(true));
  }
  for (const l of ["verifyKey(payload, ts, pk);", "wh.verify(payload, heads);", 'crypto.verify("sha256", Buffer.from(payload), pk, sigBuf);', "paddle.webhooks.unmarshal(payload, key, s);", "twilio.validateRequest(tok, s, url, params);", "webhooks.verify(payload, s);"]) {
    it(`webhook quiet with a provider verifier: ${l}`, () => expect(wh(l)).toBe(false));
  }
  it("webhook quiet with a signature verify that takes the secret", () => expect(wh("verifySignature(raw, sig, process.env.STRIPE_WEBHOOK_SECRET);")).toBe(false));
  it("jwt: Supabase's auth.getUser(t) verifies; verifyCaptchaToken does not", () => {
    expect(jwt("const u = await supabase.auth.getUser(t);")).toBe(false);
    expect(jwt("await verifyCaptchaToken(t);")).toBe(true);
  });
});
