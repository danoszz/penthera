/**
 * Two silencers from the Vercel Security Review of PR 336, both on main after
 * its merge: a look-alike that hid a real finding.
 *
 *   01M81PBRJJ5C07J1NH17QHFR9Q  webhook rule: a raw body as the only argument tied a validate-like call to the request
 *   01M81PB5WDGJQ1DDKSH1SS3VPX  auth reader: `.validateRequest(` and `.validateSession(` on any object counted as a session check
 *
 * Each "hides nothing" case reported no finding on main before the fix.
 */
import { describe, it, expect } from "vitest";
import { missingCheckHits, WEBHOOK_RULE } from "../lib/whitebox/missing-checks.js";
import { uncheckedActions } from "../lib/whitebox/server-actions.js";
import { isAuthCall, callsAuth } from "../lib/whitebox/auth-calls.js";

const hook = (line) => `export async function POST(req) {\n  const rawBody = await req.text();\n  ${line}\n  const event = JSON.parse(rawBody);\n  if (event.type === "invoice.paid") { await db.user.update({ where: { id: event.userId }, data: { plan: "pro" } }); }\n  return new Response("ok");\n}\n`;
const unsigned = (line) => Object.keys(missingCheckHits(hook(line), "app/api/webhook/route.ts").hits).includes(WEBHOOK_RULE);
const action = (line) => `"use server";\nexport async function deletePost(id) {\n  ${line}\n  await prisma.post.delete({ where: { id } });\n}\n`;
const unchecked = (line) => uncheckedActions(action(line)).hits.length > 0;

describe("webhook rule: a raw body alone ties nothing to the sender (01M81PBRJJ5C07J1NH17QHFR9Q)", () => {
  it("the plain handler is reported", () => {
    expect(unsigned("")).toBe(true);
  });

  it("a validate-like call on the raw body hides nothing", () => {
    for (const line of [
      "validate(JSON.parse(rawBody));",
      "const ok = validatePayload(rawBody);",
      "verifyShape(raw_body);",
      "await verifyJson(rawBody);",
      "const parsed = unwrapBody(rawBody);",
      "payloads.validate(rawBody);",
      "validate(rawBody, bodySchema);",
    ]) expect(unsigned(line), line).toBe(true);
  });

  it("a verifier that takes the signature, the secret or the headers still counts", () => {
    for (const line of [
      'await verifyWebhook(rawBody, req.headers.get("x-signature"), process.env.WEBHOOK_SECRET);',
      "const ok = verify(rawBody, signature);",
      "await verifyRequest(rawBody, secret);",
      "if (!validatePayload(rawBody, req.headers)) return;",
      "wh.verify(rawBody, headers);",
      "stripe.webhooks.constructEvent(rawBody, sig, secret);",
      "validateSignature(rawBody);",
      "const expected = createHmac(\"sha256\", key).update(rawBody).digest(\"hex\");",
    ]) expect(unsigned(line), line).toBe(false);
  });
});

describe("webhook rule: a schema validator is no session check either (blind review of this fix)", () => {
  it("a bare validateRequest(body, schema) hides nothing; a session reader still marks a user route", () => {
    expect(unsigned("validateRequest(JSON.parse(rawBody), EventSchema);")).toBe(true);
    expect(unsigned("const { user } = await validateRequest();")).toBe(false);
    expect(unsigned("const session = await getServerSession(authOptions);")).toBe(false);
  });
});

describe("auth reader: validateRequest and validateSession on any object (01M81PB5WDGJQ1DDKSH1SS3VPX)", () => {
  it("the plain action is reported", () => {
    expect(unchecked("")).toBe(true);
  });

  it("a validator on a schema, a form or an unknown object hides nothing", () => {
    for (const line of [
      "schema.validateRequest(id);",
      "await validator.validateSession(id);",
      "ajv.validateRequest({ id });",
      "author.validateRequest(id);",
      "this.schema.validateRequest(id);",
      "forms?.validateRequest(id);",
      "await getValidator().validateRequest(id);",
      "validators[0].validateSession(id);",
    ]) expect(unchecked(line), line).toBe(true);
  });

  it("a bare validateRequest with a second argument that is not the request hides nothing", () => {
    for (const line of ["validateRequest(id, schema);", "validateRequest({ id }, PostSchema);", `validateRequest(z.object({ ${"field: z.string().min(1).max(64), ".repeat(8)} }), { id });`]) expect(unchecked(line), line).toBe(true);
  });

  it("Lucia and the like still count: on an object named like auth, or bare", () => {
    for (const line of [
      "const { user } = await lucia.validateSession(sessionId);",
      "const { session } = await auth.validateRequest();",
      "await this.auth.validateSession(token);",
      "await authService.validateRequest();",
      "const s = await sessionManager.validateSession(token);",
      "await ctx.auth?.validateRequest();",
      "await auth.api.validateRequest();",
      "await locals.lucia.validateSession(id);",
      "const s = await validateSession(token, { fresh: true });",
      "const { user } = await validateRequest();",
      "await validateRequest(req, res);",
      "const s = await validateSession(token);",
    ]) expect(unchecked(line), line).toBe(false);
  });

  it("the other names on an object keep their reading", () => {
    expect(unchecked("const s = await ctx.getSession();")).toBe(false);
    expect(unchecked("const u = await db.getUser(id);")).toBe(true);
    expect(unchecked("await csrf.getToken();")).toBe(true);
  });

  it("isAuthCall and callsAuth agree with the rule", () => {
    const at = (text, name) => { const i = text.indexOf(name); return isAuthCall(text, name, i, i + name.length + 1); };
    expect(at("schema.validateRequest(x)", "validateRequest")).toBe(false);
    expect(at("lucia.validateSession(id)", "validateSession")).toBe(true);
    expect(at("validateRequest(body, schema)", "validateRequest")).toBe(false);
    expect(at("validateRequest()", "validateRequest")).toBe(true);
    expect(callsAuth("const r = schema.validateRequest(input);")).toBe(false);
    expect(callsAuth("const r = await auth.validateRequest();")).toBe(true);
  });

  it("reads a long receiver and long arguments in bounded steps", () => {
    const long = "a".repeat(200000);
    const text = `${long}.validateRequest(${long}, ${long});\n`.repeat(8);
    const s = performance.now();
    expect(callsAuth(text)).toBe(false);
    expect(performance.now() - s).toBeLessThan(2000);
  });
});
