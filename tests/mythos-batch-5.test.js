/**
 * Mythos deep assessment for 2.5 (12 Nov 2026), batch 5: cron routes without a
 * secret (C1), secrets with a literal fallback and connection strings (C3, A9),
 * and the December 2025 React and Next.js advisories, checked at the source (E).
 * Every snippet is inert text.
 */
import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { scanCronRoutes } from "../lib/whitebox/cron-routes.js";
import { findSecretsInText, scanSecrets, maskHit } from "../lib/whitebox/secrets.js";
import { redactCommand } from "../lib/agents/redact.js";
import { frameworkAdvisoriesForRepo } from "../lib/whitebox/framework-advisories.js";
import { maskSecrets } from "../lib/ai/units.js";

const repo = (files) => {
  const dir = mkdtempSync(join(tmpdir(), "penthera-mythos5-"));
  for (const [rel, text] of Object.entries(files)) { mkdirSync(dirname(join(dir, rel)), { recursive: true }); writeFileSync(join(dir, rel), text); }
  return dir;
};
const cron = (route) => scanCronRoutes(repo({ "vercel.json": JSON.stringify({ crons: [{ path: "/api/cron/cleanup", schedule: "0 3 * * *" }] }), "app/api/cron/cleanup/route.ts": route }));
const names = (t, p) => findSecretsInText(t, p).map((h) => h.name);

describe("C1: cron-route-no-secret", () => {
  it("a scheduled route that deletes rows and checks nothing is high", () => {
    expect(cron("export async function GET() { await db.session.deleteMany({ where: { expired: true } }); }")).toEqual([expect.objectContaining({ templateId: "cron-route-no-secret", severity: "high" })]);
  });
  it("reading the header only to log it is no check; CRON_SECRET in a comment is no check", () => {
    expect(cron('export async function GET(request) { console.log(request.headers.get("authorization")); await db.user.updateMany({ data: { x: 1 } }); }')).toHaveLength(1);
    expect(cron("// uses CRON_SECRET\nexport async function GET() { await db.x.deleteMany(); }")).toHaveLength(1);
  });
  it("Vercel's documented check and QStash's verify count", () => {
    expect(cron('export async function GET(req) {\n  const authHeader = req.headers.get("authorization");\n  if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) return new Response("Unauthorized", { status: 401 });\n  await db.x.deleteMany();\n}')).toEqual([]);
    expect(cron('import { verifySignatureAppRouter } from "@upstash/qstash/nextjs";\nasync function handler() { await db.x.deleteMany(); }\nexport const POST = verifySignatureAppRouter(handler);')).toEqual([]);
  });
  it("multi-line compares, a secret in a constant, and env modules count (blind review)", () => {
    expect(cron('export async function GET(request) {\n  if (\n    request.headers.get("authorization") !==\n    `Bearer ${process.env.CRON_SECRET}`\n  ) return new Response("no", { status: 401 });\n  await db.x.deleteMany();\n}')).toEqual([]);
    expect(cron('import { env } from "@/env";\nexport async function GET(req) {\n  const expected = `Bearer ${env.CRON_SECRET}`;\n  if (req.headers.get("authorization") !== expected) return;\n  await db.x.deleteMany();\n}')).toEqual([]);
  });
  it("`CRON_SECRET === undefined` is no check; a wrapped handler is only potential", () => {
    expect(cron("export async function GET() { if (process.env.CRON_SECRET === undefined) throw new Error(); await db.x.deleteMany(); }")).toHaveLength(1);
    expect(cron("async function handler() { await db.x.deleteMany(); }\nexport const GET = withCron(handler);")[0].confidence).toBe("potential");
  });
  it("a route with no write is medium; no vercel.json, no finding", () => {
    expect(cron("export async function GET() { return Response.json({ ok: true }); }")[0].severity).toBe("medium");
    expect(scanCronRoutes(repo({ "app/api/cron/x/route.ts": "export function GET() {}" }))).toEqual([]);
  });
  it("malformed vercel.json never quotes the file in the report (Vercel 01M81PYAGR2ECHQW3YKG0KCNKG)", () => {
    const refused = [];
    scanCronRoutes(repo({ "vercel.json": '{ "env": { "API_KEY": s3cr3tValue9x }, "crons": [] }' }), { refused });
    expect(refused).toHaveLength(1);
    expect(JSON.stringify(refused)).not.toContain("s3cr3tValue9x");
    expect(refused[0].reason).toMatch(/^it is not valid JSON/);
  });
  it("a cron path cannot climb out of the repository", () => {
    expect(scanCronRoutes(repo({ "vercel.json": JSON.stringify({ crons: [{ path: "/../../etc/passwd" }] }) }))).toEqual([]);
  });
});

describe("C3 and A9: secrets in fallbacks, signing calls and connection strings", () => {
  it("finds them", () => {
    expect(names("DATABASE_URL=postgresql://app:Zq8vT2mK9pLx@db.prod-eu.internal:5432/app", ".env.production")).toContain("Connection string password");
    expect(names('const s = process.env.NEXTAUTH_SECRET ?? "changeme";', "auth.ts")).toContain("Secret with a hardcoded fallback");
    expect(names('const t = jwt.sign({ id }, "hunter2-signing-key");', "login.ts")).toContain("JWT signed with a hardcoded key");
  });
  it("leaves local databases, placeholders, non-secret fallbacks and env keys alone", () => {
    for (const [t, p] of [
      ["process.env.TOKEN_URL || 'https://auth.example.com/token'", "a.ts"],
      ["process.env.PASSWORD_MIN_LENGTH || '12345678'", "a.ts"],
      ["process.env.API_KEY_HEADER || 'x-api-key'", "a.ts"],
      ['jwt.sign({ sub }, key, "HS256-ignored")', "a.ts"],
      ["postgres://app:<password>@db.prod.io/x", "a.ts"],
      ["DATABASE_URL=postgres://postgres:postgres@localhost:5432/dev", ".env"],
      ["DATABASE_URL=postgresql://app:${DB_PASSWORD}@db.prod.internal/app", ".env"],
      ['const port = process.env.PORT || "3000";', "server.ts"],
      ['const s = process.env.JWT_SECRET || throwMissing("JWT_SECRET");', "auth.ts"],
      ["const t = jwt.sign({ id }, process.env.JWT_SECRET);", "login.ts"],
    ]) expect(names(t, p), t).toEqual([]);
  });
});

describe("reports never show the new rules' secrets (Vercel 01M81FJ4Z1BKB702S4D86ZCH7Y)", () => {
  it("padded base64 keys and short values are masked in every finding", () => {
    const key = "Zm9vYmFyYmF6cXV4c2VjcmV0a2V5MTIzNDU2Nzg5MA==";
    const short = "q7Zp=9xK";
    const dir = repo({
      "a.ts": `const s = process.env.JWT_SECRET || "${key}";\n`,
      "b.ts": `const t = jwt.sign({ id }, "${key}");\n`,
      "c.ts": `const s = process.env.NEXTAUTH_SECRET ?? "${short}";\n`,
      ".env.production": `DATABASE_URL=postgresql://app:${key}@db.prod-eu.internal:5432/app\n`,
    });
    const found = scanSecrets(dir);
    const out = JSON.stringify(found);
    expect((found.findings || found).length).toBe(4);
    expect(out).not.toContain(key.slice(4, 30));
    expect(out).not.toContain(short);
  });
});

describe("AI mode masks the new rules' secrets on every line (Vercel 01M81HVP4086BNAWR7C5ADFHQY)", () => {
  const key = "Zm9vYmFyYmF6cXV4c2VjcmV0a2V5MTIzNDU2Nzg5MA==";
  for (const t of [`const t = jwt.sign(\n  { id },\n  "${key}"\n);`, `const s =\n  process.env.JWT_SECRET ||\n  "${key}";`]) {
    it(JSON.stringify(t.slice(0, 30)), () => expect(JSON.stringify(maskSecrets(t))).not.toContain(key.slice(4, 30)));
  }
});

describe("every report masks the new rules' keys the same way (Vercel 01M81JGZCS866JD4VKND9YD7B8)", () => {
  const key = "Zm9vYmFyYmF6cXV4c2VjcmV0a2V5MTIzNDU2Nzg5MA==";
  it("maskHit hides a padded key in a fallback and a signing call (the hook, bundle and agent paths use it)", () => {
    for (const t of [`const s = process.env.JWT_SECRET || "${key}";`, `jwt.sign({ id }, "${key}")`]) {
      for (const h of findSecretsInText(t, { path: "a.ts" })) expect(maskHit(h), t).not.toContain(key.slice(4, 30));
    }
  });
  it("the agent redactor hides the key in a command", () => {
    expect(redactCommand(`node -e 'jwt.sign({ id }, "${key}")'`)).not.toContain(key.slice(4, 30));
  });
});

describe("E: the December 2025 React Server Components advisory", () => {
  const lock = (next) => JSON.stringify({ lockfileVersion: 3, packages: { "": { dependencies: { next } }, "node_modules/next": { version: next } } }, null, 2);
  it("15.5.7 (the CVE-2025-55182 fix) is still affected, high with an app folder", () => {
    const f = frameworkAdvisoriesForRepo(repo({ "package-lock.json": lock("15.5.7"), "app/page.tsx": "export default function P() { return null; }" }));
    expect(f.find((x) => x.description.includes("CVE-2025-55184"))).toMatchObject({ severity: "high" });
  });
  it("15.5.9 is fixed; without an app folder the row is low", () => {
    expect(frameworkAdvisoriesForRepo(repo({ "package-lock.json": lock("15.5.9"), "app/page.tsx": "" })).some((x) => x.description.includes("CVE-2025-55184"))).toBe(false);
    expect(frameworkAdvisoriesForRepo(repo({ "package-lock.json": lock("15.5.8") })).find((x) => x.description.includes("CVE-2025-55184"))).toMatchObject({ severity: "low" });
  });
});
