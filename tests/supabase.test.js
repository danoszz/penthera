/**
 * Supabase checks (lib/whitebox/supabase.js): a service-role key that reaches
 * the browser, and tables without row-level security in migrations.
 *
 * Every key here is built at run time from made-up claims and a made-up
 * signature, so nothing in this file is a key, and the repo's own scan stays
 * clean. Each rule has a match and a no-match case; the BYPASS-CHECKLIST rows
 * (chunk edges, caps, refusals, budgets, linear time) have their own block.
 */
import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { execFileSync } from "node:child_process";
import { scanSupabase, findServiceKeys, checkMigrations, sqlTokens, alwaysTrue, directiveOf, exposedSchemas, isServiceRoleName } from "../lib/whitebox/supabase.js";
import { scanRepo } from "../src/scan-repo.js";
import { cpuMs } from "./fixtures/cpu-time.js";

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const SIG = "ZmFrZS1zaWduYXR1cmUtZm9yLWEtdGVzdC1maXh0dXJl";
const jwt = (claims) => `${b64({ alg: "HS256", typ: "JWT" })}.${b64(claims)}.${SIG}`;
const SERVICE = jwt({ iss: "supabase", ref: "abcdefghijklmnop", role: "service_role", iat: 1700000000, exp: 2000000000 });
const ANON = jwt({ iss: "supabase", ref: "abcdefghijklmnop", role: "anon", iat: 1700000000, exp: 2000000000 });
const DEMO = jwt({ iss: "supabase-demo", role: "service_role", exp: 1983812996 });
// The new-style secret key: prefix plus a made-up body.
const SB_SECRET = ["sb", "secret", "Qm9ndXNLZXlGb3JUZXN0c09ubHk1"].join("_");
// Env names built from parts, so this file holds none of them whole.
const PUB = (p) => `${p}SUPABASE_SERVICE_ROLE_KEY`;
const SERVER_NAME = ["SUPABASE", "SERVICE", "ROLE", "KEY"].join("_");

function repo(files, { pkg = null } = {}) {
  const root = mkdtempSync(join(tmpdir(), "penthera-supabase-"));
  if (pkg) writeFileSync(join(root, "package.json"), JSON.stringify(pkg));
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), text);
  }
  return root;
}
const VITE = { dependencies: { vite: "5.4.0", "@supabase/supabase-js": "2.45.0" } };
const NEXT = { dependencies: { next: "15.0.0", "@supabase/supabase-js": "2.45.0" } };
const hits = (root, opts) => scanSupabase(root, opts).findings.map((f) => `${f.templateId}:${f.severity}:${f.file}:${f.line}`);

describe("findServiceKeys", () => {
  it("finds a JWT that claims role service_role, and only that one", () => {
    const found = findServiceKeys(`const a = "${ANON}";\nconst s = "${SERVICE}";\n`);
    expect(found).toHaveLength(1);
    expect(found[0].kind).toBe("jwt");
    expect(found[0].demo).toBe(false);
  });

  it("marks the well-known local key (iss supabase-demo)", () => {
    expect(findServiceKeys(`k=${DEMO}`)[0].demo).toBe(true);
  });

  it("finds an sb_secret_ key and skips placeholders", () => {
    expect(findServiceKeys(`KEY=${SB_SECRET}`).map((h) => h.kind)).toEqual(["secret"]);
    expect(findServiceKeys("KEY=sb_secret_xxxxxxxxxxxxxxxxxxxx\nKEY=sb_secret_your-secret-key-here")).toEqual([]);
  });

  it("still sees the claim when the payload isn't valid JSON (the text check runs first)", () => {
    const broken = `${b64({ alg: "HS256" })}.${Buffer.from('{"role":"service_role","iss":').toString("base64url")}.${SIG}`;
    expect(findServiceKeys(broken)).toHaveLength(1);
  });

  it("stays linear on runs of eyJ and dotted segments (row 15)", () => {
    const runs = "eyJ".repeat(700_000);
    const dots = "eyJabc.".repeat(300_000);
    expect(cpuMs(() => findServiceKeys(runs), { runs: 3 })).toBeLessThan(1500);
    expect(cpuMs(() => findServiceKeys(dots), { runs: 3 })).toBeLessThan(1500);
  });
});

describe("supabase-service-role-exposed", () => {
  it("flags a service-role key in a Vite app's src/ as critical", () => {
    const root = repo({ "src/integrations/supabase/client.ts": `import { createClient } from "@supabase/supabase-js";\nexport const supabase = createClient("https://abcdefghijklmnop.supabase.co", "${SERVICE}");\n` }, { pkg: VITE });
    expect(hits(root)).toEqual(["supabase-service-role-exposed:critical:src/integrations/supabase/client.ts:2"]);
  });

  it("flags a key in a Next.js \"use client\" component, and in a file it imports", () => {
    const root = repo({
      "app/page.tsx": `// a comment first\n"use client";\nimport { admin } from "@/lib/admin";\nexport default function P() { return admin; }\n`,
      "src/lib/admin.ts": `export const admin = "${SERVICE}";\n`,
    }, { pkg: NEXT });
    expect(hits(root)).toEqual(["supabase-service-role-exposed:critical:src/lib/admin.ts:1"]);
  });

  it("reports a key in Next.js server-only code as committed, not exposed", () => {
    const root = repo({
      "app/api/admin/route.ts": `export const key = "${SERVICE}";\n`,
      "lib/admin.ts": `import "server-only";\nexport const key = "${SERVICE}";\n`,
      "app/page.tsx": `"use client";\nimport { key } from "../lib/admin";\n`,
    }, { pkg: NEXT });
    expect(hits(root).sort()).toEqual([
      "supabase-service-role-committed:high:app/api/admin/route.ts:1",
      "supabase-service-role-committed:high:lib/admin.ts:2",
    ]);
  });

  it("flags a service-role key assigned to a public env name, even in a file git ignores", () => {
    const root = repo({ ".env.local": `NEXT_PUBLIC_SUPABASE_ANON_KEY=${SERVICE}\n` });
    const ignored = { dirs: new Set(), files: new Set([join(root, ".env.local")]) };
    const f = scanSupabase(root, { ignored }).findings;
    expect(f.map((x) => `${x.templateId}:${x.severity}`)).toEqual(["supabase-service-role-exposed:high"]);
    expect(f[0].description).toContain("NEXT_PUBLIC_SUPABASE_ANON_KEY");
    expect(f[0].description).not.toContain(SERVICE.slice(-20));
  });

  it("flags a public env name for the service-role key", () => {
    const root = repo({ ".env.example": `${PUB("VITE_")}=\n`, "src/a.ts": `const k = process.env.${PUB("NEXT_PUBLIC_")};\n` });
    expect(hits(root).sort()).toEqual([
      "supabase-service-role-exposed:high:.env.example:1",
      "supabase-service-role-exposed:high:src/a.ts:1",
    ]);
  });

  it("reports one finding, not two, for a public name holding the key on one line", () => {
    const root = repo({ ".env": `${PUB("VITE_")}=${SERVICE}\n` });
    expect(hits(root)).toEqual(["supabase-service-role-exposed:critical:.env:1"]);
  });

  it("flags next.config env and vite envPrefix that inline the key", () => {
    const root = repo({
      "next.config.mjs": `export default { env: { ${SERVER_NAME}: process.env.${SERVER_NAME} } };\n`,
      "vite.config.ts": `export default { envPrefix: ["VITE_", "SUPABASE_"] };\n`,
    });
    expect(hits(root).sort()).toEqual([
      "supabase-service-role-exposed:high:next.config.mjs:1",
      "supabase-service-role-exposed:high:vite.config.ts:1",
    ]);
  });

  it("flags client code that reads the server-only name, at potential confidence", () => {
    const root = repo({ "app/x.tsx": `"use client";\nconst k = process.env.${SERVER_NAME};\n` }, { pkg: NEXT });
    const [f] = scanSupabase(root).findings;
    expect([f.templateId, f.severity, f.confidence, f.line]).toEqual(["supabase-service-role-exposed", "medium", "potential", 2]);
  });

  it("reports the local demo key low, at potential confidence", () => {
    const root = repo({ "src/client.ts": `const k = "${DEMO}";\n` }, { pkg: VITE });
    const [f] = scanSupabase(root).findings;
    expect([f.templateId, f.severity, f.confidence]).toEqual(["supabase-service-role-committed", "low", "potential"]);
  });

  it("marks hits in tests as potential, never drops them", () => {
    const root = repo({ "tests/client.test.ts": `const k = "${SERVICE}";\n` }, { pkg: VITE });
    const [f] = scanSupabase(root).findings;
    expect([f.templateId, f.severity, f.confidence]).toEqual(["supabase-service-role-committed", "high", "potential"]);
  });
});

describe("no false alarm", () => {
  it("leaves the anon key in client code alone", () => {
    const root = repo({ "src/client.ts": `createClient(url, "${ANON}");\n`, ".env": `VITE_SUPABASE_ANON_KEY=${ANON}\n` }, { pkg: VITE });
    expect(hits(root)).toEqual([]);
  });

  it("leaves the service-role key read in server code alone", () => {
    const root = repo({
      "app/api/x/route.ts": `const k = process.env.${SERVER_NAME};\n`,
      "supabase/functions/admin/index.ts": `const k = Deno.env.get("${SERVER_NAME}");\n`,
      "app/page.tsx": `export default async function P() { const k = process.env.${SERVER_NAME}; }\n`,
    }, { pkg: NEXT });
    expect(hits(root)).toEqual([]);
  });

  it("leaves a server-only key in a .env that git ignores alone", () => {
    const root = repo({ ".env.local": `${SERVER_NAME}=${SERVICE}\n` });
    const ignored = { dirs: new Set(), files: new Set([join(root, ".env.local")]) };
    expect(hits(root, { ignored })).toEqual([]);
  });

  it("doesn't read docs for env names: a warning in a README is not a leak", () => {
    const root = repo({ "README.md": `Never name it ${PUB("NEXT_PUBLIC_")}.\n` });
    expect(hits(root)).toEqual([]);
  });

  it("doesn't take a key glued to other base64 characters", () => {
    expect(findServiceKeys(`abc${SERVICE}`)).toEqual([]);
  });
});

describe("supabase-rls-disabled", () => {
  const mig = (files, opts) => checkMigrations(Object.entries(files).map(([rel, text]) => ({ rel, text })), opts);
  const tablesOf = (r) => r.findings.filter((f) => f.kind === "rls").map((f) => `${f.table.schema}.${f.table.name}`).sort();

  it("flags a public table that no migration protects", () => {
    expect(tablesOf(mig({ "001.sql": "create table public.profiles (id uuid, email text);\ncreate table todos (id int);" }))).toEqual(["public.profiles", "public.todos"]);
  });

  it("accepts RLS enabled in a later migration, in pg_dump spelling too", () => {
    const r = mig({
      "001.sql": 'CREATE TABLE IF NOT EXISTS "public"."Profiles" ("id" uuid);\ncreate table public.notes (id int);',
      "002.sql": 'ALTER TABLE ONLY "public"."Profiles" ENABLE ROW LEVEL SECURITY;\nalter table if exists notes enable row level security;',
    });
    expect(tablesOf(r)).toEqual([]);
  });

  it("doesn't count RLS named in a comment or a string", () => {
    const r = mig({ "001.sql": "create table public.t (id int);\n-- alter table public.t enable row level security;\n/* alter table public.t enable row level security; */\nselect 'alter table public.t enable row level security';" });
    expect(tablesOf(r)).toEqual(["public.t"]);
  });

  it("follows rename and set schema, and skips private schemas and temp tables", () => {
    const r = mig({ "001.sql": "create table public.a (id int);\nalter table public.a rename to b;\nalter table public.b enable row level security;\ncreate table public.c (id int);\nalter table public.c set schema private;\ncreate temp table t (id int);\ncreate table private.d (id int);" });
    expect(tablesOf(r)).toEqual([]);
  });

  it("uses search_path for unqualified names", () => {
    expect(tablesOf(mig({ "001.sql": "set search_path to internal, public;\ncreate table x (id int);" }))).toEqual([]);
    expect(tablesOf(mig({ "001.sql": "select pg_catalog.set_config('search_path', '', false);\ncreate table public.y (id int);" }))).toEqual(["public.y"]);
  });

  it("reads the exposed schemas from config.toml", () => {
    expect(exposedSchemas('[db]\nport = 1\n[api]\nenabled = true\nschemas = ["public", "api"]\n[auth]\n')).toEqual(["public", "api"]);
    expect(tablesOf(mig({ "001.sql": "create table api.items (id int);" }, { schemas: ["public", "api"] }))).toEqual(["api.items"]);
  });

  it("flags RLS disabled by a later migration, and forgets dropped tables", () => {
    const r = mig({ "001.sql": "create table public.a (id int);\nalter table public.a enable row level security;\ncreate table public.gone (id int);", "002.sql": "alter table public.a disable row level security;\ndrop table if exists public.gone;" });
    expect(tablesOf(r)).toEqual(["public.a"]);
    expect(r.findings[0].table.file).toBe("002.sql");
  });

  it("treats a table anon and authenticated can't reach as not exposed", () => {
    expect(tablesOf(mig({ "001.sql": "create table public.audit (id int);\nrevoke all on table public.audit from anon, authenticated;" }))).toEqual([]);
    expect(tablesOf(mig({ "001.sql": "alter default privileges in schema public revoke all on tables from anon, authenticated;\ncreate table public.logs (id int);" }))).toEqual([]);
    // Revoking from anon alone still leaves every signed-up user.
    expect(tablesOf(mig({ "001.sql": "create table public.audit (id int);\nrevoke all on table public.audit from anon;" }))).toEqual(["public.audit"]);
  });

  it("marks dynamic SQL and a file that ends inside a comment as unchecked, and keeps what came before (row 19)", () => {
    const r = mig({ "001.sql": "create table public.a (id int);\ndo $$ begin execute 'create table public.b (id int)'; end $$;\n/* never closed" });
    expect(tablesOf(r)).toEqual(["public.a"]);
    expect(r.unchecked.map((u) => u.why).sort()).toEqual([expect.stringContaining("function or DO block"), expect.stringContaining("ends inside a comment")]);
  });

  it("RLS turned on in a loop makes the table findings potential, never drops them", () => {
    const root = repo({ "supabase/migrations/001.sql": "create table public.a (id int);\ndo $$ declare t text; begin for t in select tablename from pg_tables where schemaname = 'public' loop execute format('alter table %I enable row level security', t); end loop; end $$;\n" });
    const f = scanSupabase(root).findings.find((x) => x.templateId === "supabase-rls-disabled");
    expect([f.severity, f.confidence]).toEqual(["high", "potential"]);
  });

  it("a statement past the token cap keeps its start and is marked (row 4)", () => {
    const r = mig({ "001.sql": `create table public.wide (${Array.from({ length: 30_000 }, (_, i) => `c${i} int`).join(", ")});` });
    expect(tablesOf(r)).toEqual(["public.wide"]);
    expect(r.unchecked[0].why).toContain("over 20000 tokens");
  });

  it("over the work budget it says so and keeps the findings it has (row 17)", () => {
    const r = mig({ "001.sql": "create table public.a (id int);\n" + "select 1;\n".repeat(1000) }, { budget: 100 });
    expect(r.overBudget).toBe(true);
    expect(tablesOf(r)).toEqual(["public.a"]);
  });
});

describe("supabase-policy-open", () => {
  const pol = (sql) => checkMigrations([{ rel: "001.sql", text: `create table public.t (id int, user_id uuid, email text);\nalter table public.t enable row level security;\n${sql}` }])
    .findings.filter((f) => f.kind === "policy").map((f) => `${f.policy.name}:${f.policy.command}:${f.roles.join(",")}`);

  it("flags permissive true policies for anon, authenticated and public", () => {
    expect(pol(`create policy "all" on public.t for all to anon using (true);
create policy rd on t for select using ((true));
create policy up on public.t for update to authenticated using (1 = 1) with check (true);
create policy ins on public.t for insert to anon with check (true);`)).toEqual(["all:all:anon", "rd:select:public", "up:update:authenticated", "ins:insert:anon"]);
  });

  it("leaves real conditions, restrictive policies, other roles and dropped policies alone", () => {
    expect(pol(`create policy own on public.t for select to authenticated using ((select auth.uid()) = user_id);
create policy r on public.t as restrictive for all to anon using (true);
create policy svc on public.t for all to service_role using (true);
create policy gone on public.t for all to anon using (true);
drop policy if exists gone on public.t;`)).toEqual([]);
  });

  it("grades by command and role: write for anyone is high, public read is low", () => {
    const root = repo({ "supabase/migrations/001.sql": `create table public.t (id int, email text);\nalter table public.t enable row level security;\ncreate policy w on public.t for delete to anon using (true);\ncreate policy r on public.t for select to anon using (true);\ncreate table public.posts (id int);\nalter table public.posts enable row level security;\ncreate policy p on public.posts for select using (true);\n` });
    const f = scanSupabase(root).findings.map((x) => `${x.severity}:${x.confidence}:${x.line}`);
    expect(f).toEqual(["high:likely:3", "medium:potential:4", "low:potential:7"]);
  });

  it("alwaysTrue is one pass however deep the brackets nest", () => {
    const deep = sqlTokens(`${"(".repeat(200_000)}true${")".repeat(200_000)}`).tokens;
    expect(cpuMs(() => alwaysTrue(deep), { runs: 3 })).toBeLessThan(1500);
    expect(alwaysTrue(sqlTokens("(true)").tokens)).toBe(true);
    expect(alwaysTrue(sqlTokens("true and auth.uid() = id").tokens)).toBe(false);
  });
});

describe("parsers", () => {
  it("tokenizes strings, quoted names, dollar bodies and nested comments in one pass", () => {
    const { tokens, open } = sqlTokens(`select 'it''s', E'a\\'b', "We""ird", $fn$ body ; $fn$ /* a /* b */ c */ ;`);
    expect(open).toBe(null);
    expect(tokens.filter((t) => t.v !== ",").map((t) => t.t)).toEqual(["word", "str", "str", "word", "body", "op"]);
    expect(tokens.find((t) => t.quoted).v).toBe('We"ird');
  });

  it("stays linear on hostile SQL (rows 4, 15)", () => {
    const cases = ["/*".repeat(500_000), "'a".repeat(500_000), "$a$".repeat(300_000), "create table public.t (".repeat(50_000)];
    for (const c of cases) expect(cpuMs(() => checkMigrations([{ rel: "x.sql", text: c }]), { runs: 2 })).toBeLessThan(3000);
  });

  it("finds the directive after comments and a BOM", () => {
    expect(directiveOf('﻿/* x */\n// y\n"use client";')).toBe("client");
    expect(directiveOf("'use server'")).toBe("server");
    expect(directiveOf('const a = "use client";')).toBe(null);
  });

  it("knows the service-role names", () => {
    expect(["SUPABASE_SERVICE_ROLE_KEY", "SERVICE_ROLE_KEY", "SUPABASE_SECRET_KEY", "SUPABASE_JWT_SECRET"].every(isServiceRoleName)).toBe(true);
    expect(["SUPABASE_ANON_KEY", "SUPABASE_URL", "SUPABASE_PUBLISHABLE_KEY"].some(isServiceRoleName)).toBe(false);
  });
});

describe("caps, refusals and chunk edges (BYPASS-CHECKLIST)", () => {
  it("row 1: a migration over the size cap makes the scan incomplete", () => {
    const root = repo({ "supabase/migrations/001.sql": "create table public.a (id int);\n" + "-- pad\n".repeat(200) });
    const r = scanSupabase(root, { maxSqlBytes: 512 });
    expect(r.incomplete).toEqual([{ file: "supabase/migrations/001.sql", reason: expect.stringContaining("over the 512-byte limit") }]);
  });

  it.skipIf(process.platform === "win32")("row 2: a migration that links out of the repo, or a FIFO, is incomplete, not skipped", () => {
    const outside = mkdtempSync(join(tmpdir(), "penthera-supabase-out-"));
    writeFileSync(join(outside, "x.sql"), "create table public.a (id int);");
    const root = repo({ "supabase/migrations/.keep": "" });
    symlinkSync(join(outside, "x.sql"), join(root, "supabase/migrations/001.sql"));
    execFileSync("mkfifo", [join(root, "supabase/migrations/002.sql")]);
    const r = scanSupabase(root);
    expect(r.incomplete.map((i) => i.file).sort()).toEqual(["supabase/migrations/001.sql", "supabase/migrations/002.sql"]);
  });

  it.skipIf(process.platform === "win32")("row 2: a migrations folder that is a link is incomplete", () => {
    const outside = mkdtempSync(join(tmpdir(), "penthera-supabase-out-"));
    const root = repo({ "supabase/config.toml": "" });
    symlinkSync(outside, join(root, "supabase/migrations"));
    expect(scanSupabase(root).incomplete.map((i) => i.file)).toEqual(["supabase/migrations"]);
  });

  it("row 1: padding a next.config env object past any length still finds the key name", () => {
    const pad = Array.from({ length: 20_000 }, (_, i) => `  PAD_${i}: "x",`).join("\n");
    const root = repo({ "next.config.js": `module.exports = {\n  env: {\n    nested: { deeper: { a: 1 } },\n${pad}\n    ${SERVER_NAME}: process.env.${SERVER_NAME},\n  },\n};\n` });
    expect(hits(root)).toEqual(["supabase-service-role-exposed:high:next.config.js:2"]);
  });

  it("row 15: nested env objects don't make the config check quadratic", () => {
    const text = `module.exports = ${"{ env: ".repeat(100_000)}1${" }".repeat(100_000)};`;
    const root = repo({ "next.config.js": text });
    expect(cpuMs(() => scanSupabase(root), { runs: 2 })).toBeLessThan(3000);
  });

  it("row 3: a key across the 8 MiB chunk edge is still found, on the right line", () => {
    const pad = "x".repeat(8 * 1024 * 1024 - 100);
    const root = repo({ "public/app.js": `${pad}\nconst k="${SERVICE}";\n` });
    expect(hits(root)).toEqual(["supabase-service-role-exposed:critical:public/app.js:2"]);
  });

  it("row 12: a last line with no newline is read like any other", () => {
    const root = repo({ "supabase/migrations/001.sql": "create table public.a (id int)" });
    expect(scanSupabase(root).findings.map((f) => f.templateId)).toEqual(["supabase-rls-disabled"]);
  });

  it.skipIf(process.platform === "win32")("row 23: Coverage counts a refused migration as not read", async () => {
    const root = repo({ "supabase/migrations/001.sql": "create table public.a (id int);" });
    execFileSync("mkfifo", [join(root, "supabase/migrations/002.sql")]);
    const r = await scanRepo(root);
    expect(r.incomplete.map((i) => i.file)).toEqual(["supabase/migrations/002.sql"]);
    expect(r.coverage.families.find((f) => f.id === "supabase")).toMatchObject({ examined: 1 });
  });

  it("the repo scan runs it, and an unreadable migration exits incomplete", async () => {
    const root = repo({ "supabase/migrations/001.sql": "create table public.a (id int);" }, { pkg: VITE });
    const r = await scanRepo(root);
    expect(r.executedProbes).toContain("supabase");
    expect(r.findings.some((f) => f.templateId === "supabase-rls-disabled")).toBe(true);
    expect(r.coverage.families.find((f) => f.id === "supabase")).toMatchObject({ ran: true, examined: 1 });
    expect(r.incomplete).toBeUndefined();
  });
});
