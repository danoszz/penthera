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
import { mkdtempSync, mkdirSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { execFileSync } from "node:child_process";
import { createHmac } from "node:crypto";
import { shown, scanSupabase, findServiceKeys, checkMigrations, sqlTokens, alwaysTrue, directiveOf, exposedSchemas, isServiceRoleName } from "../lib/whitebox/supabase.js";
import { scanRepo } from "../src/scan-repo.js";
import { cpuMs } from "./fixtures/cpu-time.js";
import { compareWithBaseline } from "../src/cli/baseline.js";
import { findingId, isSuppressed } from "../lib/memory/views.js";
import { spawnSync } from "node:child_process";
import { TOOL_BY_NAME } from "../src/mcp/tools.js";

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const SIG = "ZmFrZS1zaWduYXR1cmUtZm9yLWEtdGVzdC1maXh0dXJl";
const jwt = (claims) => `${b64({ alg: "HS256", typ: "JWT" })}.${b64(claims)}.${SIG}`;
const SERVICE = jwt({ iss: "supabase", ref: "abcdefghijklmnop", role: "service_role", iat: 1700000000, exp: 2000000000 });
const ANON = jwt({ iss: "supabase", ref: "abcdefghijklmnop", role: "anon", iat: 1700000000, exp: 2000000000 });
// A key signed with the local stack's published demo secret, and one that only claims to be.
const DEMO_SECRET = ["super", "secret", "jwt", "token", "with", "at", "least", "32", "characters", "long"].join("-");
const signed = (claims, secret) => {
  const input = `${b64({ alg: "HS256", typ: "JWT" })}.${b64(claims)}`;
  return `${input}.${createHmac("sha256", secret).update(input).digest("base64url")}`;
};
const DEMO = signed({ iss: "supabase-demo", role: "service_role", exp: 1983812996 }, DEMO_SECRET);
const FAKE_DEMO = signed({ iss: "supabase-demo", role: "service_role", exp: 1983812996 }, "a-self-hosted-secret-of-at-least-32-chars");
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

  it("marks the local demo key only when the demo secret signed it (row 6)", () => {
    expect(findServiceKeys(`k=${DEMO}`)[0].demo).toBe(true);
    expect(findServiceKeys(`k=${FAKE_DEMO}`)[0].demo).toBe(false);
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

  it("flags a public env name for the service-role key: high where it ships, medium in server code", () => {
    const root = repo({
      ".env.example": `${PUB("VITE_")}=\n`,
      "app/a.tsx": `"use client";\nconst k = process.env.${PUB("NEXT_PUBLIC_")};\n`,
      "scripts/check-env.mjs": `if (process.env.${PUB("NEXT_PUBLIC_")}) throw new Error("never public");\n`,
    }, { pkg: NEXT });
    expect(hits(root).sort()).toEqual([
      "supabase-service-role-exposed:high:.env.example:1",
      "supabase-service-role-exposed:high:app/a.tsx:2",
      "supabase-service-role-exposed:medium:scripts/check-env.mjs:1",
    ]);
  });

  it("catches SUPABASE_SERVICE_KEY, and a build config that inlines the whole env", () => {
    const name = ["SUPABASE", "SERVICE", "KEY"].join("_");
    const root = repo({
      ".env": `NEXT_PUBLIC_${name}=\n`,
      "next.config.js": "module.exports = { env: { ...process.env } };\n",
      "vite.config.mts": "export default defineConfig(({ mode }) => ({ define: { 'process.env': loadEnv(mode, process.cwd(), '') } }));\n",
    }, { pkg: NEXT });
    expect(hits(root).sort()).toEqual([
      "supabase-service-role-exposed:high:.env:1",
      "supabase-service-role-exposed:high:next.config.js:1",
      "supabase-service-role-exposed:high:vite.config.mts:1",
    ]);
  });

  it("reads Vue, Svelte, Astro, HTML and .mts files, and follows <script src>", () => {
    const root = repo({
      "src/App.vue": `<script setup>const k = "${SERVICE}";</script>\n`,
      "src/routes/+page.svelte": `<script>const k = "${SERVICE}";</script>\n`,
      "src/pages/index.astro": `---\n---\n<script>const k = "${SERVICE}";</script>\n`,
      "src/client.mts": `export const k = "${SERVICE}";\n`,
      "index.html": `<script>window.k = "${SERVICE}";</script><script type="module" src="/assets/app.js"></script>\n`,
      "assets/app.js": `const k = "${SERVICE}";\n`,
    }, { pkg: VITE });
    expect(hits(root).sort()).toEqual([
      "supabase-service-role-exposed:critical:assets/app.js:1",
      "supabase-service-role-exposed:critical:index.html:1",
      "supabase-service-role-exposed:critical:src/App.vue:1",
      "supabase-service-role-exposed:critical:src/client.mts:1",
      "supabase-service-role-exposed:critical:src/pages/index.astro:3",
      "supabase-service-role-exposed:critical:src/routes/+page.svelte:1",
    ]);
  });

  it("catches whole-env inlining in its other spellings, but not a define that picks one value (recheck)", () => {
    const pkg = { dependencies: { vite: "5.4.0", "@supabase/supabase-js": "2.45.0" } };
    const bad = [
      "const env = loadEnv(mode, process.cwd(), '');\nexport default { define: { __APP_ENV__: JSON.stringify(env) } };\n",
      "const env = loadEnv(mode, process.cwd(), '');\nexport default { define: Object.fromEntries(Object.entries(env).map(([k, v]) => [k, JSON.stringify(v)])) };\n",
    ];
    expect(bad.map((text) => hits(repo({ "vite.config.ts": text }, { pkg })))).toEqual([
      ["supabase-service-role-exposed:high:vite.config.ts:2"], // the define object
      ["supabase-service-role-exposed:high:vite.config.ts:1"], // the empty-prefix loadEnv
    ]);
    expect(hits(repo({ "next.config.js": "const env = process.env;\nmodule.exports = { env: { ...env } };\n" }, { pkg: NEXT }))).toEqual(["supabase-service-role-exposed:high:next.config.js:2"]);
    expect(hits(repo({ "vite.config.ts": "const env = loadEnv(mode, process.cwd(), '');\nexport default { define: { __V__: JSON.stringify(env.npm_package_version) } };\n" }, { pkg }))).toEqual([]);
    // No package.json, but the code loads Supabase from a CDN.
    expect(hits(repo({ "src/db.js": "import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';\n", "next.config.js": "module.exports = { env: { ...process.env } };\n" }))).toEqual(["supabase-service-role-exposed:high:next.config.js:1"]);
  });

  it("treats Svelte and Vue components, and an Astro file past its frontmatter, as client code (recheck)", () => {
    const root = repo({
      "src/routes/+page.svelte": `<script>const k = "${SERVICE}";</script>\n`,
      "src/pages/a.astro": `---\nconst server = "${SERVICE}";\n---\n<script>const k = "${SERVICE}";</script>\n`,
    }, { pkg: { dependencies: { "@sveltejs/kit": "2.0.0", astro: "4.0.0" } } });
    expect(hits(root).sort()).toEqual([
      "supabase-service-role-committed:high:src/pages/a.astro:2",
      "supabase-service-role-exposed:critical:src/pages/a.astro:4",
      "supabase-service-role-exposed:critical:src/routes/+page.svelte:1",
    ]);
  });

  it("reports client code that git ignores at high, never drops it", () => {
    const root = repo({ "src/config.ts": `export const k = "${SERVICE}";\n` }, { pkg: VITE });
    const ignored = { dirs: new Set(), files: new Set([join(root, "src/config.ts")]) };
    expect(hits(root, { ignored })).toEqual(["supabase-service-role-exposed:high:src/config.ts:1"]);
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

  it("reports the local demo key low, at potential confidence; a look-alike gets full severity", () => {
    const root = repo({ "src/client.ts": `const k = "${DEMO}";\n`, "src/other.ts": `const k = "${FAKE_DEMO}";\n` }, { pkg: VITE });
    const f = scanSupabase(root).findings.map((x) => `${x.templateId}:${x.severity}:${x.confidence}:${x.file}`).sort();
    expect(f).toEqual([
      "supabase-service-role-committed:low:potential:src/client.ts",
      "supabase-service-role-exposed:critical:likely:src/other.ts",
    ]);
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

  it("reads config.toml in one pass, even all blank lines (review 4)", () => {
    expect(cpuMs(() => exposedSchemas("\n".repeat(1_000_000)), { runs: 2 })).toBeLessThan(1500);
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

  it("ignores default-privilege revokes on functions, sequences or another role's tables (review 1)", () => {
    for (const pre of [
      "alter default privileges in schema public revoke all on functions from anon, authenticated;",
      "alter default privileges in schema public revoke all on sequences from anon, authenticated;",
      "alter default privileges for role supabase_admin in schema public revoke all on tables from anon, authenticated;",
    ]) expect(tablesOf(mig({ "001.sql": `${pre}\ncreate table public.t (id int, email text);` }))).toEqual(["public.t"]);
    expect(tablesOf(mig({ "001.sql": "alter default privileges for role postgres in schema public revoke all on tables from anon, authenticated;\ncreate table public.t (id int);" }))).toEqual([]);
  });

  it("resets search_path on DEFAULT, RESET and the end of a transaction (review 5)", () => {
    for (const reset of ["set search_path to default;", "reset search_path;", "begin; set local search_path = private; commit;"]) {
      expect(tablesOf(mig({ "001.sql": `set search_path = private;\n${reset}\ncreate table t (id int);`.replace("set search_path = private;\nbegin;", "begin;") }))).toEqual(["public.t"]);
    }
  });

  it("set_config(..., true) lasts until the transaction ends (recheck)", () => {
    expect(tablesOf(mig({ "001.sql": "begin;\nselect set_config('search_path', 'private', true);\ncommit;\ncreate table t (id int);" }))).toEqual(["public.t"]);
    expect(tablesOf(mig({ "001.sql": "select set_config('search_path', 'private', false);\ncreate table t (id int);" }))).toEqual([]);
  });

  it("CREATE TABLE IF NOT EXISTS later doesn't undo RLS (review false positive)", () => {
    expect(tablesOf(mig({ "001.sql": "create table public.t (id int);\nalter table public.t enable row level security;", "002.sql": "create table if not exists public.t (id int);" }))).toEqual([]);
  });

  it("moves policies with SET SCHEMA and marks DO '...' strings and EXECUTE ... CREATE (review 10)", () => {
    const r = mig({ "001.sql": "create table private.t (id int);\nalter table private.t enable row level security;\ncreate policy p on private.t for all to anon using (true);\nalter table private.t set schema public;\ndo 'begin execute ''create table public.x(id int)''; end';\ncreate function f() returns void language plpgsql as $$ begin execute 'create ' || 'table public.y(id int)'; end $$;" });
    expect(r.findings.filter((f) => f.kind === "policy").map((f) => `${f.table.schema}.${f.table.name}`)).toEqual(["public.t"]);
    expect(r.unchecked.map((u) => u.count)).toEqual([2]); // one entry per file and reason, counted
  });

  it("200k short public tables in one migration: one grouped finding, bounded, and an incomplete scan (Vercel, PR 312)", async () => {
    const text = Array.from({ length: 200_000 }, (_, i) => `create table public.t${i} (id int${i === 150 ? ", email text" : ""});`).join("\n");
    const root = repo({ "supabase/migrations/001.sql": text });
    const r = await scanRepo(root);
    const rls = r.findings.filter((f) => f.templateId === "supabase-rls-disabled");
    // The tracked ones as one group, and those past the cap as one more, counted, at potential.
    expect(rls.map((f) => f.confidence).sort()).toEqual(["likely", "potential"]);
    expect(rls.find((f) => f.confidence === "potential").title).toMatch(/^149999 tables changed after Penthera's 50000-object limit/);
    // The table with a private-looking column is named first; the count stops at the cap.
    rls.sort((a, b) => (a.confidence === "likely" ? -1 : 1) - (b.confidence === "likely" ? -1 : 1));
    expect(rls[0].title).toMatch(/^50001 tables in `supabase\/migrations\/001\.sql` have no row-level security \(list [0-9a-f]{16}\)$/);
    expect(rls[0].description).toMatch(/^`supabase\/migrations\/001\.sql` creates or changes 50001 tables in exposed schemas that no migration puts under row-level security: `public\.t150`/);
    expect(rls[0].lines.length).toBeLessThanOrEqual(20);
    expect(r.incomplete).toEqual([expect.objectContaining({ file: "supabase/migrations/001.sql", reason: expect.stringContaining("more than 50000 tables and policies") })]);
    // Read, but not to the end: named as not fully checked, not as not read.
    expect(r.findings.some((f) => f.title === "File not fully checked: supabase/migrations/001.sql")).toBe(true);
  }, 60_000);

  it("the cap can't hide a later unprotected table behind harmless ones; Coverage marks that file not read (review of PR 312)", async () => {
    const root = repo({
      "supabase/migrations/001.sql": Array.from({ length: 50_001 }, (_, i) => `create table private.d${i} (id int);`).join("\n"),
      "supabase/migrations/002.sql": "create table public.users (email text, password text);",
    });
    const r = await scanRepo(root);
    const f = r.findings.filter((x) => x.templateId === "supabase-rls-disabled");
    expect(f.map((x) => [x.severity, x.confidence, x.file])).toEqual([["high", "potential", "supabase/migrations/002.sql"]]);
    expect(f[0].description).toContain("`public.users`");
    // The cap fires on 002.sql's first statement: 001.sql was read whole, 002.sql only noted.
    expect(r.incomplete.map((i) => i.file)).toEqual(["supabase/migrations/002.sql"]);
    expect(r.coverage.families.find((x) => x.id === "supabase")).toMatchObject({ examined: 1 });
  }, 60_000);

  it("past the cap, search_path, DISABLE RLS, SET SCHEMA and a private-looking column still surface (recheck of PR 312)", async () => {
    const decoys = Array.from({ length: 50_001 }, (_, i) => `create table d${i} (id int);`).join("\n");
    const cases = {
      search_path: [`set search_path to private;\n${decoys}`, "set search_path to public;\ncreate table users (password text);"],
      disable: [`create table public.users (email text);\nalter table public.users enable row level security;\nset search_path to private;\n${decoys}`, "alter table public.users disable row level security;"],
      set_schema: [`create table private.users (email text);\nset search_path to private;\n${decoys}`, "alter table private.users set schema public;"],
    };
    Object.assign(cases, {
      regrant: [`create table public.users (email text);\nrevoke all on table public.users from anon, authenticated;\nset search_path to private;\n${decoys}`, "grant select on public.users to anon;"],
      open_policy: [`create table public.users (email text);\nalter table public.users enable row level security;\nset search_path to private;\n${decoys}`, "create policy p on public.users for all to anon using (true) with check (true);"],
      opened_policy: [`create table public.users (email text);\nalter table public.users enable row level security;\ncreate policy p on public.users for select to anon using (false);\nset search_path to private;\n${decoys}`, "alter policy p on public.users using (true);"],
      quoted_role: [`create table public.users (email text);\nrevoke all on table public.users from anon, authenticated;\nset search_path to private;\n${decoys}`, 'grant select on public.users to "anon";'],
      one_eq_one: [`create table public.users (email text);\nalter table public.users enable row level security;\nset search_path to private;\n${decoys}`, "create policy p on public.users for all to anon using (1 = 1) with check (1 = 1);"],
      recreate: [`create table public.users (email text);\nalter table public.users enable row level security;\nset search_path to private;\n${decoys}`, "drop table public.users;\ncreate table public.users (password text);"],
    });
    for (const [name, [a, b]] of Object.entries(cases)) {
      const r = scanSupabase(repo({ "supabase/migrations/001.sql": a, "supabase/migrations/002.sql": b }));
      const f = r.findings.filter((x) => x.templateId === "supabase-rls-disabled");
      expect(f.map((x) => x.description).join(" "), name).toContain("`public.users`");
    }
    // 1,000 harmless names first can't push a table with a private-looking column out of the names.
    const many = Array.from({ length: 1001 }, (_, i) => `create table public.o${i} (id int);`).join("\n");
    const r = scanSupabase(repo({ "supabase/migrations/001.sql": `set search_path to private;\n${decoys}`, "supabase/migrations/002.sql": `${many}\ncreate table public.users (password text);` }));
    const o = r.findings.find((x) => x.title.includes("after Penthera's"));
    expect(o.description).toMatch(/: `public\.users`/);
  }, 120_000);

  it("a grouped finding's id changes when its set of tables changes, so a suppression doesn't carry over (review of PR 312)", () => {
    const title = (sql) => scanSupabase(repo({ "supabase/migrations/001.sql": sql })).findings[0].title;
    const a = title("create table public.logs (id int);\ncreate table public.events (id int);");
    const b = title("create table public.logs (id int);\ncreate table public.users (email text);");
    expect(a).not.toBe(b);
    expect(a).toBe(title("create table public.events (id int);\ncreate table public.logs (id int);"));
  });

  it("groups many open policies per file and severity", () => {
    const pols = Array.from({ length: 30 }, (_, i) => `create policy p${i} on public.t for update to anon using (true);`).join("\n");
    const root = repo({ "supabase/migrations/001.sql": `create table public.t (id int);\nalter table public.t enable row level security;\n${pols}` });
    const f = scanSupabase(root).findings;
    expect(f.map((x) => `${x.templateId}:${x.severity}`)).toEqual(["supabase-policy-open:high"]);
    expect(f[0].title).toMatch(/^30 policies in `supabase\/migrations\/001\.sql` check nothing \(list [0-9a-f]{16}\)$/);
    expect(f[0].description).toContain("and 10 more");
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

  it("a statement past the token cap keeps its start, and the scan is incomplete (rows 1, 4)", () => {
    const r = mig({ "001.sql": `create table public.wide (${Array.from({ length: 30_000 }, (_, i) => `c${i} int`).join(", ")});` });
    expect(tablesOf(r)).toEqual(["public.wide"]);
    expect(r.unchecked[0]).toMatchObject({ why: expect.stringContaining("over 20000 tokens"), incomplete: true });
    const root = repo({ "supabase/migrations/001.sql": `create table public.a (id int);\nalter table public.a enable row level security${", alter column id set default 1".repeat(5000)}, disable row level security;` });
    expect(scanSupabase(root).incomplete.map((i) => i.file)).toEqual(["supabase/migrations/001.sql"]);
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

  it("a broadened policy shows again past a baseline and a suppression, single or grouped (Vercel, PR 312)", () => {
    const table = "create table public.t (id int);\nalter table public.t enable row level security;\n";
    const scan = (pols) => scanSupabase(repo({ "supabase/migrations/001.sql": table + pols })).findings.filter((f) => f.templateId === "supabase-policy-open");
    const pairs = {
      // Same severity and table before and after: only what the policy grants changes.
      "WITH CHECK opened": ["create policy p on public.t for update to anon using (true) with check (auth.uid() = id);", "create policy p on public.t for update to anon using (true) with check (true);"],
      // Without WITH CHECK, UPDATE checks new rows with USING: dropping it opens the check.
      "WITH CHECK dropped": ["create policy p on public.t for update to anon using (true) with check (auth.uid() = id);", "create policy p on public.t for update to anon using (true);"],
      "a quoted role can't hide an added one": ['create policy p on public.t for delete to anon, "authenticated, x" using (true);', "create policy p on public.t for delete to anon, authenticated, x using (true);"],
      "role added": ["create policy p on public.t for delete to anon using (true);", "create policy p on public.t for delete to anon, authenticated using (true);"],
      "grouped, a role added": [
        "create policy a on public.t for update to anon using (true);\ncreate policy b on public.t for delete to anon using (true);",
        "create policy a on public.t for update to anon using (true);\ncreate policy b on public.t for delete to anon, public using (true);",
      ],
      "grouped, UPDATE to ALL": [
        "create policy a on public.t for update to anon using (true);\ncreate policy b on public.t for delete to anon using (true);",
        "create policy a on public.t for all to anon using (true);\ncreate policy b on public.t for delete to anon using (true);",
      ],
    };
    for (const [name, [narrow, broad]] of Object.entries(pairs)) {
      const before = scan(narrow);
      const after = scan(broad);
      expect(before.map((f) => f.severity), name).toEqual(after.map((f) => f.severity));
      // A suppression is keyed by the finding's id: the broadened finding has a new one.
      expect(after.map(findingId).some((id) => !before.map(findingId).includes(id)), name).toBe(true);
      // And a baseline of the narrow scan reports it as new.
      const base = join(mkdtempSync(join(tmpdir(), "penthera-supabase-base-")), "base.json");
      writeFileSync(base, JSON.stringify({ findings: before }));
      expect(compareWithBaseline(after, base).newFindings.length, name).toBeGreaterThan(0);
      // The same policies scanned again stay unchanged.
      expect(compareWithBaseline(scan(narrow), base).newFindings, name).toEqual([]);
    }
  });

  it("two anon UPDATE policies broadened to ALL: a grouped suppression no longer covers them, and --baseline -q shows them (Vercel, PR 312)", () => {
    const table = "create table public.t (id int);\nalter table public.t enable row level security;\n";
    const narrow = `${table}create policy a on public.t for update to anon using (true);\ncreate policy b on public.t for update to anon using (true);\n`;
    const broad = `${table}create policy a on public.t for all to anon using (true);\ncreate policy b on public.t for all to anon using (true);\n`;
    const root = repo({ "supabase/migrations/001.sql": narrow, "package.json": "{}" });
    const policyOf = (findings) => findings.filter((f) => f.templateId === "supabase-policy-open");
    // (b) a suppression of the narrow group, at its severity, doesn't cover the broadened group.
    const [before] = policyOf(scanSupabase(root).findings);
    const views = { suppressions: [{ id: findingId(before), severity: before.severity }] };
    expect(isSuppressed(before, views)).toBeTruthy();
    writeFileSync(join(root, "supabase/migrations/001.sql"), broad);
    const [after] = policyOf(scanSupabase(root).findings);
    expect(after.severity).toBe(before.severity);
    expect(isSuppressed(after, views)).toBe(null);
    // (a) through the CLI: a baseline of the narrow scan, then --baseline -q on the broadened one.
    const home = mkdtempSync(join(tmpdir(), "penthera-supabase-home-"));
    const env = { PATH: process.env.PATH, HOME: home, NO_COLOR: "1", PENTHERA_NO_ONBOARDING: "1" };
    const cli = (...args) => spawnSync(process.execPath, ["bin/penthera.js", "--repo", root, "--offline", "--json", ...args], { env, encoding: "utf-8", maxBuffer: 64 * 1024 * 1024 });
    writeFileSync(join(root, "supabase/migrations/001.sql"), narrow);
    const base = join(home, "base.json");
    writeFileSync(base, cli().stdout);
    expect(policyOf(JSON.parse(cli("--baseline", base, "-q").stdout).findings)).toEqual([]);
    writeFileSync(join(root, "supabase/migrations/001.sql"), broad);
    const shown = policyOf(JSON.parse(cli("--baseline", base, "-q").stdout).findings);
    expect(shown.map((f) => f.title)).toEqual([after.title]);
  }, 60_000);

  it("a shortened name can't impersonate another table's finding (Vercel, PR 312)", () => {
    const one = (sql) => scanSupabase(repo({ "supabase/migrations/001.sql": sql })).findings.filter((f) => f.templateId === "supabase-rls-disabled");
    // PostgreSQL keeps 63 bytes of a name, so names that differ inside them (and show hashed: uppercase) are distinct.
    const long = (tail) => `"${"A".repeat(60)}${tail}"`;
    // Two long names sharing a 60-character prefix: distinct ids, and a suppression of one doesn't cover the other.
    const [a] = one(`create table public.${long("x")} (id int);`);
    const [b] = one(`create table public.${long("y")} (id int);`);
    expect(findingId(a)).not.toBe(findingId(b));
    const views = { suppressions: [{ id: findingId(a), severity: "high" }] };
    expect(isSuppressed(a, views)).toBeTruthy();
    expect(isSuppressed(b, views)).toBe(null);
    // A table literally named like another's shortened form doesn't share its id.
    const forged = shown("A".repeat(61));
    const [c] = one(`create table public."${"A".repeat(61)}" (id int);`);
    const [d] = one(`create table public."${forged}" (id int);`);
    expect(findingId(c)).not.toBe(findingId(d));
    // The hash is at least 16 hex characters of the whole name.
    expect(shown("A".repeat(61))).toMatch(/…[0-9a-f]{16}$/);
  });

  it("a quoted mixed-case name, a NUL and the all-tables marker each keep their own id (review of PR 312)", () => {
    const id = (sql) => scanSupabase(repo({ "supabase/migrations/001.sql": sql })).findings.map(findingId);
    expect(id('create table "Users" (id int);')).not.toEqual(id("create table users (id int);"));
    const pol = (name) => `create table public.t (id int);\nalter table public.t enable row level security;\ncreate policy ${name} on public.t for update to anon using (true);`;
    expect(id(pol('"P"'))).not.toEqual(id(pol("p")));
    // A NUL inside a quoted name no longer splits the key: it isn't read as public.t.
    expect(id(`create table public.t (id int);\nalter table public.t enable row level security;\ncreate policy p on "t\u0000z" for update to anon using (true);`)).not.toEqual(id(pol("p")));
    // Past the cap, "every table" and a table literally named "*" differ.
    const decoys = `set search_path to private;\n${Array.from({ length: 50_001 }, (_, i) => `create table d${i} (id int);`).join("\n")}`;
    const over = (b) => scanSupabase(repo({ "supabase/migrations/001.sql": decoys, "supabase/migrations/002.sql": b })).findings.filter((f) => f.title.includes("after Penthera's"));
    const all = over("grant select on all tables in schema public to anon;");
    const star = over('grant select on public."*" to anon;');
    expect(all.map(findingId)).not.toEqual(star.map(findingId));
    expect(all[0].description).toContain("`public.* (all tables)`");
  }, 60_000);

  it("names are cut at 63 bytes as PostgreSQL does; a rename to a multi-MiB name stays bounded and marks the file (Vercel, PR 312)", async () => {
    const r = checkMigrations([{ rel: "001.sql", text: `create table public."${"x".repeat(70)}" (id int);` }]);
    expect(r.findings[0].table.name).toBe("x".repeat(63));
    // UTF-8: cut on a character boundary within 63 bytes.
    expect(Buffer.byteLength(checkMigrations([{ rel: "1.sql", text: `create table public."${"é".repeat(40)}" (id int);` }]).findings[0].table.name)).toBeLessThanOrEqual(63);
    const pols = Array.from({ length: 5000 }, (_, i) => `create policy p${i} on public.t for update to anon using (true);`).join("\n");
    const huge = "N".repeat(4 * 1024 * 1024);
    const root = repo({ "supabase/migrations/001.sql": `create table public.t (id int);\nalter table public.t enable row level security;\n${pols}\nalter table public.t rename to "${huge}";\n` });
    const before = process.memoryUsage().rss;
    const t0 = Date.now();
    const scan = await scanRepo(root);
    expect(Date.now() - t0).toBeLessThan(20_000);
    expect(process.memoryUsage().rss - before).toBeLessThan(512 * 1024 * 1024);
    expect(scan.incomplete.map((i) => i.file)).toContain("supabase/migrations/001.sql");
    const pf = scan.findings.filter((f) => f.templateId === "supabase-policy-open");
    expect(pf).toHaveLength(1);
    expect(JSON.stringify(pf).length).toBeLessThan(64 * 1024);
    // Through the CLI and MCP too.
    const home = mkdtempSync(join(tmpdir(), "penthera-supabase-home-"));
    const out = spawnSync(process.execPath, ["bin/penthera.js", "--repo", root, "--offline", "--json"], {
      env: { PATH: process.env.PATH, HOME: home, NO_COLOR: "1", PENTHERA_NO_ONBOARDING: "1" }, encoding: "utf-8", maxBuffer: 64 * 1024 * 1024,
    });
    expect(out.status).toBe(2);
    expect(out.stdout.length).toBeLessThan(1024 * 1024);
    const res = await TOOL_BY_NAME.get("scan_repo").run({ path: realpathSync(root) }, { roots: async () => [realpathSync(root)] });
    expect(JSON.stringify(res).length).toBeLessThan(512 * 1024);
  }, 120_000);

  it("a dot inside a quoted name is not a schema separator (review of PR 312)", () => {
    // public."x.y" has no RLS; enabling RLS on "public.x".y must not hide it.
    const r = checkMigrations([{ rel: "001.sql", text: 'create table public."x.y" (id int);\ncreate table "public.x".y (id int);\nalter table "public.x".y enable row level security;' }]);
    expect(r.findings.filter((f) => f.kind === "rls").map((f) => [f.table.schema, f.table.name])).toEqual([["public", "x.y"]]);
    // Both exposed: the two findings read differently, so neither's id covers the other.
    const toml = '[api]\nschemas = ["public", "public.x"]\n';
    const [f] = scanSupabase(repo({ "supabase/config.toml": toml, "supabase/migrations/001.sql": 'create table public."x.y" (id int);' })).findings;
    const [g] = scanSupabase(repo({ "supabase/config.toml": toml, "supabase/migrations/001.sql": 'create table "public.x".y (id int);' })).findings;
    expect(findingId(f)).not.toBe(findingId(g));
  });

  it("200k distinct public service-role env names: bounded findings through scanRepo, CLI --json and MCP, and an incomplete scan (Vercel, PR 312)", async () => {
    const env = Array.from({ length: 200_000 }, (_, i) => `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY_${i}=`).join("\n");
    const reads = Array.from({ length: 5000 }, (_, i) => `process.env.SUPABASE_SERVICE_ROLE_KEY_${i};`).join("\n");
    const root = repo({ ".env.example": env, "app/a.tsx": `"use client";\n${reads}\n` }, { pkg: NEXT });
    const t0 = Date.now();
    const r = await scanRepo(root);
    expect(Date.now() - t0).toBeLessThan(20_000);
    const exposed = r.findings.filter((f) => f.templateId === "supabase-service-role-exposed");
    // One finding per file and kind, each naming 20 and a digest of the set.
    expect(exposed.map((f) => f.file).sort()).toEqual([".env.example", "app/a.tsx"]);
    const envFinding = exposed.find((f) => f.file === ".env.example");
    expect(envFinding.title).toMatch(/^Service-role key under 1000\+ public env names in `\.env\.example` \(list [0-9a-f]{16}\)$/);
    expect(envFinding.lines.length).toBeLessThanOrEqual(50);
    expect(r.incomplete.map((i) => i.file)).toContain(".env.example");
    expect(r.findings.some((f) => f.title === "File not fully checked: .env.example")).toBe(true);
    // The CLI's JSON stays small.
    const home = mkdtempSync(join(tmpdir(), "penthera-supabase-home-"));
    const out = spawnSync(process.execPath, ["bin/penthera.js", "--repo", root, "--offline", "--json"], {
      env: { PATH: process.env.PATH, HOME: home, NO_COLOR: "1", PENTHERA_NO_ONBOARDING: "1" }, encoding: "utf-8", maxBuffer: 64 * 1024 * 1024,
    });
    expect(out.stdout.length).toBeLessThan(1024 * 1024);
    expect(JSON.parse(out.stdout).findings.filter((f) => f.templateId === "supabase-service-role-exposed")).toHaveLength(2);
    expect(out.status).toBe(2);
    // And so does the MCP scan_repo result.
    const res = await TOOL_BY_NAME.get("scan_repo").run({ path: realpathSync(root) }, { roots: async () => [realpathSync(root)] });
    expect(JSON.stringify(res).length).toBeLessThan(512 * 1024);
  }, 120_000);

  it("names spread over 30k files, a burnt budget and a 300-character name (review of PR 312)", async () => {
    // 30,000 files with two public names each: at most 1,000 file findings plus one overflow.
    const files = {};
    for (let i = 0; i < 30_000; i++) files[`cfg/c${i}.json`] = JSON.stringify({ a: `${PUB("NEXT_PUBLIC_")}_A${i}`, b: `${PUB("VITE_")}_B${i}` });
    const root = repo(files);
    const r = await scanRepo(root);
    const exposed = r.findings.filter((f) => f.templateId === "supabase-service-role-exposed");
    expect(exposed.length).toBeLessThanOrEqual(1001);
    expect(exposed.some((f) => /^1000\+ more files use public env names/.test(f.title))).toBe(true);
    expect(JSON.stringify(r).length).toBeLessThan(8 * 1024 * 1024);
    expect(r.incomplete.length).toBeLessThanOrEqual(1001);
    // Server-only reads that are never reported don't use up the budget of a real public name.
    const burn = {};
    for (let i = 0; i < 25; i++) burn[`server/s${i}.ts`] = Array.from({ length: 1000 }, (_, k) => `process.env.SUPABASE_SERVICE_ROLE_KEY_${i}_${k};`).join("\n");
    burn[".env.production"] = `${PUB("NEXT_PUBLIC_")}=\n`;
    const [real] = scanSupabase(repo(burn)).findings.filter((f) => f.file === ".env.production");
    expect([real.title, real.line, real.severity]).toEqual([`Service-role key under a public env name: \`${PUB("NEXT_PUBLIC_")}\``, 1, "high"]);
    // A name longer than any bound is still read.
    const longName = `${PUB("NEXT_PUBLIC_")}_${"X".repeat(300)}`;
    const [lf] = scanSupabase(repo({ ".env": `${longName}=\n` })).findings;
    expect(lf.severity).toBe("high");
    expect(lf.title.length).toBeLessThan(300);
  }, 120_000);

  it("review of the DoS fixes: long config.toml schemas, server reads, overflow confidence, ASCII-only folding", () => {
    // A schema over 63 bytes in config.toml is cut like the same name in SQL, so its tables still match.
    const sch = "é".repeat(40);
    const a = scanSupabase(repo({ "supabase/config.toml": `[api]\nschemas = ["public", "${sch}"]\n`, "supabase/migrations/001.sql": `create table "${sch}".profiles (id uuid, email text);` }));
    expect(a.findings.map((f) => f.templateId)).toEqual(["supabase-rls-disabled"]);
    expect(exposedSchemas(`[api]\nschemas = ["public", "${"a".repeat(300)}"]\n`)).toEqual(["public", "a".repeat(63)]);
    // 1,025 route handlers reading the server-only key don't take the slots; the client file is named.
    const files = { "app/page.tsx": `"use client";\nconst k = process.env.${SERVER_NAME};\n` };
    for (let i = 0; i < 1025; i++) files[`app/api/r${i}/route.js`] = `export const k = process.env.${SERVER_NAME};\n`;
    const b = scanSupabase(repo(files, { pkg: NEXT }));
    expect(b.findings.map((f) => `${f.file}:${f.severity}`)).toEqual(["app/page.tsx:medium"]);
    expect(b.incomplete).toEqual([]);
    // A server-path file that client code imports is still reported (recheck of PR 312).
    const d = scanSupabase(repo({ "components/Admin.jsx": '"use client";\nimport { a } from "../server/admin.js";\n', "server/admin.js": `export const a = process.env.${SERVER_NAME};\n` }, { pkg: NEXT }));
    expect(d.findings.map((f) => `${f.file}:${f.severity}`)).toEqual(["server/admin.js:medium"]);
    // PostgreSQL folds only ASCII in an unquoted name: ÄRGER is Ärger, not ärger.
    const c = checkMigrations([{ rel: "1.sql", text: "create table public.ÄRGER (id int);\nalter table if exists public.ärger enable row level security;" }]);
    expect(c.findings.filter((f) => f.kind === "rls").map((f) => f.table.name)).toEqual(["Ärger"]); // Ä stays, RGER folds
  });

  it("the public-name overflow finding is likely unless every file in it is a test", async () => {
    const files = {};
    for (let i = 0; i < 1002; i++) files[`cfg/c${i}.json`] = JSON.stringify({ a: `${PUB("NEXT_PUBLIC_")}_${i}` });
    const r = scanSupabase(repo(files));
    const o = r.findings.find((f) => / more files use public env names/.test(f.title));
    expect([o.severity, o.confidence]).toEqual(["high", "likely"]);
  }, 60_000);

  it("policies with ~19k-token expressions keep only a summary: bounded time and output through scanRepo, CLI and MCP (Vercel, PR 312)", async () => {
    const expr = Array.from({ length: 4700 }, () => "a = 1").join(" and ");
    const files = {};
    for (let f = 0; f < 3; f++) {
      let sql = f === 0 ? "create table public.t (id int);\nalter table public.t enable row level security;\n" : "";
      for (let i = 0; i < 150; i++) sql += `create policy p${f}_${i} on public.t for update to anon using (${i === 0 && f === 2 ? "true" : expr});\n`;
      files[`supabase/migrations/00${f}.sql`] = sql;
    }
    const root = repo(files);
    // What is kept per policy: booleans and the roles that matter, no token arrays.
    const r = checkMigrations(Object.entries(files).map(([rel, text]) => ({ rel, text })));
    const [pf] = r.findings.filter((f) => f.kind === "policy");
    expect(pf.policy.using).toEqual({ open: true });
    expect(pf.policy.roles).toEqual(["anon"]);
    expect(JSON.stringify(pf.policy).length).toBeLessThan(400);
    const t0 = Date.now();
    const scan = await scanRepo(root);
    expect(Date.now() - t0).toBeLessThan(20_000);
    expect(scan.findings.filter((f) => f.templateId === "supabase-policy-open").map((f) => f.title)).toEqual([expect.stringMatching(/^Policy "p2_0" lets anyone/)]);
    const home = mkdtempSync(join(tmpdir(), "penthera-supabase-home-"));
    const out = spawnSync(process.execPath, ["bin/penthera.js", "--repo", root, "--offline", "--json"], {
      env: { PATH: process.env.PATH, HOME: home, NO_COLOR: "1", PENTHERA_NO_ONBOARDING: "1" }, encoding: "utf-8", maxBuffer: 64 * 1024 * 1024,
    });
    expect(out.stdout.length).toBeLessThan(256 * 1024);
    expect(out.status).toBe(1);
    const res = await TOOL_BY_NAME.get("scan_repo").run({ path: realpathSync(root) }, { roots: async () => [realpathSync(root)] });
    expect(JSON.stringify(res).length).toBeLessThan(256 * 1024);
  }, 120_000);

  it.skipIf(process.platform === "win32")("thousands of folder links and 60k imports: bounded time, and imports through a link still followed (Vercel, PR 312)", () => {
    const root = repo({ "shared/k.js": `export const k = "${SERVICE}";\n`, "lib/real/x.js": "export {};\n" }, { pkg: NEXT });
    mkdirSync(join(root, "links"), { recursive: true });
    for (let i = 0; i < 3000; i++) symlinkSync(join(root, "lib/real"), join(root, `links/l${i}`));
    symlinkSync(join(root, "shared"), join(root, "app-shared"));
    // 60,000 imports (under the 2 MiB a file's imports are read from): 3,000 distinct ones through
    // the folder links, the rest repeats.
    const imports = Array.from({ length: 60_000 }, (_, i) => `import "../links/l${i % 3000}/x.js";`).join("\n");
    expect(imports.length).toBeLessThan(2 * 1024 * 1024);
    mkdirSync(join(root, "app"), { recursive: true });
    writeFileSync(join(root, "app/page.tsx"), `"use client";\nimport { k } from "../app-shared/k.js";\n${imports}\n`);
    expect(cpuMs(() => scanSupabase(root), { runs: 1 })).toBeLessThan(5000);
    // The import through the app-shared link reaches shared/k.js: client code, so critical.
    expect(hits(root)).toEqual(["supabase-service-role-exposed:critical:shared/k.js:1"]);
  }, 60_000);

  it("a large real-looking app with thousands of client pages and unresolved @/ imports stays within the budget (review of PR 312)", () => {
    const files = { "lib/zz/late.ts": `"use client";\nconst k = process.env.${SERVER_NAME};\n` };
    for (let i = 0; i < 3000; i++) files[`app/p${i}/page.tsx`] = `"use client";\n${[0, 1, 2].map((j) => `import "@/public/images/marketing/campaign-${i}/hero-variant-${j}.webp";`).join("\n")}\n`;
    const r = scanSupabase(repo(files, { pkg: NEXT }));
    expect(r.incomplete).toEqual([]);
    expect(r.findings.map((f) => `${f.severity}:${f.file}`)).toEqual(["medium:lib/zz/late.ts"]);
  }, 60_000);

  it("more than 5,000 distinct imports in one client file: the rest aren't followed, and the file is named", () => {
    const imports = Array.from({ length: 5100 }, (_, i) => `import "./m${i}.js";`).join("\n");
    const r = scanSupabase(repo({ "app/page.tsx": `"use client";\n${imports}\n` }, { pkg: NEXT }));
    expect(r.incomplete).toEqual([expect.objectContaining({ file: "app/page.tsx", partial: true })]);
  });

  it("a few names in one file are one finding whose id follows the set", () => {
    const ids = (text) => scanSupabase(repo({ ".env": text })).findings.map((f) => `${f.title}|${f.severity}`);
    const two = ids(`${PUB("NEXT_PUBLIC_")}=\n${PUB("VITE_")}=\n`);
    expect(two).toHaveLength(1);
    expect(two[0]).toMatch(/^Service-role key under 2 public env names in `\.env` \(list [0-9a-f]{16}\)\|high$/);
    expect(ids(`${PUB("NEXT_PUBLIC_")}=\n${PUB("REACT_APP_")}=\n`)).not.toEqual(two);
  });

  it("policy ids ignore roles that don't matter, and titles stay short (review of PR 312)", () => {
    const table = "create table public.t (id int);\nalter table public.t enable row level security;\n";
    const scan = (pols) => scanSupabase(repo({ "supabase/migrations/001.sql": table + pols })).findings.filter((f) => f.templateId === "supabase-policy-open");
    const ids = (pols) => scan(pols).map(findingId);
    expect(ids("create policy p on public.t for delete to anon using (true);")).toEqual(ids("create policy p on public.t for delete to anon, service_role using (true);"));
    expect(ids("create policy p on public.t for update to anon using (true);")).toEqual(ids("create policy p on public.t for update to anon using (true) with check (true);"));
    const many = Array.from({ length: 5000 }, (_, i) => `r${i}`).join(", ");
    const [f] = scan(`create policy "${"n".repeat(100_000)}" on public.t for delete to anon, ${many} using (true);`);
    expect(f.title.length).toBeLessThan(300);
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

  it.skipIf(process.platform === "win32")("row 2: links out of the project and FIFOs among the files read are incomplete (review 9)", () => {
    const outside = mkdtempSync(join(tmpdir(), "penthera-supabase-out-"));
    writeFileSync(join(outside, "keys.js"), `const k = "${SERVICE}";`);
    mkdirSync(join(outside, "sb"));
    const root = repo({ "public/.keep": "", "src/inside.ts": "export {};" });
    symlinkSync(join(outside, "keys.js"), join(root, "public/keys.js"));
    symlinkSync(join(outside, "sb"), join(root, "supabase"));
    symlinkSync(join(root, "src/inside.ts"), join(root, "src/alias.ts"));
    execFileSync("mkfifo", [join(root, ".env.production")]);
    expect(scanSupabase(root).incomplete.map((i) => i.file).sort()).toEqual([".env.production", "public/keys.js", "supabase"]);
  });

  it.skipIf(process.platform === "win32")("row 2: a link out under any folder name is incomplete; a link inside ships its target (recheck)", () => {
    const outside = mkdtempSync(join(tmpdir(), "penthera-supabase-out-"));
    const root = repo({ "src/main.js": "import { x } from '../lib/x.js';\n", "server/keys.js": `export const k = "${SERVICE}";\n`, "public/.keep": "" }, { pkg: VITE });
    symlinkSync(outside, join(root, "lib"));
    symlinkSync(outside, join(root, "components"));
    symlinkSync(join(root, "server/keys.js"), join(root, "public/keys.js"));
    const r = scanSupabase(root);
    expect(r.incomplete.map((i) => i.file).sort()).toEqual(["components", "lib"]);
    expect(r.findings.map((f) => `${f.templateId}:${f.severity}:${f.file}`)).toEqual(["supabase-service-role-exposed:critical:server/keys.js"]);
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

// Vercel 01M6ZKR6TN5K2H7AFAZ0SJR388: nested supabase/ folders made every ancestor
// project reparse the same migrations with a fresh budget. Each SQL file now
// belongs to its nearest project and is read once.
describe("nested Supabase projects", () => {
  const nested = (levels, sql) => {
    let p = "supabase";
    const files = {};
    for (let i = 0; i < levels; i++) p = `${p}/migrations/n${i}/supabase`;
    files[`${p}/migrations/001.sql`] = sql;
    return repo(files);
  };
  it("reads a migration once, however deep the nesting", () => {
    const sql = "create table public.t (id int);\n" + "select 1;\n".repeat(20000);
    const shallow = nested(1, sql), deep = nested(20, sql);
    scanSupabase(shallow); scanSupabase(deep);
    const ms = (r) => { const s = process.hrtime.bigint(); for (let k = 0; k < 3; k++) scanSupabase(r); return Number(process.hrtime.bigint() - s) / 1e6; };
    const ratio = ms(deep) / Math.max(ms(shallow), 0.5);
    expect(ratio, `20 levels took ${ratio.toFixed(1)}x 1 level`).toBeLessThan(5); // the old code reparsed it 21 times
    const r = scanSupabase(deep);
    expect(r.findings.filter((f) => f.templateId === "supabase-rls-disabled").length).toBe(1); // found once, not once per ancestor
    expect(r.read).toHaveLength(1);
  });
  it("a nested supabase/ folder without migrations/ is still read by its ancestor", () => {
    const root = repo({ "supabase/migrations/old/supabase/legacy.sql": "create table public.legacy (id int);" });
    const files = scanSupabase(root).findings.filter((f) => f.templateId === "supabase-rls-disabled").map((f) => f.file);
    expect(files).toEqual(["supabase/migrations/old/supabase/legacy.sql"]);
  });
});
