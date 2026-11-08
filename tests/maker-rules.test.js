/**
 * The three checks for the stack makers ship on: framework advisories from
 * the lockfile, server secrets behind a public env prefix, and Server
 * Actions that write without an auth check. Each has a match and a no-match
 * case per form, a refusal case (incomplete, never silent), and a run through
 * scanRepo. Offline: temp folders only, no key-shaped strings in this file.
 */
import { describe, it, expect, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { scanRepo } from "../src/scan-repo.js";
import { exitCodeOf } from "../src/report/exit.js";
import { frameworkAdvisoriesForRepo, installedFromNpm, installedFromPnpm, installedFromYarn, installedFromBun, installedFromPackageJson, inRanges, FRAMEWORK_ADVISORIES } from "../lib/whitebox/framework-advisories.js";
import { isPublicSecretName, publicSecretSightings, scanPublicEnv } from "../lib/whitebox/public-env.js";
import { serverActions, uncheckedActions, scanServerActions } from "../lib/whitebox/server-actions.js";
import { buildActionPlan } from "../lib/remediation/index.js";

const temps = [];
afterAll(() => temps.forEach((d) => rmSync(d, { recursive: true, force: true })));
function repo(files) {
  const dir = mkdtempSync(join(tmpdir(), "penthera-maker-"));
  temps.push(dir);
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), text);
  }
  return dir;
}
const npmLock = (versions) => JSON.stringify({ lockfileVersion: 3, packages: { "": { dependencies: {} }, ...Object.fromEntries(Object.entries(versions).map(([k, v]) => [`node_modules/${k}`, { version: v }])) } }, null, 1);
const rsc = FRAMEWORK_ADVISORIES.find((a) => a.id === "CVE-2025-55182");
const mw = FRAMEWORK_ADVISORIES.find((a) => a.id === "CVE-2025-29927");

describe("framework-advisory: lockfile readers", () => {
  it("reads npm lockfiles, nested copies included", () => {
    const list = installedFromNpm(JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/next": { version: "15.5.6" }, "node_modules/a/node_modules/next": { version: "14.2.25" }, "node_modules/react": { version: "19.2.0" } } }));
    expect(list.map((p) => `${p.name}@${p.version}`).sort()).toEqual(["next@14.2.25", "next@15.5.6"]);
  });
  it("reads a v1 npm lockfile", () => {
    const list = installedFromNpm(JSON.stringify({ lockfileVersion: 1, dependencies: { next: { version: "13.5.8", dependencies: { "react-server-dom-webpack": { version: "19.0.0" } } } } }));
    expect(list.map((p) => `${p.name}@${p.version}`).sort()).toEqual(["next@13.5.8", "react-server-dom-webpack@19.0.0"]);
  });
  it("reads pnpm v9 and v5 keys", () => {
    expect(installedFromPnpm("lockfileVersion: '9.0'\npackages:\n  next@15.5.6(react@19.2.0):\n    resolution: {integrity: x}\n").map((p) => p.version)).toEqual(["15.5.6"]);
    expect(installedFromPnpm("lockfileVersion: 5.4\npackages:\n  /next/13.5.8:\n    resolution: {integrity: x}\n").map((p) => p.version)).toEqual(["13.5.8"]);
    expect(installedFromPnpm("packages:\n  /@scope/next/1.0.0:\n    resolution: {integrity: x}\n")).toEqual([]);
  });
  it("reads yarn classic and berry", () => {
    expect(installedFromYarn('# yarn lockfile v1\n\n"next@^15.5.0", next@15.5.6:\n  version "15.5.6"\n\nreact@^19:\n  version "19.2.0"\n').map((p) => `${p.name}@${p.version}:${p.line}`)).toEqual(["next@15.5.6:4"]);
    expect(installedFromYarn('__metadata:\n  version: 8\n\n"next@npm:^16.0.0":\n  version: 16.0.6\n').map((p) => p.version)).toEqual(["16.0.6"]);
  });
  it("reads bun.lock", () => {
    expect(installedFromBun('{\n "packages": {\n  "next": ["next@15.2.2", "", {}, ""],\n  "react-server-dom-webpack": ["react-server-dom-webpack@19.1.1", "", {}, ""],\n }\n}\n').map((p) => p.version)).toEqual(["15.2.2", "19.1.1"]);
  });
  it("takes an exact package.json pin and never a range", () => {
    expect(installedFromPackageJson('{"dependencies":{"next":"15.2.2","react":"^19.0.0"}}').map((p) => p.version)).toEqual(["15.2.2"]);
    expect(installedFromPackageJson('{"dependencies":{"next":"^15.2.2"}}')).toEqual([]);
  });
  it("compares releases only: canaries and pre-releases are never in a range", () => {
    expect(inRanges("15.5.6", rsc.packages.next)).toBe(true);
    expect(inRanges("15.5.7", rsc.packages.next)).toBe(false);
    expect(inRanges("16.0.7", rsc.packages.next)).toBe(false);
    expect(inRanges("15.0.0-canary.5", rsc.packages.next)).toBe(false);
    expect(inRanges("15.3.0-rc.1", rsc.packages.next)).toBe(false);
    expect(inRanges("14.2.24", mw.packages.next)).toBe(true);
    expect(inRanges("14.2.25", mw.packages.next)).toBe(false);
    expect(inRanges("15", mw.packages.next)).toBe(false);
  });
});

describe("framework-advisory: findings", () => {
  it("reports an affected Next.js and a fixed one not, with the lockfile line", () => {
    const bad = frameworkAdvisoriesForRepo(repo({ "package-lock.json": npmLock({ next: "15.5.6" }), "app/page.tsx": "" }));
    expect(bad.map((f) => [f.templateId, f.cve, f.severity, f.file])).toEqual([["framework-advisory", "CVE-2025-55182", "critical", "package-lock.json"]]);
    expect(bad[0].line).toBeGreaterThan(1);
    expect(frameworkAdvisoriesForRepo(repo({ "package-lock.json": npmLock({ next: "15.5.7" }) }))).toEqual([]);
  });
  it("reports the middleware bypass high with a middleware file and low without", () => {
    const withMw = frameworkAdvisoriesForRepo(repo({ "package-lock.json": npmLock({ next: "14.2.24" }), "middleware.ts": "export function middleware() {}\n" }));
    expect(withMw.map((f) => [f.cve, f.severity])).toEqual([["CVE-2025-29927", "high"]]);
    const without = frameworkAdvisoriesForRepo(repo({ "package-lock.json": npmLock({ next: "14.2.24" }) }));
    expect(without.map((f) => [f.cve, f.severity])).toEqual([["CVE-2025-29927", "low"]]);
    expect(without[0].description).toMatch(/no a middleware file|not reachable here/);
  });
  it("reports every advisory a version is in, and every copy in the tree", () => {
    const found = frameworkAdvisoriesForRepo(repo({ "package-lock.json": npmLock({ next: "15.2.2", "react-server-dom-webpack": "19.2.0" }), "middleware.ts": "x" }));
    expect(found.map((f) => `${f.cve}:${f.package}@${f.version}`).sort()).toEqual(["CVE-2025-29927:next@15.2.2", "CVE-2025-55182:next@15.2.2", "CVE-2025-55182:react-server-dom-webpack@19.2.0"]);
  });
  it("names a lockfile it cannot parse and does not pass it", () => {
    const refused = [];
    expect(frameworkAdvisoriesForRepo(repo({ "package-lock.json": "{ not json" }), { refused })).toEqual([]);
    expect(refused.map((e) => e.reason)).toEqual([expect.stringMatching(/could not be parsed/)]);
  });
  it("falls back to package.json pins only when there is no lockfile", () => {
    expect(frameworkAdvisoriesForRepo(repo({ "package.json": '{"dependencies":{"next":"15.2.2"}}' })).map((f) => f.cve).sort()).toEqual(["CVE-2025-29927", "CVE-2025-55182"]);
    expect(frameworkAdvisoriesForRepo(repo({ "package.json": '{"dependencies":{"next":"15.2.2"}}', "package-lock.json": npmLock({ next: "15.5.7" }) }))).toEqual([]);
  });
  it("has an explain_finding entry", () => {
    const plan = buildActionPlan([{ templateId: "framework-advisory", severity: "critical", title: "x" }]);
    expect(plan[0].action).toMatch(/Upgrade/);
  });
});

describe("public-env-secret: names", () => {
  it.each([
    ["NEXT_PUBLIC_OPENAI_API_KEY", true], ["VITE_API_KEY", true], ["EXPO_PUBLIC_API_TOKEN", true], ["REACT_APP_SECRET", true],
    ["PUBLIC_RESEND_API_KEY", true], ["NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY", true], ["NEXT_PUBLIC_DATABASE_URL", true], ["NUXT_PUBLIC_SMTP_PASSWORD", true],
    ["NEXT_PUBLIC_SUPABASE_ANON_KEY", false], ["NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY", false], ["NEXT_PUBLIC_FIREBASE_API_KEY", false],
    ["NEXT_PUBLIC_GA_MEASUREMENT_ID", false], ["NEXT_PUBLIC_POSTHOG_KEY", false], ["NEXT_PUBLIC_RECAPTCHA_SITE_KEY", false],
    ["NEXT_PUBLIC_API_URL", false], ["NEXT_PUBLIC_TOKEN_SYMBOL", false], ["NEXT_PUBLIC_CLIENT_ID", false], ["NEXT_PUBLIC_SENTRY_DSN", false],
    ["OPENAI_API_KEY", false], ["NEXT_PUBLIC_", false],
  ])("%s → %s", (name, want) => {
    expect(isPublicSecretName(name)).toBe(want);
  });
  it("reads env files by line, configs by token and code by env read, never comments", () => {
    expect(publicSecretSightings("# NEXT_PUBLIC_API_KEY=old\nNEXT_PUBLIC_OPENAI_API_KEY=x\nexport VITE_API_KEY='y'\nAPI_KEY=z\n", ".env.local").map((s) => `${s.name}:${s.line}`)).toEqual(["NEXT_PUBLIC_OPENAI_API_KEY:2", "VITE_API_KEY:3"]);
    expect(publicSecretSightings("// process.env.NEXT_PUBLIC_API_KEY\nconst k = process.env.NEXT_PUBLIC_API_KEY;\nconst j = process.env['NEXT_PUBLIC_RESEND_API_KEY'];\nconst v = import.meta.env.VITE_SECRET;\nconst ok = process.env.NEXT_PUBLIC_API_URL;\n", "page.tsx").map((s) => `${s.name}:${s.line}`)).toEqual(["NEXT_PUBLIC_API_KEY:2", "NEXT_PUBLIC_RESEND_API_KEY:3", "VITE_SECRET:4"]);
    expect(publicSecretSightings("module.exports = { env: { NEXT_PUBLIC_OPENAI_API_KEY: process.env.OPENAI_API_KEY } }\n", "next.config.js").map((s) => s.name)).toEqual(["NEXT_PUBLIC_OPENAI_API_KEY"]);
  });
});

describe("public-env-secret: findings", () => {
  it("is one finding per name, pointing at the env file first, high by name", () => {
    const found = scanPublicEnv(repo({
      ".env.example": "NEXT_PUBLIC_OPENAI_API_KEY=your-key-here\nNEXT_PUBLIC_SUPABASE_ANON_KEY=anon\n",
      "app/page.tsx": "export default function P() { return process.env.NEXT_PUBLIC_OPENAI_API_KEY; }\n",
      "lib/ai.ts": "const k = process.env.OPENAI_API_KEY;\n",
    }));
    expect(found.map((f) => [f.templateId, f.variable, f.severity, f.file, f.line])).toEqual([["public-env-secret", "NEXT_PUBLIC_OPENAI_API_KEY", "high", ".env.example", 1]]);
    expect(found[0].description).toContain("app/page.tsx:1");
  });
  it("is critical when the committed value is a provider key by shape", () => {
    const key = "sk-" + "proj-" + "A".repeat(40);
    const found = scanPublicEnv(repo({ ".env": `NEXT_PUBLIC_OPENAI_API_KEY=${key}\n` }));
    expect(found.map((f) => [f.severity, f.confidence])).toEqual([["critical", "confirmed"]]);
    expect(found[0].description).not.toContain(key);
  });
  it("leaves public-by-design names and non-public prefixes alone", () => {
    expect(scanPublicEnv(repo({ ".env": "NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk\nSTRIPE_SECRET_KEY=sk\nNEXT_PUBLIC_FIREBASE_API_KEY=x\n", "src/a.ts": "process.env.STRIPE_SECRET_KEY\n" }))).toEqual([]);
  });
  it("names a linked-out env file and does not pass it", () => {
    const dir = repo({ ".env": "X=1\n" });
    const outside = repo({ "secret.env": "NEXT_PUBLIC_API_KEY=x\n" });
    symlinkSync(join(outside, "secret.env"), join(dir, ".env.production"));
    const refused = [];
    scanPublicEnv(dir, { refused });
    expect(refused.map((e) => e.reason)).toEqual([expect.stringMatching(/outside the project/)]);
  });
});

const ACTION_FILES = {
  plainDelete: "\"use server\";\nimport { prisma } from \"@/lib/db\";\nexport async function deleteUser(id: string) {\n  await prisma.user.delete({ where: { id } });\n}\n",
  authed: "\"use server\";\nimport { auth } from \"@/auth\";\nimport { prisma } from \"@/lib/db\";\nexport async function deleteUser(id: string) {\n  const session = await auth();\n  if (!session) throw new Error(\"no\");\n  await prisma.user.delete({ where: { id } });\n}\n",
  wrapperByName: "\"use server\";\nimport { authAction } from \"./safe\";\nexport const removePost = authAction(async ({ id }) => { await db.delete(posts).where(eq(posts.id, id)); });\n",
  wrapperFromAuthModule: "\"use server\";\nimport { protectedClient } from \"@/lib/auth\";\nexport const removePost = protectedClient.action(async ({ id }) => { await db.delete(posts).where(eq(posts.id, id)); });\n",
  supabaseNoCheck: "\"use server\";\nimport { createClient } from \"@/utils/supabase/server\";\nexport async function addTodo(formData: FormData) {\n  const supabase = await createClient();\n  await supabase.from(\"todos\").insert({ title: formData.get(\"title\") });\n}\n",
  supabaseGetUser: "\"use server\";\nimport { createClient } from \"@/utils/supabase/server\";\nexport async function addTodo(formData: FormData) {\n  const supabase = await createClient();\n  const { data: { user } } = await supabase.auth.getUser();\n  if (!user) return;\n  await supabase.from(\"todos\").insert({ title: formData.get(\"title\") });\n}\n",
  inlineDirective: "import { db } from \"./db\";\nexport default function Page() {\n  async function save(form) {\n    \"use server\";\n    await db.insert(items).values({ a: form.get(\"a\") });\n  }\n  return null;\n}\n",
  readOnly: "\"use server\";\nexport async function list() { return await prisma.user.findMany(); }\n",
  authInComment: "\"use server\";\n// deleteUser calls auth() in middleware\nexport async function deleteUser(id) { await prisma.user.delete({ where: { id } }); }\n",
  authInString: "\"use server\";\nexport async function deleteUser(id) { const why = \"auth()\"; await prisma.user.delete({ where: { id } }); }\n",
  exportList: "\"use server\";\nasync function wipe() { await sql`DELETE FROM users`; }\nexport { wipe as wipeUsers };\n",
  mailAndPayment: "\"use server\";\nexport async function pay(amount) { await stripe.paymentIntents.create({ amount }); await resend.emails.send({ to: \"x\" }); }\n",
  clientFile: "\"use client\";\nexport async function x() { await prisma.user.delete({}); }\n",
  directiveInString: "const note = '\"use server\" is a directive';\nexport async function x() { await prisma.user.delete({}); }\n",
  notExported: "\"use server\";\nasync function helper(id) { await prisma.user.delete({ where: { id } }); }\nexport async function show() { return 1; }\n",
};
const unchecked = (src) => uncheckedActions(src).hits.map((h) => `${h.name}:${h.writes.join("+")}`);

describe("server-action-no-auth: one file", () => {
  it("reports an exported write with no check", () => expect(unchecked(ACTION_FILES.plainDelete)).toEqual(["deleteUser:a database write"]));
  it("accepts auth() in the body", () => expect(unchecked(ACTION_FILES.authed)).toEqual([]));
  it("accepts a wrapper named for auth", () => expect(unchecked(ACTION_FILES.wrapperByName)).toEqual([]));
  it("accepts a wrapper imported from an auth module", () => expect(unchecked(ACTION_FILES.wrapperFromAuthModule)).toEqual([]));
  it("reports a Supabase insert with no getUser", () => expect(unchecked(ACTION_FILES.supabaseNoCheck)).toEqual(["addTodo:a database write"]));
  it("accepts supabase.auth.getUser()", () => expect(unchecked(ACTION_FILES.supabaseGetUser)).toEqual([]));
  it("finds a function whose body starts with the directive", () => expect(unchecked(ACTION_FILES.inlineDirective)).toEqual(["save:a database write"]));
  it("never reports a read-only action", () => expect(unchecked(ACTION_FILES.readOnly)).toEqual([]));
  it("does not read a check from a comment or a string", () => {
    expect(unchecked(ACTION_FILES.authInComment)).toEqual(["deleteUser:a database write"]);
    expect(unchecked(ACTION_FILES.authInString)).toEqual(["deleteUser:a database write"]);
  });
  it("follows an export list and raw SQL", () => expect(unchecked(ACTION_FILES.exportList)).toEqual(["wipe:a database write"]));
  it("names mail and payment sinks", () => expect(unchecked(ACTION_FILES.mailAndPayment)).toEqual(["pay:a mail send+a payment call"]));
  it("ignores client files, a directive in a string, and unexported helpers", () => {
    expect(serverActions(ACTION_FILES.clientFile).actions).toEqual([]);
    expect(serverActions(ACTION_FILES.directiveInString).actions).toEqual([]);
    expect(unchecked(ACTION_FILES.notExported)).toEqual([]);
  });
});

describe("server-action-no-auth: findings", () => {
  it("is one finding per file, high, listing the actions", () => {
    const found = scanServerActions(repo({ "app/actions.ts": ACTION_FILES.plainDelete + ACTION_FILES.exportList.replace('"use server";\n', ""), "app/ok.ts": ACTION_FILES.authed }));
    expect(found.map((f) => [f.templateId, f.severity, f.confidence, f.file, f.actions])).toEqual([["server-action-no-auth", "high", "potential", "app/actions.ts", ["deleteUser", "wipe"]]]);
  });
  it("is medium when a root middleware calls an auth function", () => {
    const found = scanServerActions(repo({ "app/actions.ts": ACTION_FILES.plainDelete, "middleware.ts": "import { auth } from \"@/auth\";\nexport default auth((req) => {});\n" }));
    expect(found.map((f) => f.severity)).toEqual(["medium"]);
    expect(found[0].description).toContain("middleware.ts");
  });
  it("names a linked-out action file and does not pass it", () => {
    const dir = repo({ "app/page.tsx": "" });
    const outside = repo({ "actions.ts": ACTION_FILES.plainDelete });
    symlinkSync(join(outside, "actions.ts"), join(dir, "app", "actions.ts"));
    const refused = [];
    expect(scanServerActions(dir, { refused })).toEqual([]);
    expect(refused.map((e) => e.reason)).toEqual([expect.stringMatching(/outside the project/)]);
  });
});

describe("in a repo scan", () => {
  it("runs all three and names them in the probes", async () => {
    const r = await scanRepo(repo({
      "package-lock.json": npmLock({ next: "15.5.6" }),
      ".env.example": "NEXT_PUBLIC_RESEND_API_KEY=\n",
      "app/actions.ts": ACTION_FILES.plainDelete,
      "app/page.tsx": "export default function P() { return null; }\n",
    }));
    expect(r.executedProbes).toEqual(expect.arrayContaining(["framework-advisories", "public-env", "server-actions"]));
    expect(r.findings.map((f) => f.templateId).filter((t) => ["framework-advisory", "public-env-secret", "server-action-no-auth"].includes(t)).sort()).toEqual(["framework-advisory", "public-env-secret", "server-action-no-auth"]);
    expect(exitCodeOf(r)).toBe(1);
  });
  it("marks the scan incomplete when a lockfile cannot be parsed", async () => {
    const r = await scanRepo(repo({ "package-lock.json": "{ broken", "app/page.tsx": "" }));
    expect(r.incomplete.map((x) => x.file)).toEqual(["package-lock.json"]);
    expect(exitCodeOf(r)).toBe(2);
  });
  it("is quiet on a clean app", async () => {
    const r = await scanRepo(repo({
      "package-lock.json": npmLock({ next: "15.5.7", "react-server-dom-webpack": "19.2.1" }),
      ".env.example": "NEXT_PUBLIC_SUPABASE_ANON_KEY=\nSUPABASE_SERVICE_ROLE_KEY=\n",
      "app/actions.ts": ACTION_FILES.authed,
      "app/page.tsx": "export default function P() { return null; }\n",
    }));
    expect(r.findings.filter((f) => ["framework-advisory", "public-env-secret", "server-action-no-auth"].includes(f.templateId))).toEqual([]);
    expect(r.incomplete).toBeUndefined();
  });
});
