/**
 * Three Vercel Security Review findings opened on main on 10 Nov 2026. Each
 * test reproduces the finding's own attack and fails on the code before the fix.
 *
 *   01M72SZFW1MNN7R5ZN5BYJ3X27  session cookies: an unbounded search back through a quoted key, once per flag
 *   01M72SYYAD2K4JACQ2JGE4EQX1  webhook writes: a chain regex that restarts at every receiver-named member
 *   01M72T0BXDMKVXHAPV95R32EVX  diff: a symlink in history where today's folder stands leads the scan outside the tree
 */
import { describe, it, expect, afterAll } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { sessionAuthHits } from "../lib/whitebox/session-auth.js";
import { firstWrite, missingCheckHits, WEBHOOK_RULE } from "../lib/whitebox/missing-checks.js";
import { diffScan, folderInTree } from "../src/cli/diff.js";

const temps = [];
afterAll(() => { for (const d of temps) rmSync(d, { recursive: true, force: true }); });
const tempDir = () => { const d = realpathSync(mkdtempSync(join(tmpdir(), "penthera-main-nov10-"))); temps.push(d); return d; };

/** The fastest of three runs, in ms: one slow run on a busy machine does not decide the test. */
const best = (fn) => {
  let t = Infinity;
  for (let i = 0; i < 3; i++) { const s = performance.now(); fn(); t = Math.min(t, performance.now() - s); }
  return t;
};
/** Linear work grows about 4x from n to 4n, quadratic about 16x. */
function linear(run, n) {
  run(64);
  const a = best(() => run(n));
  const b = best(() => run(4 * n));
  expect(b / Math.max(a, 5), `n=${n}: ${a.toFixed(1)} ms, 4n: ${b.toFixed(1)} ms`).toBeLessThan(9);
  return b;
}

// ── session cookies ───────────────────────────────────────────────────────

describe("session cookies: a long quoted key with many flags (01M72SZFW1MNN7R5ZN5BYJ3X27)", () => {
  const cookies = (src) => sessionAuthHits(src).hits.cookies.items.map((h) => h.what);
  const attack = (n) => `import session from "express-session";\nconst o = { "${"k".repeat(40 * n)}": { ${"secure: false, httpOnly: false, ".repeat(n)} } };\n`;

  it("stays linear: every flag in the object used to search back through the whole key", () => {
    const at4n = linear((n) => sessionAuthHits(attack(n)), 2000);
    expect(at4n, `4n took ${Math.round(at4n)} ms`).toBeLessThan(2000);
  });

  it("still reads a quoted cookie key, alone and nested", () => {
    expect(cookies(`import session from "express-session"; app.use(session({ secret: s, "cookie": { secure: false } }))`)).toEqual(["secure: false"]);
    expect(cookies(`import NextAuth from "next-auth";\nexport default NextAuth({ "cookies": { 'sessionToken': { name: "s", "options": { secure: false } } } })`)).toEqual(["secure: false"]);
    expect(cookies(`import { getIronSession } from "iron-session";\nexport const o = { password: P, cookieOptions: { secure: false, httpOnly: false, secure: false } }`)).toEqual(["secure: false", "httpOnly: false", "secure: false"]);
  });

  // Found by the blind review of this fix, already on main: the nested-key lookup read inherited properties.
  it("does not crash on an object key named like a built-in property", () => {
    for (const key of ["constructor", "__proto__", "toString", "valueOf", "hasOwnProperty"]) {
      expect(cookies(`import session from "express-session"; export const o = { ${key}: { secure: false } };`), key).toEqual([]);
    }
    expect(cookies(`import NextAuth from "next-auth"; export default NextAuth({ cookies: { sessionToken: { options: { constructor: { x: 1 }, secure: false } } } })`)).toEqual(["secure: false"]);
  });

  it("treats a quoted key of 63 characters or more as before: not a cookie key, no hit", () => {
    for (const len of [61, 62, 63, 64, 200]) {
      expect(cookies(`import session from "express-session"; const o = { "${"c".repeat(len)}": { secure: false } }`), `length ${len}`).toEqual([]);
    }
  });
});

// ── webhook writes ────────────────────────────────────────────────────────

// The two patterns chainWrite() replaced, as they were on main.
const OLD_DB = /(?<![\w$.])(?:this\.)?(?:prisma|db|database|tx|trx|client|drizzle|kysely|knex|sequelize|supabase|supabaseAdmin|admin|firestore|collection|repo|repository|orm|em|store|pool|conn|sql)\w*(?:\s*\.\s*\w+(?:\([^()]*\))?)*\s*\.\s*(?:create|createMany|insert|insertInto|insertMany|insertOne|update|updateMany|updateOne|upsert|delete|deleteFrom|deleteMany|deleteOne|destroy|remove|save|findOneAndUpdate|findByIdAndUpdate|bulkWrite|increment|decrement|set|add)\s*\(/;
const OLD_STRIPE = /(?<![\w$.])(?:this\.)?stripe\w*(?:\s*\.\s*\w+)*\s*\.\s*(?:create|update|cancel|capture|confirm|refund|del)\s*\(/;
const oldFirst = (body) => {
  let bestAt = -1;
  for (const re of [OLD_DB, OLD_STRIPE]) { const m = re.exec(body); if (m && (bestAt === -1 || m.index < bestAt)) bestAt = m.index; }
  return bestAt;
};
const counter = () => { let spent = 0; return { spend(k = 1) { spent += k; return true; }, get over() { return false; }, get spent() { return spent; } }; };
const newFirst = (body) => firstWrite(body, "", 0, body.length, counter());

describe("webhook writes: receiver-named members with spaces after the dots (01M72SYYAD2K4JACQ2JGE4EQX1)", () => {
  const HEAD = `export async function POST(req) {\n  const event = await req.json();\n  if (event.type === "x") {\n    `;
  const attack = (n, tail = "") => `${HEAD}db${" . db".repeat(n)};${tail}\n  }\n}\n`;
  const FILE = "app/api/webhook/route.ts";

  it("charges work in proportion to the chain, for each of the two chains", () => {
    for (const word of ["db", "stripe", "this.prisma", "client"]) {
      const spent = (n) => { const b = counter(); const body = `x = ${word}${` . ${word.replace("this.", "")}`.repeat(n)};`; firstWrite(body, "", 0, body.length, b); return b.spent / body.length; };
      expect(spent(40000), `${word}: work per character at 40,000 members`).toBeLessThan(12);
      expect(spent(40000) / spent(1000), `${word}: growth of work per character`).toBeLessThan(1.5);
    }
  });

  it("stays linear through the rule itself, and the scan is complete", () => {
    const at4n = linear((n) => missingCheckHits(attack(n), FILE), 20000);
    expect(at4n, `4n took ${Math.round(at4n)} ms`).toBeLessThan(2000);
    expect(missingCheckHits(attack(80000), FILE).incomplete).toBe(false);
  });

  it("still reports the write that follows a long chain with none", () => {
    const r = missingCheckHits(attack(20000, "\n    await db . user . create({ data: event });"), FILE);
    expect(Object.keys(r.hits)).toEqual([WEBHOOK_RULE]);
    expect(r.hits[WEBHOOK_RULE][0].at).toBeGreaterThan(100000);
  });

  it("finds the writes the old patterns found, by hand-picked shape", () => {
    const shapes = [
      "await db.user.create({})", "await prisma\n  .user\n  .update(x)", "this.db.orders.insert(o)", "db . db . db . save ()",
      "x . db . y . delete(1)", "tx.select().from(t).where(a).delete()", "dbClient.query(a).set(b)", "supabase.from('t').insert(r)",
      "stripe.customers.create(c)", "await this.stripeClient . subscriptions . cancel (id)", "stripe . stripe . refunds . create(r)",
      "db.user.create", "db.user.created()", "db.user.find(a(b)).create()", "foo.db.create()", "db$.create()", "db(1).create()",
      "db.user .find (x).create()", "stripe.customers.list(a).del()", "pool.query(q)", "em.persist(x).flush()", "store.set(k, v)",
    ];
    for (const s of shapes) expect(newFirst(s), s).toBe(oldFirst(s));
    expect(shapes.filter((s) => oldFirst(s) !== -1).length).toBeGreaterThan(10);
  });

  it("agrees with the old patterns on 60,000 generated chains, match for match", () => {
    const parts = ["db", "prisma", "stripe", "this.", "this", "x", "user", "create", "update", "del", "set", "created", " ", "\n", ".", " . ", ". ", " .", "(", ")", "(a)", "()", "(a, b)", ";", "$", "1", "_", "em", "admin", "email"];
    let seed = 20261110;
    const rnd = (k) => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % k; };
    const heads = ["db", "prisma", "stripe", "this.db", "this.stripe", "x", "dbx", "stripeApi", "em", " db", ".db", "$db", "a.db", "a . db"];
    const dots = [".", " . ", ". ", " .", "\n  .", ".\n", ". \t"];
    const names = ["user", "db", "stripe", "create", "update", "del", "set", "created", "x1", "this", "customers"];
    const after = ["", "", "", "()", "(a)", "(a, b)", " (a)", "(f(a))", "(", " ("];
    let hits = 0;
    for (let i = 0; i < 60000; i++) {
      let s = "";
      if (i % 2) {
        // a member chain, then sometimes a second one
        for (let c = 1 + rnd(2); c > 0; c--) {
          s += heads[rnd(heads.length)];
          for (let k = rnd(5); k > 0; k--) s += dots[rnd(dots.length)] + names[rnd(names.length)] + after[rnd(after.length)];
          s += parts[rnd(parts.length)];
        }
      } else {
        for (let k = 2 + rnd(14); k > 0; k--) s += parts[rnd(parts.length)];
      }
      const want = oldFirst(s);
      if (want !== -1) hits++;
      expect(newFirst(s), JSON.stringify(s)).toBe(want);
    }
    expect(hits, "generated chains the old patterns match").toBeGreaterThan(2000);
  });

  it("stops and marks the scan incomplete when the budget runs out, never a silent pass", () => {
    let left = 50;
    const tight = { spend(k = 1) { left -= k; return left >= 0; }, get over() { return left < 0; } };
    const body = `x${" . y".repeat(10)}; db${" . z".repeat(100)} . create()`;
    expect(firstWrite(body, "", 0, body.length, tight)).toBe(-1);
    expect(tight.over).toBe(true);
  });
});

// ── diff ──────────────────────────────────────────────────────────────────

const git = (dir, ...args) => execFileSync("git", ["-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...args], { cwd: dir, encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] });

describe("diff: a symlink in history where today's folder stands (01M72T0BXDMKVXHAPV95R32EVX)", () => {
  it("does not scan the link's target as the baseline", async () => {
    const work = tempDir();
    const outside = join(work, "private");
    mkdirSync(outside);
    writeFileSync(join(outside, "notes.js"), "const password = 'hunter2hunter2';\n");
    const repo = join(work, "repo");
    mkdirSync(repo);
    git(repo, "init", "-q", "-b", "main");
    symlinkSync(outside, join(repo, "pkg"));
    writeFileSync(join(repo, "README.md"), "x\n");
    git(repo, "add", "-A");
    git(repo, "commit", "-qm", "base: pkg is a link to a folder outside the repo");
    git(repo, "checkout", "-qb", "feat");
    rmSync(join(repo, "pkg"));
    mkdirSync(join(repo, "pkg"));
    writeFileSync(join(repo, "pkg", "index.js"), "export const a = 1;\n");
    git(repo, "add", "-A");
    git(repo, "commit", "-qm", "feat: pkg is a real folder");

    const scanned = [];
    const scan = async (dir) => { scanned.push(realpathSync(dir)); return { findings: [] }; };
    const r = await diffScan(join(repo, "pkg"), { ref: "main", scan });
    expect(r.error).toBeUndefined();
    expect(scanned, "folders the diff scanned").toEqual([realpathSync(join(repo, "pkg"))]);
  });

  it("accepts a real folder in the tree and refuses a link, a link above it, a file, a missing path and a path that climbs out", () => {
    const work = tempDir();
    const tree = join(work, "tree");
    const outside = join(work, "outside");
    mkdirSync(join(tree, "a", "b"), { recursive: true });
    mkdirSync(join(outside, "b"), { recursive: true });
    writeFileSync(join(tree, "file"), "x");
    symlinkSync(outside, join(tree, "link"));
    symlinkSync(join(tree, "a"), join(tree, "inner"));
    expect(folderInTree(tree, "")).toBe(tree);
    expect(folderInTree(tree, join("a", "b"))).toBe(join(tree, "a", "b"));
    expect(folderInTree(tree, "link")).toBeNull();
    expect(folderInTree(tree, join("link", "b"))).toBeNull();
    expect(folderInTree(tree, join("inner", "b"))).toBeNull();
    expect(folderInTree(tree, "file")).toBeNull();
    expect(folderInTree(tree, "nope")).toBeNull();
    expect(folderInTree(tree, join("..", "outside"))).toBeNull();
    expect(folderInTree(tree, join("a", "..", "..", "outside"))).toBeNull();
    expect(folderInTree(tree, outside)).toBeNull();
    // A backslash is a separator only where the platform says so.
    if (sep === "/") {
      mkdirSync(join(tree, "c\\d"));
      expect(folderInTree(tree, "c\\d")).toBe(join(tree, "c\\d"));
      expect(folderInTree(tree, "a\\b")).toBeNull();
    }
  });
});
