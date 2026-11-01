/**
 * Fix recipes (lib/fix): diffs apply cleanly, are idempotent, and the finding
 * is gone on re-scan. Each fixture is copied into a temp git repo; nothing is
 * installed or served, so headers/cookies/CORS/rate limits are verified with
 * the recipes' static probes and secrets with the real secret scanner.
 */
import { describe, it, expect, afterAll } from "vitest";
import { execFileSync, spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, writeFileSync, rmSync, symlinkSync, existsSync, mkdirSync, linkSync, appendFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import {
  RECIPES, planFixes, fixSummary, probeRepo, redactPlan, applyDiff, restoreFiles, createPatch, parsePatch, applyHunks,
} from "../lib/fix/index.js";
import { printPlan } from "../src/cli/fix.js";
import { createModelFixer, assertLocalModelUrl, OLLAMA_ORIGIN } from "../lib/fix/model.js";
import { scanSecrets } from "../lib/whitebox/secrets.js";
import { scanRepo } from "../src/scan-repo.js";
import { assertCleanTree } from "../lib/fix/apply.js";
import { gitInfo } from "../src/report/evidence.js";

const FIXTURES = resolve("tests/fixtures/fix");
const BIN = resolve("bin/penthera.js");
const temps = [];
afterAll(() => temps.forEach((d) => rmSync(d, { recursive: true, force: true })));

function git(dir, ...args) {
  return execFileSync("git", args, { cwd: dir, encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] });
}

function tempDir() {
  const dir = mkdtempSync(join(tmpdir(), "penthera-fix-"));
  temps.push(dir);
  return dir;
}

/** Copy a fixture into a fresh, committed git repo. */
function repoFrom(name) {
  const dir = tempDir();
  cpSync(join(FIXTURES, name), dir, { recursive: true });
  git(dir, "init", "-q");
  git(dir, "-c", "user.email=t@t", "-c", "user.name=t", "add", "-A");
  git(dir, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "fixture");
  return dir;
}

function commit(dir) {
  git(dir, "add", "-A");
  git(dir, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "fix");
}

const findingsFor = (dir) => [...scanSecrets(dir), ...probeRepo(dir)];

describe("recipes that do not bite", () => {
  const planFor = async (dir, title, category) => (await planFixes(dir, [{ title, category, severity: "high", url: category === "secrets" ? "routes/pay.js" : undefined }])).plans[0];
  const STRIPE = `const STRIPE_KEY = "sk_${"live"}_51NfakefakefakefakefakefakeAB";\nexport default STRIPE_KEY;\n`; // split so a self-scan does not flag this file
  const write = (dir, file, text) => { mkdirSync(join(dir, file, ".."), { recursive: true }); writeFileSync(join(dir, file), text); };

  it("checks a moved secret just before the server listens, after dotenv has run", async () => {
    const dir = repoFrom("express");
    const server = readFileSync(join(dir, "server.js"), "utf-8");
    expect(server).toMatch(/\.listen\(/);
    write(dir, "routes/pay.js", STRIPE);
    const plan = await planFor(dir, "", "secrets");
    expect(plan.files).toContain("server.js");
    applyDiff(dir, plan.diff, { allowDirty: true });
    const fixed = readFileSync(join(dir, "server.js"), "utf-8").split("\n");
    const listens = fixed.findIndex((l) => /\.listen\(/.test(l));
    expect(fixed[listens - 1]).toMatch(/if \(!process\.env\.STRIPE_KEY\) throw new Error\("Set STRIPE_KEY before starting the server/);
  });

  it("never puts the check inside a braceless guard", async () => {
    for (const guard of ["if (require.main === module)\n  app.listen(3000);\n", "if (require.main === module)\napp.listen(3000);\n", "if (ok) start();\nelse\n  app.listen(3000);\n"]) {
      const dir = repoFrom("express");
      write(dir, "server.js", readFileSync(join(dir, "server.js"), "utf-8").replace("app.listen(3000);\n", guard));
      write(dir, "routes/pay.js", STRIPE);
      const plan = await planFor(dir, "", "secrets");
      expect(plan.diff, guard).toContain("process.env.STRIPE_KEY");
      expect(plan.diff, guard).not.toContain("throw new Error");
    }
  });

  it("puts the check inside a braced guard", async () => {
    const dir = repoFrom("express");
    write(dir, "server.js", readFileSync(join(dir, "server.js"), "utf-8").replace("app.listen(3000);\n", "if (require.main === module) {\n  app.listen(3000);\n}\n"));
    write(dir, "routes/pay.js", STRIPE);
    applyDiff(dir, (await planFor(dir, "", "secrets")).diff, { allowDirty: true });
    expect(readFileSync(join(dir, "server.js"), "utf-8")).toMatch(/\{\n {2}if \(!process\.env\.STRIPE_KEY\) throw[^\n]*\n {2}app\.listen/);
  });

  it("refuses a multi-line guard and a line it cannot read", async () => {
    for (const guard of ["if (require.main === module &&\n    !process.env.X)\n  app.listen(3000);\n", "if (ok) // start\n  app.listen(3000);\n", "if (main) // {\n  app.listen(3000);\n", "if (main) /* { */\n  app.listen(3000);\n", "if (ok)\n  // start\n  app.listen(3000);\n"]) {
      const dir = repoFrom("express");
      write(dir, "server.js", readFileSync(join(dir, "server.js"), "utf-8").replace("app.listen(3000);\n", guard));
      write(dir, "routes/pay.js", STRIPE);
      expect((await planFor(dir, "", "secrets")).diff, guard).not.toContain("throw new Error");
    }
  });

  it("keeps a comment line above listen from blocking the check", async () => {
    const dir = repoFrom("express");
    write(dir, "server.js", readFileSync(join(dir, "server.js"), "utf-8").replace("app.listen(3000);\n", "// start the server\napp.listen(3000);\n"));
    write(dir, "routes/pay.js", STRIPE);
    expect((await planFor(dir, "", "secrets")).diff).toContain("throw new Error");
  });

  it("leaves a git-ignored .env.example alone and still moves the secret", async () => {
    const dir = repoFrom("express");
    write(dir, ".gitignore", ".env*\n");
    write(dir, "routes/pay.js", STRIPE);
    const plan = await planFor(dir, "", "secrets");
    expect(plan.files).not.toContain(".env.example");
    expect(plan.diff).toContain("process.env.STRIPE_KEY");
    expect(plan.ownerActions.join(" ")).toMatch(/\.gitignore/);
  });

  it("says when nothing loads .env", async () => {
    const dir = repoFrom("express");
    write(dir, "routes/pay.js", STRIPE);
    expect((await planFor(dir, "", "secrets")).ownerActions.join(" ")).toMatch(/Nothing in this app loads \.env/);
    const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf-8"));
    write(dir, "package.json", JSON.stringify({ ...pkg, dependencies: { ...pkg.dependencies, dotenv: "^16.0.0" } }));
    expect((await planFor(dir, "", "secrets")).ownerActions.join(" ")).not.toMatch(/Nothing in this app loads/);
  });

  it("masks a secret that sits in another fix's diff context", async () => {
    const dir = repoFrom("express");
    const key = `sk_${"live"}_51NfakefakefakefakefakefakeABCD`;
    write(dir, "server.js", readFileSync(join(dir, "server.js"), "utf-8").replace("const app = express();", `const stripeKey = "${key}";\nconst app = express();`));
    const { plans } = await planFixes(dir, [{ title: "Missing Content-Security-Policy", category: "headers", severity: "medium" }]);
    expect(plans[0].diff).toContain(key);
    const shown = redactPlan(plans[0]);
    expect(shown.diff).not.toContain(key);
    expect(shown.unchangedHidden).toBeGreaterThan(0);
  });

  it("adds a start-up check before Hono's serve()", async () => {
    const dir = repoFrom("hono");
    const entry = "src/index.ts";
    write(dir, entry, 'import { serve } from "@hono/node-server";\nimport { Hono } from "hono";\nconst app = new Hono();\nconst stripeKey = "sk_' + 'live_51NfakefakefakefakefakefakeAB";\napp.get("/", (c) => c.text(stripeKey));\nserve({ fetch: app.fetch, port: 3000 });\n');
    const finding = { title: "", category: "secrets", severity: "high", url: entry };
    const plan = (await planFixes(dir, [finding])).plans[0];
    expect(plan.diff).toMatch(/\+if \(!process\.env\.\w+\) throw new Error/);
  });

  it("adds no start-up check to a Next.js project", async () => {
    const dir = repoFrom("next");
    write(dir, "routes/pay.js", STRIPE);
    const plan = await planFor(dir, "", "secrets");
    expect(plan.diff).toContain("process.env.STRIPE_KEY");
    expect(plan.diff).not.toContain("throw new Error");
  });

  it("allows the origins the code calls in connect-src, and only valid hosts", async () => {
    const dir = repoFrom("express");
    write(dir, "public/app.js", [
      'const SUPABASE_URL = "https://abcdef.supabase.co";',
      'fetch("https://api.example.com/v1/x");',
      "fetch(\"https://evil.example.com'; script-src *\");",
      'const docs = "https://docs.example.org/page";',
      "",
    ].join("\n"));
    const plan = await planFor(dir, "Missing Content-Security-Policy", "headers");
    const csp = plan.diff.split("\n").find((l) => l.includes("connect-src"));
    expect(csp).toContain("connect-src 'self' https://abcdef.supabase.co https://api.example.com https://evil.example.com;");
    expect(csp).not.toContain("script-src *");
    expect(csp).not.toContain("docs.example.org");
  });

  it("leaves a CSP that exists but controls no scripts to the owner", async () => {
    const dir = repoFrom("express");
    const { plans } = await planFixes(dir, [{ title: "Content-Security-Policy does not control scripts", category: "headers", severity: "medium" }]);
    expect(plans).toEqual([]);
  });

  it("leaves a next.config it cannot read safely to the owner", async () => {
    const dir = repoFrom("next");
    rmSync(join(dir, "next.config.mjs"), { force: true });
    write(dir, "next.config.js", "const nextConfig = { images: { domains: [] }\n};\nmodule.exports = nextConfig;\n");
    const { plans } = await planFixes(dir, [{ title: "Missing Content-Security-Policy", category: "headers", severity: "medium" }]);
    expect(plans).toEqual([]);
  });

  it("lets Next.js use eval in development only", async () => {
    const dir = repoFrom("next");
    const plan = (await planFixes(dir, [{ title: "Missing Content-Security-Policy", category: "headers", severity: "medium" }])).plans[0];
    const line = plan.diff.split("\n").find((l) => l.includes('key: "Content-Security-Policy"'));
    expect(line).toContain('process.env.NODE_ENV === "development"');
    const [dev, prod] = line.split(" : ");
    expect(dev).toContain("'unsafe-eval'");
    expect(prod).not.toContain("'unsafe-eval'");
  });

  it("plans headers for a one-line next.config, keeping its options", async () => {
    const dir = repoFrom("next");
    rmSync(join(dir, "next.config.mjs"), { force: true });
    rmSync(join(dir, "next.config.js"), { force: true });
    write(dir, "next.config.js", "/** @type {import('next').NextConfig} */\nconst nextConfig = { reactStrictMode: true };\nmodule.exports = nextConfig;\n");
    const plan = await planFor(dir, "Missing Content-Security-Policy", "headers");
    expect(plan.diff).toContain("+  reactStrictMode: true,");
    expect(plan.diff).toContain("+  async headers() {");
  });
});

describe("plans never print a secret", () => {
  const fake = {
    url: ["postgres://admin:", "Sup3rSecretPw", "@db.internal:5432/prod"],
    aws: ["wJalrXUtnFEMI/K7MDENG/", "bPxRfiCYEXAMPLEKEY"],
    slack: ["xoxb-", "123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"],
  };
  const shown = (line, sign = " ") => redactPlan({ diff: `--- a/x.js\n+++ b/x.js\n@@ -1,1 +1,1 @@\n${sign}${line}\n` });

  it("masks a password in any URL, on any line", () => {
    for (const sign of ["+", "-"]) {
      const out = shown(`const db = "${fake.url.join("")}";`, sign);
      expect(out.diff).not.toContain(fake.url[1]);
      expect(out.redacted).toBe(true);
    }
  });

  it("hides a context line that names a secret, and masks a token shape anywhere", () => {
    expect(shown(`const AWS_SECRET_ACCESS_KEY = "${fake.aws.join("")}";`).diff).not.toContain(fake.aws[0]);
    expect(shown('const dbPassword = "two words here";').diff).not.toContain("two words");
    expect(shown(`const hook = "${fake.slack.join("")}";`).diff).not.toContain(fake.slack[1]);
    expect(shown(`setSlack(\`${fake.slack.join("")}\`);`, "+").diff).not.toContain(fake.slack[1]);
    expect(shown(`x = "${fake.aws.join("")}";`).diff).not.toContain(fake.aws[0]);
    expect(shown(`DB_PASSWORD=${fake.url[1]}`, "+").diff).not.toContain(fake.url[1]);
  });

  it.each([
    ["Slack webhook", `const hook = "https://hooks.slack.com/services/T0/B0/${"a1B2".repeat(6)}";`, "a1B2a1B2"],
    ["key in a query", 'fetch("https://maps.example/geo?key=AbCd1234EfGh&x=1");', "AbCd1234"],
    ["export", "export API_TOKEN=abc123def456", "abc123def"],
    ["YAML", "password: hunter2hunter2", "hunter2"],
    ["CRLF .env", "DB_PASSWORD=hunter2hunter2\r", "hunter2"],
    ["--password=", "mysql -u root --password=Hunter2xyz db", "Hunter2xyz"],
    ["--password with a space", "mysql -u root --password Hunter2xyz db", "Hunter2xyz"],
    ["a token after an import", 'import a from "a"; const token = "Hunter2xyz";', "Hunter2xyz"],
    ["a quote inside", `const password = "it's-a-Pa55word";`, "Pa55word"],
  ])("masks %s on changed and context lines", (_, line, secret) => {
    for (const sign of ["+", " "]) expect(shown(line, sign).diff).not.toContain(secret);
  });

  it.each([
    ['const dbpass = "pl41n-w0rd-horse";', "pl41n"],
    ["const pw='shorty1';", "shorty1"],
    ["// password is letmein-comment-pw", "letmein"],
    [`const v = "${"ab12".repeat(16)}";`, "ab12ab12"],
    ['const id = "9f1c2d3e-1234-4abc-8def-0123456789ab";', "9f1c2d3e"],
  ])("hides a context line it cannot trust: %s", (line, secret) => {
    expect(shown(line).diff).not.toContain(secret);
  });

  it("masks a quoted hex key or UUID on a changed line", () => {
    expect(shown(`const v = "${"ab12".repeat(16)}";`, "+").diff).not.toContain("ab12ab12ab12");
    expect(shown('const id = "9f1c2d3e-1234-4abc-8def-0123456789ab";', "+").diff).not.toContain("1234-4abc");
  });

  it("masks a whole key block, in a diff and in one string", () => {
    const body = ["MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7", "xxTuvWxYz0123456789abcdefGHIJKLMNOPqrstuv", "short"];
    const begin = ["-----BEGIN", "PRIVATE", "KEY-----"].join(" ");
    const end = ["-----END", "PRIVATE", "KEY-----"].join(" ");
    const diff = ["--- a/x.js", "+++ b/x.js", "@@ -1,6 +1,6 @@", " const key = `" + begin, ...body.map((l) => ` ${l}`), ` ${end}\`;`, " const app = express();", ""].join("\n");
    const out = redactPlan({ diff });
    for (const line of body) expect(out.diff).not.toContain(line);
    const changed = redactPlan({ diff: diff.replace(/^ (?!const app)/gm, "+") });
    for (const line of body) expect(changed.diff).not.toContain(line);
    expect(out.diff).toMatch(/… \d+ lines unchanged/);
    const inline = shown(`const k = "${begin}\\n${body[0]}\\n${end}";`, "+");
    expect(inline.diff).not.toContain(body[0]);
  });

  it("ends a key block at its hunk or on the other side of the diff", () => {
    const begin = ["-----BEGIN", "PRIVATE", "KEY-----"].join(" ");
    const lost = redactPlan({ diff: ["--- a/x.js", "+++ b/x.js", "@@ -1,2 +1,2 @@", `-const k = \`${begin}`, "-MIIEvQIBADANBgkqhkiG9w0BAQEFAASC", "+const k = process.env.KEY;", "@@ -9,1 +9,1 @@", "-a();", "+b();", "--- a/y.js", "+++ b/y.js", ""].join("\n") });
    expect(lost.diff).toContain("+const k = process.env.KEY;");
    expect(lost.diff).toContain("+b();");
    expect(lost.diff).toContain("+++ b/y.js");
    expect(lost.diff).not.toContain("MIIEvQIBAD");
  });

  it.each([
    ["// ", ""],
    ["# ", ""],
    ['"', '",'],
    ["  ", ""],
  ])("hides a whole deleted key block with lines shaped %s…%s", (before, after) => {
    const begin = ["-----BEGIN", "RSA PRIVATE", "KEY-----"].join(" ");
    const end = ["-----END", "RSA PRIVATE", "KEY-----"].join(" ");
    const body = ["MIIEvQIBADANBgkqhkiG9w0BAQ", "shortTAIL=="];
    const lines = [begin, ...body, end].map((l) => `-${before}${l}${after}`);
    const out = redactPlan({ diff: ["--- a/x.js", "+++ b/x.js", "@@ -1,4 +1,1 @@", ...lines, "+const k = process.env.KEY;", "@@ -9,1 +9,1 @@", "-a();", "+b();", ""].join("\n") });
    for (const l of body) expect(out.diff).not.toContain(l);
    expect(out.diff).toContain("+const k = process.env.KEY;");
    expect(out.diff).toContain("+b();");
  });

  it("masks a long base64 line on its own", () => {
    expect(shown(`  "${"QUJD".repeat(14)}" +`).diff).not.toContain("QUJDQUJDQUJD");
  });

  it("keeps a module name beside a secret word on a changed line", () => {
    expect(shown('const password = require("express");', "+").diff).toContain('require("express")');
  });

  it("shows no unchanged line at all, and leaves the applied diff alone", () => {
    const leaks = ['const headers = { Authorization: "Basic dXNlcjpodW50ZXIyMTIz" };', 'encryptionKey = "enc-value-12"', "SIGNING_KEY=abcdefgh1234", "curl -u admin:pw https://x.example"];
    const diff = ["--- a/x.js", "+++ b/x.js", "@@ -1,5 +1,5 @@", ...leaks.map((l) => ` ${l}`), "-old();", "+renew();", " tail();", ""].join("\n");
    const out = redactPlan({ diff });
    for (const l of leaks) expect(out.diff).not.toContain(l);
    expect(out.diff).toContain("… 4 lines unchanged");
    expect(out.diff).toContain("… 1 line unchanged");
    expect(out.diff).toContain("+renew();");
    expect(out.diff).toContain("-old();");
    expect(out.redacted).toBe(false);
    expect(out.unchangedHidden).toBe(5);
    expect(diff).toContain(leaks[0]);
  });

  it("claims redacted only when it changed something, and leaves plain code alone", () => {
    const plain = shown('app.get("/health", (req, res) => res.send("ok"));', "+");
    expect(plain.redacted).toBe(false);
    expect(plain.diff).toContain("/health");
    expect(shown('fetch("https://api.example.com/v1/items");', "+").diff).toContain("api.example.com");
  });
});

describe("the scan's fix line", () => {
  it("counts findings a recipe could take, without reading the repo", () => {
    expect(fixSummary([{ title: "Missing Content-Security-Policy", category: "headers" }, { title: "x", category: "secrets" }, { title: "x", category: "code-pattern" }])).toBe(2);
  });

  it("does not slow a repo scan on a big, secret-heavy repo", () => {
    const dir = repoFrom("express");
    const key = `sk_${"live"}_51Nfakefakefakefakefakefake`;
    writeFileSync(join(dir, "big.js"), `app${".use('/".repeat(100_000)}\n`);
    for (let i = 0; i < 200; i++) writeFileSync(join(dir, `s${i}.js`), `const a = "${key}${String(i).padStart(4, "0")}";\nconst b = "${key}${String(i).padStart(4, "1")}";\n`);
    const start = Date.now();
    const scan = spawnSync(process.execPath, [resolve("bin/penthera.js"), "--repo", dir, "--offline", "--json"], { encoding: "utf-8", maxBuffer: 1 << 28, env: { ...process.env, NO_COLOR: "1" } });
    expect(scan.status).toBe(1);
    expect(Date.now() - start).toBeLessThan(10_000);
  }, 60_000);

  it("finds a global limiter without stalling on a long line", () => {
    const dir = repoFrom("express");
    writeFileSync(join(dir, "big.js"), `app${".use('/".repeat(100_000)}\n`);
    const start = Date.now();
    probeRepo(dir);
    expect(Date.now() - start).toBeLessThan(3_000);
  }, 60_000);

  it("fix --apply refuses a dirty tree before it asks", () => {
    const dir = repoFrom("express");
    const { plans } = JSON.parse(execFileSync(process.execPath, [resolve("bin/penthera.js"), "fix", "--plan", "--repo", dir, "--json"], { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"] }));
    writeFileSync(join(dir, "scratch.js"), "x\n");
    let status = 0;
    let stderr = "";
    try {
      execFileSync(process.execPath, [resolve("bin/penthera.js"), "fix", "--apply", plans[0].id, "--repo", dir], { encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, NO_COLOR: "1" } });
    } catch (e) { status = e.status; stderr = e.stderr; }
    expect(status).toBe(2);
    expect(stderr).toMatch(/uncommitted changes/);
    expect(stderr).not.toMatch(/re-run with --yes/);
  });

  it("prints the command after a repo scan, and leaves the exit code and JSON alone", () => {
    const dir = repoFrom("express");
    const scan = (...extra) => {
      try {
        return { status: 0, out: execFileSync(process.execPath, [resolve("bin/penthera.js"), "--repo", dir, "--offline", ...extra], { encoding: "utf-8", env: { ...process.env, NO_COLOR: "1" } }) };
      } catch (e) { return { status: e.status, out: e.stdout }; }
    };
    const text = scan();
    expect(text.out).toMatch(/\d+ may be fixable:/);
    expect(text.out).toContain("penthera fix --plan --repo");
    const json = scan("--json");
    expect(json.status).toBe(text.status);
    expect(json.out).not.toMatch(/fixable:/);
    expect(JSON.parse(json.out).brief.next[0].command).toContain("penthera fix --plan --repo");
  });
});

describe("diff", () => {
  it("round-trips an edit, an insertion and a new file", () => {
    const before = "a\nb\nc\nd\ne\nf\ng\nh\n";
    const after = "a\nB\nc\nd\ne\nf\ng\nh\ni\n";
    const patch = createPatch("x.js", before, after);
    expect(patch).toContain("--- a/x.js");
    expect(applyHunks(before, parsePatch(patch)[0].hunks)).toBe(after);

    const created = createPatch("new.txt", null, "one\ntwo\n");
    expect(created).toMatch(/^--- \/dev\/null\n\+\+\+ b\/new.txt\n@@ -0,0 \+1,2 @@/);
    expect(applyHunks(null, parsePatch(created)[0].hunks)).toBe("one\ntwo\n");
  });

  it("keeps a missing final newline", () => {
    const patch = createPatch("x", "a\nb", "a\nc");
    expect(patch).toContain("\\ No newline at end of file");
    expect(applyHunks("a\nb", parsePatch(patch)[0].hunks)).toBe("a\nc");
  });

  it("returns an empty patch when nothing changed and refuses a stale hunk", () => {
    expect(createPatch("x", "a\n", "a\n")).toBe("");
    const patch = createPatch("x", "a\nb\n", "a\nc\n");
    expect(() => applyHunks("totally\ndifferent\n", parsePatch(patch)[0].hunks)).toThrow(/does not apply/);
  });
});

describe("applyDiff safety", () => {
  const edit = (file) => createPatch(file, "x\n", "y\n");

  it("refuses paths outside the repo, absolute paths, and .git", () => {
    const dir = repoFrom("express");
    for (const header of ["--- a/../escape.js\n+++ b/../escape.js", "--- /etc/hosts\n+++ /etc/hosts", "--- a/.git/config\n+++ b/.git/config"]) {
      const diff = `${header}\n@@ -1,1 +1,1 @@\n-x\n+y\n`;
      expect(() => applyDiff(dir, diff)).toThrow(/outside the repo|inside \.git|relative to the repo/);
    }
  });

  it("refuses a symlink that points outside the repo", () => {
    const dir = repoFrom("express");
    const outside = tempDir();
    writeFileSync(join(outside, "target.js"), "x\n");
    symlinkSync(outside, join(dir, "linked"));
    commit(dir);
    expect(() => applyDiff(dir, edit("linked/target.js"))).toThrow(/is a symlink/);
    expect(readFileSync(join(outside, "target.js"), "utf-8")).toBe("x\n");
  });

  it("refuses a create through a dangling symlink to a path outside the repo (360 review)", () => {
    const dir = repoFrom("express");
    symlinkSync("../escaped.txt", join(dir, "evil.js"));
    commit(dir);
    const escaped = resolve(dir, "..", "escaped.txt");
    rmSync(escaped, { force: true });
    expect(() => applyDiff(dir, createPatch("evil.js", null, "pwned\n"))).toThrow(/is a symlink/);
    expect(existsSync(escaped)).toBe(false);
  });

  it("refuses symlinks anywhere in the path, even ones that stay inside the repo", () => {
    const dir = repoFrom("express");
    mkdirSync(join(dir, "real"));
    writeFileSync(join(dir, "real", "a.js"), "x\n");
    symlinkSync("real", join(dir, "alias"));
    commit(dir);
    expect(() => applyDiff(dir, edit("alias/a.js"))).toThrow(/alias is a symlink/);
    expect(readFileSync(join(dir, "real", "a.js"), "utf-8")).toBe("x\n");
  });

  it("refuses .git in any case, at any depth, and HFS+/NTFS aliases of it (360 review)", () => {
    const dir = repoFrom("express");
    for (const path of [".GIT/hooks/pre-commit", ".Git/config", "sub/.git/config", "vendor/x/.GIT/hooks/post-checkout", ".git./config", ".g\u200cit/config", "GIT~1/config"]) {
      expect(() => applyDiff(dir, createPatch(path, null, "#!/bin/sh\necho pwned\n")), path).toThrow(/inside \.git/);
    }
    expect(existsSync(join(dir, ".git", "hooks", "pre-commit"))).toBe(false);
  });

  it("refuses edits to .gitmodules", () => {
    const dir = repoFrom("express");
    expect(() => applyDiff(dir, createPatch(".gitmodules", null, "[submodule \"x\"]\n\turl = ../evil\n"))).toThrow(/\.gitmodules/);
    expect(() => applyDiff(dir, createPatch("lib/.GitModules", null, "x\n"))).toThrow(/\.gitmodules/);
  });

  it.skipIf(process.platform === "win32")("never runs the scanned repo's core.fsmonitor command (360 review)", () => {
    const dir = repoFrom("express");
    const marker = join(tempDir(), "fsmonitor-ran");
    const hook = join(tempDir(), "fsmonitor.sh");
    writeFileSync(hook, `#!/bin/sh\ntouch ${JSON.stringify(marker)}\nexit 1\n`, { mode: 0o755 });
    git(dir, "config", "core.fsmonitor", hook);
    assertCleanTree(dir);
    expect(gitInfo(dir).commit).toMatch(/^[0-9a-f]{40}/);
    expect(existsSync(marker)).toBe(false);
    // Control: plain git status in that repo does run it.
    git(dir, "status", "--porcelain");
    expect(existsSync(marker)).toBe(true);
  });

  it("lets Penthera's own untracked reports stay, and nothing else", () => {
    const dir = repoFrom("express");
    mkdirSync(join(dir, "reports/nested"), { recursive: true });
    writeFileSync(join(dir, "reports/nested/scan.json"), "{}\n");
    expect(assertCleanTree(dir)).toEqual(["reports/nested/scan.json"]);
    const server = readFileSync(join(dir, "server.js"), "utf-8");
    expect(applyDiff(dir, createPatch("server.js", server, server + "// patched\n")).applied).toBe(true);
    git(dir, "checkout", "--", ".");

    // A fix never writes over one of them.
    expect(() => applyDiff(dir, createPatch("reports/nested/scan.json", "{}\n", "{\"a\":1}\n"))).toThrow(/uncommitted scan report/);
    // A file beside the folder, or a folder of that name deeper in, is the user's.
    writeFileSync(join(dir, "reports.js"), "x\n");
    expect(() => assertCleanTree(dir)).toThrow(/uncommitted changes/);
    rmSync(join(dir, "reports.js"));
    mkdirSync(join(dir, "src/reports"), { recursive: true });
    writeFileSync(join(dir, "src/reports/a.json"), "{}\n");
    expect(() => assertCleanTree(dir)).toThrow(/uncommitted changes/);
  });

  it("does not excuse a tracked report that changed", () => {
    const dir = repoFrom("express");
    mkdirSync(join(dir, "reports"));
    writeFileSync(join(dir, "reports/kept.json"), "{}\n");
    git(dir, "add", "-A");
    git(dir, "-c", "user.name=t", "-c", "user.email=t@l", "commit", "-qm", "track a report");
    writeFileSync(join(dir, "reports/kept.json"), "{\"a\":1}\n");
    expect(() => assertCleanTree(dir)).toThrow(/uncommitted changes/);
  });

  it("refuses a dirty tree or a non-git directory unless allowDirty", () => {
    const dir = repoFrom("express");
    writeFileSync(join(dir, "scratch.js"), "x\n");
    expect(() => applyDiff(dir, edit("scratch.js"))).toThrow(/uncommitted changes/);
    expect(applyDiff(dir, edit("scratch.js"), { allowDirty: true }).applied).toBe(true);
    expect(readFileSync(join(dir, "scratch.js"), "utf-8")).toBe("y\n");

    const plain = tempDir();
    writeFileSync(join(plain, "a.js"), "x\n");
    expect(() => applyDiff(plain, edit("a.js"))).toThrow(/not a git work tree/);
  });

  it("writes nothing on a dry run or when any hunk fails", () => {
    const dir = repoFrom("express");
    const good = createPatch("server.js", readFileSync(join(dir, "server.js"), "utf-8"), "replaced\n");
    expect(applyDiff(dir, good, { dryRun: true }).applied).toBe(false);
    expect(readFileSync(join(dir, "server.js"), "utf-8")).not.toBe("replaced\n");

    const bad = good + createPatch("routes/auth.js", "not the real content\n", "nope\n");
    expect(() => applyDiff(dir, bad)).toThrow(/does not apply/);
    expect(readFileSync(join(dir, "server.js"), "utf-8")).not.toBe("replaced\n");
  });
});

const EXPECTED = {
  express: ["secret-to-env", "security-headers", "cookie-flags", "cors-allowlist", "auth-rate-limit"],
  next: ["secret-to-env", "security-headers", "cookie-flags", "cors-allowlist", "auth-rate-limit"],
  fastify: ["security-headers", "cookie-flags", "cors-allowlist", "auth-rate-limit"],
  hono: ["security-headers", "cookie-flags", "cors-allowlist", "auth-rate-limit"],
};

describe.each(Object.keys(EXPECTED))("recipes on the %s fixture", (name) => {
  it("plans one fix per issue, each applying cleanly to the fixture", async () => {
    const dir = repoFrom(name);
    const { plans, unmatched } = await planFixes(dir, findingsFor(dir));
    expect(plans.map((p) => p.recipe).sort()).toEqual([...EXPECTED[name]].sort());
    expect(unmatched).toEqual([]);
    for (const p of plans) {
      expect(p.source).toBe("recipe");
      expect(applyDiff(dir, p.diff, { dryRun: true }).files.length).toBeGreaterThan(0);
    }
  });

  it("applies every fix, then re-scans clean and plans nothing (idempotent)", async () => {
    const dir = repoFrom(name);
    const original = findingsFor(dir);
    expect(original.length).toBeGreaterThan(0);

    // Apply one plan at a time and re-plan, as `penthera fix --apply` does:
    // plans touching the same file are made against the tree they will patch.
    for (let round = 0; round < 10; round++) {
      const { plans } = await planFixes(dir, findingsFor(dir));
      if (plans.length === 0) break;
      applyDiff(dir, plans[0].diff);
      commit(dir);
    }

    expect(findingsFor(dir)).toEqual([]);
    const again = await planFixes(dir, original);
    expect(again.plans).toEqual([]);
  });
});

describe("recipe details", () => {
  it("re-scanning with the real repo scanner clears the secret and the CORS wildcard", async () => {
    const dir = repoFrom("next");
    const before = await scanRepo(dir);
    expect(before.findings.some((f) => f.category === "secrets")).toBe(true);
    expect(before.findings.some((f) => /cors-wildcard/.test(f.title))).toBe(true);
    for (const recipe of ["secret-to-env", "cors-allowlist"]) {
      const { plans } = await planFixes(dir, (await scanRepo(dir)).findings.concat(probeRepo(dir)));
      applyDiff(dir, plans.find((p) => p.recipe === recipe).diff);
      commit(dir);
    }
    const after = await scanRepo(dir);
    expect(after.findings.some((f) => f.category === "secrets")).toBe(false);
    expect(after.findings.some((f) => /cors-wildcard/.test(f.title))).toBe(false);
  });

  it("secret plans always ask the owner to rotate, update .env.example, and mask the value", async () => {
    const dir = repoFrom("express");
    const { plans } = await planFixes(dir, scanSecrets(dir));
    const p = plans[0];
    expect(p.ownerActions.some((a) => /rotate/i.test(a) && /never rotate/i.test(a))).toBe(true);
    expect(p.files).toEqual(["server.js", ".env.example"]);
    expect(p.diff).toContain("+API_KEY=");
    expect(p.diff).toContain("h3J9sK2dLq8Wm4Zx");
    const shown = redactPlan(p);
    expect(shown.diff).not.toContain("h3J9sK2dLq8Wm4Zx");
    expect(shown.redactions).toBeUndefined();
  });

  it("matches header findings from a URL scan to the repo's framework", async () => {
    const dir = repoFrom("hono");
    const fromUrlScan = [
      { severity: "medium", title: "Missing Content-Security-Policy", category: "headers", url: "https://staging.example.com", source: "header-audit" },
      { severity: "low", title: "Missing X-Frame-Options", category: "headers", url: "https://staging.example.com", source: "header-audit" },
    ];
    const { plans } = await planFixes(dir, fromUrlScan);
    expect(plans).toHaveLength(1);
    expect(plans[0].findings).toHaveLength(2);
    expect(plans[0].diff).toContain('import { secureHeaders } from "hono/secure-headers";');
  });

  it("uses helmet when the Express app already depends on it", async () => {
    const dir = repoFrom("express");
    const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf-8"));
    pkg.dependencies.helmet = "^8.0.0";
    writeFileSync(join(dir, "package.json"), JSON.stringify(pkg, null, 2));
    const { plans } = await planFixes(dir, [{ title: "Missing X-Frame-Options", category: "headers", severity: "low" }]);
    expect(plans[0].diff).toContain('+import helmet from "helmet";');
    expect(plans[0].diff).toContain("+app.use(helmet());");
  });

  it("returns no plan when the anchor is not there", async () => {
    const dir = tempDir();
    writeFileSync(join(dir, "package.json"), JSON.stringify({ dependencies: { express: "^5.0.0" } }));
    writeFileSync(join(dir, "server.js"), 'import express from "express";\nconst app = makeApp(express);\nconst opts = { path: "/" };\nres.cookie("sid", "v", opts);\n');
    const { plans, unmatched } = await planFixes(dir, [
      { title: "Missing X-Frame-Options", category: "headers", severity: "low" },
      { title: 'Cookie "sid" missing HttpOnly', category: "cookie", severity: "medium" },
      { title: "Generic API key assignment in source", category: "secrets", severity: "high", url: "config.json" },
    ]);
    expect(plans).toEqual([]);
    expect(unmatched).toHaveLength(3);
  });

  it("leaves an existing Next.js headers() alone", async () => {
    const dir = repoFrom("next");
    writeFileSync(join(dir, "next.config.mjs"), 'export default {\n  async headers() {\n    return [];\n  },\n};\n');
    const { plans } = await planFixes(dir, [{ title: "Missing X-Frame-Options", category: "headers", severity: "low" }]);
    expect(plans).toEqual([]);
  });

  it("recipes never write during planning", async () => {
    const dir = repoFrom("fastify");
    await planFixes(dir, findingsFor(dir));
    expect(git(dir, "status", "--porcelain")).toBe("");
  });

  it("every recipe has the documented shape", () => {
    for (const r of RECIPES) {
      expect(typeof r.id).toBe("string");
      for (const fn of ["matches", "detect", "plan"]) expect(typeof r[fn]).toBe("function");
    }
  });
});

describe("local-model fallback", () => {
  it("only ever targets 127.0.0.1:11434", () => {
    expect(OLLAMA_ORIGIN).toBe("http://127.0.0.1:11434");
    expect(() => assertLocalModelUrl("http://127.0.0.1:11434/api/generate")).not.toThrow();
    for (const bad of ["http://localhost:11434/api/generate", "https://api.example.com/v1", "http://127.0.0.1:8080/", "http://10.0.0.2:11434/"]) {
      expect(() => assertLocalModelUrl(bad)).toThrow(/Refusing/);
    }
    expect(() => createModelFixer({})).toThrow(/model name/);
  });

  it("is used only when no recipe matches, and is labelled for human review", async () => {
    const dir = repoFrom("express");
    const calls = [];
    const fakeFetch = async (url, init) => {
      calls.push({ url, body: JSON.parse(init.body) });
      const before = readFileSync(join(dir, "server.js"), "utf-8");
      const diff = createPatch("server.js", before, before.replace('app.use(express.json());', 'app.use(express.json({ limit: "100kb" }));'));
      return Response.json({ response: "```diff\n" + diff + "```" });
    };
    const model = createModelFixer({ model: "qwen2.5-coder", fetch: fakeFetch });
    const { plans } = await planFixes(dir, [
      { title: "Missing X-Frame-Options", category: "headers", severity: "low" },
      { title: "Unbounded request body", category: "dos", severity: "medium", url: "server.js" },
    ], { model });
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("http://127.0.0.1:11434/api/generate");
    expect(calls[0].body.model).toBe("qwen2.5-coder");
    const m = plans.find((p) => p.source === "local-model");
    expect(m.confidence).toBe("needs-human-review");
    expect(plans.find((p) => p.recipe === "security-headers").source).toBe("recipe");
  });

  it("drops model output that does not apply or leaves the repo", async () => {
    const dir = repoFrom("express");
    for (const response of ["NO_FIX", "--- a/../x.js\n+++ b/../x.js\n@@ -1,1 +1,1 @@\n-a\n+b\n", "--- a/server.js\n+++ b/server.js\n@@ -1,1 +1,1 @@\n-nope\n+b\n"]) {
      const model = createModelFixer({ model: "m", fetch: async () => Response.json({ response }) });
      expect(await model.plan(dir, { title: "x", category: "dos", severity: "high", url: "server.js" })).toBeNull();
    }
  });

  it("stops reading a model response that never ends", async () => {
    const dir = repoFrom("express");
    const endless = new ReadableStream({ pull(c) { c.enqueue(new TextEncoder().encode(" ".repeat(64 * 1024))); } });
    const model = createModelFixer({ model: "m", fetch: async () => new Response(endless) });
    await expect(model.plan(dir, { title: "x", category: "dos", severity: "high", url: "server.js" })).rejects.toThrow(/exceeds/);
  });
});

describe("penthera fix CLI", () => {
  const cli = (dir, args) => {
    try {
      return { code: 0, out: execFileSync(process.execPath, [BIN, "fix", ...args], { cwd: dir, encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, NO_COLOR: "1" } }) };
    } catch (e) {
      return { code: e.status, out: `${e.stdout}${e.stderr}` };
    }
  };

  it("--plan prints diffs with secrets masked; --apply needs approval, then applies and verifies", () => {
    const dir = repoFrom("express");
    const plan = cli(dir, ["--plan"]);
    expect(plan.code).toBe(0);
    expect(plan.out).toContain("+++ b/server.js");
    expect(plan.out).not.toContain("h3J9sK2dLq8Wm4Zx");

    const json = JSON.parse(cli(dir, ["--plan", "--json"]).out);
    const id = json.plans.find((p) => p.recipe === "cookie-flags").id;

    const refused = cli(dir, ["--apply", id]);
    expect(refused.code).toBe(1);
    expect(git(dir, "status", "--porcelain")).toBe("");

    const applied = cli(dir, ["--apply", id, "--yes"]);
    expect(applied.code).toBe(0);
    expect(applied.out).toMatch(/verified Cookie "sid"/);
    expect(readFileSync(join(dir, "routes/auth.js"), "utf-8")).toContain("httpOnly: true");

    // The tree is now dirty, so the next apply is refused.
    const next = JSON.parse(cli(dir, ["--plan", "--json"]).out).plans[0].id;
    expect(cli(dir, ["--apply", next, "--yes"]).out).toMatch(/uncommitted changes/);
  });

  it("reads findings from a -o report", () => {
    const dir = repoFrom("fastify");
    const report = join(tempDir(), "report.json");
    writeFileSync(report, JSON.stringify({ findings: [{ title: "Missing Content-Security-Policy", category: "headers", severity: "medium" }] }));
    const out = JSON.parse(cli(dir, ["--plan", "--json", "-o", report]).out);
    expect(out.plans.map((p) => p.recipe)).toEqual(["security-headers"]);
  });
});

describe("applyDiff: all or nothing, printable, no aliases", () => {
  const status = (dir) => git(dir, "status", "--porcelain");

  it("refuses a diff that writes one path twice, or a file and a path under it, and writes nothing", () => {
    const dir = repoFrom("express");
    const server = readFileSync(join(dir, "server.js"), "utf-8");
    const edit = createPatch("server.js", server, server + "// patched\n");
    for (const diff of [
      edit + createPatch("d", null, "f\n") + createPatch("d/x", null, "y\n"),
      createPatch("new.js", null, "one\n") + createPatch("new.js", null, "two\n"),
      edit + createPatch("server.js", server, "// other\n" + server),
    ]) {
      expect(() => applyDiff(dir, diff, { dryRun: true })).toThrow(/more than once|both a file and the directory/);
      expect(() => applyDiff(dir, diff)).toThrow(/more than once|both a file and the directory/);
      expect(status(dir)).toBe("");
    }
  });

  it("puts back every file it wrote when a later write fails", () => {
    const dir = repoFrom("express");
    const server = readFileSync(join(dir, "server.js"), "utf-8");
    const diff = createPatch("server.js", server, server + "// patched\n") + createPatch("lib/new.js", null, "n\n") + createPatch("late.js", null, "y\n");
    // late.js appears after the checks and before the writes (the dryRun flag is read
    // exactly there), so the third write fails after two succeeded.
    const opts = { allowDirty: true, get dryRun() { writeFileSync(join(dir, "late.js"), "theirs\n"); return false; } };
    expect(() => applyDiff(dir, diff, opts)).toThrow(/late\.js changed on disk/);
    expect(readFileSync(join(dir, "server.js"), "utf-8")).toBe(server);
    expect(existsSync(join(dir, "lib"))).toBe(false);
    expect(readFileSync(join(dir, "late.js"), "utf-8")).toBe("theirs\n");
  });

  it("refuses to create a file under a path that is a file", () => {
    const dir = repoFrom("express");
    expect(() => applyDiff(dir, createPatch("routes/auth.js/x", null, "y\n"), { dryRun: true })).toThrow(/not a directory/);
  });

  it("refuses added lines with control characters that could hide code in a terminal", () => {
    const dir = repoFrom("express");
    const server = readFileSync(join(dir, "server.js"), "utf-8");
    for (const line of ['console.log("x") /*\r\x1b[2K+app.disable("x-powered-by"); // */', "a\x1b]8;;x\x07b", "a\x08b", "a\u009bb"]) {
      expect(() => applyDiff(dir, createPatch("server.js", server, server + line + "\n"))).toThrow(/control character/);
    }
    // A CRLF line ending and tabs are ordinary.
    expect(applyDiff(dir, createPatch("server.js", server, server + "\tconst a = 1;\r\n"), { dryRun: true }).applied).toBe(false);
    expect(status(dir)).toBe("");
  });

  it("refuses NTFS alternate data stream names and the 8.3 alias of .gitmodules", () => {
    const dir = repoFrom("express");
    for (const path of [".git::$INDEX_ALLOCATION/hooks/pre-commit", ".git:$I30:$INDEX_ALLOCATION/config", ".git::$DATA", "GITMOD~1", "sub/gitmod~12", ".gitmodules::$DATA", "a:b.js"]) {
      expect(() => applyDiff(dir, createPatch(path, null, "x\n"), { dryRun: true, allowDirty: true }), path).toThrow(/Refusing/);
    }
  });

  it.skipIf(process.platform === "win32")("replaces a hard-linked file instead of writing through it", () => {
    const dir = repoFrom("express");
    const outside = join(tempDir(), "outside.js");
    writeFileSync(outside, "safe\n");
    linkSync(outside, join(dir, "linked.js"));
    expect(applyDiff(dir, createPatch("linked.js", "safe\n", "changed\n"), { allowDirty: true }).applied).toBe(true);
    expect(readFileSync(join(dir, "linked.js"), "utf-8")).toBe("changed\n");
    expect(readFileSync(outside, "utf-8")).toBe("safe\n");
  });

  it("restoreFiles restores what still holds the fix, leaves edited files alone, and tries every file", () => {
    const dir = repoFrom("express");
    const server = readFileSync(join(dir, "server.js"), "utf-8");
    const auth = readFileSync(join(dir, "routes/auth.js"), "utf-8");
    const res = applyDiff(dir, createPatch("routes/auth.js", auth, auth + "// a\n") + createPatch("server.js", server, server + "// s\n") + createPatch("new.js", null, "n\n"));
    appendFileSync(join(dir, "routes/auth.js"), "// the user's edit\n");
    const r = restoreFiles(dir, res.files);
    expect(r.conflicts).toEqual(["routes/auth.js"]);
    expect(r.restored.sort()).toEqual(["new.js", "server.js"]);
    expect(r.errors).toEqual([]);
    expect(readFileSync(join(dir, "server.js"), "utf-8")).toBe(server);
    expect(existsSync(join(dir, "new.js"))).toBe(false);
    expect(readFileSync(join(dir, "routes/auth.js"), "utf-8")).toContain("the user's edit");
  });
});

describe("approval prompt rendering", () => {
  it("shows control characters as escapes in diffs, titles and paths", () => {
    const hidden = 'console.log("HIDDEN") /*\r\x1b[2K+app.disable("x-powered-by"); // */';
    let out = "";
    const write = process.stdout.write;
    process.stdout.write = (s) => { out += s; return true; };
    try {
      printPlan({
        id: "local-model-1", title: "Fix\x1b[2K", source: "local-model", confidence: "needs-human-review", ownerActions: [],
        findings: [{ severity: "high", title: "t\rX", url: "a‮b.js" }],
        diff: `--- a/server.js\n+++ b/server.js\n@@ -1 +1,2 @@\n const app = 1;\n+${hidden}\n`,
      });
    } finally {
      process.stdout.write = write;
    }
    const plain = out.replace(/\x1b\[[0-9;]*m/g, ""); // the prompt's own colours
    expect(plain).not.toMatch(/[\r\x1b‮]/);
    expect(plain).toContain("/*\\r\\e[2K+app.disable");
    expect(plain).toContain("Fix\\e[2K");
    expect(plain).toContain("t\\rX");
    expect(plain).toContain("a\\u{202e}b.js");
  });
});

describe("local-model context stays in the repo", () => {
  it("never sends a file outside the repo, via package.json main or a symlink", async () => {
    const outsideDir = tempDir();
    const outside = join(outsideDir, "private.js");
    writeFileSync(outside, "PRIVATE MATERIAL OUTSIDE THE REPO\n");
    const prompts = [];
    const model = createModelFixer({ model: "m", fetch: async (url, init) => { prompts.push(JSON.parse(init.body).prompt); return Response.json({ response: "NO_FIX" }); } });

    const viaMain = tempDir();
    writeFileSync(join(viaMain, "package.json"), JSON.stringify({ name: "x", main: `../${outsideDir.split(/[\\/]/).pop()}/private.js` }));
    await model.plan(viaMain, { title: "t", category: "x", severity: "high" });

    const viaLink = tempDir();
    symlinkSync(outside, join(viaLink, "server.js"));
    await model.plan(viaLink, { title: "t", category: "x", severity: "high" });

    expect(prompts.some((p) => p.includes("PRIVATE MATERIAL"))).toBe(false);
  });
});

describe("verifier integrity: a fix never edits its own checker", () => {
  const PROTECTED = [
    "test/app.js", "tests/app.js", "src/__tests__/a.js", "src/a.test.ts", "src/a.spec.js", "conftest.py",
    "vitest.config.ts", "jest.config.js", "playwright.config.ts", "pytest.ini", "package.json", "pyproject.toml",
    "penthera.policy.json", "penthera.suppress.json", "penthera.lock", "audit/baseline.json", ".penthera/memory/events.jsonl",
    ".github/workflows/ci.yml", ".husky/pre-commit", ".pre-commit-config.yaml", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "TESTS/App.js", "Src/A.TEST.js", "PACKAGE.JSON", ".GitHub/Workflows/ci.yml", "__TEST~1/a.js", ".gitmodules",
  ];

  it("refuses every protected path with PROTECTED and says to make the change by hand", () => {
    const dir = repoFrom("express");
    for (const file of PROTECTED) {
      let err = null;
      try {
        applyDiff(dir, createPatch(file, null, "x\n"), { dryRun: true, allowDirty: true });
      } catch (e) {
        err = e;
      }
      expect(err?.code, file).toBe("PROTECTED");
      expect(err.message).toMatch(/by hand/);
    }
  });

  it("still lets a fix edit ordinary source files with similar names", () => {
    const dir = repoFrom("express");
    for (const file of ["src/attest.js", "latest/x.js", "routes/contest.js", "testing-utils.js", "audit/report.js"]) {
      expect(() => applyDiff(dir, createPatch(file, null, "x\n"), { dryRun: true, allowDirty: true }), file).not.toThrow();
    }
  });

  it("refuses a model diff that edits a test file to make it pass, and reports it", async () => {
    const dir = repoFrom("express");
    mkdirSync(join(dir, "tests"));
    writeFileSync(join(dir, "tests/app.test.js"), "expect(bodyLimit()).toBe(true);\n");
    commit(dir);
    const diff = createPatch("tests/app.test.js", "expect(bodyLimit()).toBe(true);\n", "expect(true).toBe(true);\n");
    const model = createModelFixer({ model: "m", fetch: async () => Response.json({ response: "```diff\n" + diff + "```" }) });
    const finding = { title: "Unbounded request body", category: "dos", severity: "high", url: "server.js" };
    const { plans, unmatched, refused } = await planFixes(dir, [finding], { model });
    expect(plans).toHaveLength(0);
    expect(unmatched).toEqual([finding]);
    expect(refused).toHaveLength(1);
    expect(refused[0].reason).toMatch(/tests\/app\.test\.js: fix diffs never edit tests.*by hand/);
    expect(readFileSync(join(dir, "tests/app.test.js"), "utf-8")).toBe("expect(bodyLimit()).toBe(true);\n");
  });

  it("holds a recipe's diff to the same list (defence in depth)", async () => {
    const dir = repoFrom("express");
    const pkg = readFileSync(join(dir, "package.json"), "utf-8");
    const recipe = {
      id: "rogue", title: "Rogue", matches: () => true, detect: () => "express",
      plan: () => ({ diff: createPatch("package.json", pkg, pkg.replace('"private": true', '"private": true, "scripts": { "test": "exit 0" }')), files: ["package.json"] }),
    };
    const { plans } = await planFixes(dir, [{ title: "x", category: "dos", severity: "high" }], { recipes: [recipe] });
    expect(() => applyDiff(dir, plans[0].diff)).toThrow(expect.objectContaining({ code: "PROTECTED" }));
    expect(readFileSync(join(dir, "package.json"), "utf-8")).toBe(pkg);
  });
});
