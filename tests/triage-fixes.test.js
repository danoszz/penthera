/**
 * Triage fixes from a 2.0.0 run on a Next.js + FastAPI monorepo
 * (docs/research/spec-agent-brief.md, E1 to E8). Fixtures are our own;
 * secrets are split with join() so Penthera's self-scan does not report this file.
 */
import { describe, it, expect, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, truncateSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";
import { findSecretsInText, isPasswordKey } from "../lib/whitebox/secrets.js";
import { scanCodeSinks } from "../lib/whitebox/code-sinks.js";
import { gitIgnored } from "../lib/git.js";
import { buildActionPlan } from "../lib/remediation/index.js";
import { classifyPermission, checkPermissions } from "../lib/agents/rules.js";
import { formatMarkdownReport, coverageMarkdown } from "../src/report/markdown.js";
import { buildCoverage } from "../lib/coverage.js";
import { scanRepo } from "../src/scan-repo.js";

const dirs = [];
afterAll(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });
function repo(files, { git = false } = {}) {
  const root = mkdtempSync(join(tmpdir(), "penthera-triage-"));
  dirs.push(root);
  for (const [rel, body] of Object.entries(files)) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), body);
  }
  if (git) execFileSync("git", ["init", "-q"], { cwd: root, env: { ...process.env, HOME: root, GIT_CONFIG_NOSYSTEM: "1" } });
  return root;
}

const j = (...p) => p.join("");
const V = j("Kq7", "-vR2m", "Lz9");
const pw = (text) => findSecretsInText(text).filter((h) => h.name === "Hardcoded password").length;

describe("E1: style maps are not passwords", () => {
  it("skips a status-to-class map", () => {
    expect(pw(`const tone = { pass: 'text-emerald-400', fail: 'text-red-400', warn: 'text-amber-400' };`)).toBe(0);
    expect(pw(`const label = { pass: 'complete', fail: 'incomplete' };`)).toBe(0);
    expect(pw(`const cls = { db_pass: 'dark:bg-emerald-500/20' };`)).toBe(0);
    expect(pw(`const color = { pass: 'var(--success)', warn: 'hsl(var(--warn))' };`)).toBe(0);
  });

  it("a bare pass key next to fail or warn is a status map; alone it still counts", () => {
    expect(pw(`const tone = {\n  pass: 'complete',\n  fail: 'missing',\n};`)).toBe(0);
    expect(pw(`const conn = { user: 'svc', pass: 'zduxgq' };`)).toBe(1);
    expect(pw(`const c = { pass: "${V}" };`)).toBe(1);
    for (const k of ["pass", "db_pass", "smtp-pass", "SMTP_PASS", "password", "pwd", "DB_PASSWORD"]) expect(isPasswordKey(k), k).toBe(true);
  });

  it("still finds real password assignments", () => {
    expect(pw(`${j("pass", "word")} = "${V}"`)).toBe(1);
    expect(pw(`db_pass = "${V}"`)).toBe(1);
    expect(pw(`const c = { pwd: "${V}" };`)).toBe(1);
  });
});

describe("E2: the eval check skips build output and what git ignores", () => {
  const EVAL = "export function run (code) { return eval(code) }\n";

  it("skips .next-<suffix> build folders", () => {
    const root = repo({ "src/run.js": EVAL, "apps/web/.next-dev-0/server/chunk.js": EVAL, "apps/web/.next_alt/x.js": EVAL });
    const files = scanCodeSinks(root).map((f) => f.file);
    expect(files).toEqual(["src/run.js"]);
  });

  it("skips folders git ignores", () => {
    const root = repo({ ".gitignore": "out-build/\n", "src/run.js": EVAL, "out-build/chunk.js": EVAL }, { git: true });
    const files = scanCodeSinks(root, { ignored: gitIgnored(root) }).map((f) => f.file);
    expect(files).toEqual(["src/run.js"]);
  });
});

describe("E3 to E5: the action plan picks the step that fits", () => {
  const nodeTls = {
    severity: "high", category: "runtime-advisory", source: "runtime-advisory", url: ".nvmrc",
    title: "Node.js 22.21.1 is affected by Node.js TLS certificate hostname verification bypasses",
  };
  const stepFor = (f) => buildActionPlan([f])[0];

  it("E3: a runtime advisory that names TLS gets the upgrade step, not the TLS step", () => {
    const step = stepFor(nodeTls);
    expect(step.id).toBe("runtime");
    expect(step.action).toBe("Upgrade the runtime");
    expect(step.ownerAction).toBe(false);
  });

  it("E3: a TLS scan finding still gets the TLS step", () => {
    expect(stepFor({ severity: "high", title: "Weak TLS protocol: TLSv1.1" }).id).toBe("tls");
  });

  it("E4: keys in gitignored files get their own low step, not a history purge", () => {
    const plan = buildActionPlan([
      { severity: "low", category: "secrets", localOnly: true, title: "OpenAI API key in source", url: ".env" },
      { severity: "critical", category: "secrets", title: "Stripe secret key in source", url: "src/pay.js" },
    ]);
    const local = plan.find((a) => a.id === "secrets-local");
    expect(local.severity).toBe("low");
    expect(local.fix).not.toMatch(/history/);
    expect(plan.find((a) => a.id === "secrets").findings).toHaveLength(1);
  });

  it("E5: an eval sink gets the code-execution step, not the generic one", () => {
    expect(stepFor({ severity: "high", category: "code-pattern", pattern: "eval", source: "static-analysis", title: "eval in src/run.js" }).id).toBe("injection");
    expect(stepFor({ severity: "medium", category: "code-pattern", pattern: "cors-wildcard", title: "cors-wildcard in /api/x" }).id).toBe("review");
  });
});

describe("E6: permission findings say what the grant allows", () => {
  it("a pre-approved script in /tmp is its own rule", () => {
    for (const r of ["Bash(bash /tmp/scan.sh)", "Bash(/tmp/scan.sh)", "Bash(sh /var/tmp/a.sh)", "Bash(sh /private/tmp/a.sh)", "Bash(bash /dev/shm/a.sh)"]) {
      const c = classifyPermission(r);
      expect(c, r).toMatchObject({ rule: "permission-tmp-script", severity: "medium" });
      expect(c.why, r).not.toMatch(/any arguments/);
    }
    expect(checkPermissions({ permissions: [{ list: "allow", rule: "Bash(bash /tmp/scan.sh)", file: ".claude/settings.local.json" }], settings: [] })[0].detail)
      .toMatch(/Move the script into the repository/);
  });

  it("says 'any arguments' only for open-ended grants", () => {
    for (const r of ["Bash(bash:*)", "Bash(bash)", "Bash(curl *)"]) expect(classifyPermission(r).why, r).toMatch(/any arguments/);
    for (const r of ["Bash(bash ./scripts/check.sh)", "Bash(curl https://example.com/health)", "Bash(node scripts/build.js)", "Bash(ls /tmpfiles)"]) {
      expect(classifyPermission(r), r).toBeNull();
    }
  });
});

describe("E7: reports leave out sections that do not apply to the mode", () => {
  const base = { target: ".", timestamp: "2026-10-27T20:52:08.000Z", duration: 1000, findings: [], executedProbes: [] };

  it("a deps or agents report has no Reachable row and no empty WSTG table", () => {
    for (const mode of ["deps", "agents", "repo"]) {
      const md = formatMarkdownReport({ ...base, mode, reachable: true });
      expect(md, mode).not.toMatch(/\*\*Reachable\*\*/);
      expect(md, mode).not.toMatch(/OWASP WSTG coverage/);
    }
  });

  it("a URL scan keeps both", () => {
    const md = formatMarkdownReport({ ...base, mode: "url", reachable: true, executedProbes: ["security-headers"] });
    expect(md).toMatch(/\| \*\*Reachable\*\* \| Yes \|/);
    expect(md).toMatch(/OWASP WSTG coverage/);
  });
});

describe("E8: the coverage ledger counts what the eval check did not read", () => {
  // 2.3.2: a file over 512 KB is now read (streamed), not skipped, so the 600 KB
  // one-line file counts as minified, not as over the size limit. Only a file
  // over the 64 MiB read cap is "over the size limit": checked through the
  // coverage ledger alone, which only stats it, so no test reads 64 MiB.
  it("reports files over the size limit and skipped folders", async () => {
    const big = `export const blob = "${"a".repeat(600 * 1024)}";\n`;
    const root = repo({
      "src/run.js": "export function run (c) { return eval(c) }\n",
      "src/huge.js": big,
      "tests/helper.js": "eval(x)\n",
      "apps/web/.next-dev/chunk.js": "eval(x)\n",
    });
    const r = await scanRepo(root, { quiet: true });
    const sinks = r.coverage.families.find((f) => f.id === "code-sinks");
    expect(sinks.ran).toBe(true);
    // A minified file is checked like any other and only noted (Red Team E23).
    expect(sinks.examined).toBe(2);
    expect(sinks.minified).toBe(1);
    expect(sinks.skipped.minified).toBeUndefined();
    expect(sinks.skipped["too-large"]).toBeUndefined();
    writeFileSync(join(root, "src", "giant.js"), "");
    truncateSync(join(root, "src", "giant.js"), 64 * 1024 * 1024 + 1); // sparse
    const cov = buildCoverage(root, { ...r, sinkMinified: ["src/huge.js"] });
    const s2 = cov.families.find((f) => f.id === "code-sinks");
    expect(s2.skipped["too-large"]).toBe(1);
    expect(s2.examined).toBe(2);
    expect(s2.minified).toBe(1);
    expect(sinks.skipped, JSON.stringify(sinks)).toMatchObject({ "sink-skipped-folder": 2 });
    expect(s2.skipped, JSON.stringify(s2)).toMatchObject({ "sink-skipped-folder": 2 });
    const row = coverageMarkdown(cov).find((l) => l.startsWith("| eval, vm and exec sinks"));
    expect(row).toMatch(/^\| eval, vm and exec sinks \| 2 \|/);
    expect(row).toMatch(/1 over the size limit/);
    expect(row).toMatch(/2 in a folder the eval and exec check skips/);
  });

  it("says the check did not run when it did not", () => {
    const root = repo({ "src/a.js": "x\n" });
    const cov = buildCoverage(root, { executedProbes: ["secret-scanning"], attackSurface: [] });
    const sinks = cov.families.find((f) => f.id === "code-sinks");
    expect(sinks.ran).toBe(false);
    expect(coverageMarkdown(cov).join("\n")).toMatch(/eval, vm and exec sinks \| did not run \| - \|/);
  });
});

// Clerk secret keys share Stripe's sk_live_/sk_test_ prefix. They are told
// apart by CLERK_SECRET_KEY, and reported as Clerk's, never as Stripe's.
// Keys are built at run time so no real-looking key sits in the repository.
describe("Clerk secret keys", () => {
  const key = (prefix) => `${prefix}Xq7Lm2Pz9Rt4Vb8Nc3Wd6Yf1Gh5Jk0Ms`;
  it("names a Clerk live key as Clerk's, critical, and not as Stripe's", async () => {
    const { findSecretsInText } = await import("../lib/whitebox/secrets.js");
    const hits = findSecretsInText(`CLERK_SECRET_KEY=${key("sk_" + "live_")}\n`);
    expect(hits.map((h) => [h.name, h.severity])).toEqual([["Clerk secret key", "critical"]]);
  });
  it("reports a Clerk test key at high, also in JSON and YAML config", async () => {
    const { findSecretsInText } = await import("../lib/whitebox/secrets.js");
    expect(findSecretsInText(`"CLERK_SECRET_KEY": "${key("sk_" + "test_")}"`).map((h) => h.name)).toEqual(["Clerk test secret key"]);
    expect(findSecretsInText(`CLERK_SECRET_KEY: ${key("sk_" + "test_")}`).map((h) => h.severity)).toEqual(["high"]);
  });
  it("leaves Stripe keys and Clerk publishable keys as they were", async () => {
    const { findSecretsInText } = await import("../lib/whitebox/secrets.js");
    expect(findSecretsInText(`STRIPE_SECRET_KEY=${key("sk_" + "live_")}`).map((h) => h.name)).toEqual(["Stripe secret key"]);
    expect(findSecretsInText(`NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=${key("pk_" + "test_")}`)).toEqual([]);
  });
});
