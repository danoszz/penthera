/**
 * Two false positives from a real agent run on a Next.js and Firebase repo
 * (8 Nov 2026), each decided by parsing, not matching, with the near misses
 * that must still fire:
 * 1. A Google Secret Manager resource name in a Firebase Extensions .env is a
 *    pointer, not a key: no finding.
 * 2. A password beside a reserved test address (example.com) in a test or
 *    verify script stays high but goes to Check first, with the reason.
 */
import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { findSecretsInText, isSecretManagerRef, scanSecrets } from "../lib/whitebox/secrets.js";
import { bucketOf } from "../src/report/brief.js";

const repo = (files) => {
  const d = mkdtempSync(join(tmpdir(), "penthera-precision-"));
  for (const [f, text] of Object.entries(files)) {
    mkdirSync(dirname(join(d, f)), { recursive: true });
    writeFileSync(join(d, f), text);
  }
  return d;
};
// Test values are built at run time, so Penthera's own self-scan doesn't report this file.
const TEMP = ["Temp", "Pass123!"].join("");
const ADMIN = ["Zq8!", "vLr2#pW"].join("");
const env = (value) => findSecretsInText(`LOCATION=us-central1\nSTRIPE_API_KEY=${value}\n`, { path: "extensions/firestore-stripe-payments.env" });

describe("a Secret Manager resource name is a reference, not a key", () => {
  it("the gaia value and its forms give no finding", () => {
    for (const v of [
      "projects/gaia-prod/secrets/firestore-stripe-payments-STRIPE_API_KEY/versions/1",
      "projects/123456789012/secrets/STRIPE_API_KEY/versions/latest",
      "projects/gaia-prod/secrets/STRIPE_API_KEY",
    ]) {
      expect(isSecretManagerRef(v), v).toBe(true);
      expect(env(v), v).toEqual([]);
    }
    // Under a password key, in a config file, too.
    expect(findSecretsInText("DB_PASSWORD=projects/gaia-prod/secrets/db-password/versions/2\n", { path: "extensions/x.env" })).toEqual([]);
  });

  it("near misses still fire", () => {
    const real = "aB3xK9mQ2pL7vR4tW8yZ1cN6";
    for (const v of [
      `projects/gaia-prod/secrets/${real}/versions/1`, // a generated key in the name slot
      "projects/gaia-prod/secrets/STRIPE_API_KEY/versions/1x", // not a version
      "projects/gaia-prod/secrets/STRIPE_API_KEY/versions/1/extra",
      "xprojects/gaia-prod/secrets/STRIPE_API_KEY/versions/1",
      "projects/Gaia_Prod/secrets/STRIPE_API_KEY/versions/1", // not a project ID
      "projects/gaia-prod/keys/STRIPE_API_KEY/versions/1",
      real,
    ]) {
      expect(isSecretManagerRef(v), v).toBe(false);
      expect(env(v).map((h) => h.name), v).toEqual(["Generic API key assignment"]);
    }
    // A provider key in the name slot is still found by its own rule.
    const stripe = `sk_live_${"a1B2c3D4".repeat(3)}`;
    expect(env(`projects/gaia-prod/secrets/${stripe}/versions/1`).map((h) => h.name)).toContain("Stripe secret key");
  });
});

describe("a test account's password goes to Check first, still high", () => {
  const script = (email, value = TEMP) => `const now = Date.now();\nconst testEmail = \`${email}\`;\nconst testPassword = "${value}";\nawait signUp(testEmail, testPassword);\n`;
  const pw = (d) => scanSecrets(d).filter((f) => f.title === "Hardcoded password in source");

  it("the gaia script: high, potential, Check first, and says why", () => {
    const [f] = pw(repo({ "frontend/scripts/verify-firebase-storage-security.js": script("security-check-${now}@example.com") }));
    expect(f).toMatchObject({ severity: "high", confidence: "potential" });
    expect(f.description).toMatch(/`testEmail` is set to an address at example\.com on a nearby line, in a test location/);
    expect(bucketOf(f).bucket).toBe("check");
  });

  it("other reserved test domains count too", () => {
    for (const email of ["qa@test.example.org", "a@foo.test", "x@app.invalid"]) {
      expect(pw(repo({ "e2e/login.spec.ts": script(email) }))[0].confidence, email).toBe("potential");
    }
  });

  it("a username field in the same call counts", () => {
    const [f] = pw(repo({ "tests/login.test.js": `await login({ username: "qa@example.com", password: "${TEMP}" });\n` }));
    expect(f.confidence).toBe("potential");
  });

  // The blind review of bf88323 (8 Nov 2026): real passwords in these files went to
  // Check first on a nearby example.com comment. Each must stay in Act on.
  it("the reviewer's six reproductions stay in Act on", () => {
    const P = ["Kx9!", "mQ2#vL7pR"].join("");
    const comment = (pre = "") => `// contact ops@example.com\n${pre}const password = "${P}";\n`;
    const files = {
      "scripts/deploy.js": comment(),
      "scripts/seed-prod.js": `const admin = { email: "admin@example.com", password: "${P}" };\n`,
      "src/payments/verify.ts": comment(),
      "src/auth/check.js": comment(),
      "src/health-check.js": comment(),
      "src/verify-email.ts": `const from = "noreply@example.com"; const password = "${P}";\n`,
      // A proper test-account field does not help outside a test location either.
      "scripts/migrate.js": script("a@example.com"),
      "app/spec/config.js": script("a@example.com"),
      "src/lib/smoke.js": script("a@example.org"),
    };
    for (const [file, text] of Object.entries(files)) {
      const [f] = pw(repo({ [file]: text }));
      expect(f, file).toBeDefined();
      expect(f.confidence, file).toBeUndefined();
      expect(bucketOf(f).bucket, file).toBe("act");
    }
  });

  it("in a test location, an address only counts as an email, user or login value in code", () => {
    const P = ["Kx9!", "mQ2#vL7pR"].join("");
    for (const text of [
      `// contact ops@example.com\nconst password = "${P}";\n`,
      `// testEmail = "ops@example.com"\nconst password = "${P}";\n`,
      `const x = 1; // user: "ops@example.com"\nconst password = "${P}";\n`,
      `/* email = "ops@example.com" */\nconst password = "${P}";\n`,
      `const note = "ops@example.com";\nconst password = "${P}";\n`,
      `const testEmail = "ops@example.com.evil.io";\nconst password = "${P}";\n`,
    ]) {
      const [f] = pw(repo({ "tests/login.test.js": text }));
      expect(f.confidence, text).toBeUndefined();
    }
  });

  // The re-check of 72a23e3 (Low): text that only looks like a field.
  it("a field inside a block comment, a template, after a regex quote, or inside a string does not count", () => {
    const P = ["Kx9!", "mQ2#vL7pR"].join("");
    const line = `const password = "${P}";`;
    for (const text of [
      `/*\n  email: "admin@example.com"\n*/\n${line}\n`,
      `/**\n * email: "admin@example.com"\n */\n${line}\n`,
      `  email: "admin@example.com"\n*/\n${line}\n`, // the window starts inside a comment
      `const s = \`\n  email: "admin@example.com"\n\`;\n${line}\n`,
      `const re = /"/; // email: "admin@example.com"\n${line}\n`,
      `const note = "email: 'admin@example.com'";\n${line}\n`,
    ]) {
      const [f] = pw(repo({ "tests/login.test.js": text }));
      expect(f.confidence, text).toBeUndefined();
    }
    // A real field over several lines still counts.
    const [ok] = pw(repo({ "tests/login.test.js": `const u = {\n  email: "qa@example.com",\n  password: "${P}",\n};\n` }));
    expect(ok.confidence).toBe("potential");
  });

  // Vercel Security Review on PR 310 (Low, 01M6W3PH0NW0YNDY626BYEC9VB): account-like text
  // inside a string literal kept its quotes through the filter and matched as a field.
  it("account-looking text inside a diagnostic string does not count, in verify and smoke scripts", () => {
    const P = ["Kx9!", "mQ2#vL7pR"].join("");
    const line = `const password = "${P}";`;
    for (const file of ["scripts/verify-login.js", "scripts/smoke-login.js"]) {
      for (const text of [
        `console.log(" email: \\"a@example.com\\", ok");\n${line}\n`,
        `const msg = ' email: "a@example.com",';\n${line}\n`,
        `log(\`user = "a@example.com";\`);\n${line}\n`,
        `throw new Error("login: 'a@example.com', failed");\n${line}\n`,
      ]) {
        const [f] = pw(repo({ [file]: text }));
        expect(f.confidence, `${file}: ${text}`).toBeUndefined();
        expect(bucketOf(f).bucket).toBe("act");
      }
    }
    // A quoted key in code is still a field.
    const [ok] = pw(repo({ "tests/login.test.js": `login({ "email": "a@example.com", password: "${P}" });\n` }));
    expect(ok.confidence).toBe("potential");
  });

  it("near misses stay in Act on", () => {
    const cases = {
      "a real domain beside it": { "scripts/verify-login.js": script("ops@gaia.computer") },
      "a lookalike domain": { "scripts/verify-login.js": script("ops@example.com.evil.io") },
      "a test address in an app file": { "src/lib/auth.js": script("check@example.com") },
      "the address too far away": { "scripts/verify-login.js": `const e = "a@example.com";\n${"\n".repeat(10)}const testPassword = "${TEMP}";\n` },
      "a second password elsewhere in the file": { "scripts/verify-login.js": `${script("a@example.com")}${"\n".repeat(20)}const adminPassword = "${ADMIN}";\n` },
    };
    for (const [why, files] of Object.entries(cases)) {
      const [f] = pw(repo(files));
      expect(f, why).toBeDefined();
      expect(f.severity, why).toBe("high");
      expect(f.confidence, why).toBeUndefined();
      expect(bucketOf(f).bucket, why).toBe("act");
    }
  });

  it("a file that fills the hit cap with test passwords keeps a real one in Act on", () => {
    const decoys = Array.from({ length: 300 }, (_, i) => `const e${i} = "a@example.com"; const testPassword${i} = "TempPass${i}!x";`).join("\n");
    const [f] = pw(repo({ "scripts/verify-login.js": `${decoys}\nconst adminPassword = "${ADMIN}";\n` }));
    expect(f.confidence).toBeUndefined();
    expect(bucketOf(f).bucket).toBe("act");
  });
});
