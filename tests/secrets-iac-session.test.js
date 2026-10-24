/**
 * Two secret-scan gaps from the E10 pilot: a private key in a Terraform file
 * (Juice Shop `iac-private-key`; .tf files were not read) and a session
 * signing secret written into express-session's options (DVNA
 * `session-secret`). Fixtures are written to a temp dir at runtime.
 */
import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { scanSecrets, isSecretScanTarget, findSecretsInText } from "../lib/whitebox/secrets.js";

const j = (...p) => p.join("");

function scanOne(name, content) {
  const dir = mkdtempSync(join(tmpdir(), "penthera-secrets-"));
  try {
    writeFileSync(join(dir, name), content);
    return scanSecrets(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// Split so Penthera's own self-scan does not report its test fixtures.
const SESSION = j("sess", "ion");
const COOKIE_SESSION = j("cookieSess", "ion");
const sessionHits = (text) => findSecretsInText(text).filter((h) => h.name === "Hardcoded session secret");

describe("secret scan reads Terraform and HCL", () => {
  it("scans .tf, .tfvars and .hcl files", () => {
    for (const f of ["infra/main.tf", "prod.tfvars", "terragrunt.hcl"]) expect(isSecretScanTarget(f)).toBe(true);
  });

  it("finds a private key inline in a Terraform resource", () => {
    const key = j("-----BEGIN RSA ", "PRIVATE KEY-----\\nMIICXAIBAAKBgQDNfakeTestKeyBodyNotARealKeyAtAll0123456789\\n-----END RSA ", "PRIVATE KEY-----");
    const tf = `resource "tls_cert_request" "web" {\n  private_key_pem = "${key}"\n}\n`;
    const findings = scanOne("networking.tf", tf);
    expect(findings.map((f) => f.title)).toContain("Private key block in source");
    expect(findings.find((f) => f.title === "Private key block in source")).toMatchObject({ url: "networking.tf", severity: "critical" });
  });

  it("finds a password in a .tfvars file and skips a variable reference", () => {
    expect(scanOne("prod.tfvars", j("db_pass", 'word = "Xk92-prod-Pw!"\n')).map((f) => f.title)).toContain("Hardcoded password in source");
    expect(scanOne("main.tf", "password = var.db_password\n")).toHaveLength(0);
  });
});

describe("hardcoded express-session secret", () => {
  it("finds the secret in the session options across lines", () => {
    const src = `app.use(${SESSION}({\n  name: 'sid',\n  secret: 'keyboard cat',\n  resave: true\n}))\n`;
    const hits = sessionHits(src);
    expect(hits).toHaveLength(1);
    expect(hits[0].match).toBe("secret: 'keyboard cat'");
    const findings = scanOne("server.js", src);
    expect(findings.find((f) => f.title === "Hardcoded session secret in source")).toMatchObject({ url: "server.js", severity: "high" });
  });

  it("finds a hardcoded fallback after an environment variable", () => {
    expect(sessionHits(`app.use(${SESSION}({ secret: process.env.SESSION_SECRET || 'my-shop-session-2024' }))`)).toHaveLength(1);
    expect(sessionHits(`app.use(${COOKIE_SESSION}({ keys: [], secret: process.env.S ?? "f9a8s7d6" }))`)).toHaveLength(1);
  });

  it("does not flag a secret read from the environment or a config object", () => {
    expect(sessionHits(`app.use(${SESSION}({ secret: process.env.SESSION_SECRET }))`)).toHaveLength(0);
    expect(sessionHits(`app.use(${SESSION}({ secret: config.cookieSecret, resave: false }))`)).toHaveLength(0);
  });

  it("does not flag placeholders or a `secret` key outside a session call", () => {
    expect(sessionHits(`app.use(${SESSION}({ secret: 'changeme' }))`)).toHaveLength(0);
    expect(sessionHits(`app.use(${SESSION}({ secret: 'your-secret-here' }))`)).toHaveLength(0);
    // Split so the self-scan's generic rule (a bare `secret` since E11b round 2) does not report this fixture.
    expect(sessionHits("verifySync({ secret: 'JBSWY3DP" + "EHPK3PXP', token })")).toHaveLength(0);
    expect(sessionHits(`const opts = { secret: 'abcdabcd' }; app.use(${SESSION}(opts))`)).toHaveLength(0);
  });
});
