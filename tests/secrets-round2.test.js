/**
 * E11b round 2: provider token formats and generic API keys.
 * Fixtures are our own made-up values in each provider's documented shape;
 * every secret is split with j() so Penthera's self-scan does not report
 * this file.
 */
import { describe, it, expect } from "vitest";
import { findSecretsInText, secretRulesFor } from "../lib/whitebox/secrets.js";

const j = (...p) => p.join("");
const names = (text, opts) => findSecretsInText(text, opts).map((h) => h.name);
const HEX = (n) => "9f3a1c7e5b2d4086".repeat(8).slice(0, n);
const ALNUM = (n) => "Zr8KqT2mWv5NpLx7Bc4HdJ9sYf3Ge6Ua".repeat(4).slice(0, n);

describe("round 2, R1: provider token formats", () => {
  it("finds AWS temporary (STS) access key IDs, not only long-term ones", () => {
    expect(names(j('"AccessKeyId": "AS', "IA", "Z3MXQ7HPLR2VKW4N", '"'))).toEqual(["AWS access key"]);
    expect(names(j("key = AK", "IA", "Z3MXQ7HPLR2VKW4N"))).toEqual(["AWS access key"]);
    // AWS's documented example keys are never a leak.
    expect(names(j("AS", "IAIOSFODNN7EXAMPLE"))).toEqual([]);
    expect(names(j('"AccessKeyId": "AS', "IAJEXAMPLEXEG2JICEA", '"'))).toEqual([]);
    expect(names(j("AWS_KEY=AK", "IA", "XXXXXXXXXXXXXXXX"))).toEqual([]);
  });

  it("does not report AWS IAM identifiers that are not credentials", () => {
    // AIDA (user), AROA (role) and AIPA (instance profile) IDs are public identifiers.
    for (const p of ["AI" + "DA", "AR" + "OA", "AI" + "PA"]) expect(names(j('"UserId": "', p, "Z3MXQ7HPLR2VKW4NQ", '"'))).toEqual([]);
  });

  it("finds every GitHub token prefix", () => {
    for (const p of ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"]) expect(names(j("GH = '", p, ALNUM(36), "'")), p).toEqual(["GitHub token"]);
    expect(names(j("GH = '", "github", "_pat_", ALNUM(22), "_", ALNUM(59), "'"))).toEqual(["GitHub token"]);
    expect(names(j("ghx_", ALNUM(36)))).toEqual([]);
  });

  it("finds Stripe restricted live keys and Postman API keys", () => {
    expect(names(j("STRIPE = 'rk", "_live_", ALNUM(24), "'"))).toEqual(["Stripe secret key"]);
    expect(names(j("url = 'https://api.example.com/c?apikey=PM", "AK-", HEX(24), "-", HEX(34), "'"))).toEqual(["Postman API key"]);
    expect(names(j("PM", "AK-", HEX(20), "-", HEX(34)))).toEqual([]);
  });

  it("reads reStructuredText, AsciiDoc and .markdown as docs: fixed shapes only", () => {
    for (const f of ["docs/setup.rst", "docs/guide.adoc", "docs/guide.asciidoc", "README.markdown"]) expect(secretRulesFor(f), f).toBe("shapes");
    const doc = j("    key_id = 'AK", "IA", "Z3MXQ7HPLR2VKW4N'\n    pass", "word = 'Kq7-vR2mLz9x'\n");
    expect(names(doc, { shapesOnly: true, path: "docs/setup.rst" })).toEqual(["AWS access key"]);
  });
});

describe("round 2, R2: tokens and secrets under broader key names", () => {
  const api = (text, path) => findSecretsInText(text, { path }).filter((h) => h.name === "Generic API key assignment").length;
  // Made-up values in shapes real services issue: hex (GitHub OAuth app
  // secret), base64 (a cookie key), base64url (an OAuth access token), a JWT,
  // a UUID-style token, a dotted OAuth 1 token.
  const real = [
    j("9e1c4b7f2a", "d8350c6e9f14b2a7d03c5e8f6b19"),
    j("q2Xv9LmR4t", "Kp7wZ3sN8bYc6Hd5Jf0G="),
    j("ya29.a0Af", "H6SMBx7Kq2Lp9Rv4Tn8Wz3Ys"),
    j("eyJhbGciOiJIUzI1NiJ9", ".eyJzdWIiOiI0MiJ9", ".Xq3vTn8Lp2Rw9Kz4Ys7Mb1Hd6Jf0Gc5"),
    j("7c2e9a41-", "5bd3-4f86-a0e7-3d9c1b6f2e58"),
    j("1849276035-", "Rk7Lp2Xq9Vt4Wn8Zs3Yb6Hd1Jf5Gc0Mp"),
  ];

  it("finds tokens and secrets whose key names the credential itself", () => {
    for (const v of real) {
      for (const k of ["access_token", "refreshToken", '"id_token"', "BEARER_TOKEN", "oauth_token_secret", "consumer_secret", "appSecret", "WEBHOOK_SECRET", "cookieSecret", "client_token", "token", '"secret"', "SECRET"]) {
        expect(api(`${k} = "${v}"`), `${k} ${v}`).toBe(1);
      }
    }
    expect(api(`access_token: ${real[0]}\n`, "config/app.yml")).toBe(1);
  });

  it("asks a generated-looking value of these broader names", () => {
    // Words, short values, one character class, typed runs, emails,
    // references and elided examples are not credentials.
    for (const v of ["mysecretvalue", "tokenvalue123", "abc-def-ghi-jkl-mno", "ugkdpswvxmtqnfrb", "UGKDPSWVXMTQNFRB", j("Kq7vR2", "mLz9"), j("00112233", "abcdef9988776655"), "john.smith@example.org", "${GITHUB_TOKEN}@github.com", j("eyJhbGciOiJIUzI1NiIs", "InR5cCI6IkpXVCJ9..."), "{{ .Values.token }}"]) {
      expect(api(`token = "${v}"`), v).toBe(0);
      expect(api(`access_token = "${v}"`), v).toBe(0);
    }
  });

  it("does not read identifiers, pagination cursors or names as secrets", () => {
    for (const k of ["next_token", "page_token", "continuation_token", "token_type", "token_url", "secret_name", "secretRef", "client_id", "consumer_key", "csrf_token_name", "tokenizer", "publicToken", "TOKEN_LABEL"]) {
      expect(api(`${k} = "${real[0]}"`), k).toBe(0);
    }
  });

  it("skips padded and redacted values under any API key name", () => {
    for (const v of [j("a1b2c3d4-e5f6-a1b2-", "c3d4-TOKEN1111111"), j("4f9c2e7b", "bbbbbbbbbb1d8a")]) {
      expect(api(`clientToken = "${v}"`), v).toBe(0);
      expect(api(`api_key = "${v}"`), v).toBe(0);
    }
  });

  it("keeps the old names as they were", () => {
    // An API key under its own name needs no generated-looking value.
    expect(api(`api_key = "${j("Zq8vT2mR", "x5LpW9nK")}"`)).toBe(1);
  });
});
