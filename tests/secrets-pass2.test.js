/**
 * E11b pass 2: the password rule reads key names by their words (A4a).
 * Fixtures are our own; secrets are split with join() so Penthera's
 * self-scan does not report this file.
 */
import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { cpuMs } from "./fixtures/cpu-time.js";
import { findSecretsInText, isPasswordKey, keyWords, isSequential, isCredentialName, scanSecrets } from "../lib/whitebox/secrets.js";

const j = (...p) => p.join("");
const PW = j("pass", "word");
const names = (text, opts) => findSecretsInText(text, opts).map((h) => h.name);
const pw = (text) => names(text).filter((n) => n === "Hardcoded password").length;
// A made-up value with letters, digits and a symbol.
const V = j("Kq7", "-vR2m", "Lz9");

describe("password keys, by their words", () => {
  it("splits a key into words", () => {
    expect(keyWords("adminPassword2")).toEqual(["admin", "password"]);
    expect(keyWords("DB_PASSWORD")).toEqual(["db", "password"]);
    expect(keyWords("new-password1")).toEqual(["new", "password"]);
    expect(keyWords("XMLPasswordValue")).toEqual(["xml", "password", "value"]);
  });

  it("knows which keys name a password", () => {
    for (const k of [PW, "passwd", "pwd", "db_pass", "old_password", "password1", "adminPassword", "DB_PASSWORD", "PGPASSWORD", "userpwd", "spring.datasource.password", "password_confirmation", "passwordRepeat", "SMTP_PASS", "passphrase"]) {
      expect(isPasswordKey(k), k).toBe(true);
    }
    for (const k of ["password_hash", "passwordMinLength", "password_reset_url", "passThrough", "bypass", "passport", "compass", "allow_empty_password", "forgotPassword", "LABEL_PASSWORD", "passwordPlaceholder", "invalidPassword", "password.encoder"]) {
      expect(isPasswordKey(k), k).toBe(false);
    }
  });
});

describe("password assignments in more shapes", () => {
  it("finds a quoted key: JSON, Python dicts, PHP arrays", () => {
    expect(pw(`{"${PW}": "${V}"}`)).toBe(1);
    expect(pw(`data = {'old_${PW}': '${V}', 'new_${PW}1': '${V}x'}`)).toBe(2);
    expect(pw(`$cfg['db_pass'] = '${V}';`)).toBe(1);
    expect(pw(`'${PW}' => '${V}',`)).toBe(1);
    expect(pw(`{\\"${PW}\\":\\"${V}\\"}`)).toBe(1);
  });

  it("finds prefixed and suffixed keys with :, =, => and :=", () => {
    expect(pw(`adminPassword = "${V}"`)).toBe(1);
    expect(pw(`const DB_PASSWORD = '${V}';`)).toBe(1);
    expect(pw(`${PW}1: "${V}"`)).toBe(1);
    expect(pw(`dbPass := "${V}"`)).toBe(1);
    expect(pw(`:${PW} => "${V}"`)).toBe(1);
    expect(pw(`spring.datasource.${PW}="${V}"`)).toBe(1);
  });

  it("does not read a key that only opens a string as a password key", () => {
    // The key sits inside a string literal: `"Password: "` then code.
    expect(pw(`sb.append("Password: ").append("${V}");`)).toBe(0);
  });

  it("skips a ternary and a template literal built at run time", () => {
    expect(pw(`status: ok ? "pass" : "fail",`)).toBe(0);
    expect(pw(`console.log(ok ? "PASS" : "FAIL");`)).toBe(0);
    expect(pw("body: { " + PW + ": `attempt-${i}` }")).toBe(0);
    expect(pw("body: { " + PW + ": `" + V + "` }")).toBe(1);
  });

  it("skips keys about a password rather than holding one", () => {
    expect(pw(`password_hash = "${V}"`)).toBe(0);
    expect(pw(`"LABEL_PASSWORD": "${V}"`)).toBe(0);
    expect(pw(`MYSQL_ALLOW_EMPTY_PASSWORD: '${V}'`)).toBe(0);
  });
});

describe("values that are not passwords", () => {
  it("skips booleans, stored hashes, references and code", () => {
    for (const v of ["true", "null", j("$2b$", "12$abcdefghijklmnopqrstuv"), j("$6$", "rounds=5000$salt$hash"), j("{SS", "HA}abcdEFGH"), j("pbkdf2", "_sha256$260000$salt$hash"), "$DB_PASS", "#{password}", "%(pw)s", "%DB_PASS%", "<db password>"]) {
      expect(pw(`${PW} = "${v}"`), v).toBe(0);
    }
  });

  it("skips text for people: other scripts, labels, translations", () => {
    expect(pw(`"${PW}": "Пароль"`)).toBe(0);
    expect(pw(`'${PW}': 'Contraseña'`)).toBe(0);
    expect(pw(`"${PW}": "Password:"`)).toBe(0);
    // A password with a symbol outside ASCII is still a password.
    expect(pw(`${PW}: '${V}§'`)).toBe(1);
  });

  it("skips names, defaults, sequences, test values and version ranges", () => {
    expect(isCredentialName("keystore.password")).toBe(true);
    expect(isCredentialName("my-secret")).toBe(true);
    expect(isCredentialName(`${PW}123!`)).toBe(false);
    expect(isSequential("123456")).toBe(true);
    expect(isSequential("abc123")).toBe(true);
    expect(isSequential("qwerty")).toBe(true);
    expect(isSequential(V)).toBe(false);
    for (const v of ["keystore.password", "default-password", "admin", "root", "changeit", "12345678", "abcdefgh", "test123", "testclient", "mypassword", "nopasswd", "string", "^1.0.0"]) {
      expect(pw(`"${PW}": "${v}"`), v).toBe(0);
    }
  });

  it("a translation folder runs only the fixed-shape rules", async () => {
    const { isShapesOnlyFile } = await import("../lib/whitebox/secrets.js");
    expect(isShapesOnlyFile("src/locales/de.json")).toBe(true);
    expect(isShapesOnlyFile("app/i18n/messages.js")).toBe(true);
    expect(isShapesOnlyFile("config/database.json")).toBe(false);
  });
});

describe("realistic passwords still match", () => {
  // Shapes of real generated and human passwords (our own, made up): the
  // filters above must not drop them.
  const real = [j("hunter", "2-Blue!"), j("Xk92", "-prod-Pw!"), j("t0p", "S3cr3tDb"), j("q8Z", "f$w1Lm"), j("wq7", "kz9pl"), j("Jf8", "#mQ2!vZp0rT"), j("4f9c2e", "7b1d"), j("Correct", "HorseBattery9")];
  it("in code, JSON and config shapes", () => {
    for (const v of real) {
      expect(pw(`db_${PW} = "${v}"`), v).toBe(1);
      expect(pw(`{"${PW}": "${v}"}`), v).toBe(1);
    }
  });
});

describe("bare values in config files (A4b)", () => {
  const cfg = (text, path) => findSecretsInText(text, { path }).filter((h) => h.name === "Hardcoded password").length;

  it("finds unquoted passwords in YAML, .properties, .env, .ini, .conf and TOML", () => {
    expect(cfg(`db:\n  ${PW}: ${V}\n`, "config/app.yml")).toBe(1);
    expect(cfg(`services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: ${V}\n      - MYSQL_PASSWORD=${V}x\n`, "docker-compose.yaml")).toBe(2);
    expect(cfg(`spring.datasource.${PW}=${V}\n`, "src/main/resources/application.properties")).toBe(1);
    expect(cfg(`DB_PASS=${V}\n`, ".env")).toBe(1);
    expect(cfg(`SMTP_PASSWORD=${V}\n`, ".env.production")).toBe(1);
    expect(cfg(`[db]\n${PW} = ${V}\n`, "settings.ini")).toBe(1);
    expect(cfg(`${PW} = ${V} # prod\n`, "server.conf")).toBe(1);
    expect(cfg(`admin_${PW} = ${V}\n`, "Cargo.toml")).toBe(1);
  });

  it("does not read a bare value as a password in code", () => {
    expect(cfg(`connect({ ${PW}: dbPassword })`, "src/db.js")).toBe(0);
    expect(cfg(`${PW} = get_secret()`, "app.py")).toBe(0);
    expect(cfg(`${PW}: ${V}`)).toBe(0);
  });

  it("skips placeholders, references, paths, URLs, numbers and YAML tags", () => {
    for (const v of ["${DB_PASSWORD}", "${DB_PASSWORD:-x}", "{{ db_password }}", "<password>", "[password]", "%(db_pw)s", "changeme", "true", "123456789", "/run/secrets/db", "./secrets/pw", "https://vault.example.com/pw", "!vault", "*db_pw", "|", "ENC(G6N718UuyPE5bHyWKyuLQSm02auQPUtm)", "env(DB_PASSWORD)", "admin"]) {
      expect(cfg(`${PW}: ${v}\n`, "app.yml"), v).toBe(0);
    }
  });
});

describe("private-key variants (A3)", () => {
  const BODY = "MIIBuwIBAAKBgQDfakeTestKeyBodyForPentheraUnitTestsOnly0123456789";
  const pem = (kind) => j("-----BEGIN ", kind, "-----\n", BODY, "\nAbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/AbCd\n-----END ", kind, "-----\n");
  const keys = (text) => names(text).filter((n) => n === "Private key block").length;

  it("finds DSA, encrypted PKCS#8 and PGP private keys", () => {
    expect(keys(pem("DSA PRIVATE KEY"))).toBe(1);
    expect(keys(pem("ENCRYPTED PRIVATE KEY"))).toBe(1);
    expect(keys(j("-----BEGIN PGP ", "PRIVATE KEY BLOCK-----\nVersion: GnuPG v2\n\n", BODY, "\n"))).toBe(1);
  });

  it("finds a key built by string concatenation, or in one JSON string", () => {
    const lines = pem("RSA PRIVATE KEY").trim().split("\n");
    expect(keys(lines.map((l) => `  "${l}\\n" +`).join("\n"))).toBe(1);
    expect(keys(lines.map((l) => `\t\t+ '${l}  \\n'`).join("\n"))).toBe(1);
    expect(keys(`{"key": "${lines[0]}\\n${"A1b2C3d4".repeat(80)}\\n${lines.at(-1)}"}`)).toBe(1);
  });

  it("still needs a body: a public key or a bare header is not a private key", () => {
    expect(keys(j("-----BEGIN PGP ", "PUBLIC KEY BLOCK-----\n\n", BODY, "\n"))).toBe(0);
    expect(keys(j("-----BEGIN DSA ", "PRIVATE KEY-----\n...\n"))).toBe(0);
  });
});

describe("generic API keys (A5)", () => {
  const api = (text, path) => findSecretsInText(text, { path }).filter((h) => h.name === "Generic API key assignment").length;
  // Made-up values in the shapes real providers issue: hex, base64, dotted,
  // prefixed with key-, UUID-like.
  const real = [j("4f9c2e7b1d", "8a6035e2c4b7f19d0a3e5c88"), j("Zq8vT2mR", "x5LpW9nK3sJ7dF4hY6gB"), j("SG.k3Jd9", "Lx2QwErTyUi.pA8sDf7GhJkL0zXcVbNm1Qw2Er3Ty4Ui5Op6As"), j("key-3ax6xn", "jp29jd6fds4gc373sgvjxteol0"), j("b1e4f0c2-", "9a7d-4e3b-8c6f-2d5a1e9b7c40")];

  it("finds API keys, tokens and client secrets under quoted and prefixed keys", () => {
    for (const v of real) {
      expect(api(`{"apiKey": "${v}"}`), v).toBe(1);
      expect(api(`STRIPE_API_KEY = "${v}"`), v).toBe(1);
      expect(api(`client_secret: '${v}'`), v).toBe(1);
      expect(api(`config.auth_token = "${v}"`), v).toBe(1);
      expect(api(`aws_secret_access_key = "${v}"`), v).toBe(1);
    }
  });

  it("finds a bare value in a config file, not in code", () => {
    expect(api(`MAILGUN_API_KEY=${real[3]}\n`, ".env")).toBe(1);
    expect(api(`x-api-token: ${real[1]}\n`, "app.yml")).toBe(1);
    expect(api(`apiKey: ${real[1]}`, "src/app.js")).toBe(0);
  });

  it("skips names, stand-ins, plain words, public keys and other key names", () => {
    for (const v of ["my_api_key", "secret_key_base", "oauthClientSecret", j("sk_te", "st_4f9c2e7b1d8a"), "whatever", "PROTECTED", "123456790", "1234567890abcdefghijklmnopqrstuvwxyz", "${API_KEY}", "{api_key}", "<TESLA_CLIENT_SECRET>"]) {
      expect(api(`api_key = "${v}"`), v).toBe(0);
    }
    expect(api(`publicApiKey: "${real[0]}"`)).toBe(0);
    expect(api(`api_key_id = "${real[0]}"`)).toBe(0);
    // A bare `token` counts since E11b round 2 (tests/secrets-round2.test.js); a pagination cursor does not.
    expect(api(`next_token = "${real[0]}"`)).toBe(0);
  });
});

describe("the new rules stay fast on hostile input", () => {
  it("password and key rules are linear-ish", () => {
    for (const text of [`${PW}`.repeat(50_000), "a_".repeat(100_000) + `${PW}:`, "-----BEGIN DSA PRIVATE KEY-----" + "\n \"".repeat(50_000), ` ${PW} = ` + "'".repeat(100_000), "x.".repeat(100_000) + PW]) {
      expect(cpuMs(() => findSecretsInText(text, { path: "a.yml" }))).toBeLessThan(1500);
    }
  });
});

describe("a file with many hits", () => {
  it("lists up to 200 lines per rule, not 50", () => {
    const dir = mkdtempSync(join(tmpdir(), "penthera-many-"));
    try {
      const lines = Array.from({ length: 120 }, (_, i) => `user${i}_${PW} = "${V}${i}"`);
      writeFileSync(join(dir, "users.py"), lines.join("\n") + "\n");
      const [f] = scanSecrets(dir);
      expect(f.lines).toHaveLength(120);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
