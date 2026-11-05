/**
 * How a matched secret is shown in reports (lib/whitebox/secrets.js maskMatch).
 * Reports go to JSON, Markdown, SARIF and PR comments, so the mask must never
 * show a short secret whole: DB_PASSWORD=Xk9q used to become DB_P…Xk9q.
 */
import { describe, it, expect } from "vitest";
import { maskMatch, maskRaw, findSecretsInText } from "../lib/whitebox/secrets.js";
import { maskSecretsIn } from "../lib/giants/finding.js";

describe("maskMatch", () => {
  it("keeps an assignment's name and masks its value", () => {
    expect(maskMatch("DB_PASSWORD=Xk9q")).toBe("DB_PASSWORD=***");
    expect(maskMatch('DB_PASSWORD="Xk9qLm2pQr"')).toBe('DB_PASSWORD="***"');
    expect(maskMatch("password: hunter2hunter2")).toBe("password: ***");
  });

  it("never shows a value under 20 characters, and keeps a closing quote out of the last 4", () => {
    for (const v of ["Xk9q", "abcdefgh", "abcdefghijklmnopqrs"]) expect(maskMatch(`SECRET=${v}`)).toBe("SECRET=***");
    expect(maskMatch('api_key = "abcdefghijklmnopqrstuvwxyz0123"')).toBe('api_key = "abcd…0123"');
  });

  it("shows a long key's prefix and last 4, as before", () => {
    expect(maskMatch("xk_demo_51HxQwErTyUiOpAsDfGhJkLzXcVbNm")).toBe("xk_d…VbNm");
    expect(maskMatch("short")).toBe("***");
  });

  it("never puts a short assigned secret into a finding's text", () => {
    const pw = "Xk9qZ";
    const hits = findSecretsInText(`DB_PASSWORD=${pw}\n`, { path: ".env" });
    for (const h of hits) expect(maskMatch(h.match)).not.toContain(pw.slice(-4));
  });

  it("never reads base64 padding as an assignment (Vercel, 5 Nov)", () => {
    const b64 = "QUJDREVGR0hJSktMTU5PUFFSU1RVVg==";
    expect(maskMatch(b64)).toBe("QUJD…Vg==");
    expect(maskMatch(b64)).not.toContain("SktMTU5P");
    expect(maskMatch("abc==")).toBe("***");
  });

  it("masks a value that starts with =, however long the name (Vercel, 5 Nov)", () => {
    for (const m of ["password_confirmation==ab1c", "DATABASE_PASSWORD_PRIMARY===xY9z", "password: =qwer"]) {
      expect(maskMatch(m), m).not.toMatch(/ab1c|xY9z|qwer/);
      expect(maskMatch(m), m).toMatch(/\*\*\*$/);
    }
  });

  it("masks a bare value from another tool with no prefix kept, through the evidence text", () => {
    const raw = "QUJDREVGR0hJSktMTU5PUFFSU1RVVg==";
    const out = maskSecretsIn(`trufflehog found ${raw} in config`, [raw]);
    expect(out).not.toContain("SktMTU5P");
    expect(maskRaw("user:hunter2hunter2")).toBe("***");
  });
});
