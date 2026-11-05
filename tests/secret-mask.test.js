/**
 * How a matched secret is shown in reports (lib/whitebox/secrets.js maskMatch).
 * Reports go to JSON, Markdown, SARIF and PR comments, so the mask must never
 * show a short secret whole: DB_PASSWORD=Xk9q used to become DB_P…Xk9q.
 */
import { describe, it, expect } from "vitest";
import { maskMatch, findSecretsInText } from "../lib/whitebox/secrets.js";

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
});
