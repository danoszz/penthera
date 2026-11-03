// What a person approves must stay readable: the masks hide secrets, not prose.
// Found in the 2.2.0 walk: whole context lines hidden for a quoted message, and
// the secrets recipe's own error text shown as "***".
import { describe, it, expect } from "vitest";
import { redactPlan } from "../lib/fix/index.js";

// Built at run time, so Penthera's own self-scan doesn't read these as real secrets.
const KEY = ["sk", "live", "51Hx9aZk3Tq8mNvB2cLpQrStUv"].join("_");
const PW = ["hun", "ter2"].join("");
const PHRASE = ["correct", "horse", "battery", "staple"].join(" ");
const AWS = ["AKIA", "IOSFODNN7EXAMPLE"].join("");
const TOK = ["tok", "8f7e6d5c4b3a"].join("_");
const shown = (lines, redactions = [KEY]) => {
  const r = redactPlan({ diff: ["@@ -1,9 +1,9 @@", ...lines].join("\n"), redactions }, { context: true });
  return { context: r.contextDiff, diff: r.diff };
};

describe("the fix window", () => {
  it("shows the recipe's own error text, not ***", () => {
    const { diff } = shown(['+if (!process.env.STRIPE_SECRET) throw new Error("Set STRIPE_SECRET before starting the server.");']);
    expect(diff).toContain('"Set STRIPE_SECRET before starting the server."');
    expect(diff).not.toContain("***");
  });

  it("shows context lines whose quotes are words, not values", () => {
    const { context } = shown([
      ' res.status(404).send("Not found here");',
      ' if (!password) return res.status(400).send("Missing input");',
      " const token = req.headers.authorization;",
      ' app.get("/api/v1/users/profile/settings", handler);',
      "+x();",
    ]);
    expect(context).toContain('send("Not found here")');
    expect(context).toContain('send("Missing input")');
    expect(context).toContain("const token = req.headers.authorization;");
    expect(context).toContain('"/api/v1/users/profile/settings"');
    expect(context).not.toContain("[line hidden]");
  });

  it("still hides every value a secret could be", () => {
    const lines = [
      ` const password = "${PW}";`,
      ` db.connect({ user: "app", password: "${PHRASE}" });`,
      ` const client = new Stripe("${KEY}");`,
      ` const apiKey = "${AWS}";`,
      " API_TOKEN=abc123def456",
      " curl -u admin:s3cr3tpass https://example.test",
      ' const sig = "f3a9c2e17b4d8a6e0c5f2b9d1e7a4c3b8f6d0e2a";',
      `+const password = "${PW}";`,
      `+db.connect({ user: "app", password: "${PHRASE}" });`,
      `+login("admin", "s3cr3tpass", { token: "${TOK}" });`,
    ];
    const { context, diff } = shown(lines, [KEY, "s3cr3tpass"]);
    for (const secret of [PW, PHRASE, KEY, AWS, "abc123def456", "s3cr3tpass", "f3a9c2e17b4d8a6e0c5f2b9d1e7a4c3b8f6d0e2a", TOK]) {
      expect(context, secret).not.toContain(secret);
      expect(diff, secret).not.toContain(secret);
    }
  });

  it("keeps an env name readable", () => {
    const { diff } = shown(['+const secret = process.env["STRIPE_SECRET"];']);
    expect(diff).toContain('"STRIPE_SECRET"');
  });
});
