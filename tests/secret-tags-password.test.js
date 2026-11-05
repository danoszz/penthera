/**
 * Vercel Security Review B (2.3.2): a report must not carry an unkeyed, fast
 * verifier of a human-chosen password. The salt is in the report, so a tag of
 * a dictionary password would let anyone with the report test guesses offline.
 * Only fixed-format tokens (a provider prefix, a PEM block) are tagged.
 */
import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanSecrets } from "../lib/whitebox/secrets.js";
import { secretTag, tagSalt } from "../lib/secret-tags.js";
import { compareWithBaseline } from "../src/cli/baseline.js";

const tmp = () => mkdtempSync(join(tmpdir(), "penthera-tagpw-"));
const scan = (name, text) => {
  const d = tmp();
  writeFileSync(join(d, name), text);
  return { d, findings: scanSecrets(d).filter((f) => f.source === "secret-scan") };
};
// Built at run time, so the repo's own secret scan does not report this file.
const WORDS = ["correct", "horse", "battery", "staple"].join("");      // 22 characters, all dictionary words
const STRIPE = ["sk", "live", "4eC39HqLyjWDarjtT1zdp7dc"].join("_");

describe("B: no tag for a human-chosen password", () => {
  it("a 20+ character dictionary password gets no valueTags, and no tag of it is anywhere in the finding", () => {
    expect(WORDS.length).toBeGreaterThanOrEqual(20);
    const { findings } = scan(".env", `DB_PASSWORD=${WORDS}\n`);
    const pw = findings.find((f) => f.title.startsWith("Hardcoded password"));
    expect(pw).toBeTruthy();
    expect("valueTags" in pw).toBe(false);
    const json = JSON.stringify(findings);
    for (const guess of [WORDS, `DB_PASSWORD=${WORDS}`]) expect(json).not.toContain(secretTag(guess, tagSalt()));
  });

  it("generic key=value assignments and session secrets get no tag either", () => {
    const { findings } = scan("config.js", [
      `const api_key = "${WORDS}";`,
      `const jwt_secret = "${WORDS}";`,
      `app.use(session({ secret: "${WORDS}" }));`,
    ].join("\n") + "\n");
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some((f) => "valueTags" in f)).toBe(false);
  });

  it("a fixed-format key is still tagged, so a baseline still sees it swapped", () => {
    const { d, findings } = scan("app.js", `const k = "${STRIPE}";\n`);
    expect(findings[0].valueTags).toHaveLength(1);
    const base = join(tmp(), "baseline.json");
    writeFileSync(base, JSON.stringify({ secretTagSalt: tagSalt(), findings }));
    writeFileSync(join(d, "app.js"), `const k = "${["sk", "live", "9xQ2mZ7vB4nK8pL3wR6tY1aa"].join("_")}";\n`);
    expect(compareWithBaseline(scanSecrets(d), base).stats.newCount).toBe(1);
  });
});
