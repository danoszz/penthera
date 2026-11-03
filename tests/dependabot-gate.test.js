// Dependabot's own pin bumps carry no AI trailer and no changelog fragment. They pass
// the PR checks only when GitHub says every commit is Dependabot's and verified, and the
// change touches nothing but dependency pins. Everyone else stays strict.
import { describe, it, expect } from "vitest";
import { dependabotOnly } from "../scripts/ci/dependabot.mjs";

const commit = (over = {}) => ({
  sha: "75b9686", authorEmail: "49699333+dependabot[bot]@users.noreply.github.com", committerEmail: "noreply@github.com",
  verified: true, files: [".github/workflows/codeql.yml", "action.yml"], ...over,
});
const pr = (commits, author = "dependabot[bot]") => dependabotOnly({ author, commits });

describe("the Dependabot exemption", () => {
  it("lets PR 226's shape through: verified, Dependabot's, pins only", () => {
    expect(pr([commit()]).ok).toBe(true);
    expect(pr([commit({ files: ["package.json", "package-lock.json"] })]).ok).toBe(true);
  });
  it("stays strict for anything else", () => {
    const no = [
      pr([commit()], "danoszz"),
      pr([commit({ verified: false })]),
      pr([commit({ verified: null })]),
      pr([commit({ authorEmail: "daan@example.test" })]),
      pr([commit({ committerEmail: "daan@example.test" })]),
      pr([commit({ files: ["src/cli.js"] })]),
      pr([commit({ files: ["action.yml", "lib/fix/index.js"] })]),
      pr([commit(), commit({ sha: "b", authorEmail: "someone@example.test" })]),
      pr([]),
    ];
    for (const r of no) expect(r.ok).toBe(false);
  });
  it("says why it refused", () => {
    expect(pr([commit({ verified: false })]).reason).toMatch(/not verified/);
    expect(pr([commit({ files: ["src/cli.js"] })]).reason).toMatch(/src\/cli\.js/);
  });
});
