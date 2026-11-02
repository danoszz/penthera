// The README's first screen: who builds Penthera, and how it compares, with links that land.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";

const read = (f) => readFileSync(new URL(`../${f}`, import.meta.url), "utf8");
const readme = read("README.md");

describe("the README's first screen", () => {
  it("says who builds it, linked to the trust page's section", () => {
    expect(readme).toContain("**Who builds it:** [Daan van der Zwaag](docs/trust.md#who-builds-it), part-time and in the open.");
    expect(read("docs/trust.md")).toMatch(/^## Who builds it$/m);
  });

  it("says how it compares, and the section it links to names each tool", () => {
    expect(readme).toContain("**How it compares:** [next to Snyk, Socket, Semgrep, ZAP and GitHub](#how-it-fits-with-other-tools).");
    const section = readme.split(/^## How it fits with other tools$/m)[1]?.split(/^## /m)[0] ?? "";
    for (const tool of ["Snyk", "Socket", "Semgrep", "ZAP", "GitHub"]) expect(section, tool).toContain(tool);
  });

  it("names the AI-Assisted trailer, not a co-author trailer", () => {
    expect(readme).toContain("an `AI-Assisted:` trailer");
    expect(readme).not.toMatch(/co-author trailer/i);
  });
});
