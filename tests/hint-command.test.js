import { describe, it, expect } from "vitest";
import { hintCommand } from "../src/utils/invocation.js";

describe("commands in hints work the way you ran Penthera", () => {
  const npx = { env: { npm_command: "exec" }, argv1: "/home/a/.npm/_npx/1a2b/node_modules/penthera/bin/penthera.js", version: "2.4.0" };

  it("prefixes npx under npx, pinned to the running version", () => {
    expect(hintCommand("penthera fix --plan", npx)).toBe("npx -y penthera@2.4.0 fix --plan");
    expect(hintCommand("penthera", npx)).toBe("npx -y penthera@2.4.0");
    // A bare npx command would resolve to npm's newest version: it is pinned too.
    expect(hintCommand("npx penthera ui --open", npx)).toBe("npx -y penthera@2.4.0 ui --open");
    expect(hintCommand("npx -y penthera ui", npx)).toBe("npx -y penthera@2.4.0 ui");
  });

  it("keeps a version a command already names", () => {
    expect(hintCommand("npx -y penthera@2.5.0-rc.1 ui", npx)).toBe("npx -y penthera@2.5.0-rc.1 ui");
    expect(hintCommand("npx penthera@2.3.2 deps", npx)).toBe("npx penthera@2.3.2 deps");
  });

  it("uses the version in package.json by default", async () => {
    const { readFileSync } = await import("node:fs");
    const v = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf-8")).version;
    expect(hintCommand("penthera", { env: npx.env, argv1: npx.argv1 })).toBe(`npx -y penthera@${v}`);
  });

  it("touches only a command at a word start", () => {
    for (const text of ["penthera.suppress.json", "~/.penthera/memory", "https://x.example/penthera", "/opt/penthera run", "reports/penthera-2026-11-01/code.json", "github.com/danoszz/penthera"]) {
      expect(hintCommand(text, npx), text).toBe(text);
    }
    expect(hintCommand("Review with `penthera memory show` and penthera.suppress.json.", npx)).toBe("Review with `npx -y penthera@2.4.0 memory show` and penthera.suppress.json.");
    expect(hintCommand("(penthera ui)", npx)).toBe("(npx -y penthera@2.4.0 ui)");
  });

  it("leaves a global install, a checkout and other text alone", () => {
    expect(hintCommand("penthera fix", { env: {}, argv1: "/usr/local/bin/penthera" })).toBe("penthera fix");
    expect(hintCommand("penthera fix", { env: { npm_command: "exec" }, argv1: "/code/penthera/bin/penthera.js" })).toBe("penthera fix");
    expect(hintCommand("git status", npx)).toBe("git status");
  });
});
