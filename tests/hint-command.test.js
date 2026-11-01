import { describe, it, expect } from "vitest";
import { hintCommand } from "../src/utils/invocation.js";

describe("commands in hints work the way you ran Penthera", () => {
  const npx = { env: { npm_command: "exec" }, argv1: "/home/a/.npm/_npx/1a2b/node_modules/penthera/bin/penthera.js" };

  it("prefixes npx under npx", () => {
    expect(hintCommand("penthera fix --plan", npx)).toBe("npx penthera fix --plan");
    expect(hintCommand("penthera", npx)).toBe("npx penthera");
    expect(hintCommand("npx penthera ui --open", npx)).toBe("npx penthera ui --open");
  });

  it("touches only a command at a word start", () => {
    for (const text of ["penthera.suppress.json", "~/.penthera/memory", "https://x.example/penthera", "/opt/penthera run", "reports/penthera-2026-11-01/code.json", "github.com/danoszz/penthera"]) {
      expect(hintCommand(text, npx), text).toBe(text);
    }
    expect(hintCommand("Review with `penthera memory show` and penthera.suppress.json.", npx)).toBe("Review with `npx penthera memory show` and penthera.suppress.json.");
    expect(hintCommand("(penthera ui)", npx)).toBe("(npx penthera ui)");
  });

  it("leaves a global install, a checkout and other text alone", () => {
    expect(hintCommand("penthera fix", { env: {}, argv1: "/usr/local/bin/penthera" })).toBe("penthera fix");
    expect(hintCommand("penthera fix", { env: { npm_command: "exec" }, argv1: "/code/penthera/bin/penthera.js" })).toBe("penthera fix");
    expect(hintCommand("git status", npx)).toBe("git status");
  });
});
