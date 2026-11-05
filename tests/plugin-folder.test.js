/**
 * plugin/ is what Anthropic's plugin directory reads and what
 * `/plugin install penthera@penthera` installs. It carries a copy of the skill,
 * so this keeps the copy identical to skills/penthera and the folder inside the
 * directory's limits (no package files, nothing past the file and size caps,
 * a square PNG icon, no broad shell entries in allowed-tools).
 */
import { describe, it, expect } from "vitest";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const PLUGIN = "plugin";
const files = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? files(join(dir, e.name)) : [join(dir, e.name)]));
const pkg = JSON.parse(readFileSync("package.json", "utf-8"));

describe("plugin/ folder", () => {
  it("holds an exact copy of skills/penthera", () => {
    const src = files("skills/penthera").map((f) => relative("skills/penthera", f)).sort();
    const copy = files(join(PLUGIN, "skills/penthera")).map((f) => relative(join(PLUGIN, "skills/penthera"), f)).sort();
    expect(copy).toEqual(src);
    for (const f of src) expect(readFileSync(join(PLUGIN, "skills/penthera", f), "utf-8"), f).toBe(readFileSync(join("skills/penthera", f), "utf-8"));
  });

  it("has the same licence and MCP pin as the repo, and the package version", () => {
    expect(readFileSync(join(PLUGIN, "LICENSE"), "utf-8")).toBe(readFileSync("LICENSE", "utf-8"));
    expect(JSON.parse(readFileSync(join(PLUGIN, ".mcp.json"), "utf-8"))).toEqual(JSON.parse(readFileSync(".mcp.json", "utf-8")));
    const manifest = JSON.parse(readFileSync(join(PLUGIN, ".claude-plugin/plugin.json"), "utf-8"));
    expect(manifest.version).toBe(pkg.version);
    expect(manifest.name).toBe("penthera");
  });

  it("ships no package files, binaries or large files", () => {
    for (const f of ["package.json", "package-lock.json", "bun.lockb", "bin"]) expect(existsSync(join(PLUGIN, f)), f).toBe(false);
    const all = files(PLUGIN);
    expect(all.length).toBeLessThan(512);
    for (const f of all) expect(statSync(f).size, f).toBeLessThan(256 * 1024);
  });

  it("has a square PNG icon between 512 and 2048 px", () => {
    const png = readFileSync(join(PLUGIN, ".claude-plugin/icon.png"));
    expect(png.subarray(1, 4).toString()).toBe("PNG");
    const w = png.readUInt32BE(16), h = png.readUInt32BE(20);
    expect(w).toBe(h);
    expect(w).toBeGreaterThanOrEqual(512);
    expect(w).toBeLessThanOrEqual(2048);
    expect(png.length).toBeLessThan(2 * 1024 * 1024);
  });

  it("pre-approves no shell commands, only reading (the directory holds broad Bash entries)", () => {
    for (const f of ["skills/penthera/SKILL.md", join(PLUGIN, "skills/penthera/SKILL.md")]) {
      const line = readFileSync(f, "utf-8").match(/^allowed-tools:\s*"([^"]*)"/m)?.[1];
      expect(line, f).toBe("Read");
    }
  });

  it("is the folder the marketplace entry installs", () => {
    const market = JSON.parse(readFileSync(".claude-plugin/marketplace.json", "utf-8"));
    expect(market.plugins.find((p) => p.name === "penthera").source).toBe("./plugin");
  });
});
