/**
 * plugin/ is what Anthropic's plugin directory reads and what
 * `/plugin install penthera@penthera` installs. It carries a copy of the skill,
 * so this keeps the copy identical to skills/penthera (except scripts/) and the
 * folder inside the directory's limits (only allowed file types, no package
 * files, nothing past the file and size caps, a square PNG icon, no broad shell
 * entries in allowed-tools).
 */
import { describe, it, expect } from "vitest";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const PLUGIN = "plugin";
const files = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? files(join(dir, e.name)) : [join(dir, e.name)]));
const pkg = JSON.parse(readFileSync("package.json", "utf-8"));
// skills/penthera/scripts/ (preflight.sh, validate-report.*) stays in the repo for
// a checkout, the internal audit and `npx skills add`; the plugin may not ship it.
const skillFiles = (dir) => files(dir).map((f) => relative(dir, f)).filter((f) => !f.startsWith("scripts/")).sort();

// Anthropic's directory refused the plugin on 6 Nov 2026 (LOCAL_CODE_FILE_TYPE):
// unverified publishers may ship only these file types, plus the licence, readme,
// .gitignore and icon.
const ALLOWED_EXT = /\.(?:md|markdown|txt|json|ya?ml|png|jpe?g|gif|webp|ico)$/i;
const ALLOWED_NAME = /^(?:LICEN[CS]E(?:\.\w+)?|README(?:\.\w+)?|\.gitignore)$/i;
const disallowedFiles = (paths) => paths.filter((f) => !ALLOWED_EXT.test(f) && !ALLOWED_NAME.test(f.split(/[\\/]/).pop()));

describe("plugin/ folder", () => {
  it("holds an exact copy of skills/penthera, without its scripts", () => {
    const src = skillFiles("skills/penthera");
    const copy = files(join(PLUGIN, "skills/penthera")).map((f) => relative(join(PLUGIN, "skills/penthera"), f)).sort();
    expect(copy).toEqual(src);
    for (const f of src) expect(readFileSync(join(PLUGIN, "skills/penthera", f), "utf-8"), f).toBe(readFileSync(join("skills/penthera", f), "utf-8"));
  });

  it("has the same licence as the repo, and the package version", () => {
    expect(readFileSync(join(PLUGIN, "LICENSE"), "utf-8")).toBe(readFileSync("LICENSE", "utf-8"));
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

  it("ships only the file types the directory takes from an unverified publisher", () => {
    expect(disallowedFiles(files(PLUGIN))).toEqual([]);
    expect(disallowedFiles(["p/LICENSE", "p/README.md", "p/.gitignore", "p/a.json", "p/b.yml", "p/i.png", "p/s/x.sh", "p/s/y.mjs", "p/z.js", "p/run"]))
      .toEqual(["p/s/x.sh", "p/s/y.mjs", "p/z.js", "p/run"]);
  });

  // Anthropic's directory held the plugin on 7 Nov 2026 (MCP_FORWARDS_CREDENTIAL_ENV):
  // nothing in it may read a credential from the user's environment or files.
  // The skill gives the --auth-* command for the user to run; env-var ways stay in docs/.
  it("reads no credential from the user's environment", () => {
    const READS = /process\.env\.|PENTHERA_BEARER|PENTHERA_COOKIE|\$\{\s*user_config|\$\{[A-Z_][A-Z0-9_]*\}/;
    for (const f of files(PLUGIN).filter((f) => !f.endsWith(".png"))) expect(readFileSync(f, "utf-8"), f).not.toMatch(READS);
    for (const t of ["const k = process.env.KEY", "PENTHERA_BEARER=x", "${user_config.token}", "${API_KEY}"]) expect(t).toMatch(READS);
  });

  // The hold came back on 7 Nov for credential-shaped instructions: login flags, the
  // home config files --home reads, a signing key path, a request's auth header.
  // The plugin links to docs.penthera.org for those; the CLI and docs keep them.
  it("passes no credential: no login flags, home secrets, key paths or auth headers", () => {
    const SHAPES = /--auth-(?:bearer|cookie)|\.claude\.json|~\/\.ssh\/|--sign-key|headers\.authorization|cookies\.get\(|"secrets?"|"secret-scanning"/i;
    for (const f of files(PLUGIN).filter((f) => !f.endsWith(".png"))) expect(readFileSync(f, "utf-8"), f).not.toMatch(SHAPES);
    for (const t of ["--auth-bearer x", "~/.claude.json", "--sign-key ~/.ssh/id", "req.headers.authorization", "\"secret-scanning\","]) expect(t).toMatch(SHAPES);
  });

  it("has a skill that calls no script", () => {
    for (const f of files(join(PLUGIN, "skills/penthera"))) expect(readFileSync(f, "utf-8"), f).not.toMatch(/scripts\/[\w.-]+\.(?:sh|mjs|js|py)/);
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

  // Anthropic's directory refused the plugin on 6 Nov 2026 (LOCAL_CODE_MCP_SERVER):
  // it takes MCP servers that run on the user's computer only from verified
  // publishers. The plugin is skill-only; users add the server with `claude mcp add`.
  it("declares no MCP server in any manifest the directory or another client reads", () => {
    for (const f of [".mcp.json", "mcp.json", ".claude-plugin/.mcp.json"]) expect(existsSync(join(PLUGIN, f)), f).toBe(false);
    for (const f of ["plugin.json", ".claude-plugin/plugin.json"]) {
      const manifest = JSON.parse(readFileSync(join(PLUGIN, f), "utf-8"));
      expect(manifest.mcpServers, f).toBeUndefined();
      expect(manifest.keywords, f).not.toContain("mcp");
    }
    const market = JSON.parse(readFileSync(".claude-plugin/marketplace.json", "utf-8"));
    expect(market.plugins.find((p) => p.name === "penthera").mcpServers).toBeUndefined();
  });

  it("tells the user how to add the MCP server themselves, pinned", () => {
    const v = pkg.version;
    const add = `claude mcp add penthera -- npx -y penthera@${v} mcp`;
    for (const f of [join(PLUGIN, "README.md"), join(PLUGIN, "skills/penthera/SKILL.md")]) expect(readFileSync(f, "utf-8"), f).toContain(add);
  });

  it("is the folder the marketplace entry installs", () => {
    const market = JSON.parse(readFileSync(".claude-plugin/marketplace.json", "utf-8"));
    expect(market.plugins.find((p) => p.name === "penthera").source).toBe("./plugin");
  });
});
