import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const PLUGIN = join(import.meta.dirname, "..", "plugin");
const read = (f) => JSON.parse(readFileSync(join(PLUGIN, f), "utf8"));

// Claude Code reads .claude-plugin/plugin.json. GitHub Copilot and Codex read the
// Agent Plugins 1.0.0 copy at the folder's root. They must agree. The plugin is
// skill-only, so neither has an MCP file (tests/plugin-folder.test.js checks that).
describe("the plugin's two manifests", () => {
  it("say the same thing about the plugin", () => {
    const claude = read(".claude-plugin/plugin.json");
    const agent = read("plugin.json");
    expect(agent.$schema).toBe("https://agent-plugins.org/schemas/1.0.0/plugin.schema.json");
    for (const k of ["name", "version", "description", "author", "homepage", "repository", "license", "keywords"]) {
      expect(agent[k], k).toEqual(claude[k]);
    }
  });

  it("keep to the fields the Agent Plugins schema allows", () => {
    const allowed = ["$schema", "name", "version", "description", "author", "homepage", "repository", "license", "keywords", "extensions"];
    expect(Object.keys(read("plugin.json")).filter((k) => !allowed.includes(k))).toEqual([]);
  });
});
