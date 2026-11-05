/**
 * plugin-live (scripts/ci/plugin-live.mjs): the branch Anthropic's plugin
 * directory follows only ever points at a plugin whose pinned version is on
 * npm as `latest`.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { pinOf, chooseTarget } from "../scripts/ci/plugin-live.mjs";

describe("plugin-live", () => {
  it("reads the pinned version from the plugin's .mcp.json", () => {
    expect(pinOf(readFileSync("plugin/.mcp.json", "utf-8"))).toBe(JSON.parse(readFileSync("package.json", "utf-8")).version);
    expect(pinOf('{"mcpServers":{"penthera":{"args":["-y","penthera@2.4.0","mcp"]}}}')).toBe("2.4.0");
    expect(pinOf('{"mcpServers":{"penthera":{"args":["-y","penthera@latest","mcp"]}}}')).toBeNull();
    expect(pinOf("not json")).toBeNull();
  });

  it("picks the newest commit that pins npm's latest, never one ahead of it", () => {
    const commits = [
      { sha: "c3", pin: "2.4.0" }, // release PR merged, npm not approved yet
      { sha: "c2", pin: "2.3.1" }, // a docs change after 2.3.1
      { sha: "c1", pin: "2.3.1" },
    ];
    expect(chooseTarget(commits, "2.3.1")).toBe("c2");
    expect(chooseTarget(commits, "2.4.0")).toBe("c3");
    expect(chooseTarget(commits, "2.5.0")).toBeNull();
  });

  it("never follows a release candidate or a malformed version", () => {
    const commits = [{ sha: "c1", pin: "2.4.0" }];
    for (const v of ["2.4.0-rc.1", "", "latest", "2.4"]) expect(chooseTarget(commits, v)).toBeNull();
  });
});
