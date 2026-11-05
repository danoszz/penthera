/**
 * plugin-claude-live (scripts/ci/plugin-live.mjs): the branch Anthropic's plugin
 * directory follows only ever points at a plugin whose pinned version is on
 * npm as `latest`.
 */
import { describe, it, expect } from "vitest";
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pinOf, chooseTarget, candidates } from "../scripts/ci/plugin-live.mjs";

describe("plugin-claude-live", () => {
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

  it("never promotes a plugin a PR added and then removed (first parent only)", () => {
    const dir = mkdtempSync(join(tmpdir(), "plugin-live-"));
    const env = { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1", HOME: dir };
    const run = (...a) => execFileSync("git", ["-C", dir, ...a], { encoding: "utf-8", env, stdio: ["ignore", "pipe", "pipe"] }).trim();
    const pin = (v) => {
      mkdirSync(join(dir, "plugin"), { recursive: true });
      writeFileSync(join(dir, "plugin/.mcp.json"), JSON.stringify({ mcpServers: { penthera: { args: ["-y", `penthera@${v}`, "mcp"] } } }));
    };
    let clock = 1_700_000_000; // distinct, increasing dates so rev-list's order is fixed
    const dated = () => { clock += 60; return { ...env, GIT_AUTHOR_DATE: `${clock} +0000`, GIT_COMMITTER_DATE: `${clock} +0000` }; };
    const commit = (m) => {
      run("add", "-A");
      execFileSync("git", ["-C", dir, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", m], { env: dated() });
      return run("rev-parse", "HEAD");
    };
    run("init", "-q", "-b", "main");
    pin("2.3.1"); const reviewed = commit("2.3.1 live");
    pin("2.4.0"); commit("release PR: pins 2.4.0 before npm has it");
    run("checkout", "-q", "-b", "pr");
    pin("2.3.1"); writeFileSync(join(dir, "plugin/evil"), "x"); const discarded = commit("pr: sneaks a 2.3.1-pinned plugin in");
    pin("2.4.0"); run("rm", "-q", "plugin/evil"); commit("pr: removes it again");
    run("checkout", "-q", "main");
    execFileSync("git", ["-C", dir, "-c", "user.name=t", "-c", "user.email=t@t", "merge", "-q", "--no-ff", "-m", "merge pr", "pr"], { env: dated() });
    const target = chooseTarget(candidates("main", "2.3.1", run), "2.3.1");
    expect(target).not.toBe(discarded);
    expect(target).toBe(reviewed);
  });
});
