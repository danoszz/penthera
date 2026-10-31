import { describe, it, expect } from "vitest";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { checkChange } from "../scripts/ci/docs-gate.mjs";

const NONE = { file: "changelog.d/x.md", text: "section: Fixed\ndocs: none, internal move only\n\n- Moved.\n" };
const PLAIN = { file: "changelog.d/x.md", text: "section: Fixed\n\n- Moved.\n" };

describe("docs gate: one change", () => {
  it("passes a change that touches no public surface", () => {
    const got = checkChange(["lib/whitebox/routes.js", "tests/a.test.js", "site/index.html"]);
    expect(got).toEqual({ touched: [], excused: null, missing: [] });
  });

  it("fails a CLI change with no doc and names the file", () => {
    const { missing } = checkChange(["src/cli/deps.js", "changelog.d/x.md"], [PLAIN]);
    expect(missing).toEqual([{ name: "CLI", files: ["src/cli/deps.js"] }]);
  });

  it("passes a surface change when a doc that owns it changes", () => {
    expect(checkChange(["src/cli.js", "docs/commands/scan.md"]).missing).toEqual([]);
    expect(checkChange(["src/mcp/tools.js", "docs/commands/mcp.md"]).missing).toEqual([]);
    expect(checkChange(["action.yml", "docs/commands/action.md"]).missing).toEqual([]);
    expect(checkChange(["lib/rules/core/secrets.json", "docs/rule-packs.md"]).missing).toEqual([]);
  });

  it("does not count a doc that doesn't own the surface", () => {
    expect(checkChange(["src/mcp/tools.js", "docs/privacy.md"]).missing.map((m) => m.name)).toEqual(["MCP tools"]);
    expect(checkChange(["src/cli.js", "docs/research/note.md"]).missing.map((m) => m.name)).toEqual(["CLI"]);
    expect(checkChange(["src/cli.js", "docs/funding/sponsor-tiers.md"]).missing.map((m) => m.name)).toEqual(["CLI"]);
  });

  it("checks each surface on its own", () => {
    const { touched, missing } = checkChange(["src/cli.js", "src/mcp/tools.js", "README.md"]);
    expect(touched).toEqual(["CLI", "MCP tools"]);
    expect(missing.map((m) => m.name)).toEqual(["MCP tools"]);
  });

  it("accepts a docs: none line and reports its reason", () => {
    expect(checkChange(["src/cli/deps.js", NONE.file], [NONE])).toMatchObject({ excused: "internal move only", missing: [] });
  });

  it("counts a new rule, not a re-signed pack", () => {
    const signed = ["lib/rules/advisories/pack.json", "lib/rules/advisories/pack.json.sig", "lib/rules/allowed_signers"];
    expect(checkChange(signed).touched).toEqual([]);
    expect(checkChange(["lib/rules/advisories/runtime.json"]).missing.map((m) => m.name)).toEqual(["rules"]);
    expect(checkChange(["lib/agents/rules.js"]).missing.map((m) => m.name)).toEqual(["rules"]);
  });

  it("throws on a broken docs line, so a typo can't excuse a change", () => {
    const bad = { file: "changelog.d/x.md", text: "section: Fixed\ndocs: none\n\n- Moved.\n" };
    expect(() => checkChange(["src/cli.js"], [bad])).toThrow(/x\.md/);
  });
});

describe("docs gate: on a real branch", () => {
  const SCRIPT = join(import.meta.dirname, "..", "scripts", "ci", "docs-gate.mjs");

  /** A repo with a base commit and one commit on top; returns the gate's result. */
  function run(files, remove = []) {
    const dir = mkdtempSync(join(tmpdir(), "penthera-docs-gate-"));
    const git = (...a) => execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.test", ...a], { cwd: dir, encoding: "utf-8" });
    const put = (f, text) => { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), text); };
    try {
      git("init", "-q", "-b", "main");
      put("src/cli.js", "1\n");
      put("changelog.d/old.md", "section: Fixed\n\n- Old.\n");
      git("add", "."); git("commit", "-q", "-m", "base"); git("branch", "base");
      for (const [f, text] of Object.entries(files)) put(f, text);
      for (const f of remove) rmSync(join(dir, f));
      git("add", "-A"); git("commit", "-q", "-m", "change");
      return spawnSync(process.execPath, [SCRIPT, "base", "HEAD"], { cwd: dir, encoding: "utf-8" });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  it("exits 1 and says what to do when the docs are missing", () => {
    const r = run({ "src/cli.js": "2\n" });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("CLI: src/cli.js");
    expect(r.stderr).toContain('"docs: none, <reason>"');
  });

  it("exits 0 with a doc, and with a docs: none fragment", () => {
    expect(run({ "src/cli.js": "2\n", "docs/commands/scan.md": "x\n" }).status).toBe(0);
    const r = run({ "src/cli.js": "2\n", "changelog.d/new.md": NONE.text });
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("internal move only");
  });

  it("ignores fragments the change deletes, as a release does", () => {
    expect(run({ "CHANGELOG.md": "x\n" }, ["changelog.d/old.md"]).status).toBe(0);
  });

  it("exits 2 with no base ref", () => {
    expect(spawnSync(process.execPath, [SCRIPT], { encoding: "utf-8" }).status).toBe(2);
  });
});
