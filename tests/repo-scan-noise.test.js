/**
 * The repo secret scan on a non-JS project: virtualenvs and note vaults are
 * skipped, git-ignored files are reported as local only, large files are
 * scanned in chunks with the right line numbers, and base64 blobs do not
 * produce key-shaped matches.
 *
 * Fake keys are assembled at runtime so this file never contains a string
 * that looks like a real credential.
 */
import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";
import { scanSecrets, findSecretsInText } from "../lib/whitebox/secrets.js";
import { gitIgnored } from "../lib/git.js";

const fill = (n, chars = "aB3dE5fG7h") => chars.repeat(Math.ceil(n / chars.length)).slice(0, n);
const ANTHROPIC = "sk-" + "ant-api03-" + fill(93);
const GOOGLE = "AI" + "za" + fill(35);
const AWS = "AK" + "IA" + "QWERTYUIOPASDFGH";

function withDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), "penthera-noise-"));
  try { return fn(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

function put(root, rel, text) {
  const full = join(root, rel);
  mkdirSync(join(full, ".."), { recursive: true });
  writeFileSync(full, text);
}

describe("scanSecrets: third-party folders", () => {
  it("skips Python virtualenvs, tool caches and an Obsidian vault", () => {
    withDir((dir) => {
      const leak = `KEY = "${AWS}"\n`;
      put(dir, "app.py", leak);
      put(dir, "venv/lib/python3.12/site-packages/PIL/ImageFont.py", leak);
      put(dir, ".venv/lib/x.py", leak);
      put(dir, "libs/site-packages/pkg/mod.py", leak);
      put(dir, "src/__pycache__/x.py", leak);
      put(dir, ".obsidian/plugins/p/main.js", leak);
      // A virtualenv under a name not on the list is found by its pyvenv.cfg.
      put(dir, "py311/pyvenv.cfg", "home = /usr/bin\n");
      put(dir, "py311/lib/y.py", leak);
      expect(scanSecrets(dir).map((f) => f.url)).toEqual(["app.py"]);
    });
  });
});

describe("scanSecrets: git-ignored files", () => {
  const hasGit = (() => { try { execFileSync("git", ["--version"], { stdio: "ignore" }); return true; } catch { return false; } })();

  it.skipIf(!hasGit)("skips ignored folders and reports an ignored .env as local only", () => {
    withDir((dir) => {
      execFileSync("git", ["init", "-q"], { cwd: dir });
      put(dir, ".gitignore", ".env\nout/\n");
      put(dir, ".env", `ANTHROPIC_API_KEY=${ANTHROPIC}\n`);
      put(dir, "out/generated.js", `const k = "${ANTHROPIC}";\n`);
      put(dir, "config.js", `const k = "${ANTHROPIC}";\n`);
      const findings = scanSecrets(dir, { ignored: gitIgnored(dir) });
      expect(findings.map((f) => [f.url, f.severity, !!f.localOnly]).sort()).toEqual([
        [".env", "low", true],
        ["config.js", "critical", false],
      ]);
      expect(findings.find((f) => f.url === ".env").line).toBe(1);
      expect(findings.find((f) => f.url === ".env").description).toMatch(/ignored by git/);
    });
  });
});

describe("scanSecrets: large files", () => {
  it("reads a large file whole and finds a key where an old 64 KB chunk edge was", () => {
    withDir((dir) => {
      const chunk = 64 * 1024;
      const pad = "x".repeat(chunk - 20) + "\n";
      put(dir, "big.json", `${pad}{"k": "${ANTHROPIC}"}\n${"y".repeat(chunk)}\n`);
      const findings = scanSecrets(dir);
      expect(findings).toMatchObject([{ url: "big.json", severity: "critical", line: 2 }]);
    });
  });

  it("keeps line numbers right deep in a large file", () => {
    withDir((dir) => {
      const lines = Array.from({ length: 3000 }, (_, i) => `line ${i + 1} ${"z".repeat(90)}`);
      lines[2499] = `const k = "${ANTHROPIC}";`;
      put(dir, "big.js", lines.join("\n") + "\n");
      // ~290 KB, read whole since 2.3.2 (it was read in 64 KB chunks here before).
      expect(scanSecrets(dir)).toMatchObject([{ url: "big.js", line: 2500 }]);
    });
  });

  it("still reports a file over the hard cap instead of reading it", () => {
    withDir((dir) => {
      put(dir, "big.json", `{"k": "${ANTHROPIC}"}`);
      expect(scanSecrets(dir, { maxBytes: 16 })).toMatchObject([{ severity: "info", title: "File too large to scan for secrets" }]);
    });
  });
});

describe("findSecretsInText: encoded blobs", () => {
  const blob = (inner) => fill(2000, "QmFzZTY0ZGF0YQ") + inner + fill(2000, "aW1hZ2VieXRlcw");

  it("ignores key shapes inside a long base64 run (inlined image data)", () => {
    const text = `{"slide": "data:image/png;base64,${blob(GOOGLE)}", "aws": "${blob(AWS)}"}`;
    expect(findSecretsInText(text)).toEqual([]);
  });

  it("still finds a real key next to a blob, at its original index", () => {
    const text = `{"img": "${blob("")}", "key": "${GOOGLE}"}`;
    const hits = findSecretsInText(text);
    expect(hits.map((h) => h.name)).toEqual(["Google API key (Gemini / Firebase / Maps)"]);
    expect(text.slice(hits[0].index, hits[0].index + GOOGLE.length)).toBe(GOOGLE);
  });
});
