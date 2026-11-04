/**
 * GitHub Actions workflow checks (lib/whitebox/workflows.js): a match and a
 * no-match case per rule, and our own .github/workflows as the clean case.
 */
import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { checkWorkflow, scanWorkflows } from "../lib/whitebox/workflows.js";

const rules = (text) => checkWorkflow(text, ".github/workflows/x.yml").map((f) => `${f.templateId}:${f.line}`);

describe("gha-pwn-request", () => {
  it("flags pull_request_target that checks out the PR head", () => {
    const yml = [
      "on:",
      "  pull_request_target:",
      "jobs:",
      "  build:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
      "        with:",
      "          ref: ${{ github.event.pull_request.head.sha }}",
      "      - run: npm ci && npm test",
    ].join("\n");
    expect(rules(yml)).toContain("gha-pwn-request:9");
  });

  it("leaves pull_request_target that checks out the base branch alone", () => {
    const yml = "on:\n  pull_request_target:\njobs:\n  t:\n    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        with:\n          persist-credentials: false\n";
    expect(rules(yml)).toEqual([]);
  });

  it("leaves the plain pull_request trigger alone, even with the head ref", () => {
    const yml = "on: [pull_request]\njobs:\n  t:\n    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n";
    expect(rules(yml)).toEqual([]);
  });
});

describe("gha-script-injection", () => {
  it("flags a PR title expanded inside a run script, inline and in a block", () => {
    const yml = [
      "on: pull_request",
      "jobs:",
      "  t:",
      "    steps:",
      '      - run: echo "${{ github.event.pull_request.title }}"',
      "      - run: |",
      "          echo start",
      '          git checkout "${{ github.head_ref }}"',
    ].join("\n");
    expect(rules(yml)).toEqual(["gha-script-injection:5", "gha-script-injection:8"]);
  });

  it("leaves the same value passed through env alone", () => {
    const yml = [
      "jobs:",
      "  t:",
      "    steps:",
      "      - env:",
      "          TITLE: ${{ github.event.pull_request.title }}",
      '        run: echo "$TITLE"',
      "      - run: echo ${{ github.event.pull_request.number }}",
    ].join("\n");
    expect(rules(yml)).toEqual([]);
  });
});

describe("gha-unpinned-action", () => {
  it("flags a tag, medium for a third party and low for actions/*", () => {
    const found = checkWorkflow("steps:\n  - uses: some-org/deploy@v2\n  - uses: actions/setup-node@v4\n", "w.yml");
    expect(found.map((f) => [f.templateId, f.severity])).toEqual([["gha-unpinned-action", "medium"], ["gha-unpinned-action", "low"]]);
  });

  it("leaves a full SHA, a local action and a docker image alone", () => {
    const yml = "steps:\n  - uses: some-org/deploy@0123456789abcdef0123456789abcdef01234567 # v2\n  - uses: ./\n  - uses: docker://alpine:3\n";
    expect(rules(yml)).toEqual([]);
  });
});

describe("reading an untrusted repo's workflows", () => {
  const bad = "on:\n  pull_request_target:\njobs:\n  t:\n    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        with:\n          ref: ${{ github.head_ref }}\n";
  const repo = () => {
    const root = mkdtempSync(join(tmpdir(), "penthera-wf-"));
    mkdirSync(join(root, ".github", "workflows"), { recursive: true });
    return root;
  };

  it("still reads a regular workflow file", () => {
    const root = repo();
    writeFileSync(join(root, ".github/workflows/ci.yml"), bad);
    expect(scanWorkflows(root).map((f) => f.templateId)).toEqual(["gha-pwn-request"]);
  });

  it.skipIf(process.platform === "win32")("skips a workflow symlinked to an endless device, without hanging", () => {
    const root = repo();
    symlinkSync("/dev/zero", join(root, ".github/workflows/zero.yml"));
    expect(scanWorkflows(root)).toEqual([]);
  });

  it.skipIf(process.platform === "win32")("skips a symlinked workflows folder and a symlinked file", () => {
    const outside = mkdtempSync(join(tmpdir(), "penthera-wf-out-"));
    writeFileSync(join(outside, "ci.yml"), bad);
    const root = mkdtempSync(join(tmpdir(), "penthera-wf-"));
    mkdirSync(join(root, ".github"));
    symlinkSync(outside, join(root, ".github/workflows"));
    expect(scanWorkflows(root)).toEqual([]);

    const root2 = repo();
    symlinkSync(join(outside, "ci.yml"), join(root2, ".github/workflows/ci.yml"));
    expect(scanWorkflows(root2)).toEqual([]);
  });

  it.skipIf(process.platform === "win32")("skips a FIFO without blocking", () => {
    const root = repo();
    execFileSync("mkfifo", [join(root, ".github/workflows/pipe.yml")]);
    expect(scanWorkflows(root)).toEqual([]);
  });

  it("reports a file too large to check instead of passing it", () => {
    const root = repo();
    writeFileSync(join(root, ".github/workflows/huge.yml"), bad + "#".repeat(300 * 1024));
    expect(scanWorkflows(root).map((f) => `${f.templateId}:${f.severity}`)).toEqual(["gha-workflow-unchecked:high"]);
  });
});

describe("crafted workflows can't make the parser slow", () => {
  const timed = (text) => {
    const t = performance.now();
    checkWorkflow(text, "x.yml");
    return performance.now() - t;
  };

  it("parses a near-cap file of whitespace-prefixed lines in well under a second", () => {
    const pad = " ".repeat(1999);
    const text = [`${pad}#`, `${pad}runx`, `${pad}- usesx`, `${pad}\${{ ${" ".repeat(1900)}x }}`].join("\n").repeat(25);
    expect(text.length).toBeLessThan(256 * 1024);
    expect(timed(text)).toBeLessThan(500);
  });

  it("parses one very long line, past the per-line cap, in well under a second", () => {
    expect(timed(" ".repeat(250 * 1024) + "run")).toBeLessThan(500);
    expect(timed("run: " + "${{ github.event." + "a.".repeat(100 * 1024) + " }}")).toBeLessThan(500);
  });

  it("still finds a trigger and a checkout padded far past any real line", () => {
    const pad = " #" + "x".repeat(5000);
    const yml = `on: pull_request_target${pad}\njobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4${pad}\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}${pad}\n`;
    expect(rules(yml)).toContain("gha-pwn-request:7");
    expect(rules(`on:\n  pull_request_target:${pad}\n` + yml.split("\n").slice(1).join("\n"))).toContain("gha-pwn-request:8");
  });

  it("scans many checkout steps in linear time", () => {
    const text = "on: pull_request_target\n" + "    uses: actions/checkout@v4\n    with: x\n".repeat(20000);
    expect(timed(text)).toBeLessThan(500);
  });

  it("still finds an injection inside a list item and a block", () => {
    const yml = "jobs:\n  t:\n    steps:\n      -   run: |\n          echo ${{ github.event.issue.title }}\n";
    expect(rules(yml)).toEqual(["gha-script-injection:5"]);
  });
});

describe("our own workflows", () => {
  it("have no pwn request or script injection", () => {
    const serious = scanWorkflows(".").filter((f) => f.templateId !== "gha-unpinned-action");
    expect(serious.map((f) => `${f.file}:${f.line} ${f.templateId}`)).toEqual([]);
  });
});
