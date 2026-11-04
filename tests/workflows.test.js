/**
 * GitHub Actions workflow checks (lib/whitebox/workflows.js): a match and a
 * no-match case per rule, and our own .github/workflows as the clean case.
 */
import { describe, it, expect } from "vitest";
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

describe("our own workflows", () => {
  it("have no pwn request or script injection", () => {
    const serious = scanWorkflows(".").filter((f) => f.templateId !== "gha-unpinned-action");
    expect(serious.map((f) => `${f.file}:${f.line} ${f.templateId}`)).toEqual([]);
  });
});
