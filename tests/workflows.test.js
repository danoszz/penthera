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
import { cpuMs } from "./fixtures/cpu-time.js";

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
    const found = checkWorkflow("jobs:\n  t:\n    steps:\n      - uses: some-org/deploy@v2\n      - uses: actions/setup-node@v4\n", "w.yml");
    expect(found.map((f) => [f.templateId, f.severity])).toEqual([["gha-unpinned-action", "medium"], ["gha-unpinned-action", "low"]]);
  });

  it("leaves a full SHA, a local action and a docker image alone", () => {
    const yml = "jobs:\n  t:\n    steps:\n      - uses: some-org/deploy@0123456789abcdef0123456789abcdef01234567 # v2\n      - uses: ./\n      - uses: docker://alpine:3\n";
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

// Every way to write the same workflow must give the same finding: the YAML
// means what it means to GitHub, whatever the spelling. From an adversarial
// review of the line-based reader this replaced (27 misses, 4 Nov 2026).
const P = "on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n";
const I = "on: issues\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n";
const PWN = {
  "with: before uses:": P + "      - with:\n          ref: ${{ github.event.pull_request.head.sha }}\n        uses: actions/checkout@v4\n",
  "ref on the next line": P + "      - uses: actions/checkout@v4\n        with:\n          ref:\n            ${{ github.event.pull_request.head.sha }}\n",
  "ref as a block scalar": P + "      - uses: actions/checkout@v4\n        with:\n          ref: >-\n            ${{ github.event.pull_request.head.sha }}\n",
  "uses on the next line": P + "      - uses:\n          actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
  "with: in flow style": P + '      - uses: actions/checkout@v4\n        with: { ref: "${{ github.event.pull_request.head.sha }}" }\n',
  "action in another case": P + "      - uses: Actions/Checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
  "expression in another case": P + "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.HEAD.SHA }}\n",
  "index syntax": P + "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request['head'].sha }}\n",
  "merge_commit_sha": P + "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.merge_commit_sha }}\n",
  "the fork, without a ref": P + "      - uses: actions/checkout@v4\n        with:\n          repository: ${{ github.event.pull_request.head.repo.full_name }}\n",
  "workflow_run head_commit": "on:\n  workflow_run:\n    workflows: [ci]\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.workflow_run.head_commit.id }}\n",
  "escape in a quoted ref": P + '      - uses: actions/checkout@v4\n        with:\n          ref: "${{ github.event.pull_request.\\x68ead.sha }}"\n',
  "quoted trigger in a list": 'on:\n  - "pull_request_target"\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n',
  "quoted keys": '"on":\n  \'pull_request_target\':\njobs:\n  t:\n    steps:\n      - "uses": actions/checkout@v4\n        with:\n          "r\\x65f": ${{ github.head_ref }}\n',
  "issue_comment and refs/pull": "on: issue_comment\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: refs/pull/${{ github.event.issue.number }}/head\n",
  "gh pr checkout in a script": P + "      - run: gh pr checkout ${{ github.event.pull_request.number }} && npm test\n",
  "an env var named uses": P + "      - uses: actions/checkout@v4\n        env:\n          uses: x\n        with:\n          args: |\n            - not a step\n          ref: ${{ github.event.pull_request.head.sha }}\n",
  "an anchor and alias": P + "      - uses: actions/checkout@v4\n        with: &w\n          ref: ${{ github.event.pull_request.head.sha }}\n      - uses: actions/checkout@v4\n        with: *w\n",
  "a %YAML 1.1 directive": "%YAML 1.1\n---\n" + P + "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
  "ref through env": "on: pull_request_target\nenv:\n  H: ${{ github.event.pull_request.head.sha }}\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ env.H }}\n",
  "git fetch of the head sha": P + "      - run: git fetch origin ${{ github.event.pull_request.head.sha }} && git checkout FETCH_HEAD && npm ci\n",
  "git clone of the fork": P + "      - run: git clone ${{ github.event.pull_request.head.repo.clone_url }} pr && cd pr && make\n",
  "pull/<number>/head": P + "      - run: git fetch origin pull/${{ github.event.pull_request.number }}/head:pr && git checkout pr\n",
  "a long padded line": `on: pull_request_target #${"x".repeat(5000)}\njobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}\n`,
};
const INJECT = {
  "\\x24 for $": I + '      - run: "echo \\x24{{ github.event.issue.title }}"\n',
  "an escaped line break": I + '      - run: "echo ${{ github.event.\\\n          issue.title }}"\n',
  "a folded plain scalar": I + "      - run: echo ${{ github.event.issue.title\n          }}\n",
  "split over block lines": I + "      - run: |\n          echo ${{\n            github.event.issue.title }}\n",
  "upper case": I + "      - run: echo ${{ GITHUB.EVENT.ISSUE.TITLE }}\n",
  "index syntax": I + "      - run: echo ${{ github.event.issue['title'] }}\n",
  "index on event": I + "      - run: echo ${{ github['event'].issue.title }}\n",
  "toJSON of the issue": I + "      - run: echo '${{ toJSON(github.event.issue) }}'\n",
  "actions/github-script": I + '      - uses: actions/github-script@v7\n        with:\n          script: console.log("${{ github.event.issue.title }}")\n',
  "run on the next line": I + "      - run:\n          echo ${{ github.event.issue.title }}\n",
  "an unclosed ${{ first": I + "      - run: echo '${{' && echo ${{ github.event.issue.title }}\n",
  "through env": I + "      - env:\n          T: ${{ github.event.issue.title }}\n        run: echo ${{ env.T }}\n",
  "toJSON of all of github": I + "      - run: echo '${{ toJSON(github) }}'\n",
  "spaces around a dot": I + "      - run: echo ${{ github.event.issue . title }}\n",
  "quoted run keys": I + '      - "r\\x75n": echo ${{ github.event.issue.title }}\n',
  "a heredoc line that looks like a quoted key": I + '      - run: |\n          cat <<EOF\n          "\\x1${{ github.event.issue.body }}": x\n          EOF\n',
};
const ids = (text) => checkWorkflow(text, "x.yml").filter((f) => f.templateId !== "gha-unpinned-action").map((f) => `${f.templateId}:${f.severity}`);

describe("every spelling GitHub reads the same way gives the same finding", () => {
  for (const [name, yml] of Object.entries(PWN)) it(`gha-pwn-request: ${name}`, () => expect(ids(yml)).toContain("gha-pwn-request:high"));
  for (const [name, yml] of Object.entries(INJECT)) it(`gha-script-injection: ${name}`, () => expect(ids(yml)).toContain("gha-script-injection:high"));

  it("points at the line of the expression inside a block script", () => {
    expect(rules("jobs:\n  t:\n    steps:\n      - run: |\n          echo start\n          echo ${{ github.event.issue.title }}\n")).toEqual(["gha-script-injection:6"]);
  });
});

// Safe patterns that must not fail a user's scan.
const SAFE = {
  "the base branch's ref": I.replace("issues", "pull_request_target") + "      - run: echo ${{ github.event.pull_request.base.ref }}\n",
  "the repository name": I + "      - run: echo ${{ github.event.repository.name }}\n",
  "a milestone title": I + "      - run: echo ${{ github.event.issue.milestone.title }}\n",
  "label names": P + "      - run: echo '${{ join(github.event.pull_request.labels.*.name) }}'\n",
  "contains() of a title": I + "      - run: echo ${{ contains(github.event.issue.title, 'bug') }}\n",
  "a comparison": I + "      - run: echo ${{ github.event.issue.title == 'x' }}\n",
  "the value passed through env and used as $T": I + '      - env:\n          T: ${{ github.event.issue.title }}\n        run: echo "$T"\n',
  "the merge commit, after the merge": "on:\n  pull_request_target:\n    types: [closed]\njobs:\n  a:\n    if: github.event.pull_request.merged == true\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.merge_commit_sha }}\n",
  "echoing the head sha": P + "      - run: echo ${{ github.event.pull_request.head.sha }}\n",
};

describe("safe patterns don't fail the scan", () => {
  for (const [name, yml] of Object.entries(SAFE)) it(name, () => expect(ids(yml)).toEqual([]));

  it("a same-repository guard lowers a PR checkout to medium", () => {
    const yml = "on: pull_request_target\njobs:\n  a:\n    if: github.event.pull_request.head.repo.full_name == github.repository\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n";
    expect(ids(yml)).toEqual(["gha-pwn-request:medium"]);
  });
});

// An exception that lowers a finding must be proven by the expression's syntax,
// never by text in it. These kept their finding until a shortcut dropped it.
const GUARDED = (cond) => `on: pull_request_target\njobs:\n  a:\n    if: ${cond}\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}\n`;
const SAME = "github.event.pull_request.head.repo.full_name == github.repository";

describe("exceptions hold only when the expression proves them", () => {
  it("a comparison sign inside a format() string is text, not a comparison", () => {
    for (const tpl of ["a > {0}", "{0} == x", "x != {0}", "{0} <b>"]) {
      expect(ids(I + `      - run: echo "\${{ format('${tpl}', github.event.issue.title) }}"\n`)).toEqual(["gha-script-injection:high"]);
    }
  });

  it("a boolean joined by || can still return the text itself", () => {
    expect(ids(I + "      - run: echo ${{ contains(github.event.issue.title, 'b') || github.event.issue.title }}\n")).toEqual(["gha-script-injection:high"]);
  });

  it("a same-repository check lowers the checkout only when every path requires it", () => {
    expect(ids(GUARDED(`${SAME} && github.actor != 'x'`))).toEqual(["gha-pwn-request:medium"]);
    expect(ids(GUARDED(`\${{ (${SAME}) }}`))).toEqual(["gha-pwn-request:medium"]);
    for (const cond of [`${SAME} || true`, `(${SAME} || true) && true`, `!(${SAME})`, `contains('${SAME}', 'x')`, `github.repository != github.event.pull_request.head.repo.full_name`]) {
      expect(ids(GUARDED(cond)), cond).toEqual(["gha-pwn-request:high"]);
    }
  });

  it("an if: with any text outside its ${{ }} is always true, so it guards nothing", () => {
    for (const cond of [`"\${{ ${SAME} }} "`, `|\n      \${{ ${SAME} }}`, `>\n      \${{ ${SAME} }}`, `\${{ ${SAME} }} && \${{ true }}`]) {
      expect(ids(GUARDED(cond)), cond).toEqual(["gha-pwn-request:high"]);
    }
  });

  it("a }} inside a string doesn't end the expression", () => {
    expect(ids(I + `      - run: echo "\${{ format('}}{0}', github.event.issue.title) }}"\n`)).toEqual(["gha-script-injection:high"]);
    expect(ids(I + "      - run: echo ${{ format('a}}', 'b') != 'c' && github.event.issue.title }}\n")).toEqual(["gha-script-injection:high"]);
  });

  it("a step reused by a guarded and an unguarded job keeps its high finding (Vercel, 5 Nov)", () => {
    const steps = "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n";
    for (const [first, second] of [["guarded", "open"], ["open", "guarded"]]) {
      const job = (name, ref) => name === "guarded"
        ? `  guarded:\n    if: ${SAME}\n    steps: ${ref}\n`
        : `  open:\n    steps: ${ref}\n`;
      const yml = `on: pull_request_target\nanchors:\n  s: &s\n${steps.replace(/^ {6}/gm, "    ")}jobs:\n${job(first, "*s")}${job(second, "*s")}`;
      expect(ids(yml), `${first} first`).toEqual(["gha-pwn-request:high"]);
    }
  });

  it("the merged guard needs the same proof", () => {
    const yml = (cond) => `on:\n  pull_request_target:\n    types: [closed]\njobs:\n  a:\n    if: ${cond}\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.merge_commit_sha }}\n`;
    expect(ids(yml("github.event.pull_request.merged == true"))).toEqual([]);
    expect(ids(yml("github.event.pull_request.merged == true || true"))).toEqual(["gha-pwn-request:high"]);
    expect(ids(yml("github.event.pull_request.merged == false"))).toEqual(["gha-pwn-request:high"]);
    expect(ids(yml('"${{ github.event.pull_request.merged }} "'))).toEqual(["gha-pwn-request:high"]);
    const fork = yml("github.event.pull_request.merged").replace("merge_commit_sha }}", "merge_commit_sha && github.event.pull_request.head.ref }}");
    expect(ids(fork)).toEqual(["gha-pwn-request:high"]);
  });
});

describe("a workflow it can't read fails the scan instead of passing", () => {
  it("reports Unicode line breaks, which parsers read differently", () => {
    for (const br of ["\u2028", "\u2029", "\x85"]) expect(ids(`# c${br}on: issues${br}jobs:\n`)).toEqual(["gha-workflow-unchecked:high"]);
  });

  it("reports YAML it can't parse", () => {
    expect(ids("jobs:\n  t:\n    steps:\n      - run: echo\n     bad: [\n")).toEqual(["gha-workflow-unchecked:high"]);
    expect(ids(I + "      - run: |\r          echo ${{ github.event.issue.title }}\r")).toHaveLength(1);
  });

  it("reports duplicate keys, which hide one value behind another", () => {
    expect(ids(I + "      - run: echo ok\n        run: echo ${{ github.event.issue.title }}\n")).toEqual(["gha-workflow-unchecked:high"]);
  });

  it("reports an alias bomb fast instead of expanding it", () => {
    const bomb = ["on: pull_request_target", "x0: &a0 [{uses: actions/checkout@v4}]"];
    for (let i = 1; i < 20; i++) bomb.push(`x${i}: &a${i} [${Array(9).fill(`*a${i - 1}`).join(", ")}]`);
    bomb.push("jobs:\n  t:\n    steps: *a19");
    let found;
    expect(cpuMs(() => { found = ids(bomb.join("\n")); })).toBeLessThan(2000);
    expect(found).toEqual(["gha-workflow-unchecked:high"]);
  });
});

describe("crafted workflows can't make the check slow", () => {
  // CPU time, fastest of 3: a linear check stays far under 2 s on a busy runner,
  // and anything quadratic at the 256 KB cap takes tens of seconds every run.
  const timed = (text) => cpuMs(() => checkWorkflow(text, "x.yml"), { runs: 3 });

  it("checks a near-cap workflow of many steps in well under a second", () => {
    const text = P + "      - uses: actions/checkout@v4\n        with: {ref: main}\n".repeat(4000);
    expect(text.length).toBeLessThan(256 * 1024);
    expect(timed(text)).toBeLessThan(2000);
  });

  it("peels deeply nested brackets in one pass, also with many steps", () => {
    const deep = (n) => "(".repeat(n) + "true" + ")".repeat(n);
    const steps = "      - uses: actions/checkout@v4\n        with:\n          ref: main\n".repeat(200);
    expect(timed(`on: pull_request_target\njobs:\n  a:\n    if: ${deep(10000)}\n    steps:\n${steps}`)).toBeLessThan(2000);
    expect(timed(I + `      - run: echo \${{ ${"(".repeat(60000)}github.event.issue.title${")".repeat(60000)} }}\n`)).toBeLessThan(2000);
  });

  it("resolves each alias once, however often jobs and steps reuse it (Vercel, 5 Nov)", () => {
    const L = ["on: pull_request_target", "pad:"];
    for (let i = 0; i < 25000; i++) L.push(`  - ${i}`);
    L.push("defs:", "  s: &s {uses: actions/checkout@v4, with: {ref: main}, run: echo hi}");
    L.push(`  steps: &st [${Array(40).fill("*s").join(", ")}]`, "  job: &j {runs-on: x, steps: *st}", "jobs:");
    for (let i = 0; i < 40; i++) L.push(`  j${i}: *j`);
    const text = L.join("\n") + "\n";
    expect(text.length).toBeLessThan(256 * 1024);
    let found;
    expect(cpuMs(() => { found = checkWorkflow(text, "x.yml"); }, { runs: 3 })).toBeLessThan(2000);
    expect(found.map((f) => `${f.templateId}:${f.severity}`)).toEqual(["gha-unpinned-action:low"]);
  });

  it("checks one very long line in well under a second", () => {
    expect(timed(" ".repeat(250 * 1024) + "run")).toBeLessThan(2000);
    expect(timed(I + "      - run: " + "${{ github.event." + "a.".repeat(100 * 1024) + " }}\n")).toBeLessThan(2000);
  });
});

describe("our own workflows", () => {
  it("have no pwn request or script injection", () => {
    const serious = scanWorkflows(".").filter((f) => f.templateId !== "gha-unpinned-action");
    expect(serious.map((f) => `${f.file}:${f.line} ${f.templateId}`)).toEqual([]);
  });
});
