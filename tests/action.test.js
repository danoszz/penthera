/**
 * The GitHub Action: action.yml shape, the comment body builder, the marker
 * upsert against an injected (fake) API client, fork handling and fail-on.
 * Nothing here talks to GitHub.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, rmSync, existsSync, cpSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import YAML from "yaml";
import { spawnSync } from "node:child_process";
import {
  MARKER, MAX_BODY, buildCommentBody, upsertComment, isForkPullRequest, gate, ghClient, runComment, runGate,
} from "../scripts/action/comment.mjs";

const ROOT = resolve(import.meta.dirname, "..");
const readYaml = (p) => YAML.parse(readFileSync(join(ROOT, p), "utf-8"));

/** In-memory stand-in for the GitHub issues comments API. */
function fakeApi(comments = []) {
  let next = 1000;
  const calls = [];
  return {
    comments,
    calls,
    async listComments(issue) { calls.push(["list", issue]); return comments.map((c) => ({ ...c })); },
    async createComment(issue, body) { calls.push(["create", issue]); const c = { id: next++, body, login: "github-actions[bot]", userType: "Bot" }; comments.push(c); return c; },
    async updateComment(id, body) { calls.push(["update", id]); const c = comments.find((x) => x.id === id); c.body = body; return c; },
  };
}

describe("action.yml", () => {
  const action = readYaml("action.yml");

  it("is a composite action with a Marketplace-valid name, description and branding", () => {
    // "Penthera" alone is taken by an existing GitHub organization, and the
    // Marketplace rejects descriptions of 125 characters or more.
    expect(action.name).toBe("Penthera: your open-source cyber security agent");
    expect(action.description.length).toBeGreaterThan(0);
    expect(action.description.length).toBeLessThan(125);
    expect(action.runs.using).toBe("composite");
    expect(action.branding).toEqual({ icon: "shield", color: "blue" });
  });

  it("declares the documented inputs and defaults", () => {
    const i = action.inputs;
    expect(i.mode.default).toBe("deps");
    expect(i.path.default).toBe(".");
    expect(i["base-ref"].default).toBe("");
    expect(i["fail-on"].default).toBe("none");
    expect(i.comment.default).toBe("true");
    expect(i.sarif.default).toBe("true");
    expect(i["penthera-version"].default).toBe("");
    expect(i.url).toBeDefined();
    for (const [name, input] of Object.entries(i)) expect(input.description, name).toBeTruthy();
  });

  it("runs Penthera from its own checkout, never from npm or npx", () => {
    const steps = action.runs.steps;
    const scripts = steps.map((s) => s.run || "").join("\n");
    expect(scripts).toContain('node "$PENTHERA_DIR/bin/penthera.js"');
    expect(scripts).not.toMatch(/\bnpx\b/);
    expect(scripts).not.toMatch(/npm (i|install)\b/);
    expect(scripts).not.toMatch(/--online/);
    for (const s of steps.filter((x) => x.run)) {
      expect(s.shell, s.name).toBe("bash");
      // Inputs only reach the shell through env.
      expect(s.run, s.name).not.toMatch(/\$\{\{\s*(inputs|github)\./);
    }
  });

  it("fails the job when Penthera exits 1 without writing a report (1.5.0 to 2.0.0 passed silently)", () => {
    // Runs the action's own "Run Penthera" script against a stand-in CLI.
    const run = action.runs.steps.find((s) => s.id === "run").run;
    const tmp = mkdtempSync(join(tmpdir(), "penthera-action-run-"));
    try {
      const fake = join(tmp, "penthera");
      mkdirSync(join(fake, "bin"), { recursive: true });
      writeFileSync(join(fake, "package.json"), JSON.stringify({ version: "0.0.0-test" }));
      const step = (cli) => {
        writeFileSync(join(fake, "bin", "penthera.js"), cli);
        const runner = mkdtempSync(join(tmp, "runner-"));
        const output = join(runner, "output");
        writeFileSync(output, "");
        const r = spawnSync("bash", ["-c", run], {
          cwd: tmp, encoding: "utf-8",
          env: { PATH: process.env.PATH, PENTHERA_DIR: fake, INPUT_MODE: "deps", INPUT_PATH: ".", INPUT_BASE_REF: "", PR_BASE_SHA: "", INPUT_VERSION: "", INPUT_FOOTER: "true", RUNNER_TEMP: runner, GITHUB_OUTPUT: output },
        });
        return { ...r, output: readFileSync(output, "utf-8") };
      };
      // A crash: exit 1, nothing written.
      const crash = step("process.stderr.write(\"Error [ERR_MODULE_NOT_FOUND]\\n\"); process.exit(1);\n");
      expect(crash.status).toBe(2);
      expect(crash.stdout + crash.stderr).toMatch(/::error::Penthera exited 1 without writing a report/);
      expect(crash.output).not.toMatch(/report-file=/);
      // Real findings: exit 1 with a report, which fail-on decides later.
      const findings = step(`const fs = require("node:fs"); const a = process.argv; fs.writeFileSync(a[a.indexOf("-o") + 1], "{}"); process.exit(1);\n`);
      expect(findings.status).toBe(0);
      expect(findings.output).toMatch(/report-file=/);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("deps and scan modes run from a checkout without node_modules, as the action does", () => {
    // Every release from 1.5.0 to 2.0.0 crashed here: a static `yaml` import.
    const tmp = mkdtempSync(join(tmpdir(), "penthera-action-"));
    try {
      const copy = join(tmp, "penthera");
      for (const d of ["bin", "src", "lib", "scripts", "package.json"]) cpSync(join(ROOT, d), join(copy, d), { recursive: true });
      const app = join(tmp, "app");
      cpSync(join(ROOT, "tests", "fixtures", "init", "app"), app, { recursive: true });
      const home = join(tmp, "home");
      const r = spawnSync(process.execPath, [join(copy, "bin", "penthera.js"), "deps", ".", "-o", join(tmp, "out.json")], {
        cwd: app, encoding: "utf-8", env: { ...process.env, NO_COLOR: "1", HOME: home, PENTHERA_HOME: join(home, ".penthera") },
      });
      expect(r.stderr).not.toMatch(/ERR_MODULE_NOT_FOUND/);
      expect(r.status).toBe(0);
      expect(existsSync(join(tmp, "out.json"))).toBe(true);
      // scan mode: an unreachable loopback port fails the scan (exit 2), but never on a missing module.
      const u = spawnSync(process.execPath, [join(copy, "bin", "penthera.js"), "http://127.0.0.1:9", "--offline"], {
        cwd: app, encoding: "utf-8", env: { ...process.env, NO_COLOR: "1", HOME: home, PENTHERA_HOME: join(home, ".penthera") },
      });
      expect(u.stderr + u.stdout).not.toMatch(/ERR_MODULE_NOT_FOUND|Cannot find package/);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("refuses a base-ref that git could read as an option, and ends options before it (360 review)", () => {
    const script = action.runs.steps.map((st) => st.run || "").join("\n");
    const guard = /case "\$base" in[\s\S]*?esac/.exec(script)?.[0];
    expect(guard).toBeTruthy();
    const check = (ref) => spawnSync("sh", ["-c", `base="$1"; ${guard}; echo ok`, "_", ref], { encoding: "utf-8" });
    for (const good of ["main", "origin/main", "0123456789abcdef0123456789abcdef01234567", "release/v1.5", "HEAD~1"]) {
      expect(check(good).stdout.trim(), good).toBe("ok");
    }
    for (const bad of ["--upload-pack=touch /tmp/x", "-x", "a b", "a;b", "$(id)", "a..b"]) {
      const r = check(bad);
      expect(r.status, bad).toBe(2);
      expect(r.stdout).toContain("::error::base-ref is not a plain git ref");
    }
    expect(script).toMatch(/fetch --no-tags --depth=1 --end-of-options origin "\$base"/);
  });

  it("pins every third-party action by full commit SHA", () => {
    const uses = action.runs.steps.filter((s) => s.uses).map((s) => s.uses);
    expect(uses.length).toBeGreaterThan(0);
    for (const u of uses) expect(u).toMatch(/^[\w.-]+\/[\w./-]+@[0-9a-f]{40}$/);
    const scan = readFileSync(join(ROOT, ".github/workflows/scan.yml"), "utf-8");
    const sha = scan.match(/codeql-action\/upload-sarif@([0-9a-f]{40})/)[1];
    expect(uses).toContain(`github/codeql-action/upload-sarif@${sha}`);
  });

  it("the example and dogfood workflows use least privilege and a lockfile filter", () => {
    const example = readYaml("docs/examples/pr-dependency-review.yml");
    const dogfood = readYaml(".github/workflows/dependency-review.yml");
    for (const wf of [example, dogfood]) {
      expect(wf.on.pull_request.paths).toContain("package-lock.json");
      const perms = { ...wf.permissions, ...Object.values(wf.jobs)[0].permissions };
      expect(perms).toMatchObject({ contents: "read", "pull-requests": "write", "security-events": "write" });
    }
    const exampleUses = Object.values(example.jobs)[0].steps.map((s) => s.uses).filter(Boolean);
    expect(exampleUses.find((u) => u.startsWith("danoszz/penthera@"))).toMatch(/@[0-9a-f]{40}$/);
    expect(readFileSync(join(ROOT, "docs/examples/pr-dependency-review.yml"), "utf-8")).toMatch(/danoszz\/penthera@[0-9a-f]{40} # v\d+\.\d+\.\d+/);
    expect(Object.values(dogfood.jobs)[0].steps.map((s) => s.uses)).toContain("./");
  });
});

describe("buildCommentBody", () => {
  it("puts the marker first, exactly once", () => {
    const body = buildCommentBody(`${MARKER}\n## Dependency capability diff\n\nfine\n`, { sha: "0123456789abcdef" });
    expect(body.startsWith(`${MARKER}\n`)).toBe(true);
    expect(body.split(MARKER)).toHaveLength(2);
    expect(body).toContain("commit `0123456`");
  });

  it("adds a marker when the input has none and handles empty input", () => {
    expect(buildCommentBody("## hi")).toMatch(new RegExp(`^${MARKER}\\n## hi`));
    expect(buildCommentBody("")).toContain("no output");
  });

  it("links the workflow run", () => {
    expect(buildCommentBody("x", { runUrl: "https://github.com/o/r/actions/runs/1" })).toContain("[workflow run](https://github.com/o/r/actions/runs/1)");
  });

  it("stays under GitHub's size limit", () => {
    const body = buildCommentBody("a".repeat(MAX_BODY * 2), { sha: "abc1234", runUrl: "https://x" });
    expect(body.length).toBeLessThanOrEqual(MAX_BODY);
    expect(body).toContain("truncated");
    expect(body.startsWith(MARKER)).toBe(true);
  });

  it("is deterministic", () => {
    expect(buildCommentBody("same", { sha: "a" })).toBe(buildCommentBody("same", { sha: "a" }));
  });
});

describe("upsertComment", () => {
  it("creates the comment when none has the marker", async () => {
    const api = fakeApi([{ id: 1, body: "LGTM", userType: "User" }]);
    const res = await upsertComment(api, { issue: 7, body: `${MARKER}\nfirst` });
    expect(res.action).toBe("created");
    expect(api.comments).toHaveLength(2);
  });

  it("updates the same comment on the next push instead of posting a new one", async () => {
    const api = fakeApi();
    const first = await upsertComment(api, { issue: 7, body: `${MARKER}\npush 1` });
    const second = await upsertComment(api, { issue: 7, body: `${MARKER}\npush 2` });
    expect(second).toEqual({ action: "updated", id: first.id });
    expect(api.comments).toHaveLength(1);
    expect(api.comments[0].body).toContain("push 2");
  });

  it("does nothing when the body is unchanged", async () => {
    const body = `${MARKER}\nsame`;
    const api = fakeApi([{ id: 5, body, login: "github-actions[bot]", userType: "Bot" }]);
    expect(await upsertComment(api, { issue: 7, body })).toEqual({ action: "unchanged", id: 5 });
    expect(api.calls.map((c) => c[0])).toEqual(["list"]);
  });

  it("never edits a person's comment that quotes the marker", async () => {
    const api = fakeApi([{ id: 9, body: `look: ${MARKER}`, userType: "User" }]);
    const res = await upsertComment(api, { issue: 7, body: `${MARKER}\nbot` });
    expect(res.action).toBe("created");
    expect(api.comments.find((c) => c.id === 9).body).toBe(`look: ${MARKER}`);
  });

  it("never edits another bot's or app's comment that carries the marker (360 review)", async () => {
    const api = fakeApi([
      { id: 11, body: `${MARKER}\nspoofed by an app`, login: "evil-app[bot]", userType: "Bot" },
      { id: 12, body: `${MARKER}\nno login`, userType: "Bot" },
    ]);
    const res = await upsertComment(api, { issue: 7, body: `${MARKER}\nours` });
    expect(res.action).toBe("created");
    expect(api.calls.some((c) => c[0] === "update")).toBe(false);
    expect(api.comments.find((c) => c.id === 11).body).toContain("spoofed");
  });

  it("refuses a body without the marker", async () => {
    await expect(upsertComment(fakeApi(), { issue: 1, body: "untracked" })).rejects.toThrow(/marker/);
  });
});

describe("ghClient", () => {
  it("drives gh api with paginated listing and JSON bodies on stdin", async () => {
    const calls = [];
    const run = (cmd, args, opts) => {
      calls.push({ cmd, args, input: opts.input });
      if (args.includes("--paginate")) return { status: 0, stdout: '{"id":1,"body":"a","login":"github-actions[bot]","userType":"Bot"}\n{"id":2,"body":"b","login":"x","userType":"User"}\n' };
      return { status: 0, stdout: '{"id":3}' };
    };
    const api = ghClient("o/r", { run });
    expect(await api.listComments(4)).toHaveLength(2);
    await api.createComment(4, "hello");
    await api.updateComment(3, "bye");
    expect(calls.every((c) => c.cmd === "gh" && c.args[0] === "api")).toBe(true);
    expect(calls[0].args).toContain("repos/o/r/issues/4/comments?per_page=100");
    expect(calls[0].args.join(" ")).toContain("login: .user.login");
    expect(calls[1].args).toEqual(["api", "--method", "POST", "repos/o/r/issues/4/comments", "--input", "-"]);
    expect(JSON.parse(calls[1].input)).toEqual({ body: "hello" });
    expect(calls[2].args).toContain("repos/o/r/issues/comments/3");
  });

  it("marks permission errors as forbidden", async () => {
    const api = ghClient("o/r", { run: () => ({ status: 1, stderr: "HTTP 403: Resource not accessible by integration" }) });
    await expect(api.createComment(1, "x")).rejects.toMatchObject({ forbidden: true });
  });
});

describe("isForkPullRequest", () => {
  const pr = (head, base) => ({ pull_request: { head: { repo: { full_name: head } }, base: { repo: { full_name: base } } } });
  it("detects forks", () => {
    expect(isForkPullRequest(pr("o/r", "o/r"))).toBe(false);
    expect(isForkPullRequest(pr("someone/r", "o/r"))).toBe(true);
    expect(isForkPullRequest(pr(undefined, "o/r"))).toBe(true); // deleted fork
    expect(isForkPullRequest({})).toBe(false);
  });
});

describe("runComment", () => {
  let dir, env;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "penthera-action-"));
    writeFileSync(join(dir, "c.md"), `${MARKER}\n## Dependency capability diff\n\nok\n`);
    env = { GITHUB_REPOSITORY: "o/r", GITHUB_STEP_SUMMARY: join(dir, "summary.md"), GITHUB_OUTPUT: join(dir, "out.txt"), GITHUB_EVENT_PATH: join(dir, "event.json") };
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));
  const event = (head) => writeFileSync(env.GITHUB_EVENT_PATH, JSON.stringify({
    pull_request: { number: 12, head: { sha: "feedbeef00", repo: { full_name: head } }, base: { repo: { full_name: "o/r" } } },
  }));

  it("upserts on a same-repo PR and writes the job summary", async () => {
    event("o/r");
    const api = fakeApi();
    expect((await runComment({ "body-file": join(dir, "c.md") }, env, api)).action).toBe("created");
    expect(api.calls[0]).toEqual(["list", 12]);
    expect(readFileSync(env.GITHUB_STEP_SUMMARY, "utf-8")).toContain("Dependency capability diff");
    expect(readFileSync(env.GITHUB_OUTPUT, "utf-8")).toContain("comment-action=created");
  });

  it("skips the comment on forks but still writes the summary", async () => {
    event("fork/r");
    const api = fakeApi();
    expect((await runComment({ "body-file": join(dir, "c.md") }, env, api)).action).toBe("skipped");
    expect(api.calls).toEqual([]);
    expect(existsSync(env.GITHUB_STEP_SUMMARY)).toBe(true);
  });

  it("skips cleanly when the token cannot write", async () => {
    event("o/r");
    const api = fakeApi();
    api.createComment = async () => { const e = new Error("403"); e.forbidden = true; throw e; };
    expect((await runComment({ "body-file": join(dir, "c.md") }, env, api)).action).toBe("skipped");
  });
});

describe("gate", () => {
  it("warns when the site wasn't read, and only then", () => {
    const dir = mkdtempSync(join(tmpdir(), "penthera-gate-"));
    const logs = [];
    const log = vi.spyOn(console, "log").mockImplementation((m) => logs.push(m));
    try {
      const run = (report) => {
        const file = join(dir, "r.json");
        writeFileSync(file, JSON.stringify({ findings: [], ...report }));
        logs.length = 0;
        return { res: runGate({ report: file, "fail-on": "high" }), logs: [...logs] };
      };
      const refused = run({ challenge: { provider: "Cloudflare" } });
      expect(refused.res.fail).toBe(false);
      expect(refused.logs[0]).toMatch(/^::warning::Site not read/);
      expect(run({ reachable: false }).logs[0]).toMatch(/^::warning::/);
      expect(run({ reachable: true }).logs).toEqual([]);
    } finally {
      log.mockRestore();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  const findings = [{ severity: "low" }, { severity: "high" }];
  it("applies fail-on thresholds", () => {
    expect(gate(findings, "none").fail).toBe(false);
    expect(gate(findings, "high")).toEqual({ fail: true, count: 1 });
    expect(gate(findings, "critical").fail).toBe(false);
    expect(gate([{ severity: "critical" }], "high").count).toBe(1);
    expect(() => gate(findings, "medium")).toThrow(/fail-on/);
  });
});
