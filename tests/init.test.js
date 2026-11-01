/**
 * `penthera init`: the setup wizard, driven with scripted stdin on a copy of
 * tests/fixtures/init/app (an Express app with a lockfile and agent config).
 */
import { describe, it, expect, beforeEach, afterEach, beforeAll, afterAll } from "vitest";
import { cpSync, existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync, symlinkSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { execFileSync, spawn } from "node:child_process";
import { startMockServer } from "./fixtures/mock-server.js";
import { parseToggles } from "../src/cli/prompt.js";
import { detectProjectFramework } from "../lib/whitebox/frameworks.js";
import { detectProject, portsFromEnv, DEV_PORTS } from "../src/cli/detect.js";
import { ACTION_PIN, WORKFLOW_PATH, AGENTS_WORKFLOW_PATH, workflowYaml, agentsWorkflowYaml, checkItems, fixFirst, writeNewFile } from "../src/cli/onboarding.js";
import { HOOK_MARKER } from "../lib/hook/index.js";

const BIN = join(import.meta.dirname, "..", "bin", "penthera.js");
const FIXTURE = join(import.meta.dirname, "fixtures", "init", "app");

let dir, home, mock, requests;
const children = new Set();

const git = (...args) => execFileSync("git", args, { cwd: dir, encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"], env: gitEnv() }).trim();
const gitEnv = () => ({ ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1" });

/** Run the CLI in the fixture copy with `answers` piped to stdin. Async: the mock server shares this process. */
function wizard(args, answers = []) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [BIN, ...args], {
      cwd: dir,
      env: { ...gitEnv(), NO_COLOR: "1", HOME: home, PENTHERA_HOME: join(home, ".penthera"), PENTHERA_INIT_PORTS: String(mock.port) },
      stdio: ["pipe", "pipe", "pipe"],
    });
    children.add(child);
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => { stdout += d; });
    child.stderr.on("data", (d) => { stderr += d; });
    child.on("close", (code) => { children.delete(child); resolve({ code, stdout, stderr }); });
    child.stdin.end(answers.length ? answers.join("\n") + "\n" : "");
  });
}

const reportDirs = () => (existsSync(join(dir, "reports")) ? readdirSync(join(dir, "reports")) : []);
const summary = () => JSON.parse(readFileSync(join(dir, "reports", reportDirs()[0], "summary.json"), "utf-8"));
const hookPath = () => join(dir, ".git", "hooks", "pre-commit");

beforeAll(async () => {
  mock = await startMockServer(0);
  mock.server.on("request", () => { requests++; });
});
afterAll(() => mock.close());

beforeEach(() => {
  requests = 0;
  dir = realpathSync(mkdtempSync(join(tmpdir(), "penthera-init-")));
  home = join(dir, "..", `${dir.split("/").pop()}-home`);
  mkdirSync(home);
  cpSync(FIXTURE, dir, { recursive: true });
  git("init", "-q", "-b", "main");
  git("add", "-A");
  git("-c", "user.name=t", "-c", "user.email=t@localhost", "commit", "-qm", "fixture");
});
afterEach(() => {
  // A wizard still running here means the test failed or timed out: don't leave it behind.
  for (const child of children) child.kill("SIGKILL");
  children.clear();
  rmSync(dir, { recursive: true, force: true });
  rmSync(home, { recursive: true, force: true });
});

describe("penthera init (scripted stdin)", () => {
  it("detects the project, runs the default checks and writes the hook, workflow and .gitignore", async () => {
    const r = await wizard(["init"], [
      "",  // checklist: accept code, deps, AI tooling, offline
      "",  // ~/.claude and ~/.cursor: default no
      "",  // pre-commit hook: default yes
      "",  // workflow: default yes
      "",  // agent config workflow: default yes
      "",  // .gitignore: default yes
      "",  // fix loop: default no
      "n", // dashboard
    ]);
    expect(r.code, r.stderr).toBe(0);

    // Detected
    expect(r.stdout).toContain("git repository (branch main)");
    expect(r.stdout).toContain("framework: Express");
    expect(r.stdout).toContain("lockfiles: package-lock.json");
    expect(r.stdout).toContain("agent config: .mcp.json, CLAUDE.md");
    expect(r.stdout).toContain(`dev server: http://localhost:${mock.port}`);
    expect(r.stdout).toContain("no Penthera pre-commit hook");

    // Checks run: the three defaults, offline; never the running app
    expect(r.stdout).toMatch(/✓ Code\s+[A-F]/);
    // The fixture has no node_modules: nothing read is "not checked", never an A.
    expect(r.stdout).toMatch(/! Dependencies\s+–\s+not checked: 0 of \d+ packages installed or cached/);
    expect(r.stdout).toContain("npm ci --ignore-scripts");
    expect(r.stdout).toMatch(/✓ AI tooling\s+[A-F]/);
    expect(r.stdout).not.toMatch(/Running app\s+[A-F]/);
    expect(requests).toBe(0);
    const s = summary();
    expect(s.offline).toBe(true);
    expect(s.checks.map((c) => c.id)).toEqual(["code", "deps", "agents"]);
    expect(s.checks.filter((c) => c.id !== "deps").every((c) => /^[A-F]$/.test(c.grade))).toBe(true);
    expect(s.checks.find((c) => c.id === "deps")).toMatchObject({ grade: "–", score: null, notRead: { packages: expect.any(Number) } });
    expect(s.fixFirst.length).toBeGreaterThan(0);
    expect(s.fixFirst.length).toBeLessThanOrEqual(3);
    const rd = join(dir, "reports", reportDirs()[0]);
    expect(reportDirs()[0]).toMatch(/^penthera-\d{4}-\d{2}-\d{2}$/);
    for (const f of ["code.json", "code.md", "deps.json", "deps.md", "agents.json", "agents.md", "summary.md"]) {
      expect(existsSync(join(rd, f)), f).toBe(true);
    }
    expect(r.stdout).toContain("Fix first");
    expect(r.stdout).toMatch(/Report\s+reports\/penthera-\d{4}-\d{2}-\d{2}\/summary\.md/);

    // Files written
    expect(readFileSync(hookPath(), "utf-8")).toContain(HOOK_MARKER);
    const wf = readFileSync(join(dir, WORKFLOW_PATH), "utf-8");
    expect(wf).toContain(`danoszz/penthera@${ACTION_PIN.sha} # ${ACTION_PIN.tag}`);
    expect(r.stdout).toContain(`+++ b/${WORKFLOW_PATH}`); // shown as a diff first
    const awf = readFileSync(join(dir, AGENTS_WORKFLOW_PATH), "utf-8");
    expect(awf).toContain(`npx --yes penthera@${ACTION_PIN.tag.slice(1)} agents`);
    expect(r.stdout).toContain(`+++ b/${AGENTS_WORKFLOW_PATH}`);
    expect(readFileSync(join(dir, ".gitignore"), "utf-8")).toMatch(/^reports\/$/m);
    expect(git("check-ignore", "reports/x.json")).toBe("reports/x.json");

    // Nothing committed, no fix branch
    expect(git("rev-list", "--count", "HEAD")).toBe("1");
    expect(git("branch", "--list", "penthera/*")).toBe("");
    expect(git("diff", "--cached", "--name-only")).toBe("");

    // What next
    expect(r.stdout).toContain("What next");
    expect(r.stdout).toContain("penthera agent --loop");
  });

  it("runs nothing and writes nothing when every step is declined", async () => {
    const r = await wizard(["init"], [
      "1,2,3,4", // untoggle code, deps, AI tooling; toggle the running app on
      "",        // is it your app? default no
      "n",       // hook
      "n",       // workflow
      "n",       // agent config workflow
      "n",       // .gitignore
      "n",       // dashboard (no fix loop question: code was not selected)
    ]);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toContain("Skipping the app check.");
    expect(r.stdout).toContain("Nothing selected to check.");
    expect(requests).toBe(0);
    expect(existsSync(join(dir, "reports"))).toBe(false);
    expect(existsSync(hookPath())).toBe(false);
    expect(existsSync(join(dir, WORKFLOW_PATH))).toBe(false);
    expect(existsSync(join(dir, AGENTS_WORKFLOW_PATH))).toBe(false);
    expect(existsSync(join(dir, ".gitignore"))).toBe(false);
    expect(git("status", "--porcelain")).toBe("");
  });

  it("scans the running app only after the user confirms they own it", async () => {
    const r = await wizard(["init"], [
      "1,2,3,4", // only the running app
      "y",       // it is mine
      "n", "n", "n", "n", "n",
    ]);
    expect(r.code, r.stderr).toBe(0);
    expect(requests).toBeGreaterThan(0);
    expect(r.stdout).toMatch(/✓ Running app\s+[A-F]/);
    expect(summary().checks.map((c) => c.id)).toEqual(["app"]);
    expect(r.stdout).toContain(`penthera http://localhost:${mock.port} --offline`);
  });

  it("does not start the dashboard when piped answers run out", async () => {
    // Before: the dashboard defaulted to yes, so exhausted stdin started
    // `penthera ui --open`, which runs until Ctrl-C, and init never exited.
    const r = await wizard(["init"], ["1,2,3"]); // nothing to check, then every later prompt gets EOF
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toMatch(/Open the dashboard \(penthera ui --open\)\? \[y\/N\]/);
  });

  it("re-prompts on a bad checklist answer instead of guessing", async () => {
    const r = await wizard(["init"], ["9", "1,2,3", "n", "n", "n", "n", "n"]);
    expect(r.stdout).toContain("Type item numbers from 1 to 5");
    expect(r.stdout).toContain("Nothing selected to check.");
    expect(existsSync(join(dir, "reports"))).toBe(false);
  });
});

describe("penthera init --yes (smoke)", () => {
  it("accepts the safe defaults: checks, hook, workflow, .gitignore; never the URL, fix loop or dashboard", async () => {
    const r = await wizard(["init", "--yes"]);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).not.toContain("[Y/n]");
    expect(requests).toBe(0);
    expect(summary().checks.map((c) => c.id)).toEqual(["code", "deps", "agents"]);
    expect(readFileSync(hookPath(), "utf-8")).toContain(HOOK_MARKER);
    expect(existsSync(join(dir, WORKFLOW_PATH))).toBe(true);
    expect(existsSync(join(dir, AGENTS_WORKFLOW_PATH))).toBe(true);
    expect(readFileSync(join(dir, ".gitignore"), "utf-8")).toContain("reports/");
    expect(r.stdout).toContain("Fix loop: not run with --yes");
    expect(r.stdout).toContain("Dashboard: not opened with --yes");
    expect(git("branch", "--list", "penthera/*")).toBe("");
    expect(git("rev-list", "--count", "HEAD")).toBe("1");
  });

  it("bare `penthera --yes` runs the same wizard", async () => {
    const r = await wizard(["--yes", "--dry-run"]);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toContain("Would run");
  });

  it("--dry-run --yes prints the plan and changes nothing", async () => {
    const r = await wizard(["init", "--yes", "--dry-run"]);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toContain("Dry run");
    expect(r.stdout).toContain("penthera --repo . --offline");
    expect(r.stdout).toContain("would install .git/hooks/pre-commit");
    expect(r.stdout).toContain(`would write ${WORKFLOW_PATH}`);
    expect(r.stdout).toContain(`would write ${AGENTS_WORKFLOW_PATH}`);
    expect(r.stdout).toContain("would add reports/ to .gitignore");
    expect(requests).toBe(0);
    expect(existsSync(join(dir, "reports"))).toBe(false);
    expect(existsSync(hookPath())).toBe(false);
    expect(existsSync(join(dir, WORKFLOW_PATH))).toBe(false);
    expect(git("status", "--porcelain")).toBe("");
  });

  it("skips the hook and workflow outside a git repository", async () => {
    rmSync(join(dir, ".git"), { recursive: true, force: true });
    const r = await wizard(["init", "--yes", "--dry-run"]);
    expect(r.code, r.stderr).toBe(0);
    expect(r.stdout).toContain("not a git repository");
    expect(r.stdout).toContain("Pre-commit hook: not a git repository");
    expect(r.stdout).toContain("GitHub workflow: not a git repository");
    expect(r.stdout).toContain("Agent config workflow: not a git repository");
  });

  it("never writes through a dangling symlink at a workflow path or .gitignore", async () => {
    const elsewhere = join(home, "elsewhere");
    mkdirSync(join(dir, ".github", "workflows"), { recursive: true });
    symlinkSync(join(elsewhere, "agents.yml"), join(dir, AGENTS_WORKFLOW_PATH));
    symlinkSync(join(elsewhere, "deps.yml"), join(dir, WORKFLOW_PATH));
    rmSync(join(dir, ".gitignore"), { force: true });
    symlinkSync(join(elsewhere, "gitignore"), join(dir, ".gitignore"));
    const r = await wizard(["init", "--yes"]);
    expect(r.code, r.stderr).toBe(0);
    expect(existsSync(elsewhere)).toBe(false);
    expect(r.stdout).toContain(`${AGENTS_WORKFLOW_PATH} exists, left as is`);
    expect(r.stdout).toContain(".gitignore: it is a symlink, left as is");
  });

  it("rejects unknown flags", async () => {
    const r = await wizard(["init", "--push"]);
    expect(r.code).toBe(2);
  });
});

describe("init building blocks", () => {
  it("writeNewFile refuses an existing entry, a dangling symlink and a folder outside the project", () => {
    const outside = realpathSync(mkdtempSync(join(tmpdir(), "penthera-init-out-")));
    try {
      expect(writeNewFile(dir, join(dir, "new.yml"), "a")).toBeNull();
      expect(readFileSync(join(dir, "new.yml"), "utf-8")).toBe("a");
      expect(writeNewFile(dir, join(dir, "new.yml"), "b")).toMatch(/already there/);
      symlinkSync(join(outside, "target.yml"), join(dir, "dangling.yml"));
      expect(writeNewFile(dir, join(dir, "dangling.yml"), "c")).toMatch(/already there/);
      expect(existsSync(join(outside, "target.yml"))).toBe(false);
      mkdirSync(join(dir, ".github"), { recursive: true });
      symlinkSync(outside, join(dir, ".github", "workflows"));
      expect(writeNewFile(dir, join(dir, ".github", "workflows", "x.yml"), "d")).toMatch(/outside the project/);
      expect(readdirSync(outside)).toEqual([]);
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it("writeNewFile creates no folder outside the project before it refuses", () => {
    const outside = realpathSync(mkdtempSync(join(tmpdir(), "penthera-init-out-")));
    const proj = realpathSync(mkdtempSync(join(tmpdir(), "penthera-init-proj-")));
    try {
      symlinkSync(outside, join(proj, ".github"));
      expect(writeNewFile(proj, join(proj, ".github", "workflows", "x.yml"), "d")).toMatch(/outside the project/);
      expect(readdirSync(outside)).toEqual([]);
      symlinkSync(join(outside, "missing"), join(proj, "dangling"));
      expect(writeNewFile(proj, join(proj, "dangling", "sub", "x.yml"), "d")).toMatch(/outside the project/);
      expect(readdirSync(outside)).toEqual([]);
      expect(writeNewFile(proj, join(proj, "a", "b", "x.yml"), "ok")).toBeNull();
      expect(readFileSync(join(proj, "a", "b", "x.yml"), "utf-8")).toBe("ok");
    } finally {
      rmSync(outside, { recursive: true, force: true });
      rmSync(proj, { recursive: true, force: true });
    }
  });

  it("parseToggles keeps defaults on Enter and rejects out-of-range numbers", () => {
    expect(parseToggles("", 4)).toEqual([]);
    expect(parseToggles("2, 4", 4)).toEqual([1, 3]);
    expect(parseToggles("1 1", 4)).toEqual([0]);
    expect(parseToggles("5", 4)).toBe(null);
    expect(parseToggles("yes", 4)).toBe(null);
  });

  it("detectProjectFramework reads manifests, offline", () => {
    expect(detectProjectFramework(FIXTURE)).toBe("Express");
    expect(detectProjectFramework(join(import.meta.dirname, "fixtures", "agents", "clean"))).toBe(null);
  });

  it("checkItems: defaults follow what was found, the app is never preselected", () => {
    const found = { code: true, git: true, lockfiles: { npm: [], python: ["uv.lock"] }, agentConfig: [], devServer: "http://localhost:5173" };
    const byId = Object.fromEntries(checkItems(found).map((i) => [i.id, i.checked]));
    expect(byId).toEqual({ code: true, deps: true, agents: false, app: false, offline: true });
    expect(checkItems({ ...found, devServer: null }).some((i) => i.id === "app")).toBe(false);
  });

  it("detectProject probes only the ports it is given", async () => {
    const f = await detectProject(FIXTURE, { ports: [mock.port] });
    expect(f.devServer).toBe(`http://localhost:${mock.port}`);
    expect((await detectProject(FIXTURE, { ports: [] })).devServer).toBe(null);
    expect(portsFromEnv({})).toEqual(DEV_PORTS);
    expect(portsFromEnv({ PENTHERA_INIT_PORTS: "" })).toEqual([]);
  });

  it("workflowYaml pins the action to a full commit SHA and keeps the example's steps", () => {
    expect(ACTION_PIN.sha).toMatch(/^[0-9a-f]{40}$/);
    expect(ACTION_PIN.tag).toMatch(/^v\d+\.\d+\.\d+$/);
    const yaml = workflowYaml();
    const example = readFileSync(join(import.meta.dirname, "..", "docs", "examples", "pr-dependency-review.yml"), "utf-8");
    expect(yaml).not.toContain("0".repeat(40));
    for (const line of example.split("\n").filter((l) => /^\s+- uses: actions\//.test(l) || /mode: deps/.test(l))) {
      expect(yaml).toContain(line);
    }
    for (const u of yaml.match(/uses: \S+/g)) expect(u).toMatch(/@[0-9a-f]{40}$/);
  });

  it("agentsWorkflowYaml pins npx to ACTION_PIN's version and keeps the example's SHA-pinned steps", () => {
    const yaml = agentsWorkflowYaml({ tag: "v9.8.7", sha: "a".repeat(40) });
    expect(yaml).toContain('npx --yes penthera@9.8.7 agents "$GITHUB_WORKSPACE" --sarif');
    expect(yaml).not.toMatch(/penthera@(?!9\.8\.7)\d+\.\d+\.\d+/);
    expect(yaml).toContain("persist-credentials: false");
    for (const u of yaml.match(/uses: \S+/g)) expect(u).toMatch(/@[0-9a-f]{40}$/);
    expect(agentsWorkflowYaml()).toContain(`penthera@${ACTION_PIN.tag.slice(1)} agents`);
  });

  it("ACTION_PIN is the newest stable release before this version, so it never falls behind", () => {
    const root = join(import.meta.dirname, "..");
    const { version } = JSON.parse(readFileSync(join(root, "package.json"), "utf-8"));
    const num = (v) => v.replace(/-.*/, "").split(".").map(Number);
    const older = (a, b) => { const [x, y] = [num(a), num(b)]; const i = x.findIndex((n, k) => n !== y[k]); return i >= 0 && x[i] < y[i]; };
    // Stable releases only (no -rc), newest first as CHANGELOG.md lists them.
    const released = [...readFileSync(join(root, "CHANGELOG.md"), "utf-8").matchAll(/^## \[(\d+\.\d+\.\d+)\]/gm)].map((m) => m[1]);
    const expected = released.find((v) => older(v, version));
    expect(ACTION_PIN.tag, `update ACTION_PIN in src/cli/onboarding.js to v${expected}`).toBe(`v${expected}`);
    // With the tag fetched (CI checks out full history), the SHA must be that tag's commit.
    let sha = null;
    try { sha = execFileSync("git", ["rev-parse", "--verify", "-q", `${ACTION_PIN.tag}^{commit}`], { cwd: root, encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"], env: gitEnv() }).trim(); } catch { /* tag not fetched */ }
    if (sha) expect(ACTION_PIN.sha).toBe(sha);
  });

  it("fixFirst ranks across areas by severity, then effort, and keeps three", () => {
    const plan = (severity, effort, action) => ({ severity, effort, action, why: `${action}. More.`, findings: [{}] });
    const top = fixFirst([
      { label: "Code", merged: { actionPlan: [plan("medium", "quick", "m"), plan("high", "moderate", "h2")] } },
      { label: "AI tooling", merged: { actionPlan: [plan("high", "quick", "h1"), plan("low", "quick", "l")] } },
      { label: "Dependencies", error: "boom" },
    ]);
    expect(top.map((a) => a.action)).toEqual(["h1", "h2", "m"]);
    expect(top[0]).toMatchObject({ area: "AI tooling", why: "h1." });
  });
});

describe("the fix loop hint", () => {
  it("says a repo with no commit needs one first", () => {
    const dir = mkdtempSync(join(tmpdir(), "penthera-init-hint-"));
    execFileSync("git", ["init", "-q", "-b", "main"], { cwd: dir });
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "x", version: "1.0.0" }));
    const out = execFileSync(process.execPath, [resolve("bin/penthera.js"), "init", "--yes"], { cwd: dir, encoding: "utf-8", env: { ...process.env, NO_COLOR: "1", PENTHERA_HOME: join(dir, ".h") } });
    rmSync(dir, { recursive: true, force: true });
    expect(out).toMatch(/after a first commit: fix findings/);
  }, 30_000);
});
