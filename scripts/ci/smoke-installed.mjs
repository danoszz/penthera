#!/usr/bin/env node
/**
 * Smoke-test an *installed* Penthera the way users run it: `npx penthera …`
 * from a project that installed the package, not `node bin/penthera.js` from
 * this checkout. Used by .github/workflows/install-matrix.yml on Linux, macOS
 * and Windows.
 *
 *   node scripts/ci/smoke-installed.mjs --prefix <project> [--phase <name>]
 *        [--fixture tests/fixtures/init/app] [--work <dir>]
 *
 * --prefix   folder where `npm install <penthera tarball>` ran
 * --fixture  project to check (copied to --work first; never written to)
 * --work     where the fixture copy lives. Reused if it exists, so the
 *            upgrade phases see the same project (memory is keyed by path)
 * --phase    fresh (default)    the release checks
 *            upgrade-before     on the old release: a --memory scan, ui --demo
 *            upgrade-after      on the new package: old memory still verifies,
 *                               new scans append to it, nothing errors
 *
 * Every Penthera process runs under scripts/ci/net-guard.cjs: a connection or
 * DNS query to anything but loopback fails the check.
 */
import { spawn, spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync, appendFileSync, mkdtempSync } from "node:fs";
import { join, resolve, relative, dirname } from "node:path";
import { tmpdir } from "node:os";
import { parseArgs } from "node:util";
import { fileURLToPath } from "node:url";
import { mdCell } from "../../src/report/md-escape.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const WIN = process.platform === "win32";

const { values: args } = parseArgs({
  options: {
    prefix: { type: "string" },
    fixture: { type: "string", default: join(HERE, "..", "..", "tests", "fixtures", "init", "app") },
    work: { type: "string" },
    phase: { type: "string", default: "fresh" },
  },
});
if (!args.prefix) { console.error("--prefix <project with penthera installed> is required"); process.exit(2); }

const prefix = resolve(args.prefix);
const pkgDir = join(prefix, "node_modules", "penthera");
const installed = JSON.parse(readFileSync(join(pkgDir, "package.json"), "utf8"));
const work = resolve(args.work ?? mkdtempSync(join(tmpdir(), "penthera-smoke-")));
const guardLog = join(work, "..", `net-guard-${process.pid}.log`);

// ── Environment: offline, no colour, no npm chatter ─────────────────────────
const fwd = (p) => p.replace(/\\/g, "/"); // NODE_OPTIONS treats \ as an escape inside quotes
const env = {
  ...process.env,
  NO_COLOR: "1",
  NODE_OPTIONS: `${process.env.NODE_OPTIONS ?? ""} --require "${fwd(join(HERE, "net-guard.cjs"))}"`.trim(),
  PENTHERA_NET_GUARD_LOG: guardLog,
  npm_config_update_notifier: "false",
  npm_config_fund: "false",
  npm_config_audit: "false",
  NO_UPDATE_NOTIFIER: "1",
  GIT_TERMINAL_PROMPT: "0",
  GIT_AUTHOR_NAME: "Penthera CI", GIT_AUTHOR_EMAIL: "ci@example.com",
  GIT_COMMITTER_NAME: "Penthera CI", GIT_COMMITTER_EMAIL: "ci@example.com",
};

// ── Helpers ──────────────────────────────────────────────────────────────────
const ANSI = /\x1b\[[0-9;]*m/g;
const quote = (s) => /^[\w@%+=:,./\\-]+$/.test(s) ? s
  : WIN ? `"${s.replace(/"/g, '""')}"` : `'${s.replace(/'/g, "'\\''")}'`;
/** `npx --no-install penthera …` as a shell line; --prefix finds the install from any cwd. */
const npxLine = (argv) => ["npx", "--no-install", "--prefix", quote(prefix), "penthera", ...argv.map(quote)].join(" ");

const results = [];
let failed = 0;

function npx(argv, { cwd = work, input } = {}) {
  const r = spawnSync(npxLine(argv), { cwd, env, shell: true, encoding: "utf8", input, timeout: 300_000, maxBuffer: 64 * 1024 * 1024 });
  return { status: r.status, out: `${r.stdout ?? ""}${r.stderr ?? ""}`.replace(ANSI, "").replace(/\r\n/g, "\n"), error: r.error };
}

function git(argv, cwd = work) {
  const r = spawnSync("git", argv, { cwd, env, encoding: "utf8" });
  return { status: r.status, out: `${r.stdout}${r.stderr}` };
}

function record(name, ok, detail = "") {
  results.push({ name, ok, detail });
  if (!ok) failed++;
  console.log(`${ok ? "ok  " : "FAIL"}  ${name}${detail ? `  (${detail})` : ""}`);
}

/**
 * Run `npx penthera <argv>` and check the exit code and output lines.
 * @param {object} want  exit: number|number[]; has: (string|RegExp)[]; lacks: (string|RegExp)[]
 */
function check(name, argv, want, opts) {
  const r = npx(argv, opts);
  const exits = [want.exit ?? 0].flat();
  const problems = [];
  if (r.error) problems.push(`spawn: ${r.error.message}`);
  if (!exits.includes(r.status)) problems.push(`exit ${r.status}, want ${exits.join("|")}`);
  for (const h of want.has ?? []) {
    if (!(typeof h === "string" ? r.out.includes(h) : h.test(r.out))) problems.push(`missing ${h}`);
  }
  for (const h of want.lacks ?? []) {
    if (typeof h === "string" ? r.out.includes(h) : h.test(r.out)) problems.push(`unexpected ${h}`);
  }
  record(name, problems.length === 0, problems.join("; "));
  if (problems.length) console.log(r.out.split("\n").map((l) => `      | ${l}`).join("\n"));
  return r;
}

/** Files in the fixture copy (outside .git), with sizes, to prove a dry run wrote nothing. */
function snapshot(dir) {
  const out = [];
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      if (e.name === ".git") continue;
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else out.push(`${fwd(relative(dir, p))}:${statSync(p).size}`);
    }
  };
  walk(dir);
  return out.sort().join("\n");
}

function prepareWork() {
  if (existsSync(join(work, "package.json"))) return; // reused by a later phase
  mkdirSync(work, { recursive: true });
  cpSync(resolve(args.fixture), work, { recursive: true });
  // A committed git repo: init detects it, hook and deps --base spawn git.
  for (const a of [["init", "-q", "-b", "main"], ["add", "-A"], ["commit", "-q", "-m", "fixture", "--no-verify"]]) {
    const r = git(a);
    if (r.status !== 0) { console.error(`git ${a.join(" ")} failed:\n${r.out}`); process.exit(2); }
  }
}

/**
 * Start `penthera ui --demo`, poll /api/meta until it answers 401 (no session), stop it,
 * and check the port is closed again.
 */
/**
 * `stoppedLine: false` is for the published version the upgrade job starts
 * from: up to 1.8.0, a second SIGTERM forwarded by npx could kill penthera ui
 * before it printed "Stopped." (fixed in #84). Released code cannot change,
 * so for it the check still demands that the server stops and the port
 * closes, but not the line.
 */
async function checkUi(name, { stoppedLine = true } = {}) {
  const child = spawn(npxLine(["ui", "--demo"]), { cwd: prefix, env, shell: true, detached: !WIN, stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  child.stdout.on("data", (d) => { out += d; });
  child.stderr.on("data", (d) => { out += d; });
  // The shell exits as soon as the group gets SIGTERM, but penthera (a
  // grandchild via npx) writes "Stopped." a moment later. The pipes close only
  // when every process holding them is gone, so wait for those too.
  const closed = (s) => new Promise((r) => s.once("close", r));
  const exited = Promise.all([
    new Promise((r) => child.once("exit", (code, signal) => r({ code, signal }))),
    closed(child.stdout),
    closed(child.stderr),
  ]);
  const problems = [];
  let base = null;
  const deadline = Date.now() + 90_000;
  let status = null;
  while (Date.now() < deadline) {
    // 1.8 prints /#t=<token>; 1.7.0 (the upgrade job's "before") printed /?token=<token>.
    const m = out.replace(ANSI, "").match(/http:\/\/127\.0\.0\.1:(\d+)\/(?:#t|\?token)=\S+/);
    if (m) {
      base = `http://127.0.0.1:${m[1]}`;
      try {
        status = (await fetch(`${base}/api/meta`, { redirect: "manual" })).status;
        if (status === 401) break;
      } catch { /* not listening yet */ }
    }
    if (child.exitCode !== null) break;
    await new Promise((r) => setTimeout(r, 250));
  }
  if (!base) problems.push("no one-time URL printed");
  else if (status !== 401) problems.push(`GET /api/meta without a session answered ${status}, want 401`);

  // Stop it the way a user would (Ctrl-C / SIGTERM); Windows has no signals for
  // a console-less child, so end the process tree.
  if (WIN) spawnSync("taskkill", ["/pid", String(child.pid), "/T", "/F"], { stdio: "ignore" });
  else { try { process.kill(-child.pid, "SIGTERM"); } catch { /* already gone */ } }
  const timer = setTimeout(() => { problems.push("did not stop within 30 s"); try { WIN ? child.kill() : process.kill(-child.pid, "SIGKILL"); } catch { /* gone */ } }, 30_000);
  await exited;
  clearTimeout(timer);
  if (base) {
    // The penthera process (a grandchild via npx) must be gone, not orphaned.
    let stillUp = false;
    for (let i = 0; i < 40; i++) {
      try { await fetch(`${base}/`, { signal: AbortSignal.timeout(1000) }); stillUp = true; } catch { stillUp = false; break; }
      await new Promise((r) => setTimeout(r, 250));
    }
    if (stillUp) problems.push("server still answering after stop");
  }
  if (stoppedLine && !WIN && base && !/Stopped\./.test(out)) problems.push('no "Stopped." on SIGTERM');
  record(name, problems.length === 0, problems.join("; "));
  if (problems.length) console.log(out.split("\n").map((l) => `      | ${l}`).join("\n"));
}

// ── Phases ───────────────────────────────────────────────────────────────────
async function fresh() {
  const v = installed.version;
  check("--version", ["--version"], { has: [`penthera v${v}`] }, { cwd: prefix });
  check("--help", ["--help"], { has: ["Usage", "penthera deps [path]", "penthera agents [path]", "Exit codes"] }, { cwd: prefix });

  const before = snapshot(work);
  check("init --yes --dry-run", ["init", "--yes", "--dry-run"], {
    has: ["Dry run", "nothing is scanned, written or started", "lockfiles: package-lock.json",
      "agent config: .mcp.json, CLAUDE.md", "git repository (branch main)", "Would run",
      "would install .git/hooks/pre-commit", "would write .github/workflows/penthera.yml"],
    lacks: ["not a git repository", "Error"],
  });
  record("init --dry-run wrote nothing", snapshot(work) === before);

  check("deps", ["deps"], { has: [/Mode\s+deps/, /Packages\s+1 in package-lock\.json/] });
  check("deps --base HEAD (spawns git)", ["deps", "--base", "HEAD"], { exit: [0, 1], has: [/Mode\s+deps/], lacks: ["fatal:", "Error"] });
  check("agents", ["agents"], { has: [/Mode\s+agents/, /Grade\s+\S/, 'MCP server "filesystem" runs an unpinned package via npx'] });
  check("--repo .", ["--repo", "."], { has: [/Mode\s+repo/, /Checked\s+secrets/, "Not checked"] });

  // Pre-commit hook: written into .git/hooks, then run by git itself. On
  // Windows this is Git for Windows' sh running node.exe by absolute path.
  check("hook install", ["hook", "install"], { has: ["pre-commit"] });
  const key = ["sk", "ant", "api03", "Q".repeat(40)].join("-"); // built at runtime, never in the repo
  writeFileSync(join(work, "leak.js"), `export const key = "${key}";\n`);
  git(["add", "leak.js"]);
  const blocked = git(["commit", "-m", "leak"]);
  record("hook blocks a staged secret on git commit", blocked.status !== 0 && /blocked this commit/.test(blocked.out),
    blocked.status === 0 ? "commit went through" : "");
  if (blocked.status === 0 || !/blocked this commit/.test(blocked.out)) console.log(blocked.out);
  git(["rm", "-q", "--cached", "leak.js"]);
  rmSync(join(work, "leak.js"));
  writeFileSync(join(work, "clean.js"), "export const key = process.env.API_KEY;\n");
  git(["add", "clean.js"]);
  const clean = git(["commit", "-q", "-m", "clean"]);
  record("hook lets a clean commit through", clean.status === 0, clean.status === 0 ? "" : clean.out.trim().slice(0, 300));
  check("hook uninstall", ["hook", "uninstall"], {});

  await checkUi("ui --demo answers 401 on / and stops");

  for (const pack of ["core", "ioc-2025-2026"]) {
    check(`rules verify ${pack} (bundled)`, ["rules", "verify", join(pkgDir, "lib", "rules", pack)], {
      has: [/signature\s+valid, signed by /, /files\s+all SHA-256 hashes match/, "OK"],
    }, { cwd: prefix });
  }
  check("rules list", ["rules", "list"], { has: [/core@\S+\s+bundled/, /ioc-2025-2026@\S+\s+bundled/] }, { cwd: prefix });
}

const CHAIN_OK = /OK\s+(\d+) event\(s\), chain intact/;

async function upgradeBefore() {
  check(`--version (old ${installed.version})`, ["--version"], { has: [`penthera v${installed.version}`] }, { cwd: prefix });
  check("--repo . --memory (old)", ["--repo", ".", "--memory"], { has: [/Mode\s+repo/] });
  check("memory verify (old)", ["memory", "verify", "--repo", "."], { has: [CHAIN_OK] });
  await checkUi("ui --demo (old)", { stoppedLine: false });
}

async function upgradeAfter() {
  check(`--version (new ${installed.version})`, ["--version"], { has: [`penthera v${installed.version}`] }, { cwd: prefix });
  const events = (r) => Number(r.out.match(CHAIN_OK)?.[1] ?? NaN);
  const old = check("memory verify (old state, new code)", ["memory", "verify", "--repo", "."], { has: [CHAIN_OK] });
  check("memory show (old state)", ["memory", "show", "--repo", "."], { has: [/Chain\s+ok/, /Scans\s+[1-9]/] });
  check("--repo . --memory (appends to the old chain)", ["--repo", ".", "--memory"], { has: [/Mode\s+repo/] });
  const now = check("memory verify (after append)", ["memory", "verify", "--repo", "."], { has: [CHAIN_OK] });
  record("new scan appended to the old chain", events(now) > events(old), `${events(old)} -> ${events(now)} events`);
  check("deps (new)", ["deps"], { has: [/Mode\s+deps/] });
  check("agents (new)", ["agents"], { has: [/Mode\s+agents/] });
  await checkUi("ui --demo (new, old ~/.penthera)");
}

// ── Main ─────────────────────────────────────────────────────────────────────
prepareWork();
console.log(`penthera ${installed.version} from ${pkgDir}\nfixture copy: ${work}\nphase: ${args.phase} on ${process.platform} node ${process.version}\n`);
// Line endings as the checkout produced them (CRLF on Windows with autocrlf):
// the CLI must read CRLF lockfiles and agent config the same as LF.
const lock = readFileSync(join(work, "package-lock.json"), "utf8");
console.log(`fixture line endings: ${lock.includes("\r\n") ? "CRLF" : "LF"}\n`);
const phases = { fresh, "upgrade-before": upgradeBefore, "upgrade-after": upgradeAfter };
if (!phases[args.phase]) { console.error(`unknown --phase ${args.phase}`); process.exit(2); }
await phases[args.phase]();

const blockedNet = existsSync(guardLog) ? readFileSync(guardLog, "utf8").trim() : "";
record("no network beyond loopback", !blockedNet, blockedNet ? blockedNet.split("\n").length + " blocked attempt(s)" : "");
if (blockedNet) console.log(blockedNet);

if (process.env.GITHUB_STEP_SUMMARY) {
  const title = `${args.phase} · ${process.platform} · node ${process.version} · penthera ${installed.version}`;
  appendFileSync(process.env.GITHUB_STEP_SUMMARY, `### ${title}\n\n| | check | detail |\n|---|---|---|\n${
    results.map((r) => `| ${r.ok ? "✅" : "❌"} | \`${r.name}\` | ${mdCell(r.detail)} |`).join("\n")}\n\n`);
}
console.log(`\n${results.length - failed}/${results.length} checks passed`);
process.exit(failed ? 1 : 0);
