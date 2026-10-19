#!/usr/bin/env node
/**
 * Penthera internal testing audit: the release gate.
 *
 *   npm run audit:internal                      run every gate, write audit/REPORT.md
 *   npm run audit:internal -- --with-docker     also scan OWASP Juice Shop (and crAPI if running)
 *   npm run audit:internal -- --only bench,versions   run some gates; prints, writes nothing
 *   npm run audit:internal -- --update-baseline rewrite audit/baseline.json from this run's
 *                                               self-scan (new entries need a reason)
 *   npm run audit:internal -- --no-write        print results, leave audit/ alone
 *
 * Exits 1 when any gate fails, 0 otherwise. See docs/internal-audit.md.
 *
 * Every scan here targets this repo or a server on 127.0.0.1. The only network
 * use is `npm audit` (the npm registry) and, with --with-docker, pulling the
 * Juice Shop image.
 */
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";
import { startMockServer } from "../../tests/fixtures/mock-server.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const AUDIT_DIR = join(ROOT, "audit");
const REPORT_PATH = join(AUDIT_DIR, "REPORT.md");
const BASELINE_PATH = join(AUDIT_DIR, "baseline.json");
const LOG_DIR = join(AUDIT_DIR, "logs");
const CLI = join(ROOT, "bin/penthera.js");
const PKG = readJson(join(ROOT, "package.json"));

// ── Thresholds ───────────────────────────────────────────────────────────

/** Largest allowed drop in total precision or recall versus bench/RESULTS.md. */
const BENCH_MAX_DROP = 0.02;

/** Package budget (current 1.2.0: ~475 KB packed, ~1.3 MB unpacked, 138 files). */
// Raised for the dashboard (src/ui: ~245 KB unpacked, ~40 KB packed, 22 small files, no
// dependencies): was 650_000 packed / 1_800_000 unpacked / 200 files. The headroom above
// today's size stays about the same.
const PACK_BUDGET = { packedBytes: 720_000, unpackedBytes: 2_050_000, files: 230 };

/** Paths the npm package may contain. Anything else fails the packaging gate. */
const PACK_ALLOW = [
  /^bin\/[^/]+\.js$/,
  /^src\//,
  /^lib\//,
  /^skills\/penthera\//,
  /^docs\//,
  /^(package\.json|README\.md|CHANGELOG\.md|LICENSE|SECURITY\.md|pentest\.config\.example\.js)$/,
];

/** Paths the npm package must never contain, even inside an allowed folder. */
const PACK_DENY = [
  /(^|\/)tests?\//,
  /(^|\/)__tests__\//,
  /(^|\/)fixtures?\//,
  /(^|\/)reports\//, // scan output (src/report/ is code and is fine)
  /^report[^/]*\.(json|md|sarif)$/,
  /(^|\/)(bench|audit|coverage)\//,
  /\.test\.[cm]?[jt]s$/,
  /(^|\/)\.env(\.|$)/,
  /\.(pem|key|p12|pfx|tgz|sarif)$/,
  /(^|\/)id_(rsa|ecdsa|ed25519)/,
  /(^|\/)\.npmrc$/,
  /(^|\/)pentest\.config\.js$/,
  /(^|\/)penthera\.lock$/,
];

/** Docker targets for --with-docker. Pin JUICE_SHOP_IMAGE to a digest for reproducible runs. */
const JUICE_SHOP_IMAGE = process.env.JUICE_SHOP_IMAGE || "bkimminich/juice-shop:latest";
const JUICE_SHOP_PORT = Number(process.env.JUICE_SHOP_PORT || 3300);
const CRAPI_URL = process.env.CRAPI_URL || "http://127.0.0.1:8888";

const SEVERE = new Set(["critical", "high"]);

// ── Helpers ──────────────────────────────────────────────────────────────

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf-8"));
}

let logSeq = 0;

/**
 * Run a command asynchronously (in-process servers keep serving meanwhile).
 * Output is captured and also written to audit/logs/ for the CI artifact.
 */
function run(cmd, args, { env = {}, timeout = 600_000, input = null, cwd = ROOT, log = true } = {}) {
  return new Promise((resolvePromise) => {
    const started = Date.now();
    const child = spawn(cmd, args, {
      cwd,
      env: { ...process.env, NO_COLOR: "1", FORCE_COLOR: "0", ...env },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => { stdout += d; });
    child.stderr.on("data", (d) => { stderr += d; });
    const timer = setTimeout(() => child.kill("SIGKILL"), timeout);
    child.on("error", (err) => { stderr += String(err); });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      const ms = Date.now() - started;
      if (log && !OPTS.noWrite) {
        mkdirSync(LOG_DIR, { recursive: true });
        const words = (cmd === process.execPath && args[0] === CLI ? ["penthera", ...args.slice(1)] : [cmd, ...args])
          .map((w) => (w.includes("/") ? w.split("/").pop() : w));
        const name = `${String(++logSeq).padStart(2, "0")}-${words.join(" ").replace(/[^\w.-]+/g, "_").slice(0, 80)}.log`;
        writeFileSync(join(LOG_DIR, name), `$ ${cmd} ${args.join(" ")}\n# exit ${code ?? signal} in ${ms} ms\n\n${stdout}\n--- stderr ---\n${stderr}`);
      }
      resolvePromise({ code: code ?? (signal ? 124 : 1), signal, stdout, stderr, ms });
    });
    if (input != null) child.stdin.end(input);
    else child.stdin.end();
  });
}

const penthera = (args, opts) => run(process.execPath, [CLI, ...args], opts);

function scratch(name) {
  return mkdtempSync(join(tmpdir(), `penthera-audit-${name}-`));
}

const fmt = (x) => (x == null ? "n/a" : typeof x === "number" && !Number.isInteger(x) ? x.toFixed(3) : String(x));

/** A stable identity for a finding: no timestamps, no ordering. */
function fingerprint(f) {
  const loc = f.url || f.file || f.path || "";
  const key = [f.source || f.method || "", f.title || "", loc, f.description || ""].join("|");
  return createHash("sha256").update(key).digest("hex").slice(0, 16);
}

function severeFindings(report) {
  return (report.findings || [])
    .filter((f) => SEVERE.has(f.severity))
    .map((f) => ({ fingerprint: fingerprint(f), severity: f.severity, title: f.title, location: f.url || f.file || f.path || "" }));
}

// ── Gates ────────────────────────────────────────────────────────────────
// Each gate returns { status: "pass" | "fail" | "skip", metrics, notes[] }.

/** 1. The test suite, with the live suites pointed at the mock server. */
async function gateTests() {
  const mock = await startMockServer(0);
  const dir = scratch("tests");
  const out = join(dir, "vitest.json");
  try {
    const r = await run("npm", ["test", "--", "--reporter=json", `--outputFile.json=${out}`], {
      env: { PENTEST_BASE_URL: mock.url },
      timeout: 900_000,
    });
    const metrics = { exitCode: r.code, seconds: Math.round(r.ms / 1000) };
    const notes = [`Live suites ran against the mock server (PENTEST_BASE_URL=${mock.url}).`];
    if (existsSync(out)) {
      const v = readJson(out);
      Object.assign(metrics, {
        total: v.numTotalTests,
        passed: v.numPassedTests,
        failed: v.numFailedTests,
        skipped: v.numPendingTests + (v.numTodoTests || 0),
        files: (v.testResults || []).length,
      });
      for (const file of v.testResults || []) {
        for (const t of file.assertionResults || []) {
          if (t.status === "failed") notes.push(`FAILED: ${relative(ROOT, file.name)} > ${t.fullName}`);
        }
      }
    } else {
      notes.push("vitest wrote no JSON report; see audit/logs.");
    }
    return { status: r.code === 0 && !metrics.failed ? "pass" : "fail", metrics, notes };
  } finally {
    await mock.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Parse the **Total** row of a bench/RESULTS.md. */
export function parseBenchTotals(markdown) {
  const row = markdown.split("\n").find((l) => l.startsWith("| **Total**"));
  if (!row) return null;
  const cells = row.split("|").map((c) => c.replace(/\*/g, "").trim());
  // | Total | | TP | FP | FN | Precision | Recall | F1 |
  const num = (s) => (s === "n/a" || s === "" ? null : Number(s));
  return { tp: num(cells[3]), fp: num(cells[4]), fn: num(cells[5]), precision: num(cells[6]), recall: num(cells[7]), f1: num(cells[8]) };
}

/** 2. The accuracy benchmark, compared with the committed bench/RESULTS.md. */
async function gateBench() {
  const recorded = parseBenchTotals(readFileSync(join(ROOT, "bench/RESULTS.md"), "utf-8"));
  const dir = scratch("bench");
  const out = join(dir, "bench.json");
  try {
    // Same as `npm run bench`, but leaves the committed RESULTS.md untouched.
    const r = await run("npm", ["run", "bench", "--", "--no-write", "--json", out], { timeout: 900_000 });
    if (!existsSync(out)) return { status: "fail", metrics: { exitCode: r.code }, notes: ["The benchmark produced no JSON; see audit/logs."] };
    const b = readJson(out);
    const t = b.total;
    const metrics = {
      tp: t.tp, fp: t.fp, fn: t.fn,
      precision: t.precision, recall: t.recall, f1: t.f1,
      recordedPrecision: recorded?.precision ?? null,
      recordedRecall: recorded?.recall ?? null,
      nonLoopbackRequests: b.blocked.length,
    };
    const notes = [];
    let ok = r.code === 0 && b.blocked.length === 0;
    if (b.blocked.length) notes.push(`Requests to non-loopback hosts: ${b.blocked.join(", ")}`);
    if (!recorded) {
      ok = false;
      notes.push("Could not read the Total row of bench/RESULTS.md.");
    } else {
      for (const k of ["precision", "recall"]) {
        const drop = (recorded[k] ?? 0) - (t[k] ?? 0);
        if (drop > BENCH_MAX_DROP + 1e-9) {
          ok = false;
          notes.push(`${k} dropped by ${drop.toFixed(3)} (${fmt(recorded[k])} → ${fmt(t[k])}); the limit is ${BENCH_MAX_DROP}.`);
        }
      }
      if (t.tp !== recorded.tp || t.fp !== recorded.fp || t.fn !== recorded.fn) {
        notes.push(`Counts differ from RESULTS.md (TP/FP/FN ${recorded.tp}/${recorded.fp}/${recorded.fn} → ${t.tp}/${t.fp}/${t.fn}). Run \`npm run bench\` and commit RESULTS.md if this is intended.`);
      }
    }
    return { status: ok ? "pass" : "fail", metrics, notes };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** True when the CLI dispatches a `hook` subcommand (the v1.5.0 pre-commit hook). */
function hookPresent() {
  return /argv\[2\] === "hook"|positionals\[0\] === "hook"/.test(readFileSync(join(ROOT, "src/cli.js"), "utf-8"));
}

/** A report file from a CLI scan of this repo; exit 1 only means "high findings present". */
const cliScan = (args) => async (out) => {
  const r = await penthera([...args, "-o", out, "-q"], { timeout: 600_000 });
  return r.code > 1 || !existsSync(out) ? { code: r.code } : { report: readJson(out) };
};

/**
 * The pre-commit hook checks staged content only, so stage everything: copy the
 * working tree (tracked and unignored files) into a scratch git repo, `git add
 * -A`, and run `penthera hook run` there. Blocking findings become `findings`.
 */
async function hookScan(out) {
  const work = scratch("hook");
  try {
    const ls = await run("git", ["ls-files", "-z", "-co", "--exclude-standard"], { log: false });
    for (const f of ls.stdout.split("\0").filter(Boolean)) {
      if (existsSync(join(ROOT, f))) cpSync(join(ROOT, f), join(work, f), { recursive: true });
    }
    const git = (...a) => run("git", ["-C", work, ...a], { log: false });
    await git("init", "-q", "-b", "main");
    await git("add", "-A");
    const r = await penthera(["hook", "run", "--json"], { cwd: work, timeout: 600_000 });
    if (r.code > 1) return { code: r.code };
    const res = JSON.parse(r.stdout);
    writeFileSync(out, r.stdout);
    return { report: { findings: res.blocking || [], staged: res.staged } };
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

/** Self-scans of this repo. Each returns { report } or { code } on failure. */
const SELF_SCANS = [
  { key: "repo", label: "penthera --repo .", scan: cliScan(["--repo", "."]) },
  { key: "agents", label: "penthera agents .", scan: cliScan(["agents", "."]) },
  { key: "deps", label: "penthera deps .", scan: cliScan(["deps", "."]) },
  { key: "hook", label: "penthera hook run (whole tree staged)", scan: hookScan, when: hookPresent },
];

/** 3. Penthera on itself; fail on high/critical findings not in audit/baseline.json. */
async function gateSelfScan() {
  const baseline = existsSync(BASELINE_PATH) ? readJson(BASELINE_PATH) : { selfScan: {} };
  const dir = scratch("self");
  const metrics = {};
  const notes = [];
  const current = {};
  let ok = true;
  try {
    for (const s of SELF_SCANS) {
      if (s.when && !s.when()) {
        metrics[s.key] = "not present";
        continue;
      }
      const { report, code } = await s.scan(join(dir, `${s.key}.json`));
      if (!report) {
        ok = false;
        notes.push(`\`${s.label}\` failed (exit ${code}).`);
        continue;
      }
      const severe = severeFindings(report);
      current[s.key] = severe;
      const known = new Map((baseline.selfScan?.[s.key] || []).map((b) => [b.fingerprint, b]));
      const fresh = severe.filter((f) => !known.has(f.fingerprint));
      const gone = [...known.values()].filter((b) => !severe.some((f) => f.fingerprint === b.fingerprint));
      metrics[`${s.key}.findings`] = (report.findings || []).length;
      metrics[`${s.key}.highCritical`] = severe.length;
      metrics[`${s.key}.new`] = fresh.length;
      if (s.key === "agents" && report.agents?.grade) metrics["agents.grade"] = report.agents.grade;
      for (const f of fresh) {
        ok = false;
        notes.push(`NEW ${f.severity} in \`${s.label}\`: ${f.title} (\`${f.location}\`, ${f.fingerprint}).`);
      }
      for (const b of gone) notes.push(`Resolved since the baseline: ${b.title} (\`${b.location}\`). Run with --update-baseline to drop it.`);
    }
    const accepted = OPTS.updateBaseline ? writeBaseline(baseline, current) : baseline;
    for (const [key, list] of Object.entries(accepted.selfScan || {})) {
      for (const b of list) {
        if (!b.reason || /^TODO/.test(b.reason)) {
          ok = false;
          notes.push(`Baseline entry ${key}/${b.fingerprint} (${b.title}) has no reason. Every accepted finding needs one.`);
        }
      }
    }
    return { status: ok ? "pass" : "fail", metrics, notes };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function writeBaseline(old, current) {
  const selfScan = {};
  for (const [key, list] of Object.entries(current)) {
    const prior = new Map((old.selfScan?.[key] || []).map((b) => [b.fingerprint, b]));
    selfScan[key] = list.map((f) => ({ ...f, reason: prior.get(f.fingerprint)?.reason || "TODO: say why this finding is accepted" }));
  }
  const next = {
    $comment: "High/critical self-scan findings accepted by the internal audit (scripts/audit/run.mjs). Each needs a reason. Regenerate with: npm run audit:internal -- --update-baseline",
    selfScan,
  };
  writeFileSync(BASELINE_PATH, JSON.stringify(next, null, 2) + "\n");
  console.log(`wrote ${relative(ROOT, BASELINE_PATH)}`);
  return next;
}

/** 4. Every subcommand's --help, plus a fixture run of each. */
async function gateSmoke() {
  const dir = scratch("smoke");
  const home = join(dir, "penthera-home");
  const env = { PENTHERA_HOME: home };
  const cases = [];
  // expect: { codes, test?, input?, cwd? }
  const check = async (label, cmd, args, expect) => {
    const opts = { env, input: expect.input ?? null, cwd: expect.cwd ?? ROOT };
    const r = await (cmd === "penthera" ? penthera(args, opts) : run(cmd, args, opts));
    let ok = expect.codes.includes(r.code);
    let why = ok ? "" : `exit ${r.code}, expected ${expect.codes.join("/")}`;
    if (ok && expect.test) {
      try {
        const res = expect.test(r);
        if (res !== true) { ok = false; why = res || "output check failed"; }
      } catch (err) {
        ok = false;
        why = err.message;
      }
    }
    cases.push({ label, ok, why });
  };
  const json = (r) => JSON.parse(r.stdout);

  try {
    // --help and --version
    await check("penthera --version", "penthera", ["--version"], { codes: [0], test: (r) => r.stdout.includes(PKG.version) || "wrong version" });
    await check("penthera --help", "penthera", ["--help"], { codes: [0] });
    const subcommands = ["agents", "deps", "install", "memory", "fix", "evidence", "agent"];
    if (hookPresent()) subcommands.push("hook");
    for (const sub of subcommands) await check(`penthera ${sub} --help`, "penthera", [sub, "--help"], { codes: [0] });
    await check("penthera-scan --help", process.execPath, [join(ROOT, "bin/scan.js"), "--help"], { codes: [0] });

    // URL scan of the mock server, every report format, validated.
    const mock = await startMockServer(0);
    try {
      const out = join(dir, "url.json");
      await check("penthera <mock> --profile quick (json/md/sarif)", "penthera",
        [mock.url, "--profile", "quick", "--offline", "-o", out, "--sarif", join(dir, "url.sarif"), "-q"],
        { codes: [0, 1], test: () => existsSync(join(dir, "url.md")) && existsSync(join(dir, "url.sarif")) || "missing .md or .sarif" });
      await check("validate-report on the mock scan", process.execPath, [join(ROOT, "skills/penthera/scripts/validate-report.mjs"), out], { codes: [0] });
    } finally {
      await mock.close();
    }

    // agents: a malicious and a clean fixture
    await check("penthera agents <malicious fixture>", "penthera", ["agents", "tests/fixtures/agents/malicious", "--json"],
      { codes: [1], test: (r) => json(r).agents.grade === "F" || `grade ${json(r).agents.grade}, expected F` });
    await check("penthera agents <clean fixture>", "penthera", ["agents", "tests/fixtures/agents/clean", "--json"],
      { codes: [0], test: (r) => json(r).agents.grade === "A" || `grade ${json(r).agents.grade}, expected A` });

    // deps: our own runtime tree
    await check("penthera deps . --prod", "penthera", ["deps", ".", "--prod", "--json"],
      { codes: [0], test: (r) => json(r).deps.scanned > 0 || "no packages scanned" });

    // install: dry run of this project's own manifest, npm cache only
    const proj = join(dir, "install");
    mkdirSync(proj);
    for (const f of ["package.json", "package-lock.json"]) cpSync(join(ROOT, f), join(proj, f));
    await check("penthera install --dry-run --offline", "penthera", ["install", "--dry-run", "--offline", "--json", "--dir", proj],
      { codes: [0], test: (r) => json(r).action === "dry-run" || "not a dry run" });

    // fix: plan recipes on a fixture app
    await check("penthera fix --plan <express fixture>", "penthera", ["fix", "--plan", "--repo", "tests/fixtures/fix/express", "--json"],
      { codes: [0], test: (r) => json(r).plans.length > 0 || "no plans" });

    // evidence: write a bundle, then verify it
    const bundle = join(dir, "evidence");
    await check("penthera --repo <fixture> --evidence", "penthera", ["--repo", "tests/fixtures/fix/express", "--evidence", bundle, "-q"],
      { codes: [0, 1], test: () => existsSync(join(bundle, "manifest.json")) || "no manifest.json" });
    await check("penthera evidence verify", "penthera", ["evidence", "verify", bundle], { codes: [0] });

    // agent --loop: one iteration on a throwaway git copy of a fixture, declining every diff
    const loopRepo = join(dir, "loop");
    cpSync(join(ROOT, "tests/fixtures/fix/express"), loopRepo, { recursive: true });
    const git = (...a) => run("git", ["-c", "user.name=audit", "-c", "user.email=audit@localhost", "-C", loopRepo, ...a], { log: false });
    await git("init", "-q", "-b", "main");
    await git("add", "-A");
    await git("commit", "-qm", "fixture");
    const loopOut = join(dir, "loop.json");
    await check("penthera agent --loop (decline all)", "penthera",
      ["agent", "--loop", "--repo", loopRepo, "--max-iterations", "1", "-o", loopOut],
      // Exit 1 = high findings remain, which is expected when every diff is declined.
      { codes: [0, 1], input: "n\n".repeat(20) + "q\n", test: () => readJson(loopOut).loopRun?.iterations?.length >= 1 || "no iteration in loopRun" });

    // hook: install into the throwaway repo, then remove it again
    if (hookPresent()) {
      const hookFile = join(loopRepo, ".git/hooks/pre-commit");
      await check("penthera hook install", "penthera", ["hook", "install"],
        { codes: [0], cwd: loopRepo, test: () => existsSync(hookFile) || "no .git/hooks/pre-commit" });
      await check("penthera hook uninstall", "penthera", ["hook", "uninstall"],
        { codes: [0], cwd: loopRepo, test: () => !existsSync(hookFile) || "hook still installed" });
    }

    // memory: the loop above wrote to the scratch store
    await check("penthera memory show", "penthera", ["memory", "show", "--repo", loopRepo, "--json"], { codes: [0] });
    await check("penthera memory verify", "penthera", ["memory", "verify", "--repo", loopRepo], { codes: [0] });

    const failed = cases.filter((c) => !c.ok);
    return {
      status: failed.length ? "fail" : "pass",
      metrics: { cases: cases.length, passed: cases.length - failed.length, failed: failed.length },
      notes: failed.map((c) => `FAILED: \`${c.label}\`: ${c.why}`),
      table: cases,
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** 5. npm pack: allow-list, deny-list and size budget. */
async function gatePackaging() {
  const r = await run("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], { timeout: 120_000 });
  if (r.code !== 0) return { status: "fail", metrics: { exitCode: r.code }, notes: ["npm pack --dry-run failed; see audit/logs."] };
  let p = JSON.parse(r.stdout);
  p = Array.isArray(p) ? p[0] : Object.values(p)[0]; // npm <= 10: array; npm 11+: keyed by name
  const files = p.files.map((f) => f.path);
  const notAllowed = files.filter((f) => !PACK_ALLOW.some((re) => re.test(f)));
  const denied = files.filter((f) => PACK_DENY.some((re) => re.test(f)));
  const notes = [
    ...notAllowed.map((f) => `Not on the allow-list: \`${f}\``),
    ...denied.map((f) => `Must not ship: \`${f}\``),
  ];
  const over = [];
  if (p.size > PACK_BUDGET.packedBytes) over.push(`packed ${p.size} B > ${PACK_BUDGET.packedBytes} B`);
  if (p.unpackedSize > PACK_BUDGET.unpackedBytes) over.push(`unpacked ${p.unpackedSize} B > ${PACK_BUDGET.unpackedBytes} B`);
  if (files.length > PACK_BUDGET.files) over.push(`${files.length} files > ${PACK_BUDGET.files}`);
  notes.push(...over.map((o) => `Over budget: ${o}`));
  return {
    status: notAllowed.length || denied.length || over.length ? "fail" : "pass",
    metrics: {
      files: files.length,
      packedKB: Math.round(p.size / 1024),
      unpackedKB: Math.round(p.unpackedSize / 1024),
      budgetPackedKB: Math.round(PACK_BUDGET.packedBytes / 1024),
      budgetUnpackedKB: Math.round(PACK_BUDGET.unpackedBytes / 1024),
    },
    notes,
  };
}

/** 6. A full --offline scan of the mock server must contact nobody but the target. */
async function gateOffline() {
  const mock = await startMockServer(0);
  const dir = scratch("offline");
  const out = join(dir, "offline.json");
  try {
    const r = await penthera([mock.url, "--all", "--adaptive", "--offline", "-o", out, "-q"], { timeout: 900_000 });
    if (r.code > 1 || !existsSync(out)) return { status: "fail", metrics: { exitCode: r.code }, notes: ["The offline scan failed; see audit/logs."] };
    const e = readJson(out).egress;
    if (!e) return { status: "fail", metrics: {}, notes: ["The report has no `egress` field."] };
    const third = e.thirdPartyHosts || [];
    const blocked = e.blocked || [];
    const notes = [
      ...third.map((h) => `Contacted a third party: ${h.host} (${h.requests} requests)`),
      ...blocked.map((h) => `Refused by the egress guard: ${h.host} (${h.requests} attempts). Nothing left the machine, but a code path tried.`),
    ];
    if (!e.offline) notes.push("egress.offline is false although --offline was passed.");
    return {
      status: third.length === 0 && e.offline ? "pass" : "fail",
      metrics: {
        targetRequests: (e.hosts || []).filter((h) => h.host === e.target).reduce((n, h) => n + h.requests, 0),
        thirdPartyHosts: third.length,
        blockedAttempts: blocked.reduce((n, h) => n + h.requests, 0),
      },
      notes,
    };
  } finally {
    await mock.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Every `uses:` in a workflow or composite action file. */
export function actionRefs(yamlText) {
  const refs = [];
  const walk = (node) => {
    if (Array.isArray(node)) node.forEach(walk);
    else if (node && typeof node === "object") {
      for (const [k, v] of Object.entries(node)) {
        if (k === "uses" && typeof v === "string") refs.push(v.trim());
        else walk(v);
      }
    }
  };
  walk(parseYaml(yamlText));
  return refs;
}

/** Local actions are fine; remote ones need a 40-hex commit SHA, Docker images a digest. */
export function isPinned(ref) {
  if (ref.startsWith("./")) return true;
  if (ref.startsWith("docker://")) return /@sha256:[0-9a-f]{64}$/.test(ref);
  return /@[0-9a-f]{40}$/.test(ref);
}

/** 7. Supply chain: npm audit, lockfile integrity, install scripts, pinned actions. */
async function gateSupplyChain() {
  const notes = [];
  const metrics = {};
  let ok = true;

  // npm audit (the only gate that needs the network)
  const a = await run("npm", ["audit", "--omit=dev", "--json"], { timeout: 120_000 });
  try {
    const v = JSON.parse(a.stdout).metadata.vulnerabilities;
    metrics.npmAuditVulns = v.total;
    if (v.total > 0) {
      ok = false;
      notes.push(`npm audit --omit=dev: ${Object.entries(v).filter(([k, n]) => k !== "total" && n).map(([k, n]) => `${n} ${k}`).join(", ")}`);
    }
  } catch {
    ok = false;
    metrics.npmAuditVulns = "error";
    notes.push(`npm audit did not return JSON (exit ${a.code}); it needs the npm registry. See audit/logs.`);
  }

  // Lockfile integrity
  const lock = readJson(join(ROOT, "package-lock.json"));
  const pkgs = Object.entries(lock.packages || {}).filter(([path, p]) => path && !p.link);
  const missing = pkgs.filter(([, p]) => !p.integrity || !/^sha512-/.test(p.integrity) || !p.resolved?.startsWith("https://registry.npmjs.org/"));
  metrics.lockfileVersion = lock.lockfileVersion;
  metrics.lockedPackages = pkgs.length;
  metrics.withoutIntegrity = missing.length;
  if (lock.lockfileVersion < 2) { ok = false; notes.push(`lockfileVersion ${lock.lockfileVersion} < 2`); }
  for (const [path] of missing) { ok = false; notes.push(`No sha512 integrity or registry URL in the lockfile: \`${path}\``); }

  // Install scripts in runtime dependencies, from penthera deps on our own tree
  const dir = scratch("supply");
  try {
    const out = join(dir, "deps.json");
    const r = await penthera(["deps", ".", "--prod", "-o", out, "-q"], { timeout: 300_000 });
    if (r.code > 1 || !existsSync(out)) {
      ok = false;
      notes.push(`penthera deps --prod failed (exit ${r.code}).`);
    } else {
      const d = readJson(out).deps;
      metrics.runtimePackages = d.scanned;
      metrics.runtimeInstallScripts = d.capabilityCounts["install-scripts"];
      metrics.typosquats = (d.typosquats || []).length;
      if (metrics.runtimeInstallScripts) { ok = false; notes.push(`${metrics.runtimeInstallScripts} runtime dependency/ies run install scripts.`); }
      if (metrics.typosquats) { ok = false; notes.push(`Possible typosquats: ${d.typosquats.map((t) => t.name || t).join(", ")}`); }
    }
    // Cross-check with the lockfile's own flag
    const lockScripts = pkgs.filter(([, p]) => p.hasInstallScript && !p.dev).map(([path]) => path);
    for (const p of lockScripts) { ok = false; notes.push(`Lockfile marks a runtime install script: \`${p}\``); }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }

  // GitHub Actions pinned by SHA
  const actionFiles = [
    ...readdirSync(join(ROOT, ".github/workflows")).filter((f) => /\.ya?ml$/.test(f)).map((f) => `.github/workflows/${f}`),
    "action.yml",
    ...readdirSync(join(ROOT, "docs/examples")).filter((f) => /\.ya?ml$/.test(f)).map((f) => `docs/examples/${f}`),
  ].filter((f) => existsSync(join(ROOT, f)));
  let refs = 0;
  for (const f of actionFiles) {
    const text = readFileSync(join(ROOT, f), "utf-8");
    for (const ref of actionRefs(text)) {
      refs++;
      if (!isPinned(ref)) { ok = false; notes.push(`Not pinned by SHA: \`${ref}\` in ${f}`); }
    }
    if (f.startsWith(".github/workflows/") && !/^permissions:/m.test(text)) {
      ok = false;
      notes.push(`${f} has no top-level \`permissions:\` (least privilege).`);
    }
  }
  metrics.actionRefs = refs;
  metrics.actionFiles = actionFiles.length;
  return { status: ok ? "pass" : "fail", metrics, notes };
}

/** All relative links in a Markdown file, outside code fences. */
export function markdownLinks(text) {
  const links = [];
  let fenced = false;
  for (const line of text.split("\n")) {
    if (/^\s*(```|~~~)/.test(line)) { fenced = !fenced; continue; }
    if (fenced) continue;
    const stripped = line.replace(/`[^`]*`/g, "");
    for (const m of stripped.matchAll(/\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)|href="([^"]+)"|src="([^"]+)"/g)) {
      links.push(m[1] || m[2] || m[3]);
    }
  }
  return links;
}

function walkMarkdown(dir) {
  const out = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...walkMarkdown(p));
    else if (e.name.endsWith(".md")) out.push(p);
  }
  return out;
}

/** 8. Versions in sync, CHANGELOG entry present, docs links resolve. */
async function gateVersionsDocs() {
  const notes = [];
  const v = PKG.version;
  const lock = readJson(join(ROOT, "package-lock.json"));
  const skill = readFileSync(join(ROOT, "skills/penthera/SKILL.md"), "utf-8").match(/^ {2}version:\s*"?([^"\s]+)"?/m)?.[1];
  const citation = readFileSync(join(ROOT, "CITATION.cff"), "utf-8").match(/^version:\s*"?([^"\s]+)"?/m)?.[1];
  const found = {
    "package-lock.json": lock.version,
    'package-lock.json packages[""]': lock.packages?.[""]?.version,
    ".claude-plugin/plugin.json": readJson(join(ROOT, ".claude-plugin/plugin.json")).version,
    ".claude-plugin/marketplace.json": readJson(join(ROOT, ".claude-plugin/marketplace.json")).metadata?.version,
    "skills/penthera/SKILL.md": skill,
    "CITATION.cff": citation,
  };
  for (const [file, got] of Object.entries(found)) {
    if (got !== v) notes.push(`Version drift: ${file} has ${got ?? "none"}, package.json has ${v}`);
  }
  const cli = await penthera(["--version"], { log: false });
  if (!cli.stdout.includes(v)) notes.push(`penthera --version prints "${cli.stdout.trim()}", expected ${v}`);
  if (!new RegExp(`^## \\[${v.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\]`, "m").test(readFileSync(join(ROOT, "CHANGELOG.md"), "utf-8"))) {
    notes.push(`CHANGELOG.md has no "## [${v}]" section.`);
  }
  const versionIssues = notes.length;

  // Docs links
  const files = [join(ROOT, "README.md"), ...walkMarkdown(join(ROOT, "docs"))];
  let checked = 0;
  for (const file of files) {
    for (const link of markdownLinks(readFileSync(file, "utf-8"))) {
      if (/^([a-z][a-z0-9+.-]*:|#|\/\/)/i.test(link)) continue; // URLs, mailto:, in-page anchors
      const target = decodeURIComponent(link.split("#")[0].split("?")[0]);
      if (!target) continue;
      checked++;
      const path = resolve(dirname(file), target);
      // audit/REPORT.md is written by this run, so it counts as present.
      if (!existsSync(path) && !(path === REPORT_PATH && !OPTS.noWrite)) notes.push(`Broken link in ${relative(ROOT, file)}: \`${link}\``);
    }
  }
  return {
    status: notes.length ? "fail" : "pass",
    metrics: { version: v, filesInSync: Object.keys(found).length + 1 - versionIssues, docFiles: files.length, linksChecked: checked, brokenLinks: notes.length - versionIssues },
    notes,
  };
}

// ── Optional Docker targets (--with-docker) ──────────────────────────────

async function waitForHttp(url, seconds) {
  for (let i = 0; i < seconds; i++) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(2_000) });
      if (res.status < 500) return true;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 1_000));
  }
  return false;
}

async function benchTarget(name, url) {
  const dir = scratch(name);
  const out = join(dir, `${name}.json`);
  try {
    const r = await run("npm", ["run", "bench", "--", "--target", name, "--url", url, "--no-write", "--json", out], { timeout: 1_800_000 });
    if (!existsSync(out)) return { ok: false, note: `bench --target ${name} failed (exit ${r.code})` };
    const b = readJson(out);
    const t = b.targets[0];
    return {
      ok: b.blocked.length === 0,
      metrics: {
        [`${name}.findings`]: t.findings.length,
        [`${name}.precision`]: t.score ? t.score.precision : "unlabelled",
        [`${name}.recall`]: t.score ? t.score.recall : "unlabelled",
        [`${name}.nonLoopback`]: b.blocked.length,
      },
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

async function gateDocker() {
  if (!OPTS.withDocker) return { status: "skip", metrics: {}, notes: ["Skipped by default. Run with --with-docker to scan OWASP Juice Shop (and crAPI, if it is running)."] };
  const info = await run("docker", ["info", "--format", "{{.ServerVersion}}"], { timeout: 30_000, log: false });
  if (info.code !== 0) return { status: "fail", metrics: {}, notes: ["--with-docker was passed but Docker is not available."] };
  const metrics = {};
  const notes = [];
  let ok = true;

  // Juice Shop: started and removed by the audit, bound to loopback only.
  const name = `penthera-audit-juice-${process.pid}`;
  const started = await run("docker", ["run", "-d", "--rm", "--name", name, "-p", `127.0.0.1:${JUICE_SHOP_PORT}:3000`, JUICE_SHOP_IMAGE], { timeout: 600_000 });
  if (started.code !== 0) {
    ok = false;
    notes.push(`Could not start ${JUICE_SHOP_IMAGE} (exit ${started.code}).`);
  } else {
    try {
      const url = `http://127.0.0.1:${JUICE_SHOP_PORT}`;
      if (!(await waitForHttp(url, 180))) {
        ok = false;
        notes.push("Juice Shop did not come up within 180 s.");
      } else {
        const r = await benchTarget("juice-shop", url);
        Object.assign(metrics, r.metrics || {});
        if (!r.ok) { ok = false; notes.push(r.note || "Juice Shop scan made non-loopback requests."); }
        notes.push(`Juice Shop image: ${JUICE_SHOP_IMAGE}.`);
      }
    } finally {
      await run("docker", ["rm", "-f", name], { timeout: 60_000, log: false });
    }
  }

  // crAPI needs its own Docker Compose stack; scan it only if it is already up.
  if (await waitForHttp(CRAPI_URL, 3)) {
    const r = await benchTarget("crapi", CRAPI_URL);
    Object.assign(metrics, r.metrics || {});
    if (!r.ok) { ok = false; notes.push(r.note || "crAPI scan made non-loopback requests."); }
  } else {
    metrics["crapi"] = "not running";
    notes.push(`crAPI not reachable at ${CRAPI_URL}; start it with its Docker Compose file to include it (see docs/internal-audit.md).`);
  }
  notes.push("Juice Shop and crAPI have no ground truth yet, so precision and recall read \"unlabelled\" until they are labelled in bench/ground-truth.json.");
  return { status: ok ? "pass" : "fail", metrics, notes };
}

// ── Report ───────────────────────────────────────────────────────────────

const GATES = [
  { id: "tests", title: "Test suite (`npm test`)", fn: gateTests },
  { id: "bench", title: "Benchmark vs bench/RESULTS.md", fn: gateBench },
  { id: "self-scan", title: "Self-scan vs audit/baseline.json", fn: gateSelfScan },
  { id: "smoke", title: "CLI smoke matrix", fn: gateSmoke },
  { id: "packaging", title: "Packaging (`npm pack`)", fn: gatePackaging },
  { id: "offline", title: "Offline egress (mock server)", fn: gateOffline },
  { id: "supply-chain", title: "Supply chain", fn: gateSupplyChain },
  { id: "versions-docs", title: "Versions and docs links", fn: gateVersionsDocs },
  { id: "docker", title: "Docker targets (optional)", fn: gateDocker },
];

const ICON = { pass: "PASS", fail: "**FAIL**", skip: "skip" };

function metricLine(metrics) {
  return Object.entries(metrics).map(([k, v]) => `${k} ${fmt(v)}`).join(", ");
}

/** Read the machine-readable block of a previous REPORT.md. */
export function readPreviousData(markdown) {
  const m = markdown.match(/<!-- audit-data\n([\s\S]*?)\n-->/);
  return m ? JSON.parse(m[1]) : null;
}

export function diffReports(prev, cur) {
  if (!prev) return ["No previous report: this is the first run."];
  const lines = [];
  for (const [id, g] of Object.entries(cur.gates)) {
    const p = prev.gates?.[id];
    if (!p) { lines.push(`- ${id}: new gate (${g.status})`); continue; }
    if (p.status !== g.status) lines.push(`- ${id}: ${p.status} → ${g.status}`);
    for (const [k, v] of Object.entries(g.metrics)) {
      if (k === "seconds") continue;
      if (p.metrics?.[k] !== undefined && JSON.stringify(p.metrics[k]) !== JSON.stringify(v)) lines.push(`- ${id}.${k}: ${fmt(p.metrics[k])} → ${fmt(v)}`);
    }
  }
  return lines.length ? lines : [`No changes since the previous report (${prev.commit}, ${prev.date}).`];
}

function renderReport(data, previous) {
  const L = [];
  const failed = Object.values(data.gates).filter((g) => g.status === "fail").length;
  L.push("# Internal audit report");
  L.push("");
  L.push("Generated by `npm run audit:internal` ([scripts/audit/run.mjs](../scripts/audit/run.mjs)). Do not edit by hand; see [docs/internal-audit.md](../docs/internal-audit.md).");
  L.push("");
  L.push(`- Penthera ${data.version} at \`${data.commit}\`${data.dirty ? " **plus uncommitted changes**" : ""}${data.branch ? ` (${data.branch})` : ""}`);
  L.push(`- ${data.date}, Node ${data.node}, npm ${data.npm}, ${data.platform}`);
  L.push(`- Result: **${failed ? `FAIL (${failed} gate${failed > 1 ? "s" : ""})` : "PASS"}** in ${data.seconds} s`);
  L.push("");
  L.push("| Gate | Result | Numbers |");
  L.push("|---|---|---|");
  for (const g of GATES) {
    const r = data.gates[g.id];
    if (!r) continue;
    L.push(`| ${g.title} | ${ICON[r.status]} | ${metricLine(r.metrics).replace(/\\/g, "\\\\").replace(/\|/g, "\\|")} |`);
  }
  L.push("");
  L.push("## Changes since the previous report");
  L.push("");
  L.push(...diffReports(previous, data));
  L.push("");
  L.push("## Details");
  for (const g of GATES) {
    const r = data.gates[g.id];
    if (!r) continue;
    L.push("");
    L.push(`### ${g.title}: ${ICON[r.status]}`);
    L.push("");
    if (r.table) {
      L.push("| Command | Result |");
      L.push("|---|---|");
      for (const c of r.table) L.push(`| \`${c.label}\` | ${c.ok ? "ok" : `**${c.why}**`} |`);
      L.push("");
    }
    if (r.notes.length) for (const n of r.notes) L.push(`- ${n}`);
    else L.push("Nothing to note.");
  }
  L.push("");
  L.push("<!-- audit-data");
  L.push(JSON.stringify({ ...data, gates: Object.fromEntries(Object.entries(data.gates).map(([k, g]) => [k, { status: g.status, metrics: g.metrics }])) }));
  L.push("-->");
  L.push("");
  return L.join("\n");
}

// ── Main ─────────────────────────────────────────────────────────────────

const OPTS = { withDocker: false, only: null, noWrite: false, updateBaseline: false };

function parseArgs(argv) {
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--with-docker") OPTS.withDocker = true;
    else if (a === "--no-write") OPTS.noWrite = true;
    else if (a === "--update-baseline") OPTS.updateBaseline = true;
    else if (a === "--only") OPTS.only = argv[++i].split(",");
    else if (a === "-h" || a === "--help") {
      console.log(readFileSync(fileURLToPath(import.meta.url), "utf-8").split("\n").slice(2, 14).map((l) => l.replace(/^ \* ?/, "")).join("\n"));
      process.exit(0);
    } else throw new Error(`Unknown argument: ${a}`);
  }
  if (OPTS.only) {
    const unknown = OPTS.only.filter((id) => !GATES.some((g) => g.id === id));
    if (unknown.length) throw new Error(`Unknown gate(s): ${unknown.join(", ")}. Known: ${GATES.map((g) => g.id).join(", ")}`);
    if (OPTS.only.includes("docker")) OPTS.withDocker = true;
    OPTS.noWrite = true; // a partial run never replaces the committed report
  }
}

async function main() {
  parseArgs(process.argv.slice(2));
  const started = Date.now();
  if (!OPTS.noWrite) rmSync(LOG_DIR, { recursive: true, force: true });
  const gates = {};
  for (const g of GATES) {
    if (OPTS.only && !OPTS.only.includes(g.id)) continue;
    process.stdout.write(`▸ ${g.title} … `);
    const t0 = Date.now();
    let r;
    try {
      r = await g.fn();
    } catch (err) {
      r = { status: "fail", metrics: {}, notes: [`The gate crashed: ${err.stack || err.message}`] };
    }
    gates[g.id] = r;
    console.log(`${r.status.toUpperCase()} (${((Date.now() - t0) / 1000).toFixed(1)}s)${Object.keys(r.metrics).length ? `  ${metricLine(r.metrics)}` : ""}`);
    for (const n of r.status === "fail" ? r.notes : []) console.log(`    ${n}`);
  }

  const git = async (...a) => (await run("git", a, { log: false })).stdout.trim();
  const data = {
    version: PKG.version,
    commit: await git("rev-parse", "--short", "HEAD"),
    // Uncommitted changes outside audit/ mean the report does not describe `commit` alone.
    dirty: (await git("status", "--porcelain", "--", ".", ":!audit")).length > 0,
    branch: process.env.GITHUB_REF_NAME || (await git("rev-parse", "--abbrev-ref", "HEAD")),
    date: new Date().toISOString().replace(/\.\d+Z$/, "Z"),
    node: process.version,
    npm: (await run("npm", ["--version"], { log: false })).stdout.trim(),
    platform: `${process.platform}-${process.arch}`,
    seconds: Math.round((Date.now() - started) / 1000),
    gates,
  };
  const failed = Object.entries(gates).filter(([, g]) => g.status === "fail").map(([id]) => id);

  if (!OPTS.noWrite) {
    mkdirSync(AUDIT_DIR, { recursive: true });
    const previous = existsSync(REPORT_PATH) ? readPreviousData(readFileSync(REPORT_PATH, "utf-8")) : null;
    writeFileSync(REPORT_PATH, renderReport(data, previous));
    console.log(`\nwrote ${relative(ROOT, REPORT_PATH)} (command logs in ${relative(ROOT, LOG_DIR)}/)`);
  }
  console.log(failed.length ? `\nFAIL: ${failed.join(", ")}` : "\nPASS: every gate passed");
  return failed.length ? 1 : 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main().then(
    (code) => process.exit(code),
    (err) => { console.error(err.message); process.exit(2); },
  );
}
