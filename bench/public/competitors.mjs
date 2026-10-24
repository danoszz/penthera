/**
 * E11b reference points: other open-source tools on the same split, scored
 * the same way (amendment E11b § 5). Not part of E11's registered hypotheses.
 *
 *   npm run bench:public -- --competitors --split dev [--only creddata,malware] [--tools a,b]
 *
 * Tools are pinned, installed into $PENTHERA_BENCH_CACHE/public/tools, and run
 * under macOS `sandbox-exec` with all network access denied, so a tool that
 * needs the network at scan time fails instead of reaching out. GuardDog
 * applies its own kernel sandbox, which always blocks the network and cannot
 * nest inside ours; it refuses to scan when that sandbox is unavailable. Malware rules
 * as in E11 § 10: samples only under MALWARE_DIR, never installed or run,
 * deleted at the end.
 */
import { existsSync, readFileSync, writeFileSync, rmSync, mkdtempSync, readdirSync, lstatSync, linkSync, openSync, closeSync, cpSync, realpathSync } from "node:fs";
import { join, dirname, relative, sep } from "node:path";
import { createHash } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { CACHE, RESULTS, MALWARE_DIR, fetchBuf, ensureDir, sh, fmt, cloneAt } from "./common.mjs";
import { currentSplit, inSplit } from "./split.mjs";

// Each tool pinned to the newest release that was at least four days old on
// 2026-10-24. sha256 is checked on every download: against the release's own
// checksum file where it publishes one (gitleaks, trufflehog), the GitHub
// release asset digest (kingfisher), or the hash of the first download
// (noseyparker, ripsecrets, which publish none).
export const TOOLS = {
  gitleaks: { version: "8.30.1", url: "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_darwin_arm64.tar.gz", sums: "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_checksums.txt" },
  "detect-secrets": { version: "1.5.0", pip: "detect-secrets==1.5.0" },
  guarddog: { version: "3.2.0", pip: "guarddog==3.2.0" },
  trufflehog: { version: "3.99.3", url: "https://github.com/trufflesecurity/trufflehog/releases/download/v3.99.3/trufflehog_3.99.3_darwin_arm64.tar.gz", sums: "https://github.com/trufflesecurity/trufflehog/releases/download/v3.99.3/trufflehog_3.99.3_checksums.txt", sha256: "07d8744261d4460c2e8ee8d908d71e4aee70e049496100290b50aac7757ad078", bin: "trufflehog" },
  noseyparker: { version: "0.24.0", url: "https://github.com/praetorian-inc/noseyparker/releases/download/v0.24.0/noseyparker-v0.24.0-aarch64-apple-darwin.tar.gz", sha256: "b19f983d586a738f127bc8c53ef1331055010db4926ac1789791f717fcc107b7", bin: "bin/noseyparker" },
  kingfisher: { version: "2.14.0", url: "https://github.com/mongodb/kingfisher/releases/download/v2.14.0/kingfisher-darwin-arm64.tgz", sha256: "df6710130fac7314a6479e3ac7b2b092f8aa3a2bef131fbd307fa3dd8d7d9471", bin: "kingfisher" },
  ripsecrets: { version: "0.1.11", url: "https://github.com/sirwart/ripsecrets/releases/download/v0.1.11/ripsecrets-0.1.11-aarch64-apple-darwin.tar.gz", sha256: "b2c822742e8cbf355ba0cb4cc690c3cd8fdc9ec1916c8148f27bd9098cb7aee4", bin: "ripsecrets-0.1.11-aarch64-apple-darwin/ripsecrets" },
  credsweeper: { version: "1.19.4", pip: "credsweeper==1.19.4", venv: "venv-credsweeper", bin: "credsweeper", caveat: "trained on this dataset, not comparable: made by the CredData authors, its ML model was trained with CredData" },
  whispers: { version: "2.4.0", pip: "whispers==2.4.0", venv: "venv-whispers", bin: "whispers" },
  deepsecrets: { version: "2.2.0", pip: "deepsecrets==2.2.0", venv: "venv-deepsecrets", bin: "deepsecrets" },
  // njsscan 1.x runs its bundled rules on the Semgrep engine it pins (1.172.0), found on PATH.
  njsscan: { version: "1.0.1", pip: "njsscan==1.0.1", venv: "venv-njsscan", bin: "njsscan" },
  secretlint: { version: "13.0.7", npm: ["secretlint@13.0.7", "@secretlint/secretlint-rule-preset-recommend@13.0.7"] },
  // SecBench.js, pinned at least two weeks before 2026-10-24. The CodeQL CLI
  // bundle carries the standard query packs, so nothing is downloaded at scan
  // time; its sha256 is the release's own .checksum.txt and asset digest.
  codeql: {
    version: "2.27.2", release: "github/codeql-action codeql-bundle-v2.27.2 (2026-10-07)",
    url: "https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.27.2/codeql-bundle-osx64.tar.gz",
    sums: "https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.27.2/codeql-bundle-osx64.tar.gz.checksum.txt",
    sha256: "bdd42bab471ed16277048b35b9be7264d07bd19b7391c37d30c74e9555e61e92", bin: "codeql/codeql",
    suite: "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
    license: "GitHub CodeQL Terms and Conditions (LICENSE.md in the bundle): use rights cover academic research, and analysis of codebases under an OSI-approved license; no use for automated analysis or CI outside those. This is a research benchmark run on published npm packages",
  },
  // Semgrep OSS with the community rules at a pinned commit, cloned locally:
  // never --config auto or a registry config, which fetch rules at scan time.
  semgrep: {
    version: "1.180.0", pip: "semgrep==1.180.0", venv: "venv-semgrep", bin: "semgrep",
    rules: { repo: "https://github.com/semgrep/semgrep-rules", commit: "9bbf021d0acffa3095fcffd17b2bc7787eb4796d", date: "2026-10-08", dir: "javascript", license: "Semgrep Rules License v1.0 (use allowed, no competing service)" },
  },
  // ESLint with eslint-plugin-security's recommended config (npm, 2026-10-01 and -02).
  "eslint-plugin-security": { version: "4.2.0", npmPkgs: ["eslint@10.12.0", "eslint-plugin-security@4.2.0"], eslint: "10.12.0" },
  // Bearer CLI fetches its default rules at scan time, so they are pinned and
  // passed as a local folder: bearer-rules v0.48.4 (2025-11-10), its
  // javascript.tar.gz checked against the GitHub release asset digest.
  bearer: {
    version: "2.1.1", url: "https://github.com/Bearer/bearer/releases/download/v2.1.1/bearer_2.1.1_darwin_arm64.tar.gz",
    sums: "https://github.com/Bearer/bearer/releases/download/v2.1.1/checksums.txt", sha256: "96fb52d993111c633e7b8a906b7abbba4f0745b56bc0e28894fd09123e8d6c32", bin: "bearer",
    rules: { version: "0.48.4", url: "https://github.com/Bearer/bearer-rules/releases/download/v0.48.4/javascript.tar.gz", sha256: "08c12673a8bdcf0cb0332aac93c1657baba1d2d27503e954f564268f76482688" },
  },
  // graudit: grep with signature files, pinned commit (2026-05-20), its js database.
  graudit: { version: "849d7c7", repo: "https://github.com/wireghoul/graudit", commit: "849d7c7ae428fd6dad0d06dae80b0c46e4913f99" },
  // ODGen (Li et al., USENIX Security 2022), last commit 2023-07-06. Its
  // requirements.txt is unpinned, so the four it needs to scan are pinned to
  // releases from before that commit (the GUI and web dependencies are left out).
  odgen: {
    version: "c5157ee", repo: "https://github.com/Song-Li/ODGen", commit: "c5157ee9f560a93364708ff2276dba71d1967cc3",
    venv: "venv-odgen", pip: "networkx==3.1 tqdm==4.65.0 func_timeout==4.3.5 sty==1.0.0rc0", bin: "python",
    npmPkgs: ["ansicolor@1.1.100", "commander@3.0.2", "esprima@4.0.1"],
  },
};
// Not run: Semgrep's public p/secrets ruleset is fetched from the registry at
// scan time, which breaks the no-network rule (and AGENTS.md rule 5).
export const SKIPPED = { "semgrep p/secrets": "downloads its rules from the Semgrep registry at scan time; cannot run offline" };
const TOOLS_DIR = join(CACHE, "tools");
const OFFLINE = "(version 1)(allow default)(deny network*)";
// Python multiprocessing (credsweeper's SyncManager, deepsecrets' forkserver)
// talks over Unix-domain sockets. This profile allows those and nothing else:
// every IP connection is still denied.
const OFFLINE_UNIX = `${OFFLINE}(allow network* (local unix-socket))(allow network* (remote unix-socket))`;
// Bearer's scan workers talk to the main process over TCP on 127.0.0.1. This
// profile allows loopback only; every other IP connection is still denied.
const OFFLINE_LOOPBACK = `${OFFLINE}(allow network* (local ip "localhost:*"))(allow network* (remote ip "localhost:*"))`;
const TIMEOUT = 1_800_000; // 30 minutes per tool run on dev

/** Run a command with every network operation denied by the kernel sandbox. */
function offline(cmd, args, opts = {}) {
  return spawnSync("sandbox-exec", ["-p", opts.profile || OFFLINE, cmd, ...args], {
    encoding: "utf-8", maxBuffer: 1 << 30, timeout: 3_600_000,
    env: { PATH: process.env.PATH, HOME: TOOLS_DIR, SEMGREP_SEND_METRICS: "off", SEMGREP_ENABLE_VERSION_CHECK: "0", ...opts.env },
    ...opts,
  });
}

async function install() {
  ensureDir(TOOLS_DIR);
  const gl = join(TOOLS_DIR, "gitleaks");
  if (!existsSync(gl)) {
    const tgz = await fetchBuf(TOOLS.gitleaks.url);
    const sums = (await fetchBuf(TOOLS.gitleaks.sums)).toString("utf-8");
    const want = sums.split("\n").find((l) => l.endsWith(TOOLS.gitleaks.url.split("/").pop()))?.split(/\s+/)[0];
    if (createHash("sha256").update(tgz).digest("hex") !== want) throw new Error("gitleaks checksum mismatch");
    const t = join(TOOLS_DIR, "gitleaks.tgz");
    writeFileSync(t, tgz);
    sh("tar", ["-xzf", t, "-C", TOOLS_DIR, "gitleaks"]);
  }
  const venv = join(TOOLS_DIR, "venv");
  if (!existsSync(join(venv, "bin", "python"))) {
    sh(process.env.PYTHON || "python3.12", ["-m", "venv", venv]);
    sh(join(venv, "bin", "pip"), ["install", "-q", TOOLS["detect-secrets"].pip, TOOLS.guarddog.pip], { stdio: ["ignore", "inherit", "inherit"] });
  }
  const bin = { gitleaks: gl, detectSecrets: join(venv, "bin", "detect-secrets"), guarddog: join(venv, "bin", "guarddog") };
  for (const [name, t] of Object.entries(TOOLS)) {
    try {
      if (name === "codeql") bin[name] = installCodeql(t);
      else if (t.url && t.bin) bin[name] = await installRelease(name, t);
      else if (t.venv) bin[name] = installPip(t);
      else if (t.npm) bin[name] = installNpm(name, t);
    } catch (e) {
      bin[name] = { error: `did not install: ${String(e.message || e).split("\n")[0].slice(0, 300)}` };
    }
  }
  try {
    const r = TOOLS.semgrep.rules;
    const dir = join(TOOLS_DIR, `semgrep-rules-${r.commit.slice(0, 7)}`);
    cloneAt(r.repo, dir, r.commit);
    bin.semgrepRules = join(dir, r.dir);
  } catch (e) {
    bin.semgrep = { error: `rules did not clone: ${String(e.message || e).split("\n")[0].slice(0, 300)}` };
  }
  await installSast(bin);
  return bin;
}

const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");

/** A pinned GitHub release archive, hash checked, unpacked into tools/<name>-<version>. */
async function installRelease(name, t) {
  const dir = join(TOOLS_DIR, `${name}-${t.version}`);
  const exe = join(dir, t.bin);
  if (existsSync(exe)) return exe;
  const buf = await fetchBuf(t.url);
  if (!buf) throw new Error(`${t.url} not found`);
  if (t.sums) {
    const sums = (await fetchBuf(t.sums)).toString("utf-8");
    const want = sums.split("\n").find((l) => l.trim().endsWith(t.url.split("/").pop()))?.split(/\s+/)[0];
    if (want !== t.sha256) throw new Error(`${name}: published checksum ${want} differs from the pin`);
  }
  if (sha256(buf) !== t.sha256) throw new Error(`${name} checksum mismatch`);
  ensureDir(dir);
  const arc = join(dir, t.url.split("/").pop());
  writeFileSync(arc, buf);
  sh("tar", ["-xzf", arc, "-C", dir]);
  rmSync(arc);
  return exe;
}

/**
 * The CodeQL bundle is 1.2 GB, so it goes to disk with curl instead of into
 * memory; the hash is checked against the pin and the published checksum
 * before it is unpacked.
 */
function installCodeql(t) {
  const dir = join(TOOLS_DIR, `codeql-${t.version}`);
  const exe = join(dir, t.bin);
  if (existsSync(exe)) return exe;
  ensureDir(dir);
  const arc = join(dir, t.url.split("/").pop());
  sh("curl", ["-fsSL", "--retry", "3", "-o", arc, t.url], { timeout: 3_600_000 });
  const want = sh("curl", ["-fsSL", t.sums]).split(/\s+/)[0];
  if (want !== t.sha256) throw new Error(`codeql: published checksum ${want} differs from the pin`);
  if (sh("shasum", ["-a", "256", arc]).split(/\s+/)[0] !== t.sha256) throw new Error("codeql checksum mismatch");
  sh("tar", ["-xzf", arc, "-C", dir], { timeout: 3_600_000 });
  rmSync(arc);
  return exe;
}

/** The SecBench.js tools that are not a single release binary or PyPI package. */
async function installSast(bin) {
  const err = (e) => ({ error: `did not install: ${String(e.message || e).split("\n")[0].slice(0, 300)}` });
  try {
    const t = TOOLS["eslint-plugin-security"];
    const prefix = join(TOOLS_DIR, `eslint-security-${t.version}`);
    const eslint = join(prefix, "node_modules", "eslint", "bin", "eslint.js");
    if (!existsSync(eslint)) sh("npm", ["install", "--prefix", prefix, "--no-audit", "--no-fund", "--ignore-scripts", "--save-exact", ...t.npmPkgs], { timeout: 900_000 });
    bin["eslint-plugin-security"] = eslint;
    bin.eslintPlugin = join(prefix, "node_modules", "eslint-plugin-security", "index.js");
  } catch (e) { bin["eslint-plugin-security"] = err(e); }
  try {
    const r = TOOLS.bearer.rules;
    const dir = join(TOOLS_DIR, `bearer-rules-${r.version}`);
    if (!existsSync(join(dir, "javascript"))) {
      const buf = await fetchBuf(r.url);
      if (!buf || sha256(buf) !== r.sha256) throw new Error("bearer-rules checksum mismatch");
      ensureDir(dir);
      writeFileSync(join(dir, "javascript.tar.gz"), buf);
      sh("tar", ["-xzf", join(dir, "javascript.tar.gz"), "-C", dir]);
      rmSync(join(dir, "javascript.tar.gz"));
    }
    bin.bearerRules = dir;
  } catch (e) { bin.bearer = err(e); }
  try {
    const t = TOOLS.graudit;
    const dir = join(TOOLS_DIR, `graudit-${t.version}`);
    cloneAt(t.repo, dir, t.commit);
    bin.graudit = join(dir, "graudit");
  } catch (e) { bin.graudit = err(e); }
  try {
    if (bin.odgen?.error) throw new Error(bin.odgen.error);
    const t = TOOLS.odgen;
    const dir = join(TOOLS_DIR, `odgen-${t.version}`);
    cloneAt(t.repo, dir, t.commit);
    // Its own install.sh runs `npm i` with scripts and global Babel; only the
    // AST exporter's three dependencies are needed, installed without scripts.
    if (!existsSync(join(dir, "src", "esprima", "node_modules", "esprima"))) sh("npm", ["install", "--prefix", join(dir, "src", "esprima"), "--no-audit", "--no-fund", "--ignore-scripts", "--no-save", ...t.npmPkgs], { timeout: 900_000 });
    bin.odgenDir = dir;
  } catch (e) { bin.odgen = err(e); }
}

/** A pinned PyPI package in its own venv under tools/, so dependencies cannot clash. */
function installPip(t) {
  const venv = join(TOOLS_DIR, t.venv);
  const exe = join(venv, "bin", t.bin);
  if (existsSync(exe)) return exe;
  rmSync(venv, { recursive: true, force: true });
  sh(process.env.PYTHON || "python3.12", ["-m", "venv", venv]);
  sh(join(venv, "bin", "pip"), ["install", "-q", ...t.pip.split(" ")], { stdio: ["ignore", "inherit", "inherit"], timeout: 900_000 });
  return exe;
}

/** Pinned npm packages under tools/<name>, install scripts off. */
function installNpm(name, t) {
  const prefix = join(TOOLS_DIR, name);
  const exe = join(prefix, "node_modules", ".bin", name);
  if (existsSync(exe)) return exe;
  sh("npm", ["install", "--prefix", prefix, "--no-audit", "--no-fund", "--ignore-scripts", "--save-exact", ...t.npm], { timeout: 900_000 });
  return exe;
}

// ── CredData ──────────────────────────────────────────────────────────────

function walk(dir, out = []) {
  for (const e of readdirSync(dir).sort()) {
    const p = join(dir, e);
    const st = lstatSync(p);
    if (st.isDirectory()) walk(p, out);
    else if (st.isFile()) out.push(p);
  }
  return out;
}

/** File path as CredData's meta has it ("data/<repo>/..."), from what a tool printed. */
function relPath(tree, f) {
  let p = String(f).split(sep).join("/");
  if (p.startsWith("/")) p = relative(tree, p).split(sep).join("/");
  return p.replace(/^(\.\/)+/, "");
}

/** Run one tool under the sandbox, cwd = the split tree; null stdout on timeout. */
function run(cmd, args, tree, opts = {}) {
  const r = offline(cmd, args, { cwd: tree, timeout: TIMEOUT, ...opts });
  if (r.error?.code === "ETIMEDOUT" || r.signal === "SIGTERM") throw Object.assign(new Error("timeout after 30 minutes"), { timeout: true });
  if (r.error) throw r.error;
  return r;
}

const jsonl = (text) => text.split("\n").filter((l) => l.startsWith("{")).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);

// One entry per tool: how it scans the split tree (cwd = tree, target "data"),
// with the tool's default rules; only network verification and update checks
// are turned off. Each returns the exact command line and {file, line, rule}
// hits; `variants` are other output modes of the same scan.
const CRED_RUNNERS = {
  gitleaks(exe, tree) {
    const out = join(TOOLS_DIR, "gitleaks.json");
    const args = ["dir", join(tree, "data"), "--report-format", "json", "--report-path", out, "--exit-code", "0", "--no-banner", "--log-level", "error"];
    const g = run(exe, args, tree);
    if (g.status !== 0) throw new Error(`gitleaks: ${g.stderr}`);
    const hits = JSON.parse(readFileSync(out, "utf-8")).map((f) => ({ file: relPath(tree, f.File), line: f.StartLine, rule: f.RuleID }));
    return { command: `gitleaks ${args.join(" ").replaceAll(tree, "<tree>").replaceAll(TOOLS_DIR, "<tools>")}`, hits };
  },
  "detect-secrets"(exe, tree) {
    const files = walk(join(tree, "data")).map((p) => relative(tree, p));
    const hits = [];
    for (let i = 0; i < files.length; i += 400) {
      const r = run(exe, ["scan", "--all-files", ...files.slice(i, i + 400)], tree);
      if (r.status !== 0) throw new Error(`detect-secrets: ${r.stderr.slice(0, 500)}`);
      for (const [file, list] of Object.entries(JSON.parse(r.stdout).results || {})) {
        for (const x of list) hits.push({ file: relPath(tree, file), line: x.line_number, rule: x.type });
      }
    }
    return { command: "detect-secrets scan --all-files <every file, 400 per call>", hits };
  },
  trufflehog(exe, tree) {
    // --no-verification: verification calls each provider's API. The default
    // --results (verified,unverified,unknown) is the main row; the variant adds
    // filtered_unverified, the results TruffleHog itself filters out.
    const parse = (r) => jsonl(r.stdout).filter((o) => o.SourceMetadata).map((o) => ({ file: relPath(tree, o.SourceMetadata.Data.Filesystem.file), line: o.SourceMetadata.Data.Filesystem.line, rule: o.DetectorName }));
    const base = ["filesystem", "data", "--no-verification", "--json", "--no-update"];
    const r = run(exe, base, tree);
    if (r.status !== 0) throw new Error(`trufflehog: ${r.stderr.slice(-500)}`);
    const all = [...base, "--results=verified,unverified,unknown,filtered_unverified"];
    const r2 = run(exe, all, tree);
    if (r2.status !== 0) throw new Error(`trufflehog: ${r2.stderr.slice(-500)}`);
    return { command: `trufflehog ${base.join(" ")}`, hits: parse(r), variants: { "trufflehog, all results": { command: `trufflehog ${all.join(" ")}`, hits: parse(r2) } } };
  },
  noseyparker(exe, tree) {
    // Findings group identical secrets; `report` lists 3 locations per finding
    // by default. The variant lists every location (--max-matches 0).
    const ds = mkdtempSync(join(TOOLS_DIR, "np-"));
    try {
      const store = join(ds, "datastore.np");
      const s1 = run(exe, ["scan", "--datastore", store, "--progress", "never", "data"], tree);
      if (s1.status !== 0) throw new Error(`noseyparker scan: ${s1.stderr.slice(-500)}`);
      const rep = (extra) => {
        const r = run(exe, ["report", "--datastore", store, "--format", "jsonl", ...extra], tree);
        if (r.status !== 0) throw new Error(`noseyparker report: ${r.stderr.slice(-500)}`);
        const hits = [];
        for (const f of jsonl(r.stdout)) for (const m of f.matches || []) for (const pv of m.provenance || []) if (pv.kind === "file") hits.push({ file: relPath(tree, pv.path), line: m.location.source_span.start.line, rule: f.rule_text_id || f.rule_name });
        return hits;
      };
      return {
        command: "noseyparker scan --datastore <tmp> --progress never data && noseyparker report --datastore <tmp> --format jsonl",
        hits: rep([]),
        variants: { "noseyparker, every match": { command: "noseyparker scan --datastore <tmp> --progress never data && noseyparker report --datastore <tmp> --format jsonl --max-matches 0", hits: rep(["--max-matches", "0"]) } },
      };
    } finally {
      rmSync(ds, { recursive: true, force: true });
    }
  },
  kingfisher(exe, tree) {
    // Default output keeps one location per distinct secret; the variant
    // (--no-dedup) prints every occurrence.
    const parse = (r) => jsonl(r.stdout).filter((o) => o.finding?.path).map((o) => ({ file: relPath(tree, o.finding.path), line: o.finding.line, rule: o.rule?.id }));
    const base = ["scan", "data", "--no-validate", "--no-update-check", "--format", "jsonl"];
    const r = run(exe, base, tree);
    if (r.status !== 0 && r.status !== 200 && r.status !== 205) throw new Error(`kingfisher: exit ${r.status} ${r.stderr.slice(-500)}`);
    const nd = [...base, "--no-dedup"];
    const r2 = run(exe, nd, tree);
    if (r2.status !== 0 && r2.status !== 200 && r2.status !== 205) throw new Error(`kingfisher: exit ${r2.status} ${r2.stderr.slice(-500)}`);
    return { command: `kingfisher ${base.join(" ")}`, hits: parse(r), variants: { "kingfisher, every occurrence": { command: `kingfisher ${nd.join(" ")}`, hits: parse(r2) } } };
  },
  ripsecrets(exe, tree) {
    // Prints path:line:text per hit; exit 1 means secrets were found.
    const r = run(exe, ["data"], tree);
    if (r.status !== 0 && r.status !== 1) throw new Error(`ripsecrets: exit ${r.status} ${r.stderr.slice(-500)}`);
    const hits = [];
    for (const l of r.stdout.split("\n")) {
      const m = /^(data\/[^:]+):(\d+):/.exec(l);
      if (m) hits.push({ file: relPath(tree, m[1]), line: +m[2], rule: "ripsecrets" });
    }
    return { command: "ripsecrets data", hits };
  },
  credsweeper(exe, tree) {
    const out = join(TOOLS_DIR, "credsweeper.json");
    rmSync(out, { force: true });
    const r = run(exe, ["--path", "data", "--save-json", out], tree, { profile: OFFLINE_UNIX });
    if (r.status !== 0 || !existsSync(out)) throw new Error(`credsweeper: exit ${r.status} ${r.stderr.slice(-500)}`);
    const hits = [];
    for (const c of JSON.parse(readFileSync(out, "utf-8"))) for (const d of c.line_data_list || []) hits.push({ file: relPath(tree, d.path), line: d.line_num, rule: c.rule });
    rmSync(out, { force: true });
    return { command: "credsweeper --path data --save-json <out>", profile: "network denied except Unix-domain sockets", hits };
  },
  whispers(exe, tree) {
    const out = join(TOOLS_DIR, "whispers.json");
    rmSync(out, { force: true });
    const r = run(exe, ["data", "-o", out], tree);
    if (!existsSync(out)) throw new Error(`whispers: exit ${r.status} ${r.stderr.slice(-500)}`);
    const hits = JSON.parse(readFileSync(out, "utf-8") || "[]").map((x) => ({ file: relPath(tree, x.file), line: x.line, rule: x.rule_id }));
    rmSync(out, { force: true });
    return { command: "whispers data -o <out>", hits };
  },
  deepsecrets(exe, tree) {
    const out = join(TOOLS_DIR, "deepsecrets.sarif");
    rmSync(out, { force: true });
    const r = run(exe, ["--target-dir", "data", "--outfile", out], tree, { profile: OFFLINE_UNIX });
    if (!existsSync(out)) throw new Error(`deepsecrets: exit ${r.status} ${r.stderr.slice(-500)}`);
    const hits = [];
    for (const res of JSON.parse(readFileSync(out, "utf-8")).runs?.[0]?.results || []) {
      for (const loc of res.locations || []) hits.push({ file: relPath(tree, join("data", loc.physicalLocation.artifactLocation.uri)), line: loc.physicalLocation.region.startLine, rule: res.ruleId });
    }
    rmSync(out, { force: true });
    return { command: "deepsecrets --target-dir data --outfile <out>", profile: "network denied except Unix-domain sockets", hits };
  },
  secretlint(exe, tree) {
    const rc = join(TOOLS_DIR, "secretlint", ".secretlintrc.json");
    writeFileSync(rc, JSON.stringify({ rules: [{ id: "@secretlint/secretlint-rule-preset-recommend" }] }));
    // The json formatter embeds every file's full text and fails on the whole
    // tree (one string too long), so the unix formatter: path:line:col: message.
    const r = run(exe, ["--secretlintrc", rc, "--format", "unix", "--maskSecrets", "data/**/*"], tree);
    if (r.status !== 0 && r.status !== 1) throw new Error(`secretlint: exit ${r.status} ${r.stderr.slice(0, 500)}`);
    const hits = [];
    for (const l of r.stdout.split("\n")) {
      const m = /^(\S.*?):(\d+):\d+: .*\[(?:Error|Warning|Info)\/([^\]]+)\]\s*$/.exec(l);
      if (m) hits.push({ file: relPath(tree, m[1]), line: +m[2], rule: m[3] });
    }
    return { command: "secretlint --secretlintrc <preset-recommend only> --format unix --maskSecrets 'data/**/*'", hits };
  },
};

async function creddata(bin, only) {
  const { loadMeta, scoreHits, PRIMARY } = await import("./creddata.mjs");
  const base = join(CACHE, "creddata");
  const keep = inSplit("creddata");
  // Hard links of the split's files only, so the tools never read the other half.
  const tree = join(CACHE, `creddata-${currentSplit()}`);
  rmSync(tree, { recursive: true, force: true });
  for (const p of walk(join(base, "data"))) {
    const rel = relative(base, p).split(sep).join("/");
    if (!keep(rel)) continue;
    ensureDir(dirname(join(tree, rel)));
    linkSync(p, join(tree, rel));
  }
  const rows = loadMeta().filter((r) => keep(r.file));
  const out = {};
  const exes = { ...bin, "detect-secrets": bin.detectSecrets };
  try {
    for (const [name, runner] of Object.entries(CRED_RUNNERS)) {
      if (only && !only.includes(name)) continue;
      const meta = { version: TOOLS[name].version, ...(TOOLS[name].caveat ? { caveat: TOOLS[name].caveat } : {}) };
      const exe = exes[name];
      if (!exe || exe.error) { out[name] = { ...meta, error: exe?.error || "not installed" }; continue; }
      console.error(`[competitors] ${name}`);
      const t0 = Date.now();
      try {
        const res = runner(exe, tree);
        const seconds = Math.round((Date.now() - t0) / 100) / 10;
        out[name] = { ...meta, command: res.command, ...(res.profile ? { sandbox: res.profile } : {}), seconds, hits: res.hits.length, ...scoreHits(rows, res.hits) };
        for (const [v, vr] of Object.entries(res.variants || {})) {
          out[v] = { ...meta, variantOf: name, command: vr.command, seconds: null, hits: vr.hits.length, ...scoreHits(rows, vr.hits) };
        }
      } catch (e) {
        out[name] = { ...meta, error: e.timeout ? "timeout after 30 minutes" : String(e.message || e).slice(0, 500), seconds: Math.round((Date.now() - t0) / 1000) };
      }
    }
  } finally {
    rmSync(tree, { recursive: true, force: true });
  }
  return { tools: out, primary: PRIMARY, families: [...PRIMARY, "partial", "out"], skipped: SKIPPED };
}

// ── Malware (GuardDog) ────────────────────────────────────────────────────

async function malware(bin) {
  const M = await import("./malware.mjs");
  const { untar, unpackTgz } = await import("../../lib/deps/source.js");
  const { unzip } = await import("../../lib/deps/python/source.js");
  const { gunzipSync } = await import("node:zlib");
  const results = [];
  const guard = (eco, dir) => {
    const r = spawnSync(bin.guarddog, [eco, "scan", dir, "--output-format", "json"], {
      encoding: "utf-8", maxBuffer: 1 << 30, timeout: 600_000,
      env: { PATH: process.env.PATH, HOME: TOOLS_DIR, SEMGREP_SEND_METRICS: "off" },
    });
    let j = null;
    try { j = JSON.parse(r.stdout.slice(r.stdout.indexOf("{"))); } catch { /* reported below */ }
    if (!j) return { error: `exit ${r.status}: ${(r.stderr || "").slice(-200)}` };
    return { issues: j.issues ?? 0, risk: j.risk_score?.label || null, rules: Object.entries(j.results || {}).filter(([, v]) => v && (Array.isArray(v) ? v.length : typeof v === "object" ? Object.keys(v).length : v)).map(([k]) => k), errors: Object.keys(j.errors || {}).length };
  };
  try {
    await M.fetchData(); // the split's archives only, hash checked, extracted under MALWARE_DIR
    const { sample } = JSON.parse(readFileSync(join(CACHE, "malware-sample.json"), "utf-8"));
    const keepM = inSplit("malware");
    for (const s of sample.filter((x) => keepM(x.path))) {
      const dir = join(MALWARE_DIR, "x", s.id);
      const root = existsSync(dir) ? M.findRoot(dir, s.eco) : null;
      if (!root) { results.push({ group: `malicious ${s.eco} ${s.cat}`, id: s.path, excluded: true }); continue; }
      // Same payload rows as Penthera's (E11b § 7), kind decided from the files alone.
      const kind = s.eco === "npm" ? M.payloadKind(root) : null;
      const r = { id: s.path, ...guard(s.eco, root) };
      results.push({ group: `malicious ${s.eco} ${s.cat}`, ...r });
      if (kind) results.push({ group: `malicious ${s.eco} ${s.cat}, ${kind.payload ? "payload" : "no payload"}`, ...r });
    }
  } finally {
    rmSync(MALWARE_DIR, { recursive: true, force: true });
  }
  const list = JSON.parse(readFileSync(join(CACHE, "benign", "list.json"), "utf-8"));
  const keepB = inSplit("benign");
  const tmp = mkdtempSync(join(CACHE, "benign-x-"));
  try {
    for (const eco of ["npm", "pypi"]) {
      for (const b of list[eco].filter((x) => keepB(`${eco}/${x.name}@${x.version}`))) {
        const buf = readFileSync(join(CACHE, "benign", eco, `${encodeURIComponent(b.name)}.json.bin`));
        let files;
        try {
          files = eco === "npm" ? unpackTgz(buf) : buf.readUInt32LE(0) === 0x04034b50 ? unzip(buf) : untar(gunzipSync(buf));
        } catch { results.push({ group: `benign ${eco}`, id: b.name, excluded: true }); continue; }
        const dir = join(tmp, eco, encodeURIComponent(b.name));
        for (const [rel, data] of files) {
          const p = join(dir, rel);
          if (!p.startsWith(dir + sep)) continue;
          ensureDir(dirname(p));
          writeFileSync(p, data);
        }
        results.push({ group: `benign ${eco}`, id: `${b.name}@${b.version}`, ...guard(eco, dir) });
      }
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
  const table = {};
  for (const r of results) {
    const t = (table[r.group] ||= { flagged: 0, risky: 0, n: 0, excluded: 0, toolErrors: 0, rules: {}, labels: {} });
    if (r.excluded) { t.excluded++; continue; }
    if (r.error) { t.toolErrors++; continue; }
    t.n++;
    if (r.issues > 0) t.flagged++;
    if (r.risk && r.risk !== "no_risks_detected") t.risky++;
    t.labels[r.risk || "none"] = (t.labels[r.risk || "none"] || 0) + 1;
    for (const k of r.rules) t.rules[k] = (t.rules[k] || 0) + 1;
  }
  return { guarddog: table, failures: results.filter((r) => r.error).slice(0, 5).map((r) => r.error) };
}

// ── SecBench.js (njsscan, CodeQL, Semgrep) ────────────────────────────────

// A finding counts for a class when one of its rule's CWEs is that class's:
// OS command injection (CWE-78) or code injection (CWE-94/95).
const CWE_CLASS = { 78: "command-injection", 94: "code-injection", 95: "code-injection" };
const classesOf = (texts) => [...new Set(texts.flatMap((t) => [...String(t).matchAll(/cwe[-/]0*(\d+)/gi)].map((m) => CWE_CLASS[Number(m[1])]).filter(Boolean)))];

/** Every njsscan finding as { file, line, cls }, from its JSON report; cls null when no class matches. */
export function njsscanHits(report, root) {
  const hits = [];
  for (const group of Object.values(report || {})) {
    if (!group || typeof group !== "object") continue;
    for (const rule of Object.values(group)) {
      if (!rule || typeof rule !== "object" || !Array.isArray(rule.files)) continue;
      const cls = classesOf([rule.metadata?.cwe || ""]);
      for (const f of rule.files) {
        const file = String(f.file_path || "").startsWith(root) ? f.file_path.slice(root.length + 1) : f.file_path;
        for (const c of cls.length ? cls : [null]) hits.push({ file, line: f.match_lines?.[0] ?? null, cls: c });
      }
    }
  }
  return hits;
}

/**
 * Every result of a SARIF log as { file, line, rule, cls }: one hit per class
 * its rule's CWE tags name (CodeQL "external/cwe/cwe-078", Semgrep "CWE-78:
 * ..."), or one with cls null. File paths relative to the scanned root.
 */
export function sarifHits(sarif, root = "") {
  const hits = [];
  for (const run of sarif?.runs || []) {
    const comps = [run.tool?.driver, ...(run.tool?.extensions || [])].filter(Boolean);
    const byId = new Map(comps.flatMap((c) => (c.rules || []).map((r) => [r.id, r])));
    for (const res of run.results || []) {
      const ref = res.rule || {};
      const rule = byId.get(res.ruleId ?? ref.id) || comps[ref.toolComponent?.index ?? 0]?.rules?.[ref.index ?? res.ruleIndex ?? -1] || {};
      const cls = classesOf([...(rule.properties?.tags || []), ...(res.properties?.tags || [])]);
      const loc = res.locations?.[0]?.physicalLocation || {};
      let file = decodeURIComponent(String(loc.artifactLocation?.uri || "")).replace(/^file:\/\//, "");
      if (root && file.startsWith(root + "/")) file = file.slice(root.length + 1);
      file = file.replace(/^(\.\/)+/, "");
      for (const c of cls.length ? cls : [null]) hits.push({ file, line: loc.region?.startLine ?? null, rule: res.ruleId ?? rule.id ?? null, cls: c });
    }
  }
  return hits;
}

/**
 * offline(), asynchronous, so several packages scan at once. The command runs
 * in its own process group, killed whole at the deadline (CodeQL starts a JVM).
 */
function offlineAsync(cmd, args, { profile = OFFLINE, cwd, env = {}, timeout = 600_000, stdoutFile = null } = {}) {
  return new Promise((resolve) => {
    const fd = stdoutFile ? openSync(stdoutFile, "w") : "ignore";
    const p = spawn("sandbox-exec", ["-p", profile, cmd, ...args], {
      cwd, detached: true, stdio: ["ignore", fd, "pipe"],
      env: { PATH: process.env.PATH, HOME: TOOLS_DIR, SEMGREP_SEND_METRICS: "off", SEMGREP_ENABLE_VERSION_CHECK: "0", ...env },
    });
    let stderr = "";
    let timedOut = false;
    p.stderr.on("data", (d) => { stderr = (stderr + d).slice(-4000); });
    const timer = setTimeout(() => { timedOut = true; try { process.kill(-p.pid, "SIGKILL"); } catch { /* gone */ } }, timeout);
    const done = (r) => { clearTimeout(timer); if (typeof fd === "number") closeSync(fd); resolve(r); };
    p.on("close", (status) => done({ status, stderr, timedOut }));
    p.on("error", (e) => done({ status: -1, stderr: String(e), timedOut }));
  });
}

async function pool(items, n, fn) {
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => { while (i < items.length) { const k = i++; await fn(items[k], k); } }));
}

const PKG_TIMEOUT = { njsscan: 600_000, codeql: 900_000, semgrep: 600_000, "eslint-plugin-security": 600_000, bearer: 600_000, graudit: 600_000, odgen: 600_000 };
const JOBS = { njsscan: 4, codeql: 3, semgrep: 3, "eslint-plugin-security": 4, bearer: 3, graudit: 6, odgen: 6 };

// Rules with no CWE in their output, classed by what the rule looks for.
const ESLINT_CLASS = { "security/detect-child-process": "command-injection", "security/detect-eval-with-expression": "code-injection", "security/detect-non-literal-require": "code-injection" };
// graudit prints matching lines only, not which signature matched: a line is
// classed by the js.db signatures it matches (POSIX classes written as \s).
const GRAUDIT_CLASS = [
  [/\.(spawn|exec)(File)?(Sync)?\([^);]*(['"] *\+|\$\{)/, "command-injection"],
  [/eval\s*\(/, "code-injection"],
  [/set(Interval|Timeout)\s*\([^,})]*[Rr]eq(uest)?\.[A-Za-z0-9]+/, "code-injection"],
];
const ODGEN_TYPES = { os_command: "command-injection", code_exec: "code-injection" };
const timeoutErr = () => Object.assign(new Error("timeout"), { timeout: true });

/**
 * ODGen's attack paths (logs/results_tmp.log), one hit per path: the file is
 * the last package file on the path, the class comes from the sink the path
 * ends in (its child_process stubs are command injection, also under
 * code_exec), else from the run's vulnerability type.
 */
export function odgenHits(log, roots, type) {
  const hits = [];
  for (const block of log.split(/^=+$/m)) {
    const entries = [...block.matchAll(/^\$FilePath\$(.+)\n(?:Line (\d+))?([\s\S]*?)(?=^\$FilePath\$|(?![\s\S]))/gm)].map((m) => ({ path: m[1].trim(), line: m[2] ? +m[2] : null, text: m[3] || "" }));
    if (!entries.length) continue;
    const tail = entries[entries.length - 1].text;
    const cls = /sink_hqbpillvul_(exec|execFile|execSync|spawn|spawnSync)\b/.test(tail) ? "command-injection" : /sink_hqbpillvul_db\b/.test(tail) ? null : ODGEN_TYPES[type];
    const rel = (p) => { const r = [].concat(roots).find((x) => p.startsWith(x + "/")); return r ? p.slice(r.length + 1) : null; };
    const mine = entries.filter((e) => rel(e.path));
    const last = mine[mine.length - 1];
    if (last) hits.push({ file: rel(last.path), line: last.line, rule: type, cls });
  }
  return hits;
}

export const SAST_RUNNERS = {
  async njsscan(bin, dir, work) {
    const out = join(work, "njsscan.json");
    const r = await offlineAsync(bin.njsscan, ["--json", "-o", out, dir], { profile: OFFLINE_UNIX, timeout: PKG_TIMEOUT.njsscan, env: { PATH: `${dirname(bin.njsscan)}:${process.env.PATH}` } });
    if (r.timedOut) throw Object.assign(new Error("timeout"), { timeout: true });
    if (!existsSync(out)) throw new Error(r.stderr.slice(-300));
    const rep = JSON.parse(readFileSync(out, "utf-8"));
    if (rep.errors?.length) throw new Error(String(rep.errors[0]));
    return { hits: njsscanHits(rep, dir) };
  },
  async codeql(bin, dir, work) {
    // build-mode none: JavaScript needs no build; the extractor runs node for
    // TypeScript files, so node stays on PATH. --threads/--ram per job.
    const db = join(work, "codeql-db");
    const out = join(work, "codeql.sarif");
    const deadline = Date.now() + PKG_TIMEOUT.codeql;
    const c = await offlineAsync(bin.codeql, ["database", "create", db, "--language=javascript", "--build-mode=none", `--source-root=${dir}`, "--threads=3", "--overwrite", "--quiet"], { cwd: work, timeout: PKG_TIMEOUT.codeql });
    if (c.timedOut) throw Object.assign(new Error("timeout"), { timeout: true });
    if (c.status !== 0) throw new Error(`database create: exit ${c.status} ${c.stderr.slice(-300)}`);
    const a = await offlineAsync(bin.codeql, ["database", "analyze", db, TOOLS.codeql.suite, "--format=sarif-latest", `--output=${out}`, "--threads=3", "--ram=4096", "--quiet"], { cwd: work, timeout: Math.max(1000, deadline - Date.now()) });
    if (a.timedOut) throw Object.assign(new Error("timeout"), { timeout: true });
    if (a.status !== 0 || !existsSync(out)) throw new Error(`database analyze: exit ${a.status} ${a.stderr.slice(-300)}`);
    return { hits: sarifHits(JSON.parse(readFileSync(out, "utf-8")), dir) };
  },
  async semgrep(bin, dir, work) {
    // cwd = the package, target ".": Semgrep applies its default ignore list
    // (build/, dist/, test/ folders, minified files, ...) there. The variant
    // puts an empty .semgrepignore in the package, which turns that list off.
    const once = async (out) => {
      const r = await offlineAsync(bin.semgrep, ["scan", "--metrics=off", "--disable-version-check", "--config", bin.semgrepRules, "--sarif", "-o", out, "-q", "-j", "2", "."], { cwd: dir, timeout: PKG_TIMEOUT.semgrep });
      if (r.timedOut) throw Object.assign(new Error("timeout"), { timeout: true });
      if (r.status > 1 || !existsSync(out)) throw new Error(`exit ${r.status} ${r.stderr.slice(-300)}`);
      return sarifHits(JSON.parse(readFileSync(out, "utf-8")), dir);
    };
    const hits = await once(join(work, "semgrep.sarif"));
    writeFileSync(join(dir, ".semgrepignore"), "");
    let all;
    try { all = { hits: await once(join(work, "semgrep-all.sarif")) }; } catch (e) { all = { error: e }; }
    rmSync(join(dir, ".semgrepignore"), { force: true });
    return { hits, variants: { "semgrep, every file": all } };
  },
  async "eslint-plugin-security"(bin, dir, work) {
    // The plugin's recommended config on ESLint's defaults (.js parses as an
    // ES module: on these packages that fails on far fewer files than
    // CommonJS, which rejects the transpiled-from source many ship). The config
    // is written into the package because flat-config globs are relative to it.
    const cfg = join(dir, ".penthera-eslint.config.mjs");
    writeFileSync(cfg, `import security from ${JSON.stringify(bin.eslintPlugin)};\nexport default [{ files: ["**/*.js", "**/*.cjs", "**/*.mjs", "**/*.jsx"] }, security.configs.recommended];\n`);
    const out = join(work, "eslint.json");
    const r = await offlineAsync(process.execPath, [bin["eslint-plugin-security"], "--config", cfg, "--format", "json", "--no-warn-ignored", "--no-error-on-unmatched-pattern", "--no-inline-config", "--ignore-pattern", ".penthera-eslint.config.mjs", "."], { cwd: dir, timeout: PKG_TIMEOUT["eslint-plugin-security"], stdoutFile: out });
    rmSync(cfg, { force: true });
    if (r.timedOut) throw timeoutErr();
    if (r.status > 1) throw new Error(`exit ${r.status} ${r.stderr.slice(-300)}`);
    const hits = [];
    let parseErrors = 0;
    for (const f of JSON.parse(readFileSync(out, "utf-8"))) {
      const file = relative(realpathSync(dir), f.filePath).split(sep).join("/");
      for (const m of f.messages) {
        if (m.fatal) { parseErrors++; continue; }
        hits.push({ file, line: m.line, rule: m.ruleId, cls: ESLINT_CLASS[m.ruleId] || null });
      }
    }
    return { hits, parseErrors };
  },
  async bearer(bin, dir, work) {
    // Default rules off (they are fetched at scan time), the pinned
    // bearer-rules folder in their place; JSON, because its SARIF has no CWEs.
    const out = join(work, "bearer.json");
    const r = await offlineAsync(bin.bearer, ["scan", ".", "--format", "json", "--output", out, "--quiet", "--disable-version-check", "--disable-default-rules", "--external-rule-dir", bin.bearerRules, "--exit-code", "0", "--force", "--no-extract"], { cwd: dir, profile: OFFLINE_LOOPBACK, timeout: PKG_TIMEOUT.bearer });
    if (r.timedOut) throw timeoutErr();
    if (r.status !== 0 || !existsSync(out)) throw new Error(`exit ${r.status} ${r.stderr.slice(-300)}`);
    const hits = [];
    for (const list of Object.values(JSON.parse(readFileSync(out, "utf-8") || "{}"))) {
      for (const f of list || []) {
        const cls = classesOf((f.cwe_ids || []).map((c) => `CWE-${c}`));
        for (const c of cls.length ? cls : [null]) hits.push({ file: String(f.filename).replace(/^(\.\/)+/, ""), line: f.line_number ?? null, rule: f.id, cls: c });
      }
    }
    return { hits };
  },
  async graudit(bin, dir, work) {
    const out = join(work, "graudit.txt");
    const r = await offlineAsync(bin.graudit, ["-d", "js", "-B", "-z", "-c", "0", "."], { cwd: dir, timeout: PKG_TIMEOUT.graudit, stdoutFile: out, env: { GRDIR: join(dirname(bin.graudit), "signatures") } });
    if (r.timedOut) throw timeoutErr();
    if (r.status !== 0 && r.status !== 1) throw new Error(`exit ${r.status} ${r.stderr.slice(-300)}`);
    const hits = [];
    for (const l of readFileSync(out, "utf-8").split("\n")) {
      const m = /^(?:\.\/)?([^:]+):(\d+):(.*)$/.exec(l);
      if (!m) continue;
      const cls = [...new Set(GRAUDIT_CLASS.filter(([re]) => re.test(m[3])).map(([, c]) => c))];
      for (const c of cls.length ? cls : [null]) hits.push({ file: m[1], line: +m[2], rule: "graudit js", cls: c });
    }
    return { hits };
  },
  async odgen(bin, dir, work) {
    // ODGen writes logs and a temp env into its working folder, so each
    // package gets its own copy. One run per vulnerability type, with the
    // package-mode flags from its README (-m module, -a run all exports, -q
    // stop at the first finding) and its own 120 s per-module timeout.
    const tool = join(work, "odgen");
    for (const p of ["odgen.py", "src", "builtin_packages"]) cpSync(join(bin.odgenDir, p), join(tool, p), { recursive: true });
    const deadline = Date.now() + PKG_TIMEOUT.odgen;
    const hits = [];
    for (const [type, cls] of Object.entries(ODGEN_TYPES)) {
      rmSync(join(tool, "logs"), { recursive: true, force: true });
      const out = join(work, `odgen-${type}.txt`);
      const r = await offlineAsync(bin.odgen, ["odgen.py", dir, "-maq", "-t", type, "--timeout", "120"], { cwd: tool, timeout: Math.max(1000, deadline - Date.now()), stdoutFile: out });
      if (r.timedOut) throw timeoutErr();
      const succ = join(tool, "logs", "succ.log");
      const paths = join(tool, "logs", "results_tmp.log");
      const found = existsSync(succ) && readFileSync(succ, "utf-8").includes(`${type} is detected`);
      const mine = found && existsSync(paths) ? odgenHits(readFileSync(paths, "utf-8"), [dir, realpathSync(dir)], type) : [];
      hits.push(...mine);
      if (found && !mine.length) hits.push({ file: null, line: null, rule: type, cls });
      rmSync(join(tool, "logs"), { recursive: true, force: true });
    }
    return { hits };
  },
};

const SAST_META = {
  njsscan: { command: "njsscan --json -o <out> <package>", sandbox: "network denied except Unix-domain sockets" },
  codeql: {
    command: `codeql database create <db> --language=javascript --build-mode=none --source-root=<package> --threads=3 && codeql database analyze <db> ${TOOLS.codeql.suite} --format=sarif-latest --output=<out> --threads=3 --ram=4096`,
    sandbox: "network denied", suite: "javascript-security-extended (bundled codeql/javascript-queries)", license: TOOLS.codeql.license,
  },
  semgrep: {
    command: `semgrep scan --metrics=off --disable-version-check --config <semgrep-rules@${TOOLS.semgrep.rules.commit.slice(0, 7)}>/javascript --sarif -o <out> -q -j 2 . (cwd = the package)`,
    sandbox: "network denied", rules: `${TOOLS.semgrep.rules.repo} @ ${TOOLS.semgrep.rules.commit} (${TOOLS.semgrep.rules.date}), javascript/ only`, license: TOOLS.semgrep.rules.license,
  },
  "semgrep, every file": { variantOf: "semgrep", command: "as semgrep, with an empty .semgrepignore in the package (Semgrep's default ignore list off)", sandbox: "network denied" },
  "eslint-plugin-security": {
    command: `eslint ${TOOLS["eslint-plugin-security"].eslint} --config <plugin recommended config, ESLint defaults> --format json --no-warn-ignored --no-error-on-unmatched-pattern --no-inline-config . (cwd = the package)`,
    sandbox: "network denied", classes: "by rule meaning: detect-child-process = command injection; detect-eval-with-expression, detect-non-literal-require = code injection",
  },
  bearer: {
    command: `bearer scan . --format json --output <out> --quiet --disable-version-check --disable-default-rules --external-rule-dir <bearer-rules ${TOOLS.bearer.rules.version} javascript> --exit-code 0 --force --no-extract (cwd = the package)`,
    sandbox: "network denied except TCP on loopback (its workers)", rules: `bearer-rules v${TOOLS.bearer.rules.version}, javascript`,
  },
  graudit: { command: "graudit -d js -B -z -c 0 . (cwd = the package)", sandbox: "network denied", classes: "by signature: .exec/.spawn with a concatenated or templated argument = command injection; eval( and setTimeout/setInterval with request data = code injection" },
  odgen: { command: "python odgen.py <package> -maq -t os_command --timeout 120, then -t code_exec (cwd = a per-package copy of ODGen)", sandbox: "network denied", classes: "os_command = command injection, code_exec = code injection; the file is the last package file on each attack path" },
};

/** Unpack an npm tarball into dir (paths without the "package/" prefix). */
async function unpackTo(tgzPath, dir) {
  const { unpackTgz } = await import("../../lib/deps/source.js");
  for (const [rel, buf] of unpackTgz(readFileSync(tgzPath))) {
    const f = join(dir, rel);
    if (!f.startsWith(dir + sep)) continue;
    ensureDir(dirname(f));
    writeFileSync(f, buf);
  }
}

/** Is every IP connection refused under this profile? A curl must fail. */
function sandboxCheck(profile) {
  const r = spawnSync("sandbox-exec", ["-p", profile, "curl", "-sS", "-m", "10", "-o", "/dev/null", "https://registry.npmjs.org/"], { encoding: "utf-8", timeout: 30_000 });
  return { curlExit: r.status, blocked: r.status !== 0, stderr: (r.stderr || "").trim().slice(0, 200) };
}

const median = (a) => { if (!a.length) return null; const s = [...a].sort((x, y) => x - y); return s.length % 2 ? s[(s.length - 1) / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2; };
const noise = (counts) => ({ packages: counts.length, median: median(counts), mean: counts.length ? Math.round((counts.reduce((a, b) => a + b, 0) / counts.length) * 10) / 10 : null, max: counts.length ? Math.max(...counts) : null });

async function secbench(bin, only) {
  const S = await import("./secbench.mjs");
  const status = JSON.parse(readFileSync(join(CACHE, "secbench-status.json"), "utf-8"));
  const keep = inSplit("secbench");
  const vulns = S.entries().filter((x) => S.CLASSES[x.cls] && keep(`${x.cls}/${x.folder}`) && status[`${x.cls}/${x.folder}`] === "ok");
  const notFetched = S.entries().filter((x) => S.CLASSES[x.cls] && keep(`${x.cls}/${x.folder}`) && status[`${x.cls}/${x.folder}`] !== "ok").length;
  // The benign npm half of the malware harness: a library-mode false alarm is
  // a package with at least one command or code injection finding anywhere.
  const blist = JSON.parse(readFileSync(join(CACHE, "benign", "list.json"), "utf-8")).npm;
  const keepB = inSplit("benign");
  const benign = blist.filter((b) => keepB(`npm/${b.name}@${b.version}`));
  const checks = { network: sandboxCheck(OFFLINE), "network, Unix sockets allowed": sandboxCheck(OFFLINE_UNIX), "network, loopback allowed": sandboxCheck(OFFLINE_LOOPBACK) };
  if (Object.values(checks).some((c) => !c.blocked)) throw new Error(`the sandbox let a curl through: ${JSON.stringify(checks)}`);
  const out = {};
  for (const name of Object.keys(SAST_RUNNERS)) {
    if (only && !only.includes(name)) continue;
    const exe = bin[name];
    if (!exe || exe.error) { out[name] = { version: TOOLS[name].version, error: exe?.error || "not installed" }; continue; }
    console.error(`[competitors] secbench ${name}`);
    const rows = {}; // tool or variant -> { per, counts, benign }
    const row = (k) => (rows[k] ||= { per: {}, counts: [], benign: { n: 0, flagged: 0, errors: 0, timeouts: 0, byClass: {}, flaggedIds: [], counts: [] } });
    const fail = (p, e) => { if (e.timeout) p.timeouts = (p.timeouts || 0) + 1; else { p.errors = (p.errors || 0) + 1; p.lastError = String(e.message || e).slice(-300); } };
    const tmp = mkdtempSync(join(CACHE, `secbench-${name}-`));
    const t0 = Date.now();
    try {
      await pool(vulns, JOBS[name], async (e, i) => {
        const key = `${e.cls}/${e.folder}`;
        const work = join(tmp, `v${i}`);
        const dir = join(work, "pkg");
        ensureDir(dir);
        await unpackTo(join(CACHE, "secbench-pkgs", `${key}.tgz`), dir);
        let res;
        try { res = await SAST_RUNNERS[name](bin, dir, work); } catch (err) { res = { error: err }; }
        for (const [k, r] of [[name, res], ...Object.entries(res.variants || {})]) {
          const p = (row(k).per[e.cls] ||= { strict: [0, 0], lenient: [0, 0], found: [] });
          if (r.error) { fail(p, r.error); continue; }
          if (r.parseErrors) p.parseErrorFiles = (p.parseErrorFiles || 0) + r.parseErrors;
          row(k).counts.push(r.hits.length ? new Set(r.hits.map((h) => `${h.file}:${h.line}:${h.rule ?? ""}`)).size : 0);
          const mine = r.hits.filter((h) => h.cls === e.cls);
          p.lenient[1]++;
          if (mine.length) p.lenient[0]++;
          if (e.sinkFile) {
            p.strict[1]++;
            if (mine.some((h) => h.file === e.sinkFile)) { p.strict[0]++; p.found.push(e.folder); }
          }
        }
        rmSync(work, { recursive: true, force: true });
      });
      const vSeconds = Math.round((Date.now() - t0) / 1000);
      const t1 = Date.now();
      await pool(benign, JOBS[name], async (b, i) => {
        const work = join(tmp, `b${i}`);
        const dir = join(work, "pkg");
        ensureDir(dir);
        try { await unpackTo(join(CACHE, "benign", "npm", `${encodeURIComponent(b.name)}.json.bin`), dir); } catch { rmSync(work, { recursive: true, force: true }); return; }
        let res;
        try { res = await SAST_RUNNERS[name](bin, dir, work); } catch (err) { res = { error: err }; }
        for (const [k, r] of [[name, res], ...Object.entries(res.variants || {})]) {
          const B = row(k).benign;
          if (r.error) { fail(B, r.error); continue; }
          if (r.parseErrors) B.parseErrorFiles = (B.parseErrorFiles || 0) + r.parseErrors;
          B.n++;
          B.counts.push(new Set(r.hits.map((h) => `${h.file}:${h.line}:${h.rule ?? ""}`)).size);
          const cls = [...new Set(r.hits.map((h) => h.cls).filter(Boolean))];
          if (cls.length) { B.flagged++; B.flaggedIds.push(`${b.name}@${b.version}`); }
          for (const c of cls) B.byClass[c] = (B.byClass[c] || 0) + 1;
        }
        rmSync(work, { recursive: true, force: true });
      });
      const bSeconds = Math.round((Date.now() - t1) / 1000);
      for (const [k, r] of Object.entries(rows)) {
        const { counts, ...B } = r.benign;
        for (const p of Object.values(r.per)) p.found.sort();
        B.flaggedIds.sort();
        out[k] = { version: TOOLS[name].version, ...SAST_META[k], seconds: k === name ? vSeconds : null, benignSeconds: k === name ? bSeconds : null, per: r.per, findingsPerPackage: noise(r.counts), benign: { ...B, findingsPerPackage: noise(counts) } };
      }
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  }
  return { tools: out, sandboxCheck: checks, vulnerabilities: vulns.length, notFetched, benignPackages: benign.length };
}

export async function runCompetitors(which, tools = null) {
  const bin = await install();
  const split = currentSplit();
  ensureDir(RESULTS);
  for (const name of which) {
    const res = name === "creddata" ? await creddata(bin, tools) : name === "malware" ? await malware(bin) : name === "secbench" ? await secbench(bin, tools) : null;
    if (!res) continue;
    const file = join(RESULTS, `competitors-${name}.${split}.json`);
    // A --tools run replaces only the tools it ran and keeps the rest.
    if ((name === "creddata" || name === "secbench") && tools && existsSync(file)) {
      const prev = JSON.parse(readFileSync(file, "utf-8"));
      res.tools = { ...prev.tools, ...res.tools };
    }
    writeFileSync(file, JSON.stringify({ split, date: new Date().toISOString(), pins: TOOLS, ...res }, null, 2));
    const md = markdown(name, res);
    writeFileSync(file.replace(/\.json$/, ".md"), md + "\n");
    console.log(md);
  }
}

function markdown(name, res) {
  const L = [`## Reference tools: ${name} (split ${currentSplit()})`, ""];
  if (name === "creddata") {
    const ok = Object.entries(res.tools).filter(([, s]) => !s.error);
    L.push("Rows marked \"variant\" are another output mode of the scan above them. Scored with `scoreHits` (creddata.mjs): a hit unit is a distinct file:line.", "");
    L.push("| Tool | Version | Hits | Hit lines | Precision, labelled | Strict precision | Recall, in scope (row) | Recall, all T rows (row) | Recall, file (hit on a T row) | Seconds | Caveat |", "|---|---|---:|---:|---|---|---|---|---|---:|---|");
    for (const [tool, s] of ok) {
      const all = Object.entries(s.rec).filter(([k]) => k.startsWith("family:")).reduce((a, [, v]) => [a[0] + v.found, a[1] + v.n], [0, 0]);
      L.push(`| ${tool}${s.variantOf ? " (variant)" : ""} | ${s.version ?? ""} | ${s.hits} | ${s.prec.all.units} | ${fmt(s.prec.all.correct, s.prec.all.labelled)} | ${fmt(s.prec.all.correct, s.prec.all.units)} | ${fmt(s.rec.primary.found, s.rec.primary.n)} | ${fmt(...all)} | ${fmt(s.rec["file:matched"].found, s.rec["file:matched"].n)} | ${s.seconds ?? (s.variantOf ? "in the row above" : "")} | ${s.caveat || ""} |`);
    }
    L.push("", "| Tool | provider | private-key | password | api-key | partial | out |", "|---|---|---|---|---|---|---|");
    for (const [tool, s] of ok) L.push(`| ${tool} | ${res.families.map((f) => (s.rec[`family:${f}`] ? fmt(s.rec[`family:${f}`].found, s.rec[`family:${f}`].n) : "n/a")).join(" | ")} |`);
    L.push("", "Commands (cwd = the split's hard-link tree, network denied by `sandbox-exec`):", "");
    for (const [tool, s] of ok) if (s.command) L.push(`- ${tool}: \`${s.command}\`${s.sandbox ? ` (${s.sandbox})` : ""}`);
    const failed = Object.entries(res.tools).filter(([, s]) => s.error);
    const skipped = Object.entries(res.skipped || {});
    if (failed.length || skipped.length) {
      L.push("", "Not measured:", "");
      for (const [tool, s] of failed) L.push(`- ${tool} ${s.version ?? ""}: ${s.error}`);
      for (const [tool, why] of skipped) L.push(`- ${tool}: ${why}`);
    }
  } else if (name === "secbench") {
    L.push(`${res.vulnerabilities ?? "?"} vulnerabilities with a fetched tarball (${res.notFetched ?? "?"} not on the registry), ${res.benignPackages ?? "?"} benign npm packages. A finding counts for a class by its rule's CWE (78 command injection, 94/95 code injection), or, for tools whose output has no CWE, by what the rule looks for (listed with the commands). Strict: a class finding in the sink file; lenient: anywhere in the package. A package the tool failed on or timed out on is left out of that row's denominators and counted under Errors or Timeouts. Benign false alarm: at least one command or code injection finding anywhere. Findings per package: distinct file:line:rule, all rules.`, "");
    if (res.sandboxCheck) L.push(`Sandbox check: a curl to the npm registry under each profile exits ${Object.entries(res.sandboxCheck).map(([k, v]) => `${v.curlExit} (${k})`).join(", ")}, so the network is blocked.`, "");
    L.push("| Tool | Version | Class | Strict recall (sink file) | Lenient recall (anywhere) | Errors | Timeouts |", "|---|---|---|---|---|---:|---:|");
    for (const [tool, t] of Object.entries(res.tools)) {
      if (t.error) continue;
      for (const [cls, v] of Object.entries(t.per)) L.push(`| ${tool}${t.variantOf ? " (variant)" : ""} | ${t.version} | ${cls} | ${fmt(...v.strict)} | ${fmt(...v.lenient)} | ${v.errors || 0} | ${v.timeouts || 0} |`);
    }
    L.push("", "| Tool | Benign npm false alarms | Command injection | Code injection | Errors, timeouts | Findings per package, vulns (median, mean, max) | Findings per package, benign (median, mean, max) | Seconds, vulns | Seconds, benign |", "|---|---|---:|---:|---|---|---|---:|---:|");
    const np = (x) => (x ? `${x.median}, ${x.mean}, ${x.max}` : "n/a");
    for (const [tool, t] of Object.entries(res.tools)) {
      if (t.error) continue;
      const B = t.benign;
      L.push(`| ${tool}${t.variantOf ? " (variant)" : ""} | ${B ? fmt(B.flagged, B.n) : "not run"} | ${B ? B.byClass["command-injection"] || 0 : ""} | ${B ? B.byClass["code-injection"] || 0 : ""} | ${B ? `${B.errors}, ${B.timeouts}` : ""} | ${np(t.findingsPerPackage)} | ${np(B?.findingsPerPackage)} | ${t.seconds ?? (t.variantOf ? "in the row above" : "")} | ${t.benignSeconds ?? (t.variantOf ? "in the row above" : "")} |`);
    }
    L.push("", "Commands (each package unpacked to a temp folder, network denied by `sandbox-exec`):", "");
    for (const [tool, t] of Object.entries(res.tools)) if (!t.error) L.push(`- ${tool}: \`${t.command}\` (${t.sandbox})${t.suite ? `; suite ${t.suite}` : ""}${t.rules ? `; rules ${t.rules}` : ""}${t.classes ? `; classes ${t.classes}` : ""}${t.license ? `; license: ${t.license}` : ""}`);
    const failed = Object.entries(res.tools).filter(([, t]) => t.error);
    if (failed.length) {
      L.push("", "Not measured:", "");
      for (const [tool, t] of failed) L.push(`- ${tool} ${t.version ?? ""}: ${t.error}`);
    }
  } else {
    L.push("| Group | GuardDog: any issue | GuardDog: risk label above none | Excluded | Tool errors | Risk labels | Top rules |", "|---|---|---|---:|---:|---|---|");
    for (const [g, t] of Object.entries(res.guarddog)) L.push(`| ${g} | ${fmt(t.flagged, t.n)} | ${fmt(t.risky, t.n)} | ${t.excluded} | ${t.toolErrors} | ${Object.entries(t.labels).map(([k, n]) => `${k} ${n}`).join(", ")} | ${Object.entries(t.rules).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([k, n]) => `${k} ${n}`).join(", ")} |`);
  }
  return L.join("\n");
}
