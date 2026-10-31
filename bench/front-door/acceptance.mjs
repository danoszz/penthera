#!/usr/bin/env node
/**
 * E20-R2 acceptance: one real pilot on loopback, through the same commands a real run
 * uses, then every stop condition injected in turn, each proved to refuse pass 2 through
 * `main()`. Nothing leaves the machine.
 *
 *   npm run e20r:acceptance
 *
 * Prints a pass or fail table, and exits 1 on any fail. A row passes when the command
 * behaves as the row expects and, for a refusal, gives the row's own reason. The first
 * row must be allowed, so that a gate refusing everything can't pass. What only a server
 * can supply stands in through `deps`, and the pilot is marked a fixture, which a real
 * run refuses. Labels come after pass 2, so those rows prove that scoring refuses them.
 */
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { appendFileSync, cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync, writeSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { classify, scrub } from "./classify.mjs";
import { siteOrg } from "./psl.mjs";
import { robotsVerdict, sha256, strictRobots, wholeSiteStop } from "./run.mjs";
import { claims, main as analyze, secondaryCohorts } from "./analyze-r.mjs";
import { main as reportMain } from "./pilot-report.mjs";
import { pageTextMissed, PRIVACY_STOP, recordMisses, resolverFailed, safeRecord, sealHash, stopRules, withholdText } from "./record-checks.mjs";
import { CLAIM_COHORTS, main as replicate, mergeCohorts, PREREG_R, recordedHashR, R_COHORTS, runPass, visitInWorker } from "./replicate.mjs";
import { auditFrame, drawSample, main as validation, scoreLabels, stateOf, worstCaseBounds } from "./validation-sample.mjs";
import { auditRows as auditChainRows } from "./audit-acceptance.mjs";
import { main as tables, NOT_VALIDATED } from "./report-tables.mjs";

const IP = "178.104.243.225";
const COMMIT = "c".repeat(40);
const hashOf = (s) => sha256(Buffer.from(s));
const CLASSIFIER = hashOf("classifier"), PSL = hashOf("psl");

const stub = () => Promise.reject(Object.assign(new Error("x"), { code: "ENODATA" }));
const DNS = { mx: stub, ns: stub, resolveTxt: stub, resolveCaa: stub };
const rawOf = (dir) => readFileSync(join(dir, "raw.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
const quiet = () => undefined;
const truth = (holds, said) => ({ code: holds ? 0 : 3, said });
const HERE = dirname(fileURLToPath(import.meta.url));
const SHEET = join(HERE, "run-sheet.md");
const INPUTS = Object.freeze(["Pass 1 raw", "E20 Tranco raw", "E20 YC raw", "Industry map", "E20 exclusion file"]);

/** Lists, a protocol that hashes them, and the flags a run takes. */
function fixture(root) {
  const lists = join(root, "lists");
  mkdirSync(lists);
  const hashes = {};
  for (const [cohort, { file, format }] of Object.entries(R_COHORTS)) {
    const hosts = Array.from({ length: CLAIM_COHORTS.includes(cohort) ? 12 : 2 }, (_, i) => `s${i}.${cohort.toLowerCase()}.selftest.example.com`);
    const text = format === "tranco" ? hosts.map((h, i) => `${i + 1},${h}`).join("\n") : `batch,domain\n${hosts.map((h) => `x,${h}`).join("\n")}`;
    writeFileSync(join(lists, `${file}`), `${text}\n`);
    hashes[cohort] = hashOf(`${text}\n`);
  }
  const file = (name, text) => { writeFileSync(join(root, name), text); return join(root, name); };
  const exclude = file("exclusions.txt", "gov government\n");
  const homepage = file("homepage.txt", "s0.t1k.selftest.example.com\n");
  const removals = file("removals.txt", "");
  const prior = file("prior.txt", "old.selftest.example.com\n");
  const manyRemovals = file("many-removals.txt", `${Array.from({ length: 5 }, (_, i) => `s${i}.t1k.selftest.example.com`).join("\n")}\n`);
  const otherExclude = file("other-exclusions.txt", "bad.org adult\n");
  const inputs = Object.fromEntries(INPUTS.map((label, i) => [label, file(`input-${i}.txt`, label === "Industry map" ? "domain,industry\n" : "\n")]));
  const prereg = `| Status | **Registered.** Accepted |
| Amendment 2 | **Adopted.** Merged |
| Source address | \`${IP}\` |
| Frozen classifier SHA-256 | \`${CLASSIFIER}\` |
| Public Suffix List SHA-256 | \`${PSL}\` |
| Prior opt-outs SHA-256 | \`${sha256(readFileSync(prior))}\` |
${Object.entries(hashes).map(([c, h]) => `| ${c} list SHA-256 | \`${h}\` |`).join("\n")}
${INPUTS.map((l) => `| ${l} SHA-256 | \`${sha256(readFileSync(inputs[l]))}\` |`).join("\n")}
| E20-R exclusion list SHA-256 | \`${sha256(readFileSync(exclude))}\` |
| E20-R homepage-only list SHA-256 | \`${sha256(readFileSync(homepage))}\` |

## Amendment 2

**Status: adopted.** Text.
`;
  const common = ["--registered", "E20R", "--lists", lists, "--exclude", exclude, "--homepage-only", homepage, "--removals", removals, "--prior-optouts", prior];
  const state = { classifierSha256: CLASSIFIER, protocolSha256: hashOf(prereg), studyPageSha256: hashOf("page"), codeSha256: hashOf("code"), lockfileSha256: hashOf("lock"), runtimeSha256: hashOf("node"), pslSha256: PSL };
  return { common, prereg, state, exclude, otherExclude, removals, prior, manyRemovals, inputs, roundsLog: join(root, "rounds.log"), stopFile: join(root, "stop") };
}

/** One `main()` call, with its exit code and what it said. */
async function run(fx, args, over = {}) {
  const said = [];
  const code = await replicate(args, {
    say: (m) => said.push(m), results: fx.results, preregText: fx.prereg, pageText: `Study page, from ${IP}.`, tree: { commit: COMMIT, dirty: false, hidden: false, remoteTip: COMMIT },
    sourceIps: [IP], state: fx.state, classifierHash: CLASSIFIER, pslHash: PSL, fixture: true, loopbackPort: fx.port, dns: DNS, roundsLog: fx.roundsLog, stopFile: fx.stopFile, ...over,
  });
  return { code, said: said.join(" ") };
}

/** Seal, then prune, through their commands. */
function close(fx, runDir, { skips = [fx.removals, fx.prior], exclude = fx.exclude, prune = true } = {}) {
  const code = reportMain([join(runDir, "raw.jsonl"), "--exclude", exclude, ...skips.flatMap((f) => ["--skip", f]), "--seal"], { log: quiet, fail: quiet });
  reportMain(["--decide", runDir, "--decision", "go", "--reviewer", "acceptance"], { log: quiet, fail: quiet });
  if (prune) validation(["prune", runDir], { log: quiet, fail: quiet });
  return code;
}

/** A copy of the pilot's results, with `change` applied to its records and an honest manifest. */
function variant(fx, change = (r) => r, manifest = (m) => m) {
  const dir = mkdtempSync(join(fx.root, "v-"));
  cpSync(fx.base, join(dir, "results"), { recursive: true });
  const runDir = join(dir, "results", "e20r-pilot-1");
  const text = rawOf(runDir).map((r) => JSON.stringify(change(r))).join("\n") + "\n";
  writeFileSync(join(runDir, "raw.jsonl"), text);
  const m = JSON.parse(readFileSync(join(runDir, "manifest.json"), "utf8"));
  writeFileSync(join(runDir, "manifest.json"), JSON.stringify(manifest({ ...m, rawSha256: hashOf(text) }), null, 2) + "\n");
  cpSync(fx.roundsLog, join(dir, "rounds.log"));
  return { ...fx, results: join(dir, "results"), roundsLog: join(dir, "rounds.log"), runDir };
}

/** Change a seal's fields, and give it a true hash, as someone editing it by hand would. */
function reseal(runDir, change) {
  const file = join(runDir, "pilot-result.json");
  const fields = change(JSON.parse(readFileSync(file, "utf8")));
  const sealSha256 = sealHash(fields);
  writeFileSync(file, JSON.stringify({ ...fields, sealSha256 }));
  const decision = join(runDir, "pilot-decision.json");
  if (existsSync(decision)) writeFileSync(decision, JSON.stringify({ ...JSON.parse(readFileSync(decision, "utf8")), sealSha256 }));
}

/** A second round: a copy of the first, started later, in the log as a run would put it. */
function secondRound(v) {
  const again = join(v.results, "e20r-pilot-2");
  cpSync(v.runDir, again, { recursive: true });
  const m = JSON.parse(readFileSync(join(again, "manifest.json"), "utf8"));
  writeFileSync(join(again, "manifest.json"), `${JSON.stringify({ ...m, startedAt: "2099-01-01T00:00:00.000Z" }, null, 2)}\n`);
  const manifestSha256 = sha256(readFileSync(join(again, "manifest.json")));
  reseal(again, (seal) => ({ ...seal, manifestSha256 }));
  writeFileSync(join(again, "prune-manifest.json"), JSON.stringify({ ...JSON.parse(readFileSync(join(again, "prune-manifest.json"), "utf8")), manifestSha256 }));
  appendFileSync(v.roundsLog, `${JSON.stringify({ dir: "e20r-pilot-2", pilotSitesSha256: m.pilotSitesSha256, startedAt: "2099-01-01T00:00:00.000Z" })}\n`);
  return again;
}

const labels = (n, map = (i) => `${i},page`) => `id,label\n${Array.from({ length: n }, (_, i) => map(i + 1)).join("\n")}\n`;
const key = [1, 2, 3].map((id) => ({ id, stratum: "candidate-page", stratumSize: 3, ruleLabel: "page" }));
function scored(human, agent = labels(3)) {
  try {
    scoreLabels(key, human, agent, { resamples: 10 });
    return { code: 0, said: "allowed" };
  } catch (e) {
    return { code: 3, said: e.message };
  }
}

/** A command that refuses by throwing counts as refusing. */
async function catching(fn) {
  try {
    return await fn();
  } catch (e) {
    return { code: 3, said: e.message };
  }
}

/** Make the later round's number the lower one, so only the start times tell them apart. */
function renumbered(v, later) {
  const hold = `${later}-hold`;
  cpSync(later, hold, { recursive: true });
  rmSync(later, { recursive: true });
  cpSync(v.runDir, later, { recursive: true });
  rmSync(v.runDir, { recursive: true });
  cpSync(hold, v.runDir, { recursive: true });
  rmSync(hold, { recursive: true });
  const lines = readFileSync(v.roundsLog, "utf8").trim().split("\n").map((l) => JSON.parse(l));
  writeFileSync(v.roundsLog, `${lines.map((l) => JSON.stringify(l)).join("\n")}\n`);
  return v;
}

/** `plant` puts text on the next `pages` homepages, or the next `errors` error pages, so a row can count what it planted. */
async function syntheticSite(plant = {}) {
  const server = createServer((req, res) => {
    if (req.url === "/robots.txt") { res.writeHead(200, { "content-type": "text/plain" }); res.end("User-agent: *\nAllow: /\n"); return; }
    const home = req.url === "/";
    const planted = home ? plant.pages > 0 : plant.errors > 0;
    if (planted) plant[home ? "pages" : "errors"]--;
    res.writeHead(home ? 200 : 404, { "content-type": "text/html" });
    res.end(`<html><title>A page</title><p>Hello from a synthetic site.${planted ? ` ${plant.text}` : ""}</p></html>`);
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return server;
}

/** A separate process, so a real signal can land while finalization blocks. It says when, then holds the thread. */
async function finalizingChild(root) {
  const server = await syntheticSite();
  const fx = { ...fixture(root), root, port: server.address().port, results: join(root, "results") };
  const atFinal = () => { writeSync(1, "finalizing\n"); Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500); };
  const { code } = await run(fx, ["--pilot", "50", "--pilot-round", "1", ...fx.common], { atFinal });
  server.closeAllConnections();
  server.close();
  return code;
}

/** Sends a real signal in the blocking part of finalization. A partial manifest and exit 5 count as stopped. */
function finalizing(signal, root) {
  return new Promise((done) => {
    const dir = mkdtempSync(join(root, "signal-"));
    const child = spawn(process.execPath, [fileURLToPath(import.meta.url), "--finalizing-child", dir], { stdio: ["ignore", "pipe", "ignore"] });
    child.stdout.on("data", (d) => { if (String(d).includes("finalizing")) child.kill(signal); });
    child.on("close", (code) => {
      const m = JSON.parse(readFileSync(join(dir, "results", "e20r-pilot-1", "manifest.json"), "utf8"));
      done({ code: code === 5 && m.partial ? 5 : 0, said: `exit ${code}, ${m.stoppedFor ?? "not partial"}` });
    });
  });
}

/** Run the commands a stop message printed, through their own entry points. */
function followed(message) {
  return [...message.matchAll(/^node bench\/front-door\/(pilot-report|validation-sample)\.mjs (.+)$/gm)].map(([, tool, args]) => (tool === "pilot-report" ? reportMain : validation)(args.split(" "), { log: quiet, fail: quiet }));
}

// One canary per place page text can sit. Each fires the detector, and each marks its own field.
const fires = (word) => `Look at (${word}.org). Open daily`;
const CANARY_PAGES = {
  "a-title": { body: `<title>${fires("canary-title")}</title><p>Quiet canary-beside words.</p>` },
  "a-text": { body: `<title>Fine</title><p>${fires("canary-text")}</p>` },
  "a-noscript": { body: `<title>Fine</title><p>Hello.</p><noscript>${fires("canary-noscript")}</noscript>` },
  "a-error": { status: 503, body: `<p>${fires("canary-error")}</p>` },
  "a-others": { body: "<title>Fine</title><p>Hello.</p>", other: `<p>${fires("canary-others")}</p>` },
  "a-multi": { body: `<title>${fires("canary-multi-a")}</title><p>${fires("canary-multi-b")} Reach canary-multi-c#a=b now.</p><noscript>${fires("canary-multi-d")}</noscript>` },
  "a-real": { body: "<title>Fine</title><p>Write to john at (canary-real.org). Open daily</p>" },
  "a-normal": { body: "<title>Fine</title><p>Write to canary-normal@example.com today.</p>" },
  "a-plain": { body: "<title>Fine</title><p>Hello from a plain page.</p>" },
};
const CANARY_LIST = () => mergeCohorts({ T1k: Object.keys(CANARY_PAGES).map((name, i) => ({ host: `${name}.selftest.example.com`, rank: i + 1, group: "x" })) });

async function canarySite() {
  const server = createServer((req, res) => {
    if (req.url === "/robots.txt") { res.writeHead(200, { "content-type": "text/plain" }); res.end("User-agent: *\nAllow: /\n"); return; }
    const page = CANARY_PAGES[String(req.headers.host).split(".")[0]] ?? CANARY_PAGES["a-plain"];
    const home = req.url === "/";
    res.writeHead(home ? page.status ?? 200 : 404, { "content-type": "text/html" });
    res.end(home ? `<html>${page.body}</html>` : page.other ?? "<p>Nothing here.</p>");
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return server;
}

const noDns = () => Promise.reject(Object.assign(new Error("x"), { code: "ENODATA" }));
const NO_DNS_AT_ALL = { mx: noDns, ns: noDns, resolveTxt: noDns, resolveCaa: noDns };

/** A run in its own process, so stdout, stderr, temp files and real signals are all in view. */
async function canaryChild(dir, mode, stubs) {
  const server = await canarySite();
  const stopFile = join(dir, "stop");
  let signal = null;
  process.once("SIGTERM", (name) => { signal = name; });
  let seen = 0;
  const atFinal = () => { writeSync(1, "finalizing\n"); Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500); return {}; };
  await runPass(mode === "hardcap" ? CANARY_LIST().slice(0, 3) : CANARY_LIST(), {
    pass: mode === "control" ? 2 : 3, out: join(dir, "run"), loopbackPort: server.address().port, delayMs: 0, concurrency: 4, dns: NO_DNS_AT_ALL,
    ...(mode === "worker" ? { workerFile: join(stubs, "throws.mjs") } : {}), ...(mode === "marker" ? { workerFile: join(stubs, "marker.mjs") } : {}), ...(mode === "hardcap" ? { workerFile: join(stubs, "hangs.mjs"), visitLimits: { budgetMs: 50, hardCapMs: 100 } } : {}),
    ...(mode === "final" ? { recheck: atFinal } : {}),
    stopCheck: () => (signal ? `interrupted by ${signal}` : existsSync(stopFile) ? "the stop file exists" : null),
    onRecord: () => { if (++seen === 1) writeSync(1, "visited\n"); if (seen === 3 && mode === "stopfile") writeFileSync(stopFile, ""); },
  });
  if (mode === "whole") {
    reportMain(["--privacy", join(dir, "run")]);
    validation(["draw", join(dir, "run")]);
  }
  server.closeAllConnections();
  server.close();
  return 0;
}

/** Runs one mode, sends a real signal where asked, and scans everything it left and said. */
function canaryRun(root, mode, signalOn) {
  return new Promise((done) => {
    const dir = mkdtempSync(join(root, `canary-${mode}-`));
    mkdirSync(join(dir, "tmp"));
    const child = spawn(process.execPath, [fileURLToPath(import.meta.url), "--canary-child", dir, mode, join(root, "stubs")], { stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, TMPDIR: join(dir, "tmp") } });
    let said = "";
    child.stdout.on("data", (d) => { said += d; if (signalOn && String(d).includes(signalOn)) child.kill("SIGTERM"); });
    child.stderr.on("data", (d) => { said += d; });
    child.on("close", () => {
      const manifest = JSON.parse(readFileSync(join(dir, "run", "manifest.json"), "utf8"));
      done({ dir, said, manifest, leaked: onDisk(dir, "canary-") || said.includes("canary-") });
    });
  });
}

/** Paths at which two values differ. */
function diffPaths(a, b, path = "") {
  if (JSON.stringify(a) === JSON.stringify(b)) return [];
  if (!a || !b || typeof a !== "object" || typeof b !== "object") return [path];
  return [...new Set([...Object.keys(a), ...Object.keys(b)])].flatMap((k) => diffPaths(a[k], b[k], path ? `${path}.${Array.isArray(a) ? "[]" : k}` : k));
}

/** Is this string in any file under this folder? Reads bytes, so no format can hide it. */
function onDisk(dir, needle) {
  const want = Buffer.from(needle);
  return readdirSync(dir, { withFileTypes: true }).some((e) => (e.isDirectory() ? onDisk(join(dir, e.name), needle) : readFileSync(join(dir, e.name)).includes(want)));
}

/** Every row: its condition, what it must do, and what it did. */
export async function runAcceptance() {
  const root = mkdtempSync(join(tmpdir(), "e20r2-acceptance-"));
  const plant = { text: "", pages: 0, errors: 0 };
  const server = await syntheticSite(plant);
  const rows = [];
  const add = (condition, expect, got, because = /./) => {
    const allowed = got.code === 0;
    rows.push({ condition, expect, got: `exit ${got.code}: ${got.said.slice(0, 80)}`, pass: (expect === "allowed") === allowed && because.test(got.said) });
  };
  try {
    const fx = { ...fixture(root), root, port: server.address().port, results: join(root, "results") };
    const pilotArgs = (n = 50, round = 1) => ["--pilot", String(n), "--pilot-round", String(round), ...fx.common];
    const withRemovals = (file) => { const args = [...fx.common, "--pass", "2", "--pilot-dropped", join(fx.base ?? fx.results, "e20r-pilot-1", "pilot-sites.txt")]; args[args.indexOf("--removals") + 1] = file; return args; };
    const pass2 = (at) => [...fx.common.slice(0), "--pass", "2", "--pilot-dropped", join(at.results, "e20r-pilot-1", "pilot-sites.txt")];
    const started = await run(fx, pilotArgs());
    fx.base = fx.results;
    add("real pilot runs on loopback", "allowed", started);
    const gate = (at, over) => run(at, pass2(at), { stopBeforeRun: true, ...over });
    const clean = () => { const v = variant(fx); close(fx, v.runDir); return v; };
    const stops = async (condition, because, change, manifest) => { const v = variant(fx, change, manifest); close(fx, v.runDir); add(condition, "refused", await gate(v), because); };

    add("clean pilot, sealed and pruned", "allowed", await gate(clean()), /authorized/);
    add("no pilot at all", "refused", await run({ ...fx, results: join(root, "nothing"), roundsLog: join(root, "no-rounds.log") }, [...fx.common, "--pass", "2", "--pilot-dropped", fx.removals], { stopBeforeRun: true }), /No pilot manifest/);

    await stops("privacy scrub miss", /privacy scrub/, (r) => ({ ...r, evidence: { ...r.evidence, excerpt: "you are 203.0.113.7" } }));
    await stops("B3: stored (at) address", /privacy scrub/, (r) => ({ ...r, evidence: { ...r.evidence, excerpt: "john (at) example dot com" } }));
    await stops("internal worker error", /internal error/, (r) => (r.order === 0 ? { ...r, status: "error", error: "internal" } : r));
    await stops("insufficient 2xx evidence", /excerpt/, (r) => ({ ...r, evidence: { ...r.evidence, pageExcerpt: { scripts: 0 } } }));
    await stops("missing DNS", /no DNS read/, ({ dns: _dns, ...r }) => r);
    await stops("more than 20 requests", /more than 20/, (r) => ({ ...r, counters: { ...r.counters, requests: 21 } }));
    await stops("hop to an excluded host", /excluded host/, (r) => ({ ...r, hops: [...r.hops, "ministry.gov"] }));
    await stops("dead run: no name resolves", /graded/, ({ evidence: _e, checks: _c, finalHost: _f, ...r }) => ({ ...r, status: "error", error: "not_found", netCode: "ESERVFAIL" }));
    const failing = (q) => (r) => ({ ...r, dns: { ...r.dns, listed: { ...r.dns.listed, outcomes: { ...r.dns.listed.outcomes, [q]: "resolver-failure:ESERVFAIL" } } } });
    await stops("resolver failures on NS", /resolver failure/, failing("ns"));
    await stops("B4: resolver failures on TXT", /resolver failure/, failing("txt"));
    await stops("B4: resolver failures on CAA", /resolver failure/, failing("caa"));
    await stops("B4: SPF reads unanswered", /SPF reads/, (r) => ({ ...r, dns: { ...r.dns, listed: { ...r.dns.listed, spfRecordPresent: null, spf: null } } }));
    await stops("every site blocked, zero 2xx", /no site answered/, (r) => ({ ...r, httpStatus: 403 }));
    await stops("B4: DMARC reads unanswered", /DMARC reads/, (r) => ({ ...r, dns: { ...r.dns, listed: { ...r.dns.listed, dmarc: null } } }));
    await stops("under 30 eligible sites", /under 30 eligible/, ({ evidence: _e, checks: _c, finalHost: _f, dns: _d, ...r }) => (r.order < 25 ? { ...r, status: "opted_out" } : { ...r, evidence: _e, checks: _c, finalHost: _f, dns: _d }));
    await stops("C8: under 25 graded sites", /under 25 graded/, ({ evidence: _e, checks: _c, finalHost: _f, ...r }) => (r.order < 20 ? { ...r, status: "opted_out" } : r.order < 31 ? { ...r, status: "error", error: "timeout" } : { ...r, evidence: _e, checks: _c, finalHost: _f }));
    await stops("C8: under 10 2xx responses", /under 10 2xx/, (r) => (r.order >= 9 ? { ...r, httpStatus: 403 } : r));
    await stops("C2: a failed query on the final name alone", /resolver failure/, (r) => ({ ...r, dns: { ...r.dns, final: { outcomes: {}, queries: [{ type: "TXT", name: "_dmarc.www.x.example", outcome: "resolver-failure:servfail" }] } } }));
    await stops("graded share under the floor", /graded/, ({ evidence: _e, checks: _c, finalHost: _f, ...r }) => ({ ...r, status: "error", error: "timeout" }));
    await stops("B5: every site opted out", /no eligible site/, ({ evidence: _e, checks: _c, finalHost: _f, dns: _d, ...r }) => ({ ...r, status: "opted_out" }));
    await stops("changed while the pilot ran", /changed while/, (r) => r, (m) => ({ ...m, immutableAtFinish: { ok: false, changed: ["codeSha256"] } }));

    add("B5: --pilot 1", "refused", await run(fx, pilotArgs(1, 2)), /exactly 50/);
    await stops("B5: a pilot under the floor", /floor is 50/, (r) => r, (m) => ({ ...m, sites: 49 }));

    const lowerFailed = variant(fx);
    close(fx, lowerFailed.runDir);
    const later = secondRound(lowerFailed);
    reseal(later, (seal) => ({ ...seal, passed: false, stop: ["a privacy scrub missed something"] }));
    const earlierFile = join(lowerFailed.runDir, "manifest.json");
    add("B1: the later round failed, with a lower number", "refused", await gate(renumbered(lowerFailed, later)), /failed/);
    add("B1: a round number at or below an existing one", "refused", await run(lowerFailed, pilotArgs(50, 2)), /not after round/);
    if (!existsSync(earlierFile)) throw new Error("fixture lost a round");

    const wrongExclude = variant(fx);
    close(fx, wrongExclude.runDir, { exclude: fx.otherExclude });
    add("B2: sealed with the wrong --exclude", "refused", await gate(wrongExclude), /failed.*--exclude/);
    const noSkip = variant(fx);
    close(fx, noSkip.runDir, { skips: [fx.removals] });
    add("B2: sealed without a --skip list", "refused", await gate(noSkip), /failed.*--skip/);
    const ownList = variant(fx);
    close(fx, ownList.runDir, { skips: [fx.removals, fx.prior, join(ownList.runDir, "pilot-sites.txt")] });
    add("B2: this round's own list as a skip list", "refused", await gate(ownList), /failed.*--skip/);
    const noFlag = variant(fx);
    add("B2: --seal with no --skip", "refused", { code: reportMain([join(noFlag.runDir, "raw.jsonl"), "--exclude", fx.exclude, "--seal"], { log: quiet, fail: quiet }) === 2 ? 3 : 0, said: "--seal refused" });
    const swapped = clean();
    reseal(swapped.runDir, (seal) => ({ ...seal, lists: {} }));
    add("B2: seal holds other list hashes", "refused", await gate(swapped), /other skip lists/);

    const flipped = variant(fx, (r) => ({ ...r, evidence: { ...r.evidence, excerpt: "you are 203.0.113.7" } }));
    close(fx, flipped.runDir);
    const flippedSeal = join(flipped.runDir, "pilot-result.json");
    const failedSeal = JSON.parse(readFileSync(flippedSeal, "utf8"));
    writeFileSync(flippedSeal, JSON.stringify({ ...failedSeal, passed: true, stop: [] }));
    add("seal: passed edited by hand", "refused", await gate(flipped), /own hash/);
    reseal(flipped.runDir, (seal) => ({ ...seal, passed: true, stop: [] }));
    add("seal: passed edited, hash redone", "refused", await gate(flipped), /does not pass/);
    const reportEdited = clean();
    writeFileSync(join(reportEdited.runDir, "pilot-report.json"), "{}\n");
    add("seal: report edited", "refused", await gate(reportEdited), /not the sealed one/);

    const deleted = clean();
    appendFileSync(deleted.roundsLog, `${JSON.stringify({ dir: "e20r-pilot-2", pilotSitesSha256: "x" })}\n`);
    add("rounds log: a round's folder was deleted", "refused", await gate(deleted), /rounds log/);
    const unlogged = clean();
    writeFileSync(unlogged.roundsLog, "");
    add("rounds log: a round is not in it", "refused", await gate(unlogged), /rounds log/);

    add("removal list over 5% of sites", "refused", await run(clean(), withRemovals(fx.manyRemovals), { stopBeforeRun: true }), /5 of \d+ sites.*over 5%/);

    add("S3: a loopback pilot in a real run", "refused", await gate(clean(), { fixture: false }), /ran on loopback/);

    const unsealed = variant(fx);
    validation(["prune", unsealed.runDir], { log: quiet });
    add("pilot report not sealed", "refused", await gate(unsealed), /no sealed report/);
    const unpruned = variant(fx);
    close(fx, unpruned.runDir, { prune: false });
    add("pruning absent", "refused", await gate(unpruned), /no proof/);
    const restored = clean();
    writeFileSync(join(restored.runDir, "raw.jsonl"), readFileSync(join(variant(fx).runDir, "raw.jsonl")));
    add("pruning undone: text back on disk", "refused", await gate(restored), /not the pruned one/);
    const fake = variant(fx);
    close(fx, fake.runDir, { prune: false });
    writeFileSync(join(fake.runDir, "prune-manifest.json"), JSON.stringify({ manifestSha256: "x", rawSha256Before: "x", rawSha256After: "x" }));
    add("pruning failed: proof for another run", "refused", await gate(fake), /another run/);
    const killed = variant(fx, (r) => r, ({ finishedAt: _f, rawSha256: _r, ...m }) => m);
    validation(["prune", killed.runDir], { log: quiet });
    add("pilot killed before it finished", "refused", await gate(killed), /did not finish/);
    const tampered = clean();
    reseal(tampered.runDir, (seal) => ({ ...seal, manifestSha256: "x" }));
    add("sealed report for another run", "refused", await gate(tampered), /another run/);

    const base = clean();
    const edited = hashOf("edited");
    const changed = (name) => gate(base, { state: { ...fx.state, [name]: edited } });
    add("changed classifier", "refused", await gate(base, { classifierHash: edited }), /frozen classifier/);
    add("changed classifier since the pilot", "refused", await changed("classifierSha256"), /classifierSha256/);
    add("changed protocol", "refused", await changed("protocolSha256"), /protocolSha256/);
    add("changed study page", "refused", await changed("studyPageSha256"), /studyPageSha256/);
    add("changed suffix list", "refused", await gate(base, { pslHash: edited }), /Public Suffix List/);
    add("changed code", "refused", await changed("codeSha256"), /codeSha256/);
    add("changed runtime", "refused", await changed("runtimeSha256"), /runtimeSha256/);
    const listFile = fx.common[fx.common.indexOf("--lists") + 1];
    const t1k = join(listFile, R_COHORTS.T1k.file);
    const original = readFileSync(t1k);
    writeFileSync(t1k, Buffer.concat([original, Buffer.from("999,extra.selftest.example.com\n")]));
    add("changed list", "refused", await gate(base), /listSha256/);
    writeFileSync(t1k, original);
    add("dropped list is not the pilot's", "refused", await run(base, [...fx.common, "--pass", "2", "--pilot-dropped", fx.prior], { stopBeforeRun: true }), /exactly the pilot sites/);

    const failing2 = variant(fx);
    close(fx, failing2.runDir);
    secondRound(failing2);
    reseal(failing2.runDir, (seal) => ({ ...seal, passed: false, stop: ["x"] }));
    add("S1: a failed round rerun with nothing changed", "refused", await gate(failing2), /changed nothing/);
    writeFileSync(join(failing2.runDir, "pilot-explanation.txt"), "A note on what went wrong.\n");
    add("S1: the same, with a recorded explanation", "allowed", await gate(failing2), /authorized/);

    const stopped = clean();
    const failingDns = { ...DNS, ns: () => Promise.reject(Object.assign(new Error("x"), { code: "ESERVFAIL" })) };
    add("in flight: resolver failures stop pass 2", "refused", await run(stopped, pass2(stopped), { dns: failingDns, rollingWindow: 8 }), /STOP: over 20%.*partial/);
    const stoppedRun = join(stopped.results, "e20r-pass2");
    const analysis = (dir, preregText = fx.prereg, more = {}) => {
      const said = [];
      const i = fx.inputs;
      // A fixture's manifest names a stand-in state, so the analysis is told to run under it.
      const manifestFile = join(dir, "manifest.json");
      const state = existsSync(manifestFile) ? stateOf(JSON.parse(readFileSync(manifestFile, "utf8"))) : undefined;
      const code = analyze(["--pass1", join(dir, "raw.jsonl"), "--pass2", i["Pass 1 raw"], "--e20", i["E20 Tranco raw"], i["E20 YC raw"], "--industries", i["Industry map"], "--e20-excluded", i["E20 exclusion file"], "--out", join(dir, "analysis.json")], { fail: (m) => said.push(m), preregText, state, ...more });
      return { code, said: said.join(" ") || "analyzed" };
    };
    const onLast = (act) => { let n = 0; return (_k, total) => { if (++n === total) act(); }; };
    const purgeWith = (dir, ...flags) => { const said = []; const code = validation(["purge", dir, ...flags], { log: (m) => said.push(m), fail: (m) => said.push(m) }); return { code, said: said.join(" ") }; };
    const purge = (dir) => purgeWith(dir, "--confirm", sha256(readFileSync(join(dir, "raw.jsonl"))).slice(0, 12));
    const draw = (dir) => { const said = []; const code = validation(["draw", dir], { log: quiet, fail: (m) => said.push(m) }); return { code, said: said.join(" ") || "drawn" }; };
    add("analysis of a stopped pass 2", "refused", analysis(stoppedRun), /stopped/);
    add("audit draw of a stopped pass 2", "refused", draw(stoppedRun), /stopped/);
    add("no pilot round after pass 2 started", "refused", await run(stopped, pilotArgs(50, 2)), /pass 2 has started/);
    const pruned = (dir) => { const said = []; const code = validation(["prune", dir], { log: (m) => said.push(m), fail: (m) => said.push(m) }); return { code, said: said.join(" ") }; };
    add("C4: a stopped pass is pruned, and read back", "allowed", pruned(stoppedRun), /"verified":true/);

    add("purge: a partial run", "allowed", purge(stoppedRun), /"disposition":"partial"/);
    add("purge: nothing left to analyze", "refused", analysis(stoppedRun), /purged/);

    const lastSignal = clean();
    add("1: a signal during the final record", "refused", await run(lastSignal, pass2(lastSignal), { afterRecord: onLast(() => process.emit("SIGTERM", "SIGTERM")) }), /STOP: interrupted by SIGTERM.*partial/);
    add("1: that run is partial in its manifest", "refused", analysis(join(lastSignal.results, "e20r-pass2")), /interrupted by SIGTERM/);
    const lastStop = clean();
    add("1: the stop file during the final record", "refused", await run(lastStop, pass2(lastStop), { afterRecord: onLast(() => writeFileSync(fx.stopFile, "")) }), /STOP: the stop file exists.*partial/);
    rmSync(fx.stopFile);

    add("1: a real SIGTERM during finalization", "refused", await finalizing("SIGTERM", root), /interrupted by SIGTERM/);
    add("1: a real SIGINT during finalization", "refused", await finalizing("SIGINT", root), /interrupted by SIGINT/);

    const fresh = { ...fx, results: join(root, "followed"), roundsLog: join(root, "followed.log") };
    const stoppedPilot = await run(fresh, pilotArgs(50, 1), { afterRecord: (k) => { if (k === 2) writeFileSync(fx.stopFile, ""); } });
    rmSync(fx.stopFile);
    add("5: a stopped pilot prints seal, then prune", "refused", stoppedPilot, /pilot-report\.mjs .*--seal[\s\S]*validation-sample\.mjs prune/);
    const steps = followed(stoppedPilot.said);
    const pilotSites = join(fresh.results, "e20r-pilot-1", "pilot-sites.txt");
    add("5: following it leaves a sealed, pruned round", "allowed", truth(steps.length === 2 && steps[1] === 0 && existsSync(join(fresh.results, "e20r-pilot-1", "pilot-result.json")) && existsSync(join(fresh.results, "e20r-pilot-1", "prune-manifest.json")), `steps ${steps}`));
    add("5: the next round's gate accepts that state", "allowed", await run(fresh, [...pilotArgs(50, 2), "--pilot-dropped", pilotSites], { stopBeforeRun: true }), /authorized/);
    const toFollow = clean();
    const stoppedPass = await run(toFollow, pass2(toFollow), { afterRecord: (k) => { if (k === 2) writeFileSync(fx.stopFile, ""); } });
    rmSync(fx.stopFile);
    add("5: a stopped pass 2 prints prune alone", "refused", stoppedPass, /Next: node bench\/front-door\/validation-sample\.mjs prune/);
    add("5: following it is accepted", "allowed", truth(followed(stoppedPass.said.replace("Next: ", "\n")).every((c) => c === 0) && existsSync(join(toFollow.results, "e20r-pass2", "prune-manifest.json")), "prune"));

    const leakedFields = {
      header: (r) => ({ ...r, evidence: { ...r.evidence, values: { server: "jan@example.nl" } } }), cookie: (r) => ({ ...r, evidence: { ...r.evidence, cookieNames: ["jan@example.nl"] } }),
      finalHost: (r) => ({ ...r, finalHost: "203.0.113.9" }), hop: (r) => ({ ...r, hops: ["203.0.113.9"] }), dns: (r) => ({ ...r, dns: { ...r.dns, listed: { ...r.dns?.listed, dmarcRecord: "rua=jan@example.nl" } } }),
    };
    for (const [field, change] of Object.entries(leakedFields)) {
      const failed = variant(fx, change);
      close(fx, failed.runDir, { prune: false });
      const said = [];
      add(`2: prune refuses a pilot miss in ${field}`, "refused", { code: validation(["prune", failed.runDir], { log: quiet, fail: (m) => said.push(m) }), said: said.join(" ") }, /privacy miss/);
      add(`2: pass 2 refuses it with no purge, ${field}`, "refused", await gate(failed), /privacy scrub miss and no verified purge/);
      add(`2: a purge clears that refusal, ${field}`, "allowed", purge(failed.runDir), /"verified":true/);
      add(`2: and the round then only counts as failed, ${field}`, "refused", await gate(failed), /e20r-pilot-1 failed/);
    }
    const reviewedPilot = variant(fx, leakedFields.header);
    close(fx, reviewedPilot.runDir, { prune: false });
    const notePath = join(root, "pilot-note.txt");
    writeFileSync(notePath, "Checked by hand.\n");
    reportMain(["--privacy", reviewedPilot.runDir, "--false-fire", notePath, "--reviewer", "acceptance"], { log: quiet, fail: quiet });
    add("2: a reviewed false fire may be pruned", "allowed", (() => { const said = []; const code = validation(["prune", reviewedPilot.runDir], { log: (m) => said.push(m), fail: (m) => said.push(m) }); return { code, said: said.join(" ") }; })(), /"verified":true/);
    add("2: and passes the privacy check of the gate", "refused", await gate(reviewedPilot), /e20r-pilot-1 failed/);

    const beside = clean();
    const sealedRaw = readFileSync(join(beside.runDir, "raw.jsonl"));
    purge(beside.runDir);
    writeFileSync(join(beside.runDir, "raw.jsonl"), sealedRaw);
    add("3: a purge proof beside an existing raw", "refused", await gate(beside), /purge proof does not hold: raw\.jsonl still there/);
    rmSync(join(beside.runDir, "raw.jsonl"));
    writeFileSync(join(beside.runDir, "validation-sheet.json"), "[]");
    add("3: raw gone, the sheet still there", "refused", await gate(beside), /validation-sheet\.json still there/);
    rmSync(join(beside.runDir, "validation-sheet.json"));
    writeFileSync(join(beside.runDir, "validation-key.json"), "[]");
    add("3: raw gone, the key still there", "refused", await gate(beside), /validation-key\.json still there/);
    rmSync(join(beside.runDir, "validation-key.json"));
    const purgeFile = join(beside.runDir, "purge-manifest.json");
    const heldProof = JSON.parse(readFileSync(purgeFile, "utf8"));
    for (const [name, wrong, why] of [["kind", { kind: "prune" }, /not a purge proof/], ["manifest", { manifestSha256: "x" }, /another run/], ["raw hash", { rawSha256: "x" }, /another raw file/], ["disposition", { disposition: "crashed" }, /disposition/]]) {
      writeFileSync(purgeFile, JSON.stringify({ ...heldProof, ...wrong }));
      add(`3: a purge proof with the wrong ${name}`, "refused", await gate(beside), why);
    }

    const noDecision = clean();
    rmSync(join(noDecision.runDir, "pilot-decision.json"));
    add("6: no recorded decision", "refused", await gate(noDecision), /no recorded go decision/);
    const noGo = clean();
    reportMain(["--decide", noGo.runDir, "--decision", "no-go", "--reviewer", "acceptance"], { log: quiet, fail: quiet });
    add("6: a no-go decision", "refused", await gate(noGo), /no recorded go decision/);
    const staleDecision = clean();
    const decisionFile = join(staleDecision.runDir, "pilot-decision.json");
    writeFileSync(decisionFile, JSON.stringify({ ...JSON.parse(readFileSync(decisionFile, "utf8")), reportSha256: "x" }));
    add("6: a decision for another report", "refused", await gate(staleDecision), /decision is for another report/);
    for (const [name, wrong] of [["no reviewer", { reviewer: "  " }], ["no time", { decidedAt: undefined }], ["an unparseable time", { decidedAt: "soon" }]]) {
      const thin = clean();
      const file = join(thin.runDir, "pilot-decision.json");
      writeFileSync(file, JSON.stringify({ ...JSON.parse(readFileSync(file, "utf8")), ...wrong }));
      add(`6: a decision with ${name}`, "refused", await gate(thin), /no reviewer or no valid time/);
    }
    const failedGo = variant(fx, leakedFields.header);
    close(fx, failedGo.runDir, { prune: false });
    const goSaid = [];
    add("6: a failed round can't be a go", "refused", { code: reportMain(["--decide", failedGo.runDir, "--decision", "go", "--reviewer", "x"], { log: quiet, fail: (m) => goSaid.push(m) }), said: goSaid.join(" ") }, /can't be a go/);

    const signaled = clean();
    add("C4: SIGTERM ends a run with a partial manifest", "refused", await run(signaled, pass2(signaled), { afterRecord: (k) => { if (k === 1) process.emit("SIGTERM", "SIGTERM"); } }), /STOP: interrupted by SIGTERM.*partial.*prune/);
    const signaledRun = join(signaled.results, "e20r-pass2");
    add("C4: its manifest is final, and analysis refuses it", "refused", analysis(signaledRun), /interrupted by SIGTERM/);
    add("C4: its text is pruned", "allowed", pruned(signaledRun), /"verified":true/);

    const toStop = clean();
    add("C6: the stop file stops a run between sites", "refused", await run(toStop, pass2(toStop), { afterRecord: (k) => { if (k === 1) writeFileSync(fx.stopFile, ""); } }), /STOP: the stop file exists.*partial/);
    add("C6: no run starts while the stop file exists", "refused", await gate(clean()), /stop file/);
    rmSync(fx.stopFile);
    const moved = clean();
    let reads = 0;
    add("C6: a changed source address stops a run", "refused", await run(moved, pass2(moved), { sourceNow: () => (reads++ > 3 ? ["203.0.113.9"] : [IP]) }), /STOP: the source address changed.*partial/);

    const shifted = clean();
    const kept2 = readFileSync(fx.exclude);
    add("C3: an input file changed during the run", "refused", await run(shifted, pass2(shifted), { afterRecord: (k) => { if (k === 1) writeFileSync(fx.exclude, Buffer.concat([kept2, Buffer.from("#\n")])); } }), /changed during the run: inputFiles/);
    writeFileSync(fx.exclude, kept2);
    add("C3: that run decides nothing", "refused", analysis(join(shifted.results, "e20r-pass2")), /something changed/);
    const addressEnd = clean();
    let calls = 0;
    const late = await run(addressEnd, pass2(addressEnd), { sourceNow: () => (calls++ > 40 ? ["203.0.113.9"] : [IP]), rollingWindow: 1000 });
    add("C6: the address is read again at the end", "refused", late, /source address changed|changed during the run: sourceIps/);

    const whole = clean();
    add("pass 2 runs to its end", "allowed", await run(whole, pass2(whole)));
    const wholeRun = join(whole.results, "e20r-pass2");
    add("C5: analysis with no privacy report", "refused", analysis(wholeRun), /privacy report/);
    add("C5: audit draw with no privacy report", "refused", draw(wholeRun), /privacy report/);
    add("C4: a whole pass is not pruned by hand", "refused", (() => { const said = []; const code = validation(["prune", wholeRun], { log: quiet, fail: (m) => said.push(m) }); return { code, said: said.join(" ") }; })(), /finished whole/);
    const privacy = (dir) => { const said = []; const code = reportMain(["--privacy", dir], { log: quiet, fail: (m) => said.push(m) }); return { code, said: said.join(" ") || "clean" }; };
    const leaks = {
      header: { evidence: { values: { server: "jan@example.nl" } } }, cookie: { evidence: { cookieNames: ["jan@example.nl"] } },
      finalHost: { finalHost: "203.0.113.9" }, hops: { hops: ["203.0.113.9"] }, dns: { dns: { listed: { dmarcRecord: "rua=jan@example.nl" } } },
    };
    for (const [field, leak] of Object.entries(leaks)) {
      const leaky = join(whole.results, `leaky-${field}`);
      cpSync(wholeRun, leaky, { recursive: true });
      const leakRaw = `${readFileSync(join(leaky, "raw.jsonl"), "utf8")}${JSON.stringify({ status: "ok", ...leak })}\n`;
      writeFileSync(join(leaky, "raw.jsonl"), leakRaw);
      writeFileSync(join(leaky, "manifest.json"), JSON.stringify({ ...JSON.parse(readFileSync(join(leaky, "manifest.json"), "utf8")), rawSha256: hashOf(leakRaw) }));
      add(`2: a miss in ${field} fails the privacy report`, "refused", privacy(leaky));
      add(`3: analysis after that failure, ${field}`, "refused", analysis(leaky), /privacy report/);
      add(`purge with no code, ${field}`, "refused", purgeWith(leaky), /--confirm/);
      add(`purge with a wrong code, ${field}`, "refused", purgeWith(leaky, "--confirm", "0".repeat(12)), /--confirm/);
      add(`3: purge after that failure, ${field}`, "allowed", purge(leaky), /"disposition":"privacy-failed"/);
      add(`3: no analysis after the purge, ${field}`, "refused", analysis(leaky), /purged/);
    }
    const reviewedDir = join(whole.results, "false-fire");
    cpSync(wholeRun, reviewedDir, { recursive: true });
    const flaggedRaw = `${readFileSync(join(reviewedDir, "raw.jsonl"), "utf8")}${JSON.stringify({ status: "ok", evidence: { values: { server: "(AT) Wien" } } })}\n`;
    writeFileSync(join(reviewedDir, "raw.jsonl"), flaggedRaw);
    writeFileSync(join(reviewedDir, "manifest.json"), JSON.stringify({ ...JSON.parse(readFileSync(join(reviewedDir, "manifest.json"), "utf8")), rawSha256: hashOf(flaggedRaw) }));
    const printed = [];
    reportMain(["--privacy", reviewedDir], { log: (m) => printed.push(m), fail: quiet });
    add("a failed report prints the code and no field or text", "allowed", truth(printed.join("").includes(hashOf(flaggedRaw).slice(0, 12)) && !/Wien|flaggedFields/.test(printed.join("")), "privacy output"));
    add("a false fire has no run until it is reviewed", "refused", analysis(reviewedDir), /privacy report/);
    const note = join(fx.root, "false-fire.txt");
    writeFileSync(note, "Checked by hand: a place name, not an address.\n");
    add("a reviewed false fire keeps the run", "allowed", (() => { const code = reportMain(["--privacy", reviewedDir, "--false-fire", note, "--reviewer", "acceptance"], { log: quiet, fail: quiet }); return { code, said: "reviewed" }; })());
    add("and the analysis reports it as a deviation", "allowed", (() => { const got = analysis(reviewedDir); return { code: got.code || (JSON.parse(readFileSync(join(reviewedDir, "analysis.json"), "utf8")).privacyDeviation?.noteSha256 ? 0 : 3), said: got.said }; })(), /analyzed/);

    const crashed = join(whole.results, "crashed");
    cpSync(wholeRun, crashed, { recursive: true });
    const { finishedAt: _gone, ...unfinished } = JSON.parse(readFileSync(join(crashed, "manifest.json"), "utf8"));
    writeFileSync(join(crashed, "manifest.json"), JSON.stringify(unfinished));
    add("3: purge of a crashed run", "allowed", purge(crashed), /"disposition":"crashed"/);
    add("C5: a clean pass 2 writes its report", "allowed", privacy(wholeRun));
    const sibling = join(wholeRun, "other.jsonl");
    cpSync(join(wholeRun, "raw.jsonl"), sibling);
    const siblingSaid = [];
    add("analysis of a sibling file", "refused", { code: analyze(["--pass1", sibling, "--e20", sibling, sibling], { fail: (m) => siblingSaid.push(m) }), said: siblingSaid.join(" ") }, /raw\.jsonl/);
    add("analysis of a whole pass 2", "allowed", analysis(wholeRun), /analyzed/);
    add("a second start of pass 2", "refused", await catching(() => run(whole, pass2(whole))), /already holds a run/);
    const rawFile = join(wholeRun, "raw.jsonl");
    const kept = readFileSync(rawFile);
    writeFileSync(rawFile, Buffer.concat([kept, Buffer.from("{}\n")]));
    add("analysis of a raw file that changed", "refused", analysis(wholeRun), /not the one the manifest hashed/);
    add("audit draw of a raw file that changed", "refused", draw(wholeRun), /not the one the manifest hashed/);
    writeFileSync(rawFile, kept);
    add("audit draw of a whole pass 2", "allowed", draw(wholeRun), /drawn/);
    add("analysis after the draw pruned it", "allowed", analysis(wholeRun), /analyzed/);
    add("a second draw", "refused", draw(wholeRun), /drawn already/);
    const proofFile = join(wholeRun, "prune-manifest.json");
    const proof = readFileSync(proofFile);
    // Every row was sampled here, so the draw changed nothing. A pruned file stands in.
    const prunedRaw = Buffer.concat([kept, Buffer.from("\n")]);
    writeFileSync(rawFile, prunedRaw);
    writeFileSync(proofFile, JSON.stringify({ ...JSON.parse(proof), rawSha256After: sha256(prunedRaw), kind: "stopped" }));
    add("prune proof of the wrong kind", "refused", analysis(wholeRun), /not the one the manifest hashed/);
    writeFileSync(proofFile, JSON.stringify({ ...JSON.parse(proof), rawSha256After: sha256(prunedRaw) }));
    add("prune proof of the draw", "allowed", analysis(wholeRun), /analyzed/);
    writeFileSync(rawFile, kept);
    writeFileSync(proofFile, proof);
    const keyFile = join(wholeRun, "validation-key.json");
    writeFileSync(keyFile, `${readFileSync(keyFile, "utf8")} `);
    const keySaid = [];
    add("validation key not this run's", "refused", { code: validation(["score", wholeRun], { fail: (m) => keySaid.push(m) }), said: keySaid.join(" ") }, /not the one/);

    const wrongKind = clean();
    const pilotProof = join(wrongKind.runDir, "prune-manifest.json");
    writeFileSync(pilotProof, JSON.stringify({ ...JSON.parse(readFileSync(pilotProof, "utf8")), kind: "validation-draw" }));
    add("pilot prune proof of the wrong kind", "refused", await gate(wrongKind), /another run/);
    const earlier = clean();
    secondRound(earlier);
    reseal(earlier.runDir, (seal) => ({ ...seal, rawSha256: "x" }));
    add("an earlier round's seal is for another run", "refused", await gate(earlier), /e20r-pilot-1: its sealed report is for another run/);
    const twoLive = variant(fx, (r) => r, (m) => ({ ...m, loopback: false }));
    close(fx, twoLive.runDir);
    const third = secondRound(twoLive);
    if (!existsSync(third)) throw new Error("fixture lost a round");
    add("C8: a third live pilot round", "refused", await run(twoLive, pilotArgs(50, 3)), /2 live pilot rounds/);

    // Amendment 3: pass 2 stopped, a person reviewed it, it was pruned, a pilot round followed, pass 3 ran.
    const adopted = `${fx.prereg}\n| Amendment 3 | **Adopted.** Merged |\n\n## Amendment 3\n\n**Status: adopted.** Merged\n`;
    const pass3 = (at) => pass2(at).map((a, i, all) => (all[i - 1] === "--pass" ? "3" : a));
    const stopSoon = { afterRecord: (k) => { if (k === 2) writeFileSync(fx.stopFile, ""); } };
    // What the frozen detector fired on, in the first record, with a manifest that hashes it.
    const stoppedFor = (dir, reason, extra = {}) => {
      const rows = readFileSync(join(dir, "raw.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
      rows[0] = { ...rows[0], evidence: { pageExcerpt: { text: "Reach us at <email>. Open daily" } } };
      const text = `${rows.map((r) => JSON.stringify(r)).join("\n")}\n`;
      writeFileSync(join(dir, "raw.jsonl"), text);
      const m = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));
      writeFileSync(join(dir, "manifest.json"), JSON.stringify({ ...m, partial: true, stoppedFor: reason ?? m.stoppedFor, records: rows.length, rawSha256: hashOf(text), ...extra }));
    };
    const reviewNote = join(root, "pass2-note.txt");
    writeFileSync(reviewNote, "Checked by hand: our own token, no address.\n");
    const review = (dir) => reportMain(["--privacy", dir, "--false-fire", reviewNote, "--reviewer", "acceptance"], { log: quiet, fail: quiet });
    const dispose = (dir) => { reportMain(["--legacy-findings", dir], { log: quiet, fail: quiet }); review(dir); validation(["prune", dir], { log: quiet, fail: quiet }); };
    const refusedBoth = async (name, at, why) => {
      add(`8: ${name}: pilot round 2`, "refused", await run(at, pilotArgs(50, 2), { preregText: adopted }), why);
      add(`8: ${name}: pass 3`, "refused", await run(at, pass3(at), { preregText: adopted }), why);
    };
    const passDir = (at) => join(at.results, "e20r-pass2");

    const byTerm = clean();
    await run(byTerm, pass2(byTerm), { afterRecord: (k) => { if (k === 1) process.emit("SIGTERM", "SIGTERM"); } });
    stoppedFor(passDir(byTerm));
    dispose(passDir(byTerm));
    await refusedBoth("a SIGTERM stop", byTerm, /another reason: interrupted by SIGTERM/);
    const byResolver = clean();
    await run(byResolver, pass2(byResolver), { dns: { ...DNS, ns: () => Promise.reject(Object.assign(new Error("x"), { code: "ESERVFAIL" })) }, rollingWindow: 8 });
    stoppedFor(passDir(byResolver));
    dispose(passDir(byResolver));
    await refusedBoth("a resolver stop", byResolver, /another reason: over 20%/);
    const byFile = clean();
    await run(byFile, pass2(byFile), stopSoon);
    rmSync(fx.stopFile);
    stoppedFor(passDir(byFile));
    dispose(passDir(byFile));
    await refusedBoth("a stop-file stop", byFile, /another reason: the stop file exists/);
    const byAddress = clean();
    let addressReads = 0;
    await run(byAddress, pass2(byAddress), { sourceNow: () => (addressReads++ > 3 ? ["203.0.113.9"] : [IP]) });
    stoppedFor(passDir(byAddress));
    dispose(passDir(byAddress));
    await refusedBoth("a source-address stop", byAddress, /something changed while pass 2 ran/);
    const byInputs = clean();
    const heldExclude = readFileSync(fx.exclude);
    await run(byInputs, pass2(byInputs), { afterRecord: (k) => { if (k === 1) writeFileSync(fx.exclude, Buffer.concat([heldExclude, Buffer.from("#\n")])); } });
    writeFileSync(fx.exclude, heldExclude);
    stoppedFor(passDir(byInputs), PRIVACY_STOP);
    dispose(passDir(byInputs));
    await refusedBoth("changed inputs", byInputs, /something changed while pass 2 ran/);
    const unfixtured = clean();
    await run(unfixtured, pass2(unfixtured), stopSoon);
    rmSync(fx.stopFile);
    stoppedFor(passDir(unfixtured), PRIVACY_STOP, { fixture: false });
    dispose(passDir(unfixtured));
    await refusedBoth("a loopback run", unfixtured, /pass 2 ran on loopback/);
    const notPass2 = clean();
    await run(notPass2, pass2(notPass2), stopSoon);
    rmSync(fx.stopFile);
    stoppedFor(passDir(notPass2), PRIVACY_STOP, { pass: 3 });
    dispose(passDir(notPass2));
    await refusedBoth("a manifest that isn't pass 2", notPass2, /not pass 2's/);
    const cleanLabelled = clean();
    await run(cleanLabelled, pass2(cleanLabelled), stopSoon);
    rmSync(fx.stopFile);
    const cleanDir = passDir(cleanLabelled);
    const cleanRaw = readFileSync(join(cleanDir, "raw.jsonl"));
    writeFileSync(join(cleanDir, "manifest.json"), JSON.stringify({ ...JSON.parse(readFileSync(join(cleanDir, "manifest.json"), "utf8")), stoppedFor: PRIVACY_STOP, rawSha256: sha256(cleanRaw) }));
    const labelSaid = [];
    add("8: a clean report labelled a false fire", "refused", { code: reportMain(["--privacy", cleanDir, "--false-fire", reviewNote, "--reviewer", "x"], { log: quiet, fail: (m) => labelSaid.push(m) }), said: labelSaid.join(" ") }, /nothing to call a false fire/);
    reportMain(["--privacy", cleanDir], { log: quiet, fail: quiet });
    const handMade = join(cleanDir, "privacy-report.json");
    writeFileSync(handMade, JSON.stringify({ ...JSON.parse(readFileSync(handMade, "utf8")), reviewed: { noteSha256: "a".repeat(64), reviewer: "x" } }));
    validation(["prune", cleanDir], { log: quiet, fail: quiet });
    await refusedBoth("a hand-written clean review", cleanLabelled, /no legacy finding report/);
    reportMain(["--legacy-findings", cleanDir], { log: quiet, fail: quiet });
    await refusedBoth("a report with no finding", cleanLabelled, /no legacy finding report|another run|does not reproduce/);
    const wrongReport = clean();
    await run(wrongReport, pass2(wrongReport), stopSoon);
    rmSync(fx.stopFile);
    stoppedFor(passDir(wrongReport), PRIVACY_STOP);
    dispose(passDir(wrongReport));
    const legacyFile = join(passDir(wrongReport), "legacy-findings.json");
    const legacyHeld = JSON.parse(readFileSync(legacyFile, "utf8"));
    writeFileSync(legacyFile, JSON.stringify({ ...legacyHeld, rawSha256: "0".repeat(64) }));
    await refusedBoth("a finding report for another raw file", wrongReport, /legacy finding report is for another run/);
    writeFileSync(legacyFile, JSON.stringify({ ...legacyHeld, purgeConfirm: "changed" }));
    await refusedBoth("a review bound to another report", wrongReport, /review is not bound/);

    const falseFired = clean();
    await run(falseFired, pass2(falseFired), stopSoon);
    rmSync(fx.stopFile);
    const firedRun = join(falseFired.results, "e20r-pass2");
    stoppedFor(firedRun, PRIVACY_STOP);
    add("prune before the review", "refused", pruned(firedRun), /before any prune/);
    const replaySaid = [];
    const replayCode = reportMain(["--replay", join(firedRun, "raw.jsonl")], { log: (m) => replaySaid.push(m), fail: quiet });
    add("replay prints counts only", "allowed", truth(replayCode === 0 && !/selftest|example/.test(replaySaid.join("")) && JSON.parse(replaySaid[0]).records > 0, "replay"));
    add("pass 3 before the review", "refused", await run(falseFired, pass3(falseFired), { preregText: adopted }), /no legacy finding report/);
    add("no pilot round before the review", "refused", await run(falseFired, pilotArgs(50, 2), { preregText: adopted }), /pass 2 has started.*legacy finding/);
    add("the frozen detector reproduces the stop", "allowed", { code: reportMain(["--legacy-findings", firedRun], { log: quiet, fail: quiet }), said: "found" });
    add("pass 3 with a finding and no review", "refused", await run(falseFired, pass3(falseFired), { preregText: adopted }), /no recorded false-fire review/);
    const unnamed = [];
    add("a review with no person named", "refused", { code: reportMain(["--privacy", firedRun, "--false-fire", reviewNote], { log: quiet, fail: (m) => unnamed.push(m) }), said: unnamed.join(" ") }, /--reviewer/);
    add("a review with a person named", "allowed", { code: reportMain(["--privacy", firedRun, "--false-fire", reviewNote, "--reviewer", "acceptance"], { log: quiet, fail: quiet }), said: "reviewed" });
    add("pass 3 before the prune", "refused", await run(falseFired, pass3(falseFired), { preregText: adopted }), /no prune proof/);
    add("the stopped pass is pruned", "allowed", pruned(firedRun), /"verified":true/);
    add("pilot round 2 before Amendment 3 is adopted", "refused", await run(falseFired, pilotArgs(50, 2)), /needs Amendment 3 adopted/);
    add("pass 3 with no pilot round after the stop", "refused", await run(falseFired, pass3(falseFired), { preregText: adopted }), /pilot round after the stopped pass/);
    secondRound(falseFired);
    add("pass 3 with the amendment unadopted", "refused", await run(falseFired, pass3(falseFired), { stopBeforeRun: true }), /Amendment 3 adopted/);
    const PRICE_FORM = "Look at (example.com). Cancel anytime";
    const REAL_FORM = "john at (mailbox-acme.com). Write anytime";
    plant.text = `${PRICE_FORM} ${REAL_FORM}`;
    plant.pages = 2;
    const thirdRun = await run(falseFired, pass3(falseFired), { preregText: adopted });
    add("pass 3 under Amendment 3", "allowed", thirdRun);
    add("W1: a fired page doesn't stop pass 3", "allowed", truth(plant.pages === 0 && !/STOP/.test(thirdRun.said), thirdRun.said.slice(0, 60)));
    const thirdManifest = JSON.parse(readFileSync(join(falseFired.results, "e20r-pass3", "manifest.json"), "utf8"));
    add("W1: the run logs it, per kind and cohort", "allowed", truth(thirdManifest.textWithheld.records === 2 && thirdManifest.textWithheld.kinds.email > 0 && Object.keys(thirdManifest.textWithheld.byCohort).length > 0 && !thirdManifest.partial, JSON.stringify(thirdManifest.textWithheld).slice(0, 70)));
    add("W1: the planted text is on no disk", "allowed", truth(!onDisk(root, PRICE_FORM) && !thirdRun.said.includes(PRICE_FORM), "every file under the run's root"));
    add("W3: a real address only the detector sees, on no disk", "allowed", truth(!onDisk(root, "mailbox-acme") && !thirdRun.said.includes("mailbox-acme"), "every file under the run's root"));
    const stoppedHosts = new Set(readFileSync(join(firedRun, "raw.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l).host));
    const thirdRaw = readFileSync(join(falseFired.results, "e20r-pass3", "raw.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
    const withheldRows = thirdRaw.filter((r) => r.evidence?.textWithheld);
    const plainRows = thirdRaw.filter((r) => r.status === "ok" && !r.evidence?.textWithheld);
    add("W6: withheld records keep label and grade", "allowed", truth(withheldRows.length === 2 && plainRows.length > 0 && withheldRows.every((r) => JSON.stringify([r.evidence.class, r.evidence.classRegistered, r.score, r.checks.map((c) => [c.id, c.passed])]) === JSON.stringify([plainRows[0].evidence.class, plainRows[0].evidence.classRegistered, plainRows[0].score, plainRows[0].checks.map((c) => [c.id, c.passed])])), "same label, grade and checks"));
    const thirdDir = join(falseFired.results, "e20r-pass3");
    add("W8: a clean privacy report after withholding", "allowed", privacy(thirdDir));
    const analyzed = analysis(thirdDir);
    const analyzedOut = JSON.parse(readFileSync(join(thirdDir, "analysis.json"), "utf8"));
    add("W: analysis reports withheld overall and per cohort", "allowed", { code: analyzed.code || (analyzedOut.textWithheld?.records === 2 && Object.keys(analyzedOut.textWithheld.byCohort).length ? 0 : 3), said: analyzed.said });
    const drawSaid = [];
    add("E27: the draw reports what it left out", "allowed", { code: validation(["draw", thirdDir], { log: (m) => drawSaid.push(m), fail: (m) => drawSaid.push(m) }), said: drawSaid.join(" ") }, /"withheldFromDraw":2/);
    // The real commands in a row, on a real pass with withheld records and a real analysis.
    const realKey = JSON.parse(readFileSync(join(thirdDir, "validation-key.json"), "utf8"));
    const realLabels = `id,label\n${realKey.map((k) => `${k.id},${k.ruleLabel}`).join("\n")}\n`;
    for (const role of ["human", "model"]) {
      writeFileSync(join(thirdDir, `labels-${role}.csv`), realLabels);
      validation(["bind", thirdDir, role, JSON.parse(readFileSync(join(thirdDir, "prune-manifest.json"), "utf8")).sheetSha256], { log: quiet, fail: quiet });
    }
    // A fixture's manifest names a stand-in state, so each step is told to run under it.
    const realManifest = JSON.parse(readFileSync(join(thirdDir, "manifest.json"), "utf8"));
    const realState = { ...stateOf(realManifest), runtimeSha256: realManifest.runtimeSha256 };
    analysis(thirdDir, fx.prereg, { state: realState });
    const realSaid = [];
    const realScore = validation(["score", thirdDir], { log: quiet, fail: (m) => realSaid.push(m), state: realState });
    const i = fx.inputs;
    const realReport = realScore || tables(["--analysis", join(thirdDir, "analysis.json"), "--score", join(thirdDir, "score.json"), "--out", join(thirdDir, "final-report.md"), "--run", thirdDir, "--pass2", i["Pass 1 raw"], "--e20", i["E20 Tranco raw"], i["E20 YC raw"], "--industries", i["Industry map"], "--e20-excluded", i["E20 exclusion file"]], { log: quiet, fail: (m) => realSaid.push(m), state: realState, preregText: fx.prereg });
    add("R: a real pass, real analysis, score and report, checked against the run", "allowed", { code: realReport, said: realSaid.join(" ") || "reported" });
    const realText = existsSync(join(thirdDir, "final-report.md")) ? readFileSync(join(thirdDir, "final-report.md"), "utf8") : "";
    const realFrame = JSON.parse(readFileSync(join(thirdDir, "audit-frame.json"), "utf8"));
    const realRows = realText.split("\n").filter((l) => /^\| C(?:1|2|3|4|5|8|9|10|11) \|/.test(l));
    add("R: real-page views say so exactly when the headline is not estimable", "allowed", truth(realRows.length > 0 && (realFrame.notEstimable ? realText.includes(NOT_VALIDATED) : !realText.includes(NOT_VALIDATED)) && realText.indexOf("Headline audit") < realText.indexOf("## Claims"), `headline ${realFrame.headline}, ${realText.split(NOT_VALIDATED).length - 1} warnings`));
    const headerMiss = join(falseFired.results, "header-miss");
    cpSync(thirdDir, headerMiss, { recursive: true });
    rmSync(join(headerMiss, "prune-manifest.json"));
    const missRaw = `${readFileSync(join(headerMiss, "raw.jsonl"), "utf8")}${JSON.stringify({ status: "ok", evidence: { values: { server: "jan@example.nl" } } })}\n`;
    writeFileSync(join(headerMiss, "raw.jsonl"), missRaw);
    writeFileSync(join(headerMiss, "manifest.json"), JSON.stringify({ ...JSON.parse(readFileSync(join(headerMiss, "manifest.json"), "utf8")), rawSha256: hashOf(missRaw) }));
    add("W8: a header miss on a finished pass fails the report", "refused", privacy(headerMiss));
    add("W8: and analysis then waits for a person", "refused", analysis(headerMiss), /privacy report/);
    add("nobody gets a second visit in pass 3", "allowed", truth(stoppedHosts.size > 0 && thirdRaw.filter((r) => stoppedHosts.has(r.host)).length === stoppedHosts.size && thirdRaw.filter((r) => stoppedHosts.has(r.host)).every((r) => r.status === "excluded" && !r.counters), "pass 3 records"));
    add("pass 3's manifest names the stopped pass", "allowed", truth(JSON.parse(readFileSync(join(falseFired.results, "e20r-pass3", "manifest.json"), "utf8")).stoppedPass?.sites === stoppedHosts.size, "manifest"));
    add("a second start of pass 3", "refused", await catching(() => run(falseFired, pass3(falseFired), { preregText: adopted })), /already holds a run/);
    add("the pass 2 lock stays", "refused", await catching(() => run(falseFired, pass2(falseFired), { preregText: adopted })), /already holds a run/);
    add("no pilot round after pass 3 started", "refused", await run(falseFired, pilotArgs(50, 3), { preregText: adopted }), /pass 3 has started/);
    const noStop = clean();
    add("pass 3 with no pass 2 at all", "refused", await run(noStop, pass3(noStop), { preregText: adopted }), /no stopped pass|there is none/);
    const wholeThen = clean();
    await run(wholeThen, pass2(wholeThen));
    add("pass 3 after a whole pass 2", "refused", await run(wholeThen, pass3(wholeThen), { preregText: adopted }), /no finished, partial manifest/);
    const purgedStop = clean();
    await run(purgedStop, pass2(purgedStop), stopSoon);
    rmSync(fx.stopFile);
    purge(join(purgedStop.results, "e20r-pass2"));
    add("pass 3 after a purged pass 2", "refused", await run(purgedStop, pass3(purgedStop), { preregText: adopted }), /purged/);
    // Package 8, A to F. Every text field, every exit, both sides of the worker boundary.
    mkdirSync(join(root, "stubs"));
    writeFileSync(join(root, "stubs", "throws.mjs"), `throw new Error(${JSON.stringify(fires("canary-thrown"))});`);
    writeFileSync(join(root, "stubs", "hangs.mjs"), 'import { parentPort } from "node:worker_threads"; parentPort.postMessage({ progress: { requests: 1, bytes: 1, redirects: 0, hosts: [] } }); for (;;);');
    const canaries = await canarySite();
    const canaryPort = canaries.address().port;
    const rowFor = (name) => CANARY_LIST().find((r) => r.host.startsWith(`${name}.`));
    const raw = (dir) => readFileSync(join(dir, "raw.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));

    const whole2 = await canaryRun(root, "whole");
    const wholeRows = raw(join(whole2.dir, "run"));
    const byName = (name) => wholeRows.find((r) => r.host.startsWith(`${name}.`));
    for (const name of ["a-title", "a-text", "a-noscript", "a-error", "a-others", "a-real"]) add(`A1,4: a finding in ${name} withholds the record`, "allowed", truth(Boolean(byName(name)?.evidence?.textWithheld), JSON.stringify(byName(name)?.evidence?.textWithheld ?? null)));
    add("A2,12: several findings are one record, with counts per kind", "allowed", truth(byName("a-multi").evidence.textWithheld.fields === 3 && byName("a-multi").evidence.textWithheld.kinds.email === 3 && whole2.manifest.textWithheld.records === 7, JSON.stringify(byName("a-multi").evidence.textWithheld)));
    add("A5: a normal address becomes <email>, and isn't withheld", "allowed", truth(!byName("a-normal").evidence.textWithheld && byName("a-normal").evidence.pageExcerpt.text.includes("<email>"), "kept, scrubbed"));
    add("A6: no canary in any file, temp folder, stdout or stderr", "allowed", truth(!whole2.leaked && existsSync(join(whole2.dir, "run", "validation-sheet.json")) && existsSync(join(whole2.dir, "run", "privacy-report.json")), `${whole2.said.length} bytes of output scanned`));
    const signaledCanary = await canaryRun(root, "signal", "visited");
    add("A7: a signal leaves no canary", "allowed", truth(!signaledCanary.leaked && signaledCanary.manifest.partial === true, String(signaledCanary.manifest.stoppedFor)));
    const stoppedCanary = await canaryRun(root, "stopfile");
    add("A7: the stop file leaves no canary", "allowed", truth(!stoppedCanary.leaked && stoppedCanary.manifest.partial === true, String(stoppedCanary.manifest.stoppedFor)));
    const thrownCanary = await canaryRun(root, "worker");
    add("A7: a worker error leaves no canary, even in its message", "allowed", truth(!thrownCanary.leaked && raw(join(thrownCanary.dir, "run")).every((r) => r.status === "error"), "every visit failed"));
    const hungCanary = await canaryRun(root, "hardcap");
    add("A7: a hard-cap timeout leaves no canary", "allowed", truth(!hungCanary.leaked && raw(join(hungCanary.dir, "run")).every((r) => r.reason === "hard_cap"), "every visit capped"));
    const racedCanary = await canaryRun(root, "final", "finalizing");
    add("A7: a signal in finalization leaves no canary", "allowed", truth(!racedCanary.leaked && racedCanary.manifest.partial === true, String(racedCanary.manifest.stoppedFor)));
    const controlCanary = await canaryRun(root, "control");
    add("A control: pass 2's path does store it, so the scan can fail", "allowed", truth(controlCanary.leaked && controlCanary.manifest.stoppedFor === PRIVACY_STOP, String(controlCanary.manifest.stoppedFor)));
    add("B14: pass 2 keeps its write and stop", "allowed", truth(raw(join(controlCanary.dir, "run")).some((r) => /canary-/.test(JSON.stringify(r.evidence ?? {}))), "text stored, then the stop"));

    const unflagged = await visitInWorker(rowFor("a-text"), { loopbackPort: canaryPort, withhold: false });
    const flagged = await visitInWorker(rowFor("a-text"), { loopbackPort: canaryPort, withhold: true });
    add("A9: the worker alone withholds", "allowed", truth(JSON.stringify(unflagged).includes("canary-text") && !JSON.stringify(flagged).includes("canary-text"), "with and without the worker's check"));
    const onlyText = new Set(["evidence.pageExcerpt.title", "evidence.pageExcerpt.text", "evidence.pageExcerpt.noscript", "evidence.excerpt", "evidence.others.[].excerpt", "evidence.textWithheld"]);
    const changedPaths = diffPaths({ ...unflagged, at: "" }, { ...flagged, at: "" });
    add("B10: nothing but the five text paths and the marker changed", "allowed", truth(changedPaths.length > 0 && changedPaths.every((p) => onlyText.has(p)), changedPaths.join(" ")));
    const allFive = { evidence: { excerpt: fires("x"), pageExcerpt: { title: "t", text: "t", noscript: "t", chars: 1 }, others: [{ kind: "s", excerpt: "t", bodySha256: "h" }, { kind: "r", bodySha256: "h" }] } };
    add("A: any finding removes all five paths", "allowed", truth(diffPaths(allFive, withholdText(allFive)).every((p) => onlyText.has(p)) && !/"t"/.test(JSON.stringify(withholdText(allFive))), "main excerpt fired, four others went too"));
    add("B11: the marker passes the scan", "allowed", truth(Object.values(recordMisses(flagged)).every((n) => n === 0), "recordMisses"));
    add("B13: withholding twice is withholding once", "allowed", truth(JSON.stringify(withholdText(withholdText(allFive))) === JSON.stringify(withholdText(allFive)) && safeRecord(flagged) === flagged, "idempotent"));

    const SAMPLES = { ipv4: "203.0.113.7", ipv6: "2001:db8::1:2", email: "a@example.org", query: "page?a=b", fragment: "page#a=b", jwt: "eyJhbGci.eyJzdWI.sig", longHex: "0123456789abcdef0123456789abcdef", longNumber: "123456789012" };
    const stubFile = join(root, "stubs", "raw-text.mjs");
    writeFileSync(stubFile, `import { parentPort, workerData } from "node:worker_threads"; const texts = ${JSON.stringify(SAMPLES)}; const { row } = workerData; const kind = row.host.split(".")[0]; parentPort.postMessage({ record: { ...row, status: "ok", httpStatus: 200, checks: [], evidence: { bodySha256: "h", pageExcerpt: { text: texts[kind] ?? "A page." }, others: [] }, finalHost: row.host, score: 1, counters: {}, hops: [], robots: [] } });`);
    const kindList = mergeCohorts({ T1k: Object.keys(SAMPLES).map((k, i) => ({ host: `${k}.selftest.example.com`, rank: i + 1, group: "x" })) });
    const seenByCallback = [];
    const kindRun = await runPass(kindList, { pass: 3, out: join(root, "kinds"), loopbackPort: 9, delayMs: 0, dns: NO_DNS_AT_ALL, workerFile: stubFile, onRecord: (r) => seenByCallback.push(JSON.stringify(r)) });
    const kindManifest = JSON.parse(readFileSync(join(root, "kinds", "manifest.json"), "utf8"));
    add("A3: every detector kind withholds", "allowed", truth(Object.keys(SAMPLES).every((k) => kindManifest.textWithheld.kinds[k] > 0) && kindManifest.textWithheld.records === 8, Object.keys(kindManifest.textWithheld.kinds).join(" ")));
    add("A8,9: with a worker that doesn't withhold, the parent does", "allowed", truth(kindRun.records.every((r) => r.evidence.textWithheld) && !Object.values(SAMPLES).some((t) => onDisk(join(root, "kinds"), t)), "parent check alone"));
    add("A8: callbacks and aggregation never see the text", "allowed", truth(seenByCallback.length === 8 && !seenByCallback.some((r) => Object.values(SAMPLES).some((t) => r.includes(t))) && !Object.values(SAMPLES).some((t) => JSON.stringify(kindRun.aggregate).includes(t)), "onRecord and the aggregate"));

    const pilotAt = (name) => ({ ...fx, results: join(root, name), roundsLog: join(root, `${name}.log`) });
    const sealOf = (at) => join(at.results, "e20r-pilot-1");
    // Every normal DMARC record is stored as `rua=mailto:<redacted>@...`, by the real read, so a round must seal with one.
    const withDmarc = pilotAt("pilot-dmarc");
    const dmarcTxt = (name) => (name.startsWith("_dmarc.") ? Promise.resolve([["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]]) : stub());
    await run(withDmarc, pilotArgs(50, 1), { dns: { ...DNS, resolveTxt: dmarcTxt } });
    const dmarcSealed = close(fx, sealOf(withDmarc));
    const dmarcStored = rawOf(sealOf(withDmarc)).filter((r) => r.dns?.listed?.dmarcRecord?.includes("<redacted>@example.com")).length;
    const dmarcGate = await gate(withDmarc);
    add("a round whose records hold a real DMARC rua seals and clears the gate", "allowed", { code: dmarcSealed || dmarcGate.code || (dmarcStored ? 0 : 3), said: `${dmarcStored} records hold it, ${dmarcGate.said}` }, /authorized/);
    for (const n of [0, 1, 2]) {
      Object.assign(plant, { text: fires(`pilot-form-${n}`), pages: n, errors: 0 });
      const at = pilotAt(`pilot-${n}`);
      await run(at, pilotArgs(50, 1));
      const sealed = close(fx, sealOf(at));
      add(`C15: ${n} withheld seals, takes a go, and clears the pilot gate`, "allowed", await (async () => { const got = await gate(at); return { code: sealed || got.code, said: got.said }; })(), /authorized/);
      add(`C18: ${n} withheld is no scrub miss in the report`, "allowed", truth(Object.values(JSON.parse(readFileSync(join(sealOf(at), "pilot-report.json"), "utf8")).scrubMisses).every((v) => v === 0) && !onDisk(root, "pilot-form"), "report clean, text on no disk"));
    }
    Object.assign(plant, { text: fires("three-form"), pages: 3, errors: 0 });
    const threePilot = pilotAt("pilot-three");
    await run(threePilot, pilotArgs(50, 1));
    const threeCode = close(fx, sealOf(threePilot), { prune: false });
    add("C16: 3 of 50 withheld fails the seal", "refused", { code: threeCode, said: JSON.parse(readFileSync(join(sealOf(threePilot), "pilot-result.json"), "utf8")).stop.join("; ") }, /over 2 records had their text withheld/);
    const notGo = [];
    add("C16: and the round can't be a go", "refused", { code: reportMain(["--decide", sealOf(threePilot), "--decision", "go", "--reviewer", "x"], { log: quiet, fail: (m) => notGo.push(m) }), said: notGo.join(" ") }, /can't be a go/);
    const excerptReport = (twoxxWithExcerpt, twoxxWithheld) => ({ scrubMisses: {}, outcomes: {}, sites: 50, evidence: { graded: 50, twoxx: 30, twoxxWithExcerpt, twoxxWithheld }, dns: { read: 50, answered: { spf: 50, dmarc: 50 } }, resolverFailures: 0, counters: { maxRequestsPerSite: 3 }, excludedHops: 0 });
    add("C17: the 90% rule reads readable 2xx", "allowed", truth(stopRules(excerptReport(27, 0), { floors: false }).length === 0 && stopRules(excerptReport(26, 2), { floors: false }).length === 0 && stopRules(excerptReport(25, 2), { floors: false }).length === 1, "27 of 30 and 26 of 28 pass; 25 of 28 fails"));
    for (const [field, leak] of Object.entries({ header: { evidence: { values: { server: "jan@example.nl" } } }, dns: { dns: { listed: { dmarcRecord: "rua=jan@example.nl" } } } })) {
      const noted = join(root, `non-text-${field}`);
      cpSync(join(falseFired.results, "e20r-pass3"), noted, { recursive: true });
      rmSync(join(noted, "prune-manifest.json"));
      const text = `${readFileSync(join(noted, "raw.jsonl"), "utf8")}${JSON.stringify({ status: "ok", ...leak })}\n`;
      writeFileSync(join(noted, "raw.jsonl"), text);
      writeFileSync(join(noted, "manifest.json"), JSON.stringify({ ...JSON.parse(readFileSync(join(noted, "manifest.json"), "utf8")), rawSha256: hashOf(text) }));
      add(`C19: a ${field} finding still goes to the privacy report`, "refused", privacy(noted));
    }

    const stubAll = join(root, "stubs", "all-fire.mjs");
    writeFileSync(stubAll, `import { parentPort, workerData } from "node:worker_threads"; const { row } = workerData; parentPort.postMessage({ record: { ...row, status: "ok", httpStatus: 200, checks: [], evidence: { bodySha256: "h", pageExcerpt: { text: ${JSON.stringify(fires("every-page"))} } }, finalHost: row.host, score: 1, counters: {}, hops: [], robots: [] } });`);
    const manyList = mergeCohorts({ T1k: Array.from({ length: 300 }, (_, i) => ({ host: `m${i}.selftest.example.com`, rank: i + 1, group: "x" })) });
    const many = await runPass(manyList, { pass: 3, out: join(root, "many"), loopbackPort: 9, delayMs: 0, concurrency: 8, workerFile: stubAll, dns: NO_DNS_AT_ALL });
    add("D20: every record withheld doesn't stop pass 3, and all are reported", "allowed", truth(!many.stoppedFor && many.records.length === 300 && JSON.parse(readFileSync(join(root, "many", "manifest.json"), "utf8")).textWithheld.records === 300 && !onDisk(join(root, "many"), "every-page"), "300 of 300"));

    const auditRows = [...Array.from({ length: 400 }, (_, i) => ({ host: `d${i}.org`, status: "ok", httpStatus: 200, cohorts: { T1k: {} }, platform: { edge: "other" }, evidence: { class: { label: "candidate-page" }, ...(i % 4 === 0 ? { textWithheld: { kinds: { email: 1 }, fields: 1 } } : {}) } })), ...Array.from({ length: 25 }, (_, i) => ({ host: `c${i}.org`, status: "ok", httpStatus: 403, cohorts: { "YC-new": {} }, platform: { edge: "cloudflare" }, evidence: { class: { label: "challenge" }, ...(i < 10 ? { textWithheld: { kinds: { fragment: 1 }, fields: 1 } } : {}) } }))];
    const drawn = drawSample(auditRows);
    add("E27: the draw never picks a withheld record", "allowed", truth(drawn.every((d) => !auditRows.find((r) => r.host === d.host).evidence.textWithheld), `${drawn.length} rows`));
    add("E28: stratum sizes and weights use the non-withheld frame", "allowed", truth(drawn.filter((d) => d.stratum === "candidate-page").length === 150 && drawn.find((d) => d.stratum === "candidate-page").stratumSize === 300, "300 of 400 in the frame"));
    const counted = (await import("./record-checks.mjs")).withheldCounts(auditRows);
    add("E29: withheld is reported as a share, and small groups join other", "allowed", truth(counted.byCohort.T1k.share === 0.25 && counted.byCohort["YC-new"].share === 0.4 && counted.byStatus["2xx"].of === 400 && !("none" in counted.byStatus), "by cohort, status class and share"));
    add("E29: counts reconcile overall and by every group", "allowed", truth(counted.records === 110 && ["byCohort", "byStratum", "byLabel", "byStatus", "byEdge"].every((g) => Object.values(counted[g]).reduce((n, v) => n + v.records, 0) === 110) && counted.kinds.email === 100 && counted.kinds.fragment === 10, "110 in every group"));
    const frame = auditFrame(auditRows);
    add("E30: a stratum over 2.0% makes the headline not estimable", "allowed", truth(frame.notEstimable && frame.headline === "not estimable" && frame.strata.challenge.overLimit && frame.strata.challenge.frame === 15, "10 of 25 withheld"));
    const oneStratum = (eligible, withheld) => auditFrame(Array.from({ length: eligible }, (_, i) => ({ status: "ok", evidence: { class: { label: "challenge" }, ...(i < withheld ? { textWithheld: { kinds: { email: 1 }, fields: 1 } } : {}) } })));
    add("E30: exactly 2.0% stands", "allowed", truth(!oneStratum(50, 1).notEstimable && !oneStratum(150, 3).notEstimable, "1 of 50, 3 of 150"));
    add("E30: just over 2.0% doesn't", "allowed", truth(oneStratum(49, 1).notEstimable && oneStratum(149, 3).notEstimable, "1 of 49, 3 of 149"));
    add("E30: a small frame alone doesn't decide the headline", "allowed", truth(!oneStratum(10, 0).notEstimable && !oneStratum(10, 0).labels.challenge.figures, "10 rows, no figures of its own"));
    const reportedFrame = scoreLabels(key, labels(3), labels(3), { frame, resamples: 10 });
    add("E30: the score says the headline first, and keeps the rest", "allowed", truth(Object.keys(reportedFrame)[0] === "headline" && reportedFrame.frame.share > 0 && Boolean(reportedFrame.worstCase.page) && Boolean(reportedFrame.metrics), Object.keys(reportedFrame).slice(0, 3).join(" ")));
    const scoredRows = drawn.map((d, i) => ({ ...d, id: i + 1, human: d.ruleLabel }));
    const bounds = worstCaseBounds(scoredRows, frame.withheldByRule);
    add("E31: worst-case bounds count all withheld rows", "allowed", truth(bounds.page.precision < 0.76 && bounds.page.precision > 0.74 && frame.withheld === 110, `page precision ${bounds.page.precision.toFixed(3)}`));
    const claimRows = [...Array.from({ length: 25 }, (_, i) => ({ host: `t${i}.org`, finalHost: `t${i}.org`, status: "ok", cohorts: { T1k: { rank: 1 } }, checks: [{ id: "csp", passed: i < 5, weight: 1 }], evidence: { class: { label: "candidate-page" } } })), ...Array.from({ length: 25 }, (_, i) => ({ host: `y${i}.org`, finalHost: `y${i}.org`, status: "ok", cohorts: { "YC-new": { rank: 1 } }, checks: [{ id: "csp", passed: i < 15, weight: 1 }], evidence: { class: { label: "candidate-page" } } }))];
    const claimMarked = claimRows.map((r, i) => (i % 3 ? r : { ...r, evidence: { ...r.evidence, textWithheld: { kinds: { email: 1 }, fields: 1 } } }));
    add("E32: main claims keep withheld records", "allowed", truth(JSON.stringify(claims(claimRows, null, {}, { resamples: 20 })) === JSON.stringify(claims(claimMarked, null, {}, { resamples: 20 })), "claims identical"));

    const forgedRun = clean();
    await run(forgedRun, pass2(forgedRun), stopSoon);
    rmSync(fx.stopFile);
    const forgedDir = passDir(forgedRun);
    stoppedFor(forgedDir, PRIVACY_STOP);
    const forgedRaw = raw(forgedDir);
    forgedRaw[0].evidence = { values: { server: "Reach us at <email>. Open daily" } };
    const forgedText = `${forgedRaw.map((r) => JSON.stringify(r)).join("\n")}\n`;
    writeFileSync(join(forgedDir, "raw.jsonl"), forgedText);
    writeFileSync(join(forgedDir, "manifest.json"), JSON.stringify({ ...JSON.parse(readFileSync(join(forgedDir, "manifest.json"), "utf8")), rawSha256: hashOf(forgedText) }));
    reportMain(["--legacy-findings", forgedDir], { log: quiet, fail: quiet });
    const forgedFile = join(forgedDir, "legacy-findings.json");
    const genuine = JSON.parse(readFileSync(forgedFile, "utf8"));
    add("F35: the named review stays bound after withholding", "allowed", truth(JSON.parse(readFileSync(join(firedRun, "privacy-report.json"), "utf8")).reviewed.legacyFindingsSha256 === sha256(readFileSync(join(firedRun, "legacy-findings.json"))), "legacyFindingsSha256"));
    add("F33: the report itself says the stop isn't reproduced", "allowed", truth(genuine.reproducesStop === false && genuine.findings[0].path === "evidence.values.server", genuine.findings[0].path));
    writeFileSync(forgedFile, JSON.stringify({ ...genuine, reproducesStop: true }));
    const forgedSaid = [];
    add("F33: a forged summary can't get a review", "refused", { code: reportMain(["--privacy", forgedDir, "--false-fire", reviewNote, "--reviewer", "x"], { log: quiet, fail: (m) => forgedSaid.push(m) }), said: forgedSaid.join(" ") }, /nothing to call a false fire/);
    reportMain(["--privacy", forgedDir], { log: quiet, fail: quiet });
    const bindReview = (report) => {
      const bytes = JSON.stringify(report);
      writeFileSync(forgedFile, bytes);
      const file = join(forgedDir, "privacy-report.json");
      writeFileSync(file, JSON.stringify({ ...JSON.parse(readFileSync(file, "utf8")), reviewed: { noteSha256: "a".repeat(64), reviewer: "x", legacyFindingsSha256: hashOf(bytes) } }));
    };
    bindReview({ ...genuine, reproducesStop: true });
    validation(["prune", forgedDir], { log: quiet, fail: quiet });
    await refusedBoth("F33: a forged summary with a hand-bound review", forgedRun, /not valid: its summary doesn't match/);
    const good = genuine.findings[0];
    const pagePath = { ...good, path: "evidence.pageExcerpt.text" };
    for (const [name, findings, why] of [["a text order", [{ ...pagePath, order: "0" }], /record the raw file/], ["an order not in the raw file", [{ ...pagePath, order: 99999 }], /record the raw file/], ["an unknown path", [{ ...pagePath, path: "nowhere.x" }, pagePath], /unknown field/], ["an unknown kind", [{ ...pagePath, kind: "shape" }], /unknown kind/], ["a zero count", [{ ...pagePath, count: 0 }], /valid count/], ["a negative count", [{ ...pagePath, count: -2 }], /valid count/], ["a duplicate finding", [pagePath, pagePath], /appears twice/]]) {
      bindReview({ ...genuine, findings, reproducesStop: true });
      add(`F34: ${name}`, "refused", await run(forgedRun, pass3(forgedRun), { preregText: adopted }), why);
    }
    bindReview({ ...genuine, findings: [pagePath], reproducesStop: false });
    add("F34: a summary that disagrees with its findings", "refused", await run(forgedRun, pass3(forgedRun), { preregText: adopted }), /summary doesn't match/);
    canaries.closeAllConnections();
    await new Promise((r) => canaries.close(r));

    add("the scrub's own output doesn't stop a run", "allowed", truth(!pageTextMissed({ evidence: { pageExcerpt: { text: scrub("Reach us at info@example.com. We reply.") } } }), "pageTextMissed"));

    const wrongInput = fx.prereg.replace(/(Pass 1 raw SHA-256 \| `)[0-9a-f]{64}/, `$1${"0".repeat(64)}`);
    const secondRun = clean();
    add("7: a registered input that doesn't match", "refused", await (async () => { await run(secondRun, pass2(secondRun)); const dir = join(secondRun.results, "e20r-pass2"); privacy(dir); return analysis(dir, wrongInput); })(), /Pass 1 raw does not match/);
    await stops("a claim cohort with no usable output", /no usable output in YC-old/, ({ evidence: _e, checks: _c, finalHost: _f, ...r }) => (r.cohorts?.["YC-old"] ? { ...r, status: "error", error: "timeout" } : { ...r, evidence: _e, checks: _c, finalHost: _f }));
    const noSeal = variant(fx, (r) => r, (m) => ({ ...m, partial: true, stoppedFor: "the stop file exists" }));
    validation(["prune", noSeal.runDir], { log: quiet });
    add("5: a finished manifest needs a seal, stopped or not", "refused", await gate(noSeal), /no sealed report/);
    const purgedRound = clean();
    secondRound(purgedRound);
    purge(purgedRound.runDir);
    add("5: a purged round counts as text gone", "allowed", await gate(purgedRound), /authorized/);

    add("2: an IPv4 in finalHost or hops is a miss", "allowed", truth(recordMisses({ finalHost: "203.0.113.9" }).ipv4 > 0 && recordMisses({ hops: ["203.0.113.9"] }).ipv4 > 0, "recordMisses"));
    add("4: only a real digest at a known path is exempt", "allowed", truth(recordMisses({ evidence: { bodySha256: "a".repeat(64) } }).longHex === 0 && recordMisses({ evidence: { bodySha256: "jan@example.nl" } }).email === 1 && recordMisses({ evidence: { otherSha256: "a".repeat(64) } }).longHex === 1, "recordMisses"));
    add("2: an SPF address is the one exception", "allowed", truth(recordMisses({ dns: { listed: { spfRecord: "v=spf1 ip4:203.0.113.7 -all" } } }).ipv4 === 0 && recordMisses({ dns: { listed: { dmarcRecord: "203.0.113.7" } } }).ipv4 > 0, "recordMisses"));
    add("2: a redirect to a literal IPv4 is refused", "allowed", truth((() => { try { strictRobots().robotsHop(new URL("http://203.0.113.9/")); return false; } catch (e) { return e.reason === "ipv4_literal"; } })(), "robotsHop"));
    add("6: secondary intervals are labeled, DNS from DNS records", "allowed", truth(secondaryCohorts([], []).every((c) => c.interval === "naive row-level" && c.source === "dns"), "secondaryCohorts"));
    add("8: unsure totals and denominators stand apart", "allowed", truth((() => { const v = scoreLabels(key, labels(3, (i) => (i === 1 ? "1,unsure" : `${i},page`)), labels(3), { resamples: 10 }).humanVsAgent; return v.humanUnsure === 1 && v.agentUnsure === 0 && v.bothAnswered === 2; })(), "scoreLabels"));
    add("C1: a tenant of a shared suffix is its own organization", "allowed", truth(siteOrg("www.github.io") === "www.github.io" && siteOrg("github.io") === "github.io", "siteOrg"));
    add("C2: a host-specific DMARC failure counts", "allowed", truth(resolverFailed({ dns: { listed: { outcomes: {}, queries: [{ outcome: "resolver-failure:timeout" }] } } }), "resolverFailed"));
    add("C7: the amendment removes the header-check labels", "allowed", truth(/removes the inherited requirement that labelers judge/.test(readFileSync(PREREG_R, "utf8")), "amendment"));
    const sheet = existsSync(SHEET) ? readFileSync(SHEET, "utf8") : "";
    add("C9: the run sheet holds acceptance and recovery", "allowed", truth(["npm run e20r:acceptance", "validation-sample.mjs prune", "pilot-report.mjs --privacy", "Failure recovery"].every((t) => sheet.includes(t)), "run sheet"));
    add("a compressed answer is no candidate page", "allowed", truth(classify({ status: 200, headers: { "content-encoding": "gzip" }, body: "" }).label === "body-unavailable", "classify"));
    const beaten = "User-agent: Penthera-Research\nDisallow: /\nAllow: /\n";
    add("the early opt-out agrees with the matcher", "allowed", truth(!wholeSiteStop(beaten) && robotsVerdict(beaten, "/") === "allowed", "robots"));

    // Package 9: a worker that says it withheld and didn't. Raw, callbacks, reports, temp files, stdout, stderr.
    writeFileSync(join(root, "stubs", "marker.mjs"), `import { parentPort, workerData } from "node:worker_threads"; const fires = ${JSON.stringify(fires("canary-marker"))}; const { row } = workerData; const place = row.host.split(".")[0]; const page = { title: place === "a-title" ? fires : "plain", text: place === "a-text" ? fires : "plain", noscript: place === "a-noscript" ? fires : "plain" }; parentPort.postMessage({ record: { ...row, status: "ok", httpStatus: 200, checks: [], finalHost: row.host, score: 1, counters: {}, evidence: { bodySha256: "h", textWithheld: { kinds: { email: 1 }, fields: 1 }, pageExcerpt: page, excerpt: place === "a-error" ? fires : "plain", others: [{ kind: "x", excerpt: place === "a-others" ? fires : "plain" }] } } });`);
    const markerRun = await canaryRun(root, "marker");
    const markerRows = raw(join(markerRun.dir, "run"));
    add("M: a marker beside text leaves no canary in any file, temp folder, stdout or stderr", "allowed", truth(!markerRun.leaked && markerRows.length === Object.keys(CANARY_PAGES).length && markerRows.every((r) => r.evidence.textWithheld && r.evidence.pageExcerpt.text === undefined && r.evidence.excerpt === undefined), `${markerRows.length} records, ${markerRun.said.length} bytes of output`));
    auditChainRows(root, add, truth, { inputs: fx.inputs, preregText: fx.prereg });

    const protocolNow = readFileSync(PREREG_R, "utf8");
    const liveClassifier = sha256(readFileSync(join(HERE, "classify.mjs")));
    add("the protocol names the live classifier, in both places", "allowed", truth(recordedHashR(protocolNow, "Frozen classifier") === liveClassifier && protocolNow.includes(`**New hash.** \`${liveClassifier}\``), liveClassifier.slice(0, 12)));

    add("audit labels complete", "allowed", scored(labels(3)));
    add("audit labels incomplete", "refused", scored(labels(2)), /no label/);
    add("audit labels duplicate", "refused", scored(labels(3).replace("2,page", "1,page")), /duplicate/);
    add("audit labels unknown id", "refused", scored(labels(3).replace("3,page", "9,page")), /unknown id/);
    add("audit labels invalid", "refused", scored(labels(3).replace("3,page", "3,maybe")), /invalid label/);
    add("agent labels incomplete", "refused", scored(labels(3), labels(2)), /agent labels/);
  } finally {
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
    rmSync(root, { recursive: true, force: true });
  }
  return rows;
}

async function main() {
  const rows = await runAcceptance();
  const width = Math.max(...rows.map((r) => r.condition.length));
  console.log(`${"Condition".padEnd(width)}  Expected  Result  Detail`);
  for (const r of rows) console.log(`${r.condition.padEnd(width)}  ${r.expect.padEnd(8)}  ${r.pass ? "PASS  " : "FAIL  "}  ${r.got}`);
  const failed = rows.filter((r) => !r.pass).length;
  console.log(`\n${rows.length - failed} of ${rows.length} passed.`);
  return failed ? 1 : 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const child = { "--finalizing-child": () => finalizingChild(process.argv[3]), "--canary-child": () => canaryChild(process.argv[3], process.argv[4], process.argv[5]) }[process.argv[2]];
  (child ?? main)().then((code) => { process.exitCode = code; });
}
