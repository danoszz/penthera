/**
 * E20-R2 acceptance, the audit's end: real commands on a synthetic, finished pass, from the
 * draw to the report. Each row runs through `main()`, as a run would. Nothing leaves the
 * machine, and the files stay in the caller's folder.
 */
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { scrub, scrubMisses } from "./classify.mjs";
import { pageTextMissed, safeRecord, selfHashed, withheldCounts, withholdText } from "./record-checks.mjs";
import { NOT_THE_RESULT, NOT_VALIDATED, main as report } from "./report-tables.mjs";
import { codeFiles, studyState } from "./replicate.mjs";
import { sha256 } from "./run.mjs";
import { auditFrame, main as validation, scoreLabels, stateOf, SUPPRESSED, NO_ANSWERS } from "./validation-sample.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const quiet = () => undefined;
const STRATUM_CLASS = {
  "candidate-page": { label: "candidate-page", rule: "page" }, challenge: { label: "challenge", rule: "c" },
  "block-signature": { label: "block", rule: "signature" }, "block-unrecognized-403": { label: "block", rule: "unrecognized-403" },
  "unrecognized-error-response": { label: "unrecognized-error-response", rule: "e" },
};
const RULE_TO_ANSWER = { "candidate-page": "page", challenge: "challenge", "block-signature": "block", "block-unrecognized-403": "block", "unrecognized-error-response": "error" };
const say = (fn, args) => { const said = []; const code = fn(args, { log: quiet, fail: (m) => said.push(m) }); return { code, said: said.join(" ") || "ok" }; };
const json = (file) => JSON.parse(readFileSync(join(file), "utf8"));
const put = (file, value) => writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);

/** Records for `sizes`, a count per stratum. The first `withheld[stratum]` of each lost their text. */
function records(sizes, withheld = {}, tag = "") {
  let order = 0;
  return Object.entries(sizes).flatMap(([stratum, n]) => Array.from({ length: n }, (_, i) => ({
    pass: 3, order: order++, host: `${tag}${stratum}-${i}.selftest.example.com`, status: "ok", httpStatus: stratum === "candidate-page" ? 200 : 403, cohorts: { T1k: { rank: i } }, platform: { edge: "other" },
    evidence: { status: 200, headerNames: ["server"], values: {}, cookieNames: [], class: STRATUM_CLASS[stratum], ...(i < (withheld[stratum] ?? 0) ? { pageExcerpt: { chars: 9 }, textWithheld: { kinds: { email: 1 }, fields: 1 } } : { pageExcerpt: { title: "Fine", text: `A plain page, ${tag}${i}.`, chars: 9 } }) },
  })));
}

/** A finished pass with a clean privacy report, under this checkout's state. */
export function finishedRun(dir, rows) {
  mkdirSync(dir, { recursive: true });
  const raw = `${rows.map((r) => JSON.stringify(r)).join("\n")}\n`;
  writeFileSync(join(dir, "raw.jsonl"), raw);
  const manifest = { study: "E20-R2", kind: "pass", pass: 3, git: { commit: "c".repeat(40) }, ...studyState(), finishedAt: "2026-11-07T00:00:00.000Z", immutableAtFinish: { ok: true }, rawSha256: sha256(Buffer.from(raw)) };
  put(join(dir, "manifest.json"), manifest);
  put(join(dir, "privacy-report.json"), { clean: true, rawSha256: manifest.rawSha256, manifestSha256: sha256(readFileSync(join(dir, "manifest.json"))) });
  return dir;
}

/** Labels that agree with the rules, as `id,label`. */
const labelsFor = (dir, change = (l) => l) => `id,label\n${json(join(dir, "validation-key.json")).map((k) => `${k.id},${change(RULE_TO_ANSWER[k.stratum])}`).join("\n")}\n`;

/** Draw, labels, bind and score, on one run. Returns the sheet hash the kit would show. */
export function scoredRun(dir, { resamples = 200, change } = {}) {
  validation(["draw", dir], { log: quiet, fail: quiet });
  for (const role of ["human", "model"]) writeFileSync(join(dir, `labels-${role}.csv`), labelsFor(dir, change));
  const shown = json(join(dir, "prune-manifest.json")).sheetSha256;
  for (const role of ["human", "model"]) validation(["bind", dir, role, shown], { log: quiet, fail: quiet });
  validation(["score", dir], { log: quiet, fail: quiet, resamples });
  return shown;
}

const VIEW = { diff: 0.1, ci: [0.05, 0.15], orgsA: 30, orgsB: 30, direction: "as predicted" };

/** An analysis of this run, in the shape analyze-r.mjs writes, with one view of each kind. */
export function analysisOf(dir) {
  const manifest = json(join(dir, "manifest.json"));
  const rows = readFileSync(join(dir, "raw.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
  const claim = (id) => ({ id, label: "x minus y", check: "csp", predicted: "-", S: VIEW, R: VIEW, decision: "supported" });
  return selfHashed({
    experiment: "E20-R", level: 0.9954, primaryRefusal: { n: rows.length, share: 0.1, ci: [0.05, 0.15] }, refusals: { all: 0.2, registered: 0.15 },
    claims: [claim("C1"), claim("C2"), { id: "C6", label: "DNS", check: "spf+dmarc", predicted: "-", S: VIEW, decision: "not estimable" }, { id: "C12", label: "share", n: 9, diff: 0.1, ci: [0.05, 0.15] }],
    cspControlsScripts: [claim("C1")], standardized: { C1: { diff: 0.1, ci: [0, 0.2] } }, standardizedR: { C1: { diff: 0.1, ci: [0, 0.2] } }, replicationAsE20: [claim("C1")],
    bounds: { C1: { low: 0, high: 0.2, coverageA: 0.9, coverageB: 0.9 } }, skipsByCohort: { T1k: { exclusion_list: 1 } }, dnsCoverage: { T1k: { read: 9, exists: 9, nxdomain: 0, unknown: 0 } },
    textWithheld: withheldCounts(rows), auditFrame: auditFrame(rows),
    provenance: { manifestSha256: sha256(readFileSync(join(dir, "manifest.json"))), rawSha256: sha256(readFileSync(join(dir, "raw.jsonl"))), state: stateOf(manifest) },
  });
}

const count = (text, needle) => text.split(needle).length - 1;

/** Every row of this package, handed to `add`. */
export function auditRows(root, add, truth) {
  const FULL = { "candidate-page": 160, challenge: 50, "block-signature": 50, "block-unrecognized-403": 30, "unrecognized-error-response": 20 };
  const at = (name) => join(root, "audit", name);
  mkdirSync(at(""), { recursive: true });
  const reportOf = (dir, analysis = analysisOf(dir), score = json(join(dir, "score.json"))) => {
    put(join(dir, "analysis.json"), analysis);
    const scoreFile = join(dir, "score-used.json");
    put(scoreFile, score);
    const out = join(dir, "final-report.md");
    rmSync(out, { force: true });
    const got = say(report, ["--analysis", join(dir, "analysis.json"), "--score", scoreFile, "--out", out]);
    return { ...got, text: existsSync(out) ? readFileSync(out, "utf8") : null };
  };

  // Both branches, end to end, from one withheld record's difference.
  const stands = at("stands");
  finishedRun(stands, records({ ...FULL, challenge: 51 }, { challenge: 1 }));
  scoredRun(stands);
  const flips = at("flips");
  finishedRun(flips, records(FULL, { challenge: 2 }));
  scoredRun(flips);
  const a = reportOf(stands), b = reportOf(flips);
  add("R1: exactly 2.0% stands, end to end", "allowed", truth(a.code === 0 && a.text.includes("**Headline audit: stands, on its frame.**") && count(a.text, NOT_VALIDATED) === 0 && !a.text.includes("not the audit's result") && !a.text.includes("Headline audit: not estimable") && a.text.includes("Audit figures, on the frame") && a.text.includes("| C6 | DNS "), "1 of 51 is under, the warning count is 0"));
  const realViews = 2 + 1 + 1 + 1;
  add("R2: one more withheld flips every row", "allowed", truth(b.code === 0 && count(b.text, NOT_VALIDATED) === realViews && b.text.includes("**Headline audit: not estimable.** Over 2.0% withheld: challenge 2 of 50. It changes no claim's decision.") && b.text.includes("Frame figures, not the audit's result") && b.text.includes(NOT_THE_RESULT) && b.text.includes("Frame only, not the audit's result: kappa"), `${count(b.text, NOT_VALIDATED)} warnings on ${realViews} real-page views`));
  add("R3: the headline stands above the first claim row, after provenance and scope", "allowed", truth(b.text.indexOf("Headline audit") < b.text.indexOf("| C1 |") && b.text.indexOf("## Provenance") < b.text.indexOf("Headline audit") && b.text.indexOf("Headline audit") < b.text.indexOf("Audit figures describe non-withheld records, not the run as a whole."), "order"));
  add("R4: a DNS claim with no real-page view gets no warning", "allowed", truth(b.text.split("\n").filter((l) => l.startsWith("| C6 |")).every((l) => !l.includes(NOT_VALIDATED)), "C6"));
  const order = ["## Provenance", "Headline audit", "## Primary refusal endpoint", "## Claims C1 to C11", "## CSP controls scripts", "## Standardized figures", "## The E20-matched reading", "## C12 to C15", "## Worst-case bounds of the claims", "## Text withheld", "## The audit's detail"].map((s) => b.text.indexOf(s));
  add("R5: the sections come in the registered order", "allowed", truth(order.every((n, i) => n >= 0 && (i === 0 || n > order[i - 1])), order.join(" ")));

  // Refusals. Each edits one thing, and an edit to score.json carries a fresh self-hash, so the check itself must catch it.
  const edited = (score, change) => { const { selfSha256: _s, ...fields } = score; const next = JSON.parse(JSON.stringify(fields)); change(next); return selfHashed(next); };
  const rehash = (s) => { s.provenance.frameSha256 = sha256(Buffer.from(`${JSON.stringify(s.frame, null, 2)}\n`)); };
  const scoreA = json(join(stands, "score.json")), scoreB = json(join(flips, "score.json"));
  const refused = (name, got, why) => add(name, "refused", got, why);
  const written = (got) => ({ code: got.code, said: got.text === null ? got.said : `${got.said} and it wrote a file` });
  refused("R6: a flipped headline", written(reportOf(stands, undefined, edited(scoreA, (s) => { s.headline = "not estimable"; s.frame.headline = "not estimable"; s.frame.notEstimable = true; rehash(s); }))), /headline doesn't match/);
  refused("R6: a hidden not estimable", written(reportOf(flips, undefined, edited(scoreB, (s) => { s.headline = "stands, on its frame"; s.frame.headline = "stands, on its frame"; s.frame.notEstimable = false; rehash(s); }))), /headline doesn't match/);
  refused("R6: a score edited by hand, self-hash left", written(reportOf(stands, undefined, { ...scoreA, kappa: 0.1 })), /changed after/);
  refused("R7: an analysis from another run", written(reportOf(stands, analysisOf(flips))), /manifestSha256 differs/);
  refused("R7: a score from another run", written(reportOf(flips, analysisOf(flips), scoreA)), /manifestSha256 differs/);
  const analysisWith = (dir, change) => { const { selfSha256: _s, ...fields } = analysisOf(dir); const next = JSON.parse(JSON.stringify(fields)); change(next); return selfHashed(next); };
  refused("R7: an analysis of the raw file before the draw", written(reportOf(stands, analysisWith(stands, (x) => { x.provenance.rawSha256 = json(join(stands, "manifest.json")).rawSha256; }))), /rawSha256 differs/);
  for (const field of ["classifierSha256", "protocolSha256", "codeSha256"]) refused(`R8: ${field} differs, by name`, written(reportOf(stands, analysisWith(stands, (x) => { x.provenance.state[field] = "0".repeat(64); }))), new RegExp(`${field} differs`));
  for (const missing of ["sheetSha256", "keySha256", "frameSha256", "drawProofSha256"]) refused(`R9: the score has no ${missing}`, written(reportOf(stands, undefined, edited(scoreA, (s) => { delete s.provenance[missing]; }))), new RegExp(missing));
  refused("R9: a frame edited to hide a withheld record", written(reportOf(flips, undefined, edited(scoreB, (s) => { s.frame.strata.challenge.withheld = 0; s.frame.strata.challenge.frame = 50; s.frame.labels.challenge.frame = 50; s.frame.strata.challenge.overLimit = false; s.frame.notEstimable = false; s.frame.headline = "stands, on its frame"; s.headline = "stands, on its frame"; delete s.note; rehash(s); }))), /different audit frames/);
  refused("R9: the score has no label hash", written(reportOf(stands, undefined, edited(scoreA, (s) => { delete s.provenance.model.labelsSha256; }))), /labelsSha256/);
  refused("R10: a suppressed label carries a number", written(reportOf(stands, undefined, edited(scoreA, (s) => { s.metrics.error.suppressed = SUPPRESSED; s.metrics.error.precision = 1; }))), /carries a number/);
  const small = at("small");
  finishedRun(small, records({ ...FULL, "unrecognized-error-response": 19 }));
  scoredRun(small);
  const smallScore = json(join(small, "score.json"));
  refused("R10: suppression lifted by hand", written(reportOf(small, undefined, edited(smallScore, (s) => { const { suppressed: _x, frame: _f, ...rest } = s.metrics.error; s.metrics.error = { ...rest, precision: 1, recall: 1 }; }))), /under 20 in frame/);
  const shown = reportOf(small);
  add("R11: a suppressed label says so in every figure column", "allowed", truth(shown.code === 0 && shown.text.split("\n").find((l) => l.startsWith("| error | 19 |"))?.split("|").filter((c) => c.trim() === SUPPRESSED).length === 6, "6 columns, and frame 19"));

  // The whole chain against the run folder.
  const chain = at("chain");
  finishedRun(chain, records({ ...FULL, "candidate-page": 170 }, { challenge: 1, "candidate-page": 1 }, "x"));
  scoredRun(chain, { resamples: 20_000 });
  const untouched = (dir, change) => {
    const copy = `${dir}-${Math.random().toString(36).slice(2, 8)}`;
    cpSync(dir, copy, { recursive: true });
    change(copy);
    put(join(copy, "analysis.json"), analysisOf(dir));
    const said = [];
    const code = report(["--analysis", join(copy, "analysis.json"), "--score", join(copy, "score.json"), "--out", join(copy, "final.md"), "--run", copy], { log: quiet, fail: (m) => said.push(m) });
    return { code, said: said.join(" ") || "ok", wrote: existsSync(join(copy, "final.md")) };
  };
  add("P1: a whole chain reports, with the run checked", "allowed", untouched(chain, quiet));
  const other = at("other");
  finishedRun(other, records(FULL, {}, "y"));
  scoredRun(other);
  const bump = (file, change) => { const v = json(file); change(v); put(file, v); };
  refused("P2: an altered sheet", untouched(chain, (d) => bump(join(d, "validation-sheet.json"), (s) => { s[0].excerpt = "changed"; })), /sheet is not the one/);
  refused("P2: an altered sheet with its proof rewritten", untouched(chain, (d) => { bump(join(d, "validation-sheet.json"), (s) => { s[0].excerpt = "changed"; }); bump(join(d, "prune-manifest.json"), (p) => { p.sheetSha256 = sha256(readFileSync(join(d, "validation-sheet.json"))); }); }), /doesn't match the raw file/);
  refused("P3: sheet and key swapped", untouched(chain, (d) => { const s = readFileSync(join(d, "validation-sheet.json")); writeFileSync(join(d, "validation-sheet.json"), readFileSync(join(d, "validation-key.json"))); writeFileSync(join(d, "validation-key.json"), s); }), /not the one/);
  refused("P3: another run's key", untouched(chain, (d) => cpSync(join(other, "validation-key.json"), join(d, "validation-key.json"))), /key is not the one/);
  refused("P4: labels changed after they were bound", untouched(chain, (d) => writeFileSync(join(d, "labels-model.csv"), readFileSync(join(d, "labels-model.csv"), "utf8").replace(",page", ",block"))), /changed after they were bound/);
  refused("P5: a copied proof", untouched(chain, (d) => cpSync(join(other, "prune-manifest.json"), join(d, "prune-manifest.json"))), /manifest hashed|another run/);
  refused("P6: a wrong manifest", untouched(chain, (d) => bump(join(d, "manifest.json"), (m) => { m.startedAt = "2099"; })), /manifest hashed|privacy report|another run/);
  refused("P6: a wrong raw file", untouched(chain, (d) => writeFileSync(join(d, "raw.jsonl"), `${readFileSync(join(d, "raw.jsonl"), "utf8")}{}\n`)), /not the one the manifest hashed/);
  refused("P7: labels from another draw, by manifest", untouched(chain, (d) => cpSync(join(other, "labels-human.manifest.json"), join(d, "labels-human.manifest.json"))), /another sheet/);
  const bindOther = at("bind");
  finishedRun(bindOther, records(FULL, {}, "z"));
  validation(["draw", bindOther], { log: quiet, fail: quiet });
  writeFileSync(join(bindOther, "labels-human.csv"), labelsFor(bindOther));
  refused("P7: labels from another draw, by the kit's hash", say(validation, ["bind", bindOther, "human", json(join(other, "prune-manifest.json")).sheetSha256]), /another sheet/);
  refused("P7: a hash too short to mean anything", say(validation, ["bind", bindOther, "human", "ab"]), /another sheet/);
  add("P8: bind writes a manifest with no name", "allowed", truth(say(validation, ["bind", bindOther, "human", json(join(bindOther, "prune-manifest.json")).sheetSha256]).code === 0 && Object.keys(json(join(bindOther, "labels-human.manifest.json"))).join() === "role,sheetSha256,labelsSha256,createdAt", "role, two hashes, time"));
  refused("P8: a manifest is written once", say(validation, ["bind", bindOther, "human", json(join(bindOther, "prune-manifest.json")).sheetSha256]), /already bound/);
  refused("P8: score needs both manifests", say(validation, ["score", bindOther]), /model labels have no manifest/);
  refused("P9: a second score", say(validation, ["score", chain]), /has a score/);
  refused("P10: figures edited with a fresh self-hash", untouched(chain, (d) => put(join(d, "score.json"), edited(json(join(chain, "score.json")), (s) => { s.metrics.page.precision = 0.5; }))), /don't follow from its inputs/);
  const scoreBound = json(join(chain, "score.json")).provenance;
  add("P11: the score holds every input's hash and the study state", "allowed", truth(["manifestSha256", "rawSha256", "drawProofSha256", "frameSha256", "sheetSha256", "keySha256"].every((k) => /^[0-9a-f]{64}$/.test(scoreBound[k])) && /^[0-9a-f]{64}$/.test(scoreBound.human.manifestSha256) && Boolean(scoreBound.state.codeSha256), "provenance"));
  const elsewhere = at("elsewhere");
  finishedRun(elsewhere, records(FULL, {}, "w"));
  bump(join(elsewhere, "manifest.json"), (m) => { m.codeSha256 = "0".repeat(64); });
  bump(join(elsewhere, "privacy-report.json"), (p) => { p.manifestSha256 = sha256(readFileSync(join(elsewhere, "manifest.json"))); });
  scoredRun(elsewhere);
  add("P12: a score under other code is refused", "allowed", truth(!existsSync(join(elsewhere, "score.json")), "no score written"));

  // What the labeler sees, and what the frozen code covers.
  const sheetFile = join(chain, "validation-sheet.json");
  const kit = spawnSync(process.execPath, [join(HERE, "make-labeler-kit.mjs"), sheetFile, join(at(""), "kit")], { encoding: "utf8" });
  const shownHash = sha256(readFileSync(sheetFile));
  add("K1: the kit shows the sheet's hash, as bind needs it", "allowed", truth(kit.status === 0 && kit.stdout.includes(shownHash) && readFileSync(join(at(""), "kit", "labeler.html"), "utf8").includes(`Sheet ${shownHash}`), "page and stdout"));
  const hashed = codeFiles().map((f) => f.split("/").pop());
  add("K2: the report and the kit are in the code hash", "allowed", truth(hashed.includes("report-tables.mjs") && hashed.includes("make-labeler-kit.mjs"), `${hashed.length} files`));

  // Under 20, by label. `block` pools its two strata, in both headline branches.
  const key = (sizes) => Object.entries(sizes).flatMap(([stratum, n]) => Array.from({ length: Math.min(n, 3) }, () => ({ stratum, stratumSize: n, ruleLabel: RULE_TO_ANSWER[stratum] }))).map((k, i) => ({ id: i + 1, ...k }));
  const label = (sizes, withheld, name, human = (k) => k.ruleLabel) => {
    const frame = auditFrame(records(sizes, withheld));
    const k = key(sizes);
    const csv = `id,label\n${k.map((x) => `${x.id},${human(x)}`).join("\n")}\n`;
    return { frame, scored: scoreLabels(k, csv, csv, { frame, resamples: 5 }), name };
  };
  const quietRow = (s, name) => ["precision", "recall", "precisionCi", "recallCi"].every((f) => s.metrics[name][f] === null) && s.worstCase[name].precision === null && s.worstCase[name].recall === null && s.metrics[name].suppressed === SUPPRESSED && s.worstCase[name].suppressed === SUPPRESSED;
  const speaks = (s, name) => !s.metrics[name].suppressed && typeof s.metrics[name].precision === "number" && !s.worstCase[name].suppressed;
  const CASES = [
    ["page", { "candidate-page": 19 }, false], ["page", { "candidate-page": 20 }, true],
    ["challenge", { challenge: 19 }, false], ["challenge", { challenge: 20 }, true],
    ["error", { "unrecognized-error-response": 19 }, false], ["error", { "unrecognized-error-response": 20 }, true],
    ["block", { "block-signature": 19 }, false], ["block", { "block-unrecognized-403": 19 }, false], ["block", { "block-signature": 20 }, true], ["block", { "block-unrecognized-403": 20 }, true],
    ["block", { "block-signature": 19, "block-unrecognized-403": 1 }, true], ["block", { "block-signature": 1, "block-unrecognized-403": 19 }, true], ["block", { "block-signature": 10, "block-unrecognized-403": 9 }, false],
  ];
  for (const [name, sizes, figures] of CASES) {
    const text = Object.values(sizes).join("+");
    const standing = label({ "candidate-page": 60, challenge: 60, "block-signature": 60, "block-unrecognized-403": 60, "unrecognized-error-response": 60, ...Object.fromEntries(Object.entries(RULE_TO_ANSWER).filter(([, v]) => v === name).map(([k]) => [k, 0])), ...sizes }, {}, name);
    add(`S: ${name} at ${text}, headline stands`, "allowed", truth(!standing.frame.notEstimable && (figures ? speaks(standing.scored, name) : quietRow(standing.scored, name)), figures ? "has figures" : SUPPRESSED));
    const over = label({ "candidate-page": 60, challenge: 60, "block-signature": 60, "block-unrecognized-403": 60, "unrecognized-error-response": 60, ...Object.fromEntries(Object.entries(RULE_TO_ANSWER).filter(([, v]) => v === name).map(([k]) => [k, 0])), ...sizes, ...(name === "page" ? { challenge: 49 } : { "candidate-page": 49 }) }, name === "page" ? { challenge: 1 } : { "candidate-page": 1 }, name);
    add(`S: ${name} at ${text}, not estimable`, "allowed", truth(over.frame.notEstimable && (figures ? speaks(over.scored, name) : quietRow(over.scored, name)), figures ? "has figures" : "stays suppressed"));
  }
  const pooled = label({ "block-signature": 49, "block-unrecognized-403": 49 }, { "block-signature": 1 }, "block");
  add("S: the 2.0% rule stays per stratum in block", "allowed", truth(pooled.frame.notEstimable && pooled.frame.strata["block-signature"].overLimit && !pooled.frame.strata["block-unrecognized-403"].overLimit, "1 of 49 and 0 of 49, though 1 of 98 pooled is under"));
  const silent = label({ "candidate-page": 30, "unrecognized-error-response": 5 }, {}, "error", (k) => (k.stratum === "unrecognized-error-response" ? "page" : k.ruleLabel));
  add("S: a silent label's rows count in other labels' recall", "allowed", truth(silent.scored.metrics.error.suppressed === SUPPRESSED && silent.scored.metrics.page.recall < 1 && silent.scored.metrics.page.recall > 0.8, `page recall ${silent.scored.metrics.page.recall.toFixed(3)}`));
  const kappa19 = label({ "candidate-page": 10, challenge: 9 }, {}, "page"), kappa20 = label({ "candidate-page": 10, challenge: 10 }, {}, "page");
  add("S: kappa at a whole frame of 19", "allowed", truth(kappa19.scored.kappa === null && kappa19.scored.kappaSuppressed === SUPPRESSED && kappa19.scored.humanVsAgent.kappa === null, SUPPRESSED));
  add("S: kappa at a whole frame of 20", "allowed", truth(typeof kappa20.scored.kappa === "number" && !kappa20.scored.kappaSuppressed, "has a figure"));
  const unsure = label({ "candidate-page": 30, challenge: 30 }, {}, "page", () => "unsure");
  add("S: a frame of 20 or more with every row unsure", "allowed", truth(unsure.scored.metrics.page.suppressed === NO_ANSWERS && unsure.scored.metrics.page.precision === null && unsure.scored.worstCase.page.precision === null && unsure.scored.kappaSuppressed === NO_ANSWERS, NO_ANSWERS));
  const numbers = label({ "candidate-page": 30, "unrecognized-error-response": 5 }, {}, "error");
  add("S: suppressed never reads as 0, 1 or NaN", "allowed", truth(!/NaN|Infinity/.test(JSON.stringify(numbers.scored.metrics, (_k, v) => (typeof v === "number" && !Number.isFinite(v) ? "NaN" : v))) && numbers.scored.metrics.error.precision === null, "nulls"));
  add("S: stratum counts stay, whatever the size", "allowed", truth(numbers.frame.strata["unrecognized-error-response"].drawn === 5 && numbers.frame.strata["unrecognized-error-response"].shortfall === 15, "drawn 5, shortfall 15"));

  // The parent's check reads the content, whatever marker the record carries.
  const FIRES = "Look at (canary-marker.example.org). Open daily";
  const text = { title: "t", text: "t", noscript: "t" };
  const marked = {
    "evidence.excerpt": { excerpt: FIRES, pageExcerpt: text },
    "evidence.pageExcerpt.title": { pageExcerpt: { ...text, title: FIRES } },
    "evidence.pageExcerpt.text": { pageExcerpt: { ...text, text: FIRES } },
    "evidence.pageExcerpt.noscript": { pageExcerpt: { ...text, noscript: FIRES } },
    "evidence.others.excerpt": { pageExcerpt: text, others: [{ kind: "x", excerpt: "t" }, { kind: "y", excerpt: FIRES, bodySha256: "h" }] },
  };
  for (const [path, evidence] of Object.entries(marked)) {
    const r = { host: "x", evidence: { ...evidence, status: 200, textWithheld: { kinds: { email: 1 }, fields: 1 } } };
    const out = safeRecord(r);
    add(`M: marker and text in ${path}`, "allowed", truth(pageTextMissed(r) && !pageTextMissed(out) && !JSON.stringify(out).includes("canary") && !/"t"/.test(JSON.stringify(out)) && out.evidence.status === 200 && out.evidence.textWithheld.kinds.email > 1, "all five paths gone, counts kept"));
  }
  const stale = safeRecord({ evidence: { pageExcerpt: { text: "A plain page." }, textWithheld: { kinds: {}, fields: 0 } } });
  add("M: a marker with text beside it never stands", "allowed", truth(stale.evidence.pageExcerpt.text === undefined, "text removed though nothing fired"));
  const poisoned = safeRecord({ evidence: { textWithheld: { kinds: { "john at example.org": 1, email: "x" }, fields: "john at example.org", note: "john at example.org" } } });
  add("M: a marker can't carry text", "allowed", truth(!JSON.stringify(poisoned).includes("john") && JSON.stringify(poisoned.evidence.textWithheld) === '{"kinds":{},"fields":0}', "counts only"));
  const once = withholdText(marked["evidence.excerpt"].pageExcerpt ? { evidence: { excerpt: FIRES } } : {});
  add("M: withholding twice is withholding once", "allowed", truth(safeRecord(once) === once, "same object"));

  // The detector's grammar, both ways through the scrub.
  const caught = (t) => scrubMisses(t).email > 0 && (scrub(t).includes("<email>") || scrubMisses(scrub(t)).email > 0);
  for (const t of ["john at example.x.com", "john at example.a-b.com", "john at example.3m.com", "john at a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.com", "john at example.xn--80ak6aa92e.com", "john at xn--e1afmkfd.xn--p1ai", "john at example.испытание.рф", "john at 例子.测试.中国", "john at ตัวอย่าง.ไทย", "john at उदाहरण.भारत", "john at (example.x.com)", "john at [example.a-b.com]", "john at <example.3m.com>", 'john at "example.x.com"', "john at 'example.a-b.com'", "john at example dot x dot com", "john at example . a-b . com", "john at example (dot) co (dot) uk", "john (at example.x.com)", "john(at example.x.com)", '"john" at example.x.com', "john @ example.x.com", "(info) @ example.x.com", "john @ [example.x.com]", "john ａｔ example.x.com", "john&nbsp;at&nbsp;example.x.com", "john at exam​ple.x.com", "JOHN AT EXAMPLE.X.COM"]) add(`D: fires on ${t}`, "allowed", truth(caught(t), `raw ${scrubMisses(t).email}, after scrub ${scrubMisses(scrub(t)).email}`));
  for (const t of ["see it at $29. Open daily", "open at 5:30. Open daily", "meet at Joe's. Open daily", "up at 100%. Open daily", "priced at 3.99. Open daily", "open at 7.30am. Then more", "see it at /docs/guide.html today", "see it at https://example.org/x today", "Reach us at <email>. Open daily", "Reach us at (<email>). Open daily", "<redacted>@example.com", "rua=mailto:<redacted>@example.com", "<email>@example.com", "<token>@example.com", "<id>@a.bc", "<email> at example.x.com", "<number> at example.co.uk", "boom (a.js:1:2)\n    at Object.parse (native)", "x [y]\n  at Module.load (node.js:9:9)", "john at -example.com", "john at example-.com", "john at example.-x.com", "john at example.x-.com", "john at example.com-", "john at example.c0m", "john at example.x"]) add(`D: quiet on ${t}`, "allowed", truth(scrubMisses(t).email === 0 && scrubMisses(scrub(t)).email === 0, "no finding"));
  const started = performance.now();
  for (const t of ["at a. ".repeat(40_000), `x at ${"a.".repeat(100_000)}`, "x at ".repeat(40_000)]) scrubMisses(t);
  add("D: the walk stays bounded on hostile text", "allowed", truth(performance.now() - started < 2000, `${Math.round(performance.now() - started)} ms`));
}
