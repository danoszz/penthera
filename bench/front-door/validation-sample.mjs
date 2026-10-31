#!/usr/bin/env node
/**
 * E20-R2 audit (Amendment 2): a stratified sample of pass 2, a blind sheet, the deletion
 * of text outside the sample, and scoring. It is a single-human audit with model
 * comparison, not independent validation.
 *
 *   node bench/front-door/validation-sample.mjs draw <run folder>
 *       Writes validation-sheet.json (blind) and validation-key.json, deletes unsampled
 *       page text from raw.jsonl, and writes prune-manifest.json. It can't be undone,
 *       which is its purpose.
 *   node bench/front-door/validation-sample.mjs prune <run folder>
 *       Deletes all text of a pilot, or of a pass that stopped, and writes
 *       prune-manifest.json. Seal a pilot first.
 *   node bench/front-door/validation-sample.mjs purge <run folder> --confirm <first 12 characters of the raw hash>
 *       Deletes the whole per-site raw file, and the audit sheet and key, and writes
 *       purge-manifest.json with the original hash and the run's disposition. For a
 *       real privacy miss above all. It can't be undone, and the run decides nothing.
 *       The privacy report prints the code; for a crashed run, take it from sha256sum.
 *   node bench/front-door/validation-sample.mjs bind <run folder> <human|model> <sheet hash shown to the labeler>
 *       Binds labels-human.csv or labels-model.csv, in the run folder, to this draw's sheet.
 *       Each csv: id,label. Writes a manifest once. The hash, or its first 12 characters, is
 *       what the labeler's kit showed, so labels made from another sheet are refused.
 *   node bench/front-door/validation-sample.mjs score <run folder>
 *       Refuses a run, draw, sheet, key or label file that doesn't chain, and a missing,
 *       duplicate, unknown or invalid row. Writes score.json once: weighted precision and
 *       recall, kappa, disagreement, the unsure count and the hash of every input.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { dispositionOf, falseFireReviewed, NO_PRIVACY, PRIVACY_STOP, PURGED_FILES, recordMisses, selfHashed, STRATA, stratumOf, unfinishedRun } from "./record-checks.mjs";
import { holdsText, PASS_SEED, seeded, shuffled, studyState } from "./replicate.mjs";

// A label with a frame this small gives no precision or recall of its own.
export const MIN_AUDIT_FRAME = 20;
export const SUPPRESSED = "under 20 in frame";
export const NO_ANSWERS = "no answered rows";
// Strata are how we draw and labels are what we report. Block pools its two, and the floor reads the pool.
export const LABEL_STRATA = Object.freeze({ page: ["candidate-page"], challenge: ["challenge"], block: ["block-signature", "block-unrecognized-403"], error: ["unrecognized-error-response"] });
// The headline audit is not estimable past 2.0% withheld in any stratum: 1 in 50, as whole numbers, with no rounding.
export const MAX_WITHHELD = Object.freeze({ records: 1, per: 50 });
export const overWithheldLimit = (withheld, eligible) => withheld * MAX_WITHHELD.per > MAX_WITHHELD.records * eligible;
export const LABELS = Object.freeze(["page", "challenge", "block", "error"]);
export const ANSWERS = Object.freeze([...LABELS, "unsure"]);
export const LABELERS = Object.freeze(["human", "model"]);
const RULE_LABEL = Object.freeze({ "candidate-page": "page", challenge: "challenge", block: "block", "unrecognized-error-response": "error" });
export const BOOTSTRAP = Object.freeze({ resamples: 20_000, seed: PASS_SEED[2] });

export { STRATA, stratumOf };

/**
 * The audit's frame. For each stratum, `eligible` is its graded records before withholding,
 * `withheld` the ones that lost their text and `frame` the rest, which the draw uses. Withheld
 * rows aren't missing at random, so the headline audit is not estimable when any stratum is over
 * the limit. A label whose pooled frame is small loses its own figures, and that alone doesn't
 * decide the headline.
 */
export function auditFrame(records) {
  const graded = records.filter((r) => r.status === "ok");
  const strata = {}, withheldByRule = Object.fromEntries(LABELS.map((l) => [l, 0]));
  for (const stratum of Object.keys(STRATA)) {
    const all = graded.filter((r) => stratumOf(r) === stratum);
    const withheld = all.filter((r) => r.evidence?.textWithheld).length;
    const frame = all.length - withheld;
    const drawn = Math.min(frame, STRATA[stratum]);
    strata[stratum] = { eligible: all.length, withheld, share: all.length ? withheld / all.length : 0, overLimit: overWithheldLimit(withheld, all.length), frame, drawn, target: STRATA[stratum], shortfall: STRATA[stratum] - drawn };
  }
  for (const r of graded) if (r.evidence?.textWithheld && stratumOf(r)) withheldByRule[RULE_LABEL[r.evidence.class.label]]++;
  const labels = Object.fromEntries(Object.entries(LABEL_STRATA).map(([label, list]) => {
    const frame = list.reduce((n, stratum) => n + strata[stratum].frame, 0);
    return [label, { strata: list, frame, figures: frame >= MIN_AUDIT_FRAME }];
  }));
  const withheld = Object.values(withheldByRule).reduce((a, b) => a + b, 0);
  const eligible = Object.values(strata).reduce((n, g) => n + g.eligible, 0);
  const notEstimable = Object.values(strata).some((g) => g.overLimit);
  return { headline: notEstimable ? "not estimable" : "stands, on its frame", notEstimable, scope: "non-withheld records", withheld, eligible, share: eligible ? withheld / eligible : 0, strata, labels, withheldByRule };
}

/** Precision and recall if the rule label were wrong on every withheld row. */
export function worstCaseBounds(rows, withheldByRule) {
  const answered = reweighted(rows.filter((r) => r.human !== "unsure"));
  const total = Object.values(withheldByRule).reduce((a, b) => a + b, 0);
  return Object.fromEntries(LABELS.map((label) => {
    let tp = 0, called = withheldByRule[label] ?? 0, actual = total - (withheldByRule[label] ?? 0);
    for (const r of answered) {
      if (r.ruleLabel === label) called += r.weight;
      if (r.human === label) actual += r.weight;
      if (r.ruleLabel === label && r.human === label) tp += r.weight;
    }
    return [label, { precision: called ? tp / called : NaN, recall: actual ? tp / actual : NaN }];
  }));
}

/** Fixed sample per stratum, with the stratum's size for the weights. */
export function drawSample(records, { seed = PASS_SEED[2] } = {}) {
  // Nobody could label a withheld record, so the audit's frame leaves it out, and the number is reported.
  const graded = records.filter((r) => r.status === "ok" && !r.evidence?.textWithheld);
  return Object.entries(STRATA).flatMap(([stratum, size]) => {
    const all = graded.filter((r) => stratumOf(r) === stratum);
    return shuffled(all, seed).slice(0, size).map((r) => ({ host: r.host, stratum, stratumSize: all.length, ruleLabel: RULE_LABEL[r.evidence.class.label] }));
  });
}

/**
 * What a labeler sees, in a seeded order, with an id. No host, label, rule or stratum
 * field. Page text can still name the site: it can't be blinded from that.
 */
export function blindSheet(sample, records, { seed = PASS_SEED[2] } = {}) {
  const byHost = new Map(records.map((r) => [r.host, r]));
  const order = shuffled(sample, seed);
  const sheet = order.map((s, i) => {
    const e = byHost.get(s.host).evidence;
    // `soft` and `hard` name the rules that fired, which would tell the labeler the answer.
    const { soft: _soft, hard: _hard, ...shown } = e.pageExcerpt ?? {};
    return { id: i + 1, status: e.status, headerNames: e.headerNames, values: e.values, cookieNames: e.cookieNames, excerpt: e.excerpt ?? "", pageExcerpt: e.pageExcerpt ? shown : null };
  });
  return { sheet, key: order.map((s, i) => ({ id: i + 1, stratum: s.stratum, stratumSize: s.stratumSize, ruleLabel: s.ruleLabel })) };
}

/** The record without text, unless it was sampled. Counts and flags stay. `all` also takes error excerpts. */
export function pruneExcerpt(record, sampled = new Set(), { all = false } = {}) {
  const e = record.evidence;
  if (!e || sampled.has(record.host)) return record;
  const out = { ...e };
  if (e.pageExcerpt) {
    const { title: _title, text: _text, noscript: _noscript, ...shape } = e.pageExcerpt;
    out.pageExcerpt = shape;
  }
  if (all) {
    delete out.excerpt;
    out.others = (e.others ?? []).map(({ excerpt: _excerpt, ...o }) => o);
  }
  return { ...record, evidence: out };
}

/** id,label rows for exactly the key's ids. Throws on anything else, so a bad file can't be scored. */
export function parseLabels(text, ids, name = "labels") {
  const want = new Set(ids);
  const out = new Map();
  const lines = String(text).trim().split(/\r?\n/);
  if (!/^id,label(,|$)/i.test(lines[0] ?? "")) throw new Error(`${name}: the first line must be id,label`);
  for (const line of lines.slice(1)) {
    const [idCell, labelCell] = line.split(",");
    const id = Number(idCell), label = (labelCell ?? "").trim();
    if (!want.has(id)) throw new Error(`${name}: unknown id ${idCell}`);
    if (out.has(id)) throw new Error(`${name}: duplicate id ${id}`);
    if (!ANSWERS.includes(label)) throw new Error(`${name}: invalid label "${label}" for id ${id}`);
    out.set(id, label);
  }
  const missing = ids.filter((id) => !out.has(id));
  if (missing.length) throw new Error(`${name}: ${missing.length} ids have no label: ${missing.slice(0, 20).join(", ")}`);
  return out;
}

/** Stratum size over answered rows, so a stratum keeps its full weight when a row is left out. */
function reweighted(rows) {
  const answered = {};
  for (const r of rows) answered[r.stratum] = (answered[r.stratum] ?? 0) + 1;
  return rows.map((r) => ({ ...r, weight: r.stratumSize / answered[r.stratum] }));
}

function point(rows) {
  const out = {};
  for (const label of LABELS) {
    let tp = 0, called = 0, actual = 0;
    for (const r of rows) {
      if (r.ruleLabel === label) called += r.weight;
      if (r.human === label) actual += r.weight;
      if (r.ruleLabel === label && r.human === label) tp += r.weight;
    }
    out[label] = { precision: called ? tp / called : NaN, recall: actual ? tp / actual : NaN };
  }
  return out;
}

/** Unweighted Cohen's kappa between two fields of the rows, over whatever answers they hold. */
function kappaOf(rows, x, y) {
  const n = rows.length;
  if (!n) return NaN;
  const po = rows.filter((r) => r[x] === r[y]).length / n;
  const pe = ANSWERS.reduce((s, l) => s + (rows.filter((r) => r[x] === l).length / n) * (rows.filter((r) => r[y] === l).length / n), 0);
  return pe === 1 ? 1 : (po - pe) / (1 - pe);
}

/**
 * Amendment 2. `unsure` rows are left out of precision, recall and kappa, and counted.
 * The sensitivity keeps them as their own answer, which no rule gives, so each one is
 * a disagreement and no class is invented. Weights are taken over answered rows.
 * Intervals resample within each stratum.
 */
export function weightedMetrics(rows, { resamples = BOOTSTRAP.resamples, seed = BOOTSTRAP.seed } = {}) {
  const bad = rows.find((r) => !ANSWERS.includes(r.human));
  if (bad) throw new Error(`invalid label "${bad.human}"`);
  const answered = reweighted(rows.filter((r) => r.human !== "unsure"));
  const strata = Object.keys(STRATA).map((s) => answered.filter((r) => r.stratum === s)).filter((g) => g.length);
  const next = seeded(seed);
  const draws = Object.fromEntries(LABELS.map((l) => [l, { precision: [], recall: [] }]));
  for (let i = 0; i < resamples; i++) {
    const m = point(strata.flatMap((g) => g.map(() => g[Math.floor(next() * g.length)])));
    for (const l of LABELS) for (const k of ["precision", "recall"]) if (Number.isFinite(m[l][k])) draws[l][k].push(m[l][k]);
  }
  const ci = (v) => { const s = [...v].sort((a, b) => a - b); return s.length ? [s[Math.floor(s.length * 0.025)], s[Math.floor(s.length * 0.975)]] : [NaN, NaN]; };
  const est = point(answered);
  return {
    rows: rows.length, unsure: rows.length - answered.length,
    // A stratum with no answered row has no weight to give, so the metrics leave it out.
    strataWithoutAnswers: [...new Set(rows.map((r) => r.stratum))].filter((s) => !answered.some((r) => r.stratum === s)),
    kappa: kappaOf(answered, "human", "ruleLabel"),
    kappaUnsureAsDisagreement: kappaOf(rows, "human", "ruleLabel"),
    metrics: Object.fromEntries(LABELS.map((l) => [l, { ...est[l], precisionCi: ci(draws[l].precision), recallCi: ci(draws[l].recall) }])),
  };
}

/** A figure that can't be stated gives way to the reason, as nulls, so nothing reads as an estimate. */
function stated(figures, frame, reason) {
  return Object.fromEntries(Object.entries(figures).map(([label, f]) => {
    const why = reason(label);
    const value = (v) => (Array.isArray(v) ? v.map(value) : why || !Number.isFinite(v) ? null : v);
    const shown = Object.fromEntries(Object.entries(f).map(([k, v]) => [k, why && Array.isArray(v) ? null : value(v)]));
    return [label, why ? { ...shown, suppressed: why, frame: frame.labels[label].frame } : shown];
  }));
}

/** Both labelers against the rules and each other. The model is a comparison, never a judge. */
export function scoreLabels(key, humanText, agentText, { frame, ...opts } = {}) {
  if (!key.length) throw new Error("the key is empty");
  const ids = key.map((k) => k.id);
  const human = parseLabels(humanText, ids, "human labels");
  const agent = parseLabels(agentText, ids, "agent labels");
  const rows = key.map((k) => ({ ...k, human: human.get(k.id), agent: agent.get(k.id) }));
  const both = rows.filter((r) => r.human !== "unsure" && r.agent !== "unsure");
  const pairs = {};
  for (const r of rows) if (r.human !== r.agent) pairs[`human ${r.human}, agent ${r.agent}`] = (pairs[`human ${r.human}, agent ${r.agent}`] ?? 0) + 1;
  const measured = weightedMetrics(rows, opts);
  const compared = {
    rows: rows.length, humanUnsure: rows.filter((r) => r.human === "unsure").length, agentUnsure: rows.filter((r) => r.agent === "unsure").length,
    bothAnswered: both.length,
    // The main reading: rows where neither is unsure.
    kappa: kappaOf(both, "human", "agent"), disagreements: both.filter((r) => r.human !== r.agent).length,
    // Over every row, with any `unsure` a disagreement, also when both are unsure.
    kappaUnsureAsDisagreement: kappaOf(rows.map((r) => (r.agent === "unsure" ? { ...r, agent: "agent-unsure" } : r)), "human", "agent"),
    pairs,
  };
  if (!frame) return { ...measured, humanVsAgent: compared };
  // Kappa is one figure over the whole audit, so its floor reads every frame together.
  const whole = Object.values(frame.labels).reduce((n, l) => n + l.frame, 0) < MIN_AUDIT_FRAME ? SUPPRESSED : null;
  const answered = (label) => rows.some((r) => frame.labels[label].strata.includes(r.stratum) && r.human !== "unsure");
  const reason = (label) => (!frame.labels[label].figures ? SUPPRESSED : answered(label) ? null : NO_ANSWERS);
  const kappaWhy = whole ?? (rows.some((r) => r.human !== "unsure") ? null : NO_ANSWERS);
  const comparedWhy = whole ?? (both.length ? null : NO_ANSWERS);
  return {
    headline: frame.headline, ...(frame.notEstimable ? { note: "These figures are for the frame, and are not the audit's result." } : {}), auditScope: frame.scope, frame,
    worstCase: stated(worstCaseBounds(rows, frame.withheldByRule), frame, reason), kappaWorstCase: "no bound",
    ...measured, metrics: stated(measured.metrics, frame, reason),
    ...(kappaWhy ? { kappa: null, kappaUnsureAsDisagreement: null, kappaSuppressed: kappaWhy } : {}),
    humanVsAgent: { ...compared, ...(comparedWhy ? { kappa: null, kappaUnsureAsDisagreement: null, kappaSuppressed: comparedWhy } : {}) },
  };
}

const PRIVATE = Object.freeze({ mode: 0o600 });
// What a result rests on. The score, the analysis and the report all run from the run's own commit, so each
// must equal the manifest. A laptop's Node binary can't match the server's, so the version is what's compared.
export const STATE_FIELDS = Object.freeze(["codeSha256", "classifierSha256", "protocolSha256", "amendmentSha256", "studyPageSha256", "pslSha256", "lockfileSha256", "node"]);
/** The study state a score or an analysis ran under, for the report to compare. */
export const stateOf = (state = studyState()) => Object.fromEntries(STATE_FIELDS.map((k) => [k, state[k] ?? (k === "node" ? process.version : undefined)]));
/** Where a state departs from the run's manifest, by name, or null. */
export function stateProblem(manifest, state) {
  const now = stateOf(state), run = stateOf(manifest);
  const field = STATE_FIELDS.find((k) => now[k] !== run[k]);
  return field ? `this checkout is not the run's: ${field} differs` : null;
}
const hash = (b) => createHash("sha256").update(b).digest("hex");
const readRaw = (file) => readFileSync(file, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));

/**
 * Rewrites the raw file and leaves a second manifest. The run's own manifest is not
 * touched, so its raw hash stays true of what was recorded; this one links the two.
 */
export function rewriteRun(dir, records, kind, extra = {}) {
  const raw = join(dir, "raw.jsonl");
  const manifestBytes = readFileSync(join(dir, "manifest.json"));
  const manifest = JSON.parse(manifestBytes);
  const before = hash(readFileSync(raw));
  // A killed run has no end hash. Its text still has to go.
  if (manifest.finishedAt && before !== manifest.rawSha256) throw new Error("Refused: the raw file is not the one the manifest hashed.");
  const after = records.map((r) => JSON.stringify(r)).join("\n") + "\n";
  writeFileSync(`${raw}.tmp`, after, PRIVATE);
  renameSync(`${raw}.tmp`, raw);
  const proof = { kind, manifestSha256: hash(manifestBytes), rawSha256Before: before, rawSha256After: hash(after), records: records.length, prunedAt: new Date().toISOString(), ...extra };
  writeFileSync(join(dir, "prune-manifest.json"), JSON.stringify(proof, null, 2) + "\n", PRIVATE);
  return proof;
}

/**
 * What's wrong with this run's draw, or the hashes that bind it. The proof must be this run's,
 * for its manifest and its raw file, and the frame, sheet and key must be the ones it wrote. All
 * three are drawn again from the raw file, so a file that matches its hash must also match the run.
 */
export function verifyDraw(dir) {
  const problem = unfinishedRun(dir);
  if (problem) return { problem: `this run can't be scored: ${problem}` };
  const read = (name) => (existsSync(join(dir, name)) ? readFileSync(join(dir, name)) : null);
  const proofBytes = read("prune-manifest.json"), manifestBytes = read("manifest.json"), raw = read("raw.jsonl"), frame = read("audit-frame.json"), sheet = read("validation-sheet.json"), key = read("validation-key.json");
  const proof = proofBytes && JSON.parse(proofBytes);
  const manifest = JSON.parse(manifestBytes);
  if (proof?.kind !== "validation-draw") return { problem: "this run has no draw proof" };
  if (proof.manifestSha256 !== hash(manifestBytes) || proof.rawSha256Before !== manifest.rawSha256) return { problem: "its draw proof is for another run" };
  if (proof.rawSha256After !== hash(raw)) return { problem: "the raw file is not the one the draw left" };
  if (!frame || proof.frameSha256 !== hash(frame)) return { problem: "this audit frame is not the one this run's draw wrote" };
  if (!sheet || proof.sheetSha256 !== hash(sheet)) return { problem: "this sheet is not the one this run's draw wrote" };
  if (!key || proof.keySha256 !== hash(key)) return { problem: "this key is not the one this run's draw wrote" };
  const records = readRaw(join(dir, "raw.jsonl"));
  const again = blindSheet(drawSample(records), records);
  if (JSON.stringify(auditFrame(records)) !== JSON.stringify(JSON.parse(frame))) return { problem: "this audit frame doesn't match the raw file" };
  if (JSON.stringify(again.sheet) !== JSON.stringify(JSON.parse(sheet))) return { problem: "this sheet doesn't match the raw file" };
  if (JSON.stringify(again.key) !== JSON.stringify(JSON.parse(key))) return { problem: "this key doesn't match the raw file" };
  return { manifestSha256: hash(manifestBytes), rawSha256: proof.rawSha256After, drawProofSha256: hash(proofBytes), frameSha256: proof.frameSha256, sheetSha256: proof.sheetSha256, keySha256: proof.keySha256 };
}

export const labelsFile = (dir, role) => join(dir, `labels-${role}.csv`);
const labelManifest = (dir, role) => join(dir, `labels-${role}.manifest.json`);

/** Records once that a label file answers this draw's sheet: who, the two hashes and when. No name. */
export function bindLabels(dir, role, shown) {
  if (!LABELERS.includes(role)) throw new Error("Refused: bind takes human or model.");
  const bound = verifyDraw(dir);
  if (bound.problem) throw new Error(`Refused: ${bound.problem}.`);
  if (String(shown ?? "").length < 12 || !bound.sheetSha256.startsWith(shown)) throw new Error("Refused: these labels were made from another sheet.");
  const file = labelsFile(dir, role);
  if (!existsSync(file)) throw new Error(`Refused: there is no labels-${role}.csv in this run.`);
  const text = readFileSync(file);
  parseLabels(text.toString("utf8"), JSON.parse(readFileSync(join(dir, "validation-key.json"), "utf8")).map((k) => k.id), `${role} labels`);
  const record = { role, sheetSha256: bound.sheetSha256, labelsSha256: hash(text), createdAt: new Date().toISOString() };
  if (existsSync(labelManifest(dir, role))) throw new Error(`Refused: the ${role} labels are already bound.`);
  writeFileSync(labelManifest(dir, role), `${JSON.stringify(record, null, 2)}\n`, { ...PRIVATE, flag: "wx" });
  return record;
}

function checkedLabels(dir, role, sheetSha256) {
  const file = labelManifest(dir, role);
  if (!existsSync(file)) return { problem: `the ${role} labels have no manifest` };
  if (!existsSync(labelsFile(dir, role))) return { problem: `there is no labels-${role}.csv in this run` };
  const bytes = readFileSync(file);
  const m = JSON.parse(bytes);
  if (m.role !== role || Number.isNaN(Date.parse(m.createdAt))) return { problem: `the ${role} label manifest is not valid` };
  if (m.sheetSha256 !== sheetSha256) return { problem: `the ${role} labels are for another sheet` };
  const labels = readFileSync(labelsFile(dir, role));
  if (m.labelsSha256 !== hash(labels)) return { problem: `the ${role} labels changed after they were bound` };
  return { labelsSha256: m.labelsSha256, manifestSha256: hash(bytes), text: labels.toString("utf8") };
}

/** The score of this run's bound inputs, with every input's hash, or what's wrong with them. Scoring twice gives the same figures. */
export function scoreRun(dir, { state = studyState(), ...opts } = {}) {
  const bound = verifyDraw(dir);
  if (bound.problem) return bound;
  const manifest = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));
  const departs = stateProblem(manifest, state);
  if (departs) return { problem: departs };
  const human = checkedLabels(dir, "human", bound.sheetSha256), model = checkedLabels(dir, "model", bound.sheetSha256);
  for (const side of [human, model]) if (side.problem) return side;
  const side = ({ labelsSha256, manifestSha256 }) => ({ labelsSha256, manifestSha256 });
  const frame = JSON.parse(readFileSync(join(dir, "audit-frame.json"), "utf8"));
  const scored = scoreLabels(JSON.parse(readFileSync(join(dir, "validation-key.json"), "utf8")), human.text, model.text, { frame, ...opts });
  return JSON.parse(JSON.stringify({ ...scored, provenance: { ...bound, human: side(human), model: side(model), state: stateOf(state), runState: stateOf(manifest), runRuntimeSha256: manifest.runtimeSha256, aggregateSha256: manifest.aggregateSha256 ?? null, commit: manifest.git?.commit ?? null } }));
}

/** All text out, for a pilot or for a pass that stopped, and read back to prove it. */
export function prunePilot(dir) {
  const { kind, stoppedFor } = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));
  // A later detector may not flag what stopped the run, so the stop itself asks for the review.
  if (stoppedFor === PRIVACY_STOP && !falseFireReviewed(dir)) throw new Error("Refused: this run stopped on a privacy finding. A person reviews it first, before any prune. A real miss goes to purge.");
  const records = readRaw(join(dir, "raw.jsonl"));
  // Pruning takes excerpts. A miss can sit in a field it leaves, so it needs a person, then a purge.
  if (records.some((r) => Object.values(recordMisses(r)).some(Boolean)) && !falseFireReviewed(dir)) throw new Error("Refused: this run stores a privacy miss, which prune can't clear. A person reviews it. A real miss goes to purge; a false fire is recorded with --false-fire.");
  const proof = rewriteRun(dir, records.map((r) => pruneExcerpt(r, new Set(), { all: true })), kind === "pass" ? "stopped" : "pilot");
  if (holdsText(join(dir, "raw.jsonl"))) throw new Error("The raw file still holds text after pruning.");
  return { ...proof, verified: true };
}

/** The whole raw file gone, for any run. Nothing field by field: a miss's neighbours can't be trusted either. */
export function purgeRun(dir, confirm) {
  const raw = join(dir, "raw.jsonl");
  if (!existsSync(raw)) throw new Error("Refused: this run has no raw file to purge.");
  if (confirm !== hash(readFileSync(raw)).slice(0, 12)) throw new Error("Refused: purge needs --confirm with the first 12 characters of this raw file's hash.");
  const manifestBytes = readFileSync(join(dir, "manifest.json"));
  const manifest = JSON.parse(manifestBytes);
  const privacyFile = join(dir, "privacy-report.json");
  const privacy = existsSync(privacyFile) ? JSON.parse(readFileSync(privacyFile, "utf8")) : null;
  const proof = { kind: "purge", disposition: dispositionOf(manifest, privacy), manifestSha256: hash(manifestBytes), rawSha256: hash(readFileSync(raw)), records: readRaw(raw).length, purgedAt: new Date().toISOString() };
  // The proof comes last and whole, so it never claims a deletion that didn't happen.
  for (const f of PURGED_FILES) rmSync(join(dir, f), { force: true });
  const left = PURGED_FILES.filter((f) => existsSync(join(dir, f)));
  if (left.length) throw new Error(`The purge left ${left.join(", ")}.`);
  writeFileSync(join(dir, "purge-manifest.json.tmp"), JSON.stringify(proof, null, 2) + "\n", PRIVATE);
  renameSync(join(dir, "purge-manifest.json.tmp"), join(dir, "purge-manifest.json"));
  return { ...proof, verified: true };
}

export function main([mode, target, a, b], { log = console.log, fail = console.error, ...opts } = {}) {
  if (mode === "draw" && target) {
    const problem = unfinishedRun(target);
    if (problem) { fail(`Refused: ${problem}. ${problem === NO_PRIVACY ? "Run pilot-report.mjs --privacy first." : "Use prune to delete its text."}`); return 3; }
    if (existsSync(join(target, "prune-manifest.json"))) { fail("Refused: this run was drawn already. A second draw would change the sample."); return 3; }
    const records = readRaw(join(target, "raw.jsonl"));
    const sample = drawSample(records);
    const { sheet, key } = blindSheet(sample, records);
    const frameText = JSON.stringify(auditFrame(records), null, 2) + "\n";
    writeFileSync(join(target, "audit-frame.json"), frameText, PRIVATE);
    const sheetText = JSON.stringify(sheet, null, 2) + "\n";
    writeFileSync(join(target, "validation-sheet.json"), sheetText, PRIVATE);
    const keyText = JSON.stringify(key, null, 2) + "\n";
    writeFileSync(join(target, "validation-key.json"), keyText, PRIVATE);
    const sampled = new Set(sample.map((s) => s.host));
    log(JSON.stringify({ sampled: sample.length, withheldFromDraw: records.filter((r) => r.evidence?.textWithheld).length, ...rewriteRun(target, records.map((r) => pruneExcerpt(r, sampled)), "validation-draw", { keySha256: hash(keyText), frameSha256: hash(frameText), sheetSha256: hash(sheetText) }) }));
    return 0;
  }
  if (mode === "prune" && target) {
    const problem = unfinishedRun(target);
    const { kind } = JSON.parse(readFileSync(join(target, "manifest.json"), "utf8"));
    if (kind === "pass" && (!problem || problem === NO_PRIVACY)) { fail("Refused: this pass finished whole, so the audit draw prunes it."); return 3; }
    try {
      log(JSON.stringify(prunePilot(target)));
      return 0;
    } catch (e) {
      fail(e.message);
      return 3;
    }
  }
  if (mode === "purge" && target) {
    try {
      log(JSON.stringify(purgeRun(target, a === "--confirm" ? b : undefined)));
      return 0;
    } catch (e) {
      fail(e.message);
      return 3;
    }
  }
  if (mode === "bind" && target && a) {
    try {
      log(JSON.stringify(bindLabels(target, a, b)));
      return 0;
    } catch (e) {
      fail(e.message);
      return 3;
    }
  }
  if (mode === "score" && target) {
    try {
      const scored = scoreRun(target, opts);
      if (scored.problem) { fail(`Refused: ${scored.problem}.`); return 3; }
      if (existsSync(join(target, "score.json"))) { fail("Refused: this run has a score. A second one has nothing new to say."); return 3; }
      const text = `${JSON.stringify(selfHashed({ ...scored, scoredAt: new Date().toISOString() }), null, 2)}\n`;
      writeFileSync(join(target, "score.json"), text, { ...PRIVATE, flag: "wx" });
      log(text);
      return 0;
    } catch (e) {
      fail(`Refused: ${e.message}.`);
      return 3;
    }
  }
  console.error("Usage: validation-sample.mjs draw <run folder> | prune <run folder> | purge <run folder> --confirm <code> | bind <run folder> <human|model> <sheet hash> | score <run folder>");
  return 2;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = main(process.argv.slice(2));
