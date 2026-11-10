/**
 * `penthera verify <findings.json> [--repo <path>] [--json] [-o file.json] [--sarif file] [--markdown file]`
 *
 * Checks findings another tool's model proposed (today: Cloudflare's
 * security-audit skill) against Penthera's rules on a local checkout.
 * Rung 1 of the verification ladder in docs/research/spec-ai-mode.md.
 *
 * Reads one file and the checkout. Runs no model, no project code, and
 * contacts no host. Exit 0 when the file was read and checked (whatever the
 * results), 2 when it could not be: a usage error, an unreadable file, or a
 * file that does not match the producer's schema. Unverified model findings
 * never change the exit code.
 */
import { parseArgs } from "node:util";
import { closeSync, existsSync, fstatSync, mkdirSync, openSync, readSync, statSync, writeFileSync, constants } from "node:fs";
import { dirname, resolve } from "node:path";
import { parseCloudflareFindings, PRODUCER, SCHEMA_PIN, MAX_INPUT_BYTES } from "../../lib/llm-audit/cloudflare.js";
import { verifyCandidates, sha256 } from "../../lib/llm-audit/verify.js";
import { stampProvenance } from "../../lib/provenance.js";
import { formatSarif, formatJson } from "../reporter.js";
import { mdInline } from "../report/md-escape.js";
import { bold, dim, green, yellow } from "./ansi.js";

const HELP = `
  penthera verify <findings.json> [--repo <path>] [options]

  Checks findings a model proposed against Penthera's rules on your checkout.
  Reads Cloudflare security-audit-skill findings.json (schema at ${SCHEMA_PIN}).

  Each finding ends as one of:
    confirmed by rule     a Penthera rule flags the same thing in the same file
    unverified            no rule could confirm it; shown as "model-proposed, unverified"
    location not found    the file or line it points at is not in this checkout
    out of scope          the path leads outside the repository

  Penthera runs no model and sends nothing anywhere. The model ran in your own
  agent, under its terms.

  Options:
    --repo <path>        The checkout the findings are about (default: .)
    --json               Print the result as JSON
    -o, --output <file>  Write the JSON result to a file
    --sarif <file>       Write SARIF: rule-confirmed findings, and model findings in a separate run
    --markdown <file>    Write a Markdown report
    -h, --help           Show this help

  Exit codes: 0 checked, 2 the file could not be read or does not match the schema.
`;

const CONTROL = /[\u0000-\u001f\u007f-\u009f‎‏‪-‮⁦-⁩]/g;
/** Model-written text, made safe for a terminal: no escape sequences, no bidi overrides. */
const safe = (s) => String(s ?? "").replace(CONTROL, " ");

function readInput(path) {
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK || 0));
    const st = fstatSync(fd);
    if (!st.isFile()) throw new Error("not a regular file");
    if (st.size > MAX_INPUT_BYTES) throw new Error(`larger than ${MAX_INPUT_BYTES} bytes`);
    const buf = Buffer.alloc(st.size);
    let off = 0;
    while (off < st.size) {
      const n = readSync(fd, buf, off, st.size - off, off);
      if (n === 0) break;
      off += n;
    }
    return buf.subarray(0, off).toString("utf-8");
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

export async function runVerify(argv, { out = process.stdout, err = process.stderr, scanners } = {}) {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        repo: { type: "string", default: "." },
        json: { type: "boolean", default: false },
        output: { type: "string", short: "o" },
        sarif: { type: "string" },
        markdown: { type: "string" },
        help: { type: "boolean", short: "h", default: false },
      },
    });
  } catch (e) {
    err.write(`  ${e.message}\n${HELP}`);
    return 2;
  }
  const { values, positionals } = parsed;
  if (values.help) { out.write(HELP); return 0; }
  if (positionals.length !== 1) { err.write(`  verify takes one findings file.\n${HELP}`); return 2; }

  const repo = resolve(values.repo);
  if (!existsSync(repo) || !statSync(repo).isDirectory()) { err.write(`  --repo ${values.repo} is not a folder.\n`); return 2; }

  let text;
  try {
    text = readInput(resolve(positionals[0]));
  } catch (e) {
    err.write(`  Could not read ${positionals[0]}: ${e.message}\n`);
    return 2;
  }
  const parsedFile = parseCloudflareFindings(text);
  if (!parsedFile.ok) {
    err.write(`  ${positionals[0]} is not a valid ${PRODUCER} findings.json (${SCHEMA_PIN}). Nothing was imported.\n`);
    for (const e of parsedFile.errors) err.write(`    ${safe(e)}\n`);
    return 2;
  }

  const result = await verifyCandidates(repo, parsedFile.candidates, {
    scanners,
    input: { file: positionals[0], sha256: sha256(text), producer: PRODUCER, schema: SCHEMA_PIN, rejected: parsedFile.rejected },
  });
  result.findings = stampProvenance(result.findings, result.timestamp);

  if (values.output) writeFile(values.output, formatJson(result));
  if (values.sarif) writeFile(values.sarif, JSON.stringify(verifySarif(result), null, 2) + "\n");
  if (values.markdown) writeFile(values.markdown, formatVerifyMarkdown(result));
  if (values.json) out.write(formatJson(result));
  else printVerify(result, out);
  return 0;
}

function writeFile(path, text) {
  mkdirSync(dirname(resolve(path)), { recursive: true });
  writeFileSync(resolve(path), text);
}

const STATUS_TEXT = {
  "confirmed-by-rule": "Confirmed by a Penthera rule",
  unverified: "Model-proposed, unverified",
  "location-not-found": "Location not found in this checkout",
  "out-of-scope": "Outside the repository",
};

export function printVerify(r, out = process.stdout) {
  const w = (s = "") => out.write(s + "\n");
  const c = r.counts;
  w("");
  w(`  ${bold("penthera verify")} ${dim(`${r.input.candidates} model finding${r.input.candidates === 1 ? "" : "s"} from ${r.input.producer}`)}`);
  w(`  ${dim(r.ai.note)}`);
  w("");
  w(`  ${green(String(c["confirmed-by-rule"]).padStart(4))}  confirmed by a Penthera rule`);
  w(`  ${yellow(String(c.unverified).padStart(4))}  model-proposed, unverified ${dim("(a person should look; never fails CI)")}`);
  if (c["location-not-found"]) w(`  ${String(c["location-not-found"]).padStart(4)}  point at a file or line not in this checkout`);
  if (c["out-of-scope"]) w(`  ${String(c["out-of-scope"]).padStart(4)}  point outside the repository`);
  if (r.input.rejected) w(`  ${dim(`${String(r.input.rejected).padStart(4)}  rejected by the producer itself, not imported`)}`);
  for (const status of ["confirmed-by-rule", "unverified", "location-not-found", "out-of-scope"]) {
    const list = r.candidates.filter((x) => x.verification.status === status);
    if (!list.length) continue;
    w("");
    w(`  ${bold(STATUS_TEXT[status])}`);
    for (const x of list) {
      w(`    ${safe(x.title)}`);
      w(`    ${dim(`${safe(x.file)}:${x.line} · ${x.classLabel} · ${safe(x.verification.reason)}`)}`);
    }
  }
  w("");
}

/** SARIF with two runs: Penthera's rule findings, and model findings under their own tool name, as notes. */
export function verifySarif(r) {
  const rule = formatSarif({ ...r, findings: r.findings.filter((f) => !f.modelProposed) });
  const model = formatSarif({ ...r, findings: r.findings.filter((f) => f.modelProposed).map((f) => ({ ...f, templateId: `llm-audit/${f.class}` })) });
  const run = model.runs[0];
  run.tool.driver.name = "penthera-ai";
  for (const res of run.results) res.level = "note";
  for (const d of run.tool.driver.rules) d.defaultConfiguration.level = "note";
  rule.runs.push(run);
  return rule;
}

export function formatVerifyMarkdown(r) {
  const L = [];
  L.push("# Penthera verify", "");
  L.push(`Model findings from \`${mdInline(r.input.producer)}\` (${mdInline(r.input.schema)}), checked against Penthera's rules on \`${mdInline(r.target)}\`.`);
  L.push("", `> ${r.ai.note}`, "");
  L.push("| Result | Findings |", "|---|---:|");
  for (const [s, n] of Object.entries(r.counts)) L.push(`| ${STATUS_TEXT[s]} | ${n} |`);
  if (r.input.rejected) L.push(`| Rejected by the producer, not imported | ${r.input.rejected} |`);
  L.push("");
  for (const status of ["confirmed-by-rule", "unverified", "location-not-found", "out-of-scope"]) {
    const list = r.candidates.filter((x) => x.verification.status === status);
    if (!list.length) continue;
    L.push(`## ${STATUS_TEXT[status]}`, "");
    if (status === "unverified") L.push("No Penthera rule or reproduction confirmed these. They are a model's claims: read the code before acting on them.", "");
    L.push("| Finding | Location | Class | Why |", "|---|---|---|---|");
    for (const x of list) L.push(`| ${mdInline(x.title)} | \`${mdInline(x.file)}:${x.line}\` | ${mdInline(x.classLabel)} | ${mdInline(x.verification.reason)} |`);
    L.push("");
  }
  L.push("Classes are inferred from each finding's text with a fixed table (`lib/llm-audit/classes.js`), not by a model.", "");
  return L.join("\n");
}
