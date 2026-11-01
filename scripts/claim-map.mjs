#!/usr/bin/env node
/**
 * The claim map: docs/claims.md ties each headline claim to the test that
 * holds it. tests/claims.test.js runs this in `npm test`.
 *
 * A row fails when its text left a file it names, or when its test is gone,
 * renamed or can't run. It parses the test file, so a test that is commented
 * out, skipped, or inside a skipped group doesn't count. It can't see a skip
 * decided at run time, and it checks that the link exists, not that the test
 * is strong enough. Those parts are for review.
 *
 *   node scripts/claim-map.mjs      check the map, exit 1 on a broken row
 */
import { parse } from "acorn";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const HELD_BY = /^`([^`]+)`: `([^`]+)`$/;

/** Text as a reader sees it: HTML tags gone, each run of whitespace one space. */
function flat(s) {
  let text = s;
  let before;
  do {
    before = text;
    text = text.replace(/<[^>]+>/g, "");
  } while (text !== before);
  return text.replace(/\s+/g, " ");
}

const TEST = new Set(["it", "test"]);
const GROUP = new Set(["describe", "suite"]);
/** Vitest's aliases that never run the test. */
const OFF = new Set(["xit", "xtest", "xdescribe"]);
/** Modifiers after which a passing test doesn't show that the claim holds. */
const NOT_RUN = new Set(["skip", "skipIf", "runIf", "todo", "fails"]);

/** `it.skip.each(x)` as ["it", "skip", "each"], or null for any other callee. */
function calleeNames(node) {
  if (node.type === "CallExpression") return calleeNames(node.callee);
  if (node.type === "Identifier") return [node.name];
  if (node.type === "MemberExpression" && !node.computed) {
    const left = calleeNames(node.object);
    return left && [...left, node.property.name];
  }
  return null;
}

/** A test's title as written, or null when it's built at run time. */
function titleOf(node, source) {
  if (node?.type === "Literal" && typeof node.value === "string") return node.value;
  if (node?.type === "TemplateLiteral") return source.slice(node.start + 1, node.end - 1);
  return null;
}

/** The titles of the tests in `source` that will run. Throws if it doesn't parse. */
export function runnableTests(source) {
  const found = [];
  const walk = (node, off, only) => {
    if (Array.isArray(node)) { for (const n of node) walk(n, off, only); return; }
    if (!node || typeof node.type !== "string") return;
    let childOff = off, childOnly = only;
    if (node.type === "CallExpression") {
      const names = calleeNames(node.callee);
      if (names && (TEST.has(names[0]) || GROUP.has(names[0]) || OFF.has(names[0]))) {
        const isOff = OFF.has(names[0]) || names.some((n) => NOT_RUN.has(n));
        const isOnly = names.includes("only");
        if (GROUP.has(names[0]) || names[0] === "xdescribe") {
          childOff = off || isOff;
          childOnly = only || isOnly;
        } else {
          found.push({ title: titleOf(node.arguments[0], source), off: off || isOff, only: only || isOnly });
        }
      }
    }
    for (const key of Object.keys(node)) {
      if (key !== "type" && node[key] && typeof node[key] === "object") walk(node[key], childOff, childOnly);
    }
  };
  walk(parse(source, { ecmaVersion: "latest", sourceType: "module" }), false, false);
  // One .only in a file stops every other test in it.
  const hasOnly = found.some((t) => t.only);
  return new Set(found.filter((t) => !t.off && (!hasOnly || t.only)).map((t) => t.title));
}

/** Reads the rows of the table in docs/claims.md. */
export function parseClaims(markdown) {
  return markdown.split("\n")
    .filter((line) => line.startsWith("| ") && !/^\| Claim \|/.test(line) && !/^\|-/.test(line))
    .map((line) => {
      const [claim, where, heldBy, limit] = line.slice(2, -2).split(" | ").map((c) => c.trim());
      return { claim, where, heldBy, limit };
    });
}

/**
 * Checks every row.
 * @param {{claim: string, where: string, heldBy: string}[]} rows
 * @param {(file: string) => string|null} read a repo file's text, null if it doesn't exist
 * @returns {string[]} one line per problem
 */
export function checkClaims(rows, read) {
  if (!rows.length) return ["docs/claims.md: no claims found"];
  const problems = [];
  for (const { claim, where, heldBy } of rows) {
    for (const file of (where ?? "").split(", ").map((f) => f.replace(/`/g, "")).filter(Boolean)) {
      const text = read(file);
      if (text === null) problems.push(`${claim}: ${file} doesn't exist`);
      else if (!flat(text).includes(claim)) problems.push(`${claim}: not in ${file}`);
    }
    const m = HELD_BY.exec(heldBy ?? "");
    if (!m) { problems.push(`${claim}: "Held by" should be \`tests/file.test.js\`: \`test title\``); continue; }
    const [, file, title] = m;
    const test = read(file);
    if (test === null) { problems.push(`${claim}: ${file} doesn't exist`); continue; }
    try {
      if (!runnableTests(test).has(title)) problems.push(`${claim}: no test "${title}" in ${file}`);
    } catch (e) {
      problems.push(`${claim}: can't parse ${file}: ${e.message}`);
    }
  }
  return problems;
}

/** Reads a file under the repo root, or null. */
export const readRepo = (file) => (existsSync(join(ROOT, file)) ? readFileSync(join(ROOT, file), "utf8") : null);

if (import.meta.url === `file://${process.argv[1]}`) {
  const rows = parseClaims(readRepo("docs/claims.md"));
  const problems = checkClaims(rows, readRepo);
  if (problems.length) {
    console.error(`Claim map: ${problems.length} broken:\n  ${problems.join("\n  ")}`);
    process.exit(1);
  }
  console.log(`Claim map: ${rows.length} claims, each in its files and held by a test.`);
}
