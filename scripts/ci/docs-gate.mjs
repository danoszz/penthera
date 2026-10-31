#!/usr/bin/env node
/**
 * Docs gate for pull requests (CONTRIBUTING.md, "Sending a change").
 *
 *   node scripts/ci/docs-gate.mjs <base-ref> [head-ref]
 *
 * A change to the public surface (CLI flags and output, MCP tools, rules, the
 * GitHub Action) must come with a change to a doc that owns that surface, or
 * with a line in its changelog fragment that says why none is needed:
 *
 *   section: Fixed
 *   docs: none, the flag parser moved and nothing changes for users
 *
 * Only paths decide. It can't tell whether a doc is right: that's for
 * scripts/docs-commands.mjs and tests/docs-coverage.test.js. Exits 1 and names
 * what's missing, 2 on a usage error.
 */
import { execFileSync } from "node:child_process";
import { parseFragment } from "../changelog.mjs";

const USER_DOCS = /^(README\.md|docs\/(?!research\/|funding\/|decisions\/).+\.md|skills\/penthera\/.+)$/;

/** Each surface: the paths that make it up, and the docs that own it. */
export const SURFACES = [
  {
    name: "CLI",
    paths: [/^bin\//, /^src\/cli\.js$/, /^src\/cli\//, /^src\/report\/(exit|brief)\.js$/],
    docs: USER_DOCS,
  },
  {
    name: "MCP tools",
    paths: [/^src\/mcp\//, /^server\.json$/],
    docs: /^(docs\/commands\/mcp\.md|docs\/mcp-listing\.md|docs\/mcp-clients\/.+|skills\/penthera\/.+)$/,
  },
  {
    name: "rules",
    // A re-signed pack changes pack.json and its .sig, and no rule.
    paths: [/^lib\/rules\/[^/]+\/(?!pack\.json(\.sig)?$)/, /^lib\/agents\/(rules|grade)\.js$/],
    docs: USER_DOCS,
  },
  {
    name: "GitHub Action",
    paths: [/^action\.yml$/],
    docs: /^(README\.md|docs\/commands\/action\.md|docs\/examples\/.+)$/,
  },
];

const FRAGMENT = /^changelog\.d\/(?!README\.md$)[^/]+\.md$/;

/**
 * Decides one change.
 * @param {string[]} files paths the change touches
 * @param {{file: string, text: string}[]} fragments changelog fragments the change adds or edits
 * @returns {{touched: string[], excused: string|null, missing: {name: string, files: string[]}[]}}
 */
export function checkChange(files, fragments = []) {
  const hits = SURFACES
    .map((s) => ({ ...s, files: files.filter((f) => s.paths.some((p) => p.test(f))) }))
    .filter((s) => s.files.length);
  const excused = fragments.map((f) => parseFragment(f.text, f.file).docsNone).find(Boolean) ?? null;
  const missing = excused ? [] : hits.filter((s) => !files.some((f) => s.docs.test(f)));
  return { touched: hits.map((s) => s.name), excused, missing: missing.map(({ name, files }) => ({ name, files })) };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [base, head = "HEAD"] = process.argv.slice(2);
  if (!base) {
    console.error("usage: docs-gate.mjs <base-ref> [head-ref]");
    process.exit(2);
  }
  const git = (...args) => execFileSync("git", args, { encoding: "utf-8" });
  const files = git("diff", "--name-only", `${base}...${head}`).split("\n").filter(Boolean);
  const present = new Set(git("ls-tree", "-r", "--name-only", head, "changelog.d").split("\n"));
  const fragments = files.filter((f) => FRAGMENT.test(f) && present.has(f))
    .map((file) => ({ file, text: git("show", `${head}:${file}`) }));
  try {
    const { touched, excused, missing } = checkChange(files, fragments);
    if (missing.length) {
      console.error("Docs gate: this change touches the public surface but no doc that owns it:");
      for (const m of missing) console.error(`  ${m.name}: ${m.files.slice(0, 5).join(", ")}${m.files.length > 5 ? ", ..." : ""}`);
      console.error('Update the doc, or add "docs: none, <reason>" under "section:" in your changelog fragment (changelog.d/README.md).');
      process.exit(1);
    }
    console.log(touched.length
      ? `Docs gate: ${touched.join(", ")} touched; ${excused ? `no docs needed: ${excused}` : "docs updated."}`
      : "Docs gate: no public surface touched.");
  } catch (e) {
    console.error(`Docs gate: ${e.message}`);
    process.exit(1);
  }
}
