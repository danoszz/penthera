/**
 * Provenance check for pull requests (CONTRIBUTING.md, "Use of generative AI").
 *
 *   node scripts/ci/provenance.mjs <base-ref> [head-ref]
 *
 * The disclosure is the `AI-Assisted:` trailer, which names the tool and model
 * and says what the AI did. A `Co-Authored-By:` line naming an AI is optional,
 * but a commit that has one must also carry `AI-Assisted:` (it would otherwise
 * claim AI help without saying what it was). Commits with neither are
 * human-written and pass. Exits 1 and lists the offending commits otherwise.
 * Dependabot's verified pin bumps pass too (scripts/ci/dependabot.mjs).
 */
import { execFileSync } from "node:child_process";
import { dependabotPr } from "./dependabot.mjs";

const AI_COAUTHOR = /^Co-Authored-By:.*\b(?:Claude|GPT|ChatGPT|Codex|Gemini|Copilot|Cursor|Llama|Mistral|Qwen|DeepSeek)\b/im;
const AI_ASSISTED = /^AI-Assisted:\s*\S.*;\s*\S/im;

const [base, head = "HEAD"] = process.argv.slice(2);
if (!base) {
  console.error("usage: provenance.mjs <base-ref> [head-ref]");
  process.exit(2);
}

const bot = await dependabotPr(base, head);
if (bot.ok) {
  console.log(`Provenance: ${bot.reason}.`);
  process.exit(0);
}

const git = (...args) => execFileSync("git", args, { encoding: "utf-8" });
const shas = git("rev-list", "--no-merges", `${base}..${head}`).split("\n").filter(Boolean);

const bad = [];
for (const sha of shas) {
  const body = git("show", "-s", "--format=%B", sha);
  const coauthor = AI_COAUTHOR.test(body);
  const assisted = AI_ASSISTED.test(body);
  if (coauthor && !assisted) bad.push(`${sha.slice(0, 7)} names an AI co-author but has no "AI-Assisted: <tool> with <model>; <what it did>" trailer`);
}

if (bad.length) {
  console.error(`Provenance: ${bad.length} of ${shas.length} commit(s) need trailers (see CONTRIBUTING.md#use-of-generative-ai):\n  ${bad.join("\n  ")}`);
  process.exit(1);
}
console.log(`Provenance: ${shas.length} commit(s) checked, all disclosed consistently.`);
