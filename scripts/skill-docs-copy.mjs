#!/usr/bin/env node
/**
 * Writes docs/skill.md, the copy of the Agent Skill that docs.penthera.org
 * serves to agents. It is skills/penthera/SKILL.md with its relative links to
 * references/ and scripts/ made absolute.
 *
 * The links point at the release tag the skill pins (`penthera@X.Y.Z`), not at
 * `main`, so an agent that follows one reads the files of that release and
 * nothing that changed since.
 *
 *   node scripts/skill-docs-copy.mjs          # write docs/skill.md
 *   node scripts/skill-docs-copy.mjs --check  # exit 1 if it is out of date
 */
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SOURCE = join(ROOT, "skills/penthera/SKILL.md");
const TARGET = join(ROOT, "docs/skill.md");

/** The base URL for the skill's files at the release its text pins. */
export function skillLinkBase(skill) {
  const pin = skill.match(/penthera@(\d+\.\d+\.\d+)/)?.[1];
  if (!pin) throw new Error("skills/penthera/SKILL.md pins no penthera@X.Y.Z version");
  return `https://github.com/danoszz/penthera/blob/v${pin}/skills/penthera/`;
}

/** The docs-site copy of the skill text. */
export function skillDocsCopy(skill = readFileSync(SOURCE, "utf-8")) {
  const base = skillLinkBase(skill);
  return skill.replace(/\]\((references|scripts)\//g, (_, dir) => `](${base}${dir}/`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const want = skillDocsCopy();
  if (process.argv.includes("--check")) {
    if (readFileSync(TARGET, "utf-8") !== want) {
      console.error("docs/skill.md is out of date. Run: node scripts/skill-docs-copy.mjs");
      process.exit(1);
    }
  } else {
    writeFileSync(TARGET, want);
  }
}
