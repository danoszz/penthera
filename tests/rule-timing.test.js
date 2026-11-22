/**
 * Every scanner that reads untrusted text, timed on input built from its own
 * rule words (tests/helpers/timing.js). A failure names the scanner, the glue
 * shape and the timings: paste that shape into a file to reproduce it.
 *
 * By default each first measurement holds 16 words, each in its own long run,
 * and only a group that costs more than neutral input is tested word by word.
 * That is quick, and it can miss a slow path that one word in sixteen dilutes.
 * PENTHERA_TIMING_FULL=1 tests every word alone (about a minute per scanner);
 * PENTHERA_TIMING_FULL=lib/a.js,lib/b.js does so for those scanners. CI runs
 * the long form for the scanners a pull request changes.
 */
import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { ruleWords, SHAPES, PREFIXES, PREFIXED, blocks, groups, slowWords, baselineOf } from "./helpers/timing.js";
import { scanHiddenContent } from "../lib/agents/hidden-content.js";
import { findRegistryRedirects, findLoaderEnv } from "../lib/agents/rules.js";
import { redactCommand } from "../lib/agents/redact.js";
import { missingCheckHits } from "../lib/whitebox/missing-checks.js";
import { sessionAuthHits } from "../lib/whitebox/session-auth.js";
import { uncheckedActions } from "../lib/whitebox/server-actions.js";
import { findSinks } from "../lib/whitebox/code-sinks.js";
import { checkWorkflow } from "../lib/whitebox/workflows.js";
import { findSecretsInText } from "../lib/whitebox/secrets.js";
import { publicSecretSightings } from "../lib/whitebox/public-env.js";
import { riskPatterns } from "../lib/whitebox/frameworks.js";
import { findServiceKeys } from "../lib/whitebox/supabase.js";
import { scanSource } from "../lib/deps/capabilities.js";
import { scrubSecrets } from "../lib/scrub.js";

const ROOT = join(import.meta.dirname, "..");
// "1" tests every word alone for every scanner; a comma list of source files does so for those scanners only.
const FULL_ENV = (process.env.PENTHERA_TIMING_FULL || "").trim();
const fullFor = (file) => FULL_ENV === "1" || FULL_ENV.split(",").map((x) => x.trim()).includes(file);

// Slow paths on main today, each with the pull request that fixes it. Delete an entry
// once its fix is on main; anything slow that is not listed here fails the test.
const KNOWN_SLOW = [
  // A PowerShell download word on a line, with no pipe later in the file: thenOnLine()
  // looks for the next "|" to the end of the file, once per line. Fixed by PR 335
  // (pipe positions are read once).
  { scanner: "agents: hidden content", match: /shape w, (?:one per line|line continued), word (?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|DownloadString):/ },
];

// A head opens a rule's gate (an import, a directive, a download), so the filler reaches the rule.
const WEBHOOK = `export async function POST(req) {\n  const event = await req.json();\n  if (event.type === "x") {\n`;
const SCANNERS = [
  { name: "agents: hidden content", file: "lib/agents/hidden-content.js", run: (t) => scanHiddenContent(t), heads: ["", "curl -o /tmp/x https://example.com/x\n", "curl https://example.com/a ", "chmod +x /tmp/x\n"] },
  { name: "agents: registry redirects", file: "lib/agents/rules.js", run: (t) => findRegistryRedirects(t, ".npmrc"), heads: [""] },
  { name: "agents: loader env", file: "lib/agents/rules.js", run: (t) => findLoaderEnv(t), heads: [""] },
  { name: "agents: command redaction", file: "lib/agents/redact.js", run: (t) => redactCommand(t), heads: [""] },
  { name: "repo: missing checks", file: "lib/whitebox/missing-checks.js", run: (t) => missingCheckHits(t, "app/api/webhook/route.ts"), heads: ["", WEBHOOK, `import jwt from "jsonwebtoken";\n${WEBHOOK}`] },
  { name: "repo: session and auth", file: "lib/whitebox/session-auth.js", run: (t) => sessionAuthHits(t, { middleware: () => true }), heads: ["", `import session from "express-session";\nconst o = { `, `import NextAuth from "next-auth";\nconst password = encrypt(req.query.token);\n`] },
  { name: "repo: server actions", file: "lib/whitebox/server-actions.js", run: (t) => uncheckedActions(t), heads: ["", `"use server";\nexport async function save(form) {\n`] },
  { name: "repo: code sinks", file: "lib/whitebox/code-sinks.js", run: (t) => findSinks(t), heads: ["", `const { exec } = require("child_process");\napp.get("/", (req, res) => {\n`] },
  { name: "repo: workflows", file: "lib/whitebox/workflows.js", run: (t) => checkWorkflow(t, ".github/workflows/ci.yml"), heads: ["", "on: pull_request_target\njobs:\n  a:\n    steps:\n      - run: |\n"] },
  { name: "repo: secrets", file: "lib/whitebox/secrets.js", run: (t) => findSecretsInText(t, { path: "src/a.js" }), heads: ["", "const password = "] },
  { name: "repo: public env", file: "lib/whitebox/public-env.js", run: (t) => publicSecretSightings(t, ".env"), heads: ["", "NEXT_PUBLIC_"] },
  { name: "repo: framework risks", file: "lib/whitebox/frameworks.js", run: (t) => riskPatterns(t), heads: ["", `import express from "express";\n`] },
  { name: "repo: Supabase keys", file: "lib/whitebox/supabase.js", run: (t) => findServiceKeys(t), heads: ["", `import { createClient } from "@supabase/supabase-js";\n`] },
  { name: "deps: package source", file: "lib/deps/capabilities.js", run: (t) => scanSource(t, "index.js"), heads: ["", `const cp = require("child_process");\n`] },
  { name: "output: secret scrubber", file: "lib/scrub.js", run: (t) => scrubSecrets(t), heads: [""] },
];

// Words per first measurement; a group that costs more than neutral input is then tested word by word.
const GROUP = 16;
// Characters at n (the check also reads 4n and, to confirm, 16n). Smaller by default to keep `npm test` quick.
const SIZE = { quick: 12 * 1024, full: 32 * 1024 };

describe("scanners stay linear on input built from their own rule words", () => {
  for (const s of SCANNERS) {
    it(s.name, () => {
      const words = ruleWords(join(ROOT, s.file));
      expect(words.length, `rule words read from ${s.file}`).toBeGreaterThan(5);
      const slow = [];
      const full = fullFor(s.file);
      const opts = { n: full ? SIZE.full : SIZE.quick };
      for (const head of s.heads) {
        for (const [shapeName, shape] of Object.entries(SHAPES)) {
          for (const prefixName of ["", ...(PREFIXED[shapeName] || [])]) {
            const make = (ws, n) => head + PREFIXES[prefixName](n) + blocks(shape, ws, n);
            const base = baselineOf(s.run, make, opts);
            for (const group of groups(words, full ? 1 : GROUP)) {
              for (const { word, why } of slowWords(s.run, make, group, base, opts)) {
                slow.push(`head ${JSON.stringify(head.slice(0, 40))}, prefix ${prefixName || "none"}, shape ${shapeName}, word ${word}: ${why}`);
              }
            }
          }
        }
      }
      const known = KNOWN_SLOW.filter((k) => k.scanner === s.name);
      expect(slow.filter((line) => !known.some((k) => k.match.test(line))), `${s.name}: work grows faster than the input`).toEqual([]);
    }, fullFor(s.file) ? 1_800_000 : undefined);
  }
});
