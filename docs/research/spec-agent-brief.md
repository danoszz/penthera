# Spec: the agent brief

Status: approved 2026-10-27, built for 2.1.0-rc.2. User docs: [docs/commands/brief.md](../commands/brief.md).

## Problem

When an AI assistant runs Penthera (CLI, MCP or the Agent Skill), it gets
either the full Markdown report or a short MCP summary. Neither tells it what
to say back to the user. So every assistant writes its own summary, and a lot
of that summary is the assistant redoing triage that Penthera's rules could do:

- deciding which findings are real and which are noise;
- grouping 16 near-identical findings into one line;
- noticing that a clean area was never checked;
- correcting an action plan step that does not fit the findings.

A test run on a private Next.js + FastAPI monorepo (2.0.0, three scans) showed
this. The assistant had to explain that 19 of 21 high findings were noise, and
that two of the three action plan steps did not apply. Its reply was good, but
it was the assistant's judgment, written freehand, in a different shape each
time.

## Goal

One brief, the same shape everywhere, that an assistant can pass on with
little or no rewriting. Rules fill it. The assistant may add its own view, but
only in a labelled section of its own.

## The brief

Six sections, always in this order. An empty section is left out, except
**Not checked**, which is always shown.

| # | Section | What goes in it | Decided by |
|---|---|---|---|
| 1 | **Verdict** | One line: `Fix now`, `Review`, `Nothing to fix` or `Nothing to assess`, plus the counts behind it | rules |
| 2 | **Act on** | Findings that need a change: what, where (`file:line`), why in one clause, the fix in one line, the rule id | rules |
| 3 | **Check first** | Heuristic findings a person has to look at before acting | rules |
| 4 | **Likely noise** | Findings demoted by a deterministic reason, grouped by reason, one line per group | rules |
| 5 | **Not checked** | What the scan did not read, so a short brief is not read as "safe" | coverage ledger |
| 6 | **Next** | Exact commands to run next, at most three | rules |

### Verdict

- `Fix now`: at least one finding in **Act on** at high or critical.
- `Review`: anything in **Act on** below high, anything in **Check first**, or a
  run that exits 1 or 2 with nothing high in **Act on**. A line then gives the
  reason, and the JSON has `exit_code`, `exit_reason` and
  `likely_noise[].severe`.
- `Nothing to fix`: both empty and exit 0. Still followed by **Not checked**.
- `Nothing to assess`: an agents audit that found no agent config. It has no
  grade. Still followed by **Not checked**.

The verdict uses the same words as the penthera.org check, so the user sees one
vocabulary.

### Which bucket a finding goes in

Only fields Penthera already sets decide this (AGENTS.md rule 4):

| Bucket | Rule |
|---|---|
| Likely noise | the file is gitignored or in generated output (`.next*`, `dist`, `build`, `__pycache__`), **or** `localOnly` is set, **or** the path is a test fixture |
| Check first | confidence is `potential` or `needs-human-review`, **or** severity is low, **or** it is a dependency capability (what a package *can* do is not proof of harm) |
| Act on | medium or above, confidence `confirmed` or `likely`, and none of the above |
| (no bucket) | info findings: one with a command goes to **Next**, a coverage note goes to **Not checked** |

The first matching row wins, top to bottom.

Noise is never hidden. Each group says what it is and how many, and the full
list stays in the JSON and the full report.

### Grouping

Findings with the same rule and the same reason collapse into one line with a
count and up to three example paths, for example "`eval` in generated build
output: 16 files in 8 `.next-*` folders". Findings with the same fix (two
advisories for one runtime pin) collapse into one step.

### Length

At most about 40 lines. The brief ends with the path of the full report.

## Example

The test run above, as a brief, assuming the engine fixes below (E1 removes the
three false "hardcoded password" hits). Paths shortened.

```markdown
**Penthera: Fix now.** 3 to act on, 9 to check first, 20 likely noise. Scanned: repo, dependencies, agent config.

### Act on
1. **Node.js 22.21.1 pinned in `.nvmrc`** has 2 high advisories (Brotli decoder RCE, TLS hostname check). Fix: pin 22.23.4 or later. `nodejs-cve-2026-111497`, `nodejs-tls-hostname-2026-10`
2. **`.claude/settings.local.json` pre-approves `bash /tmp/graphify_scan.sh`.** Any local process can write that file, and it then runs without asking. Fix: move the script into the repo, or remove the rule. `permission-tmp-script`

### Check first
- 7 dependencies run code at install or Python start: esbuild and 4 others (install scripts), setuptools (`.pth`). Usual for these packages; rerun `penthera deps --diff` after each lockfile change.
- Skill `shadcn` pre-approves `npx shadcn@latest *` and `bunx --bun shadcn@latest *`, which can run any code while the skill is active.

### Likely noise
- 16 `eval` hits in gitignored build output (`apps/frontend/.next-*`).
- 4 API keys in gitignored `.env` files, never committed. Rotate them only if a file was shared.

### Not checked
- Route analysis did not run: no Next.js, Express, Hono or Fastify routes found, and Python (736 files) is not supported. Point `--api-root` at your routes if they live elsewhere.
- 36,549 files in folders the scan skips (virtualenvs, caches, gitignored folders). Files over the size limit: not counted yet (E8).

### Next
- `penthera agents . --pin` once you have reviewed the agent config, so later runs catch changes.
- Full reports: `reports/repo.md`, `reports/deps.md`, `reports/agents.md`
```

## Where it appears

| Surface | Change |
|---|---|
| JSON report | a `brief` object (`schema: "penthera.brief/1"`) next to `findings` and `actionPlan` |
| CLI | `--brief` prints the brief to stdout; `--audience agent --markdown <file>` writes it |
| MCP | the text part of every tool result becomes the brief; `structuredContent.brief` holds the object |
| Agent Skill | SKILL.md tells the assistant to read the brief and reply in its shape (below) |
| penthera.org check | unchanged for now; it already uses the verdict words |

A combined run (repo, deps and agent config together) gives one brief, not
three. The skill already runs the three scans; the brief merges their findings
before bucketing.

## How the assistant replies

A short reply contract, in SKILL.md and in the MCP server instructions:

1. Pass the brief on in its order. Keep the verdict line, the reason line under it when there is one, and the section names.
2. Do not move a finding between sections, change a severity or drop a group.
3. If you checked something yourself (you opened the file and saw `pass:` is a
   CSS class map), say so under a last section, **My read**, and name what you
   looked at. That section is your judgment, not Penthera's.
4. Ask before changing files. Name the one change you would make first.

This keeps the line AGENTS.md draws: rules decide, a model may only propose.

## Engine fixes the brief depends on

The brief is only as good as the triage under it. The test run found these.
Each gets a fixture test.

| # | Problem | Fix |
|---|---|---|
| E1 | "Hardcoded password" fires on `pass: 'text-emerald-400'` (a style map) and is marked `confirmed` | require a password-like key (`password`, `passwd`, `pwd`, `pass` only with a separator such as `db_pass`); reject values that look like class lists |
| E2 | The `eval` check reads gitignored build output (`.next-<suffix>`) | pass the git-ignore set to the code-sink walk, as the secret scan does; skip `.next*` |
| E3 | The action plan maps a Node.js advisory to "Fix the TLS configuration" because the title says TLS | runtime advisories get their own step, "Upgrade the runtime"; the TLS step matches `category: tls` only |
| E4 | Secret step is HIGH and says "purge from git history" when every secret is in a gitignored file | local-only secrets get their own low step: "check where these files went; rotate if shared" |
| E5 | 16 `eval` hits get "Review and remediate this finding" | code-sink findings map to the injection step |
| E6 | `Bash(bash /tmp/x.sh)` is described as "bash with any arguments" | new rule `permission-tmp-script`: a pre-approved script under a world-writable path; the "any arguments" text only for real wildcards |
| E7 | Agent and deps reports print an empty OWASP WSTG table; repo reports say "Reachable: No" | leave out sections that do not apply to the mode |
| E8 | Files over the size limit are skipped without a word | count them in the coverage ledger |

E8 and the "Not checked" section together answer the question an assistant
could not: did Penthera read the 37 MB JSON files or not?

## Out of scope

- Python route analysis (FastAPI, Flask). It stays a coverage gap that the
  brief names; it is a separate roadmap item.
- A known-good list for package files such as the setuptools `.pth`. If added,
  it must match exact file hashes, and it is its own change.
- Any model in the triage. Buckets come from rules only.

## Tests

- The brief for each fixture repo is a snapshot test.
- A property test: every finding in the JSON appears in exactly one brief
  bucket or group count.
- The MCP text result stays under the existing byte budget.
- The docs-as-tests check covers `--brief` and `--audience agent`.

## Decisions

1. Section names as above.
2. A scan prints the brief by default when stdout is not a terminal and this
   is not CI (an agent calling the CLI). `PENTHERA_BRIEF=0` turns it off,
   `--brief` turns it on anywhere.
3. Ships in 2.1.0-rc.2 with the E1 to E8 fixes.
4. Counts in the verdict line are findings, not lines: two advisories on one
   pin are one line and two findings.
5. A bare `pass` key (E1) is dropped only when it sits in a map of check
   outcomes (`fail`, `warn`, `skip` nearby) or its value is CSS. Dropping every
   bare `pass` key cost 25 true positives on the CredData dev half, so it was
   not done.
