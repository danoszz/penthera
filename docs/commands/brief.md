---
title: "The agent brief"
sidebarTitle: "The agent brief"
description: "The brief is a short summary of a scan, the same shape every time, for an AI assistant to pass on as it is."
---

> **Pro.** For "what should my AI assistant tell me after a scan?"

The brief is a short summary of a scan, the same shape every time, for an AI
assistant to pass on as it is. Penthera's rules fill it; no model is involved.

| Section | What is in it |
|---|---|
| Verdict | `Fix now` when Act on holds a critical or high finding. `Review` when anything is in Act on, or the run exits 1 or 2. `Nothing to fix now` when only Check first holds something (headers read from code, say, which your host may still add) and the run exits 0: the count to check is beside it. `Nothing to fix` otherwise. `Site not read` when a firewall answered instead of the site, unless a critical or high finding says `Fix now`; the exit code doesn't change. With the counts. `Nothing to assess` when `penthera agents` found no agent config. Never `Nothing to fix` when a finding or a required tool makes the scan exit 1 or 2: it says `Review` and gives the reason on the next line. A failure after the brief prints, such as an output file it can't write, exits 2 with an error of its own |
| Do this first | One line under the verdict: the first step for the top finding in Act on (or Check first), where it is, and why it matters. Only when there is something to act on or check |
| Act on | Findings that need a change: where, why it matters, the fix, the rule id |
| Check first | Heuristic and low findings, and what a dependency *can* do |
| Likely noise | Hits in files git ignores, generated build output, test fixtures, test files, vendored or minified third-party code, or examples and samples, one line per group |
| Not checked | What the scan did not read. Always shown, so a short brief is not read as "safe" |
| Next | Up to three commands, and the path of the full report |

Findings that repeat collapse into one line: two advisories for one Node.js
pin, or the same rule in 16 build files. Every finding is counted once. The
full list stays in the JSON and Markdown reports.

## Get it

| Where | How |
|---|---|
| A scan, in a terminal | `penthera --repo . --brief` |
| A scan, from an agent | Nothing to add: with no terminal on stdout, a scan prints the brief instead of the terminal report. `PENTHERA_BRIEF=0` or `--verbose` turns that off, `PENTHERA_BRIEF=1` turns it on anywhere, and CI keeps the terminal report. `--json`, `--audience` and `--report-template` print their own output instead |
| A report file | `penthera --repo . --audience agent --markdown reports/brief.md` |
| JSON | The `brief` field of `-o report.json` (schema `penthera.brief/1`). `exit_code` is the code the findings give, `exit_reason` the line under the verdict or null, and `likely_noise[].severe` the critical or high findings in that group. Top-level fields: `schema`, `verdict`, `verdict_id` (a stable name: `fix`, `review`, `check`, `clean`, `none`, `unread` or `suppressed`), `exit_code`, `exit_reason`, `target`, `scanned`, `counts` (`problems`, `act`, `check`, `noise`, `info`, `suppressed`, `total`), `act_on`, `check_first`, `likely_noise`, `not_checked`, `next`, `set_aside` (how to suppress a problem you checked, by fid with a reason; only when findings carry a fid), `reports`, and since 2.5.0 `first` (`title`, `where`, `action`, `why_it_matters`, `from`, or null). Each item in `act_on` and `check_first` has `confidence` and `exploitability`, and since 2.5.0 `why_it_matters` and `first_step` (null when the table has no line for the rule) |
| Several scans in one | `penthera brief reports/repo.json reports/deps.json reports/agents.json` |
| MCP | The text of every scan tool's result is the brief; `structuredContent.brief` holds the object. `explain_finding` has no brief |

```bash
penthera --repo . -o reports/repo.json
penthera deps . -o reports/deps.json
penthera agents . -o reports/agents.json
penthera brief reports/repo.json reports/deps.json reports/agents.json
```

`penthera brief --json` prints the merged brief as JSON. `penthera brief`
reads only the files you name and runs no scan. `penthera brief --card` also
writes the merged result as a share card, and `--card-out <path>` picks where
([scan.md](scan.md#share-card)).

## Why it matters, in plain words

Each finding in Act on and Check first gets a "Why it matters" line written
for someone who is not in security, and a first step. They come from a fixed
table in `src/report/plain.js`, keyed on the rule id and, for a secret, the
key's name. The table covers what makers ship most: Stripe and Clerk keys,
AI provider keys, Supabase service_role keys and row-level security, Next.js
`NEXT_PUBLIC_` variables, Server Actions and source maps, framework
advisories, and GitHub Actions workflows.

No model writes these lines, and they never move a finding, change its
severity or change the verdict. A rule the table does not know keeps the
finding's own description, and the fix stays the finding's own when it has
one.

## How an assistant should reply

The MCP server and the Agent Skill ask the assistant to:

1. Pass the brief on in its order, with the verdict line, the **Do this
   first** line and the section names, and lead with that first step.
2. Not move a finding between sections, change a severity or drop a group.
3. Put anything it checked itself under a last section, **My read**, and say
   what it looked at. That section is the assistant's view, not Penthera's.
4. Ask before changing files.

## How Penthera counts

Every surface counts one run's findings the same way and uses the same words:
the brief, the terminal report, `penthera ui`, the MCP tools, the JSON and
SARIF reports, `penthera fix` and the fix loop.

| Word | What it counts |
|---|---|
| finding | Anything a rule reported, info and likely noise included |
| problem | A finding to act on or to check first. Info, likely noise and suppressed findings are not problems |
| fix planned | One diff from `penthera fix` that fixes at least one problem. One fix can cover several problems. A finding a recipe matches but cannot change is not fixable |

The verdict line reads `8 problems (4 to act on, 4 to check first), 0 likely
noise`. SARIF carries the same counts in `runs[0].properties.counts`.

## Which section a finding goes in

The first matching rule wins:

1. **Likely noise:** the file is local only (git ignores it), in generated
   output (`.next*`, `.turbo`, `.svelte-kit`, `.nuxt`, `.output`,
   `__pycache__`, `coverage`, and `dist`, `build` or `out` unless a source
   folder such as `app`, `src`, `api`, `pages`, `routes` or `lib` comes
   first, so `app/api/build/route.ts` stays real code), a test fixture
   (`fixtures`, `__fixtures__`, `testdata`, `__mocks__`), a test file
   (anything under `test`, `tests`, `test_*`, `test-*`, `__tests__`, `e2e`,
   `cypress` or `playwright`, or named `*.test.*`, `*.spec.*` or `*.cy.*`),
   with the reason "in test files", vendored or minified third-party code
   (`vendor`, `third_party`, `bower_components`, `public/js/lib` and the like,
   `*.min.js`), or an example or sample (`examples`, `samples`, `demos`). A
   rootkit, persistence, suspicious-file, malicious-package or agent-config
   finding is never moved to noise for being in a vendored or example folder. The finding is still listed, still counted, and the exit
   code doesn't change. A fixtures folder inside `tests` keeps the fixture
   reason. In a skill folder you name, `dist` and `build` are the skill's
   own code, so they are not noise there.
2. An **info** finding goes to **Next** if it names a command, or to **Not
   checked** if it says something was not found or not run.
3. **Check first:** confidence `potential` or `needs-human-review`, severity
   low, or a dependency capability. A hardcoded password stays high but goes
   here when it is in a test location (a test folder, a `*.test.*` or `*.spec.*`
   file, or a `scripts/verify-*` or `scripts/smoke-*` script) and, within three
   lines, an email, user or login field is set to an address at a test domain
   (`example.com`, `.test`, `.invalid`) in code, not in a comment. The finding
   says so. Anything else, or one other password in the file, keeps it in Act on.
4. **Act on:** everything else.

The design is in [docs/research/spec-agent-brief.md](https://github.com/danoszz/penthera/blob/main/docs/research/spec-agent-brief.md).