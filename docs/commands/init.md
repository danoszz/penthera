---
title: "Set up in one command: penthera init"
sidebarTitle: "Set up"
description: "One command detects your project, runs the offline checks and offers the hook, the workflow and the dashboard."
---

> **Starter.** For "is my app safe to ship?"

## Start here

New to Penthera? Run it with no arguments in your project folder:

```bash
npx penthera          # in a terminal, with no arguments: the setup wizard
penthera init         # the same wizard, by name (also works with piped answers)
penthera init --yes   # accept every safe default, ask nothing
penthera init --dry-run   # show what would run and be written, change nothing
```

The wizard finds what your project has, asks one question about what to check,
runs those checks offline, shows one summary, and then offers to set up the
hook, the CI workflow and the rest, one yes/no at a time. Press Enter to accept
a default.

Without a terminal (a coding agent, CI, a pipe), `npx penthera` with no
arguments does not start the wizard. It prints three commands to run instead,
`penthera init --yes --dry-run`, `penthera init --yes` and `penthera --repo .`,
and exits 2.

## What it does

**1. Detect.** Offline, read-only:

- whether this is a git repository (and which branch);
- the web framework, from `package.json`, `requirements.txt` or `pyproject.toml`;
- lockfiles: `package-lock.json`, `npm-shrinkwrap.json`, `uv.lock`,
  `poetry.lock`, `pdm.lock`, `Pipfile.lock`, `requirements.txt`;
- agent config: `.mcp.json`, `.claude/`, `.cursor/`, `CLAUDE.md`, `AGENTS.md`, `skills/`;
- a dev server on localhost ports 3000, 5173, 8000 or 8080 (a TCP connect to
  127.0.0.1 and ::1, nothing else);
- whether the Penthera pre-commit hook or a Penthera GitHub workflow is already there.

**2. Ask what to check.** One checklist, with defaults from what was found.
Type numbers to toggle items (`2,4`), or press Enter:

```
  What should Penthera check?
    1. [x] Code: secrets and risky API routes in ./                 penthera --repo .
    2. [x] Dependencies: what your npm and Python packages can do   penthera deps
    3. [x] AI tooling: skills, MCP servers, hooks, agent instructions  penthera agents
    4. [ ] The running app at http://localhost:3000                 only if it is yours
    5. [x] Offline mode: nothing leaves this machine                recommended
```

- AI tooling then asks whether to include `~/.claude` and `~/.cursor` too (default no).
- The running app is only listed when a dev server answered, is never
  preselected, and is only scanned after you confirm it is yours (default no).
  It runs the standard safe checks: no attack payloads.
- With offline mode off, `deps` also reads npm registry metadata and the URL
  scan may download the Retire.js database. Nothing else changes.

**3. Run and summarize.** One line per check, then the grade per area (A to F,
the same scale as `penthera agents`, or `–` when there was nothing to read), the
three things to fix first in plain language, and the report folder:

```
  Running 3 checks  (offline)
    ✓ Code          B  1 high  0.1s
    ✓ Dependencies  A  no issues  0.0s
    ✓ AI tooling    A  1 medium  0.0s
```

An area with nothing to read gets no grade. On a fresh clone with no
`node_modules`, Dependencies shows `–  not checked: 0 of 61 packages installed
or cached`, with the fix: `npm ci --ignore-scripts` installs the packages
without running their code, so the next run can read them. When only some are
missing, the grade covers what was read and the line says how many were not.

Every report lands in `reports/penthera-<date>/`: `code`, `deps`, `agents` and
`app` as JSON and Markdown, plus `summary.md` and `summary.json`.

**4. Set up.** Each step is a yes/no:

| Step | Default | What it does |
|---|---|---|
| Pre-commit hook | yes | `penthera hook install`: blocks staged secrets, risky agent config and lockfile changes ([hook.md](hook.md)). Git repos only |
| GitHub workflow | yes | Writes `.github/workflows/penthera.yml` from [the PR dependency review example](https://github.com/danoszz/penthera/blob/main/docs/examples/pr-dependency-review.yml), with the action pinned to the release commit SHA. Shown as a diff first. Needs a git repo and `package-lock.json` |
| Agent config workflow | yes | Writes `.github/workflows/penthera-agents.yml` from [the agent config example](https://github.com/danoszz/penthera/blob/main/docs/examples/github-actions-agents.yml): `npx --yes penthera@<version> agents` on every pull request, with SARIF to code scanning. The version is the same release as the action pin. Shown as a diff first. Needs a git repo and agent config |
| `.gitignore` | yes | Appends `reports/` so scan output is never committed |
| Fix loop | no | `penthera agent --loop` on a local `penthera/fix-<date>` branch; every diff asks first ([fix.md](fix.md)) |
| Dashboard | yes | `penthera ui --open` on this run's reports ([dashboard.md](../dashboard.md)). Runs until Ctrl-C |

Steps that are already done (a hook or workflow that exists, `reports/` already
ignored) are skipped and say so.

**5. What next.** The commands to rerun each check, check staged changes, run
the fix loop or open the dashboard.

## Before you launch

When you know what you want, run the checks directly. Start the app locally,
then:

```bash
npx penthera http://localhost:3000 --repo .   # the running app and its source, together
npx penthera fix --plan --repo .              # fixes for what it can fix, as diffs
npx penthera hook install                     # stop secrets at commit time from now on
```

Or ask your coding agent, with the [Agent Skill](skill.md) installed: "scan my
app on localhost:3000 and fix what you find". Before you deploy, run the same
scan against your preview URL. Only scan systems you own.

The scan looks for what tends to go wrong in apps written fast, often with an
AI assistant: an API route that returns any user's data if you change the id,
an AI provider key in a client bundle, a missing security header, a CORS policy
of `*`, a login with no rate limit. `penthera fix --plan` then prints a diff
per fix it knows. Nothing is written until you apply a plan
([fixes](fix.md)).

## `--yes` and `--dry-run`

`--yes` answers every question with its safe default: the code, dependency and
AI tooling checks that apply, offline, then the hook, the workflows and
`.gitignore`. It never scans a URL, never runs the fix loop and never opens the
dashboard, even when a dev server is running.

`--dry-run` runs detection and asks the questions, then prints what it would
run and write instead of doing it. Combine them for a plan with no prompts:

```bash
penthera init --yes --dry-run
```

`penthera --yes` and `penthera --dry-run` (no other arguments) are the same as
`penthera init --yes` and `penthera init --dry-run`.

## What it does not do

- It is not a penetration test by a person. It checks known classes of problem.
  It will not find a flaw in your business logic, such as a coupon that can be
  applied twice.
- It does not fix IDOR or auth design for you. It points at the route. The fix
  is yours.
- It does not watch production yet. Scheduled checks are on the
  [roadmap](https://github.com/danoszz/penthera/blob/main/ROADMAP.md).
- A clean scan is not proof of safety. Every finding has a confidence label, and
  probes that could not run are listed as inconclusive rather than passed.
- Its accuracy is measured only on labs we wrote ourselves: precision 0.92
  (95% CI 0.74 to 0.98) and recall 0.96 (95% CI 0.79 to 0.99) on 24 findings
  ([results](https://github.com/danoszz/penthera/blob/main/bench/RESULTS.md)). Accuracy on real apps is not measured
  yet. That is [experiment E1](https://github.com/danoszz/penthera/blob/main/docs/research/prereg/E1-real-world-accuracy.md).

## What it never does

- Commit, push, open a pull request, or touch a remote. The workflow file is
  written for you to review and commit yourself.
- Write outside the project: reports, `.gitignore` and the workflow go under
  the project root (the git top level when there is one), the hook into the
  repository's hooks folder.
- Contact anything but localhost, unless you turn offline mode off or confirm
  the running app.

Exit code: 0 when the wizard finishes (whatever the grades), 2 for a bad flag.
For a gate in CI, use the commands themselves (`penthera --repo .`, `penthera deps`):
they exit 1 on high or critical findings.

`PENTHERA_NO_ONBOARDING=1` stops a bare `penthera` from opening the wizard, and
`PENTHERA_INIT_PORTS` replaces the dev ports it probes (a comma list, or empty
for none).

The pinned SHA is the last release tagged before this version
(`ACTION_PIN` in `src/cli/onboarding.js`); Dependabot's `github-actions`
updates keep it current in your repo.

Known limit: `init` pins v2.1.2, the release before this one, and that version's
`deps` can stall on big bundles under Node 22. If a workflow run hangs there, move
the pin in your workflow to v2.2.0. `init` picks that up with the next release.

Known issue: in every release from 1.5.0 to 2.0.0, the action's `mode: deps`
exits before it scans, and the job still reports success, with no comment and
no SARIF. 2.1.0-rc.1 has the fix, and `init` writes a pin to a release that has it. A workflow
written by an older `init` needs its pin moved to 2.1.0-rc.1 or later.
