---
title: "The local loop"
sidebarTitle: "Local loop"
description: "Since v1.4, Penthera has a loop that runs entirely on your machine: scan, fix on a local branch, verify, record the outcome, repeat."
---

> **Pro.** For "how do I run the fix loop, and what does it remember?"

Since v1.4, Penthera has a loop that runs entirely on your machine: scan, fix on
a local branch, verify, record the outcome, repeat. Nothing in it talks to a
Penthera server, because there isn't one. This page covers the loop itself
(`penthera agent --loop`) and the local learning store it records into. The
store counts which fix recipes worked for which framework. It re-orders and
suppresses findings. It does not train a model.

## The agent loop

```bash
penthera agent --loop --repo . --url http://localhost:3000 -o reports/loop.json
penthera agent --loop --repo . --run-tests          # also run the project's test script
penthera agent --loop --repo . --auto low           # auto-apply only recipes memory has proven
```

One iteration:

1. **Scan** the repo (white-box scan plus the fix recipes' static probes) and,
   with `--url`, the running app.
2. **Triage**: drop findings suppressed in memory or `penthera.suppress.json`,
   and rank the rest with memory (severity always first).
3. **Plan**: a deterministic recipe first. The local model is asked only with
   `--fix-model <name>`, and only for findings no recipe matches.
4. **Patch** on a local branch `penthera/fix-<yyyymmdd-hhmm>`, created from the
   current HEAD when the run starts.
5. **Verify**: re-scan. A fix passes when the findings it targeted are gone from
   the repo scan, no new finding appeared, and, with `--run-tests`, the
   project's `test` script exits 0 (`node --run test`).
   Verification uses the checker the run began with: no fix may edit tests,
   test config or Penthera's own files (see [the protected files](#what-it-guarantees)),
   and if any of them changed since the run began, the fix fails without the
   tests being run.
6. **Learn**: `scan`, `fix_applied` and `fix_verified` or `fix_failed` go to
   memory, and `gave_up` when the loop could not fix a finding.
7. **Commit** each verified fix on its own, with a message that lists the
   findings, the recipe, and how it was verified. A fix that fails is reverted:
   each file gets back the bytes it had before the fix, and files it created
   are removed. A file that changed again after the fix was written (you saved
   it meanwhile) is left alone and the fix is marked `conflict`. The commit
   contains only the fix's own files (`git commit --only`).

Plans are applied one at a time and re-planned against the tree after each
fix, since two recipes can touch the same file. The loop repeats until nothing
fixable is left, `--max-iterations` (default 5) is reached, or you stop it.
A fix you decline (`n`) is not proposed again in the same run; `s` skips it
until the next iteration.

**The safe exit.** "Could not fix" is a normal outcome, not something to work
around. When a fix fails verification, its diff is refused, or the local model
has no usable fix, the loop gives up on those findings for the rest of the run
and does not try them again. Each give-up is a `gave_up` event in memory with
the reason, is listed in `loopRun.gaveUp`, and is printed in the summary
(`gave up on N (not retried this run; fix by hand): title (reason); ...`).
A give-up never counts as a recipe failure, so neither the ranking nor
`--auto low` can learn to avoid it.

A live URL serves the code it was started with, so a fix to response headers
shows up in the URL scan only after the app restarts. The loop counts those as
`liveRemaining` in the fix's `verify` block, not as a failure; the repo scan
decides whether the fix landed.

### What it guarantees

Each of these has a test in `tests/agent.test.js`.

- **No remote operations.** All git goes through `src/agent/git.js`, an
  allow-list of local subcommands (`rev-parse`, `symbolic-ref`, `status`,
  `diff`, `log`, `show-ref`, `checkout`, `add`, `commit`, `config --get`).
  `push`, `fetch`, `pull`, `remote`, `clone`, `ls-remote`, `submodule` and
  everything else are refused before a process starts, as are URL arguments
  and `-c` overrides. Every call also runs with `protocol.allow=never` and
  `GIT_NO_LAZY_FETCH=1`, so no transport can work. The loop never runs `gh`
  and never opens a pull request.
- **The repo's hooks never run.** Git runs with `core.hooksPath=/dev/null`,
  `core.fsmonitor=false` and `commit --no-verify`, because a scanned repo can ship
  hooks that run anything.
- **Network.** The whole run shares one egress context with `--offline` always
  on, so the URL target is the only host. Loopback is added only when
  `--fix-model` is set, and the model client then accepts only
  `http://127.0.0.1:11434`.
- **Clean start.** A dirty tree (untracked files included), a detached HEAD, a
  repo without commits, or a directory that is not a git repo is refused.
  `--allow-dirty` lets the loop start anyway, but it never patches a file that
  has uncommitted changes; this is checked again right before each write and
  each commit. Plans that touch untracked or git-ignored files are skipped.
- **Git.** The loop's git calls ignore hooks, fsmonitor, signing, and any
  filter the repository configures, and treat paths literally. Writes are
  refused when the repository's own config sets `filter.*`, `gpg.*` or
  `include.*` keys, and on git older than 2.31: the loop stops before its first
  write with one message naming the key and the way forward (move it to your
  global config, or apply fixes by hand from `penthera fix --plan`).
- **The checker stays as it was.** A fix diff, from a recipe or the model, may
  not touch tests (`test/`, `tests/`, `__tests__/`, `*.test.*`, `*.spec.*`,
  `conftest.py`), test runner config or the test script (`vitest.*`,
  `jest.*`, `playwright.*`, `pytest.ini`, `pyproject.toml`, `setup.cfg`,
  `tox.ini`, `package.json`), Penthera's own files (`penthera.*`,
  `audit/baseline.json`, `.penthera/`), `.github/workflows/`, git hooks
  (`.husky/`, `.githooks/`, lefthook, pre-commit), lockfiles or `.gitmodules`,
  in any case. `applyDiff` refuses it with `PROTECTED` and the finding is given
  up. Before the tests run and again before the verdict, the loop checks that
  every protected file is as it was when the run began; if not, the fix fails.
  A real fix that needs a test change is yours to make by hand.
- **Approval.** Every diff is shown, secrets masked, with
  `[y]es / [n]o / [s]kip / [q]uit`. When input runs out (piped stdin), the
  answer is `n`. `--auto low` applies a diff without asking only when it comes
  from a recipe (not the model), its confidence is not `needs-human-review`,
  memory's chain verifies, and memory shows that recipe with at least 3
  verified fixes and no failures for this framework.
- **Interruption.** The first Ctrl-C lets the fix in flight finish: it is
  verified and committed, or reverted. The loop then stops on the fix branch,
  which holds only verified commits. A second Ctrl-C reverts the fix in flight
  at once and exits.

`--run-tests` runs the project's own code, so it can do anything that code
does, including network calls. It is off by default for that reason.

### The loopRun object

`-o <file>` writes `{ "loopRun": { ... } }`. The fix timeline in the audience
reports ([evidence.md](evidence.md#audience-reports)) renders it.
Every step carries `startedAt` and `durationMs`.

```js
{
  schema: "penthera.loopRun/1",
  id, startedAt, finishedAt, durationMs,
  target: { repo, url },
  branch: { base, baseSha, fix },            // base is null on a detached HEAD
  options: { maxIterations, auto: "off" | "low", runTests, fixModel, offline: true, allowDirty },
  stopReason: "no-fixable-findings" | "declined-or-failed-left" | "max-iterations"
            | "user-quit" | "interrupted" | "error",
  error,                                     // message when stopReason is "error"
  gaveUp: [{ fid, title, reason }],          // findings the loop could not fix; not retried this run
  findings: { initial, final },              // non-info, unsuppressed
  totals: { iterations, planned, applied, verified, failed, declined, skipped, commits: [sha] },
  memory: { projectId, chain: "ok" | "broken", eventsAppended },
  iterations: [{
    n, startedAt, durationMs,
    findings: { total, suppressed, fixable },
    steps: [{ step: "scan" | "triage" | "plan", startedAt, durationMs }],
    fixes: [{
      planId, recipe, title, framework, source: "recipe" | "local-model", confidence,
      files, findings: [{ fid, title, severity, category }],
      memory: { verified, failed } | null,   // recipe history when the plan was ranked
      decision: "approved" | "auto" | "declined" | "skipped" | "quit" | "obsolete",
      status: "verified" | "failed" | "not-applied",
      reason, commit,
      verify: { targetedRemaining, newFindings, liveRemaining, tests: { ok, exitCode, durationMs } | null } | null,
      testOutput,                            // tail of the test output, only when tests failed
      steps: [{ step: "approve" | "patch" | "learn" | "verify" | "commit" | "revert", startedAt, durationMs }],
    }],
  }],
}
```

`obsolete` means an earlier fix in the same iteration already covered the plan.
The same object, without `testOutput` and with finding ids in place of finding
objects, is appended to memory as a `loop_run` event.

Exit codes: `0` nothing fixable left, `1` fixable findings remain (declined,
failed, or out of iterations) or the loop stopped on an error, `2` the loop could not start (dirty tree,
detached HEAD, bad options), `130` interrupted.

## The learning store

Scans run with `--memory` record what happened, and the next scan uses that
record to rank and suppress findings.

```bash
penthera --repo . --memory            # scan, apply memory, record this scan
penthera memory show                  # what memory knows about this project
penthera memory verify                # check the hash chain
penthera memory suppress <id> --reason "set by the CDN" [--expires 2027-01-01]
penthera memory forget                # delete this project's memory
penthera memory forget --all          # delete all memory
```

`<id>` is the 16-character `fid` shown next to each finding in a `--memory`
report.

### Where it lives

```
~/.penthera/memory/<project-id>/events.jsonl   the event log
~/.penthera/memory/<project-id>/head.json      count and hash of the last event
~/.penthera/memory/<project-id>/meta.json      the project's path or origin, for `memory show`
```

`<project-id>` is a SHA-256 of the repo's absolute path plus its git remote URL,
or of the target origin for URL-only scans. Set `PENTHERA_HOME` to move the
root (the tests do). Penthera reads the remote from `.git/config` itself rather
than running `git`, because running git inside an untrusted repo can execute
that repo's hooks or `core.fsmonitor` command.

### What it records

One JSON event per line, append-only:

```json
{ "v": 1, "ts": "...", "type": "scan", "data": { ... }, "prev": "<hash of previous line>", "hash": "..." }
```

`hash = sha256(prev + canonical JSON of { v, ts, type, data })`, with object
keys sorted. The first line's `prev` is derived from the project id.

| Type | Data |
| --- | --- |
| `scan` | stack, modes, counts by severity, ids of the actionable findings |
| `probe_yield` | probe id, stack, findings count |
| `fix_applied` | finding id, recipe id, framework, category, diff SHA-256 |
| `fix_verified` / `fix_failed` | finding id (recipe and framework are joined from `fix_applied`) |
| `gave_up` | finding id, reason, source, loop run id. Never counted in recipe success |
| `fp_suppressed` | finding id, reason, actor, optional expiry |
| `loop_run` | one `penthera agent --loop` run: the [loopRun](#the-looprun-object) without test output, finding ids only |

From these, `penthera memory show` derives four views: recipe success rate per
framework, active suppressions, probe ranking by yield per stack, and median
time to fix (first seen in a scan to `fix_verified`).

### How a scan uses it

Memory can do two things to a report, and nothing else:

1. **Suppress** a finding the user (or the loop, on the user's behalf) marked as
   a false positive, with a reason. Suppressed findings move to a separate
   "Suppressed" section in the terminal and Markdown reports, each with who
   suppressed it and why. They do not count toward the exit code.
2. **Re-order** findings within a severity: categories with a fix recipe that
   has worked on this framework come first, then findings that have shown up in
   more past scans. Severity is never changed and no finding is dropped.

## Threat model

The learning store is an attack surface. An agent loop that learns from its own
past is open to memory poisoning (OWASP Agentic Security Initiative, ASI06): if
an attacker can write to what the loop remembers, they can steer what it does
next. In Penthera's case the two goals would be hiding a real finding and
getting the loop to run something. The store is built so that neither can
happen unnoticed.

### Why it never executes

Memory is data. No value read from it is ever executed, evaluated, imported,
used as a file path, or passed to a shell. A recipe id in memory is only a
string that gets counted. The recipe code lives in Penthera's own source
(`lib/fix/`) and is chosen by Penthera, not by the log. Every field a view reads
is type- and length-checked, and an event that fails a check is ignored rather
than interpreted. Strings shown in the terminal have control characters stripped,
so a stored reason cannot inject ANSI escape sequences.

The worst a fully poisoned memory can do is hide findings, and hidden findings
are listed, with their reason, in every report.

### Why it is hash-chained

The chain makes tampering visible. Editing a line, reordering lines, deleting a
line from the start or middle, or splicing in another project's log all break
the chain, and `penthera memory verify` names the first broken line. `head.json`
records the count and hash of the last event, so cutting lines off the end is
caught too.

When the chain is broken, scans **fail closed**: memory suppressions and
ranking are not applied, nothing new is appended, and the scan prints a warning
telling you to run `penthera memory verify`. You can then inspect the log or
start over with `penthera memory forget`.

The limit: the chain is tamper-evident, not tamper-proof. Anyone who
can write to your home directory can rewrite the whole log and recompute every
hash. Keying the chain would not help, since the key would sit in the same home
directory. The chain is there to catch a partial edit, an accidental truncation,
or a tool that writes where it should not. It is not a defense against malware
already running as you.

### Why it lives in your home directory

Memory is never read from the scanned repo. If it were, a repo could ship
pre-poisoned memory, for example a suppression for the secret it is about to
leak. Keeping memory under `~/.penthera` means only runs on your machine, as
you, write to it.

### The one thing a repo can say: `penthera.suppress.json`

Teams do need to share decisions like "this key is a revoked test fixture". For
that a repo may contain `penthera.suppress.json`:

```json
{
  "version": 1,
  "suppress": [
    { "id": "16e06eb3fd94664b", "reason": "test fixture, revoked", "expires": "2027-01-01" }
  ]
}
```

It is held to a stricter standard than memory:

- Every entry needs a reason. Entries without one, with a malformed id or date,
  or past their expiry are dropped with a warning.
- Every finding it hides is listed in the report as **suppressed by repo file**
  with the reason, so a reviewer sees both the file change in the PR and its
  effect in the report.
- It only applies with `--memory`, and a local suppression for the same finding
  takes precedence.

Treat a change to `penthera.suppress.json` in a pull request like a change to
CI config: it decides what the scanner reports.

### Concurrency

Two scans of the same project can run at once. Each append takes an exclusive
lock file (`events.lock`, created with `O_EXCL`), reads the tip, and writes one
line with a single `O_APPEND` write. Lines never interleave and the chain never
forks. A lock older than 30 seconds is treated as stale and removed.
