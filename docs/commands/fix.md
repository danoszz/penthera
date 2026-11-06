---
title: "Fixing what it finds: penthera fix and penthera agent --loop"
sidebarTitle: "Fix"
description: "Ask your agent to fix what Penthera finds."
---

> **Pro.** For "how do I run the fix loop?"

## Scan and fix

Plans show changed lines only, with `… N lines unchanged` in place of the rest, so
a secret beside a change is never printed. Open the file for context. Changed lines
mask what Penthera can recognise, in text and `--json`: key blocks, known token
shapes, URL passwords, `?key=` values, and values next to a word like "password".
A secret in another shape on a changed line can still show. `redacted: true` means
a changed line was masked. The diff that gets applied is the real one. The dashboard's
approval window also shows the unchanged lines around a fix, with the same masks, on
your local screen only.

A repo scan ends with `N may be fixable: penthera fix --plan --repo <path>`. The
count is the scan's findings a recipe could take. `penthera fix` also checks cookie
flags, CORS and rate limits in your code, which do not change a scan's findings or
exit code.

`penthera fix` exits 2 when its run is incomplete: the repo scan, a report given
with `-o`, or the cookie check left a file unread or not fully checked. It names
those files, and `--json` lists them under `incomplete`. The plans it shows may
then miss a fix.

Ask your agent to fix what Penthera finds. It detects the issue, applies a framework-aware fix to your code (shown as a diff for you to approve), and re-scans to prove it is resolved.

```
"Scan my app and fix what you find"
"Fix the security headers on my Next.js app and re-scan to confirm"
"Find and fix hardcoded secrets in this repo"
```

Fixes come from a [remediation playbook](https://github.com/danoszz/penthera/blob/main/skills/penthera/references/remediation.md) covering Next.js, Express, Fastify, Hono, and FastAPI. They are always shown as diffs for your approval and verified by a re-scan, and nothing touches production. To build secure-by-default in the first place, see [secure defaults](https://github.com/danoszz/penthera/blob/main/skills/penthera/references/secure-defaults.md).

### Fix recipes

For the most common findings you don't need an agent at all. `penthera fix` plans deterministic, local fixes and prints each one as a unified diff:

```bash
penthera fix --plan --repo .                  # fresh repo scan, one diff per fix
penthera fix --plan --repo . -o report.json   # or use the findings from an earlier scan (-o, --input)
penthera fix --apply <id> --repo .            # apply one diff after you approve it
```

| Recipe | What it changes | Frameworks |
|--------|-----------------|------------|
| `security-headers` | Adds a starter CSP (with `frame-ancestors`), HSTS, X-Frame-Options, Referrer-Policy and X-Content-Type-Options | Next.js (`headers()` in `next.config.*`), Express (`helmet` if installed, otherwise a small middleware), Fastify (`@fastify/helmet` if installed, otherwise an `onSend` hook), Hono (`secureHeaders`) |
| `cookie-flags` | Adds `httpOnly`, `secure` and `sameSite` to cookies set in code | `res.cookie`, `reply.setCookie`, Hono `setCookie`, Next.js `cookies().set` |
| `cors-allowlist` | Replaces `cors()`, `origin: "*"`, `origin: true` and `origin \|\| "*"` with an allowlist from `CORS_ALLOWED_ORIGINS` | Express, Fastify, Hono, Next.js route handlers |
| `auth-rate-limit` | Puts a rate-limit stub (in memory, 10 attempts per 15 minutes) on login and auth routes | Express (`express-rate-limit` if installed), Fastify, Hono, Next.js App Router |
| `secret-to-env` | Moves a hardcoded secret in JS/TS to `process.env.NAME` and adds `NAME=` to `.env.example` | Any |

How it stays safe:

- **Planning never writes.** Applying is a separate step: it needs a plan id plus a `y/N` confirmation (or `--yes`), refuses a dirty git tree unless you pass `--allow-dirty`, refuses any path outside the repo, and writes nothing unless every hunk applies. It never commits or pushes.
- **A fix never edits its own checker.** A diff from a recipe or a local model may not touch tests (`test/`, `tests/`, `__tests__/`, `*.test.*`, `*.spec.*`, `conftest.py`), test runner config or the test script (`vitest.*`, `jest.*`, `playwright.*`, `pytest.ini`, `pyproject.toml`, `setup.cfg`, `tox.ini`, `package.json`), Penthera's own files (`penthera.*` such as the policy, suppressions and lock, `audit/baseline.json`, `.penthera/`), `.github/workflows/`, git hooks (`.husky/`, `.githooks/`, lefthook, pre-commit), lockfiles or `.gitmodules`. Such a diff is refused with `PROTECTED` before anything is written, and `fix` prints it as refused. If the real fix needs one of those files changed, make that change by hand.
- **Conservative edits.** No AST rewriting: each recipe edits at an anchor it recognizes exactly (`const app = express()`, the exported Next.js config object, a one-line `res.cookie(...)`). If the anchor isn't there, or the code already does something custom (an existing `headers()`, cookie options in a variable), the recipe returns no plan instead of a risky diff.
- **Owner actions are listed, not done.** A recipe can move a secret out of the code but can never rotate it, so every secret fix says "rotate this secret". Other recipes flag what is still on you, such as tightening the starter CSP or setting `CORS_ALLOWED_ORIGINS`.
- **The flagged secret stays masked.** Its value is masked in printed and `--json` plans.
- **Verified.** After `--apply`, Penthera re-scans the repo and says whether each finding is gone. Headers, cookies, CORS and rate limits are checked statically from source, so re-run your URL scan to confirm against the live app.

No recipe for a finding? `--fix-model <name>` can ask a model running in [Ollama](https://ollama.com) on `127.0.0.1:11434`, and nowhere else. It is off by default and only used when no recipe matches. Its diffs are labeled `needs-human-review`.

### The local loop: `penthera agent --loop`

`penthera agent --loop` runs scan → fix → verify → learn on your machine until nothing fixable is left (or `--max-iterations`, default 5):

```bash
penthera agent --loop --repo . --url http://localhost:3000 -o reports/loop.json
```

It shows each diff and asks `y/n/skip/quit`, applies it on a local branch `penthera/fix-<yyyymmdd-hhmm>`, re-scans (plus your tests with `--run-tests`), commits the fix if it verified and reverts it if not, and records the outcome in [local memory](../local-loop.md). It refuses a dirty tree or a detached HEAD, runs only an allow-list of local git commands with your repo's hooks disabled, contacts only the `--url` host, and never pushes or opens a pull request. If your repo's own `.git/config` sets `gpg.*`, `filter.*` or `include.*` (or git is older than 2.31), the loop does not start and names the key: move it to your global config, or apply fixes by hand from `penthera fix --plan`. `--auto low` applies without asking only recipes that memory shows verified 3+ times with no failures on your framework. The checker stays as it was: fixes may not touch the protected files above, and a fix is not verified if any of them changed during the run. When the loop cannot fix a finding (verification failed, the diff was refused, or the model had no usable fix), it gives up on it for the rest of the run, records `gave_up` with the reason, and lists it in the summary. A give-up never counts against a recipe. Details and the `loopRun` JSON: [docs/local-loop.md](../local-loop.md#the-agent-loop).

[Back to the README](https://github.com/danoszz/penthera/blob/main/README.md) · [All commands](https://github.com/danoszz/penthera/blob/main/docs/commands/README.md)
