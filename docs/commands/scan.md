---
title: "Scanning your app: penthera <url> and --repo"
sidebarTitle: "Scan"
description: "Black-box scans of a running app (localhost, preview, or staging) and white-box scans of its source."
---

> **Starter.** For "is my app safe to ship?"

Black-box scans of a running app (localhost, preview, or staging) and white-box scans of its source. The default scan is non-destructive. Payload-based testing is opt-in.

## Scan modes and profiles

| Mode | Command | Coverage |
|------|---------|----------|
| **URL scan** | `penthera https://example.com` | TLS, fingerprinting, endpoint discovery, templates, CORS, cookies, JS CVEs, param discovery, OpenAPI/FastAPI probes, security headers, auth hardening |
| **Repo scan** | `penthera --repo ./my-app` | API route discovery (Next.js, Express, Hono, Fastify), trust-boundary mapping, hardcoded-secret scanning (including Anthropic, OpenAI, Gemini, Groq, Hugging Face and other AI provider keys), and your GitHub Actions workflows ([below](#github-actions-workflows)) |
| **Combined** | `penthera https://staging.app --repo .` | Black-box and white-box in one run |
| **Interactive** | `penthera` *(no args)* | Setup wizard: detects the project, runs the offline checks, offers the hook and workflow ([init.md](init.md)) |
| **Machine audit** | `penthera --machine` | macOS checks (keyloggers, persistence, rootkits) |
| **Dependencies** | `penthera deps` | What each npm or Python package can do (install scripts, shell, network, env, eval, native, obfuscation, `.pth` startup hooks), capability diff on upgrades, typosquats. Offline ([deps.md](deps.md)) |

Pick a profile, or add individual flags for more depth:

| Profile | Command | What runs |
|---------|---------|-----------|
| **quick** | `--profile quick` | Headers, OpenAPI, auth checks; no login POSTs (about 10s, about 180 requests) |
| **standard** | *(default)* | Full non-destructive scan: no attack payloads, and one `POST /api/login` with invalid credentials |
| **deep** | `--profile deep` | recon, injection probes, API fuzzing, and on `/api/login` an 8-attempt rate-limit burst and an SQL error check |

What each profile sends to `/api/login`: `quick` nothing; `standard` one
login with obviously invalid credentials, to catch a login that accepts
anything; `--deep` also 8 rapid attempts (rate limiting) and an
`' OR '1'='1` string (SQL errors). A CDN firewall can read the last two as an
attack and start challenging you, so they only run with `--deep`.

How many requests `quick` sends: 182 against the test server in
`tests/fixtures/mock-server.js`. Most of them are a fixed list of probe paths,
178 against a server that answers 404 to everything. Each path in the site's
OpenAPI spec adds more: a spec with 60 paths took 275. Scripts and links on the
home page add none. A `standard` scan sent 197 to the same test server.

Individual flags: `--recon`, `--deep`, `--fuzz`, `--adaptive`, `--nuclei <path>`, `--templates <dirs>`, `--all`

### Active modes ask first

`--deep`, `--fuzz`, `--adaptive`, `--all` and `--profile deep` send test
payloads (and, with `--deep`, the login burst above), so they need your
confirmation before the first request:

- In a terminal, Penthera asks. For a target on this machine (`localhost`,
  `*.localhost`, `127.x.x.x`, `[::1]`) a yes is enough; for any other target, type its
  hostname back.
- In CI, Docker or a script, pass `--confirm-target <host>` with the target's
  hostname. Without it, or with a different host, the run stops with exit
  code 2 before anything is sent.
- Active scans send at most 10 requests per second. Change that with
  `--rate <n>`; `--rate 0` removes the limit. `--rate` also works on a
  standard scan, which has no limit by default.

```bash
penthera https://staging.myapp.com --profile deep --confirm-target staging.myapp.com
penthera http://localhost:3000 --deep --rate 25
```

### What active modes can change

Active modes send real requests to real routes. Run them on a local or staging
copy with data you can lose, and never on production. A safe-looking target can
still store what these requests send.

| Mode | What it sends | What that can change |
|------|---------------|----------------------|
| `--fuzz` | `POST` bodies to up to 5 API routes: long strings, wrong types, and injection strings, including `'; DROP TABLE users; --` | Creates records and can trigger emails or webhooks. A route with SQL injection could run that string and lose the table |
| `--deep` | SQL, template and command injection strings, including `sleep 3` and `id`, on up to 10 API routes. `POST` bodies for the cross-site scripting (XSS) check. URLs for your server to fetch, such as cloud metadata and `localhost`. 8 failed logins on `/api/login` | A route with command injection runs those commands. Stored fields can keep the XSS strings, so they may run in a browser later. Sleep strings tie up database or server workers. The login burst can trip a block on the IP you scan from |
| `--adaptive` | `DELETE`, `PUT`, `PATCH`, `POST` and `GET` to up to 15 routes, each method the route doesn't declare. `POST` bodies with `__proto__`. Guesses at cron secrets | An unprotected route can delete or overwrite data. A route that really runs a job can run it. A vulnerable Node.js process can stay polluted until it restarts |
| `--all`, `--profile deep` | Both turn on `--deep`, `--fuzz` and recon. Neither turns on `--adaptive` | As for `--deep` and `--fuzz` |

Any of these can also fill logs, raise alerts, trigger a firewall block or use
up paid API quota.

Active requests don't use `--auth-bearer` or `--auth-cookie`, so they test what
a stranger can reach. Penthera sends placeholders such as `Bearer test-token`.
They don't clean up after themselves: Penthera can't undo what a route stored.

## Quick start

```bash
# First time? Run with no args for guided setup
penthera

# Safe default scan (non-destructive)
penthera https://myapp.com

# Staging plus source code, full report set
penthera https://staging.myapp.com --repo . --all -o reports/scan.json --sarif reports/scan.sarif

# Baseline diff: counts of new, resolved and unchanged findings (add -q to keep only the new ones)
penthera https://myapp.com -o reports/scan.json --baseline reports/previous.json

# Authenticated scan (session cookie or bearer token)
PENTHERA_BEARER=eyJ... penthera https://myapp.com --profile standard
penthera https://myapp.com --auth-cookie "session=abc123"
```

Writing to `-o reports/scan.json` also drops a human-readable `reports/scan.md`
next to it. `penthera init` can add `reports/` to your `.gitignore`.

### What `--baseline` counts as new

A finding is new when the baseline report has no finding with the same
identity (source, category, file or URL, and title). Since 2.3.2 it is also new when:

- its severity is above the baseline's for that identity, so a low that became
  critical fails `--baseline -q`;
- it is a secret, and it now holds more lines than in the baseline, or holds a
  value the baseline didn't (a second key of one rule in one file, or one key
  swapped for another). A `--repo` report keeps a short salted hash of each
  fixed-format secret value, such as a provider key or a private key
  (`valueTags`, with the salt in `secretTagSalt`), never the value, and
  `--baseline` reuses the baseline's salt to compare them. Passwords and other
  `name = value` secrets get no hash, because a person may have chosen the
  value and the salt is in the report. Neither does a key-shaped value inside a
  longer word, a `name = value` match or a URL's `user:password@`, nor the
  legacy `sk-` OpenAI shape. Those, and a baseline without tags,
  compare the count and the first masked value, as before;
- it is an eval or exec sink, and it lists a call the baseline didn't. Line
  numbers are left out, so an edit above the call changes nothing.

A sink finding lists at most 5 calls, so a sixth call in the same file is not
seen as new. 2.3.2 also changed how short values are masked, so a baseline
written by an earlier version can show its secrets as new once. Write a fresh
baseline after the upgrade.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No critical or high rule fired. This run does not prove login, access rules or payments are right |
| `1` | Critical or high findings detected (other tools' too, with `--giants`) |
| `2` | Scan failed or is incomplete (unreachable target, missing path, bad config, a tool the policy requires did not run, a dependency input `penthera deps` refused to read) |

A firewall that refuses the scan isn't a failed scan. The verdict is `Site not read`,
with no grade, and the exit code follows the findings Penthera could still make, such
as SPF and DMARC from DNS. So a refused scan can exit 0, and that doesn't mean the site
is fine. A server's own 5xx exits 2.

Hints print the command the way you ran it, so a run through npx suggests `npx penthera`.

Two findings changed in 2.2. A Content-Security-Policy that names no script sources, or
lets any host run them with `*`, `http:` or `https:`, gets "Content-Security-Policy does
not control scripts" ([how to fix it](https://penthera.org/csp-that-controls-scripts)).
A pattern that matches a whole file, such as `exec`, is one finding that lists the routes,
not one per route.

Every finding has an id, `fid` in `-o` JSON, beside the title in the terminal report and
in the Id column of the Markdown report's findings tables.
The brief doesn't print it. Use it with `penthera memory suppress <fid> --reason "..." --severity <level>`.
A suppression covers the finding up to that severity, and medium when you give
none. If the finding escalates past it, it shows again.

---

## Output

Every scan says what it reached. It names any check that did not run, and a live
scan says whether it sent injection probes. With `--repo`, `--deep` counts your
routes, for example `--deep reached 3 of 13 routes in your code.`

| Format | Flag | Use |
|--------|------|-----|
| Terminal | *(default)* | A `--repo` scan opens with one screen: what was checked, the top three to act on with a fix each, what wasn't checked and one next step. Findings and coverage follow. No colors when stdout is not a terminal or `NO_COLOR` is set; `FORCE_COLOR=1` keeps them in a pipe, `FORCE_COLOR=0` turns them off in a terminal |
| **Agent brief** | `--brief`, or the default when stdout is not a terminal and not CI | Verdict, act on, check first, likely noise, not checked, next: short, for an AI assistant ([brief.md](brief.md)) |
| **Markdown** | `--markdown file.md` or `-o file.json` | Human-readable report (exec summary, findings tables, fixes). Written next to `-o` automatically |
| JSON | `--json` or `-o file.json` | CI pipelines, baseline diffs, custom tooling |
| SARIF | `--sarif file.sarif` | GitHub Security / Code Scanning tab |
| AI-audit seeds | `--audit-seeds seeds.json` (with `--repo`) | Repo findings in Cloudflare security-audit-skill `findings.json` form, so an agent running the skill starts from them ([verify.md](verify.md#the-other-way-seeds-for-the-skill)) |
| Audience report | `--audience developer\|owner\|auditor\|agent` | The same scan written for a developer, an owner, an auditor or an AI assistant ([docs/evidence.md](../evidence.md#audience-reports), [brief.md](brief.md)) |
| Your template | `--report-template file.md` | Your own Markdown with `{{summary.critical}}`, `{{#each findings}}`, `{{#if x}}`; no code runs |
| **Evidence bundle** | `--evidence <dir> [--sign-key <ssh-key>]` | All reports plus `manifest.json` with SHA-256s, optionally SSH-signed. Auditors check it with `penthera evidence verify <dir> --allowed-signers <file>` ([docs/evidence.md](../evidence.md)) |

### GitHub Actions workflows

A `--repo` scan reads the workflows GitHub runs, in `.github/workflows/`. It parses each one as YAML and runs nothing. Three rules come from GitHub's own guidance on securing workflows, and a fourth reports a workflow it can't read:

| Rule | Severity | What it means |
|------|----------|---------------|
| `gha-pwn-request` | high | A `pull_request_target`, `workflow_run`, `issue_comment` or `issues` workflow checks out the pull request's code (its head, merge commit or fork), or fetches it in a script (`gh pr checkout`, `refs/pull/`). That code then runs with your repository's token and secrets. Medium when an `if:` that every path must pass limits it to pull requests from your own repository. |
| `gha-script-injection` | high | Text an outsider writes (a PR title, an issue body, a branch name) goes into a `run:` script or an `actions/github-script` `script:` through `${{ }}`, where it becomes code. Pass it through `env:` instead. |
| `gha-unpinned-action` | medium (low for `actions/*`, `github/*`) | An action or reusable workflow is used by a tag or branch its owner can move. Pin the full commit SHA. |
| `gha-workflow-unchecked` | high | A workflow is over 256 KB, or isn't valid YAML (duplicate keys included). Penthera reports it instead of passing it unread. |

Each finding points to the file and line. `explain_finding` knows all four ids. Every spelling YAML allows means the same thing here: quoted keys, escapes, block scalars, flow style, anchors. Expressions are compared without case, with `['x']` read as `.x`.

**Limits.** It doesn't follow reusable workflows or composite actions into their own files, and it doesn't trace a value through `env:` or a step output into a script. A clean result means none of these patterns was found in what it read. It doesn't prove the workflow is safe.

### Coverage: what a repo scan read

Every `--repo` scan adds a **Coverage** section to the terminal, Markdown and
JSON (`coverage`) reports. For each check (the secret scan, route and
code-pattern analysis, runtime versions) it says how many files were read and
why the others were not: file type not read, over the size limit, a language
route analysis does not support, or no server routes found (a client-only app
has none). Route analysis reads Next.js route handlers anywhere under `app/` or
`src/app/` and a Worker's `export default { fetch }` entry, besides Express,
Hono and Fastify routes. How many routes it found is part of Coverage, not a
finding. Source files no code
analysis read are listed as blind spots, up to 200. A file that was not read
is unchecked, not clean. Dependency behaviour and agent config have their own
commands (`penthera deps`, `penthera agents`) and are listed as not part of a
repo scan.

### Library mode: scanning a package

In an app, untrusted data arrives in a request. In a library it arrives as an
argument: whoever calls an exported function decides what its parameters
hold. In library mode the repo scan treats those parameters as untrusted too.

```bash
penthera --repo ./my-package --library      # always scan as a library
penthera --repo ./my-package --no-library   # always scan as an app
```

Without either flag, library mode turns on by itself when `package.json` looks
publishable: it has `main`, `exports` or `bin` (or an `index.js` next to it),
is not `"private": true`, and does not depend on an app framework such as
Express, Koa, Fastify or Next.js. The report says when it is on, and why.

How it works. Penthera finds the functions a caller can reach
(`module.exports`, `exports.x`, prototype and class methods of an exported
constructor, objects and instances returned by an exported factory, members
copied onto `exports` in a loop, ESM `export`). It
follows each parameter through assignments, closures and callbacks inside that
function, and one call further: when the function passes the value to a named
function in the same file, that function's parameter is followed too. A value
a constructor or setter keeps on `this` (`this.path = path`) is followed into
the other methods of the same class or prototype. A shell command built from one is reported as `command-injection`
at `potential` confidence and severity high. A function whose whole job is to
run its argument (`exec(cmd)`) is reported at severity medium, with the note
that callers must not pass untrusted input. In library mode the scan also
reads `dist/` or `build/` when `package.json` points there, and skips tooling,
examples and docs folders.

How we know. On the dev half of SecBench.js (49 command injections in npm
packages, the half we tuned on), strict recall went from 0.00 to 0.82, 95% CI
0.69 to 0.90 (40 of 49), in the first version. The helper step and fields on
`this` took it to 0.94, 95% CI 0.83 to 0.98 (46 of 49); 39 of 49 without the
"runs its argument" cases. It flagged no command injection in 150 npm packages
of the benign baseline (dev half), and nothing new in 16 app repositories. The
sealed test half was scored once ([results](https://github.com/danoszz/penthera/blob/main/bench/public/RESULTS.md)).

Limits. Only one helper call is followed, and only to a function the file
calls by name. A field set from another field is not followed. Sanitizers are not recognized, so a
correctly escaped command can still be reported; that is what `potential`
means.

## CI integration

```yaml
# Scan a staging URL on a schedule and upload results to GitHub Security.
- run: npx penthera@2.3.1 "$PENTEST_URL" --profile standard --sarif reports/scan.sarif
- uses: github/codeql-action/upload-sarif@6f2ac81f5cd81fe351a197ba0b00d91d03cd2aee # v4.39.0
  with:
    sarif_file: reports/scan.sarif
```

Copy the full workflow from
[`docs/examples/github-actions-scan.yml`](https://github.com/danoszz/penthera/blob/main/docs/examples/github-actions-scan.yml)
into your app's repo. Pin the Penthera version so a scheduled run never picks up
code you have not reviewed.

Penthera's own CI runs the full test suite on Node 22 and 24, self-scans a mock
vulnerable API on every push, and runs CodeQL and OpenSSF Scorecard.

## Configuration

Flags that tune any scan:

| Flag | Use |
|------|-----|
| `--api-root <path>` | API routes directory (default: auto-detect) |
| `--timeout <ms>` | Request timeout (default: 10000) |
| `--concurrency <n>` | Concurrent requests (default: 15) |
| `-v, --verbose` | Detailed output, and the terminal report instead of the brief |
| `-q, --quiet` | Findings only. With `--baseline`, only the new ones |

For live integration tests against your own routes:

```bash
cp pentest.config.example.js pentest.config.js   # gitignored
```

Edit the route groups, then run `npm run pentest:live`. Set `PENTEST_BASE_URL` to
point at staging without editing the file.

[Back to the README](https://github.com/danoszz/penthera/blob/main/README.md) · [All commands](https://github.com/danoszz/penthera/blob/main/docs/commands/README.md)
