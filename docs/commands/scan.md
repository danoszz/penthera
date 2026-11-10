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
| **Repo scan** | `penthera --repo ./my-app` | API route discovery (Next.js, Express, Hono, Fastify), trust-boundary mapping, hardcoded-secret scanning (including Anthropic, OpenAI, Gemini, Groq, Hugging Face and other AI provider keys), security headers, cookie flags, CORS and login rate limits as your code sets them (the checks [`penthera fix`](fix.md) fixes), and your GitHub Actions workflows ([below](#github-actions-workflows)) |
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

### Behind Vercel Deployment Protection

A Vercel deployment behind Vercel Authentication answers 401 to the scanner.
Set Vercel's Protection Bypass for Automation secret in `PENTHERA_VERCEL_BYPASS`:

```bash
PENTHERA_VERCEL_BYPASS="$VERCEL_AUTOMATION_BYPASS_SECRET" penthera https://myapp-git-main-team.vercel.app
```

Penthera sends it as the `x-vercel-protection-bypass` header, and only to an
`https://*.vercel.app` target's own origin: not to another host, not after a
redirect to one, not to any other target, and never in an MCP scan, where the
report notes "not sent". It must be 16 to 128 characters of `A-Z a-z 0-9 . _ ~ -`,
as Vercel generates it, so no encoded copy of it can slip past the redaction.
Set it only for a scan of your own deployment. It is read from the environment only, so it is never in the command
line, and it is replaced with `[redacted]` anywhere in the report. A scan that
still gets 401 or 403 on the home page records it as `httpStatus`; treat that
as a scan that read nothing. The [Vercel integration](https://docs.penthera.org/vercel#deployment-protection)
and the [Action](action.md) pass it for you.

To compare with the merge-base of your branch instead of a saved report, use
[`penthera diff`](diff.md).

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
| `2` | Scan failed or is incomplete (unreachable target, missing path, bad config, a tool the policy requires did not run, a file the scan had to read but refused: a route, server or code file over 5 MiB, a FIFO or a link out of the project, a dependency input, agent config; or code files past the headers, cookies, CORS and login rate limit check's 5,000-file limit) |

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
The brief doesn't print it, but it says how to use it under its problems. Use it with `penthera memory suppress <fid> --reason "..." --severity <level>`, or add the fid and reason to `penthera.suppress.json` to share it with your team; both apply to scans with `--memory`.
A suppression covers the finding up to that severity, and medium when you give
none. If the finding escalates past it, it shows again.

In `-o` JSON a repo finding also has `path`, its file (the same value `url`
holds, which stays for older readers), and every finding has `exploitability`.
`confidence` says how sure the rule is about what it matched, not whether it
can be exploited in your app: `exploitability` is `not-assessed` for a rule
match, and `needs-human-review` where a scanner cannot judge it. Text reports
use the words `pattern matched`, `likely match`, `possible match` and
`needs a person` for the four confidence values.

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
| **Share card** | `--card [--card-out <path>]` | One image of the run to post: the verdict, what was read, what wasn't, the number to fix first and the top fix. PNG and SVG, made offline ([below](#share-card)) |

### Share card

`--card` writes the result as an image you can post, a security receipt:

```bash
penthera --card                 # the folder you are in, like penthera --repo . --card
penthera agents . --card        # your AI-agent configs: skills, MCP servers, hooks
penthera https://my-app.example --repo . --card
```

| File | Size | For |
|---|---|---|
| `penthera-card.png`, `penthera-card.svg` | 1080 × 1350 | X and other feeds (4:5) |
| `penthera-card-og.png`, `penthera-card-og.svg` | 1200 × 630 | Link previews |

`--card-out <path>` picks another place and name: `--card-out reports/card`
writes `reports/card.png`, `reports/card-og.png` and their SVGs.

The card never writes through a symbolic link. If a folder on the way is a
link, or a card name is a folder, nothing is written and the run exits 2; a
link planted at a card's name is replaced, and the file it pointed to is left
as it was. `--card` does not work with `penthera deps` (write `-o deps.json`
and use `penthera brief deps.json --card`) or with `--baseline` and `-q`
together, which counts only new findings; both exit 2.

The card is built on your machine from the brief, so it shows the same
verdict as the brief, and no model is involved. Penthera draws it with its own
renderer and pixel font: nothing is fetched or uploaded, and it adds no
dependency.

What a card always shows:

- The verdict: Fix now, Review, Nothing to fix now (only things to check
  first, with how many: `Nothing to fix now · 4 to check`), Nothing to fix,
  Nothing to assess, Site not read, or how many findings are suppressed.
- On an agent-config card, the audit's grade as the big letter, with its score
  out of 100 next to it and the number to fix first as a line. Repo and URL
  scans have no score, so their card leads with the number to fix first; none
  is made up.
- What was read: code, dependencies, AI-agent configs and the live site, each
  read, partly read or not run. On a card that merges several scans, AI-agent
  configs show the audit's grade and score on their line.
- What was not checked, including what the checks themselves could not read
  (an agent audit starts no MCP server, so tool descriptions are not read). A
  repo or live-site card always adds that login, access rules and payments are
  not proven.
- The number to fix first and, when there is one, the top fix: the most severe
  finding that needs a change.
- The command that made it, at the bottom.

What it never shows: file paths, file contents, hidden characters, URLs,
credentials, package versions or anything shaped like a key. A dependency's
version can be a URL with a password in it, so a card names only the package.
A finding's title loses its path, and long key-like strings are replaced with
`[hidden]`. The target is the folder name or the host, not the full path.

A run that read nothing never looks clean. Site not read and Nothing to
assess show a `?` instead of a number, and suppressed findings are the number
when they are all that is left.

A repo scan alone lists dependencies and AI-agent configs as not run. To put
all of them on one card, write each report and merge them:

```bash
penthera --repo . -o reports/repo.json
penthera deps . -o reports/deps.json
penthera agents . -o reports/agents.json
penthera brief reports/repo.json reports/deps.json reports/agents.json --card
```

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

### Framework versions with a published vulnerability

A `--repo` scan reads the installed version of `next` and the React Server Components packages (`react-server-dom-webpack`, `-turbopack`, `-parcel`) from the lockfile and compares it with a short table that ships with Penthera. Lockfiles read: `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock` (classic and berry) and `bun.lock`. With no lockfile, an exact pin in `package.json` counts; a range such as `^15.5.0` says nothing about what is installed and is not guessed. Every copy in the tree is checked, nested ones too. Pre-release and canary builds are not compared.

| Rule | Severity | What it means |
|------|----------|---------------|
| `framework-advisory` | critical, high or low | The installed version is in a published advisory's affected range. Critical for CVE-2025-55182 (React Server Components deserialisation, remote code execution, fixed in Next.js 15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7 and 16.0.7). High for CVE-2025-29927 (the middleware bypass, fixed in 12.3.5, 13.5.9, 14.2.25 and 15.2.3) when the project has a middleware file, low when it has none. The finding names the lockfile line, the advisory and the fixed versions. |

A lockfile that cannot be read or parsed is named and makes the scan incomplete (exit 2), never a silent pass.

### Server secrets behind a public env prefix

Next.js writes every `NEXT_PUBLIC_*` variable into the browser bundle at build time; Vite does the same for `VITE_*`, Expo for `EXPO_PUBLIC_*`, Create React App for `REACT_APP_*`, Nuxt for `NUXT_PUBLIC_*`, SvelteKit and Astro for `PUBLIC_*`, Gatsby for `GATSBY_*`. The rule reads names, not values, so a placeholder in `.env.example` or a `process.env.NEXT_PUBLIC_RESEND_API_KEY` read in a component is enough. It reads `.env*` files, `next.config.*`, `turbo.json`, `vercel.json`, `netlify.toml`, Expo's `app.json` and `app.config.*`, and `process.env.X` or `import.meta.env.X` reads in code (comments blanked).

| Rule | Severity | What it means |
|------|----------|---------------|
| `public-env-secret` | high; critical when a committed value matches a provider key shape | The part after the prefix names a secret (`API_KEY`, `TOKEN`, `SECRET`, `PASSWORD`, `SERVICE_ROLE`, `DATABASE_URL`, ...) and nothing in the name says the value is public by design (`PUBLISHABLE`, `ANON`, `SITE_KEY`, `CLIENT_ID`, `DSN`, ...). Keys providers issue for the browser, such as `FIREBASE_API_KEY`, `GOOGLE_MAPS_API_KEY`, `MAPBOX_TOKEN`, `STRIPE_PUBLISHABLE_KEY` and `SUPABASE_ANON_KEY`, are not reported. One finding per variable name, pointing at the first place it is defined. |

Rename the variable without the prefix, read it in server code only, and rotate the value if it was ever deployed. If the value is meant for the browser, say so in its name.

### Server Actions without an auth check

Every exported async function in a file that starts with `"use server"`, and every function whose body starts with it, is a public POST endpoint: the client bundle carries its id, and anyone can call it with any arguments. A `--repo` scan reads these files on lexed source (comments blanked, strings masked) and reports an action that writes data without checking who is calling.

| Rule | Severity | What it means |
|------|----------|---------------|
| `server-action-no-auth` | high (medium when a root `middleware` file calls an auth function) | An action's body calls a database write (Prisma, Drizzle, Supabase, Mongoose, Kysely, Knex, Firestore, or raw `INSERT`, `UPDATE`, `DELETE`), sends mail or calls a payment API, and neither the body nor the wrapper it is passed to calls an auth function: `auth()`, `getServerSession`, `getUser`, `currentUser`, `verifySession`, `requireUser`, a name that starts with `require`, `verify`, `assert`, `ensure` or `check` and names auth, a session, a user, an admin or a permission, or anything imported from an auth module (next-auth, `@clerk/*`, `@supabase/ssr`, lucia, Kinde, WorkOS, Auth0, iron-session, better-auth, or a local file whose path names auth or a session). One finding per file, at `potential` confidence, listing the actions and what they write. |

**Limits.** A check in a helper this rule does not know by name, or in middleware whose matcher covers the page, is not seen, which is why the confidence is `potential`. Actions in `test`, `fixtures` and `public` folders are not read. A read-only action is never reported.

`jwtVerify` and `jwt.verify` count as auth calls, and a re-export from an auth module (`export { auth as middleware } from "@/auth"`) counts as an auth import, so an Auth.js middleware lowers these findings to medium.

### Missing checks: webhooks, tokens and client-chosen values

Five places where server code skips the one standard check that makes it safe. A `--repo` scan reads every server code file on lexed source (comments blanked, strings masked), so a call named in a comment or a string does not count. Each rule looks for the check, and stays quiet when anything in the file could be it: a verify call, a webhook secret, an expiry word, an admin check. Browser code (`"use client"` files), test folders and `*.test.*` files are not read.

| Rule | Severity | What it means |
|------|----------|---------------|
| `webhook-signature-missing` | high; `likely`, or `potential` when the file reads a signature header | A webhook handler takes the request body and writes data, sends mail or calls a payment API, and nothing in the file verifies the provider's signature. A handler is a file whose path names a webhook, a route registered on a path with `webhook` or `/hooks`, or a file that handles Stripe events (`checkout.session.completed`, `invoice.paid`, ...). It also needs a provider import (stripe, svix, Clerk, Octokit, Lemon Squeezy, Paddle, Polar, Shopify, ...) or an event read (`event.type`). The check can be `constructEvent`, `createHmac`, `timingSafeEqual`, any verify or validate call, `stripe.events.retrieve`, or a webhook or signing secret by name. A file that reads a user session (`auth()`, `getServerSession`) is a settings route, not a provider's webhook. |
| `jwt-decode-unverified` | high, `likely` | A file reads a token from the request (an `Authorization` header, a cookie, a `token` query) and decodes it with `jwt.decode`, `decodeJwt` or `jwtDecode`, and nothing in the file verifies a token (`jwt.verify`, `jwtVerify`, any verify call, `getToken`, `getServerSession`). A decode with a secret (jwt-simple, next-auth's `decode`) verifies, so it is not reported. |
| `secret-compare-not-constant-time` | medium for an HMAC or a signature, low otherwise; `likely` | `===`, `!==`, `==` or `!=` with an HMAC on one side (`createHmac`, or a name assigned from it), or a value from the request (a header, the query, the body, a cookie) on one side and a secret on the other: an env secret (`process.env.CRON_SECRET`, also inside a template), a constant such as `API_KEY`, or a name such as `apiKey`, `signature`, `csrfToken`, `resetToken`. Lengths, types, literals, `typeof` and flags (`isSecret`) are not compared secrets. One finding per file, at the worst hit, listing the lines. |
| `reset-token-no-expiry` | medium, `potential` | A file looks up a password-reset token (`resetToken`, `reset_password_token`, `password_reset_tokens`, ...) and writes a password, and has no expiry check anywhere: no expiry field or word, no date filter (`gt:`, `$gt`), no time comparison, no `now()`, no verify call. A token kept in Redis or another key-value store expires by its TTL there, so those files are not reported. |
| `client-trusted-value` | high for an amount sent to a payment API (`likely`) or a role, plan or credit field from the request (`potential`); medium for the whole body written to a user record (`potential`) | A value from the request body, the query or a form goes, as the client sent it, into `amount` or `unit_amount` of a Stripe, PayPal, Razorpay, Mollie, Paddle or Lemon Squeezy create call, or into `role`, `plan`, `tier`, `credits`, `isAdmin`, `permissions` or `emailVerified` of a write to a user, account, profile, member, team or tenant record. Or the whole body is the data (`data: body`, `{ ...body }`, `User.findByIdAndUpdate(id, req.body)`, `new User(req.body)`). A body passed through a schema parse (`Schema.parse`) is not whole, since the parse keeps only the keys it names. Admin routes (an admin check by name, a role comparison, an `admin` path), refunds, `metadata`, and donations, tips and top-ups, where the payer picks the amount, are not reported. |

**How we checked it.** On 10 open-source projects (Polar, Umami, Uptime Kuma, SonicJS and six more), four known-vulnerable apps (Juice Shop, DVNA, NodeGoat, crAPI) and Penthera itself, the five rules report 5 findings, all from the timing rule: a bridge token and a CSRF token compared with `!==`, and three HMAC compares, one of them in Penthera's own offline check of the public Supabase demo key. All five are true by the rule; none is a practical risk except the two tokens. On the 150 benign npm packages of the benchmark's dev half (6,063 files, `dist` included) they report none. Recall is measured only on the crafted cases in `tests/missing-checks.test.js`: those apps hold few webhook, checkout or reset handlers.

**Limits.** Each rule reads one file. A check in an imported helper whose name says nothing (`await handle(sig)`) is not seen, and a check anywhere in the file counts, even in another function: so the rules miss more than they invent. The body read is recognised by the request's usual names (`req`, `request`, `event`, `c.req`, `ctx.request`), not by a handler parameter with another name. Server Action parameters other than `formData.get(...)` are not followed. Every file is read whole under a 4 MiB cap; a larger file, a file Penthera may not read, or more work than 16 times the file's length is named and makes the scan incomplete (exit 2), keeping the findings made so far. `explain_finding` knows all five ids.

### Middleware, sessions, passwords and OAuth callbacks

Five checks on lexed source (comments blanked, strings masked), in every code file outside `test`, `fixtures` and `public` folders. Each is one finding per file, with file:line evidence and a CWE.

| Rule | Severity | What it means |
|------|----------|---------------|
| `next-middleware-no-auth` | medium, potential | A Next.js `middleware` or `proxy` file (it imports `next/server`, has a `matcher`, or sits next to a `next.config` file) names a protected area in a string, such as `/admin`, `/dashboard`, `/account`, `/settings`, `/billing`, `/workspace` or `/internal`. It also checks nothing: no auth call by name (the Server Actions check's list), nothing imported or re-exported from an auth module, no read of a cookie or of the `Authorization` header, and no redirect to a path such as `/login`. CWE-306. |
| `credential-in-url` | medium, likely (a password); low, potential (a secret) | Code reads a password, API key, access or refresh token, client secret or `secret` from the query string: `req.query.password`, `req.query["api_key"]`, `searchParams.get("password")`, `c.req.query("api_key")`, a Next.js page's `searchParams.password`, `getQuery(event).password`, or `const { password } = req.query`. A URL ends up in history, logs and the Referer header. CWE-598. |
| `password-encrypted-not-hashed` | high, likely (decrypted to compare); high, potential (encrypted) | A password is decrypted and compared at login (`decrypt(user.password) !== password`, `createDecipheriv(...).update(row.password)`), or a user's password goes to `encrypt()`, crypto-js `AES.encrypt()` or a `createCipheriv` cipher's `update()` in a file that never hashes one. CWE-257. |
| `session-cookie-insecure` | medium, likely (turned off); medium, potential (left at the default) | A file that imports a session library (express-session, cookie-session, koa-session, `@fastify/session`, iron-session, next-auth, `@auth/*`, better-auth, Lucia, or Remix and React Router's cookie sessions) sets `secure: false` or `httpOnly: false` in its cookie options (`cookie`, `cookieOptions`, `cookies.sessionToken.options`, `sessionCookie.attributes`, ...), or `useSecureCookies: false`. Or express-session gets options, inline or from a `const` in the same file, with no `cookie.secure`. It then sends the cookie without Secure. CWE-614. |
| `oauth-callback-no-state` | medium, potential | A file reads `code` from the URL and exchanges it: an `authorization_code` grant, arctic's `validateAuthorizationCode`, or an OAuth client's `getToken(code)`. Nothing in the file mentions `state`, a PKCE `code_verifier` or a `nonce`, and nothing in it comes from a library that checks state for you (Auth.js, Passport, openid-client, oauth4webapi, `@fastify/oauth2`, Supabase, better-auth, Clerk, Auth0, WorkOS, Kinde). CWE-352. |

The cookie calls themselves (`res.cookie`, `cookies().set`) are the cookie-flag check's, under `fix`; this rule reads only a session library's options.

**Limits.** These rules are built for precision. Anything that may hide a check makes them stay quiet: a spread (`...base`) in the options, options imported from another file, a `sess.cookie.secure = true` assignment anywhere in the file, a check in a helper with an unknown name, or a callback that reads `state` but never compares it. A one-time `token` or `code` in a link, Stripe's `session_id` and `key` are not credentials here. A password for another system (`smtp.password`, `config.db.password`) may be encrypted, and is not reported. Middleware for public paths (`/app`, `/team`, `/user/:name`) is not reported. On the four known-vulnerable apps Penthera benchmarks (Juice Shop, DVNA, NodeGoat, WebGoat: 910 files) and on 11,390 files of the maintainer's own apps, the checks reported 3 findings, all real. One was NodeGoat's documented "session cookie lacks the Secure flag". The same sets were used to tune the rules (`session_id` was taken out after two false alarms there), so the count is not independent. The middleware, password and OAuth rules had no hit in either set, so their precision is not measured yet.

Work per file is bounded: the reads that depend on the code's shape are charged to a budget of 16 times the file's length. Past it, what was found is kept, the file is named as not fully checked, and the scan is incomplete (exit 2). So is a file it could not read. `explain_finding` knows all five ids.

### Supabase: the service-role key and row-level security

A `--repo` scan checks the two leaks most common in a Supabase app. It reads your code (including `.vue`, `.svelte`, `.astro` and HTML), your `.env` files and the SQL in `supabase/migrations/` and `supabase/schemas/`. It runs nothing and connects to nothing.

| Rule | Severity | What it means |
|------|----------|---------------|
| `supabase-service-role-exposed` | critical (high in a file git ignores) | A service-role key is in browser code: a Next.js `"use client"` file or a file it imports, a `pages/` page, a Svelte or Vue component, an Astro file below its frontmatter, the `src/` of a Vite, Create React App or Expo app, `public/`, or HTML and the scripts it loads. Or the key is assigned to a public env name (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`, `NUXT_PUBLIC_`, `PUBLIC_`, `GATSBY_`, `VUE_APP_`). The key bypasses row-level security, and the bundle ships to every visitor. |
| | high | A public env name for the key, such as `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY` or `NEXT_PUBLIC_SUPABASE_SERVICE_KEY`, in client code, `.env` or config files. Or a build config that inlines it, or the whole environment (`...process.env`, `JSON.stringify(env)`, a `process.env` key in `define`, or `loadEnv` with an empty prefix feeding a `define` built by code), in a project that uses Supabase: `env` or `publicRuntimeConfig` in `next.config`, `define` or `envPrefix` in `vite.config`. In server code only, such as a check that refuses the name, it is medium, potential. |
| | medium, potential | Client code reads the key under a server-only name (`process.env.SUPABASE_SERVICE_ROLE_KEY`). The value is undefined there unless a build config exposes it, but the code expects admin access in the browser. |
| `supabase-service-role-committed` | high | A service-role key committed outside browser code: a route handler, an Edge Function, a migration, a doc. Low, potential, for the key of a local Supabase stack: one signed with the demo JWT secret Supabase publishes. A key that only claims `iss: supabase-demo` gets full severity. |
| `supabase-rls-disabled` | high | A migration creates a table in an exposed schema (`public`, or the `[api] schemas` in `supabase/config.toml`) and no migration enables row-level security on it, or a later one disables it. |
| `supabase-policy-open` | high to low | A permissive policy for `anon`, `authenticated` or everyone checks `true` in `USING` or `WITH CHECK`. High when anyone can update, delete or do everything; medium when only signed-in users can, or anyone can insert; low, potential, for a public read, medium when the table has columns such as `email` or `phone`. |
| `supabase-sql-unchecked` | medium, potential | A migration ends inside a string or comment, has a statement over 20,000 tokens, or creates tables or changes row-level security in a `DO` block, function body or `EXECUTE`, which Penthera doesn't read. When such a block turns row-level security on, the `supabase-rls-disabled` findings of that project drop to potential. |

A key is recognized by its shape and its claims: a JWT whose payload says `"role": "service_role"`, or an `sb_secret_` key. The signature isn't checked, and reports show the claim, never the key. A server-only key in a `.env` file git ignores is the right setup, and Penthera says nothing about it. Migrations are read in the order the Supabase CLI applies them. `ALTER TABLE … RENAME`, `SET SCHEMA`, `DROP TABLE`, `DROP POLICY`, `search_path`, and `REVOKE ALL … FROM anon, authenticated` (also as default privileges on tables) are followed. Hits in test folders are reported at potential confidence. Client code that git ignores is still reported, at high. Env names are one finding per file: several public names for the key, or several server-only names read in client code, are listed together with a count, the first 20 and a digest of the set. A file with more than 1,000 distinct names, or a repo with more than 20,000 of one kind, is named as not fully checked and the scan exits 2. Past 1,000 files of one kind, the rest are counted into one finding that names the first 20, and the scan exits 2. Names in SQL are cut at 63 bytes, as PostgreSQL does; a name over 1,024 characters marks the migration not fully checked. Tables without row-level security are one finding per migration file, and open policies one per file and severity, each with a count and the first 20 names, tables with columns such as `email` first. The title carries a short digest of the whole list, and a policy's title says what it grants (command, roles, which clause is `true`), so a suppression or baseline covers that exact set and grant: a new table or a broadened policy shows again. Past 50,000 tables and policies, Penthera stops tracking and marks the scan incomplete. It still notes every later statement that can leave a table in an exposed schema reachable: a new table, `DISABLE ROW LEVEL SECURITY`, a move into the schema, a policy with `true` in it, or a `GRANT` to `anon`, `authenticated` or everyone. It reports them together at potential confidence, naming up to 1,000. A migration over 16 MiB, a statement over 20,000 tokens, more than 50,000 tables and policies in one project, a file or folder Penthera may not read (a link out of the project, a broken link, a FIFO, a folder it can't list), or more work than the migrations' size allows makes the scan incomplete (exit 2). `explain_finding` knows all five ids.

**Limits.** It doesn't read the database, so row-level security turned on in the dashboard but not in a migration is reported as off. It doesn't check what a policy's condition allows beyond `true`, views (which skip row-level security by default), storage buckets, or functions marked `security definer`. Client code is found from `"use client"`, the file type, the framework in `package.json`, relative, `@/` and `~/` imports, and links inside the project. Other path aliases, and a key split across strings or built at run time, are not followed: such a key is reported as committed (high), not dropped. A Next.js `pages/` file counts as client code as a whole, so a key read only in `getServerSideProps` is reported too. On the E11b development half of Samsung CredData (337 repositories, 35,183 labelled lines) and 300 benign npm and PyPI packages, it reported nothing, so the secret scan's precision there is unchanged. Neither set holds a Supabase app, so recall is measured only on our own fixtures (`tests/supabase.test.js`). A clean result means none of these patterns was found in what it read.

### Coverage: what a repo scan read

Every `--repo` scan adds a **Coverage** section to the terminal, Markdown and
JSON (`coverage`) reports. For each check (the secret scan, route and
code-pattern analysis, runtime versions, and headers, cookies, CORS and login
rate limits) it says how many files were read and
why the others were not: file type not read, over the size limit, a language
route analysis does not support, or no server routes found (a client-only app
has none). Each file is read whole, up to a size limit: 64 MiB for the secret
scan and 4 MiB for the eval and exec check. Minified code is checked like any
other code, and Coverage notes how many files were minified. A file over those limits, or one that
can't be read at all (a FIFO, a device, no permission), is named and makes the
scan incomplete: it exits 2. A route or server file linked to another file in
the project is read through the link. One linked out of the project or to
nothing, or a linked folder outside it, is named the same way. Route analysis reads Next.js route handlers anywhere under `app/` or
`src/app/` and a Worker's `export default { fetch }` entry, besides Express,
Hono and Fastify routes. How many routes it found is part of Coverage, not a
finding. Source files no code
analysis read are listed as blind spots, up to 200. A file that was not read
is unchecked, not clean. Headers read from code are marked `potential`: your
host or CDN may still add them, and a scan of the live address shows what it
sends. The headers check reads `next.config.*`, `middleware.*` and `vercel.json`
for a Next.js app, and every code file for Express, Hono and Fastify. That
check reads up to 5,000 code files of up to 5 MiB each, leaving out
dependencies, generated output (`dist`, `build`, `.next`, `out` and the like)
and folders git ignores. A linked file is read when its target is inside the
project. A file it refused (a link out of the project, a FIFO, over the size
limit), one it could not fully check, or one past the 5,000, makes the scan
incomplete (exit 2) and is named in the report; scan each app folder on its own
with `--repo <folder>`. Cookie calls written over several lines are checked
too; `penthera fix` edits only one-line calls. `vercel.json` headers count
when they are set for every route (`/(.*)`), and HSTS with `max-age=0` does
not count. Dependency behaviour and agent config have their own
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
means. Library mode reads the body of each exported function, so exported
functions nested inside each other are read once per level. A file that would
take more than 16 times its own length of reading (plus 4 MiB) is checked up to
that point, named as `File not fully checked`, and the scan exits 2.

## CI integration

```yaml
# Scan a staging URL on a schedule and upload results to GitHub Security.
- run: npx penthera@2.4.0 "$PENTEST_URL" --profile standard --sarif reports/scan.sarif
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
