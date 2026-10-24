# Scanning your app: `penthera <url>` and `--repo`

> **Starter.** For "is my app safe to ship?"

Black-box scans of a running app (localhost, preview, or staging) and white-box scans of its source. The default scan is non-destructive. Payload-based testing is opt-in.

## Scan modes and profiles

| Mode | Command | Coverage |
|------|---------|----------|
| **URL scan** | `penthera https://example.com` | TLS, fingerprinting, endpoint discovery, templates, CORS, cookies, JS CVEs, param discovery, OpenAPI/FastAPI probes, security headers, auth hardening |
| **Repo scan** | `penthera --repo ./my-app` | API route discovery (Next.js, Express, Hono, Fastify), trust-boundary mapping, hardcoded-secret scanning (including Anthropic, OpenAI, Gemini, Groq, Hugging Face and other AI provider keys) |
| **Combined** | `penthera https://staging.app --repo .` | Black-box and white-box in one run |
| **Interactive** | `penthera` *(no args)* | Setup wizard: detects the project, runs the offline checks, offers the hook and workflow ([init.md](init.md)) |
| **Machine audit** | `penthera --machine` | macOS checks (keyloggers, persistence, rootkits) |
| **Dependencies** | `penthera deps` | What each npm or Python package can do (install scripts, shell, network, env, eval, native, obfuscation, `.pth` startup hooks), capability diff on upgrades, typosquats. Offline ([deps.md](deps.md)) |

Pick a profile, or add individual flags for more depth:

| Profile | Command | What runs |
|---------|---------|-----------|
| **quick** | `--profile quick` | Headers, OpenAPI, auth checks; no login POSTs (about 10s) |
| **standard** | *(default)* | Full non-destructive scan: no attack payloads, and one `POST /api/login` with invalid credentials |
| **deep** | `--profile deep` | recon, injection probes, API fuzzing, and on `/api/login` an 8-attempt rate-limit burst and an SQL error check |

What each profile sends to `/api/login`: `quick` nothing; `standard` one
login with obviously invalid credentials, to catch a login that accepts
anything; `--deep` also 8 rapid attempts (rate limiting) and an
`' OR '1'='1` string (SQL errors). A CDN firewall can read the last two as an
attack and start challenging you, so they only run with `--deep`.

Individual flags: `--recon`, `--deep`, `--fuzz`, `--adaptive`, `--nuclei <path>`, `--templates <dirs>`, `--all`

### Active modes ask first

`--deep`, `--fuzz`, `--adaptive`, `--all` and `--profile deep` send test
payloads (and, with `--deep`, the login burst above), so they need your
confirmation before the first request:

- In a terminal, Penthera asks. For a target on this machine (`localhost`,
  `127.0.0.1`, `*.localhost`) a yes is enough; for any other target, type its
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

## Quick start

```bash
# First time? Run with no args for guided setup
penthera

# Safe default scan (non-destructive)
penthera https://myapp.com

# Staging plus source code, full report set
penthera https://staging.myapp.com --repo . --all -o reports/scan.json --sarif reports/scan.sarif

# Baseline diff: show only new findings since the last scan
penthera https://myapp.com -o reports/scan.json --baseline reports/previous.json

# Authenticated scan (session cookie or bearer token)
PENTHERA_BEARER=eyJ... penthera https://myapp.com --profile standard
penthera https://myapp.com --auth-cookie "session=abc123"
```

Writing to `-o reports/scan.json` also drops a human-readable `reports/scan.md`
next to it. `penthera init` can add `reports/` to your `.gitignore`.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No critical or high findings |
| `1` | Critical or high findings detected |
| `2` | Scan failed (unreachable target, bad config) |

---

## Output

| Format | Flag | Use |
|--------|------|-----|
| Terminal | *(default)* | Colored summary plus top 3 fixes |
| **Markdown** | `--markdown file.md` or `-o file.json` | Human-readable report (exec summary, findings tables, fixes). Written next to `-o` automatically |
| JSON | `--json` or `-o file.json` | CI pipelines, baseline diffs, custom tooling |
| SARIF | `--sarif file.sarif` | GitHub Security / Code Scanning tab |
| AI-audit seeds | `--audit-seeds seeds.json` (with `--repo`) | Repo findings in Cloudflare security-audit-skill `findings.json` form, so an agent running the skill starts from them ([verify.md](verify.md#the-other-way-seeds-for-the-skill)) |
| Audience report | `--audience developer\|owner\|auditor` | The same scan written for a developer, an owner or an auditor ([docs/evidence.md](../evidence.md#audience-reports)) |
| Your template | `--report-template file.md` | Your own Markdown with `{{summary.critical}}`, `{{#each findings}}`, `{{#if x}}`; no code runs |
| **Evidence bundle** | `--evidence <dir> [--sign-key <ssh-key>]` | All reports plus `manifest.json` with SHA-256s, optionally SSH-signed. Auditors check it with `penthera evidence verify <dir> --allowed-signers <file>` ([docs/evidence.md](../evidence.md)) |

### Coverage: what a repo scan read

Every `--repo` scan adds a **Coverage** section to the terminal, Markdown and
JSON (`coverage`) reports. For each check (the secret scan, route and
code-pattern analysis, runtime versions) it says how many files were read and
why the others were not: file type not read, over the size limit, a language
route analysis does not support, or no API routes found. Source files no code
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
sealed test half is not scored yet.

Limits. Only one helper call is followed, and only to a function the file
calls by name. A field set from another field is not followed. Sanitizers are not recognized, so a
correctly escaped command can still be reported; that is what `potential`
means.

## CI integration

```yaml
# Scan a staging URL on a schedule and upload results to GitHub Security.
- run: npx penthera@1.8.1 "$PENTEST_URL" --profile standard --sarif reports/scan.sarif
- uses: github/codeql-action/upload-sarif@6f2ac81f5cd81fe351a197ba0b00d91d03cd2aee # v4.39.0
  with:
    sarif_file: reports/scan.sarif
```

Copy the full workflow from
[`docs/examples/github-actions-scan.yml`](../examples/github-actions-scan.yml)
into your app's repo. Pin the Penthera version so a scheduled run never picks up
code you have not reviewed.

Penthera's own CI runs the full test suite on Node 22 and 24, self-scans a mock
vulnerable API on every push, and runs CodeQL and OpenSSF Scorecard.

## Configuration

For live integration tests against your own routes:

```bash
cp pentest.config.example.js pentest.config.js   # gitignored
```

Edit the route groups, then run `npm run pentest:live`. Set `PENTEST_BASE_URL` to
point at staging without editing the file.

[Back to the README](../../README.md) · [All commands](README.md)
