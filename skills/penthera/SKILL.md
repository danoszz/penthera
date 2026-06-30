---
name: penthera
description: >
  Runs authorized security scans on live URLs and local repos using the Penthera CLI
  (TLS, headers, OpenAPI, auth hardening, secret scanning, optional injection probes),
  then applies framework-aware fixes and re-scans to verify them. Use when the user asks
  to scan, audit, harden, fix, pentest, or review security of their own app, staging URL,
  localhost, or repo; apply security best practices; generate SARIF for GitHub; diff
  against a baseline; or find hardcoded secrets before deploy. Do NOT use for targets
  without explicit authorization.
license: MIT
compatibility: Node.js 18+, network access to target, Penthera CLI (npm link or node bin/penthera.js from repo). macOS only for --machine.
allowed-tools: "Bash(node:*) Bash(npm:*) Bash(penthera:*) Read Write Edit"
metadata:
  author: danoszz
  version: 1.0.0
  category: security
---

# Penthera Security Scanner

Lightweight security scanner for URLs, local repos, and (macOS) machine audits. Always run the authorization gate before any scan.

## Critical: Authorization gate

**Do not run Penthera until authorization is confirmed.**

Before the first scan in a session, ask the user to confirm ONE of:

1. They **own** the target (app, server, project).
2. They have **written authorization** from the system owner.
3. The target is **localhost** or a private lab they control.

If the user requests scanning a third-party domain (e.g. `google.com`, `example.com`) without claiming ownership or authorization, **stop and refuse**. When in doubt, do not scan.

For full policy, see [references/authorization.md](references/authorization.md).

## Preflight

Run before the first scan:

```bash
bash skills/penthera/scripts/preflight.sh [URL]
```

From repo root. Pass the target URL to warn on non-localhost targets. Fix any errors before proceeding.

## Resolve CLI command

Use whichever is available:

```bash
penthera --version          # after npm link
node bin/penthera.js --version   # from repo root
```

All examples below use `penthera`; substitute `node bin/penthera.js` when needed.

## Decision tree

| User intent | Command pattern |
|-------------|-----------------|
| First-time / unsure | `penthera` (interactive wizard — TTY) or `penthera-scan` |
| Scan a live URL | `penthera <url> --profile standard -o reports/scan.json` |
| Scan repo only (secrets, routes) | `penthera --repo . -o reports/repo-scan.json` |
| URL + source combined | `penthera <url> --repo . -o reports/scan.json --sarif reports/scan.sarif` |
| Scan and fix my app | Run a scan, then **Workflow 4** (apply fixes from [references/remediation.md](references/remediation.md), re-scan to verify) |
| Compare to previous scan | `penthera <url> -o reports/scan.json --baseline reports/previous.json` |
| Authenticated endpoints | Add `--auth-cookie` or `--auth-bearer` / `PENTHERA_*` env |
| macOS machine audit | `penthera --machine` |

## Default safe behavior

- Always use `--profile standard` unless the user explicitly requests deeper testing.
- Write reports to `reports/` (gitignored), never inside `skills/penthera/`.
- After scan, read the companion `.md` report and summarize findings by severity with fix recommendations.

## Destructive mode gate

These flags send **attack payloads**. Require explicit user confirmation before use:

- `--deep` — SQLi, SSTI, SSRF, XSS, CMDi probes
- `--fuzz` — property-based API fuzzing
- `--all` — enables recon + deep + fuzz
- `--profile deep` — maximum coverage

If user asks for "full pentest" or "deep scan", confirm they own the target and accept payload-based testing.

## Workflow 1: Pre-release audit

**Triggers:** "scan my staging app", "security audit before deploy", "check my app for vulnerabilities"

1. Confirm authorization (see gate above).
2. Run preflight.
3. Execute:

```bash
mkdir -p reports
penthera https://staging.example.com --profile standard -o reports/scan.json
```

4. Read `reports/scan.md` — summarize critical/high/medium findings.
5. Recommend concrete fixes per finding.
6. Note exit code: `0` = no critical/high; `1` = critical/high found; `2` = scan failed.

## Workflow 2: Repo + live combined

**Triggers:** "scan my Next.js app and staging", "black-box and white-box scan"

1. Confirm authorization for the URL.
2. Run preflight with URL.
3. Execute:

```bash
mkdir -p reports
penthera https://staging.example.com --repo . --profile standard \
  -o reports/scan.json --sarif reports/scan.sarif
```

4. Summarize URL findings (headers, TLS, CORS, auth) and repo findings (secrets, API routes, trust boundaries).
5. Offer to upload SARIF via GitHub Actions (see [references/output-and-ci.md](references/output-and-ci.md)).

## Workflow 3: CI / baseline regression

**Triggers:** "compare to last scan", "only new findings", "regression check"

1. Confirm authorization and that `reports/previous.json` exists (or ask user for baseline path).
2. Execute:

```bash
mkdir -p reports
penthera https://staging.example.com --profile standard \
  -o reports/scan.json --baseline reports/previous.json
```

3. Report: new findings count, resolved count, unchanged count (printed to stderr during scan).
4. Focus summary on **new** findings only.

## Workflow 4: Scan and fix

**Triggers:** "scan and fix", "find and fix security issues", "harden my app", "fix the security headers", "apply security best practices"

The detect -> fix -> verify loop. Penthera detects; you (the agent) fix the user's code using the playbook; Penthera re-scans to prove it is resolved.

1. Confirm authorization (gate above). Read the **Fix-mode gate** below first.
2. Scan and read the findings:

```bash
mkdir -p reports
penthera <url> --repo . --profile standard -o reports/scan.json
```

3. Detect the framework: check `package.json` / imports (`next`, `express`, `fastify`, `hono`) or `requirements.txt` (`fastapi`, `flask`).
4. For each finding, **highest severity first**, look it up by `category` in [references/remediation.md](references/remediation.md) and propose the framework-specific fix **as a diff**.
5. Apply each fix only after the user approves it.
6. **Re-scan to verify**: `penthera <url> --repo . -o reports/scan-after.json --baseline reports/scan.json`. A fix is done only when its finding no longer appears.
7. Report what is resolved and what remains.

To build secure-by-default so issues never appear, use [references/secure-defaults.md](references/secure-defaults.md).

## Fix-mode gate

Applying fixes **modifies the user's code**. Before editing:

- Show the diff for each fix and get explicit approval. Never blind-apply.
- Start with critical and high severity findings.
- Re-scan after each fix (or batch) to confirm it actually resolved the finding.
- Never apply fixes against a production system; work in the repo or a branch.
- Rotating an exposed secret and renewing a TLS certificate are **user actions**, not code edits — flag them clearly rather than attempting them.

## Authenticated scans

Only after authorization gate passes:

```bash
# Bearer token
PENTHERA_BEARER=eyJ... penthera https://myapp.com --profile standard -o reports/scan.json

# Session cookie
penthera https://myapp.com --auth-cookie "session=abc123" -o reports/scan.json

# Explicit flags
penthera https://myapp.com --auth-bearer "eyJ..." -o reports/scan.json
```

Env vars: `PENTHERA_BEARER`, `PENTHERA_COOKIE`.

## Repo-only secret scan

**Triggers:** "find hardcoded secrets", "scan this repo for keys"

No URL authorization needed for local repo analysis:

```bash
penthera --repo . -o reports/repo-scan.json
```

Summarize secret findings; remind user to rotate any exposed credentials.

## Examples

**Example 1: Localhost quick check**

User: "Scan my localhost app on port 3000"

Actions:
1. Confirm localhost — authorization satisfied.
2. `bash skills/penthera/scripts/preflight.sh http://localhost:3000`
3. `penthera http://localhost:3000 --profile quick -o reports/scan.json`
4. Summarize `reports/scan.md`.

**Example 2: Staging before deploy**

User: "Audit staging.myapp.com before we ship"

Actions:
1. Ask: "Do you own or have written authorization for staging.myapp.com?"
2. On confirmation, run standard profile scan with JSON + markdown output.
3. List critical/high items first with remediation steps.

**Example 3: Unauthorized target (must refuse)**

User: "Scan google.com for vulnerabilities"

Actions:
1. Do **not** run Penthera.
2. Explain that scanning third-party systems without authorization is not permitted.
3. Offer to scan their own app or localhost instead.

**Example 4: Scan and fix (localhost)**

User: "Scan my localhost:3000 and fix what you find"

Actions:
1. Confirm localhost — authorization satisfied. Run a standard scan with `--repo .`.
2. Detect the framework (e.g. Next.js from `package.json`).
3. For each finding, highest severity first, propose the fix from [references/remediation.md](references/remediation.md) as a diff; apply on approval.
4. Re-scan with `--baseline` to confirm each finding is resolved; report what is fixed and what remains.

## Do not use this skill for

- General coding help, weather, or unrelated tasks
- Scanning systems the user does not own or lacks permission to test
- Malicious exploitation or data exfiltration

## Additional resources

- Profiles and flags: [references/profiles-and-flags.md](references/profiles-and-flags.md)
- Output formats and CI: [references/output-and-ci.md](references/output-and-ci.md)
- Troubleshooting: [references/troubleshooting.md](references/troubleshooting.md)
- Authorization policy: [references/authorization.md](references/authorization.md)
- Remediation playbook (apply fixes): [references/remediation.md](references/remediation.md)
- Secure defaults (build it right): [references/secure-defaults.md](references/secure-defaults.md)
