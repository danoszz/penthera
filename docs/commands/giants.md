---
title: "Other tools in one run: --giants"
sidebarTitle: "Other tools (--giants)"
description: "--giants runs the free scanners you already have installed, after Penthera's own scan, and folds their findings into the same report, JSON and SARIF."
---

> **Pro.** For "can Penthera run gitleaks, Semgrep, Trivy and the rest for me, and put it all in one report?"

`--giants` runs the free scanners you already have installed, after Penthera's
own scan, and folds their findings into the same report, JSON and SARIF. Each
finding names the tool, its version and the rule that raised it. An area is
"covered" when Penthera's own rules read files there or another tool ran. An
area neither reached is reported as "not covered", never as clean.

Penthera never installs, downloads or bundles these tools, their rules or
their databases. It runs the copies on your `PATH`, each as its own program
under its own licence. Their findings are their own deterministic output,
labelled with their name. No model is involved.

```bash
penthera giants                            # which tools you have, their versions, install hints
penthera --repo . --giants                 # Penthera, then every installed offline tool
penthera --repo . --with gitleaks,trivy    # only these tools
penthera --repo . --giants --without trufflehog
penthera --repo . --giants --giants-online # also pip-audit, TruffleHog key verification and osv-scanner's API
penthera https://staging.example.com --giants --nuclei ./my-templates
```

This is a feature description, not a claim that the combination finds more.
Experiment E14 measured that
([results](https://github.com/danoszz/penthera/blob/main/bench/public/RESULTS.md)).

## What runs

| Area | Penthera's own | Tools, if installed | Network |
|---|---|---|---|
| Secrets | Secret rules | gitleaks, TruffleHog | None. TruffleHog verifies keys only with `--giants-online` |
| Code | Code patterns, library mode | Semgrep (your local rules only); CodeQL only with `--with codeql` | None |
| Dependencies | `penthera deps` | osv-scanner (your local database), pip-audit | osv-scanner: none with a local database, its API with `--giants-online`. pip-audit: always online, so only with `--giants-online` |
| Infrastructure | Runtime versions in Dockerfiles and version files | Trivy (`trivy fs`, vulnerabilities and IaC), Checkov | None, with Trivy's database already in its cache |
| Live app (URL scans) | Passive checks, templates, `--deep` probes | nuclei (your templates), the ZAP baseline scan | The target only |

The exact command line of every tool is in the Markdown and JSON reports, so a
reviewer can rerun it. These are the commands for 2.1:

| Tool | Minimum | Command (repo at `<root>`) |
|---|---|---|
| gitleaks | 8.30 | `gitleaks dir <root> --report-format sarif --report-path <tmp>/gitleaks.sarif --redact --exit-code 0` |
| TruffleHog | 3.90 | `trufflehog filesystem <root> --json --no-update --no-verification` |
| Semgrep | 1.100 | `semgrep scan --config <your rules> --metrics off --disable-version-check --sarif --output <tmp>/semgrep.sarif <root>` |
| osv-scanner | 2.0 | `osv-scanner scan source --format json --recursive --offline <root>` |
| pip-audit | 2.7 | `pip-audit -r <root>/requirements.txt --format json --no-deps --disable-pip` |
| Trivy | 0.55 | `trivy fs --skip-db-update --skip-check-update --scanners vuln,misconfig --format json --output <tmp>/trivy.json <root>` |
| Checkov | 3.0 | `checkov -d <root> --output json --output-file-path <tmp>/checkov --skip-download` |
| nuclei | 3.2 | `nuclei -u <url> -t <your templates> -duc -ni -jsonl -etags intrusive,dos,fuzz` |
| ZAP baseline | 2.15 | `zap-baseline.py -t <url> -J penthera-zap.json -I -z -silent` |
| CodeQL | 2.15 | `codeql database create` (JavaScript, TypeScript, Python), then `codeql database analyze --no-download` |

A version below the minimum is skipped. A newer version runs with a warning
until we have recorded its output as a test fixture, because its output format
may have changed.

## What you set up yourself

Penthera does not fetch anything for these tools. Run these once:

| Tool | What it needs | How you fill it |
|---|---|---|
| Trivy | Its vulnerability database in its cache | `trivy fs --download-db-only` |
| osv-scanner | Its offline database | `osv-scanner scan source --download-offline-databases --offline-vulnerabilities .` |
| Semgrep | A local rules folder (the registry downloads rules at scan time, so it is not used) | `git clone https://github.com/semgrep/semgrep-rules`, then set `PENTHERA_SEMGREP_RULES` or `giants.semgrepRules` |
| nuclei | Your templates folder | `--nuclei <dir>` or `giants.nucleiTemplates` |

Without these, the tool is skipped and the report says why and gives the
command.

## How Penthera runs another program

A repository is hostile input, and so is anything it can put on `PATH`.

- **Found outside your project.** Each tool comes from a `PATH` folder outside
  the scanned repository and outside the current folder. A
  `./node_modules/.bin/gitleaks` or `./bin/trivy` is refused and reported.
- **No shell.** Every tool starts with an argument list, so a file name or URL
  cannot inject a command.
- **Stopped when stuck.** Each tool gets 300 seconds (`--giants-timeout`) and
  50 MB of output. Past either, it is stopped and its area reads "timed out" or
  "failed".
- **Network denied.** Offline tools run under macOS `sandbox-exec` or Linux
  `bwrap` with the network denied. A tool scanning a target on your machine
  can reach your machine only (macOS). Without a sandbox, the report says the
  network was not enforced.
- **Minimal environment.** A tool sees `PATH`, a temp `HOME` (or your own when
  it needs its cache), the locale and the cache folders you set for these
  tools. No tokens from your environment.
- **Secrets masked.** gitleaks runs with `--redact`. TruffleHog prints secrets
  in full; Penthera masks them (first and last four characters) before any
  report, the dashboard or the evidence bundle sees them.
- **Unreadable output is a failure.** A report that does not parse makes the
  area "failed", never clean.
- **Not from inside your repository.** Tools run from a temp folder, so a
  `.checkov.yaml` or `trivy.yaml` in the scanned repository is not loaded.

## How findings are merged

Two findings are the same when their keys match:

| Category | Key |
|---|---|
| Secret | File, line, and the secret's value (hashed in memory, never written). When a tool gives no value, as on a line inside a private key block, file and line alone |
| Code | File, line, and a shared CWE |
| Dependency or container vulnerability | Ecosystem, package, version, and a shared advisory id across aliases (CVE, GHSA, OSV, PYSEC) |
| Infrastructure | File, resource, and a shared check id |
| Web | URL, parameter, and a shared CWE |

The default is **Penthera-first**, as E14's rule kept it. A tool finding
that matches one of Penthera's is folded into it, and the report says
"found by Penthera, gitleaks". Penthera's confidence and remediation lead.
Everything else is merged among the tools (highest severity wins, every source
kept) and listed in its own section, "Also reported by other tools".

## Reports

The terminal report gets a **Coverage by area** table:

```
  Coverage by area Penthera's own checks, then the other tools you have installed

  Secrets          covered     Penthera (702 files), gitleaks 8.30.1 (4), trufflehog 3.99.3 (1)
  Code             covered     Penthera (405 files), semgrep 1.180.0 (3), codeql: skipped
  Dependencies     covered     Penthera: run penthera deps, osv-scanner 2.6.0 (17), pip-audit: skipped, trivy 0.76.1 (17)
  Infrastructure   covered     Penthera (2 files), trivy 0.76.1 (15), checkov 3.3.30 (13)
  codeql: skipped, runs only with --with codeql
  pip-audit: skipped, needs --giants-online (it contacts a service)
```

"Penthera (702 files)" is what Penthera's own scan read in that area. A tool
that is not on your `PATH` is listed as `not installed`, with the install
command, and is never started. In the JSON, an area's `status` is about the
other tools only; `pentheraRead` holds what Penthera read there.

- **JSON** (`-o`): a `giants` object with each tool's status, version,
  command line, exit code and network mode, the areas, and the other tools'
  findings. Each finding has `source` (the tool), `sources` (tool, version,
  rule id, rule URL) and `foundBy`.
- **Markdown**: the same tables, and the command lines.
- **SARIF** (`--sarif`): one run per tool, with that tool's name and version,
  so GitHub code scanning shows each tool as itself. Penthera's run stays first.
- **Evidence bundle** (`--evidence`): each tool's raw output under `giants/`,
  hashed in the manifest like the rest.
- **Dashboard** (`penthera ui`): a source filter on the findings list and the
  coverage table.

## Exit code and the policy file

Other tools' critical and high findings count toward the exit code like
Penthera's own: exit 1. A team can report them without gating, or require,
limit or forbid tools, in `penthera.policy.json`:

```json
{
  "giants": {
    "require": ["gitleaks"],
    "only": ["gitleaks", "trivy", "osv-scanner"],
    "deny": ["trufflehog"],
    "failOn": "never",
    "semgrepRules": "../semgrep-rules/javascript",
    "nucleiTemplates": "./nuclei-templates",
    "timeout": 600
  }
}
```

A required tool that did not run makes the scan exit 2. Paths are relative to
the policy file. For a repo scan the policy file is the one in the scanned
repository.

## Live tools: nuclei and the ZAP baseline

They run only in URL scans, against the target you typed, a host on your
machine, or a host you allowed, under the same rules as Penthera's own probes.
Any other host is refused before either tool starts.

- **nuclei** runs only your templates folder, never its own template download
  (`-duc`), never the interactsh callback servers (`-ni`), and without the
  `intrusive`, `dos` and `fuzz` tags unless the scan is `--deep` (which asks
  for confirmation first).
- **ZAP** runs the baseline scan only: a passive spider and passive checks.
  `-z -silent` stops its add-on update check. Its active scan is not offered.

Penthera runs `zap-baseline.py` from `PATH`. To use ZAP's container, put a
small wrapper of your own on `PATH`, for example:

```sh
#!/bin/sh
# zap-baseline.py: ZAP's baseline scan in its container, the current folder at /zap/wrk.
exec docker run --rm --network host -v "$PWD:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable zap-baseline.py "$@"
```

On macOS, Docker cannot use `--network host` for a target on your machine:
rewrite `127.0.0.1` in the target to `host.docker.internal`, and mount a folder
that Docker can see.

## CodeQL

CodeQL runs only with `--with codeql`, never with plain `--giants`. Its terms
allow academic research and the analysis of open-source code, not automated
analysis of other code. Penthera prints a one-line notice before it runs;
using it on closed-source code is your responsibility under your own licence
(for example GitHub Advanced Security).

On JavaScript library code it is worth adding. In E14, on the sealed test
half of SecBench.js, Penthera with CodeQL found 54 of 64 injection bugs
against 45 for Penthera alone, at a mean of 4 findings per package instead
of 1. Whether those extra findings are right could not be measured there (the
dataset has no labelled negatives), so `--giants` keeps Penthera-first and
lists CodeQL's findings under "Also reported by other tools"
([results](https://github.com/danoszz/penthera/blob/main/bench/public/RESULTS.md)).

## Limits

- Each tool runs with sane defaults. It is not tuned for your project; when
  you need that, run it yourself with your own configuration.
- macOS and Linux only. Windows has no network sandbox here.
- Burp is out of scope: manual, proxy-driven testing by a person is a
  different job, and it is proprietary.
- Other tools' findings are not checked by Penthera's rules or by a model.
- Penthera's own repo scan does not check dependencies for known
  vulnerabilities (that is `penthera deps`), so the Dependencies area relies on
  the tools you have.

The design and its decisions are in the
[spec](https://github.com/danoszz/penthera/blob/main/docs/research/spec-giants.md).
