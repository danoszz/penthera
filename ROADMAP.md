# Roadmap

> **Project page.** For anyone asking "what ships next, and when?"

This page lists where Penthera stands, what ships next, and what is
deliberately not being built. The experiments that decide what ships are in the
[research plan](docs/vision-2.0.md). How releases are cut is in
[CONTRIBUTING.md](CONTRIBUTING.md#release-cadence-and-freeze).

Penthera is maintained part-time, alongside a PhD. Work is ordered by value per
hour. A feature that does not answer a real user question, or does not hold up
when measured, does not ship. Issues and pull requests are welcome on anything
here.

## Where it stands

| npm tag | Version | Install |
|---|---|---|
| `latest` | 2.1.2 (2026-10-31) | `npx penthera` |

## Now: 2.1.2

2.1.2 is on npm's `latest` tag since 2026-10-31. It's a patch release.

| In 2.1.2 | What it means for you |
|---|---|
| `penthera agents ./some-skill` scans the skill | A folder you name with `SKILL.md` at its root gets the same rules and findings as a skill under `skills/<name>/`. It used to report `Nothing to assess` and read nothing ([docs](docs/commands/agents.md)) |
| A run that fails no longer reads as clean | The exit codes stay the same. The reports now say why a run fails when Penthera's own findings do not explain it ([docs](docs/commands/brief.md)) |
| A run that read no agent config no longer looks clean | The terminal and Markdown reports say this is not a clean result |
| `--repo <missing path>` exits 2 | It used to read as clean and exit 0 |
| `penthera.lock` is never read or written through a symbolic link | A linked lock is reported as a corrupt lock, and `--pin` refuses to follow it |
| `--help` keeps escape codes off a pipe | The help of every command honors `NO_COLOR` and uses color only on a terminal |

## Before: 2.1.1

2.1.1 was on npm's `latest` tag from 2026-10-30. It's a patch release.

| In 2.1.1 | What it means for you |
|---|---|
| MCP `scan_url` stays in scope | On every request and redirect, with or without `--offline`. It refuses any other host and names it under Not checked ([docs](docs/commands/mcp.md)) |
| No grade without agent config | `penthera agents` reports `Nothing to assess` instead of A, 100 ([docs](docs/commands/agents.md)) |
| No false critical on a clean single-page app | The CVE-2025-29927 check now needs its header to steadily change the answer, not a 200 alone. Three more checks ask for proof ([limits](docs/METHODOLOGY.md#what-the-scanners-cannot-see)) |
| Exit 0 says what it means | No critical or high rule fired. The run does not prove login, access rules or payments are right ([docs](docs/before-you-publish.md)) |
| `init` pins the action to v2.1.0 | The old v2.0.0 pin skipped the scan in `mode: deps` and still reported success |

## Before: 2.1.0

2.1.0 was on npm's `latest` tag from 2026-10-29. It went through two release
candidates first.

| In 2.1.0 (rc.2) | What it means for you |
|---|---|
| The agent brief | Your AI assistant gets one short reply after a scan: a verdict, what to act on, what to check first, likely noise, what was not checked. Rules fill it ([docs](docs/commands/brief.md)) |
| Fewer false findings | Style maps are no longer passwords, `eval` in build output is not reported, and action plan steps fit the findings |
| `--giants` merge fix | A key inside a private-key block that two tools find counts once |
| [Pro, an experiment](https://penthera.org/pro) | Does anyone need more than the free agent? The waitlist measures it. Nothing is for sale, and the free tool stays complete |

| In 2.1.0 (rc.1) | What it means for you |
|---|---|
| `--giants` | Runs the free scanners you already have (gitleaks, trufflehog, Semgrep, osv-scanner, pip-audit, trivy, checkov, nuclei, the ZAP baseline) and folds their findings into one report; areas without a tool are reported as not covered ([docs](docs/commands/giants.md)) |
| First-run fixes | The GitHub Action's `mode: deps` scans again (it exited early on 1.5.0 to 2.0.0); nothing unread is reported as clean; a clear message for agents running without a terminal |
| Benchmark pages | [penthera.org/benchmarks](https://penthera.org/benchmarks): every tool, with intervals and caveats, losses included |

## Before: 2.0.0

2.0.0 was on npm's `latest` tag from 2026-10-25. It's a major version because
the default scan finds more, so a CI gate that passed on 1.9 can fail after the
upgrade ([upgrading](CHANGELOG.md)).

| In 2.0.0 | What it means for you |
|---|---|
| Public benchmarks | On a sealed half of four public datasets: 1st on npm and PyPI malware (tied 1st to 3rd), 1st on JS library injection bugs (tied 1st to 4th), 2nd on leaked secrets ([results](bench/public/RESULTS.md)) |
| Library mode | The parameters of an exported function count as untrusted, so command and code injection in npm libraries is found ([docs](docs/commands/scan.md)) |
| More of your repo read for secrets | Key files, PHP, C#, configs, Terraform state; docs and translations with fixed-shape rules only; every line a rule hit is listed |
| Malware detection | Code that runs what it downloads, HTTP tarball dependencies, Python code that runs at import time, `setup.py` payloads |
| Setup per tool | [Penthera in your coding tool](docs/integrations.md): Claude Code, Cursor, VS Code, Codex and nine more, plus Lovable, Bolt, Base44, Replit and v0 |

What 1.9.0 added (the MCP server, opt-in AI mode, signed rule packs) is in the
[CHANGELOG](CHANGELOG.md).

## Next

Ordered, not dated. Each item names the user question it answers.

### This month: upkeep in your own CI

The checks Penthera already does, on a schedule, in your own repository, with a
report you can hand on. Everything stays offline and MIT; no server, no account.

| Item | Question it answers |
|---|---|
| `penthera watch` in the GitHub Action, on a schedule | "Did anything change since last week?" Weekly passive checks of your own live site, plus `deps` and `agents`, reported as a job summary and an issue |
| A readable evidence report | "Can I show a client or an auditor what was checked?" A signed Markdown or PDF summary of an evidence bundle: what was checked, found and fixed |
| `verify` for more AI reviewers | "Which of my AI reviewer's findings are real?" `penthera verify` reads SARIF and the output of Claude Code's `/security-review`, with a small preregistered measurement of how many model findings the rules confirm |
| New-CVE alerts for your SBOM, offline | "Is something I shipped now known to be vulnerable?" Advisories with CISA KEV and EPSS ranking arrive with each release in the signed packs; `watch` compares your SBOM against them |
| A fresh-malware holdout | "Does it catch malware nobody tuned on?" Packages reported after the freeze date, scored once and published whatever the result |
| Setup pages per agent | "How do I use it from Codex, ChatGPT or Cursor?" One page each, next to [Penthera in your coding tool](docs/integrations.md) |

### In the top 10 on every benchmark that fits (research track)

The goal: Penthera benchmarked against the free tools on **every established
public benchmark within its scope**, in the top 10 on each, and #1 where the
data allows, with every result published, losses included.

| Item | Question it answers | State |
|---|---|---|
| E13: the benchmark list and its inclusion rules, written before any run | "Did you only test where you win?" | Planned. In scope: secrets, malicious packages, JS/TS and Python code, passive site checks, MCP and agent config. Java and C benchmarks (OWASP Benchmark, Juliet) are listed as "not supported". The field includes every free tool in scope that runs offline, newer ones too (for example StingWard), whatever their result |
| New benchmarks: SecretBench, Backstabber's Knife Collection, the OpenSSF CVE Benchmark, mcp-vulnbench, MCPTox | "How does it do on data other people chose?" | Planned, same protocol as E11b: sealed half, split by repository, one locked run, leakage audit |
| Fresh holdouts: malware samples published after each freeze date | "Does it catch threats nobody tuned on?" | Planned |
| E12: detection rules learned from large datasets, shipped as readable signed rules | "Does it keep getting better on new threats?" | Planned; tested on a time split (learn from the past, measure on the future) |
| Python code rules | "Does it find bugs in my Python app?" | Planned, moved up: parse Python with its syntax tree rather than patterns, measured on a public Python benchmark in E13 |

### Measure on real code (research track)

| Item | Question it answers | State |
|---|---|---|
| Penthera Bench v1 and experiment E1 | "How accurate is it on code like mine?" | Pre-registered; tooling in review ([#61](https://github.com/danoszz/penthera/pull/61)) |
| Pre-registrations for E2 to E5 | "Will the next feature actually help?" | Drafts in review ([#61](https://github.com/danoszz/penthera/pull/61)) |
| The registered E10 run | "How much does it find in apps it has not seen?" | Pilot published; protocol is a draft ([E10](docs/research/prereg/E10-known-vulnerable-apps.md)) |
| E9: AI mode against rules alone | "Does AI mode find more?" | Planned; AI mode stays opt-in until it is measured |
| Harness audit: a checklist, planned `harness-*`, `sandbox-*` and `scorer-*` rules, experiments E7 and E8 | "Am I running my AI agents properly?" | Specs in review: [checklist](docs/agents-safely.md), [rule spec](docs/research/spec-harness-rules.md), [E8 draft](docs/research/prereg/E8-harness-guardrails.md). No rule code before approval |
| Real-world precision and recall, with intervals | "Can I trust a clean report?" | After E1 runs; published whatever the result |

### One first pass, with the best free tools

A common setup is a list of separate scanners, each with its own install, output
and false alarms. The goal: one `penthera` run covers the whole first pass. Where
Penthera is measured best, its own rules do the work. Where another free tool is
better or covers what Penthera doesn't, Penthera runs that tool, if you have it
installed, and folds its findings into the same report and SARIF. Every finding
names the tool and rule that raised it, duplicates are merged, and the decision
to report stays deterministic.

| Area | Penthera today | Combined with | State |
|---|---|---|---|
| Secrets | F1 0.74 on CredData, ahead of gitleaks (0.52) and trufflehog (0.10) | gitleaks, trufflehog (verifies keys only with your opt-in, since it contacts the provider) | Planned |
| Code | JS/TS injection: 0.70 on SecBench.js, ahead of CodeQL (0.64) and Semgrep (0.38) | Semgrep with local rules, for other languages; CodeQL only where its terms allow (open-source code, or your own licence) | Planned |
| Dependencies | Capabilities, malware (1st on npm and PyPI, tied 1st to 3rd once the uncertainty is counted), licences, typosquats | osv-scanner, pip-audit, for known CVEs in your lockfiles | Planned |
| Infrastructure | Runtime versions pinned in Dockerfiles and version files | trivy (container images, IaC), checkov (Terraform, Kubernetes, CI config) | Planned |
| Live app | Passive checks, Nuclei-compatible templates, `--deep` injection probes | nuclei, the ZAP baseline scan | Planned |
| E14: the combination against each tool alone | "Is the combined report better, or only longer?" | Same protocol as E11b on the same public benchmarks. Combined precision may not drop by more than 0.02 | Pre-registered ([E14](docs/research/prereg/E14-giants-combination.md)); [spec](docs/research/spec-giants.md) approved. Next: the build, then the dev-half rerun |

How it works, and what it won't do:

- **Your tools, not ours.** Penthera finds tools that are already installed.
  It never downloads them or their rules at run time; `penthera init` can show
  the install command. Without a tool, its area is reported as not covered, not
  as clean.
- **Offline stays the default.** A tool that needs the network (a registry
  rule download, key verification) runs only with your opt-in.
- **Licences are respected.** Each tool runs as its own program under its own
  licence. Penthera bundles none of them.
- **Burp stays separate.** Manual, proxy-driven testing by a person is a
  different job, and Penthera is no replacement for a pentest.

### Before you deploy

| Item | Question it answers |
|---|---|
| A confirmation gate and rate limit for active modes | "Can `--deep` hit the wrong host by mistake?" In review ([#95](https://github.com/danoszz/penthera/pull/95)) |
| `penthera ship` | "Is this build safe to ship?" One pass or fail over repo scan, `deps`, `agents` and a localhost or preview scan |
| Preview-deployment scanning | "Is this pull request safe?" A GitHub Action that waits for the Vercel, Netlify or Cloudflare Pages preview, scans it and comments the result |
| Framework presets | "Why is my first scan empty?" Routes, auth flows and headers for Next.js, SvelteKit, Remix, Nuxt and Astro |
| Authenticated preview scans | "Can it test pages behind a login?" With test accounts from your own seed data, never real credentials |
| AI app builder integrations | "I built this in Base44, Lovable or Bolt. Is it safe?" Today: the [setup per builder](docs/integrations.md#app-builders-lovable-bolt-base44-replit-v0) (live check plus GitHub sync). Next: checks for what these tools build |
| Supabase tables without row-level security | "Can anyone read my users' data?" Tables created in migrations or SQL without `enable row level security`, and policies that allow everyone, found in the repo; the public anon key in the frontend is expected, an open table is not |

### After you ship

| Item | Question it answers |
|---|---|
| `penthera watch` | "Did anything change in production?" Scheduled, non-destructive checks for certificate expiry, header and CSP regressions, new endpoints, keys in bundles |
| New-CVE alerts for your SBOM | "Is something I shipped now known to be vulnerable?" As a reviewed rule-pack update or an opt-in advisory lookup |
| Known vulnerabilities ranked by real-world exploitation | "Which of these do I fix first?" CISA's Known Exploited Vulnerabilities list and FIRST's EPSS scores, shipped as data in the signed rule packs so ranking stays offline. Applies to Penthera's runtime advisories and to osv-scanner and trivy findings under `--giants` |
| Alerts where you already look | A GitHub issue, the job summary or a local notification. Nothing leaves your infrastructure |
| Dashboard history | Posture over time in `penthera ui`, fed by `watch` runs |

### Open for contributors

| Item | State |
|---|---|
| JS bundle key scan | Open ([#6](https://github.com/danoszz/penthera/issues/6)) |
| LLM endpoint configuration checks | Parked; needs a narrower design |

## Later

- **Team pack.** Shared policy files, a faster signed rule-pack channel and a
  self-hostable dashboard. The single-machine tool stays complete and MIT.
- **A public, signed registry** of scan results for popular skills and MCP
  servers. It would be a hosted service, so it would live outside the offline
  core, if it happens at all.
- **Earlier candidates:** risk-based prioritization, an MFA probe, a CyFun
  adapter for Belgium, exploit-chain explanations, transitive SBOM entries and
  container images, and an authorized-versus-unauthorized IDOR baseline.

## Not planned

- **Workspace API integrations (Microsoft 365, Google).** They would need OAuth,
  stored tokens and accounts. Running offline with no accounts is a deliberate
  property of this tool.
- **ISO 27001 Annex A mapping.** Mostly organizational controls, and it would
  dilute the NIS2 focus.
- **Telemetry, or an agent that pushes.** No usage data leaves your machine,
  and the fix loop never pushes, opens pull requests or sends your code
  anywhere. You review and push.
- **An LLM judge as the primary detector.** Published bypasses show it can be
  talked out of a finding. Rules decide; a model may only propose.
- **Active scans over MCP.** `penthera mcp` offers passive checks only, because
  it cannot confirm that a person typed the target host.
- **A hosted service.** If a hosted version ever exists, it will not remove
  anything from the local tool.
- **Bundling or auto-installing other scanners.** Penthera runs the ones you
  have installed and reports what is not covered. It ships none of them.

## Principles

- Works offline. Where an online source adds value it stays optional, with a
  local fallback.
- Nothing leaves your machine unless you ask: no telemetry, no auto-push, no
  remote learning.
- Never claims to certify. Output is readiness, evidence and self-assessment.
- Honest about confidence. A heuristic is labelled as one, and accuracy comes
  with an interval.
- Proportionate. A small organization can produce the evidence it needs without
  enterprise overhead.
- Authorized testing only. Anything that touches a third party stays passive
  and uses public data only.

## Shipped

The full history is in the [CHANGELOG](CHANGELOG.md). In short:

| Release | Theme | Highlights |
|---|---|---|
| 1.2.0 | Hardened releases | Trusted publishing with 2FA approval, SHA-pinned CI, CodeQL, OpenSSF Scorecard |
| 1.4.0 | AI toolchain and local loop | `penthera agents`, `penthera.lock`, `deps` and `deps --diff`, typosquat check, `--offline`, the fix loop, the install firewall, the PR-comment Action, evidence bundles, the methodology and benchmark |
| 1.5.0 | AI apps and compliance | Pre-commit hook, license policy, CRA helper and AI-BOM (shipped inside 1.6.0) |
| 1.6.0 | Hardening | Fixes from a full security review, Python `deps`, the internal audit gate, the first dashboard |
| 1.7.0 | One view, one command | The single-view dashboard, the `npx penthera` setup, the APA-cited methodology |
| 1.8.0 | Runtime advisories and review fixes | Runtime advisories, the Simple and Advanced dashboard, fixes from a second independent review, a fix loop that cannot edit its own tests |

1.3.0 was folded into 1.4.0.
