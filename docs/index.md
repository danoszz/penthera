# Penthera documentation

Open-source security for the apps and AI systems you ship: check it before you deploy, vet what you build with, keep watching after you ship. Offline, deterministic, free.

## Getting started

| Guide | Description |
|-------|-------------|
| [README](../README.md) | Install, quick start, ethical use |
| [Run it](../README.md#run-it) | Install + first-time wizard (`penthera` with no args) |
| [Use cases](./use-cases/README.md) | By situation: [before launch](./use-cases/solo-founder.md), [AI-coding teams](./use-cases/ai-coding-teams.md), [maintainers](./use-cases/open-source-maintainers.md), [EU SMEs](./use-cases/eu-sme-compliance.md), [agencies](./use-cases/agencies.md) |
| [Comparisons](./compare/README.md) | Using Penthera with [Socket](./compare/socket.md), [Snyk](./compare/snyk.md), [GitHub](./compare/github.md), [ZAP](./compare/zap.md), [Semgrep](./compare/semgrep.md) |
| [Commands](./commands/README.md) | One page per command: [scan](./commands/scan.md), [agents](./commands/agents.md), [deps](./commands/deps.md), [install](./commands/install.md), [fix](./commands/fix.md), [hook](./commands/hook.md), [action](./commands/action.md), [skill](./commands/skill.md) |
| [CHANGELOG](../CHANGELOG.md) | Version history |
| [Roadmap](../ROADMAP.md), [plan to v2.0](./plan.md) and [release plan](./release-plan.md) | What ships next, in what order, and how quality is measured |

## Scanning

| Topic | Link |
|-------|------|
| Scan profiles | `quick` · `standard` · `deep`, see `--profile` in `penthera --help` |
| Authenticated scans | `--auth-cookie`, `--auth-bearer`, `PENTHERA_BEARER` env |
| Adaptive probes | `--adaptive`, knowledge-graph-driven escalation on live routes |
| Custom templates | `--templates ./my-templates`, Nuclei-compatible YAML dirs |
| Baseline diff | `--baseline reports/previous.json` |

## Reports

| Format | Flag |
|--------|------|
| Markdown | `-o report.json` (auto `.md`) or `--markdown report.md` |
| JSON | `-o report.json` or `--json` |
| SARIF | `--sarif results.sarif`, GitHub Security tab |

## Standards & CI

| Topic | Link |
|-------|------|
| OWASP WSTG mapping | [owasp-wstg-coverage.md](./owasp-wstg-coverage.md) |
| NIS2 compliance guide | [compliance-nis2.md](./compliance-nis2.md) |
| Local loop and learning store | [local-loop.md](./local-loop.md) |
| CRA reporting and AI-BOM | [compliance-cra.md](./compliance-cra.md) |
| Reports and evidence bundles | [evidence.md](./evidence.md) |
| Privacy, network use, `--offline` | [privacy.md](./privacy.md) |
| Local dashboard (`penthera ui`) | [dashboard.md](./dashboard.md) |
| Scan your app in GitHub Actions | [examples/github-actions-scan.yml](./examples/github-actions-scan.yml), set `PENTEST_STAGING_URL` |
| Penthera's own CI | `.github/workflows/ci.yml` (full tests + mock scan), `codeql.yml`, `scorecard.yml` |
| Docker | `docker build -t penthera . && docker run penthera https://localhost:3000` |

## Methodology & research

| Topic | Link |
|-------|------|
| How detection works, confidence model, limits | [METHODOLOGY.md](./METHODOLOGY.md) |
| Cited research and standards | [references.md](./references.md) ([BibTeX](./references.bib)) |
| Accuracy benchmark (`npm run bench`) | [bench/README.md](../bench/README.md), latest [results](../bench/RESULTS.md) |
| Citing Penthera | [CITATION.cff](../CITATION.cff) |
| Refresh the README's numbers | `npm run docs:numbers` (`-- --tests` to count tests) |
| How Socket positions itself, and what Penthera took from it | [research/socket-positioning-notes.md](./research/socket-positioning-notes.md) |

## Agent skill

| Topic | Location |
|-------|----------|
| Skill files | `skills/penthera/SKILL.md` |
| Preflight | `bash skills/penthera/scripts/preflight.sh [URL]` |
| Validate report | `npm run validate:report -- reports/scan.json` |
| Release zip | `npm run package:skill` |

## Programmatic API

```javascript
import { loadTemplatesFromPaths, runTemplateScan } from "penthera/plugins";
import { runAdaptiveProbes } from "penthera/adaptive";
```

See `lib/plugins.js` and `lib/blackbox/adaptive-scan.js` for exports shipped in the npm package.

## Security

Report vulnerabilities in Penthera via [SECURITY.md](../SECURITY.md). Only scan systems you own or have authorization to test.
