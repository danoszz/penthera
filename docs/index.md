# Penthera documentation

Lightweight security scanner for developers — scan live URLs, local repos, or macOS machines from the CLI.

## Getting started

| Guide | Description |
|-------|-------------|
| [README](../README.md) | Install, quick start, ethical use |
| [Run it](../README.md#run-it) | Install + first-time wizard (`penthera` with no args) |
| [CHANGELOG](../CHANGELOG.md) | Version history |

## Scanning

| Topic | Link |
|-------|------|
| Scan profiles | `quick` · `standard` · `deep` — see `--profile` in `penthera --help` |
| Authenticated scans | `--auth-cookie`, `--auth-bearer`, `PENTHERA_BEARER` env |
| Adaptive probes | `--adaptive` — knowledge-graph-driven escalation on live routes |
| Custom templates | `--templates ./my-templates` — Nuclei-compatible YAML dirs |
| Baseline diff | `--baseline reports/previous.json` |

## Reports

| Format | Flag |
|--------|------|
| Markdown | `-o report.json` (auto `.md`) or `--markdown report.md` |
| JSON | `-o report.json` or `--json` |
| SARIF | `--sarif results.sarif` — GitHub Security tab |

## Standards & CI

| Topic | Link |
|-------|------|
| OWASP WSTG mapping | [owasp-wstg-coverage.md](./owasp-wstg-coverage.md) |
| GitHub Actions CI | `.github/workflows/ci.yml` (mock scan + SARIF) |
| Staging scans | `.github/workflows/scan.yml` — set `PENTEST_STAGING_URL` secret |
| Docker | `docker build -t penthera . && docker run penthera https://localhost:3000` |

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
