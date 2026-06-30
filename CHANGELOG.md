# Changelog

All notable changes to Penthera are documented here. Versioning follows [SemVer](https://semver.org/).

## [1.0.0] — 2026-06-30

First production-ready release.

### Added

- PostHog-style interactive onboarding (`penthera` with no args, `penthera-scan`)
- Scan profiles: `quick`, `standard`, `deep`
- Markdown reports with OWASP WSTG coverage section
- Session-aware scanning (`--auth-cookie`, `--auth-bearer`, `PENTHERA_*` env)
- JWT, IDOR/BOLA, OAuth, client-side auth, and security header probes
- Secret scanning and Express/Hono/Fastify route discovery in repo mode
- Baseline diff mode (`--baseline`)
- Adaptive probe engine in CLI (`--adaptive`)
- Plugin/templates API (`--templates`, `lib/plugins.js`, programmatic exports)
- Agent Skill (`skills/penthera/`) with preflight and report validation scripts
- CI scan job with mock server, SARIF upload, and skill validation
- Staging URL workflow (`.github/workflows/scan.yml`)
- Docker image (`Dockerfile`)
- Documentation hub (`docs/index.md`, `docs/owasp-wstg-coverage.md`)

### Fixed

- URL trailing-slash normalization (double-slash 404 bug)

## [0.2.0] — 2026-04

- Markdown reports, scan profiles, auth tooling, expanded API discovery

## [0.1.x] — 2026-04

- Initial CLI: URL, repo, and machine scan modes
- Built-in templates, TLS, CORS, SARIF export

[1.0.0]: https://github.com/danoszz/penthera/compare/v0.2.0...v1.0.0
