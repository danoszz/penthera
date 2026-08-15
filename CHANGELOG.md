# Changelog

All notable changes to Penthera are documented here. Versioning follows [SemVer](https://semver.org/).

## [Unreleased]

Open-source-core credibility pass.

### Added

- Remediation action plan: the report (terminal-adjacent Markdown + JSON
  `actionPlan`) now includes a prioritised, owner-actionable plan — what, why,
  how to fix, rough effort, and whether it's a code change or an owner action
  (rotate a secret, renew a cert, change DNS) — replacing the old generic
  recommendations list. Built from a remediation knowledge base (`lib/remediation`)
- Agent Skill Workflow 5 + `references/reporting.md`: generate owner-facing
  documents from a scan — a remediation plan, a prefilled security-questionnaire
  response, and a NIS2 duty-of-care evidence summary — grounded in scan evidence,
  with unbacked/organisational items marked `NEEDS HUMAN INPUT` (never fabricated)
- Email authentication probe (SPF, DMARC, MX via DNS) — new `lib/blackbox/email-dns.js`,
  runs in the standard profile for public domains. Flags missing/permissive SPF,
  missing or monitoring-only (`p=none`) DMARC, and nudges DKIM verification. A
  questionnaire staple that was previously uncovered
- `--framework nis2` compliance report mode: a per-scan NIS2 Article 21 coverage
  table (which measures this scan actually exercised, driven by the probes that
  ran) added to the terminal, Markdown, and JSON reports. Frameworks are
  declarative so national transpositions and other regimes can be added as data
- NIS2 / cyberwetgeving compliance section in the README: Article 21(2)(a–j)
  mapped to what Penthera actually tests, with a coverage key and a clear
  "not legal advice / not a certification" disclaimer
- Code of Conduct (Contributor Covenant 2.1), issue templates, and PR template
- `tests/detection-hardening.test.js` covering the secret-scan and SSTI fixes

### Fixed

- Secret scanner no longer flags dummy/probe credentials (e.g. the
  `invalid-password-12345` payload Penthera flagged on its own repo); rule
  renamed so the title no longer reads "Password in source in source"
- SSTI probe uses a randomized arithmetic canary instead of `7*7=49`, removing
  the critical false positive on any page containing "49"
- Endpoint calibration compares body length to body length (was body vs
  Content-Length), so the noise filter actually filters default/404 pages
- WSTG coverage now reflects the probes that actually ran, instead of asserting
  every profile probe was exercised; dropped two WSTG IDs that were mapped but
  never tested (CRYP-02 padding oracle, CONF-13 path confusion)
- Login "accepts arbitrary credentials" no longer fires on a bare HTTP 200; it
  requires an actual authenticated response (auth cookie or token) for the
  invalid-credential attempt, so SPA logins that return 200 `{success:false}`
  are no longer false-flagged
- Reflected XSS is only reported when the response is served as HTML; JSON/text
  APIs that echo a payload are no longer flagged as XSS
- Removed the fuzzer's prototype-pollution false positive (it fired on any
  object payload returning 200, because `payload.__proto__` is always truthy)
- Open-redirect false positives (found scanning a real Vercel-hosted site): the
  OAuth and injection open-redirect probes now confirm the `Location` actually
  resolves to the attacker's host, instead of substring-matching. A same-site
  apex→www canonicalization that preserves the payload in the query is no longer
  reported as an open redirect. Also removed the redundant, FP-prone
  "open redirect via callback" built-in template
- Login hardening probe no longer runs against a path that returns a redirect
  (3xx), 404, or 405 — not a real login handler — removing a false "no login
  rate limiting detected" on redirected paths

### Changed

- Interactive wizard's remote-host permission prompt now defaults to **no**
- README shows the live CI status badge instead of a hand-written test count;
  live integration tests report as skipped (not passed) without a running target
- Corrected the built-in template count (14, not 17) in docs and progress output

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
