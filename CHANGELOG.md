# Changelog

All notable changes to Penthera are documented here. Versioning follows [SemVer](https://semver.org/).

## [Unreleased]

## [1.1.1] - 2026-08-16

A correctness release. One of these was a live outage: if you are on 1.1.0,
upgrade.

### Fixed

- **JS dependency scanning was silently dead.** The Retire.js vulnerability
  database URL pointed at a fork that now returns 404, so every scan reported
  "no vulnerable JS libraries" without ever running the check. It now reads from
  upstream RetireJS with a mirror, validates the payload, and when no source is
  reachable it says the check did not run instead of returning a clean result.
  The probe is also excluded from coverage in that case, so a compliance report
  cannot claim supply-chain evidence that was never collected
- **Command injection in the machine audit.** Binary paths read from
  attacker-writable plists were interpolated into a shell string, so a malicious
  persistence entry could execute code inside the scanner. Paths are now argv
  entries and signature checks use the exit status, failing closed
- Two built-in templates fired on any single-page app with catch-all routing:
  the `.env.local` matcher accepted a bare `=` (present in every HTML attribute)
  and the Firebase one accepted any 200 without the word "error", so an
  `index.html` served at those paths was reported as critical
- Time-based SQL and command injection no longer report on a single slow
  response. A candidate delay is re-sampled and only reported when the median
  holds, which a garbage-collection pause or cold start does not survive
- Community template regexes ran unbounded against whole response bodies. A
  catastrophically-backtracking pattern would hang the scanner; patterns with
  nested quantifiers are now refused and input is capped
- Dedupe and baseline comparison used different keys that included severity, so
  re-rating a finding reported it as one resolved plus one new. Both now share
  the audit loop's fingerprint
- A measure with nothing scanned and nothing attested was scored as a gap,
  telling an entity that had not yet filled in the self-assessment that it had
  failed. That state is now reported as not assessed
- The XSS canary was a fixed, fingerprintable string; it is now randomised per
  probe
- XProtect staleness was computed and discarded; it is now reported

### Changed

- The Nuclei loader documents the subset it actually implements and reports per
  template which unsupported features it needs, instead of letting a template
  that cannot match look like a clean pass
- Provenance (confidence, method, collection time) now travels into SARIF, and
  the terminal marks findings a scanner cannot adjudicate

## [1.1.0] - 2026-08-16

NIS2 / Cyberbeveiligingswet readiness work: a hardening pass over the
open-source core, a full offline NIS2 readiness toolkit, and a humanizing pass
that removed AI-writing tells (em dashes and so on) from all public-facing text
and generated documents.

### Added

- **Customer security-questionnaire answerer** (`--questionnaire <file>`): reads a
  questionnaire (one question per line) and drafts an answer for each from the
  readiness evidence, citing the Article 21 measure and what backs it (scan
  probe or attestation). Anything it can't map is marked NEEDS HUMAN INPUT
  rather than guessed. Writes `questionnaire-response.md`
- **Attack chains surfaced in reports**: the adaptive engine's knowledge graph
  already correlated findings (for example an auth bypass that combines with an
  IDOR into cross-user access) but the result was computed nowhere. Chains now
  appear as findings with their path
- **Provenance + honest confidence on every finding**: each finding carries
  `{ source, method, collected_at, confidence }`, with confidence labelled
  `confirmed` / `likely` / `potential` / `needs-human-review` so a heuristic
  isn't presented as a certainty. Shown in the report's Confidence column and in
  JSON (`lib/provenance.js`)
- **Supplier passive rating** (`--suppliers <file>`): point Penthera's passive
  checks (homepage security headers, TLS certificate, SPF/DMARC/MX via DNS) at
  your own suppliers' public domains and get a red/amber/green posture per
  supplier, supply-chain risk screening (measure d). Strictly passive,
  public-data-only, non-intrusive, and documented as such; not a pentest of the
  supplier
- **Remediation / audit-loop tracking** (`--history <file>`): folds each scan's
  findings into a persistent history keyed by a stable fingerprint (severity-
  and count-independent), and reports open vs resolved, median time-to-fix,
  ageing buckets, and drift since last scan, the effectiveness evidence for
  measure f, and a "close the loop" counter to noisy discovery-only scanning
- **SBOM output** (`--sbom <file>`): generates a CycloneDX 1.5 software bill of
  materials from `package-lock.json` / `package.json` / `requirements.txt`,
  offline, with resolved versions and purls. Supply-chain evidence (measure d)
  and the artifact enterprises increasingly require of suppliers
- **Incident-report helper** (`--incident <file>`, `--incident-init` to scaffold):
  computes the NIS2 reporting deadlines (24h early warning / 72h notification /
  1-month final report) from when you became aware, flags overdue ones, and
  drafts each report against the jurisdiction's required content, with
  `NEEDS INPUT` markers for facts you still have to supply. Offline; drafts to
  help meet the deadlines, not a substitute for the authority's official form
- **Policy-pack generator** (`--policy-pack <dir>`): writes proportionate,
  editable Markdown starting points for the core policies NIS2 expects
  (information security, access control, incident response, backup/continuity,
  acceptable use, supplier security, vulnerability management). Pre-filled from
  the jurisdiction's incident deadlines and the readiness gaps; clearly labelled
  as templates, not legal advice
- **NIS2 readiness report** (`--readiness`): combines scan evidence with an
  offline **self-assessment** (`--assessment-init` to scaffold, `--assessment` to
  supply) into a per-measure `met / partial / gap / n-a` report across all ten
  Article 21 measures, with proportionality notes, the jurisdiction's
  incident-reporting deadlines, and **provenance** (`source, method, collected_at,
  confidence`) on every piece of evidence. Writes `<output>-readiness.md`. Works
  offline; jurisdiction data is config (`lib/jurisdictions/nl.json`, NL today)
- Remediation action plan: the report (terminal-adjacent Markdown + JSON
  `actionPlan`) now includes a prioritised, owner-actionable plan, what, why,
  how to fix, rough effort, and whether it's a code change or an owner action
  (rotate a secret, renew a cert, change DNS), replacing the old generic
  recommendations list. Built from a remediation knowledge base (`lib/remediation`)
- Agent Skill Workflow 5 + `references/reporting.md`: generate owner-facing
  documents from a scan, a remediation plan, a prefilled security-questionnaire
  response, and a NIS2 duty-of-care evidence summary, grounded in scan evidence,
  with unbacked/organisational items marked `NEEDS HUMAN INPUT` (never fabricated)
- Email authentication probe (SPF, DMARC, MX via DNS), new `lib/blackbox/email-dns.js`,
  runs in the standard profile for public domains. Flags missing/permissive SPF,
  missing or monitoring-only (`p=none`) DMARC, and nudges DKIM verification. A
  questionnaire staple that was previously uncovered
- `--framework nis2` compliance report mode: a per-scan NIS2 Article 21 coverage
  table (which measures this scan actually exercised, driven by the probes that
  ran) added to the terminal, Markdown, and JSON reports. Frameworks are
  declarative so national transpositions and other regimes can be added as data
- NIS2 / cyberwetgeving compliance section in the README: Article 21(2)(a-j)
  mapped to what Penthera actually tests, with a coverage key and a clear
  "not legal advice / not a certification" disclaimer
- Code of Conduct (Contributor Covenant 2.1), issue templates, and PR template
- `tests/detection-hardening.test.js` covering the secret-scan and SSTI fixes

### Fixed

- Interactive onboarding now attaches the remediation action plan to its report,
  matching the main CLI path (the two had drifted)
- Audit-loop fingerprint no longer merges genuinely distinct findings. Collapsing
  every digit run made different ciphers, TLS versions, library versions, API
  versions, and per-CVE findings look like one item, which distorted the
  measure-f numbers. It now collapses only numeric URL path segments and
  separates dependency CVEs by description
- `updateHistory` no longer mutates the history object passed to it
- Jurisdiction data is loaded once instead of re-read per document
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
  (3xx), 404, or 405, not a real login handler, removing a false "no login
  rate limiting detected" on redirected paths

### Changed

- Interactive wizard's remote-host permission prompt now defaults to **no**
- README shows the live CI status badge instead of a hand-written test count;
  live integration tests report as skipped (not passed) without a running target
- Corrected the built-in template count (14, not 17) in docs and progress output

## [1.0.0], 2026-06-30

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

## [0.2.0], 2026-04

- Markdown reports, scan profiles, auth tooling, expanded API discovery

## [0.1.x], 2026-04

- Initial CLI: URL, repo, and machine scan modes
- Built-in templates, TLS, CORS, SARIF export

[1.1.1]: https://github.com/danoszz/penthera/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/danoszz/penthera/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/danoszz/penthera/compare/v0.2.0...v1.0.0
