# Contributing to Penthera

Thanks for helping make Penthera better. This guide covers local setup, how the
project is organized, and the release/publishing checklist for maintainers.

By participating you agree to keep things respectful and to use the tool only
for **authorized** security testing (see [README — Ethical use](README.md#ethical-use--authorization)).

Looking for a first task? Pick an issue labelled
[`good first issue`](https://github.com/danoszz/penthera/labels/good%20first%20issue),
or search the code for `TODO(good-first-issue)`: each marks a small, scoped
change. Maintainers: see [docs/marketing.md](docs/marketing.md#contributor-flywheel).

---

## Development setup

```bash
git clone https://github.com/danoszz/penthera.git
cd penthera
npm install
npm test          # full suite (vitest)
npm link          # optional: expose `penthera` globally for manual testing
```

Node 22+ is required (see `.nvmrc` for the pinned version).

### Test suites

| Command | What it covers |
|---------|----------------|
| `npm test` | Everything (vitest) |
| `npm run pentest:mock` | Tests against the local mock vuln API |
| `npm run pentest:adaptive` | Knowledge-graph adaptive probes |
| `npm run pentest:wstg` | OWASP WSTG mapping |
| `npm run pentest:live` | Live playbooks — opt-in: needs `pentest.config.js` or `PENTEST_BASE_URL` + a running server |
| `npm run mock-server` | Start the mock API on port 8765 |
| `npm run audit:internal` | The release gate: every check above and more, written to `audit/REPORT.md` ([docs/internal-audit.md](docs/internal-audit.md)) |

CI runs the full `npm test` suite on Node 22 and 24, checks that every version
string is in sync, and self-scans the mock server (`.github/workflows/ci.yml`).
CodeQL and OpenSSF Scorecard run on their own workflows. Keep new tests offline:
no test may reach the public internet, so CI stays deterministic.

---

## Project layout

```
bin/                CLI entry points (penthera.js, scan.js)
src/
  cli/              profiles, baseline, onboarding, run-scan, ansi, prompt
  report/           markdown.js (human-readable reports)
  utils/            url, http, auth
  scan-url.js       black-box orchestrator
  scan-repo.js      white-box + secret scanning
  reporter.js       terminal, JSON, SARIF output
lib/
  blackbox/         headers, openapi, client-auth, jwt, idor, oauth, email-dns, adaptive-scan
  whitebox/         secrets scanner (incl. AI provider keys), route discovery, SBOM
  compliance/       NIS2 readiness, self-assessment, policy pack, incident, questionnaire
  remediation/      fix playbook and prioritised action plan
  jurisdictions/    per-country config (nl.json)
  owasp-wstg.js     WSTG v4.2 probe mapping
  provenance.js     confidence + provenance on every finding
  audit-loop.js     remediation history, time-to-fix
  plugins.js        templates/plugins API (also exported from the package)
skills/penthera/    Agent Skill (SKILL.md, references/, scripts/)
docs/               documentation hub
tests/              vitest suites + fixtures/mock-server.js
```

`src/` is the CLI/orchestration layer; `lib/` is the scanner engine. The package
re-exports engine pieces via `exports` in `package.json`
(`penthera/plugins`, `penthera/adaptive`, `penthera/wstg`).

---

## Adding a probe or template

- **New black-box check:** add a module under `lib/blackbox/`, wire it into
  `src/scan-url.js`, and map it to an OWASP WSTG id in `lib/owasp-wstg.js`.
- **New custom template:** Penthera loads Nuclei-compatible YAML. Point users at
  a directory with `--templates ./dir` or call `loadTemplatesFromPaths()` from
  `penthera/plugins`.
- Every finding needs a `severity`, `title`, `target`, and a remediation hint so
  reports stay actionable. Add a test (prefer the mock server over live hosts).
- **Say where the technique comes from.** In the PR, give the source (paper,
  advisory, OWASP or MITRE ATLAS entry, incident write-up) and the date. If the
  finding uses a new `category`, map it to 1-3 entries in `lib/references.json`,
  adding any new entry to `docs/references.bib` only after checking it against
  the publisher, then run `node scripts/build-references.mjs`.
- **Add a benchmark case.** A labelled true positive in `bench/`, plus a decoy
  where a false positive is plausible, then `npm run bench` and commit the
  updated `bench/RESULTS.md`. See [bench/README.md](bench/README.md).
- Rules ship in releases only. Do not add code that downloads rules,
  templates or signatures at run time
  ([why](docs/METHODOLOGY.md#how-new-attack-techniques-are-adopted)). The
  Retire.js database download is the one existing exception, documented in
  [METHODOLOGY.md](docs/METHODOLOGY.md#offline-and-no-telemetry).

---

## Pull requests

1. Branch from `main`.
2. Keep changes focused; add or update tests.
3. Run `npm test`; it must be green on Node 22+.
4. Update `CHANGELOG.md` and relevant docs.
5. Sign off every commit (see below).
6. Open the PR with a clear description and rationale.

### Sign off your commits (DCO)

Penthera uses the [Developer Certificate of Origin 1.1](https://developercertificate.org/).
By signing off a commit you certify that you wrote the change, or otherwise
have the right to submit it under the project's MIT licence. Add the sign-off
with `-s`:

```bash
git commit -s -m "fix: describe the change"
```

This adds a line like `Signed-off-by: Your Name <you@example.com>` to the
commit message. It must match the commit author. To sign off commits you
already made on your branch, run `git rebase --signoff main` and force-push.

If an AI assistant helped write a change, say so with a `Co-Authored-By:`
trailer naming the tool. You are still the one signing off, so review the
change as your own before you do.

Report security issues in Penthera itself privately — see [SECURITY.md](SECURITY.md).

---

## Cutting a release

Publishing is automated and two-step. Pushing a `v*` tag runs
`.github/workflows/publish.yml`, which tests, checks the tag against
`package.json`, **stages** the package on npm with provenance (trusted
publishing, no token), and creates the GitHub Release. The version only goes
live once a maintainer approves it with 2FA. **Do not run `npm publish` locally.**

1. Bump the version everywhere it appears. CI fails if they drift:
   - `package.json` and `package-lock.json` (`npm version X.Y.Z --no-git-tag-version`)
   - `skills/penthera/SKILL.md` (`metadata.version`)
   - `.claude-plugin/plugin.json` (`version`)
   - `.claude-plugin/marketplace.json` (`metadata.version`)
   - `CITATION.cff` (`version`)
2. Move the `[Unreleased]` notes in `CHANGELOG.md` under the new version.
   Refresh the typosquat list with `npm run refresh:popular` and commit
   `lib/deps/popular-packages.json` if it changed (the only time it is fetched).
3. Run the internal audit on the release branch: `npm run audit:internal`.
   **It must pass.** Commit the regenerated `audit/REPORT.md` with the release
   and read its "Changes since the previous report". A new self-scan finding
   is fixed, or accepted in `audit/baseline.json` with a reason in review;
   never by loosening a threshold to make the gate pass.
4. Merge to `main` through a PR so CI runs.
5. Tag the merge commit and push the tag: `git tag vX.Y.Z && git push origin vX.Y.Z`.
   Do not tag a commit whose audit failed.
6. Approve the staged version with 2FA: npmjs.com → penthera → Staged Packages →
   Approve, or `npm stage list penthera` and `npm stage approve <stage-id>`.
   Check the file list and provenance before you approve.
7. Optional: `npm run package:skill` and attach the zip to the release for
   Claude.ai uploads.
