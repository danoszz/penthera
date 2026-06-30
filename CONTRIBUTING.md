# Contributing to Penthera

Thanks for helping make Penthera better. This guide covers local setup, how the
project is organized, and the release/publishing checklist for maintainers.

By participating you agree to keep things respectful and to use the tool only
for **authorized** security testing (see [README — Ethical use](README.md#ethical-use--authorization)).

---

## Development setup

```bash
git clone https://github.com/danoszz/penthera.git
cd penthera
npm install
npm test          # full suite (vitest)
npm link          # optional: expose `penthera` globally for manual testing
```

Node 18+ is required (see `.nvmrc` for the pinned version).

### Test suites

| Command | What it covers |
|---------|----------------|
| `npm test` | Everything (vitest) |
| `npm run pentest:static` | Offline unit tests (no network) |
| `npm run pentest:mock` | Tests against the local mock vuln API |
| `npm run pentest:adaptive` | Knowledge-graph adaptive probes |
| `npm run pentest:wstg` | OWASP WSTG mapping |
| `npm run pentest:live` | Live playbooks — needs `pentest.config.js` + a running server |
| `npm run mock-server` | Start the mock API on port 8765 |

CI runs the offline suites on Node 18/20/22 plus a self-scan of the mock server
(`.github/workflows/ci.yml`). Keep new tests offline-friendly so CI stays
deterministic.

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
  blackbox/         headers, openapi, client-auth, jwt, idor, oauth, adaptive-scan
  whitebox/         secrets scanner, framework route discovery
  owasp-wstg.js     WSTG v4.2 probe mapping
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

---

## Pull requests

1. Branch from `main`.
2. Keep changes focused; add or update tests.
3. Run `npm test` — green on Node 18+.
4. Update `CHANGELOG.md` and relevant docs.
5. Open the PR with a clear description and rationale.

Report security issues in Penthera itself privately — see [SECURITY.md](SECURITY.md).

---

## Maintainer notes — skill publishing & discovery

There is **no central approval queue** for Agent Skills. Discovery is
distributed: host the skill in a public repo and make it trivial to install.

**Release checklist:**

1. Make the repo public on GitHub (`danoszz/penthera`).
2. Add GitHub topics: `agent-skills`, `cursor`, `claude-code`, `security`,
   `pentest`, `cli`, `owasp` (Settings → General → Topics).
3. Verify install paths still work:
   - `curl -fsSL .../install.sh | bash`
   - `npx skills add danoszz/penthera`
   - manual copy into `~/.cursor/skills` / `~/.claude/skills`
4. Add a skills.sh badge once indexed:
   `[![skills.sh](https://img.shields.io/badge/skills.sh-penthera-0000ed)](https://skills.sh/danoszz/penthera)`
5. Reference the open standard ([agentskills.io](https://agentskills.io)) in
   release notes.
6. **npm publish** — `skills/` is already in the package `files` array, so
   `npm i -g penthera` ships the skill with the CLI. Run `npm run package:skill`
   to produce the Claude.ai upload zip and attach it to the GitHub Release.

**Skill maturity phases:**

| Phase | Status | What it covered |
|-------|--------|-----------------|
| Phase 1 | Done | `SKILL.md`, references, preflight script, Cursor symlink |
| Phase 2 | Done | `validate-report.mjs`, CI skill validation, OWASP WSTG docs |
| Phase 3 | Done | Bundled in the npm package, release zip, install.sh, production metadata |

---

## Cutting a release

1. Bump `version` in `package.json` and `skills/penthera/SKILL.md`.
2. Update `CHANGELOG.md` (SemVer).
3. Tag: `git tag vX.Y.Z && git push --tags`.
4. `npm publish` (runs `prepack` → tests first).
5. Create the GitHub Release; attach the skill zip.
