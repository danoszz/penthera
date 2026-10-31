# AGENTS.md

> **Project page.** For coding agents asking "how do I work on Penthera, or use
> it, without breaking its rules?"

Penthera is an offline, rule-based security agent (MIT, Node.js 22 or later).
Deterministic rules decide every finding. A model may only propose.

## Commands

| Command | What it does |
|---|---|
| `npm install` | Install dependencies |
| `npm test` | The full suite (vitest), including docs-as-tests and the changelog check |
| `npm run lint` | ESLint: unused code, undefined names, unreachable code |
| `npm run audit:internal` | The release gate, written to `audit/REPORT.md`; includes the docs link check |
| `npm run changelog` | Checks every fragment in `changelog.d/` |

Tests must stay offline and parallel-safe: temp dirs, port 0, no real `HOME`.
The details are in [CONTRIBUTING.md](CONTRIBUTING.md#writing-tests-that-stay-reliable).

## Layout

```
bin/          CLI entry points
src/          CLI and orchestration: scan-url, scan-repo, reporter, ui, mcp, agent loop
lib/          the engine: blackbox, whitebox, deps, agents, install, hook, fix,
              advisories, rules, ai, memory, compliance
skills/       the Agent Skill (skills/penthera/SKILL.md)
tests/        vitest suites and fixtures
bench/        the benchmark and the E10 known-vulnerable-apps runner
docs/         user docs (start at docs/index.md); docs/research/ holds research notes
changelog.d/  one changelog fragment per pull request
site/         penthera.org
```

## Rules

1. **Add a changelog fragment** in `changelog.d/` with a `section:` line
   ([format](changelog.d/README.md)). Do not edit `CHANGELOG.md`.
2. **Add the AI-Assisted trailer** to every commit you write. Do not add a
   `Co-Authored-By:` line. CI checks it (`scripts/ci/provenance.mjs`):

   ```
   AI-Assisted: <tool> with <model and version>; <what it did, in one line>
   ```

3. **No version bumps or tags.** Only the maintainer starts a release.
4. **Rules decide.** Do not add a code path where a model's output becomes a
   finding, a fix or an exit code without a deterministic check.
5. **No run-time downloads** of rules, templates or signatures. Rules ship in
   releases.
6. **Only authorized targets.** Scan your own code, loopback, or hosts the
   maintainer named. Never point a scan or a test at a third-party system.
7. **Docs follow the [voice guide](docs/voice.md).** Every command you document
   must exist in `--help`; `npm test` checks it.

## Using Penthera from an agent

Pin the version. `latest` on npm is 2.1.2, with the MCP server, AI mode, library mode and the agent brief.

| Route | Command | Read |
|---|---|---|
| CLI | `npx penthera@2.1.2 --repo .` | [scan](docs/commands/scan.md) |
| Agent Skill | `npx skills add danoszz/penthera` | [skill](docs/commands/skill.md) |
| MCP server | `claude mcp add penthera -- npx -y penthera@2.1.2 mcp` | [mcp](docs/commands/mcp.md) |

The MCP tools are read-only, read only inside your project, never apply fixes
and run no shell. `scan_url` is passive and reaches only loopback or hosts the
user listed with `--allow-host`. A redirect may also move within the target's
registrable domain.
