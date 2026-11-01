---
title: "Claim map"
sidebarTitle: "Claim map"
description: "Each headline claim in the README and on penthera.org, and the test that holds it."
---

> **Project page.** For "which test holds this claim?"

Each row is a claim we make in public, the file that makes it, and the test that
holds it. `npm test` fails if the text leaves that file, or if the test is
renamed, removed, commented out or skipped, alone or with its group. If you
change a claim, change its row.

This checks the link, not the test's strength. A review still has to ask whether
the test proves the claim, and it can't see a skip decided at run time, such as
a test behind an `if`. The Limit column says what the test doesn't cover.
This is a short list of headline claims, not every sentence in the docs.

| Claim | Where | Held by | Limit |
|---|---|---|---|
| **132** readable rules | `README.md` | `tests/claims.test.js`: `README and site quote the same rule total` | Counts rules, not what they catch |
| **6** read-only MCP tools | `README.md` | `tests/mcp-e2e.test.js`: `lists six read-only tools` | None |
| **1** runtime dependency | `README.md` | `tests/claims.test.js`: `package.json has one runtime dependency` | Direct dependencies only |
| **0** requests past loopback in the benchmark | `README.md` | `tests/bench.test.js`: `stays above the CI floor and makes no non-loopback requests` | The bundled benchmark only |
| no telemetry | `README.md` | `tests/egress.test.js`: `lists recon sources and Retire.js mirrors, falls back to the snapshot` | Covers one online URL scan, not every command |
| it contacts only the target you named | `site/index.html` | `tests/egress.test.js`: `profile ${name}: only the target host is contacted` | URL scans with `--offline` |
| Default scans send no attack payloads. | `README.md` | `tests/login-probes.test.js`: `a default (standard) scan sends no injection strings anywhere, and one login POST` | Against the mock server |
| confirmation bound to the target | `README.md` | `tests/active-gate.test.js`: `a --confirm-target for another host is refused` | None |
| is rate-limited | `README.md` | `tests/active-gate.test.js`: `defaults to the active rate only for active scans; 0 means no limit` | Checks the default, not the rate on the wire |
| including `'; DROP TABLE users; --` | `docs/commands/scan.md` | `tests/claims.test.js`: `--fuzz sends the DROP TABLE string the docs name` | None |
| `DELETE`, `PUT`, `PATCH`, `POST` and `GET` to up to 15 routes | `docs/commands/scan.md` | `tests/claims.test.js`: `--adaptive sends DELETE to a route that does not declare it` | Holds the `DELETE` case, not the 15-route cap |
| asks before every change by default | `README.md` | `tests/agent.test.js`: `asks for every diff by default: n declines for the run, quit stops` | None |
| never pushes or opens pull requests | `README.md` | `tests/agent.test.js`: `rejects push, fetch, pull, remote, clone, ls-remote, submodule and other non-local git` | Checks the `git` commands the loop allows |
| a deterministic re-scan and your tests decide | `README.md` | `tests/agent.test.js`: `reverts a fix whose verification fails and records fix_failed` | None |
| as signed, versioned | `README.md` | `tests/rule-packs.test.js`: `refuses a pack.json changed after signing (signature mismatch)` | Signature checks only |
| No run logs in, so it doesn't cover login or access rules | `README.md` | `tests/claims.test.js`: `no E10 run logs in` | Holds that no run logs in. That the answer keys score no login or access item comes from the results file |
| 1st on npm and PyPI malware | `README.md` | `tests/bench-summary.test.js`: `README.md carries the summary publish.mjs writes, unchanged` | Checks the copy, not the score |
| read only inside your project | `site/index.html` | `tests/mcp-tools.test.js`: `refuses paths outside the workspace: parent, absolute and through a symlink` | None |
| reaches only loopback or hosts the | `AGENTS.md` | `tests/mcp-scope.test.js`: `refuses other hosts, on a first request and on a redirect` | None |
