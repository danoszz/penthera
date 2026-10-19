# Commands

One page per command, with every flag that matters and an example. The
[README](../../README.md) has the short version; `penthera <command> --help`
has the full flag list.

| Command | Page | What it does |
|---|---|---|
| `penthera <url>`, `--repo .` | [scan.md](scan.md) | Scan a running app and its source: modes, profiles, outputs, exit codes, CI |
| `penthera agents` | [agents.md](agents.md) | Audit skills, MCP servers, hooks, plugins and rule files |
| `penthera deps` | [deps.md](deps.md) | What each package can do, the upgrade diff, typosquats, license policy |
| `penthera install` | [install.md](install.md) | Check a new package before any install script runs |
| `penthera fix`, `penthera agent --loop` | [fix.md](fix.md) | Deterministic fix recipes and the local scan, fix, verify loop |
| `penthera hook` | [hook.md](hook.md) | Pre-commit hook for secrets, agent config and dependency changes |
| GitHub Action | [action.md](action.md) | The capability diff as a pull-request comment, plus SARIF |
| Agent Skill | [skill.md](skill.md) | Let Claude Code, Cursor and other agents drive Penthera |
| `penthera ui` | [dashboard.md](../dashboard.md) | The local dashboard: posture, findings, history, evidence, and the fix loop from the page |

Compliance flags (`--framework nis2`, `--readiness`, `--cra`, `--aibom`, ...)
are covered in [compliance-nis2.md](../compliance-nis2.md) and
[compliance-cra.md](../compliance-cra.md). Reports and evidence bundles are in
[evidence.md](../evidence.md). Network use and `--offline` are in
[privacy.md](../privacy.md).
