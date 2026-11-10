# Commands

> **Pro.** For "which command and flag do I need?"

One page per command, with the main flags and an example. The
[README](../../README.md) has the short version; `penthera <command> --help`
has the full flag list.

| Command | Page | What it does |
|---|---|---|
| `penthera`, `penthera init` | [init.md](init.md) | Set up in one command: detect, check, then hook, workflow and dashboard |
| `penthera <url>`, `--repo .` | [scan.md](scan.md) | Scan a running app and its source: modes, profiles, outputs, exit codes, CI |
| `penthera agents` | [agents.md](agents.md) | Audit skills, MCP servers, hooks, plugins and rule files |
| `penthera diff` | [diff.md](diff.md) | Only the findings your branch added, against the merge-base with main |
| `penthera deps` | [deps.md](deps.md) | What each package can do, the upgrade diff, typosquats, license policy |
| `penthera install` | [install.md](install.md) | Check a new package before any install script runs |
| `penthera fix`, `penthera agent --loop` | [fix.md](fix.md) | Deterministic fix recipes and the local scan, fix, verify loop |
| `penthera --repo . --ai`, `penthera ai` | [ai-mode.md](../ai-mode.md) | Opt-in AI mode: a local model proposes, Penthera's rules check; asks every run |
| `--giants`, `penthera giants` | [giants.md](giants.md) | Run the free scanners you have installed (gitleaks, Trivy, Semgrep, ...) and fold their findings into one report |
| `penthera verify` | [verify.md](verify.md) | Check findings from an AI audit (Cloudflare's security-audit skill) against Penthera's rules |
| `penthera hook` | [hook.md](hook.md) | Pre-commit hook for secrets, agent config and dependency changes |
| `penthera rules list`, `penthera rules verify <dir>` | [rule-packs.md](../rule-packs.md) | Signed, versioned rule packs (IOCs, patterns); add your own with `--rules <dir>`, never fetched |
| GitHub Action | [action.md](action.md) | The capability diff as a pull-request comment, plus SARIF |
| Agent Skill | [skill.md](skill.md) | Let Claude Code, Cursor and other agents drive Penthera |
| `penthera brief`, `--brief` | [brief.md](brief.md) | One short, fixed-shape summary of one or more scans for your AI assistant to pass on |
| `penthera mcp` | [mcp.md](mcp.md) | Penthera as an MCP server: six read-only tools your agent can call |
| `penthera memory` | [local-loop.md](../local-loop.md#the-learning-store) | What the local store remembers: show, verify, forget, suppress |
| `penthera evidence verify` | [evidence.md](../evidence.md) | Check a signed evidence bundle against its manifest |
| `penthera ui` | [dashboard.md](../dashboard.md) | The local dashboard: one view with projects, findings, side cards, and the fix loop from the page |

Compliance flags (`--framework nis2`, `--readiness`, `--cra`, `--aibom`, ...)
are covered in [compliance-nis2.md](../compliance-nis2.md) and
[compliance-cra.md](../compliance-cra.md). Reports and evidence bundles are in
[evidence.md](../evidence.md). Network use and `--offline` are in
[privacy.md](../privacy.md).
