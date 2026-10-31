---
title: "Install firewall: penthera install"
sidebarTitle: "Install firewall"
description: "penthera deps tells you what changed after the fact."
---

> **Starter.** For "is this package safe to add?"

### Install firewall: `penthera install`

`penthera deps` tells you what changed after the fact. `penthera install` asks
before anything runs:

```bash
penthera install left-pad             # check, then install (asks if the policy says so)
penthera install -D vitest --dry-run  # report only
penthera install --yes                # CI: install only if nothing breaches the policy
```

```
  ▲ color-helper 1.0.0 → 1.1.0  + install script
      postinstall: node postinstall.js

  Policy    defaults (no penthera.policy.json)
  ! color-helper@1.1.0  needs approval: install script

  Install anyway? [y]es, run the install scripts / [s]kip scripts / [N]o:
```

1. npm resolves the new tree in a temporary copy of `package.json` and the
   lockfile, with scripts off (`npm install --package-lock-only --ignore-scripts`).
2. New tarballs are fetched with `npm cache add`. Nothing is unpacked into
   `node_modules` and no package code runs; each tarball is checked against
   the proposed lockfile's integrity before it is read.
3. The `deps` engine diffs capabilities against your current lockfile, lists
   new install scripts with their commands, and checks new names for typosquats.
4. `penthera.policy.json` decides. On approval, the reviewed lockfile is
   installed as is, with `--ignore-scripts` unless you approved the scripts
   (on npm 12+, approved scripts are pinned in `package.json` `allowScripts`).
   On abort, exit code 1, and the project is byte for byte unchanged.

```json
{
  "allow": ["@acme/*", "esbuild", "sharp@0.33.5"],
  "deny": ["ai-cli-invoke", "token-harvest"],
  "requireApproval": ["install-scripts", "startup-hook", "ai-config-write",
                      "ai-cli-invoke", "token-harvest", "obfuscated", "typosquat",
                      "unscanned"]
}
```

`deny` and `requireApproval` take capability ids from the [capability table](deps.md)
(`install-scripts`, `shell`, `network`, `env-bulk`, `obfuscated`, ...) plus
`typosquat` and `unscanned`. The `requireApproval` list shown is the default.
`allow` takes names or globs, optionally pinned to a version, and overrides
both, except two floors: `script-mismatch` is always denied, and `unscanned`
always needs approval. The one network use is npm talking to your configured registry, and
Penthera prints which one; Penthera itself sends nothing. Workspaces and
`file:` dependencies are not supported yet.

Other flags: `--dir <path>`, `--policy <file>`, `-D, --save-dev`,
`-E, --save-exact`, `--offline` (npm cache only), `-v, --verbose`, `--json`, and
`--allow-non-registry` to accept git and tarball-URL packages, which are refused
by default.

[Back to the README](https://github.com/danoszz/penthera/blob/main/README.md) · [All commands](https://github.com/danoszz/penthera/blob/main/docs/commands/README.md)
