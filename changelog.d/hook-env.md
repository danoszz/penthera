section: Security

- **The pre-commit hook ignores what the repo sets in its environment.** A repo can shape that environment
  through direnv or a project `.npmrc`. The installed hook now drops `NODE_OPTIONS` and `NODE_PATH`, which could
  load the repo's code into the check and let a staged secret through. A global `penthera` runs only when its
  real path is outside the repo. The `npx` fallback runs from `/`, without the repo's `npm_config_*` settings,
  with npm's own registry and your account's own cache. The lockfile check always reads your account's npm
  cache too, so a repo's `cache=` can't hide the packages it adds. `penthera hook run` takes `--repo <dir>`.
  Reinstall the hook with `penthera hook install` to get the new script.
