section: Fixed

- **`penthera init` pins the current release.** The workflow it writes pins the Action to v2.2.0's commit, and
  the AI tooling workflow runs `npx penthera@<the version you ran>`. It pinned v2.1.2, whose `deps` can stall on
  big bundles under Node 22.
- **The fix window shows what you approve.** A context line is hidden only when it holds a value that could be a
  secret, not because it quotes a sentence or mentions `password`. A changed line keeps its error message,
  where the secrets recipe's own `throw new Error("Set STRIPE_SECRET …")` used to show as `"***"`.
- **The install matrix tests a real upgrade.** Its upgrade job installs the previous minor release (2.1.2 for
  2.2.x, from `scripts/ci/upgrade-from.mjs`) and names it. It read "from 1.9.0" while it reinstalled 2.2.0.
- **Dependabot's pin bumps can merge.** The provenance and docs checks pass a pull request only when GitHub
  verifies every commit as Dependabot's and it touches nothing but dependency pins. Everything else stays
  strict.
