section: Security

- **Penthera checks every pull request from a fork before CI runs.** A new workflow reads the changed files as data, without installing or running anything from the pull request, runs Penthera on them, and labels the PR `standard-paths` or `needs-maintainer-review` (for changes to CI, install or agent files). A maintainer approves the full CI run after reading its comment. CONTRIBUTING.md describes it.
