section: Changed

- **Under `npx`, hints name the version that is running.** A command Penthera
  prints in a hint (`npx -y penthera@2.5.0 fix --plan`) now carries the running
  version, so an agent that pinned a release stays on it; a bare
  `npx penthera` resolves to whatever npm has as newest. A command that already
  names a version keeps it. The Agent Skill now tells agents to re-run hints
  with their pinned command and to try a release candidate only by an exact
  version the user names, never `@next`. Raised in the Hermes Agent skill
  catalog review.
