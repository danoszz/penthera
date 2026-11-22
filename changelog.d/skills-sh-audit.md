section: Docs

- **The skill reads its reference files from its own folder only.** It no
  longer tells an agent that a copy without the folder can use the same files
  from GitHub; if the folder is missing, the agent skips them. That fallback
  was Snyk's W012 warning on skills.sh.
- The Semgrep comparison cites Semgrep's docs through `semgrep.dev/docs/…`,
  which redirects to the same pages. The `docs.semgrep.dev` links were flagged
  by a reputation scanner in skills.sh's Gen Agent Trust Hub audit, a false
  positive by that audit's own analysis.
