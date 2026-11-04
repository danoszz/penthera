section: Fixed
docs: none, the lock format is unchanged; Windows now writes the same keys as Linux and macOS

- **A `penthera.lock` pinned on Windows now matches on Linux and macOS, and the other way round.** On Windows, `penthera agents --pin` wrote keys such as `skill:.claude\skills\demo`, so a lock committed from one OS reported every skill and MCP server outside the repo root as new on the other. Keys and report paths inside the repo now always use `/`. If you pinned on Windows before, run `penthera agents --pin` once more.
