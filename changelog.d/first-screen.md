section: Changed

- **A repo scan opens with its verdict.** In a terminal, `penthera --repo .` starts with one screen: what it
  checked and in how many files, the top three things to act on with where and how to fix each, what it didn't
  check, and one next step, the same as the agent brief's. When nothing is found it says "Nothing found in what
  Penthera checked", where it said "Clean scan, no issues found". Exit codes don't change.
