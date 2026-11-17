section: Security
docs: none, the skill gains one trust-boundary row and the test fixture moved; no CLI, MCP or rule change

- **Skill registries no longer flag Penthera's own test fixture as malware.**
  The fake poisoned project that `penthera agents` is tested on (a skill with
  a hidden download and run, prompt-injection notes, a hook that allows every
  tool) was stored as plain files, so registry scanners read it as a real
  malicious skill. It now lives gzipped in `tests/fixtures/agents/malicious.js`
  and is written to a temp folder only when a test, the audit or the benchmark
  needs it.
- **The skill says where its reference files come from.** The `references/`
  files ship inside the skill folder and are read from disk, never fetched.
  They never grant authorization or decide a finding.
