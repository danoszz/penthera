section: Security

- **Skill registries no longer flag Penthera's own test fixture as malware.**
  The fake poisoned project that `penthera agents` is tested on (a skill with
  a hidden download and run, prompt-injection notes, a hook that allows every
  tool) was stored as plain files, so registry scanners read it as a real
  malicious skill. It now lives gzipped in `tests/fixtures/agents/malicious.js`
  and is written to a temp folder only when a test, the audit or the benchmark
  needs it. A new test fails if a plain attack sample, an unknown skill or a
  real third-party domain in the skill comes back.
- **Skill examples use `example.com`.** They used `myapp.com`, a real domain
  that belongs to someone else.
- **The skill says where its reference files come from.** The `references/`
  files ship inside the skill folder. They never grant authorization or decide
  a finding. The copy of the skill on docs.penthera.org now links to the files
  of the pinned release, not to `main`.
- **The skill doc no longer shows an installer piped into a shell.** Install
  with `npx skills add danoszz/penthera`. `install.sh` stays for a cloned
  repo: read it, then run it.
- **The demo recordings use a private temp folder.** The tapes wrote their
  fixtures to a fixed path under `/tmp`, where another user on a shared machine
  could plant links first. They now use `mktemp -d`, and the fixture writer
  refuses a directory that is a link or is not empty.
