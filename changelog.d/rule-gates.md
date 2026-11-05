section: Detection
docs: none, rule fixes that close bypasses; no flag, output field or doc changes

- **A byte-order mark no longer hides a config or a lock file.** Agent configs,
  `package.json`, lock files and `penthera.lock` that start with a BOM are now
  read, as VS Code, npm and Node tools read them.
- **A key written with `\u` escapes is found.** The secret scan also reads the
  text with printable `\uXXXX` escapes decoded, so `"sk_live_…"` and a
  service-account file with escaped keys are caught.
- **`fetch(url).then(r => r.text()).then(eval)` is a remote eval.** Passing
  `eval` as a callback no longer slips past `agents/js-eval-remote`.
- **The eval and exec check says when it stops.** It reads at most 5,000 code
  files; past that it now adds an info note, and Coverage lists the unread
  files instead of counting them as examined.
- **A rule gate in the tests.** Every rule is read from the code and must be
  fired by a fixture, high and critical findings must reach the exit code, and
  readers that skip input must leave a trace. Today's gaps are listed with a
  reason and can only shrink. Same-meaning tests rewrite each bad fixture
  (CRLF, BOM, key order, escapes, comments, long lines) and expect the same
  findings.
