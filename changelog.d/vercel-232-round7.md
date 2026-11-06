section: Security
docs: none, the checks find more and run faster; no flag, output or exit code changes

- **A Python package's file list is read as Python reads it.** A path in RECORD
  with a comma, a doubled quote or text after its quotes was dropped from the
  scan. A row Python can't read leaves the package unscanned, and the run exits 2.
- **A line separator inside a JavaScript string no longer hides code.** The
  dependency scan ended a string at U+2028 or U+2029, so code after it could
  pass as a comment.
- **A pipe into a shell is read once per stage.** Escaped and quoted pipes no
  longer make the check slow, and `X=/usr/bin/timeout bash` is read as an
  assignment and a shell. A long stage is read word by word.
- **Secret redaction runs in one pass.** A finding that quotes a command hides a
  secret percent-encoded twice, and a known secret written out again raw. When
  a file holds too many secret values to check, the quote is withheld.
- **A padded import or destructure no longer hides a shell function.** The
  command-injection check read only the first 2,000 characters of an import
  list, and 400 of a destructure or object. `import { …, exec as runTask }`
  past that was never bound, so `runTask(req.body.c)` passed. Lists are now
  read whole.
