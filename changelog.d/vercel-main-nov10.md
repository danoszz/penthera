section: Security
docs: none, no flag, output or rule changes; the same findings, found in linear time and inside the repository

- **A crafted file can no longer stall the webhook and session-cookie checks.**
  A long chain such as `db . db . db …` made the webhook write check read the
  rest of the chain again from every member, and a very long quoted key made
  the session-cookie check search back through it once per flag. Both now read
  each part once, and the work counts against the file's budget. They report
  the same writes and cookies as before.
- **`penthera diff` no longer follows a link from history out of the
  repository.** If the commit you compare against had a symlink where today's
  folder stands, the baseline scan read the link's target, and what it found
  there could land in the report. A path with a link in it is now not a
  baseline, so every finding in that folder counts as new.
- **A session options object with a key named `constructor` no longer stops
  the scan.** The session-cookie check crashed on keys that share a name with
  a built-in property.
