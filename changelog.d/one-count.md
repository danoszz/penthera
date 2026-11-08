section: Changed

- **One count everywhere.** A repo scan now runs the checks `penthera fix` uses:
  security headers, cookie flags, CORS and login rate limits as your code sets
  them, including in `next.config.mjs`. The scan, `penthera ui`, the MCP tools,
  the JSON and SARIF reports, `penthera fix` and the fix loop count one set of
  findings with the same words: a *problem* is a finding to act on or to check
  first, and one *fix planned* can cover several problems. On the Next.js
  fixture the scan used to say 2 problems while `fix --plan` planned 5 fixes for
  10 findings; every surface now says 8 problems, and the scan and the plan
  both say `5 fixes planned for 8 problems`. The scan's fix line counts the
  fixes the plan really makes: likely noise, and findings a recipe matches but
  cannot change (a secret in a `.env` file), no longer show as fixable after
  you fixed the rest. Headers read from code are marked
  `potential`, since a host or CDN may still add them. The new findings are
  medium or lower, so no exit code changes.
- **The fix planner's checks are bounded.** Now that every scan runs them, each
  code file is read once and dropped, a long line can no longer make the CORS
  or cookie check quadratic (80 KB took seven seconds before; 5 MiB now takes
  milliseconds), each check keeps the 25 worst hits per file, and symbolic
  links are no longer followed. A code file that check could not read (over
  the size limit, a device or FIFO, unreadable) or never reached (past the
  2,000-file walk) makes the scan incomplete and exits 2, as a refused route
  file already did. Any number of `cookies()` stores is read, padding inside
  `.get( "origin" )` is read as before, and a file with many hits holds only
  the 25 worst in memory.
- **Words an agent can act on.** In the JSON a repo finding also has `path`
  (the file `url` already held, which stays) and every finding has
  `exploitability`: `not-assessed` for a rule match, so `confidence: confirmed`
  no longer reads as a verdict. Text reports say `pattern matched`,
  `likely match`, `possible match` or `needs a person`. The brief says how to
  suppress a problem you checked by its fid with a reason (`set_aside` in its
  JSON), and `penthera fix --plan` prints its headline again at the end.
