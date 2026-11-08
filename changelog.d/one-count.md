section: Changed

- **One count everywhere.** A repo scan now runs the checks `penthera fix` uses:
  security headers, cookie flags, CORS and login rate limits as your code sets
  them, including in `next.config.mjs`. The scan, `penthera ui`, the MCP tools,
  the JSON and SARIF reports, `penthera fix` and the fix loop count one set of
  findings with the same words: a *problem* is a finding to act on or to check
  first, and one *fix planned* can cover several problems. On the Next.js
  fixture the scan used to say 2 problems while `fix --plan` planned 5 fixes for
  10 findings; every surface now says 8 problems, and the plan says
  `5 fixes planned for 8 problems`. The scan's fix line counts only problems
  a recipe can change: likely noise, and a secret in a `.env` file, no longer
  show as fixable after you fixed the rest. `penthera fix --plan` counts a fix
  only when it changes a problem, and lists fixes for likely noise apart. Headers read from code are marked
  `potential`, since a host or CDN may still add them. The new findings are
  medium or lower, so no exit code changes.
- **The fix planner's checks are bounded.** Now that every scan runs them, each
  code file is read once and dropped, a long line can no longer make the CORS
  or cookie check quadratic (80 KB took seven seconds before; 5 MiB now takes
  milliseconds), each check keeps the 25 worst hits per file, and a link is
  followed only inside the project. A code file that check could not read
  (over the size limit, a device or FIFO, a link out of the project,
  unreadable) or never reached (past the 5,000-file walk, which leaves out
  generated and git-ignored folders) makes the scan incomplete and exits 2, as
  a refused route file already did. Cookie calls written over several lines
  (the Prettier style) are now checked and reported, to fix by hand: the fix
  edits one-line calls, so they are not counted as fixable. `vercel.json`
  headers count only when set for every route. Any number of `cookies()` stores is read, padding inside
  `.get( "origin" )` is read as before, and a file with many hits holds only
  the 25 worst in memory.
- **Words an agent can act on.** In the JSON a repo finding also has `path`
  (the file `url` already held, which stays) and every finding has
  `exploitability`: `not-assessed` for a rule match, so `confidence: confirmed`
  no longer reads as a verdict. Text reports say `pattern matched`,
  `likely match`, `possible match` or `needs a person`. The brief says how to
  suppress a problem you checked by its fid with a reason (`set_aside` in its
  JSON), and `penthera fix --plan` prints its headline again at the end.
- **Nothing to fix now.** A run with nothing to act on and only things to check
  first (headers read from code, which your host may still add) says `Nothing
  to fix now`, and its share card `Nothing to fix now · 4 to check`. Medium
  or low things to check first and likely noise no longer lower the
  agent-config grade; a finding to act on, or any critical or high finding,
  still does. A confirmed problem still says `Fix now` or `Review`, and
  suppressed findings keep their own verdict. The brief's JSON adds
  `verdict_id`, a stable name for the verdict.
