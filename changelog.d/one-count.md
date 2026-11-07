section: Changed

- **One count everywhere.** A repo scan now runs the checks `penthera fix` uses:
  security headers, cookie flags, CORS and login rate limits as your code sets
  them, including in `next.config.mjs`. The scan, `penthera ui`, the MCP tools,
  the JSON and SARIF reports, `penthera fix` and the fix loop count one set of
  findings with the same words: a *problem* is a finding to act on or to check
  first, and one *fix planned* can cover several problems. On the Next.js
  fixture the scan used to say 2 problems while `fix --plan` planned 5 fixes for
  10 findings; every surface now says 8 problems, and the plan says
  `5 fixes planned for 8 problems`. Headers read from code are marked
  `potential`, since a host or CDN may still add them. The new findings are
  medium or lower, so no exit code changes.
- **The fix planner's checks are bounded.** Now that every scan runs them, each
  code file is read once and dropped, a long line can no longer make the CORS
  or cookie check quadratic (80 KB took seven seconds before; 5 MiB now takes
  milliseconds), each check keeps the 25 worst hits per file, and symbolic
  links are no longer followed. Files over the size limit, refused or past the
  2,000-file walk are listed under Not checked.
