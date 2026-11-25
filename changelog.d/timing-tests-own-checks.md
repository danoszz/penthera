section: Fixed
docs: none, tests and CI only

- **Three timing tests no longer fail on a busy runner, and the security check
  stops waiting on itself.** The pipe-to-shell tests timed their work by the
  wall clock and failed on CI at 1,691 ms for 210 ms of work; they now measure
  CPU time with `cpuMs()`. The Supabase "reads a migration once" test counts
  the reads and no longer compares two times. The "Penthera: security" check
  counted its own two checks as CodeQL jobs still running, so it showed
  "Running" for days; it now skips them.
