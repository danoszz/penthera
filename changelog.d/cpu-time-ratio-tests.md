section: Fixed
docs: none, only test timing changed and nothing changes for users

- **Timing tests measure CPU time.** Five linear-time checks from the November
  fix batches timed themselves by the wall clock and failed on busy CI runners
  while the code ran as fast as before. They now use `cpuMs()`, as the
  contributor guide asks.
