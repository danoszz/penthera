section: Detection

- **A long comment inside a command call no longer hides it.** The command
  check read the first 300 characters of a call whose closing bracket was far
  away, so `exec("ls " + /* 2,100 characters */ req.body.d)` passed. It now
  reads to the real closing bracket. A file with very long argument lists
  shares a work budget, and when that runs out the scan says it is incomplete
  instead of passing quietly.
- **A download reaches the shell through other commands too.** `curl … | cat
  | sh`, `| tee f | bash`, `| gunzip | sh` and `| jq . | sh` now count as a
  download piped to a shell, in skills, scripts, hooks and MCP launch commands.
  So do `. <(curl …)`, `python3 -c "$(curl …)"`, and a download saved to a file
  and run later on the same line (`curl -o /tmp/a … && sh /tmp/a`, or after
  `chmod +x`), as the new `download-then-run` rule.
