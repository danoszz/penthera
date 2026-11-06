section: Security

- **A pipe into a shell is read by two checks, and either one reports it.** The
  stage parser from 2.3.2 now runs beside the regex from 2.3.1, so nothing the
  old check caught is lost. The parser now reads quotes and escapes as the shell
  does, takes redirections off the command word (`bash>/var/log/x`), and sees a
  shell behind `nohup`, `exec`, `command`, `time`, `nice`, `timeout`, `{ }` and
  `( )`, and after a quoted assignment like `FOO="a b"`. Repeated `env -S` and
  `--split-string` now take linear time.
- **A secret is hidden in its encoded forms too.** A finding that quotes a
  command hides a known secret when it appears percent-encoded, base64 or hex.
- **`penthera fix` exits 2 when its run is incomplete.** Cookie calls it could
  not read, and the scan's or report's unread files, were dropped before. Now
  it names them.
