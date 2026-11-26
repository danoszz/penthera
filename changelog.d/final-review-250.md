section: Security

- **`curl … >| /bin/sh` in a hook, an MCP command or a script is found
  again.** A pipe written as `>|` or `>>|` was read by one pattern only, which
  knew `sh` and `bash` but not a shell named by its path or run through
  `sudo`, `env`, `nohup` or `nice`. 2.4.0 found these; the development branch
  did not. They are critical again, however the shell is spelled.
- **A crafted `pnpm-lock.yaml` can no longer run the scan out of memory, or
  stall it.** A few megabytes of open brackets made the framework advisory
  check use gigabytes and end the scan with no report, and a long run of
  commas kept it busy for a minute. The lockfile is now read for every
  `name@version` of a watched package in one pass, whatever its size, indent,
  quoting or line endings. A file with shapes pnpm never writes (an escaped
  key, a `? ` key, a list left open across lines, hundreds of commas on a
  line) is named and the scan is incomplete (exit 2).
- **`penthera diff` and `--baseline` see a second problem in a file that
  already had one.** A new Server Action without an auth check, a second token
  read from a URL or another unsafe cookie in the same file counted as
  unchanged, so the diff said "Nothing to fix". Rules that report once per
  file are now compared by the names and the number of places they list.
  Three rules name one place per file, so a second case there is still the
  same finding: the webhook signature, the password-reset expiry and the
  OAuth state rule.
- **A framework advisory keeps its severity in a monorepo.** With the lockfile
  at the root and the app in `apps/web`, the React Server Components and
  middleware advisories dropped to low and said the bug was not reachable.
  The check now looks for the `app` folder or middleware file anywhere in the
  project, and keeps high when it cannot finish looking or meets a linked
  folder.
- **An `eval` in a Next.js route file stays in Act on.** It had moved to Check
  first when the value came from the handler's `params`.
- **A `.env` file with Windows line endings is read.** The check for server
  secrets behind a public prefix (`NEXT_PUBLIC_`, `VITE_`) reported nothing
  for a file saved with CRLF.
- **`penthera init` pins the 2.4.0 Action.** The workflow it writes was still
  pinned to the 2.3.2 release commit, one release behind the docs and examples.
