section: Fixed

- **The maker checks name a file they cannot read.** The public env, Server
  Action and framework lockfile checks stopped the scan on a file without read
  permission. Now they name it and the run ends incomplete (exit 2), like every
  other check.
