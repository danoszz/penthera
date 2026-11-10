section: Detection

- **Three checks for the stack makers ship on.** `--repo` now reads the
  installed Next.js and React Server Components versions from the lockfile
  (npm, pnpm, yarn, bun) and reports a version in a published advisory's
  range (`framework-advisory`: CVE-2025-55182, the Server Components remote
  code execution, and CVE-2025-29927, the middleware bypass). It reports a
  server secret behind a public env prefix (`public-env-secret`:
  `NEXT_PUBLIC_OPENAI_API_KEY`, `VITE_API_KEY` and the like are written into
  the browser bundle, whatever the value), reading `.env*` files, the
  framework configs and `process.env` reads in code. And it reports a Next.js
  Server Action that writes data, sends mail or calls a payment API without
  an auth check (`server-action-no-auth`), one finding per file at `potential`
  confidence. A lockfile or source file one of these could not read is named
  and makes the scan incomplete, never a silent pass.
  [Read the rules](https://penthera.org/docs/commands/scan#framework-versions-with-a-published-vulnerability).
