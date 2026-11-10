section: Detection

- **Five checks for middleware, sessions, passwords and OAuth callbacks.**
  `--repo` now reports a Next.js middleware or proxy that names protected
  paths (`/admin`, `/dashboard`, ...) but checks no session
  (`next-middleware-no-auth`). It also reports a password or secret read from
  the query string (`credential-in-url`, CWE-598) and a password encrypted or
  decrypted instead of hashed (`password-encrypted-not-hashed`, CWE-257). It
  reports Secure or HttpOnly turned off in a session library's cookie
  options, or express-session left without `cookie.secure`
  (`session-cookie-insecure`, CWE-614). And it reports an OAuth callback that
  exchanges the code without reading `state`, a PKCE verifier or a nonce
  (`oauth-callback-no-state`, CWE-352). Each is one finding per file at
  `likely` or `potential` confidence. On the four known-vulnerable apps and
  11,390 files of the maintainer's apps they reported 3 findings, all real
  (the same sets were used to tune them, so not an independent count).
  Work per file is bounded; past the budget the file is named and the scan
  exits 2. The Server Actions check now counts `jwtVerify`, `jwt.verify` and
  re-exports from an auth module (`export { auth as middleware } from
  "@/auth"`) as auth.
  [Read the rules](https://penthera.org/docs/commands/scan#middleware-sessions-passwords-and-oauth-callbacks).
