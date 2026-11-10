section: Changed

- **Fewer hints at the top of the brief, and no real finding dropped.** Four
  rules put a hardening hint or a word in a comment under Act on, where a
  coding agent read it as a proven bug.
  - Supabase's `auth.getSession()` no longer counts as an auth check in the
    Server Actions check or the route records. It reads the session from the
    cookie without verifying it; `auth.getUser()` and `auth.getClaims()` count.
    A Server Action that writes data behind `getSession()` alone is now
    reported. next-auth's bare `getSession()` counts as before.
  - The route patterns (`eval`, `innerHTML`, `exec`, `err.message`,
    `origin || "*"`, an unguarded `JSON.parse`) read code with comments
    blanked and strings kept. `el["innerHTML"]` still matches, and a comment
    the lexer may have misread never hides a match.
  - A route file whose every `exec` or `spawn` call runs fixed text gets
    `command-injection` at medium, potential (Check first) instead of
    critical. A command built from anything but a literal, an exec function
    aliased or renamed, or a sink finding for the file keeps it critical.
  - The rate-limit findings (a public route calling a paid API, a login
    route) and `secret-compare-not-constant-time` for an HMAC or signature
    are low.
