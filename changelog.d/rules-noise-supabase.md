section: Changed

- **Fewer hints at the top of the brief, and no real finding dropped.** Three
  rules put a hardening hint or a word in a comment under Act on, where a
  coding agent read it as a proven bug.
  - Supabase's `auth.getSession()` no longer counts as an auth check in the
    Server Actions check or the route records. It reads the session from the
    cookie without verifying it; `auth.getUser()` and `auth.getClaims()` count.
    A Server Action that writes data behind `getSession()` alone is now
    reported. next-auth's bare `getSession()` counts as before.
  - The low-severity route hints (`err.message`, `origin || "*"`, an
    unguarded `JSON.parse`) skip comments. The serious sinks (`eval`,
    `innerHTML`, `exec`, `spawn`) match the raw text or the comment-blanked
    code, so no comment trick hides one, and a command in a route stays at
    its full severity.
  - The rate-limit findings (a public route calling a paid API, a login
    route) and `secret-compare-not-constant-time` for an HMAC or signature
    are low.
