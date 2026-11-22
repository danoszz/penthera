section: Detection

- **One reader decides "does this code check who is calling?"** The Server
  Actions check, the session check, the webhook check and the route list each
  had their own list, and they disagreed. They now share one.
  - A lookup that only looks like a check no longer hides a Server Action that
    writes data: `getUserById(id)`, `getAccountSettings(id)`, `isLoginEnabled()`,
    `db.getUserCount()` or `getUser(id)` with an id.
  - A root `middleware` file no longer lowers these findings to medium. The
    finding still names it. Next.js does not treat middleware as the auth
    boundary, and a helper there named like a check (`getUserLocale`,
    `isLoginPage`) lowered every action below the exit line.
  - A webhook without a signature check is reported even when the file holds
    `sendVerificationEmail(u)`, `verifyCaptcha(x)`, `r.unwrap()`, `getUser(id)`
    or an unused `STRIPE_WEBHOOK_SECRET`. A verify call counts when it takes the
    signature header, the headers, the raw body or the secret, and a secret
    counts when it is compared or passed on.
  - `jwt.decode` next to `verifyCaptcha(x)` or `getUser(p.sub)` is reported.
  - The route list reads auth from code, not comments: a comment that says
    `requireAuth` or a field named `isAdmin` is no check, and Clerk's `auth()`,
    Lucia's `validateRequest()` and a bare `getUser()` are.
