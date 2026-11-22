section: Security
docs: none, the same two rules report more of what they already look for; no flag or output changes

- **A validator on the request body no longer hides an unsigned webhook.**
  `validate(JSON.parse(rawBody))` counted as a signature check because it
  takes the raw body. A verify-like call now counts only when it takes the
  signature, the secret or the headers.
- **A schema validator no longer hides a Server Action with no auth check.**
  `schema.validateRequest(input)` counted as a session check on any object.
  `validateRequest` and `validateSession` on an object now count only when the
  object is named like auth (`lucia`, `auth`, `session`), and a bare
  `validateRequest(body, schema)` does not count.
