section: Detection

- **Five missing-check rules for the code makers ship.** `--repo` now reports a
  webhook handler that writes data without verifying the provider's signature
  (`webhook-signature-missing`), a token from the request read with
  `jwt.decode`, `decodeJwt` or `jwtDecode` in a file that never verifies one
  (`jwt-decode-unverified`), a secret, an API key or an HMAC compared with
  `===` instead of `crypto.timingSafeEqual` (`secret-compare-not-constant-time`),
  a password-reset token used with no expiry check (`reset-token-no-expiry`),
  and a payment amount, role, plan or credit balance taken from the request
  into Stripe or the user record (`client-trusted-value`, CWE-472 and mass
  assignment). Each finding names the file and line, at `likely` or
  `potential` confidence. On 10 open-source projects, four known-vulnerable apps
  and 150 benign npm packages they report 5 findings, all timing-rule
  compares that are true by the rule. A file over 4 MiB, a file Penthera may
  not read, or more work than 16 times a file's length makes the scan
  incomplete (exit 2). `explain_finding` knows all five ids.
  [Read the rules](https://penthera.org/docs/commands/scan#missing-checks-webhooks-tokens-and-client-chosen-values).
