section: Fixed
docs: none, adds offline tests for security headers and JWT probes without changing CLI or rules

- **Add offline tests for security headers and JWT probes.** Covers
  `auditSecurityHeaders` (`tests/security-headers.test.js`) and `probeJwt`
  (`tests/jwt.test.js`) with injected `probeFetch` and a `/jwt-demo/alg-none`
  route on the mock server.
