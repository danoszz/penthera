section: Security

- **The Vercel check passes only a scan that read the deployment.** A
  deployment that answered with a bot challenge, a block page, a 401 or 403, or
  nothing at all could pass the check, because the scan only warned "Site not
  read" and still succeeded. The workflow now reads Penthera's report and
  reports failed unless it proves the site was read, and the check says why:
  "Site not read: ...". Copy the workflow again from Penthera's setup page.
- **A pass counts only for the deployment's own address.** The address the
  workflow scanned comes from Vercel's dispatch, which nobody signs. The
  workflow now sends a SHA-256 fingerprint of it (never the address), and the
  server passes the check only when it matches the deployment's URL in Vercel's
  record. A workflow from before this change reports failed, "Scanned URL is
  not this deployment", until you copy it again.
- **The Action fails a gated scan that did not read the site.** With `fail-on`
  set, a URL scan exits 2 (incomplete), as the CLI does for an input it could
  not read, unless its report proves a read: a 2xx home page, no bot challenge
  or block page, no rate limiting, and the app scan done. This reaches the
  Vercel workflow with the next release of the Action; until then the
  workflow's own report check covers it.
