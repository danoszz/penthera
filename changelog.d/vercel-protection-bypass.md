section: Added

- **Scans behind Vercel Deployment Protection.** Set Vercel's Protection Bypass
  for Automation secret in `PENTHERA_VERCEL_BYPASS`, or pass it to the Action
  as `vercel-bypass-secret`. Penthera sends it as the
  `x-vercel-protection-bypass` header to an `https://*.vercel.app` target's own
  origin only, never to another host or after a redirect to one, and replaces
  it with `[redacted]` anywhere in the report. It is read from the environment,
  never from a flag, never sent in an MCP scan, and must be 16 to 128
  characters of `A-Z a-z 0-9 . _ ~ -`, as Vercel generates it.
- **The Vercel integration's workflow uses it.** Store the secret as the repo
  secret `VERCEL_AUTOMATION_BYPASS_SECRET`; it never reaches Penthera's server.
  Without it, a protected deployment fails the check with the steps to add it.
