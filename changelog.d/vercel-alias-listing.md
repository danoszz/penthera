section: Fixed
docs: none, the integration server's README, the Vercel guide and the terms cover it; nothing in the CLI, MCP tools, rules or Action changed

- **Turn on the check works on live Vercel.** Vercel refused the check with
  "Only deployment-alias and none are currently supported for blocks". The
  check now uses `deployment-alias`: a failing production deployment stays off
  your production domain until it passes, and Force Promote still overrides it.
- **Installing from Penthera's listing page on Vercel is no longer refused.**
  Vercel sends that install back with no CSRF state, and it was refused as
  "Part of your install link is missing". It now takes the same path as a
  Marketplace install. An install that does carry a state is still checked
  against this browser's cookie.
