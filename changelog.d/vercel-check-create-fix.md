section: Fixed
docs: none, the integration server's README covers it; nothing in the CLI, MCP tools, rules or Action changed

- **"Turn on the check" no longer guesses the integration id.** The Vercel
  integration reads it from Vercel's record of your installation instead of
  sending the OAuth client id, and a failed create now logs Vercel's own error
  code and message (never a token). If Vercel refuses the check's 20-minute
  timeout, it retries once with Vercel's default.
