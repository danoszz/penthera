section: Fixed
docs: none, the integration server's README covers it; nothing in the CLI, MCP tools, rules or Action changed

- **"Turn on the check" in the Vercel integration says what went wrong and
  how to fix it.** Each project that fails now gets Vercel's answer in plain
  words, what to do, a link to the right Vercel page, and a code you can send
  us. It offers "Try again" only when that can help. On a reinstall, a Penthera
  check left over from your earlier install is removed first, so it can't hold
  production deploys forever. Penthera never removes a check it did not add.
