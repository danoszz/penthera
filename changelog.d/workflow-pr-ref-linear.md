section: Security
docs: none, a speed fix inside an existing rule

- **A crafted workflow can no longer stall a repo scan.** The check for `pull/<number>/head` in a script re-read the rest of the line at every `pull/`, so one long line of unclosed `pull/${{` took seconds (4 s for 175 KB) and blocked the CLI and the MCP server. It now reads the line once. Found by Vercel Security Review on 2.3.0.
