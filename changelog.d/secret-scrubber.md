section: Security

- **One secret scrubber for every output.** The terminal report, `--json`,
  the JSON, Markdown, SARIF and audience reports, the evidence bundle, the
  brief, the share card, MCP results, errors and progress lines all mask
  secrets through one function (`lib/scrub.js`), before any text is cut to
  length. It masks every fixed-shape rule of the secret scan, whole private
  key blocks, JWTs, `sb_secret_`, Stripe test and webhook secrets, Slack, npm,
  GitLab, SendGrid and Vercel Blob tokens, the password in a URL, and the token
  after `Bearer`. Tests plant a key of each shape and check every output.
  See [docs/privacy.md](../docs/privacy.md#secrets-in-what-penthera-writes).
