section: Detection

- **More provider token formats.** AWS temporary access keys (`ASIA…`, from
  STS) are found next to long-term ones (`AKIA…`), and so are every GitHub
  token prefix (`gho_`, `ghu_`, `ghs_`, `ghr_` and fine-grained
  `github_pat_`, not only `ghp_`), Stripe restricted live keys (`rk_live_`)
  and Postman API keys (`PMAK-`). AWS's documented example keys (they spell
  `EXAMPLE`) and runs of `X` don't count.
- **Tokens and secrets under more names.** The generic API key rule also
  finds OAuth access, refresh and ID tokens, bearer and session tokens,
  OAuth 1 token secrets, consumer, app, signing, webhook and cookie secrets,
  and a key named just `token` or `secret`. Because these names also hold
  test data and words, the value has to look generated: 16 characters or
  more, mixed character classes, not words, an email, a reference, an elided
  example or a typed run like `123456`. Pagination cursors (`next_token`) and
  names (`secret_name`) don't count.
- **reStructuredText, AsciiDoc and `.markdown` files are read as docs.** As in
  `.md` and `.txt`, only the rules that match a fixed shape (provider keys,
  private keys) run on them.
