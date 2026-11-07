section: Changed

- **The skill no longer tells the agent to put credentials in the environment.** Anthropic's plugin directory held the plugin because the skill showed `PENTHERA_BEARER` and `PENTHERA_COOKIE` and a fix example that read a key with `process.env`. For an authenticated scan, the skill now gives the `--auth-cookie` or `--auth-bearer` command for you to run with your own value, and the agent never asks for it. The hardcoded-secret fix is described in words. The environment variables still work, and docs/commands/scan.md still documents them.
