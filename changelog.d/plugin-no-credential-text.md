section: Changed

- **The Claude plugin's skill links to the docs for logins and signing keys.** Anthropic's plugin directory still held the plugin because the skill showed `--auth-bearer` and `--auth-cookie`, the home config files `penthera agents --home` reads, and a signing key path. The skill now points to the scan, agents and evidence docs for these, and its fix examples call your auth library instead of reading a request header. The CLI and the docs are unchanged.
