section: Changed

- **The Claude plugin ships Markdown and JSON only.** Anthropic's plugin directory takes only Markdown, text, JSON, YAML and images from an unverified publisher, and held the plugin for its `.sh` and `.mjs` scripts. The plugin's skill no longer has a `scripts/` folder: the preflight is now four plain checks in SKILL.md (Node.js 22 or later, a working `penthera` command, a `reports/` folder, an authorized target), the same in the skill you add with `npx skills add`. A checkout and `npx skills add` keep `scripts/preflight.sh` and `validate-report`.
