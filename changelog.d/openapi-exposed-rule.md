section: Changed

- **An exposed OpenAPI specification has its own rule, `openapi-exposed`.** The finding used to carry only its category, so `explain_finding` gave the general advice for exposed files and the brief could not name it. `explain_finding` with `openapi-exposed` now says how to stop serving the spec, and the rule shows up in the brief, the MCP results and SARIF. In GitHub code scanning the finding moves from the `exposure` rule to `openapi-exposed`.
