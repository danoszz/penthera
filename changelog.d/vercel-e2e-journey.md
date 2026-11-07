section: Fixed
docs: none, the integration server's README covers it; nothing in the CLI, MCP tools, rules or Action changed

- **The Vercel relay reads a deployment's project in every view Vercel
  answers.** Vercel's reduced public view of a deployment names the project as
  `project.id`, not `projectId`. Penthera read only `projectId`, so it would
  have refused every scan result and held production deploys. A new end-to-end
  test walks the whole install against a fake Vercel that checks each request
  against Vercel's published API spec, and lints the workflow with actionlint.
