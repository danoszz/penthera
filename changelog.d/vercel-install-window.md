section: Fixed
docs: none, the integration server's README and privacy notice cover it; nothing in the CLI, MCP tools, rules or Action changed

- **Installing Penthera from the Vercel Marketplace no longer fails with "This
  install timed out".** That happened in a browser that had started an install
  from Penthera's own link before. The install now goes through and clears the
  leftover check. An install from Penthera's own link has 30 minutes, as long as
  Vercel's install code, instead of 15. When an install is refused, the page now
  says which of three things happened, and that nothing was added to your
  projects.
