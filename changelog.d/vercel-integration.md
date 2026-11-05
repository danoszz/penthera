section: Added
docs: none, integrations/vercel/README.md owns this; it is a separate server, not part of the CLI or the npm package

- **A server for a Vercel Marketplace integration, in `integrations/vercel/`.**
  It registers Penthera's GitHub Action as a Vercel Deployment Check on the
  projects you pick, and links you to GitHub with the workflow file filled in.
  Scans still run in your own GitHub Actions. The server keeps one encrypted
  install token per installation and deletes it when you uninstall. It is
  deployed on its own and is not in the npm package. A setup session ends
  when the installation is transferred or reinstalled. Not live yet: the
  integration still needs a live scope test and the maintainer's go.
