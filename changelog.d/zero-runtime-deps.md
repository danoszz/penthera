section: Security

- **No runtime dependencies.** The `yaml` parser that reads skill frontmatter and Nuclei templates now ships
  inside the package: version 2.9.1, unchanged, with its ISC license and the npm tarball's sha512 in
  `lib/vendor/yaml`. A test fails if a byte of it changes. Installing Penthera fetches nothing else, and the
  GitHub Action's `mode: agents` no longer runs `npm ci`. The package grows by about 74 KB packed, and a full
  install shrinks by about 38 KB, because yaml's own tarball is no longer fetched.
