section: Fixed
docs: none, release workflow only; nothing changes for users

- **The release job installs actionlint before the tests.** The publish
  workflow now sets up the same pinned, checksummed actionlint as CI, so the
  Vercel template test runs there too.
