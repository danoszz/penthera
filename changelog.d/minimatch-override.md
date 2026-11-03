section: Security
docs: none, dev dependency only

- **minimatch 11.0.4 for eslint.** An override lifts minimatch from 10.2.6 to 11.0.4 for the lint tools, which
  fixes GHSA-g3hv-75wg-m249, a denial of service. eslint 10 still asks for minimatch 10, so no upstream release
  fixes it yet. It's a dev dependency: the published package has no runtime dependencies and doesn't include it.
