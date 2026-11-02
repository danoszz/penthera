# yaml, vendored

> For maintainers: "where does Penthera's YAML parser come from, and how do I update it?"

This is [yaml](https://github.com/eemeli/yaml) **2.9.1** by Eemeli Aro, under the ISC license in `LICENSE`.
It parses skill frontmatter in `lib/agents/discover.js` and Nuclei templates in `lib/nuclei-loader.js`.
Penthera ships it inside the package, so installing Penthera installs no other package.

## What's here

The ESM build from the npm tarball, unchanged:

| Here | In the tarball |
|---|---|
| `dist/` | `package/browser/dist/` |
| `index.js` | `package/browser/index.js` |
| `LICENSE` | `package/LICENSE` |

- Tarball: `https://registry.npmjs.org/yaml/-/yaml-2.9.1.tgz`
- Its sha512, as the npm registry gives it:
  `sha512-3NxN8+78OdzbT7C/WjGsyfPAtJaN3FNDsWxv7Y7mcDsT/oOmgW8BpyQQFFBnvZE3j9Y2Sdz1ULFLezL7Eb2yFw==`
- Tree hash of the files above: `5355a67c2bfeab64d845afd1a0671ef90b2ba2d978faa3c1492df41e9fab888b` (75 files).
  `tests/vendor-yaml.test.js` recomputes it, so an edit here fails the suite.

One difference from the Node build: a `!!binary` value parses to a `Uint8Array`, not a `Buffer`. The bytes are
the same.

## Updating

Never edit these files. To move to a new version:

1. Read the release notes and the diff between the two versions.
2. Run `npm pack yaml@<version>` in an empty folder, and check that the tarball's sha512 matches
   `npm view yaml@<version> dist.integrity`.
3. Replace `dist/`, `index.js` and `LICENSE` with the files the table names.
4. Update the version, the sha512 and the tree hash in this file and in `tests/vendor-yaml.test.js`. The test
   prints the new tree hash when it fails.
5. Run `npm test`. Add a changelog fragment under Security.

Don't swap in a parser of our own. A parser that reads a file differently from the agent that runs it can be
used to hide instructions in a skill.
