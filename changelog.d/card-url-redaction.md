section: Security

- **The share card never shows a URL or credentials from a dependency
  version.** An old lockfile can store a package's version as a download URL
  with a user name, password or token in it, and a card could show that URL
  after the package name. A card now names only the package, drops every URL
  wherever it starts, drops `user:password@` parts and cuts query strings,
  in the image and in its description.
