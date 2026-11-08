section: Security

- **The share card never shows a URL, a credential or a path from your
  project.** An old lockfile can store a package's version as a download URL
  with a user name, password or token in it, and a card could show that URL
  after the package name. A card now names only the package and drops every
  word that holds a URL, a `user:password@` part, a `key:value` pair, a
  percent escape or a path (route paths such as `app/[slug]/page.tsx`, home and
  Windows paths included). The value after a key like `password:`, `token=` or
  `Authorization:` is hidden whole, and a key split by dots is still hidden.
  Invisible characters are removed before these checks, so they can't hide a
  URL from them. "Not checked" lines such as the MCP note stay on the card
  however short it gets.
