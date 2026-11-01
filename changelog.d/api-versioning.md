section: Site

- **`/openapi.json` states what counts as a breaking change.** A new response
  field or error code doesn't. Before a breaking change or a removal, the
  operation is marked `deprecated: true`, responses carry a `Deprecation`
  header, and the changelog lists it.
