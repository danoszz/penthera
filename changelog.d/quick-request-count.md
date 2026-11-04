section: Docs

- **The scan docs say how many requests the quick profile sends.** About 180: 182 against the test
  server, more on a site whose OpenAPI spec lists more paths. A test fails if the count against the
  test server grows past the documented number (#235).
