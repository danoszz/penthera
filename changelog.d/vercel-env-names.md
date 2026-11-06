section: Fixed

- **The Vercel integration server reads `INTEGRATION_CLIENT_ID` and
  `INTEGRATION_CLIENT_SECRET`.** Vercel reserves environment variable names
  that start with `VERCEL_`, so the old names could not be set.
