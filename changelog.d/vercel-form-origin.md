section: Fixed

- **The Vercel integration's setup form works in real browsers.** With
  `Referrer-Policy: no-referrer`, browsers send `Origin: null` on a form post,
  so "Next" failed with "Form check failed". The pages now use `same-origin`,
  a `null` origin is decided by the session's form token, and the setup pages
  use Penthera's black style.
