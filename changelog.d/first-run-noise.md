section: Detection

- **Fewer rows for one problem, and fewer status lines as findings.** Tuned on five starter apps, kept out of
  every benchmark. On those apps the repo scan went from 7 findings, 4 of them noise, to 1.
  - A runtime pin on an end-of-life line gives one end-of-life finding that lists the advisories the line won't
    get a fix for, with their CVEs, where it gave one HIGH row per advisory as well. When the pin is in several
    files, the finding points at the Dockerfile.
  - Route analysis reads Next.js route handlers anywhere under `app/` or `src/app/`, not only under `app/api`,
    and a Worker's `export default { fetch }` entry. Handlers written as `export const PUT = …` or
    `export { handler as GET }` get their methods.
  - "No API routes directory found" and "Found N API routes" are no longer findings. Coverage says how many
    routes were read, or that a client-only app has no server routes, where it said "not run".
  - The next-step line says the fix plan also checks cookie flags, CORS and rate limits, where it said "It".
