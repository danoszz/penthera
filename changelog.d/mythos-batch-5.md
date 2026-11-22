section: Detection

- **New rule `cron-route-no-secret`.** A route that `vercel.json` runs on a
  schedule and that checks nothing (no `Authorization` or `CRON_SECRET`
  compare, no signed request) can be run by anyone who finds its URL. High
  when it writes data, sends mail or calls a payment API, else medium.
- **The secret scan finds three more kinds of committed secret:** a database or
  queue URL with its password (`postgresql://app:…@db.prod…`, also in
  `.env.production`), a secret read from the environment with a literal
  fallback (`process.env.JWT_SECRET || "dev"`), and `jwt.sign` with a key in
  the code. Local databases (`localhost`, `db`, `postgres`) and `${VAR}`
  placeholders are not reported.
- **Next.js and React: the December 2025 Server Components advisories.**
  CVE-2025-55184 (completed as CVE-2025-67779, and CVE-2026-23864 in React)
  lets one request hang an App Router server, and CVE-2025-55183 can show
  Server Function code. The versions that fixed CVE-2025-55182, such as 15.5.7,
  are still affected; the fixed versions are Next.js 14.2.35, 15.0.7, 15.1.11,
  15.2.8, 15.3.8, 15.4.10, 15.5.9 and 16.0.10, and `react-server-dom-*` 19.0.4,
  19.1.5 and 19.2.4. Every version was checked against nextjs.org and react.dev.
