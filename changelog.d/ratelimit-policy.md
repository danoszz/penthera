section: Site

- **`POST /api/check` answers with `RateLimit-Policy`.** Agents can read the
  limits from any response and pace themselves. It carries no remaining count,
  because each server instance counts on its own.
