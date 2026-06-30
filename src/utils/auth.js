/**
 * Build auth headers from scan options or environment.
 */
export function resolveAuth(opts = {}) {
  const cookie = opts.authCookie || process.env.PENTHERA_COOKIE || null;
  const bearer = opts.authBearer || process.env.PENTHERA_BEARER || null;

  const headers = {};
  if (cookie) headers.Cookie = cookie;
  if (bearer) headers.Authorization = bearer.startsWith("Bearer ") ? bearer : `Bearer ${bearer}`;

  return { cookie, bearer, headers };
}
