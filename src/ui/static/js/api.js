// Same-origin JSON client. The session cookie is HttpOnly and SameSite=Strict,
// so it rides along on its own; POSTs send JSON so the server's Origin and
// Content-Type checks pass for this page and fail for every other site.

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function call(method, path, body) {
  const res = await fetch(path, {
    method,
    credentials: "same-origin",
    cache: "no-store",
    headers: body === undefined ? { Accept: "application/json" } : { Accept: "application/json", "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data = null;
  try { data = await res.json(); } catch { /* empty or not JSON */ }
  if (!res.ok) throw new ApiError(data?.error || `${res.status} ${res.statusText}`, res.status);
  return data;
}

export const api = {
  get: (path) => call("GET", path),
  post: (path, body = {}) => call("POST", path, body),
};
