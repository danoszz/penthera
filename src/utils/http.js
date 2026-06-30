const DEFAULT_TIMEOUT = 8_000;

/**
 * Fetch with timeout and graceful failure (returns null on network error).
 */
export async function safeFetch(url, opts = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), opts.timeout || DEFAULT_TIMEOUT);
  try {
    return await fetch(url, {
      ...opts,
      signal: controller.signal,
      redirect: opts.redirect ?? "manual",
    });
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Fetch helper that always returns status, body text, and headers.
 */
export async function probeFetch(url, opts = {}) {
  const res = await safeFetch(url, opts);
  if (!res) return null;

  const body = await res.text().catch(() => "");
  const headers = Object.fromEntries(res.headers.entries());

  return {
    status: res.status,
    body,
    headers,
    ok: res.ok,
  };
}
