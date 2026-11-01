// Same-origin JSON client. `penthera ui` prints a link with a one-time token
// after the # (never sent over the network). signIn() posts it once, gets a
// session id back and keeps that in this tab's sessionStorage; every request
// then carries it as `Authorization: Bearer`. No cookie: cookies are not bound
// to a port, so every other server on 127.0.0.1 would receive one.

import { ERR } from "./copy.js";

const SESSION_KEY = "penthera-ui-session";
let sid = null;

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

function stored() {
  try { return sessionStorage.getItem(SESSION_KEY); } catch { return null; }
}

/** Redeem `#t=<token>` from the address bar (and remove it from there), or reuse this tab's session. */
export async function signIn() {
  const m = /^#t=([A-Za-z0-9_-]{16,128})$/.exec(location.hash);
  if (m) {
    history.replaceState(null, "", location.pathname);
    const r = await call("POST", "/api/session", { token: m[1] }, false);
    sid = r.session;
    try { sessionStorage.setItem(SESSION_KEY, sid); } catch { /* storage off: this page load only */ }
    return;
  }
  sid = stored();
}

function headers(extra = {}) {
  return sid ? { ...extra, Authorization: `Bearer ${sid}` } : extra;
}

/** A fetch that never reached the server: this tab outlived penthera ui. */
const stopped = () => { throw new ApiError(ERR.stopped, 0); };

async function call(method, path, body, auth = true) {
  const base = body === undefined ? { Accept: "application/json" } : { Accept: "application/json", "Content-Type": "application/json" };
  const res = await fetch(path, {
    method,
    credentials: "omit",
    cache: "no-store",
    headers: auth ? headers(base) : base,
    body: body === undefined ? undefined : JSON.stringify(body),
  }).catch(stopped);
  let data = null;
  try { data = await res.json(); } catch { /* empty or not JSON */ }
  if (!res.ok) throw new ApiError(data?.error || `${res.status} ${res.statusText}`, res.status);
  return data;
}

/** Fetch a file the API serves as an attachment and hand it to the browser as a download. */
async function download(path) {
  const res = await fetch(path, { credentials: "omit", cache: "no-store", headers: headers() }).catch(stopped);
  if (!res.ok) {
    let data = null;
    try { data = await res.json(); } catch { /* not JSON */ }
    throw new ApiError(data?.error || `${res.status} ${res.statusText}`, res.status);
  }
  const name = /filename="([^"]+)"/.exec(res.headers.get("Content-Disposition") || "")?.[1] || "penthera-report.md";
  const href = URL.createObjectURL(await res.blob());
  const a = document.createElement("a");
  a.href = href;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(href), 10_000);
}

/**
 * Read a run's event stream with fetch, so it carries the Authorization
 * header (EventSource cannot). Reconnects with Last-Event-ID after a dropped
 * connection. Returns { close }.
 * @param {string} path
 * @param {(type: string, data: string) => void} onEvent
 */
function stream(path, onEvent) {
  const ctl = new AbortController();
  let last = 0;
  let done = false;
  let tries = 0;
  const dispatch = (block) => {
    let type = "message";
    let id = null;
    const data = [];
    for (const line of block.split("\n")) {
      if (!line || line.startsWith(":")) continue;
      const i = line.indexOf(":");
      const field = i < 0 ? line : line.slice(0, i);
      const value = i < 0 ? "" : line.slice(i + 1).replace(/^ /, "");
      if (field === "event") type = value;
      else if (field === "data") data.push(value);
      else if (field === "id") id = value;
    }
    if (id != null && /^\d+$/.test(id)) last = Number(id);
    if (type === "end") done = true;
    onEvent(type, data.join("\n"));
  };
  (async () => {
    while (!done && !ctl.signal.aborted) {
      try {
        const res = await fetch(path, {
          credentials: "omit", cache: "no-store", signal: ctl.signal,
          headers: headers({ Accept: "text/event-stream", ...(last ? { "Last-Event-ID": String(last) } : {}) }),
        });
        if (!res.ok || !res.body) { onEvent("error", JSON.stringify({ status: res.status })); return; }
        tries = 0;
        const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
        let buf = "";
        for (;;) {
          const { value, done: eof } = await reader.read();
          if (eof) break;
          buf += value.replace(/\r\n?/g, "\n");
          let cut;
          while ((cut = buf.indexOf("\n\n")) >= 0) {
            dispatch(buf.slice(0, cut));
            buf = buf.slice(cut + 2);
          }
        }
      } catch {
        if (ctl.signal.aborted) return;
      }
      if (done || ++tries > 5) return;
      await new Promise((r) => setTimeout(r, 500 * tries));
    }
  })();
  return { close: () => ctl.abort() };
}

export const api = {
  get: (path) => call("GET", path),
  post: (path, body = {}) => call("POST", path, body),
  download,
  stream,
};
