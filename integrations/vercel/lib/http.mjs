/**
 * Responses, headers, cookies and the small HTML pages.
 *
 * Every response carries the security headers below. Pages run no script
 * (script-src 'none') and load nothing from elsewhere; their one inline style
 * is allowed by its hash. COOP is unsafe-none because Vercel's dashboard
 * watches the install popup's closed state and needs that value.
 */
import { createHash } from "node:crypto";

const STYLE = `
:root{color-scheme:dark;--fg:#e8e8e8;--bg:#000;--muted:#8a8a8a;--line:#262626;--accent:#0000ed;--on:#fff}
body{font:16px/1.55 system-ui,sans-serif;color:var(--fg);background:var(--bg);margin:0;padding:24px 16px}
main{max-width:640px;margin:8vh auto 0}h1{font-size:22px;margin:0 0 8px}p{margin:8px 0}
.muted{color:var(--muted);font:13px/1.5 ui-monospace,monospace;letter-spacing:.02em}ul{list-style:none;padding:0}
li{border:1px solid var(--line);border-radius:0;padding:12px;margin:8px 0;display:flex;gap:12px;align-items:flex-start}
li .name{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:420px;display:block}
li.off{opacity:.55}button,.button{font:13px/1 ui-monospace,monospace;letter-spacing:.02em;background:var(--accent);color:var(--on);border:1px solid var(--accent);box-shadow:0 0 0 2px var(--bg),0 0 0 3px var(--fg);border-radius:0;min-height:36px;padding:0 14px;text-decoration:none;display:inline-flex;align-items:center;cursor:pointer}
button:hover,.button:hover{background:var(--fg);color:var(--accent);border-color:var(--fg)}
a{color:var(--fg)}
button.quiet{background:transparent;color:var(--fg);border:1px solid var(--line);box-shadow:none;min-height:28px;padding:0 10px}
textarea{width:100%;height:220px;font:12px/1.4 ui-monospace,monospace;box-sizing:border-box;background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:0}
.void{position:fixed;inset:0;background:#000;color:#bbb;display:flex;align-items:center;justify-content:center;text-align:center;padding:24px;box-sizing:border-box}
.shrug{font:40px/1 ui-monospace,monospace;color:#fff;margin:0 0 24px;white-space:pre}.void p{font-size:17px;margin:0 0 28px}
.void .btn{display:inline-flex;align-items:center;min-height:36px;padding:0 14px;background:#0000ed;color:#fff;border:1px solid #0000ed;box-shadow:0 0 0 2px #000,0 0 0 3px #fff;border-radius:0;font:13px/1 ui-monospace,monospace;letter-spacing:.02em;text-decoration:none}
.void .btn:hover{background:#fff;color:#0000ed;border-color:#fff}
.grow{flex:1;min-width:0}.warn{border-left:3px solid #b26a00;padding-left:10px}code{font-size:14px;word-break:break-all}
`;
const STYLE_HASH = createHash("sha256").update(STYLE).digest("base64");

export const CSP = [
  "default-src 'none'",
  `style-src 'sha256-${STYLE_HASH}'`,
  "img-src 'none'",
  "script-src 'none'",
  // Chrome checks redirects after a form post against form-action, and the last step lands on vercel.com.
  "form-action 'self' https://vercel.com",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "upgrade-insecure-requests",
].join("; ");

export const SECURITY_HEADERS = {
  "Content-Security-Policy": CSP,
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "same-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()",
  "Cross-Origin-Opener-Policy": "unsafe-none",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Cache-Control": "no-store",
};

function withHeaders(extra = {}, cookies = []) {
  const h = new Headers({ ...SECURITY_HEADERS, ...extra });
  for (const c of cookies) h.append("Set-Cookie", c);
  return h;
}

export function json(status, data, { cookies } = {}) {
  return new Response(JSON.stringify(data), { status, headers: withHeaders({ "Content-Type": "application/json; charset=utf-8" }, cookies) });
}

export function html(status, title, body, { cookies } = {}) {
  const page = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex"><title>${esc(title)}</title><style>${STYLE}</style></head><body><main>${body}</main></body></html>`;
  return new Response(page, { status, headers: withHeaders({ "Content-Type": "text/html; charset=utf-8" }, cookies) });
}

export function redirect(location, { cookies, status = 303 } = {}) {
  return new Response(null, { status, headers: withHeaders({ Location: location }, cookies) });
}

/** A short message page, for errors and dead ends. */
export function message(status, title, text, { cookies } = {}) {
  return html(status, title, `<h1>${esc(title)}</h1><p>${esc(text)}</p>${FOOTER}`, { cookies });
}

export const FOOTER = `<p class="muted">Penthera runs in your own GitHub Actions. This server keeps only an encrypted install token, deleted when you uninstall. <a href="https://penthera.org" target="_blank" rel="noopener noreferrer">penthera.org</a></p>`;

const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
export function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ESC[c]);
}

/** `__Host-` cookies: Secure, path /, no Domain, so a sibling host can never set or read them. */
export function setCookie(name, value, maxAgeSeconds) {
  return `__Host-${name}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSeconds}`;
}

export function clearCookie(name) {
  return setCookie(name, "", 0);
}

export function readCookie(request, name) {
  const header = request.headers.get("cookie") ?? "";
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === `__Host-${name}`) return part.slice(i + 1).trim();
  }
  return null;
}

/** Vercel's `next` URL, only if it is https on exactly vercel.com, the one host CSP form-action allows. Anything else is an open redirect. */
export function safeNext(value) {
  try {
    const u = new URL(String(value ?? ""));
    return u.protocol === "https:" && u.hostname === "vercel.com" && (u.port === "" || u.port === "443") && !u.username && !u.password
      ? u.toString()
      : null;
  } catch {
    return null;
  }
}

/** Reads a urlencoded form, refusing bodies over `limit` bytes. */
export async function readForm(request, limit = 16_384) {
  const raw = await readBody(request, limit);
  return raw === null ? null : new URLSearchParams(raw.toString("utf8"));
}

/** The raw body bytes, or null when it is larger than `limit` bytes. */
export async function readBody(request, limit) {
  const declared = Number(request.headers.get("content-length") ?? 0);
  if (declared > limit) return null;
  const buf = Buffer.from(await request.arrayBuffer());
  return buf.length > limit ? null : buf;
}
