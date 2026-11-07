/**
 * Responses, headers, cookies and the small HTML pages.
 *
 * Every response carries the security headers below. Pages run no script
 * (script-src 'none') and load nothing from elsewhere; their one inline style
 * is allowed by its hash, and the font and favicon are static files from
 * public/ on this origin. The look follows penthera.org: the ink palette,
 * Helvetica titles, Departure Mono labels, one blue button per page. COOP is unsafe-none because Vercel's dashboard
 * watches the install popup's closed state and needs that value.
 */
import { createHash } from "node:crypto";

const STYLE = `
@font-face{font-family:"Departure Mono";src:url(/fonts/DepartureMono-Regular.woff2) format("woff2");font-weight:400;font-style:normal;font-display:swap}
:root{color-scheme:dark;--ground:#000;--plate:#15171b;--text-1:#fff;--text-2:rgba(255,255,255,.72);--text-3:rgba(255,255,255,.6);--edge:rgba(255,255,255,.45);--accent:#0000ed;--accent-ink:#7a7aff;--focus:#7a7aff;
--display:"Helvetica Neue",Helvetica,Arial,"Nimbus Sans",sans-serif;--px:"Departure Mono",ui-monospace,"SF Mono",Menlo,monospace;
--t-note:.8125rem;--t-small:.9375rem;--t-text:1.0625rem;--t-lead:clamp(1.375rem,2.4vw,1.75rem);--t-h2:clamp(2rem,4.4vw,3.5rem);--t-h1:clamp(2.5rem,6.4vw,5.5rem);--t-poster:clamp(2.625rem,8.2vw,7.75rem);
--measure:40rem;--gutter:16px;--target:44px;--veil:64px;--out:cubic-bezier(.23,1,.32,1)}
@media (min-width:720px){:root{--gutter:32px}}
@media (min-width:1100px){:root{--gutter:48px}}
*{box-sizing:border-box}
html{background:var(--ground);-webkit-text-size-adjust:100%}
body{margin:0;min-height:100vh;min-height:100dvh;display:flex;flex-direction:column;background:var(--ground);color:var(--text-2);font-family:var(--display);font-size:var(--t-text);line-height:1.6;letter-spacing:-.01em;font-variant-numeric:tabular-nums lining-nums;-webkit-font-smoothing:antialiased;overflow-x:clip}
::selection{background:var(--accent);color:#fff}
:focus-visible{outline:2px solid var(--focus);outline-offset:3px}
a{color:var(--accent-ink);text-underline-offset:3px;text-decoration-thickness:1px}
a:hover{background:var(--accent);color:#fff;text-decoration:none}
p{margin:0}
code{font-family:var(--px);font-size:var(--t-note);letter-spacing:.02em;color:var(--text-1);overflow-wrap:anywhere}
.top{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:24px var(--gutter) 0}
.mark{display:block;width:112px;height:auto}
.step{font-family:var(--px);font-size:var(--t-note);line-height:1;letter-spacing:.02em;color:var(--text-3);white-space:nowrap}
main{flex:1 0 auto;width:100%;max-width:calc(var(--measure) + 2 * var(--gutter));padding:clamp(48px,9vh,96px) var(--gutter) 0}
h1{margin:0 0 24px;font-family:var(--display);font-size:var(--t-h2);font-weight:500;line-height:1.02;letter-spacing:-.035em;color:var(--text-1);text-wrap:balance}
h1 .aside{color:var(--text-3)}
.one{max-width:calc(64rem + 2 * var(--gutter))}
.one h1{font-size:var(--t-h1)}
h2{margin:48px 0 16px;font-family:var(--display);font-size:var(--t-lead);font-weight:500;line-height:1.12;letter-spacing:-.02em;color:var(--text-1)}
.lede{max-width:36rem;color:var(--text-2)}
.lede+.lede,p+p{margin-top:16px}
.small{max-width:36rem;margin-top:24px;font-size:var(--t-small);line-height:1.5;color:var(--text-3)}
.list{list-style:none;margin:32px 0 0;padding:0;display:grid;grid-template-columns:minmax(0,1fr);gap:2px}
.row{display:flex;flex-wrap:wrap;align-items:center;gap:12px 16px;min-height:72px;padding:14px 16px;background:var(--plate)}
.pick{display:flex;align-items:center;gap:16px;flex:1 1 15rem;min-width:0;min-height:var(--target);cursor:pointer}
.off .pick{cursor:default}
.grow{flex:1 1 15rem;min-width:0}
.name{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:500;line-height:1.35;color:var(--text-1)}
.off .name{color:var(--text-2)}
.meta{display:block;margin-top:4px;font-family:var(--px);font-size:var(--t-note);line-height:1.4;letter-spacing:.02em;color:var(--text-3);overflow-wrap:anywhere}
.meta code{color:var(--text-2)}
.on{color:var(--accent-ink)}
.empty{padding:20px 16px;background:var(--plate);color:var(--text-2)}
input[type=checkbox]{-webkit-appearance:none;appearance:none;flex:none;display:grid;place-content:center;width:22px;height:22px;margin:0;border:1px solid var(--edge);border-radius:0;background:var(--ground);cursor:pointer;transition:background-color 120ms var(--out),border-color 120ms var(--out)}
input[type=checkbox]::before{content:"";width:12px;height:10px;background:#fff;clip-path:polygon(0 55%,14% 41%,38% 66%,86% 0,100% 14%,38% 100%);transform:scale(0);transition:transform 120ms var(--out)}
input[type=checkbox]:checked{background:var(--accent);border-color:#fff}
input[type=checkbox]:checked::before{transform:scale(1)}
input[type=checkbox]:disabled{cursor:default}
input[type=checkbox]:disabled:not(:checked){border-style:dashed;background:transparent}
.pick:hover input[type=checkbox]:not(:disabled){border-color:#fff}
.more{margin-top:16px}
.more a,.foot a{display:inline-flex;align-items:center;min-height:var(--target)}
.act{display:flex;flex-wrap:wrap;gap:16px;margin-top:32px}
.btn{position:relative;display:inline-flex;align-items:center;justify-content:center;gap:10px;min-height:var(--target);max-width:100%;padding:10px 18px;font-family:var(--px);font-size:var(--t-note);line-height:1.35;letter-spacing:.02em;text-align:left;text-decoration:none;color:var(--text-1);background:var(--ground);border:1px solid var(--text-1);border-radius:0;cursor:pointer;transition:transform 100ms var(--out),background-color 160ms var(--out),color 160ms var(--out)}
.btn:hover{background:#fff;color:#000}
.btn:active{transform:scale(.97)}
.btn.quiet{border-color:var(--edge);color:var(--text-2)}
.btn.quiet:hover{border-color:#fff;color:#000}
.btn.go{color:#fff;background:linear-gradient(180deg,#5a5aff 0%,#0000ed 55%,#0000b8 100%);border-color:rgba(255,255,255,.4);box-shadow:inset 0 1px 0 rgba(255,255,255,.5),0 0 0 2px var(--ground),0 0 0 3px #fff,0 10px 28px -8px rgba(0,0,237,.8)}
.btn.go:hover{color:#fff;background:linear-gradient(180deg,#7676ff 0%,#2a2aff 55%,#0000d0 100%)}
.row .btn{flex:0 1 auto;margin-left:auto}
.stack .grow{flex-basis:100%}
.stack .btn{margin-left:0}
.cap{display:block;margin-top:48px;font-family:var(--px);font-size:var(--t-note);line-height:1.4;letter-spacing:.02em;color:var(--text-3)}
textarea{display:block;width:100%;height:17rem;margin:12px 0 0;padding:16px;font-family:var(--px);font-size:var(--t-note);line-height:1.6;letter-spacing:.02em;color:var(--text-1);background:var(--plate);border:1px solid var(--edge);border-radius:0;resize:vertical;tab-size:2;white-space:pre;overflow-wrap:normal;overflow-x:auto}
textarea:focus-visible{outline-offset:0}
textarea+.lede{margin-top:32px}
.left{max-width:36rem;margin:24px 0 0;padding:16px 20px;background:var(--plate);display:grid;gap:12px}
.left div{display:grid;grid-template-columns:6rem minmax(0,1fr);gap:4px 16px}
.left dt{font-family:var(--px);font-size:var(--t-note);line-height:1.75;letter-spacing:.02em;color:var(--text-3)}
.left dd{margin:0;line-height:1.5;color:var(--text-1)}
.why{max-width:36rem;margin-top:32px;font-size:var(--t-small);line-height:1.5;color:var(--text-3)}
.why span{display:block;margin-bottom:4px;font-family:var(--px);font-size:var(--t-note);letter-spacing:.02em}
@media (max-width:480px){.left div{grid-template-columns:minmax(0,1fr)}}
.note{max-width:36rem;margin-top:24px;padding:16px 20px;background:var(--plate);color:var(--text-1)}
.steps{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:minmax(0,1fr);gap:2px;max-width:40rem}
.steps li{display:flex;gap:16px;padding:16px 20px;background:var(--plate);line-height:1.5}
.steps .n{flex:none;width:1.5ch;font-family:var(--px);font-size:var(--t-note);line-height:1.9;color:var(--accent-ink)}
.steps strong{font-weight:500;color:var(--text-1)}
.links{display:flex;flex-wrap:wrap;gap:0 24px;margin:16px 0 0;padding:0;list-style:none;font-family:var(--px);font-size:var(--t-note);letter-spacing:.02em}
.links a{display:inline-flex;align-items:center;min-height:var(--target)}
.links.col{flex-direction:column;align-items:flex-start}
.links.col a{display:block;min-height:0;padding:12px 0;line-height:1.4;overflow-wrap:anywhere}
.faq{margin-top:48px;background:var(--plate)}
.faq summary{display:flex;align-items:center;justify-content:space-between;gap:16px;min-height:64px;padding:12px 20px;list-style:none;cursor:pointer;font-size:var(--t-lead);font-weight:500;line-height:1.2;letter-spacing:-.02em;color:var(--text-1)}
.faq summary::-webkit-details-marker{display:none}
.faq summary::after{content:"+";flex:none;font-family:var(--px);font-size:var(--t-lead);line-height:1;color:var(--accent-ink)}
.faq[open] summary::after{content:"−"}
.faq summary:focus-visible{outline-offset:0}
.faq dl{margin:0;padding:4px 20px 0}
.faq dt{margin-top:20px;font-weight:500;line-height:1.35;color:var(--text-1)}
.faq dt:first-child{margin-top:0}
.faq dd{max-width:36rem;margin:4px 0 0;font-size:var(--t-small);line-height:1.5;color:var(--text-2)}
.faq .links{padding:0 20px 12px}
.foot{width:100%;max-width:calc(var(--measure) + 2 * var(--gutter));padding:64px var(--gutter) calc(var(--veil) + 16px);font-family:var(--px);font-size:var(--t-note);line-height:1.6;letter-spacing:.02em;color:var(--text-3)}
.foot ul{display:flex;flex-wrap:wrap;gap:0 24px;margin:8px 0 0;padding:0;list-style:none}
.home{display:grid;place-items:center;max-width:none;padding-bottom:var(--veil);text-align:center}
.home .shrug{margin:0 0 32px;max-width:none;font-family:var(--display);font-size:var(--t-poster);font-weight:500;line-height:1;letter-spacing:-.02em;color:var(--text-1);white-space:pre}
.home .line{margin:0 auto 40px;max-width:24ch;font-size:var(--t-lead);line-height:1.3;letter-spacing:-.02em;color:var(--text-1);text-wrap:balance}
.veil{position:fixed;inset:auto 0 0;z-index:9;height:var(--veil);pointer-events:none}
.veil i{position:absolute;inset:auto 0 0;-webkit-backdrop-filter:blur(var(--b));backdrop-filter:blur(var(--b));-webkit-mask-image:linear-gradient(to top,#000 var(--s),transparent);mask-image:linear-gradient(to top,#000 var(--s),transparent)}
.veil i:nth-child(1){--b:2px;--s:50%;height:100%}
.veil i:nth-child(2){--b:6px;--s:40%;height:64%}
.veil i:nth-child(3){--b:16px;--s:20%;height:34%}
@media (forced-colors:active){input[type=checkbox]::before{background:CanvasText}.btn.go{border-color:ButtonText}}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
`;
const STYLE_HASH = createHash("sha256").update(STYLE).digest("base64");

export const CSP = [
  "default-src 'none'",
  `style-src 'sha256-${STYLE_HASH}'`,
  // Same-origin files only, from public/: the favicon and Departure Mono. Nothing from elsewhere.
  "img-src 'self'",
  "font-src 'self'",
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

/**
 * A page: the wordmark, the body, the footer. `step` is the setup step ("Step 1 of 2"), `footer: false`
 * leaves the footer out, and `main` names a layout class for <main>.
 */
export function html(status, title, body, { cookies, step = "", footer = true, main = "", refresh = null } = {}) {
  // `refresh` ({ seconds, url }, same origin) takes the visitor on by itself when the only next step is to wait. No script needed.
  const go = refresh ? `<meta http-equiv="refresh" content="${Number(refresh.seconds) | 0};url=${esc(refresh.url)}">` : "";
  const head = `<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex"><meta name="color-scheme" content="dark">${go}<link rel="icon" href="/favicon.svg" type="image/svg+xml"><title>${esc(title)}</title><style>${STYLE}</style>`;
  const top = `<header class="top">${MARK}${step ? `<span class="step">${esc(step)}</span>` : ""}</header>`;
  const page = `<!doctype html><html lang="en"><head>${head}</head><body>${top}<main${main ? ` class="${esc(main)}"` : ""}>${body}</main>${footer ? FOOTER : ""}${VEIL}</body></html>`;
  return new Response(page, { status, headers: withHeaders({ "Content-Type": "text/html; charset=utf-8" }, cookies) });
}

export function redirect(location, { cookies, status = 303 } = {}) {
  return new Response(null, { status, headers: withHeaders({ Location: location }, cookies) });
}

/**
 * A message page for errors and dead ends, written like an engineer next to you: what happened, what
 * is left behind on each side (`left`: { penthera, vercel }), one way on (`action`: { href, label },
 * same origin), and why we check (`why`). `reason` is a stable data-reason for pages that share a
 * status; `refresh` takes the visitor on by itself when the only next step is to wait.
 */
export function message(status, title, text, { cookies, action, reason, left, why, refresh } = {}) {
  const r = reason ? ` data-reason="${esc(reason)}"` : "";
  const rows = left ? [["Penthera", left.penthera], ["Vercel", left.vercel]].filter(([, v]) => v) : [];
  const block = rows.length ? `<dl class="left">${rows.map(([k, v]) => `<div><dt>${k}</dt><dd>${esc(v)}</dd></div>`).join("")}</dl>` : "";
  const out = action ? `<div class="act"><a class="btn go" href="${esc(action.href)}">${esc(action.label)}</a></div>` : "";
  const because = why ? `<p class="why"><span>Why we check this</span>${esc(why)}</p>` : "";
  return html(status, title, `<h1${r}>${esc(title)}</h1><p class="lede">${esc(text)}</p>${block}${out}${because}`, { cookies, main: "one", refresh });
}

/** The wordmark, drawn: one path in brushed metal, lit from above. */
const MARK = `<svg class="mark" viewBox="0 0 279 63" role="img" aria-label="Penthera"><defs><linearGradient id="metal" x1="0" y1="0" x2="0" y2="63" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#fff"/><stop offset=".48" stop-color="#d4d4d4"/><stop offset=".6" stop-color="#8c8c8c"/><stop offset=".66" stop-color="#e6e6e6"/><stop offset="1" stop-color="#a8a8a8"/></linearGradient></defs><path fill="url(#metal)" d="M13.0292 54.9484L20.4241 57.491H0L7.39494 54.9484V3.53139L0 0.988789H16.7619C25.5654 0.988789 31.0588 5.36771 31.0588 12.0774C31.0588 21.9652 20.4241 27.0504 13.0292 27.5448V54.9484ZM13.0292 1.69507V26.8386C17.4661 26.4854 25.0019 24.0135 25.0019 13.9137C25.0019 7.06278 20.7763 1.69507 13.0292 1.69507Z M46.8324 56.7848C53.7344 56.7848 58.453 52.8296 61.4815 42.1648L62.6083 38.2096H63.0309L58.1713 57.491H29.4367L36.8316 54.9484V3.53139L29.4367 0.988789H58.1009L61.1997 18.7164H60.7772L60.0025 14.6906C58.2418 5.50896 53.9457 1.69507 46.0577 1.69507H42.4659V23.3778H57.5375V23.5191L42.4659 26.9092V56.7848H46.8324Z M101.382 0.988789L93.9873 3.46076L93.2126 58.6917L68.2811 4.52018L69.1262 54.9484L76.5916 57.491H59.4071L66.8725 54.9484L67.6472 3.60202L59.8297 0.988789H73.211L92.79 44.7074L91.9449 3.53139L84.5499 0.988789H101.382Z M129.767 0.988789L132.866 18.7164H132.444L131.599 14.1962C129.838 4.73206 124.415 1.69507 119.415 1.69507H118.288V54.9484L125.823 57.491H105.118L112.653 54.9484V1.69507H111.808C107.09 1.69507 101.385 4.66143 99.6243 14.1962L98.7791 18.7164H98.3566L101.455 0.988789H129.767Z M137.934 3.53139L130.539 0.988789H150.964L143.569 3.53139V25.7791H160.119V3.53139L152.724 0.988789H173.148L165.753 3.53139V54.9484L173.148 57.491H152.724L160.119 54.9484V26.4854H143.569V54.9484L150.964 57.491H130.539L137.934 54.9484V3.53139Z M188.032 56.7848C194.934 56.7848 199.653 52.8296 202.681 42.1648L203.808 38.2096H204.231L199.371 57.491H170.637L178.032 54.9484V3.53139L170.637 0.988789H199.301L202.4 18.7164H201.977L201.202 14.6906C199.442 5.50896 195.146 1.69507 187.258 1.69507H183.666V23.3778H198.737V23.5191L183.666 26.9092V56.7848H188.032Z M214.34 54.9484L221.735 57.491H201.311L208.706 54.9484V3.53139L201.311 0.988789H218.073C226.877 0.988789 232.37 5.15583 232.37 11.0179C232.37 17.3744 227.018 21.4002 221.383 23.3072L235.891 63H235.68L214.34 24.6491V54.9484ZM214.34 1.69507V24.0135C221.172 23.8016 226.313 19.2814 226.313 12.5011C226.313 6.42713 222.088 1.69507 214.34 1.69507Z M258.576 57.491L265.971 55.0191L259.21 31.5H247.589L241.814 55.0191L249.279 57.491H232.518L239.49 54.8778L255.195 0L271.605 54.9484L279 57.491H258.576ZM247.8 30.7937H258.998L252.871 9.88789L247.8 30.7937Z"/></svg>`;

/** The bottom blur: three layers, each blurring more over a shorter band nearer the edge. */
const VEIL = `<div class="veil" aria-hidden="true"><i></i><i></i><i></i></div>`;

export const FOOTER = `<footer class="foot"><p>Penthera runs in your own GitHub Actions. This server keeps an encrypted install token and the projects you turned the check on for, and deletes both when you uninstall.</p><ul><li><a href="https://penthera.org" target="_blank" rel="noopener noreferrer">penthera.org</a></li><li><a href="https://docs.penthera.org/vercel/terms" target="_blank" rel="noopener noreferrer">Terms</a></li><li><a href="https://docs.penthera.org/vercel/privacy" target="_blank" rel="noopener noreferrer">Privacy</a></li></ul></footer>`;

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
  return readCapped(request.body, limit);
}

/**
 * Reads a byte stream into a Buffer, counting as it goes, and stops reading the moment it passes
 * `limit`: a chunked body with no or a false Content-Length is never read past the cap. Returns
 * null when it is over. A null stream is an empty body.
 */
export async function readCapped(stream, limit) {
  if (!stream) return Buffer.alloc(0);
  const reader = stream.getReader();
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) {
        reader.cancel().catch(() => {});
        return null;
      }
      chunks.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
    }
  } finally {
    reader.releaseLock?.();
  }
  return Buffer.concat(chunks, size);
}
