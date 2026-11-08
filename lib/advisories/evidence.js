/**
 * Evidence that a runtime or server is in use, and at which version.
 *
 * Black-box: what one HTTP response says about itself (Server, X-Powered-By,
 * a PHPSESSID cookie, links to .php pages). White-box: what the repository
 * pins (Dockerfile and compose images, .tool-versions, .php-version, .nvmrc,
 * .python-version, runtime.txt, composer.json).
 *
 * Every item is `{ product, version, kind, where, raw, distro? }`:
 *   version  the parsed version (lib/advisories/versions.js) or null
 *   kind     "exact"   an upstream x.y.z
 *            "branch"  only x.y (a floating Docker tag, `.python-version: 3.12`)
 *            "distro"  a version with a distribution build string, or on a
 *                      response whose Server header names a distribution
 *            "present" the product is in use, the version is not visible
 *   where    the header, cookie or file it came from
 *   raw      the text it was read from (a header value, a line), for the report
 *   banner   true for black-box evidence (a header), which may come from a
 *            distribution package even without a distribution token
 *
 * Nothing here decides whether anything is vulnerable; that is index.js.
 */
import { readdirSync, lstatSync, openSync, fstatSync, readSync, closeSync, constants } from "node:fs";
import { join, relative, basename } from "node:path";
import { PRODUCTS, DISTRO_HINT } from "./products.js";
import { parseVersion } from "./versions.js";

const clip = (s, n = 200) => (s.length > n ? `${s.slice(0, n)}…` : s);

function kindOf(product, v, distro) {
  if (!v) return "present";
  // A pre-release is an upstream build, not a distribution one.
  if (v.patch !== null) return distro || v.suffix ? "distro" : "exact";
  // "php:8" spans release lines; "php:8.3" and "node:20" name one.
  return PRODUCTS[product].branchOf(v) ? "branch" : "present";
}

// ── Black-box ─────────────────────────────────────────────────────────────

/**
 * Evidence from one response's headers, cookies and page links.
 * @param {{ headers?: Record<string,string>, cookieNames?: string[], phpLink?: string|null }} fp
 *   what lib/crawler.js fingerprint() collected for the homepage
 * @param {{ phpPaths?: string[] }} [more]  .php paths the endpoint discovery found reachable
 */
export function evidenceFromResponse(fp = {}, more = {}) {
  const headers = fp.headers || {};
  const out = [];
  const server = String(headers.server || "");
  const poweredBy = String(headers["x-powered-by"] || "");
  const distro = DISTRO_HINT.test(server);

  for (const [id, p] of Object.entries(PRODUCTS)) {
    let found = false;
    for (const [name, value] of [["server", server], ["x-powered-by", poweredBy]]) {
      if (!value) continue;
      const m = p.banner && p.banner.exec(value);
      if (m) {
        const v = parseVersion(m[1]);
        if (v) {
          out.push({ product: id, version: v, kind: kindOf(id, v, distro), where: `${name} header`, raw: clip(`${name}: ${value}`), banner: true });
          found = true;
          continue;
        }
      }
      if (p.present && p.present.test(value)) {
        out.push({ product: id, version: null, kind: "present", where: `${name} header`, raw: clip(`${name}: ${value}`) });
        found = true;
      }
    }
    if (id === "php" && !found) {
      if ((fp.cookieNames || []).some((n) => n.toUpperCase() === "PHPSESSID")) {
        out.push({ product: id, version: null, kind: "present", where: "Set-Cookie", raw: "PHPSESSID cookie (PHP's default session cookie name)" });
        found = true;
      }
    }
    if (id === "php" && !found) {
      const link = fp.phpLink || (more.phpPaths || [])[0];
      if (link) out.push({ product: id, version: null, kind: "present", where: fp.phpLink ? "homepage links" : "endpoint discovery", raw: clip(`.php page: ${link}`) });
    }
  }
  return dedupe(out);
}

// ── White-box ─────────────────────────────────────────────────────────────

export const RUNTIME_PIN_SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", "coverage", "reports", "vendor",
  "venv", ".venv", "site-packages", "__pycache__", ".tox", ".nox", ".obsidian",
]);
const MAX_DEPTH = 4;
const MAX_FILE_BYTES = 256 * 1024;

const isDockerfile = (n) => /^(?:Dockerfile|Containerfile)(?:\..+)?$/i.test(n) || /\.(?:dockerfile|containerfile)$/i.test(n);
const isCompose = (n) => /^(?:docker-)?compose(?:\.[\w-]+)?\.ya?ml$/i.test(n);
const VERSION_FILES = new Set(Object.values(PRODUCTS).flatMap((p) => p.versionFiles));
const ROOT_ONLY = new Set([".tool-versions", "runtime.txt", "composer.json"]);

/** Would the runtime-pin check read a file with this name at this folder depth (0 = repo root)? */
export function isRuntimePinFile(name, depth) {
  if (depth > MAX_DEPTH) return false;
  if (isDockerfile(name) || isCompose(name) || VERSION_FILES.has(name)) return true;
  return depth === 0 && ROOT_ONLY.has(name);
}

function readSmall(path) {
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK || 0) | (constants.O_NOFOLLOW || 0));
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > MAX_FILE_BYTES) return null;
    const buf = Buffer.alloc(st.size);
    const n = st.size ? readSync(fd, buf, 0, st.size, 0) : 0;
    return buf.subarray(0, n).toString("utf-8");
  } catch {
    return null;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function walk(dir, depth, files) {
  if (depth > MAX_DEPTH) return;
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (RUNTIME_PIN_SKIP_DIRS.has(e.name)) continue;
    const full = join(dir, e.name);
    if (e.isFile()) {
      if (isRuntimePinFile(e.name, depth)) files.push({ full, depth });
      continue;
    }
    if (!e.isDirectory()) continue;
    // Not a symlinked folder, and not a nested repo or worktree.
    let st;
    try { st = lstatSync(full); } catch { continue; }
    if (!st.isDirectory()) continue;
    try { lstatSync(join(full, ".git")); continue; } catch { /* no nested .git */ }
    walk(full, depth + 1, files);
  }
}

/** The release line a codename stands for (`lts/iron`, `iron` → "20"), or null. */
function aliasLine(product, value) {
  const name = value.toLowerCase().replace(/^lts\//, "");
  return Object.hasOwn(PRODUCTS[product].lineAliases || {}, name) ? PRODUCTS[product].lineAliases[name] : null;
}

const imageProduct = new Map(Object.entries(PRODUCTS).flatMap(([id, p]) => p.dockerImages.map((img) => [img, id])));

/**
 * `php:8.3.12-fpm-alpine`, `docker.io/library/node:20`, `python@sha256:…`.
 * Official images are upstream builds, so a variant after the version
 * (`-fpm-alpine`, `-slim-bookworm`) is not a distro build string.
 */
export function parseImageRef(ref) {
  const noDigest = ref.split("@")[0];
  const slash = noDigest.lastIndexOf("/");
  const colon = noDigest.indexOf(":", slash + 1);
  const repo = colon === -1 ? noDigest : noDigest.slice(0, colon);
  const tag = colon === -1 ? "" : noDigest.slice(colon + 1);
  const path = repo.toLowerCase().replace(/^(?:docker\.io\/)?(?:library\/)?/, "");
  const product = imageProduct.get(path);
  if (!product) return null;
  // `8.6.0RC4-fpm` and `3.15.0rc1-slim` are pre-release images; `iron` and
  // `jod-alpine` are Node.js LTS codenames.
  const m = /^(\d+(?:\.\d+){0,2}(?:(?:RC|rc|a|b)\d+)?)(?:$|-)/.exec(tag);
  const alias = m ? null : aliasLine(product, tag.split("-")[0]);
  const v = m ? parseVersion(m[1]) : alias ? parseVersion(alias) : null;
  return { product, version: v, kind: kindOf(product, v, false), tag: tag || "latest" };
}

function fromDockerfile(text, where) {
  const out = [];
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)/i.exec(line);
    if (!m || m[1].includes("$")) continue;
    const img = parseImageRef(m[1]);
    if (img) out.push({ product: img.product, version: img.version, kind: img.kind, where, raw: clip(line.trim()) });
  }
  return out;
}

function fromCompose(text, where) {
  const out = [];
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*image:\s*["']?([^\s"'#]+)/.exec(line);
    if (!m || m[1].includes("$")) continue;
    const img = parseImageRef(m[1]);
    if (img) out.push({ product: img.product, version: img.version, kind: img.kind, where, raw: clip(line.trim()) });
  }
  return out;
}

function versionLine(product, value, where, raw) {
  const v = parseVersion(aliasLine(product, value) ?? value);
  return { product, version: v, kind: kindOf(product, v, false), where, raw: clip(raw) };
}

function fromToolVersions(text, where) {
  const out = [];
  for (const line of text.split(/\r?\n/)) {
    const [tool, value] = line.trim().split(/\s+/);
    if (!tool || !value || tool.startsWith("#")) continue;
    const id = Object.keys(PRODUCTS).find((k) => PRODUCTS[k].toolVersions.includes(tool));
    if (id) out.push(versionLine(id, value, where, line.trim()));
  }
  return out;
}

function fromVersionFile(name, text, where) {
  const id = Object.keys(PRODUCTS).find((k) => PRODUCTS[k].versionFiles.includes(name));
  const value = text.split(/\r?\n/).map((l) => l.trim()).find((l) => l && !l.startsWith("#"));
  if (!id || !value) return [];
  return [versionLine(id, value, where, `${name}: ${value}`)];
}

function fromComposer(text, where) {
  let j;
  try { j = JSON.parse(text); } catch { return []; }
  if (!j || typeof j !== "object") return [];
  // `require.php` is a constraint and `config.platform.php` a version Composer
  // pretends to have while resolving; neither is the PHP that runs. Both only
  // say PHP is in use.
  const constraint = typeof j.require?.php === "string" ? ` (require.php: ${clip(j.require.php, 60)})` : "";
  return [{ product: "php", version: null, kind: "present", where, raw: `composer.json${constraint}` }];
}

/**
 * Evidence from a repository's pins.
 * @param {string} root
 */
export function evidenceFromRepo(root) {
  const files = [];
  walk(root, 0, files);
  const out = [];
  for (const { full } of files) {
    const text = readSmall(full);
    if (text === null) continue;
    const name = basename(full);
    const where = relative(root, full).split("\\").join("/");
    if (isDockerfile(name)) out.push(...fromDockerfile(text, where));
    else if (isCompose(name)) out.push(...fromCompose(text, where));
    else if (name === ".tool-versions") out.push(...fromToolVersions(text, where));
    else if (name === "runtime.txt") {
      const m = /^[ \t]*python-(\d+\.\d+(?:\.\d+)?)[ \t]*\r?$/m.exec(text);
      if (m) out.push(versionLine("python", m[1], where, `runtime.txt: python-${m[1]}`));
    } else if (name === "composer.json") out.push(...fromComposer(text, where));
    else out.push(...fromVersionFile(name, text, where));
  }
  return dedupe(out);
}

function dedupe(items) {
  const seen = new Set();
  return items.filter((e) => {
    const k = `${e.product}|${e.version?.raw ?? ""}|${e.kind}|${e.where}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}
