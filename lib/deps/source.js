/**
 * Where a package's files come from, offline.
 *
 * The capability scanner reads files through a small source interface so the
 * same code can scan an installed folder in node_modules or a tarball from
 * npm's local content cache. The cache is what makes `--diff` work without a
 * network: npm stores every tarball it has downloaded under its integrity hash,
 * and a lockfile records that hash, so an old version can be read back exactly
 * and verified byte for byte.
 */
import { readFileSync, readdirSync, statSync, realpathSync, existsSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { createHash } from "node:crypto";
import { gunzipSync } from "node:zlib";
import { homedir } from "node:os";
import { trimEndChars, trimStartChars, cutAtFirst } from "../linear-text.js";

/**
 * Most files a package may have. The same as the tarball entry cap, so any
 * tarball the reader accepts is read whole. A source with more sets
 * `truncated`, and the scan then fails closed (see scanPackage): files past
 * the cap were never read, so the package cannot be called clean.
 */
export const MAX_FILES = 50_000;

/** Files of an installed package folder. Skips nested node_modules and symlinks. */
export class DirSource {
  constructor(dir, { skip, maxFiles = MAX_FILES } = {}) {
    this.dir = dir;
    this.kind = "installed";
    this.skip = skip || null;
    this.maxFiles = maxFiles;
    this.truncated = false;
  }

  files() {
    if (this._files) return this._files;
    const out = [];
    let realRoot = this.dir;
    try { realRoot = realpathSync(this.dir); } catch { /* keep as given */ }
    const inside = (t) => t === realRoot || t.startsWith(realRoot + sep);
    const seen = new Set([realRoot]);
    const rel = (p) => relative(this.dir, p).split(sep).join("/");
    const walk = (d) => {
      let entries;
      try { entries = readdirSync(d, { withFileTypes: true }); } catch (err) {
        this.anomaly ??= `${rel(d) || "the package folder"} could not be listed (${err.code || err.message})`;
        return;
      }
      entries.sort((a, b) => a.name.localeCompare(b.name));
      for (const e of entries) {
        if (this.truncated) return;
        const p = join(d, e.name);
        if (e.isSymbolicLink()) {
          if (e.name === "node_modules" || e.name === ".git") continue;
          // Read a link that stays inside the package; one that leaves it or leads
          // nowhere makes the package unscanned (scanPackage reads `anomaly`), never clean.
          let target = null;
          try { target = realpathSync(p); } catch { /* broken */ }
          if (!target || !inside(target)) {
            this.anomaly ??= `${rel(p)} is a link ${target ? "out of the package" : "to nothing"}, so what it points to was not read`;
            continue;
          }
          let st;
          try { st = statSync(p); } catch { continue; }
          if (st.isDirectory()) {
            if (seen.has(target)) continue; // a loop, or a folder already read
            seen.add(target);
            walk(p);
          } else if (st.isFile()) {
            if (out.length >= this.maxFiles) { this.truncated = true; return; }
            out.push(rel(p));
          } else {
            this.anomaly ??= `${rel(p)} links to something that is not a regular file, so it was not read`;
          }
          continue;
        }
        if (e.isDirectory()) {
          if (e.name === "node_modules" || e.name === ".git" || this.skip?.has(e.name)) continue;
          walk(p);
        } else if (e.isFile()) {
          if (out.length >= this.maxFiles) { this.truncated = true; return; }
          out.push(relative(this.dir, p).split(sep).join("/"));
        } else {
          // A FIFO, a socket or a device: no package manager installs one, and it is
          // never read. The package is unscanned (scanPackage reads `anomaly`), never clean.
          this.anomaly ??= `the installed folder holds ${relative(this.dir, p).split(sep).join("/")}, which is not a regular file, so it was not read`;
        }
      }
    };
    walk(this.dir);
    this._files = out;
    return out;
  }

  // stat, not lstat: a followed link's size is its target's, so the size caps hold.
  size(rel) {
    try { return statSync(join(this.dir, rel)).size; } catch { return 0; }
  }

  read(rel) {
    return readFileSync(join(this.dir, rel));
  }
}

/**
 * Files of an unpacked tarball, held in memory. `anomaly` is set when the
 * archive could not be read safely (the scan then fails closed, see
 * scanPackage). `oversize` maps files too large to hold to their real size.
 */
export class MapSource {
  constructor(map, kind = "npm-cache", { anomaly = null, maxFiles = MAX_FILES } = {}) {
    this.map = map;
    this.kind = kind;
    this.anomaly = anomaly;
    this.oversize = map.oversize || new Map();
    this.truncated = map.size > maxFiles;
    this.maxFiles = maxFiles;
  }

  files() {
    return [...this.map.keys()].sort().slice(0, this.maxFiles);
  }

  size(rel) {
    return this.oversize.get(rel) ?? (this.map.get(rel)?.length || 0);
  }

  read(rel) {
    return this.map.get(rel);
  }
}

// ── Tarballs ──────────────────────────────────────────────────────────────

/** Unpacked size limits, enforced while reading, not afterwards. */
export const MAX_UNPACKED_BYTES = 256 * 1024 * 1024;
export const MAX_FILE_BYTES = 64 * 1024 * 1024;
const MAX_ENTRIES = 50_000;

/** A tarball that could not be parsed unambiguously. Callers fail closed. */
export class TarError extends Error {
  constructor(message) {
    super(message);
    this.name = "TarError";
  }
}

function cstr(buf, start, len) {
  const s = buf.subarray(start, start + len);
  const z = s.indexOf(0);
  return (z === -1 ? s : s.subarray(0, z)).toString("utf-8");
}

/**
 * A numeric header field: octal (NUL or space terminated), or GNU base-256
 * (high bit of the first byte set). Anything else is an error, never 0: a size
 * read wrong desyncs the parser from what npm (node-tar) extracts.
 */
export function tarNumber(header, start, len, field) {
  const f = header.subarray(start, start + len);
  if (f[0] & 0x80) {
    if (f[0] === 0xff) throw new TarError(`negative base-256 ${field}`);
    let n = BigInt(f[0] & 0x7f);
    for (let i = 1; i < f.length; i++) n = (n << 8n) | BigInt(f[i]);
    if (n > BigInt(Number.MAX_SAFE_INTEGER)) throw new TarError(`${field} too large`);
    return Number(n);
  }
  const s = trimStartChars(trimEndChars(f.toString("latin1"), "\0 "), " ");
  if (s === "") return 0;
  if (!/^[0-7]+$/.test(s)) throw new TarError(`malformed ${field} ${JSON.stringify(s)}`);
  return parseInt(s, 8);
}

function checksumOk(header) {
  const want = tarNumber(header, 148, 8, "checksum");
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 32 : header[i];
  return sum === want;
}

/** pax extended header records ("<len> <key>=<value>\n"). */
function parsePax(body) {
  const out = {};
  let i = 0;
  while (i < body.length) {
    if (body[i] === 0) break; // NUL padding after the last record
    const sp = body.indexOf(0x20, i);
    if (sp === -1) throw new TarError("malformed pax header");
    const len = Number(body.subarray(i, sp).toString("latin1"));
    if (!Number.isInteger(len) || len <= sp - i || i + len > body.length || body[i + len - 1] !== 0x0a) {
      throw new TarError("malformed pax record");
    }
    const rec = body.subarray(sp + 1, i + len - 1).toString("utf-8");
    const eq = rec.indexOf("=");
    if (eq === -1) throw new TarError("malformed pax record");
    out[rec.slice(0, eq)] = rec.slice(eq + 1);
    i += len;
  }
  return out;
}

/**
 * Tar reader (ustar, pax and GNU extensions). Returns Map<path, Buffer> with
 * the leading "package/" directory stripped. Only regular files are kept;
 * paths that try to climb out ("..") are dropped. Files over MAX_FILE_BYTES
 * are listed in map.oversize (path -> size) instead of being copied.
 *
 * Fails closed: a bad checksum, a malformed or impossible size, a truncated
 * entry, data after the end-of-archive marker, or a pax global header that
 * sets size, path or linkpath throws TarError. These are the ways known to
 * make this reader frame entries differently from npm (node-tar); this is a
 * small reader, not a proof that the two can never disagree.
 */
export function untar(buf, { maxTotal = MAX_UNPACKED_BYTES, maxFile = MAX_FILE_BYTES } = {}) {
  const files = new Map();
  files.oversize = new Map();
  let off = 0;
  let pax = {};
  let longName = null;
  let total = 0;
  let entries = 0;
  while (off + 512 <= buf.length) {
    const header = buf.subarray(off, off + 512);
    if (header.every((b) => b === 0)) {
      // End of archive. Everything after it must be zero padding too.
      for (let i = off; i < buf.length; i++) if (buf[i] !== 0) throw new TarError(`data after the end-of-archive marker at byte ${off}`);
      return files;
    }
    if (++entries > MAX_ENTRIES) throw new TarError(`more than ${MAX_ENTRIES} entries`);
    if (!checksumOk(header)) throw new TarError(`bad header checksum at byte ${off}`);
    const type = String.fromCharCode(header[156] || 48);
    let size = tarNumber(header, 124, 12, "size");
    if (pax.size != null && type !== "x" && type !== "g" && type !== "L" && type !== "K") {
      if (!/^\d+$/.test(pax.size)) throw new TarError(`malformed pax size ${JSON.stringify(pax.size)}`);
      size = Number(pax.size);
    }
    if (size > maxTotal) throw new TarError(`entry larger than ${maxTotal} bytes`);
    if (off + 512 + size > buf.length) throw new TarError(`truncated entry at byte ${off}`);
    total += size;
    if (total > maxTotal) throw new TarError(`unpacked size over ${maxTotal} bytes`);
    let name = cstr(header, 0, 100);
    const ustar = header.subarray(257, 263).toString("latin1") === "ustar\0";
    const prefix = ustar ? cstr(header, 345, 155) : "";
    if (prefix) name = `${prefix}/${name}`;
    const body = buf.subarray(off + 512, off + 512 + size);
    off += 512 + Math.ceil(size / 512) * 512;

    if (type === "x") { // pax extended header, for the next entry
      pax = parsePax(body);
      continue;
    }
    if (type === "g") {
      // pax global header. node-tar applies its keys to every later entry; this
      // reader does not, so one that changes how entries are framed or named
      // is refused rather than read differently from npm.
      const g = parsePax(body);
      for (const k of ["size", "path", "linkpath"]) {
        if (Object.hasOwn(g, k)) throw new TarError(`pax global header sets ${k}`);
      }
      continue;
    }
    if (type === "L") { // GNU long name
      longName = cstr(body, 0, body.length);
      continue;
    }
    if (type === "K") continue; // GNU long link name
    if (pax.path != null) name = pax.path;
    else if (longName) name = longName;
    pax = {};
    longName = null;
    if (type !== "0" && type !== "\0" && type !== "7") continue;
    const parts = name.split("/").filter(Boolean);
    parts.shift(); // top-level folder, usually "package"
    if (parts.length === 0 || parts.includes("..")) continue;
    const rel = parts.join("/");
    if (size > maxFile) {
      files.set(rel, Buffer.alloc(0));
      files.oversize.set(rel, size);
    } else {
      files.set(rel, Buffer.from(body));
      files.oversize.delete(rel);
    }
  }
  if (off !== buf.length) throw new TarError(`trailing partial block at byte ${off}`);
  return files;
}

/** gunzip with an output cap, then untar. Throws on any anomaly. */
export function unpackTgz(tgz) {
  return untar(gunzipSync(tgz, { maxOutputLength: MAX_UNPACKED_BYTES }));
}

/** A verified tarball that could not be unpacked safely: no files, an anomaly. */
function unreadable(kind, e) {
  return new MapSource(new Map(), kind, { anomaly: `tarball could not be read safely (${e.message})` });
}

/** Split an SRI string into { algo, hex } entries. */
export function parseIntegrity(sri) {
  return String(sri || "").split(/\s+/).filter(Boolean).map((s) => {
    const i = s.indexOf("-");
    if (i === -1) return null;
    const algo = s.slice(0, i);
    const b64 = cutAtFirst(s.slice(i + 1), "?\n");
    return { algo, hex: Buffer.from(b64, "base64").toString("hex") };
  }).filter((x) => x && /^sha(1|256|384|512)$/.test(x.algo) && x.hex);
}

/** True when the bytes match the SRI integrity string. */
export function verifyIntegrity(bytes, sri) {
  const entries = parseIntegrity(sri);
  if (entries.length === 0) return false;
  return entries.some(({ algo, hex }) => createHash(algo).update(bytes).digest("hex") === hex);
}

/** npm's cache directory: npm_config_cache, else ~/.npm. */
export function npmCacheDir(env = process.env) {
  return env.npm_config_cache || env.NPM_CONFIG_CACHE || join(homedir(), ".npm");
}

/**
 * Read a package tarball from npm's content-addressed cache (cacache) by its
 * lockfile integrity, verify it, and unpack it. Returns a MapSource or null.
 */
export function sourceFromNpmCache(integrity, cacheDir = npmCacheDir()) {
  for (const { algo, hex } of parseIntegrity(integrity)) {
    const p = join(cacheDir, "_cacache", "content-v2", algo, hex.slice(0, 2), hex.slice(2, 4), hex.slice(4));
    if (!existsSync(p)) continue;
    let tgz;
    try { tgz = readFileSync(p); } catch { continue; }
    if (!verifyIntegrity(tgz, integrity)) continue; // corrupt entry, try the next hash
    // The bytes are the ones the lockfile pins. If they do not unpack cleanly,
    // say so: returning null would let the package pass as merely "not cached".
    try {
      return new MapSource(unpackTgz(tgz), "npm-cache");
    } catch (e) {
      return unreadable("npm-cache", e);
    }
  }
  return null;
}

/** Unpack a verified tarball buffer (used by --online). */
export function sourceFromTarball(tgz, integrity, kind = "registry") {
  if (integrity && !verifyIntegrity(tgz, integrity)) return null;
  try {
    return new MapSource(unpackTgz(tgz), kind);
  } catch (e) {
    return unreadable(kind, e);
  }
}
