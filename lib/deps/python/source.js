/**
 * Where a Python package's files come from, offline.
 *
 *   - An installed distribution in a virtualenv: site-packages/*.dist-info
 *     names the package (METADATA) and lists its files with hashes (RECORD).
 *     No pip, no interpreter: the files are read as data.
 *   - pip's HTTP cache (http-v2/.../*.body): every wheel or sdist pip downloaded,
 *     stored as raw bytes. Matched to a lockfile by sha256, so what is read is
 *     exactly the artifact the lockfile pinned.
 *   - uv's cache (wheels-vN/pypi/<name>/): unpacked wheels. Accepted when uv
 *     recorded a hash the lockfile also lists, or when uv fetched it from the
 *     lockfile's own files.pythonhosted.org URL (those paths are
 *     content-addressed), and the unpacked files still match their RECORD.
 *   - A local path dependency: the folder itself.
 *
 * Sources share the files()/read()/size() interface of lib/deps/source.js.
 */
import { readFileSync, readdirSync, existsSync, statSync, lstatSync, realpathSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { createHash } from "node:crypto";
import { inflateRawSync, gunzipSync } from "node:zlib";
import { homedir } from "node:os";
import { DirSource, MapSource, untar, MAX_FILES } from "../source.js";
import { normalizeName } from "./lockfiles.js";
import { recordHash } from "./capabilities.js";
import { readRepoFile } from "../../fs-safe.js";

// Not part of a local package's source: environments, caches, build output.
const LOCAL_SKIP = new Set([".venv", "venv", ".tox", ".nox", "__pycache__", ".mypy_cache", ".pytest_cache", "build", "dist", ".eggs"]);
const MAX_ARCHIVE_BYTES = 512 * 1024 * 1024;
const MAX_UNPACKED_BYTES = 256 * 1024 * 1024;
const MAX_META_BYTES = 16 * 1024 * 1024;

/**
 * A venv file the scanned repo controls (.venv/.../METADATA, RECORD, a .pth,
 * a module): a regular file only, never a FIFO that waits for a writer or a
 * link to /dev/zero. A link to a regular file is followed, as Python does.
 */
const readRegular = (p, encoding = null, maxBytes = MAX_META_BYTES) => readRepoFile(p, { followLinks: true, encoding, maxBytes });
export { readRegular };

// ── Virtualenvs ───────────────────────────────────────────────────────────

/** site-packages folders inside a virtualenv (posix lib/pythonX.Y, Windows Lib). */
export function sitePackagesDirs(venv) {
  const out = [];
  if (/site-packages[\\/]?$/.test(venv) && existsSync(venv)) return [resolve(venv)];
  for (const lib of ["lib", "lib64", "Lib"]) {
    const d = join(venv, lib);
    let entries;
    try { entries = readdirSync(d); } catch { continue; }
    if (entries.includes("site-packages")) out.push(join(d, "site-packages"));
    for (const e of entries.sort()) {
      if (/^(?:python|pypy)\d/.test(e) && existsSync(join(d, e, "site-packages"))) out.push(join(d, e, "site-packages"));
    }
  }
  // lib and Lib are one folder on case-insensitive file systems: dedupe by inode.
  const seen = new Set();
  return out.map((p) => { try { return realpathSync(p); } catch { return p; } }).filter((p) => {
    let key = p;
    try { const st = statSync(p); key = `${st.dev}:${st.ino}`; } catch { /* keep path */ }
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** The project's virtualenv: --venv, else .venv or venv beside the project. */
export function findVenv(root, explicit) {
  if (explicit) {
    const p = resolve(root, explicit);
    if (!existsSync(p)) throw new Error(`--venv path not found: ${explicit}`);
    if (!sitePackagesDirs(p).length) throw new Error(`No site-packages under ${explicit}; pass the virtualenv folder (the one with pyvenv.cfg).`);
    return p;
  }
  for (const name of [".venv", "venv"]) {
    const p = join(root, name);
    if (existsSync(p) && sitePackagesDirs(p).length) return p;
  }
  return null;
}

/** Parse RFC 822-style METADATA / PKG-INFO headers (first block only). */
export function parseMetadata(text) {
  const head = String(text).replace(/\r\n/g, "\n").split("\n\n")[0];
  const out = {};
  for (const line of head.split("\n")) {
    const m = line.match(/^([\w-]+):\s?(.*)$/);
    if (m && !(m[1] in out)) out[m[1]] = m[2].trim();
  }
  return out;
}

/** Parse a RECORD file (CSV: path,hash,size). Paths may be quoted. */
export function parseRecord(text) {
  const out = [];
  for (const line of String(text).split(/\r?\n/)) {
    if (!line.trim()) continue;
    let path;
    let rest;
    if (line.startsWith('"')) {
      const end = line.indexOf('",', 1);
      path = line.slice(1, end === -1 ? undefined : end).replace(/""/g, '"');
      rest = end === -1 ? "" : line.slice(end + 2);
    } else {
      const i = line.lastIndexOf(",", line.lastIndexOf(",") - 1);
      path = line.slice(0, i);
      rest = line.slice(i + 1);
    }
    const [hash] = rest.split(",");
    out.push({ path, hash: hash || null });
  }
  return out;
}

/** Files of an installed distribution, as listed by its RECORD, read from disk. */
export class RecordSource {
  constructor(siteDir, entries, kind = "installed") {
    this.dir = siteDir;
    this.kind = kind;
    const root = resolve(siteDir);
    // Only files inside site-packages: console-script wrappers in bin/ are generated by pip.
    const ok = entries.filter((e) => e.path && !e.path.split(/[\\/]/).includes("..") && resolve(root, e.path).startsWith(root + sep));
    const all = [...new Set(ok.map((e) => e.path.replace(/\\/g, "/")))].sort();
    this.maxFiles = MAX_FILES;
    this.truncated = all.length > MAX_FILES;
    this._files = all.slice(0, MAX_FILES);
    this.recordHashes = new Map(ok.filter((e) => e.hash).map((e) => [e.path.replace(/\\/g, "/"), e.hash]));
  }

  files() { return this._files; }

  size(rel) {
    try { return lstatSync(join(this.dir, rel)).size; } catch { return 0; }
  }

  read(rel) {
    const p = join(this.dir, rel);
    if (lstatSync(p).isSymbolicLink()) throw new Error("symlink");
    return readRegular(p, null, MAX_UNPACKED_BYTES);
  }
}

/**
 * Installed distributions in one site-packages folder.
 * @returns {{ name, version, distInfo, source: RecordSource }[]} plus `unownedPth` on the array
 */
export function listInstalled(siteDir) {
  let entries;
  try { entries = readdirSync(siteDir).sort(); } catch { return Object.assign([], { unownedPth: [] }); }
  const out = [];
  const owned = new Set();
  for (const e of entries) {
    const isDist = e.endsWith(".dist-info");
    const isEgg = e.endsWith(".egg-info");
    if (!isDist && !isEgg) continue;
    const meta = join(siteDir, e, isDist ? "METADATA" : "PKG-INFO");
    let md;
    try { md = parseMetadata(readRegular(meta, "utf-8")); } catch { continue; }
    if (!md.Name) continue;
    let record = [];
    if (isDist) {
      try { record = parseRecord(readRegular(join(siteDir, e, "RECORD"), "utf-8")); } catch { /* no RECORD */ }
    } else {
      try {
        record = readRegular(join(siteDir, e, "installed-files.txt"), "utf-8").split(/\r?\n/).filter(Boolean)
          .map((p) => ({ path: relative(siteDir, resolve(siteDir, e, p)).split(sep).join("/"), hash: null }));
      } catch { /* no file list */ }
    }
    let guessTruncated = false;
    if (!record.length) {
      // No file list: fall back to the folder named after the distribution.
      const guess = md.Name.replace(/-/g, "_");
      if (existsSync(join(siteDir, guess))) {
        const dir = new DirSource(join(siteDir, guess));
        record = dir.files().map((f) => ({ path: `${guess}/${f}`, hash: null }));
        guessTruncated = dir.truncated;
      }
    }
    const src = new RecordSource(siteDir, record);
    if (guessTruncated) src.truncated = true;
    for (const f of src.files()) owned.add(f);
    out.push({ name: normalizeName(md.Name), displayName: md.Name, version: md.Version || null, distInfo: e, source: src });
  }
  const unownedPth = entries.filter((e) => e.endsWith(".pth") && !owned.has(e));
  return Object.assign(out, { unownedPth });
}

// ── Archives ──────────────────────────────────────────────────────────────

/** A wheel that could not be parsed unambiguously. Callers fail closed. */
export class ZipError extends Error {
  constructor(message) {
    super(message);
    this.name = "ZipError";
  }
}

/**
 * Minimal zip reader for wheels: central directory, stored and deflated
 * entries. Paths that climb out are dropped. Returns Map<path, Buffer>.
 *
 * Fails closed. The sizes in the central directory are the archive's own
 * claim, so each entry is checked against the bytes really there, and the
 * total is capped on what was actually inflated. A bad record, an entry that
 * does not fit the archive, a size that does not match its data, encryption,
 * ZIP64 or an unknown compression method throws ZipError rather than being
 * skipped: whatever comes after it would otherwise go unread.
 */
export function unzip(buf, { maxTotal = MAX_UNPACKED_BYTES, maxEntries = MAX_FILES } = {}) {
  const files = new Map();
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd === -1) throw new ZipError("not a zip file");
  const count = buf.readUInt16LE(eocd + 10);
  const cdSize = buf.readUInt32LE(eocd + 12);
  let off = buf.readUInt32LE(eocd + 16);
  if (count === 0xffff || cdSize === 0xffffffff || off === 0xffffffff) throw new ZipError("ZIP64 archives are not supported");
  if (buf.readUInt16LE(eocd + 4) !== 0 || buf.readUInt16LE(eocd + 8) !== count) throw new ZipError("multi-disk archive");
  if (count > maxEntries) throw new ZipError(`more than ${maxEntries} entries`);
  const cdEnd = off + cdSize;
  if (cdEnd > eocd) throw new ZipError("central directory outside the archive");
  let total = 0;
  for (let n = 0; n < count; n++) {
    if (off + 46 > cdEnd || buf.readUInt32LE(off) !== 0x02014b50) throw new ZipError(`bad central directory record ${n}`);
    const flags = buf.readUInt16LE(off + 8);
    const method = buf.readUInt16LE(off + 10);
    const csize = buf.readUInt32LE(off + 20);
    const usize = buf.readUInt32LE(off + 24);
    const nameLen = buf.readUInt16LE(off + 28);
    const extraLen = buf.readUInt16LE(off + 30);
    const commentLen = buf.readUInt16LE(off + 32);
    const local = buf.readUInt32LE(off + 42);
    if (off + 46 + nameLen + extraLen + commentLen > cdEnd) throw new ZipError(`central directory record ${n} overruns`);
    const name = buf.subarray(off + 46, off + 46 + nameLen).toString("utf-8");
    const label = JSON.stringify(name);
    off += 46 + nameLen + extraLen + commentLen;
    if (csize === 0xffffffff || usize === 0xffffffff || local === 0xffffffff) throw new ZipError("ZIP64 entries are not supported");
    if (flags & 1) throw new ZipError(`encrypted entry ${label}`);
    if (local + 30 > buf.length || buf.readUInt32LE(local) !== 0x04034b50) throw new ZipError(`bad local header for ${label}`);
    const start = local + 30 + buf.readUInt16LE(local + 26) + buf.readUInt16LE(local + 28);
    if (start + csize > buf.length) throw new ZipError(`entry ${label} runs past the end of the archive`);
    if (name.endsWith("/")) continue;
    const raw = buf.subarray(start, start + csize);
    let data;
    if (method === 0) data = Buffer.from(raw);
    else if (method === 8) {
      try {
        // Capped on what really comes out, not on the size the entry claims.
        data = inflateRawSync(raw, { maxOutputLength: Math.max(1, maxTotal - total) });
      } catch (e) {
        throw new ZipError(`entry ${label} could not be inflated within ${maxTotal} bytes (${e.code || e.message})`);
      }
    } else throw new ZipError(`unsupported compression method ${method} for ${label}`);
    if (data.length !== usize) throw new ZipError(`entry ${label} holds ${data.length} bytes, the archive says ${usize}`);
    total += data.length;
    if (total > maxTotal) throw new ZipError(`unpacked size over ${maxTotal} bytes`);
    const parts = name.split("/").filter(Boolean);
    if (parts.includes("..") || name.startsWith("/")) continue;
    files.set(parts.join("/"), data);
  }
  return files;
}

/**
 * Unpack a wheel (zip) or sdist (.tar.gz) into a MapSource. The bytes are an
 * artifact the caller chose to scan (matched by hash, or a local path), so one
 * that cannot be read safely is not "missing": it comes back as a source with
 * an anomaly and no files, and the scan fails closed.
 */
export function sourceFromArtifact(bytes, kind) {
  try {
    if (bytes.length >= 4 && bytes.readUInt32LE(0) === 0x04034b50) return new MapSource(unzip(bytes), kind);
    if (bytes[0] === 0x1f && bytes[1] === 0x8b) return new MapSource(untar(gunzipSync(bytes, { maxOutputLength: MAX_UNPACKED_BYTES })), kind);
  } catch (e) {
    return new MapSource(new Map(), kind, { anomaly: `archive could not be read safely (${e.message})` });
  }
  return new MapSource(new Map(), kind, { anomaly: "archive is neither a wheel nor a gzipped sdist" });
}

// ── pip's HTTP cache ──────────────────────────────────────────────────────

/** pip's cache folder: PIP_CACHE_DIR, else the platform default. */
export function pipCacheDir(env = process.env, platform = process.platform) {
  if (env.PIP_CACHE_DIR) return env.PIP_CACHE_DIR;
  if (platform === "darwin") return join(homedir(), "Library", "Caches", "pip");
  if (platform === "win32") return join(env.LOCALAPPDATA || join(homedir(), "AppData", "Local"), "pip", "Cache");
  return join(env.XDG_CACHE_HOME || join(homedir(), ".cache"), "pip");
}

/** uv's cache folder: UV_CACHE_DIR, else the platform default. */
export function uvCacheDir(env = process.env, platform = process.platform) {
  if (env.UV_CACHE_DIR) return env.UV_CACHE_DIR;
  if (platform === "win32") return join(env.LOCALAPPDATA || join(homedir(), "AppData", "Local"), "uv", "cache");
  return join(env.XDG_CACHE_HOME || join(homedir(), ".cache"), "uv");
}

const pipIndexes = new Map();

/** sha256 -> body path for every artifact in pip's http-v2 cache (built once per folder). */
function pipIndex(dir) {
  if (pipIndexes.has(dir)) return pipIndexes.get(dir);
  const idx = new Map();
  const walk = (d, depth) => {
    let entries;
    try { entries = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const p = join(d, e.name);
      if (e.isDirectory() && depth < 8) walk(p, depth + 1);
      else if (e.isFile() && e.name.endsWith(".body")) {
        try {
          if (statSync(p).size > MAX_ARCHIVE_BYTES) continue;
          const bytes = readFileSync(p);
          // Wheels (zip) and sdists (gzip) only; PEP 658 metadata files are text.
          if (!(bytes.readUInt32LE(0) === 0x04034b50 || (bytes[0] === 0x1f && bytes[1] === 0x8b))) continue;
          idx.set(createHash("sha256").update(bytes).digest("hex"), p);
        } catch { /* unreadable entry */ }
      }
    }
  };
  walk(join(dir, "http-v2"), 0);
  pipIndexes.set(dir, idx);
  return idx;
}

const sha256Of = (hashes) => hashes.filter((h) => h.startsWith("sha256:")).map((h) => h.slice(7));

/**
 * An artifact from pip's cache whose sha256 is one the lockfile lists.
 * Prefers a wheel (what pip installs) over an sdist.
 */
export function sourceFromPipCache(pkg, dir = pipCacheDir()) {
  const wanted = sha256Of(pkg.hashes || []);
  if (!wanted.length || !existsSync(join(dir, "http-v2"))) return null;
  const idx = pipIndex(dir);
  const hits = wanted.map((h) => idx.get(h)).filter(Boolean).map((p) => readFileSync(p));
  // Wheels ("PK") first.
  hits.sort((a, b) => (b[0] === 0x50) - (a[0] === 0x50));
  for (const bytes of hits) {
    // Re-verify: the cache may have changed since it was indexed.
    if (!wanted.includes(createHash("sha256").update(bytes).digest("hex"))) continue;
    // These are the bytes the lockfile pins. If they do not unpack cleanly the
    // source carries an anomaly, so the package cannot pass as merely uncached.
    return sourceFromArtifact(bytes, "pip-cache");
  }
  return null;
}

// ── uv's cache ────────────────────────────────────────────────────────────

/** Decode the first msgpack value of a buffer (enough for uv's archive pointers). */
export function msgpackFirst(buf) {
  let i = 0;
  const str = (n) => { const s = buf.subarray(i, i + n).toString("utf-8"); i += n; return s; };
  const bin = (n) => { const s = buf.subarray(i, i + n); i += n; return s; };
  const read = (depth = 0) => {
    if (depth > 16 || i >= buf.length) throw new Error("msgpack");
    const b = buf[i++];
    if (b <= 0x7f) return b;
    if (b >= 0xe0) return b - 256;
    if ((b & 0xe0) === 0xa0) return str(b & 0x1f);
    if ((b & 0xf0) === 0x90) return Array.from({ length: b & 0x0f }, () => read(depth + 1));
    if ((b & 0xf0) === 0x80) return Object.fromEntries(Array.from({ length: b & 0x0f }, () => [read(depth + 1), read(depth + 1)]));
    switch (b) {
      case 0xc0: return null;
      case 0xc2: return false;
      case 0xc3: return true;
      case 0xcc: return buf[i++];
      case 0xcd: i += 2; return buf.readUInt16BE(i - 2);
      case 0xce: i += 4; return buf.readUInt32BE(i - 4);
      case 0xd9: return str(buf[i++]);
      case 0xda: i += 2; return str(buf.readUInt16BE(i - 2));
      case 0xc4: return bin(buf[i++]);
      case 0xc5: i += 2; return bin(buf.readUInt16BE(i - 2));
      case 0xdc: { i += 2; const n = buf.readUInt16BE(i - 2); return Array.from({ length: n }, () => read(depth + 1)); }
      case 0xde: { i += 2; const n = buf.readUInt16BE(i - 2); return Object.fromEntries(Array.from({ length: n }, () => [read(depth + 1), read(depth + 1)])); }
      default: throw new Error("msgpack type");
    }
  };
  return read();
}

const hexDigests = (v, out = []) => {
  if (typeof v === "string") for (const m of v.matchAll(/[0-9a-f]{64}/g)) out.push(m[0]);
  else if (Buffer.isBuffer(v) && v.length === 32) out.push(v.toString("hex"));
  else if (Array.isArray(v)) v.forEach((x) => hexDigests(x, out));
  else if (v && typeof v === "object") Object.values(v).forEach((x) => hexDigests(x, out));
  return out;
};

/** True when every file of an unpacked wheel still matches its own RECORD. */
function recordIntact(dir) {
  let distInfo;
  try { distInfo = readdirSync(dir).find((e) => e.endsWith(".dist-info")); } catch { return false; }
  if (!distInfo) return false;
  let entries;
  try { entries = parseRecord(readFileSync(join(dir, distInfo, "RECORD"), "utf-8")); } catch { return false; }
  for (const e of entries) {
    if (!e.hash) continue;
    try {
      const [algo] = e.hash.split("=");
      if (recordHash(readFileSync(join(dir, e.path)), algo) !== e.hash) return false;
    } catch { return false; }
  }
  return entries.length > 0;
}

/**
 * An unpacked wheel from uv's cache for pkg (name, version, hashes, files[].url).
 */
export function sourceFromUvCache(pkg, dir = uvCacheDir()) {
  let wheelsRoots;
  try { wheelsRoots = readdirSync(dir).filter((e) => /^wheels-v\d+$/.test(e)).sort().reverse(); } catch { return null; }
  const wanted = sha256Of(pkg.hashes || []);
  const urls = (pkg.files || []).map((f) => f.url).filter((u) => u && /^https:\/\/files\.pythonhosted\.org\/packages\//.test(u));
  if (!wanted.length && !urls.length) return null;
  for (const w of wheelsRoots) {
    const pdir = join(dir, w, "pypi", pkg.name);
    let entries;
    try { entries = readdirSync(pdir); } catch { continue; }
    for (const e of entries.filter((x) => x.startsWith(`${pkg.version}-`) && x.endsWith(".http")).sort()) {
      let buf;
      try { buf = readFileSync(join(pdir, e)); } catch { continue; }
      let pointer;
      try { pointer = msgpackFirst(buf); } catch { continue; }
      if (!Array.isArray(pointer) || typeof pointer[0] !== "string") continue;
      const recorded = hexDigests(pointer[1]);
      const text = buf.toString("latin1");
      const byHash = recorded.some((h) => wanted.includes(h));
      const byUrl = !recorded.length && urls.some((u) => text.includes(u));
      if (!byHash && !byUrl) continue;
      const archive = join(dir, "archive-v0", pointer[0]);
      if (!/^[\w-]+$/.test(pointer[0]) || !existsSync(archive)) continue;
      if (!recordIntact(archive)) continue;
      const src = new DirSource(archive);
      src.kind = "uv-cache";
      return src;
    }
  }
  return null;
}

/** A local path dependency (uv/poetry path source, `-e ./pkg` in requirements). */
export function sourceFromLocalPath(p) {
  try {
    if (!statSync(p).isDirectory()) {
      // `-e /dev/zero` or a FIFO is refused, not read without end.
      return sourceFromArtifact(readRegular(p, null, MAX_ARCHIVE_BYTES), "local");
    }
  } catch { return null; }
  const src = new DirSource(p, { skip: LOCAL_SKIP });
  src.kind = "local";
  return src;
}
