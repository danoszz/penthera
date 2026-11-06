/**
 * Reading a file a scanned repo controls. A repo can name its package-lock.json
 * a link to /dev/zero, make penthera.lock a FIFO, or point `-r` at /dev/stdin:
 * a plain readFileSync then fills memory or waits forever. readRepoFile opens
 * without following a final link (O_NOFOLLOW) and without waiting for a writer
 * (O_NONBLOCK), reads only a regular file, and only up to a size cap.
 *
 * A refusal throws a RefusedFileError (code "EREFUSED"), whose message names
 * the path and the reason but never the content. A missing file throws the
 * usual ENOENT, so callers can tell "absent" from "refused": absent is
 * silent, refused must become a note or a finding.
 */
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync, realpathSync } from "node:fs";
import { relative, resolve, sep, isAbsolute } from "node:path";

/** Default cap: 16 MiB. A lockfile of a large monorepo stays well under it. */
export const DEFAULT_MAX_BYTES = 16 * 1024 * 1024;

export class RefusedFileError extends Error {
  constructor(path, reason) {
    super(`${path} was not read: ${reason}`);
    this.name = "RefusedFileError";
    this.code = "EREFUSED";
    this.path = path;
    this.reason = reason;
  }
}

/** True for an error readRepoFile threw because it refused the file. */
export const isRefused = (e) => e?.code === "EREFUSED";

function inside(root, p) {
  const rel = relative(root, p);
  return rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel));
}

/**
 * Read a regular file, never a link out of `root`, a device, a FIFO or a socket.
 *
 * @param {string} path
 * @param {object} [opts]
 * @param {number} [opts.maxBytes] - refuse a larger file (default 16 MiB)
 * @param {string} [opts.root] - the file must resolve inside this folder; a
 *   link is then followed only when its target is inside too. Without a root
 *   a link is refused.
 * @param {string|null} [opts.encoding] - "utf-8" (default), or null for a Buffer
 * @param {string} [opts.label] - how the path is named in a refusal (default: the path)
 * @param {boolean} [opts.followLinks] - follow a link anywhere (a home dotfile
 *   managed by a dotfiles repo); the target must still be a regular file under the cap
 * @param {number} [opts.head] - read only the first `head` bytes, whatever the file's size
 * @returns {string|Buffer}
 */
/** Open `path` under readRepoFile's rules (links, root, O_NOFOLLOW, O_NONBLOCK); returns the fd. */
function openChecked(path, { root = null, label = path, followLinks = false } = {}) {
  const st = lstatSync(path); // ENOENT and the like go to the caller as they are
  let target = path;
  if (followLinks) {
    if (st.isSymbolicLink()) {
      try { target = realpathSync(path); } catch { throw new RefusedFileError(label, "it is a broken link"); }
    }
  } else if (root) {
    const realRoot = (() => { try { return realpathSync(root); } catch { return resolve(root); } })();
    if (!inside(resolve(root), resolve(path))) throw new RefusedFileError(label, "it is outside the project folder");
    let real;
    try { real = realpathSync(path); } catch { throw new RefusedFileError(label, "it is a broken link"); }
    if (!inside(realRoot, real)) throw new RefusedFileError(label, "it resolves outside the project folder");
    if (st.isSymbolicLink()) target = real;
  } else if (st.isSymbolicLink()) {
    throw new RefusedFileError(label, "it is a symbolic link");
  }
  let fd;
  try {
    fd = openSync(target, constants.O_RDONLY | (constants.O_NONBLOCK || 0) | (constants.O_NOFOLLOW || 0));
  } catch (e) {
    if (e.code === "ELOOP" || e.code === "EMLINK") throw new RefusedFileError(label, "it is a symbolic link");
    throw e;
  }
  return fd;
}

export function readRepoFile(path, { maxBytes = DEFAULT_MAX_BYTES, root = null, encoding = "utf-8", label = path, followLinks = false, head = 0 } = {}) {
  const fd = openChecked(path, { root, label, followLinks });
  try {
    const fst = fstatSync(fd);
    if (!fst.isFile()) throw new RefusedFileError(label, "it is not a regular file (a device, FIFO or socket)");
    if (head > 0) {
      // Only the first `head` bytes (a magic-number sniff): no size cap applies.
      const buf = Buffer.alloc(Math.min(fst.size, head));
      let off = 0;
      for (let n; off < buf.length && (n = readSync(fd, buf, off, buf.length - off, off)) > 0;) off += n;
      return encoding ? buf.subarray(0, off).toString(encoding) : buf.subarray(0, off);
    }
    if (fst.size > maxBytes) throw new RefusedFileError(label, `it is ${fst.size} bytes, over the ${maxBytes}-byte limit`);
    // Read at most maxBytes + 1: a file that grows while we read is still capped.
    const buf = Buffer.alloc(Math.min(fst.size, maxBytes) + 1);
    let off = 0;
    for (let n; off < buf.length && (n = readSync(fd, buf, off, buf.length - off, off)) > 0;) off += n;
    if (off > maxBytes) throw new RefusedFileError(label, `it is over the ${maxBytes}-byte limit`);
    const out = buf.subarray(0, off);
    return encoding ? out.toString(encoding) : out;
  } finally {
    closeSync(fd);
  }
}
