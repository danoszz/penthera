/**
 * Is an IP address public? For the live check's guard and the CLI's local test.
 * new URL() writes an embedded IPv4 in hex ([::ffff:7f00:1]), so IPv6 is read
 * as 8 numbers and any IPv4 inside is checked as IPv4. Only 2000::/3 is public.
 */
import { isIP } from "node:net";
import { cutAtFirst } from "../linear-text.js";

const V4_BLOCKED = [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16],
  ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24], ["192.168.0.0", 16],
  ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
];

const v4num = (ip) => ip.split(".").reduce((n, p) => n * 256 + Number(p), 0);
const v4of = (hi, lo) => [hi >> 8, hi & 255, lo >> 8, lo & 255].join(".");

function isPublicV4(ip) {
  const n = v4num(ip);
  return !V4_BLOCKED.some(([base, bits]) => Math.floor(n / 2 ** (32 - bits)) === Math.floor(v4num(base) / 2 ** (32 - bits)));
}

/** An IPv6 address as 8 groups, or null. */
export function ipv6Groups(text) {
  let a = cutAtFirst(String(text).toLowerCase().replace(/^\[|\]$/g, ""), "%\n");
  if (isIP(a) !== 6) return null;
  const dotted = /(?<![\d.])(\d+\.\d+\.\d+\.\d+)$/.exec(a);
  if (dotted) {
    const n = v4num(dotted[1]);
    a = `${a.slice(0, -dotted[1].length)}${(n >>> 16).toString(16)}:${(n & 0xffff).toString(16)}`;
  }
  const [head, tail] = a.includes("::") ? a.split("::") : [a, null];
  const left = head ? head.split(":") : [];
  const right = tail ? tail.split(":") : [];
  const groups = [...left, ...Array(8 - left.length - right.length).fill("0"), ...right].map((g) => parseInt(g, 16));
  return groups.length === 8 && groups.every((g) => g >= 0 && g <= 0xffff) ? groups : null;
}

/** The IPv4 addresses an IPv6 address carries, or null. */
function embeddedV4(g) {
  const zero = (from, to) => g.slice(from, to).every((x) => x === 0);
  if (zero(0, 5) && g[5] === 0xffff) return [v4of(g[6], g[7])]; // mapped
  if (zero(0, 4) && g[4] === 0xffff && g[5] === 0) return [v4of(g[6], g[7])]; // translated
  if (zero(0, 6)) return [v4of(g[6], g[7])]; // compatible
  if (g[0] === 0x64 && g[1] === 0xff9b && zero(2, 6)) return [v4of(g[6], g[7])]; // NAT64
  if (g[0] === 0x2002) return [v4of(g[1], g[2])]; // 6to4
  if (g[0] === 0x2001 && g[1] === 0) return [v4of(g[2], g[3]), v4of(g[6] ^ 0xffff, g[7] ^ 0xffff)]; // Teredo
  return null;
}

export function isPublicIp(ip) {
  const text = String(ip ?? "").replace(/^\[|\]$/g, "");
  if (isIP(text) === 4) return isPublicV4(text);
  const g = ipv6Groups(text);
  if (!g) return false;
  const v4 = embeddedV4(g);
  if (v4) return v4.every(isPublicV4);
  if (g[0] === 0x64 && g[1] === 0xff9b && g[2] === 1) return false; // local NAT64
  if (g[0] === 0x100 && g.slice(1, 4).every((x) => x === 0)) return false; // discard
  if ((g[0] & 0xe000) !== 0x2000) return false;
  if (g[0] === 0x2001 && g[1] === 0xdb8) return false; // docs
  return true;
}
