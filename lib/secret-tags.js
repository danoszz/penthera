/**
 * Short, salted, one-way tags for secret values, so a baseline can tell a
 * swapped key from the same key without storing either (Vercel review, B03).
 *
 * A tag is the first 12 hex characters of sha256(salt, value). The salt is
 * random per report and written in it (`secretTagSalt`); a scan run with
 * --baseline reuses the baseline's salt, so the two reports' tags compare.
 * The salt keeps a tag from matching across reports or a precomputed table;
 * it does not make a short, guessable value safe to publish: a report that
 * holds such a value is a leak either way, and the masked form shows it too.
 */
import { createHash, randomBytes } from "node:crypto";

const SALT = /^[0-9a-f]{32}$/;
let salt = null;

/** This process's salt: the baseline's when useTagSalt() took one, else a random one. */
export function tagSalt() {
  return (salt ??= randomBytes(16).toString("hex"));
}

/** Use a baseline report's salt (ignored unless it is 32 hex characters). Returns true when taken. */
export function useTagSalt(s) {
  if (typeof s !== "string" || !SALT.test(s)) return false;
  salt = s;
  return true;
}

/** The tag of one secret value. */
export function secretTag(value, s = tagSalt()) {
  return createHash("sha256").update(s).update("\0").update(String(value)).digest("hex").slice(0, 12);
}
