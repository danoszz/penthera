/**
 * JSON as the tools that read it see it. npm, VS Code and most JSON readers skip a
 * leading byte-order mark, so a config written with one still runs. JSON.parse doesn't,
 * and a reader that used it saw a broken file and missed what was in it.
 */

/** The text without a leading byte-order mark. */
export const stripBom = (text) => (String(text).charCodeAt(0) === 0xfeff ? String(text).slice(1) : String(text));

/** JSON.parse, after a leading byte-order mark. */
export const parseJson = (text) => JSON.parse(stripBom(text));
