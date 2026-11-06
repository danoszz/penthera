/**
 * Where install records live, behind four methods:
 *
 *   get(configurationId) -> record | null
 *   put(record)          -> overwrites the record for record.configurationId
 *   delete(configurationId)
 *   ids()                -> every stored configurationId (for the sweep)
 *
 * and four for project links, which tell POST /report which installation turned the check on:
 *
 *   getLink(projectId) -> link | null
 *   putLink(link)      -> overwrites the link for link.projectId
 *   deleteLink(projectId)
 *   links()            -> [{ key, link }] for every stored link, key being the projectId it is
 *                         stored under and link the parsed value or null (uninstall, sweep)
 *
 * and one anonymous counter set per UTC day, for upkeep (README, "What it keeps"):
 *
 *   countStats(day, counts) -> adds { field: n } to that day's counters; the day's key is given a
 *                              90-day expiry once per store instance (not on every write)
 *   stats(day)              -> { field: count } for that day
 *
 * A counter has no id of any kind: the key is the date, the field one of STAT_FIELDS.
 *
 * A record is exactly { configurationId, ownerId, ciphertext, iv, tag,
 * keyVersion, createdAt, sessionNonce }, and a link exactly { projectId, configurationId }.
 * put() and putLink() refuse anything else, so no other field can reach the store by accident.
 *
 * Two implementations: memoryStore() for tests, and redisStore() for
 * production, which speaks the Upstash Redis REST protocol with plain fetch
 * (no SDK). The Upstash store from the Vercel Marketplace sets
 * KV_REST_API_URL and KV_REST_API_TOKEN on the project. README.md says why
 * this store was picked.
 */
const FIELDS = ["configurationId", "ownerId", "ciphertext", "iv", "tag", "keyVersion", "createdAt", "sessionNonce"];
const PREFIX = "pv:cfg:";
const LINK_FIELDS = ["configurationId", "projectId"];
const LINK_PREFIX = "pv:prj:";
const STAT_PREFIX = "pv:stats:";
export const STAT_TTL_SECONDS = 90 * 86_400;
/** Why POST /report refused a relay: its error codes, and nothing else. */
export const REJECT_REASONS = [
  "unauthorized", "too_large", "bad_json", "bad_body", "bad_deployment", "bad_project", "bad_conclusion",
  "bad_token", "workflow_not_allowed", "try_again", "not_enabled", "repository_mismatch", "deployment_mismatch",
  "already_completed", "vercel_unavailable",
];
/** The only counter names: relays received, relayed as succeeded or failed, and rejected by reason. */
export const STAT_FIELDS = new Set(["received", "succeeded", "failed", ...REJECT_REASONS.map((r) => `rejected_${r}`)]);

export function assertStats(day, counts) {
  if (typeof day !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(day)) throw new Error("store: bad stats day");
  const entries = Object.entries(counts ?? {});
  if (!entries.length) throw new Error("store: no counts");
  for (const [field, n] of entries) {
    if (!STAT_FIELDS.has(field)) throw new Error("store: a counter has one of the documented names");
    if (!Number.isSafeInteger(n) || n < 1 || n > 1_000_000) throw new Error("store: bad count");
  }
  return entries;
}

export function assertRecord(record) {
  const keys = Object.keys(record ?? {}).sort();
  if (keys.join() !== [...FIELDS].sort().join()) throw new Error("store: a record has exactly the documented fields");
  if (!/^icfg_[A-Za-z0-9]{1,64}$/.test(record.configurationId)) throw new Error("store: bad configurationId");
  // At least 128 random bits, base64url (lib/app.mjs makes 192).
  if (!/^[A-Za-z0-9_-]{22,128}$/.test(record.sessionNonce ?? "")) throw new Error("store: bad sessionNonce");
  return record;
}

export function assertLink(link) {
  const keys = Object.keys(link ?? {}).sort();
  if (keys.join() !== LINK_FIELDS.join()) throw new Error("store: a link has exactly the documented fields");
  if (!/^prj_[A-Za-z0-9]{1,64}$/.test(link.projectId)) throw new Error("store: bad projectId");
  if (!/^icfg_[A-Za-z0-9]{1,64}$/.test(link.configurationId)) throw new Error("store: bad configurationId");
  return link;
}

export function memoryStore() {
  const map = new Map();
  const linkMap = new Map();
  const statMap = new Map();
  return {
    async get(id) {
      const v = map.get(id);
      return v ? { ...v } : null;
    },
    async put(record) {
      assertRecord(record);
      map.set(record.configurationId, { ...record });
    },
    async delete(id) {
      map.delete(id);
    },
    async ids() {
      return [...map.keys()];
    },
    async getLink(projectId) {
      const v = linkMap.get(projectId);
      return v ? { ...v } : null;
    },
    async putLink(link) {
      assertLink(link);
      linkMap.set(link.projectId, { ...link });
    },
    async deleteLink(projectId) {
      linkMap.delete(projectId);
    },
    async links() {
      return [...linkMap.entries()].map(([key, v]) => ({ key, link: v && typeof v === "object" ? { ...v } : null }));
    },
    async countStats(day, add) {
      const entries = assertStats(day, add);
      const counts = statMap.get(day) ?? {};
      for (const [field, n] of entries) counts[field] = (counts[field] ?? 0) + n;
      statMap.set(day, counts);
    },
    async stats(day) {
      return { ...(statMap.get(day) ?? {}) };
    },
    /** Tests only: every stats key. */
    statDays: () => [...statMap.keys()],
    /** Tests only: the raw contents. */
    dump: () => [...map.values()].map((v) => ({ ...v })),
    dumpLinks: () => [...linkMap.values()].map((v) => ({ ...v })),
    /** Tests only: write a link without the field check, as someone with store access could. */
    rawLink: (projectId, value) => linkMap.set(projectId, value),
  };
}

export function redisStore({ url, token, fetch: fetchImpl = globalThis.fetch }) {
  if (!url || !token) throw new Error("store: KV_REST_API_URL and KV_REST_API_TOKEN are not set");
  const base = new URL(url);
  if (base.protocol !== "https:") throw new Error("store: KV_REST_API_URL must be https");
  async function command(...args) {
    const res = await fetchImpl(base, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(args),
      signal: AbortSignal.timeout(5_000),
    });
    if (!res.ok) throw Object.assign(new Error("store_request_failed"), { status: res.status });
    const json = await res.json();
    if (json.error) throw new Error("store_command_failed");
    return json.result;
  }
  const expiring = new Set();
  async function scan(prefix) {
    const out = [];
    let cursor = "0";
    do {
      const [next, keys] = await command("SCAN", cursor, "MATCH", `${prefix}*`, "COUNT", "200");
      cursor = String(next);
      out.push(...keys);
    } while (cursor !== "0" && out.length < 100_000);
    return out;
  }
  return {
    async get(id) {
      const raw = await command("GET", PREFIX + id);
      return raw ? JSON.parse(raw) : null;
    },
    async put(record) {
      assertRecord(record);
      await command("SET", PREFIX + record.configurationId, JSON.stringify(record));
    },
    async delete(id) {
      await command("DEL", PREFIX + id);
    },
    async ids() {
      return (await scan(PREFIX)).map((k) => k.slice(PREFIX.length));
    },
    async countStats(day, add) {
      const entries = assertStats(day, add);
      for (const [field, n] of entries) await command("HINCRBY", STAT_PREFIX + day, field, String(n));
      // One EXPIRE per day key per instance, not one per write. The key stops being written after
      // its day, so it is gone at most 90 days after the day's first write in each instance.
      if (!expiring.has(day)) {
        await command("EXPIRE", STAT_PREFIX + day, String(STAT_TTL_SECONDS));
        if (expiring.size > 400) expiring.clear();
        expiring.add(day);
      }
    },
    async stats(day) {
      const flat = (await command("HGETALL", STAT_PREFIX + day)) ?? [];
      const out = {};
      for (let i = 0; i + 1 < flat.length; i += 2) out[flat[i]] = Number(flat[i + 1]);
      return out;
    },
    async getLink(projectId) {
      const raw = await command("GET", LINK_PREFIX + projectId);
      return raw ? JSON.parse(raw) : null;
    },
    async putLink(link) {
      assertLink(link);
      await command("SET", LINK_PREFIX + link.projectId, JSON.stringify(link));
    },
    async deleteLink(projectId) {
      await command("DEL", LINK_PREFIX + projectId);
    },
    async links() {
      // One MGET per 100 keys, so an uninstall stays inside the webhook's time.
      const out = [];
      const keys = await scan(LINK_PREFIX);
      for (let i = 0; i < keys.length; i += 100) {
        const batch = keys.slice(i, i + 100);
        const values = await command("MGET", ...batch);
        batch.forEach((key, j) => {
          const raw = Array.isArray(values) ? values[j] : null;
          if (!raw) return;
          let link = null;
          try {
            link = JSON.parse(raw);
          } catch {}
          out.push({ key: key.slice(LINK_PREFIX.length), link: link && typeof link === "object" ? link : null });
        });
      }
      return out;
    },
  };
}
