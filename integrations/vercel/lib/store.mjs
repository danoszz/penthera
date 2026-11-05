/**
 * Where install records live, behind four methods:
 *
 *   get(configurationId) -> record | null
 *   put(record)          -> overwrites the record for record.configurationId
 *   delete(configurationId)
 *   ids()                -> every stored configurationId (for the sweep)
 *
 * A record is exactly { configurationId, ownerId, ciphertext, iv, tag,
 * keyVersion, createdAt, sessionNonce }. put() refuses anything else, so no other field can
 * reach the store by accident.
 *
 * Two implementations: memoryStore() for tests, and redisStore() for
 * production, which speaks the Upstash Redis REST protocol with plain fetch
 * (no SDK). The Upstash store from the Vercel Marketplace sets
 * KV_REST_API_URL and KV_REST_API_TOKEN on the project. README.md says why
 * this store was picked.
 */
const FIELDS = ["configurationId", "ownerId", "ciphertext", "iv", "tag", "keyVersion", "createdAt", "sessionNonce"];
const PREFIX = "pv:cfg:";

export function assertRecord(record) {
  const keys = Object.keys(record ?? {}).sort();
  if (keys.join() !== [...FIELDS].sort().join()) throw new Error("store: a record has exactly the documented fields");
  if (!/^icfg_[A-Za-z0-9]{1,64}$/.test(record.configurationId)) throw new Error("store: bad configurationId");
  // At least 128 random bits, base64url (lib/app.mjs makes 192).
  if (!/^[A-Za-z0-9_-]{22,128}$/.test(record.sessionNonce ?? "")) throw new Error("store: bad sessionNonce");
  return record;
}

export function memoryStore() {
  const map = new Map();
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
    /** Tests only: the raw contents. */
    dump: () => [...map.values()].map((v) => ({ ...v })),
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
      const out = [];
      let cursor = "0";
      do {
        const [next, keys] = await command("SCAN", cursor, "MATCH", `${PREFIX}*`, "COUNT", "200");
        cursor = String(next);
        out.push(...keys.map((k) => k.slice(PREFIX.length)));
      } while (cursor !== "0" && out.length < 100_000);
      return out;
    },
  };
}
