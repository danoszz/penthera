/**
 * The production wiring: the Redis store from env and the global fetch.
 * Built on the first request, so a missing env var answers a 500 with
 * "not_configured" instead of crashing the function at import.
 */
import { createApp } from "./app.mjs";
import { redisStore } from "./store.mjs";

let app = null;

function instance() {
  app ??= createApp({
    env: process.env,
    store: lazyStore(),
  });
  return app;
}

// The store is opened on first use, inside the route's error guard.
function lazyStore() {
  let store = null;
  const open = () => (store ??= redisStore({ url: process.env.KV_REST_API_URL, token: process.env.KV_REST_API_TOKEN }));
  return {
    get: (id) => open().get(id),
    put: (r) => open().put(r),
    delete: (id) => open().delete(id),
    ids: () => open().ids(),
    getLink: (id) => open().getLink(id),
    putLink: (l) => open().putLink(l),
    deleteLink: (id) => open().deleteLink(id),
    links: () => open().links(),
    countStats: (day, counts) => open().countStats(day, counts),
    stats: (day) => open().stats(day),
  };
}

/** A Vercel function for one route: `export default route("install")`. */
export function route(name) {
  return { fetch: (request) => instance()[name](request) };
}
