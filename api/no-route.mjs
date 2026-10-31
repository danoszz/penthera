/**
 * The 404 for API clients. vercel.json rewrites /api and any path under it
 * that matched no function to here, so an agent gets the same error shape as
 * POST /api/check instead of Vercel's text page.
 */
const ORIGIN = "https://penthera.org";

export const NO_ROUTE = {
  error: {
    code: "unknown_endpoint",
    message: "There is no API route at this address.",
    hint: `The public API is POST ${ORIGIN}/api/check. See ${ORIGIN}/openapi.json.`,
  },
};

export default function handler(req, res) {
  res.writeHead(404, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
  res.end(req.method === "HEAD" ? undefined : JSON.stringify(NO_ROUTE));
}
