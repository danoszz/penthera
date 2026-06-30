/**
 * Penthera mock API — intentional vulnerabilities for offline tests.
 *
 *   node tests/fixtures/mock-server.js
 *   MOCK_PORT=8765 node tests/fixtures/mock-server.js
 */
import http from "node:http";

const USERS = {
  1: { id: 1, email: "alice@lab.test", role: "user", secret: "alice-private-data" },
  2: { id: 2, email: "bob@lab.test", role: "user", secret: "bob-private-data" },
  999: { id: 999, email: "admin@lab.test", role: "admin", secret: "admin-settings-key" },
};

const OPENAPI = {
  openapi: "3.1.0",
  info: { title: "Penthera Mock API", version: "1.0.0" },
  paths: {
    "/api/health": { get: { summary: "Health" } },
    "/api/users/{user_id}": { get: { summary: "Get user by ID" } },
    "/api/login": { post: { summary: "Login" } },
    "/api/oauth/callback": { get: { summary: "OAuth callback" } },
  },
};

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
    Server: "penthera-mock/1.0",
  });
  res.end(payload);
}

function html(res, status, body) {
  res.writeHead(status, { "Content-Type": "text/html", Server: "penthera-mock/1.0" });
  res.end(body);
}

function handle(req, res) {
  const url = new URL(req.url, "http://127.0.0.1");
  const { pathname } = url;

  if (pathname === "/api/oauth/callback") {
    const redirect = url.searchParams.get("redirect_uri") || url.searchParams.get("redirect");
    if (redirect?.includes("evil-attacker.example")) {
      res.writeHead(302, { Location: redirect });
      res.end();
      return;
    }
    json(res, 400, { error: "missing code" });
    return;
  }

  if (pathname === "/api/health") {
    json(res, 200, { status: "ok" });
    return;
  }

  if (pathname === "/openapi.json") {
    json(res, 200, OPENAPI);
    return;
  }

  if (pathname === "/docs") {
    html(res, 200, "<html><body>swagger mock</body></html>");
    return;
  }

  const userMatch = pathname.match(/^\/api\/users\/(\d+)$/);
  if (req.method === "GET" && userMatch) {
    const user = USERS[userMatch[1]];
    if (user) {
      json(res, 200, user);
      return;
    }
    json(res, 404, { error: "not found" });
    return;
  }

  if (pathname === "/api/login" && req.method === "POST") {
    json(res, 401, { error: "invalid credentials" });
    return;
  }

  if (pathname === "/") {
    html(res, 200, "<html><body>Penthera Mock API</body></html>");
    return;
  }

  json(res, 404, { detail: "Not Found" });
}

export function startMockServer(port = 0) {
  return new Promise((resolve) => {
    const server = http.createServer(handle);
    server.listen(port, "127.0.0.1", () => {
      const addr = server.address();
      const resolvedPort = typeof addr === "object" ? addr.port : port;
      resolve({
        server,
        port: resolvedPort,
        url: `http://127.0.0.1:${resolvedPort}`,
        close: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}

const isMain = process.argv[1]?.includes("mock-server.js");
if (isMain) {
  const port = parseInt(process.env.MOCK_PORT || "8765", 10);
  startMockServer(port).then(({ url }) => {
    console.log(`Penthera mock server: ${url}`);
  });
}
