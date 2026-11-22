// The code corpus: one small vulnerable file per repo rule family, for the
// findings gate (scripts/ci/findings-gate.mjs). The gate scans every case with
// the base branch's scanner and with this branch's, and fails when a finding
// the base reported is gone or lower here.
//
// Each case also runs with every DECOY added: a harmless line whose name looks
// like a check. 14 of the 38 Vercel Security Review findings logged by
// 22 Nov 2026 were a real finding hidden by a look-alike (`getLoginUrl()`
// counted as a session check, `getSignature(req.headers)` as a signature
// check). A decoy must never silence a case.
//
// Each case is a minimal reproduction written here, not a copy of anyone's code.

const code = (name, path, text, extra = {}) => ({ name, files: { [path]: text, ...extra } });

export const CODE_CASES = [
  code("unsigned webhook, Next route", "app/api/webhook/route.ts",
    `export async function POST(req) {\n  const event = await req.json();\n  if (event.type === "invoice.paid") {\n    await db.user.update({ where: { id: event.userId }, data: { plan: "pro" } });\n  }\n  return new Response("ok");\n}\n`),
  code("unsigned webhook, Express route", "server/webhooks.js",
    `import express from "express";\nconst app = express();\napp.post("/api/webhook", express.json(), async (req, res) => {\n  const event = req.body;\n  if (event.type === "order.created") {\n    await supabase.from("orders").insert({ id: event.id });\n  }\n  res.sendStatus(200);\n});\n`),
  code("unsigned Stripe events", "app/api/stripe/route.ts",
    `import Stripe from "stripe";\nexport async function POST(req) {\n  const event = await req.json();\n  switch (event.type) {\n    case "checkout.session.completed":\n      await prisma.order.create({ data: { id: event.data.object.id } });\n  }\n  return Response.json({ received: true });\n}\n`),
  code("jwt.decode where verify belongs", "lib/auth.js",
    `import jwt from "jsonwebtoken";\nexport function currentUser(req) {\n  const token = req.headers.authorization.split(" ")[1];\n  const payload = jwt.decode(token);\n  return payload.sub;\n}\n`),
  code("secret compared with ===", "app/api/cron/route.ts",
    `export async function GET(req) {\n  const key = req.headers.get("x-api-key");\n  if (key === process.env.API_KEY) {\n    await db.job.create({ data: { at: Date.now() } });\n  }\n  return new Response("ok");\n}\n`),
  code("session cookie without Secure", "server/session.js",
    `import session from "express-session";\nimport express from "express";\nconst app = express();\napp.use(session({ secret: process.env.SESSION_SECRET, cookie: { secure: false, httpOnly: false } }));\n`),
  code("password encrypted, not hashed", "lib/users.js",
    `import crypto from "node:crypto";\nexport function storePassword(password) {\n  const cipher = crypto.createCipheriv("aes-256-cbc", KEY, IV);\n  const encryptedPassword = cipher.update(password, "utf8", "hex") + cipher.final("hex");\n  return db.user.update({ data: { password: encryptedPassword } });\n}\n`),
  code("token in a URL", "app/api/reset/route.ts",
    `export async function GET(req) {\n  const password = new URL(req.url).searchParams.get("password");\n  const token = req.query.token;\n  return login(token, password);\n}\n`),
  code("Server Action writes with no auth", "app/actions.ts",
    `"use server";\nexport async function deletePost(id) {\n  await prisma.post.delete({ where: { id } });\n}\n`),
  code("request input in a shell command", "server/convert.js",
    `const { exec } = require("child_process");\nconst express = require("express");\nconst app = express();\napp.get("/convert", (req, res) => {\n  exec("convert " + req.query.file + " out.png", () => res.send("ok"));\n});\n`),
  code("request input in eval", "server/calc.js",
    `const express = require("express");\nconst app = express();\napp.post("/calc", (req, res) => {\n  res.send(String(eval(req.body.expr)));\n});\n`),
  code("workflow runs a pull request title", ".github/workflows/triage.yml",
    `name: triage\non: pull_request_target\njobs:\n  greet:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "\${{ github.event.pull_request.title }}"\n`),
];

/** Harmless lines whose names look like a check. None of them checks anything. */
export const DECOYS = [
  ["a signature getter", `const sig = getSignature(req.headers);`],
  ["an action client factory", `const actionClient = createSafeActionClient();`],
  ["a login URL getter", `const loginUrl = getLoginUrl();`],
  ["a lookup by id", `const owner = await getUserById("42");`],
  ["a verification email", `await sendVerificationEmail("a@example.com");`],
  ["an email validator", `const emailOk = validateEmail("a@example.com");`],
  ["a schema validator", `const shape = validateSchema({ a: 1 });`],
  ["a header name constant", `const SIGNATURE_HEADER = "x-signature";`],
  ["a log line", `console.log("signature verification comes later");`],
  ["a comment", `// TODO: verifySignature(req) and requireAuth() before launch`],
  ["a parser named like HMAC", `const parts = parseHmacHeader("t=1,v1=abc");`],
  ["an unwrap helper", `const inner = unwrapResult({ ok: true });`],
];

/** `text` with `line` added as the first statement of its first function body, or null when there is none. */
export function withDecoy(text, line) {
  const m = /\{[ \t]*\n/.exec(text);
  if (!m) return null;
  const at = m.index + m[0].length;
  const indent = /^[ \t]*/.exec(text.slice(at))[0];
  return `${text.slice(0, at)}${indent}${line}\n${text.slice(at)}`;
}

/** Every code case, then every case with every decoy: [{ name, files }]. */
export function codeCases() {
  const out = [...CODE_CASES];
  for (const c of CODE_CASES) {
    const [path, text] = Object.entries(c.files)[0];
    if (!/\.[cm]?[jt]sx?$/.test(path)) continue;
    for (const [label, line] of DECOYS) {
      const decoyed = withDecoy(text, line);
      if (decoyed) out.push({ name: `${c.name} + ${label}`, files: { ...c.files, [path]: decoyed } });
    }
  }
  return out;
}
