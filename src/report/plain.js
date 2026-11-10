/**
 * Why a finding matters, in words a person who is not in security follows,
 * and the first thing to do about it. Tuned for the stacks makers ship most:
 * Next.js, Supabase, Stripe and Vercel, plus the AI keys those apps hold.
 *
 * A fixed table, matched on the rule id, the finding's source and the
 * secret's name in its title. No model writes these lines, and none decides
 * anything: the bucket, severity and verdict come from the rules as before.
 * A finding the table does not know gets no line, and the brief keeps the
 * finding's own description.
 */

const SECRET = {
  why: "Anyone who can read this repo, or any copy of it, can use this key as you.",
  act: "Revoke the key where it was issued, then load it from an environment variable.",
};

// Secret names, as a secret finding's title holds them, most specific first.
const SECRETS = [
  [/\bStripe\b/i, {
    why: "Anyone with this key can charge cards, refund payments and read your customers' payment details in your Stripe account.",
    act: "Roll the key in the Stripe Dashboard (Developers, API keys), then read it from a server-only environment variable.",
  }],
  [/\bClerk\b/i, {
    why: "Anyone with this key can read, change or delete your users' accounts in Clerk.",
    act: "Rotate the key in the Clerk Dashboard, then read it from a server-only environment variable.",
  }],
  [/\b(?:OpenAI|Anthropic|OpenRouter|Google API key|Groq|Hugging Face|Replicate|xAI|Perplexity|LangSmith|Pinecone)\b/i, {
    why: "Anyone with this key can send requests on your account, and you pay the bill.",
    act: "Revoke the key in the provider's dashboard, then read it from a server-only environment variable.",
  }],
  [/\bAWS\b/i, {
    why: "Anyone with this key can use your AWS account as you, and you pay for what they run.",
    act: "Deactivate the key in AWS IAM, then use a role or an environment variable on the server.",
  }],
  [/\bGitHub token\b/i, {
    why: "Anyone with this token can read your repositories, and with write access push code to them.",
    act: "Revoke the token in GitHub (Settings, Developer settings), then use a secret in your CI instead.",
  }],
  [/private key|service account/i, {
    why: "Whoever holds a private key can sign in or sign requests as you or your server.",
    act: "Replace the key pair, remove the old public key wherever it is trusted, and keep the new private key out of the repo.",
  }],
  [/password/i, {
    why: "Anyone who can read this repo can sign in with this password.",
    act: "Change the password, then read it from an environment variable.",
  }],
];

// By rule id (rule, templateId or category).
const RULES = {
  "supabase-service-role-exposed": {
    why: "This key skips row-level security: whoever has it can read, change or delete every row in your Supabase database, and it ships to every visitor.",
    act: "Rotate the service_role key in Supabase (Project Settings, API), use it only in server code, and give the browser the anon key.",
  },
  "supabase-service-role-committed": {
    why: "This key skips row-level security: whoever can read the repo can read, change or delete every row in your Supabase database.",
    act: "Rotate the service_role key in Supabase (Project Settings, API), then read it from a server-only environment variable.",
  },
  "supabase-rls-disabled": {
    why: "With row-level security off, anyone with your public anon key can read and change this table straight from their browser.",
    act: "Turn on row-level security for the table and add a policy that says who may read and write each row.",
  },
  "supabase-policy-open": {
    why: "This policy lets every visitor through, so row-level security protects nothing on this table.",
    act: "Limit the policy to the rows a user owns, for example `auth.uid() = user_id`.",
  },
  "public-env-secret": {
    why: "Next.js and Vite copy every NEXT_PUBLIC_ or VITE_ variable into the JavaScript each visitor downloads, so this value is public.",
    act: "Rotate the value, drop the public prefix, and read it only in server code (a Route Handler or a Server Action).",
  },
  "server-action-no-auth": {
    why: "A Server Action is a public endpoint: anyone can call it directly, signed in or not, unless the action checks.",
    act: "Check the session at the top of the action, before it reads or changes any data.",
  },
  "nextjs-sourcemap-exposure": {
    why: "Public source maps hand anyone your original source code, comments and internal paths included.",
    act: "Turn off productionBrowserSourceMaps in next.config, or upload source maps to your error tracker without serving them.",
  },
  "nextjs-debug-endpoint": {
    why: "A debug route on a live app can show anyone your config, environment or data.",
    act: "Remove the route, or return 404 from it outside development.",
  },
  "framework-advisory": {
    why: "This version of your framework has a published security bug, and the write-up shows attackers how to use it.",
    act: "Update the framework to the fixed version the finding names, then deploy again.",
  },
  "openapi-exposed": {
    why: "Your API description is public, so anyone gets a map of every route to try.",
    act: "Serve the API docs only behind a login, or only in development.",
  },
  "gha-pwn-request": {
    why: "A pull request from a stranger can run code in your CI with your repository's secrets.",
    act: "Do not check out the pull request's code in a pull_request_target workflow, or move the job to pull_request.",
  },
  "gha-script-injection": {
    why: "Text anyone can write (an issue title, a branch name) runs as a shell command in your CI.",
    act: "Pass the value through an env variable and quote it, instead of writing ${{ }} into the script.",
  },
  "gha-unpinned-action": {
    why: "If this action's owner or account is taken over, the next run of your CI runs their code.",
    act: "Pin the action to a full commit SHA.",
  },
  "webhook-signature-missing": {
    why: "Anyone who finds this webhook URL can post a fake event, like a paid checkout, and your app treats it as real.",
    act: "Verify the provider's signature on the raw body first (for Stripe, stripe.webhooks.constructEvent) and reject the request when it fails.",
  },
  "jwt-decode-unverified": {
    why: "Decoding a token doesn't check who signed it, so anyone can write one that says they're any user or an admin.",
    act: "Use jwt.verify or jose's jwtVerify and read the claims from its result.",
  },
  "secret-compare-not-constant-time": {
    why: "Comparing a secret with === takes a little longer the more of it is right, so it can be guessed one character at a time.",
    act: "Compare with crypto.timingSafeEqual on two buffers of the same length.",
  },
  "reset-token-no-expiry": {
    why: "A reset link that never expires works for whoever finds the old email, years later.",
    act: "Store an expiry next to the token, check it in the lookup, and delete the token once it's used.",
  },
  "client-trusted-value": {
    why: "The browser decides what's in the request, so a visitor can set their own price, role or plan.",
    act: "Look prices and roles up on the server, and write only the fields you pick from the request.",
  },
  "next-middleware-no-auth": {
    why: "This middleware runs on pages like /admin or /dashboard but checks no session, so it keeps nobody out.",
    act: "Check the session in the middleware and redirect to login, and check it again in each page and route.",
  },
  "credential-in-url": {
    why: "A password or key in the URL ends up in browser history, server logs and the Referer header sent to other sites.",
    act: "Send passwords in a POST body and keys in a header, then rotate any key that was ever in a URL.",
  },
  "password-encrypted-not-hashed": {
    why: "An encrypted password turns back into the password with a key that lives next to it, so one leak exposes every user.",
    act: "Store a slow hash (argon2id, scrypt or bcrypt) and rehash each password at the user's next login.",
  },
  "session-cookie-insecure": {
    why: "Without Secure or HttpOnly the session cookie can be read on open Wi-Fi or by any script on the page, which hands over the login.",
    act: "Set secure: true and httpOnly: true in the session library's cookie options.",
  },
  "oauth-callback-no-state": {
    why: "Without a state check, someone can send a link that logs a visitor into the attacker's account.",
    act: "Store a random state in a cookie before the redirect and compare it in the callback, or let your auth library run the flow.",
  },
};

// By category, when the rule id says nothing more.
const CATEGORIES = {
  "command-injection": {
    why: "If a visitor's input reaches this call, they can make your server run their own commands.",
    act: "Pass arguments as a list (execFile, spawn without a shell) and never build a command from request data.",
  },
  // eval, Function, vm (a code-pattern finding's `pattern`, else its category).
  "code-pattern": {
    why: "If a visitor's input reaches this call, they can make your server run their own code.",
    act: "Do not pass request data to eval, Function, vm or exec; parse it instead.",
  },
  cors: {
    why: "Other websites could call your API with your signed-in users' cookies and read the answers.",
    act: "Allow only your own origins, and never reflect the Origin header together with credentials.",
  },
  headers: {
    why: "Without these headers, the browser has fewer guards against injected scripts and against your pages being framed by another site.",
    act: "Set the headers in next.config (headers()) or vercel.json, then check them on the live site.",
  },
  cookie: {
    why: "A session cookie without these flags can be read by an injected script or sent over plain HTTP, and then someone can take over the session.",
    act: "Set Secure, HttpOnly and SameSite on the session cookie.",
  },
  cve: {
    why: "This package version has a published security bug, and the write-up shows attackers how to use it.",
    act: "Update the package to the fixed version the finding names.",
  },
  "js-vulnerability": {
    why: "This script version has a published security bug that runs in your visitors' browsers.",
    act: "Update the script to the fixed version the finding names.",
  },
};

const ruleId = (f) => String(f.rule || f.templateId || "");

/** Every line in the table, for the voice checks in tests/brief-plain.test.js. */
export const PLAIN_LINES = [SECRET, ...SECRETS.map(([, v]) => v), ...Object.values(RULES), ...Object.values(CATEGORIES)];

/**
 * { why, act } for a finding, or null when the table does not know it.
 * `why` says what could happen; `act` is the first step to take.
 */
export function plainWords(f) {
  if (!f) return null;
  const byRule = RULES[ruleId(f)] || RULES[f.category];
  if (byRule) return byRule;
  if (f.source === "secret-scan" || f.category === "secrets") {
    const title = String(f.title || "");
    return SECRETS.find(([re]) => re.test(title))?.[1] || SECRET;
  }
  return CATEGORIES[f.pattern] || CATEGORIES[f.category] || null;
}
