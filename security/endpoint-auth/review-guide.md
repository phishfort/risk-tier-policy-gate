# Endpoint auth review guide

Read by the AI endpoint reviewer in the endpoint auth gate. Humans can use it too. The goal is narrow: **can someone who is not supposed to call this endpoint read or change data through it?**

## What counts as an endpoint

Count anything reachable over the network that runs code on request:
- Worker `fetch` handlers and the routes they dispatch (`url.pathname === ...`)
- Hono, Express, itty and FastAPI/Flask routes
- Next.js `pages/api/*` and `app/**/route.ts` handlers, and server actions
- tRPC procedures
- HTTP Cloud Functions (`https.onRequest`, `onRequest`) and Cloud Run servers
- Pages Functions
- MCP tools and resources
- Webhook receivers

## Auth levels

| `auth` | Meaning |
|---|---|
| `ok` | A credential is checked in code before data is touched. Acceptable checks:<br>- a JWT or session whose **signature** is verified<br>- an HMAC signature (webhooks)<br>- an API key compared with a **configured** secret, failing closed when the secret is missing<br>- platform IAM (for example a Cloud Run invoker restricted to a service account)<br>- an endpoint that is public by design and harmless (health, static assets, public marketing forms with abuse protection) |
| `weak` | A check exists but it can be bypassed. See the list below. |
| `none` | No check at all before the handler reads or changes data. |
| `unclear` | Auth is enforced somewhere you can't see, such as an external proxy, and nothing in the repo shows it is enforced for every path to this code. |

**Weak patterns (treat as `weak`):**
- Identity is taken from a request header (`Cf-Access-Authenticated-User-Email`, `X-Forwarded-User`, `x-user-email`, ...) or from an *unverified* JWT payload (base64-decoded, `jwt.decode` without verify).
- The check only tests that a token or header is **present** (`if (req.headers.get('cf-access-jwt-assertion')) return true`).
- Auth is skipped when a secret is unset (`if (!env.KEY) return true`, `if (KEY && provided !== KEY)`), or a hardcoded fallback/default key is used.
- A hardcoded shared secret is in the source, or a key arrives in the URL query string where it gets logged.
- The caller's identity is checked, but the **tenant/resource is taken from the request** (`clientId`, `orgId`, `userId`, document id) without checking it belongs to the caller (IDOR / cross-tenant access).
- A role, permission or "checked at" timestamp is accepted from the client (session update payload, request body).
- Auth runs on some methods or routes of a handler but not others, or a failed auth branch doesn't `return`.

## Platform facts to keep in mind

- **Cloudflare Workers:**
  - Unless `workers_dev = false`, the Worker is also served at `<name>.<subdomain>.workers.dev`.
  - Preview URLs and `*.pages.dev` branch previews are also reachable.
  - Cloudflare Access on a custom domain does **not** protect those URLs.
  - So identity headers are spoofable unless the Access JWT (`Cf-Access-Jwt-Assertion`) is verified in code against the team certs and `aud`.
- **Cloud Run / Cloud Functions:**
  - With `allUsers` / `--allow-unauthenticated` (the Firebase CLI default for HTTP functions), the app must enforce auth itself.
  - Fetching caller-supplied URLs from these services can reach the metadata server.
- **Firebase Auth:**
  - If self sign-up is enabled, *any* person can obtain a valid ID token.
  - A valid token proves who someone is, not that they may access this data. Look for an allowlist, role or tenant check.
- **Service-to-service:** internal headers (like an actor email forwarded by a trusted backend) are fine only if the request is itself authenticated as coming from that backend.

## Sensitive

Set `sensitive: true` when the endpoint:
- returns or changes non-public data: client/customer data, incidents, users, files and documents, messages, credentials, internal configuration
- performs privileged or admin actions
- triggers paid resources (LLM calls, scraping, bulk jobs)

## Confidence

| Level | When to use it |
|---|---|
| `high` | You read the handler and its auth path end to end. |
| `medium` | Auth lives in code you could partly follow. |
| `low` | It depends on deployment config you cannot see. |

## Output discipline

- One entry per endpoint that was added or changed. Use the handler's `file:line`.
- `issue` and `fix` are one sentence each. Never include secret values.
- Do not report style, performance or non-auth bugs.
