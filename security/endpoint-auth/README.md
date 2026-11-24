# Endpoint auth check

A separate org-wide required workflow, [`endpoint-auth-required.yml`](../../.github/workflows/endpoint-auth-required.yml), injected next to the Risk Tier Profiler. On every PR in an enrolled repo it flags code that may expose data or actions **without proper authentication**.

It is **non-blocking**:
- The workflow job always passes, so it never stops a merge.
- Findings show up as their own check run, **"Endpoint auth findings"**:
  - it goes red when there is something to look at,
  - it carries inline annotations on the changed lines in *Files changed*.
- A **🔐 PhishFort Endpoint Auth Check** PR comment explains the findings and how to fix them.
- The label `security:unauth-endpoint` stays on the PR while findings are unresolved.

It is independent of the Risk Tier Profiler: it doesn't change `risktier:*` labels or approvals.

## Two layers

| Layer | When | What |
|---|---|---|
| **Rules** (semgrep, [`rules/`](rules/)) | Every PR, on lines the PR adds or changes | Known anti-patterns:<br>- spoofable identity headers<br>- presence-only JWT checks<br>- auth that turns off when a secret is unset<br>- hardcoded fallback keys<br>- HTTP Cloud Functions with no credential check<br><br>Also informational notes: Worker reachable on `*.workers.dev`, public Cloud Run invoker. |
| **AI endpoint review** (Claude, read-only tools) | Only when the latest push touches route or handler code (including route-table entries), or shared auth code / permission tables (file names with auth, middleware, session, guard, permission, policy, rbac, acl), or deletes/changes a line that looks like an auth check (`app.use(requireUser)`, `if (!req.user) return 401`, `@UseGuards`, ...) | For each added or changed endpoint, judges which auth runs before data is touched, using [`review-guide.md`](review-guide.md). It catches what patterns can't, such as a new route with no auth check at all, or a tenant id taken from the request. Advisory. |

**How the diff is evaluated:**
- Rules always evaluate the **full PR diff**, measured from the merge-base to the PR head, so unresolved findings keep the check red on later pushes.
- Line numbers match the PR head, so annotations and links point at the right lines.
- The AI review re-runs only when a push touches route, handler or auth/permission files. Otherwise its previous findings are carried over from the comment.
- Every endpoint the AI assessed (including `ok` ones) and the files in scope are listed on the workflow run's **job summary** page, so a green result shows what it covered.

## Check-run states

| "Endpoint auth findings" | Meaning |
|---|---|
| ❌ failure | Unresolved findings, a **newly added** `nosemgrep` suppression (shown once for a reviewer to confirm), or the rules could not run (results incomplete). |
| ⚪ neutral | Rules ran clean, but the AI review didn't return a usable result. |
| ✅ success | Nothing to report. No comment is posted unless one already exists, in which case it is updated to "resolved". |

If the gate itself breaks (for example, the report step errors), the workflow logs an `::error` annotation. The job still passes, so merges are never blocked by tooling problems.

## Rules

| Rule | Catches |
|---|---|
| `access-jwt-presence-only` | `if (req.headers.get('cf-access-jwt-assertion')) return true`: the header exists, but its JWT is never verified. |
| `access-identity-header-trusted` (+ `py-…`) | Identity read from `Cf-Access-Authenticated-User-Email` / `X-Forwarded-User` / … in a file that never verifies a JWT. |
| `auth-fails-open-when-secret-unset` (+ `py-…`) | `if (!env.KEY) return true`, `if (KEY && provided !== KEY)`: a missing secret means no auth. |
| `hardcoded-secret-fallback` (+ `py-…`) | `process.env.API_KEY \|\| "literal"` / `os.getenv("API_KEY", "literal")`. |
| `bearer-compare-against-unset-secret` | `` auth === `Bearer ${env.TOKEN}` `` becomes `"Bearer undefined"` when the secret is unset. |
| `http-cloud-function-without-auth` | `https.onRequest` / `onRequest` handlers that never read a credential. |

## False positives

- **Rules:** fix the code, or add an inline suppression with a reason:
  ```ts
  const who = request.headers.get("Cf-Access-Authenticated-User-Email"); // nosemgrep: access-identity-header-trusted -- JWT verified in middleware.ts
  ```
  The suppression must name the rule (several: `nosemgrep: rule-a, rule-b`). A bare `nosemgrep`, or one naming a different rule, suppresses nothing.
  Suppressions are never silent. The push that adds one turns the check red once and shows the reason, so a reviewer can confirm it. After that it is listed under "Suppressed findings".
- **AI findings:** advisory. A reviewer checks them and merges.

## Changing the rules

1. Edit `rules/*.yml`.
2. Add `// ruleid: <id>` / `// ok: <id>` cases to the matching fixture (`rules/js-endpoint-auth.ts`, `rules/py-endpoint-auth.py`).
3. Run the tests locally:
   ```bash
   semgrep --metrics=off --test security/endpoint-auth/rules
   security/endpoint-auth/tests/e2e.sh
   ```
4. CI runs the same tests (`.github/workflows/endpoint-auth-tests.yml`).

**This repo is public:** keep rules and fixtures generic. Use no internal service names, URLs or real secrets.

## Known gaps

- Only PRs to enrolled repos are checked. Direct pushes, and deploys from a laptop (`wrangler deploy`, `gcloud … deploy`), bypass GitHub entirely.
- The rules cover JS/TS and Python. Other languages rely on the AI review.
- Whether a service is *actually* reachable (Access policies, IAM invokers) is deploy-time config the gate can't see. Reviewers should check.
- A fix made outside route and auth/permission files (for example in a shared helper) leaves the previous AI findings showing until the next route change. The reviewer can merge over them.
- Auth/permission files are recognised by file name only. Auth logic in a file named otherwise (for example `index.js`) relies on the rules, or on a route change in the same push.
