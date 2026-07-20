# Risk Tier Policy Gate

**WARNING: This is a PUBLIC repository. Never commit internal repo names, secrets, internal URLs, or any confidential org information.**

Central policy repo that auto-classifies PRs as `risktier:high` or `risktier:low` across the phishfort org.

## Architecture

```
risk-tier-required.yml  ← org-level required workflow (the main entrypoint)
config/risk-rules.json  ← deterministic pattern rules (high-risk file globs)
scripts/risk-rules.mjs  ← evaluates changed files against risk-rules.json
scripts/risk-transition.mjs ← approval transition and stale-review policy
scripts/risk-glob.mjs   ← shared glob-to-regex implementation
scripts/nul-records.mjs ← shared byte-safe NUL record parsing
risk-tier-conditions.md ← policy doc Claude reads for non-deterministic classification
```

**Flow:** deterministic rules run first → if forced_high, label immediately → otherwise Claude classifies → if no Claude token, fallback to high → finally, auto-approve low-risk PRs or dismiss bot approvals and request reviews from write-access collaborators for high-risk PRs.

**Full-PR classification:** Every `opened`, `reopened`, and `synchronize` run resolves and classifies the complete live PR diff (`base.sha...head.sha`, using merge-base PR semantics). Changed filenames are transported NUL-delimited. A non-UTF-8 filename is classified high with an explanatory result rather than crashing the gate. The label is never derived from only the latest push. A previous `risktier:high` changes to `risktier:low` only when the complete current PR is reclassified as low, at which point the bot auto-approves it.

**Review-relative approval freshness:** Whenever the full PR is high, the workflow evaluates every active approval against current HEAD. Bot approval is always dismissed on high. Human approval at current HEAD is preserved. For older human approval, the workflow evaluates the complete net diff from that review's `commit_id` to HEAD, filtered to files still in the current PR. Approval persists only when every file is deterministically low-safe and the delta stays below size gates; unknown code, missing commits, or evaluation errors require fresh review.

- **High → high + low-risk follow-up:** The full PR remains `risktier:high`. Existing human approval persists only when all net changes since that approval are proven deterministically low-safe.
- **High → high + risky/unknown follow-up:** The full PR remains `risktier:high`; approvals at older commits are dismissed and fresh human review is requested.
- **High → low:** The complete current PR is now low-risk (for example, risky changes were removed or the PR shrank below the size threshold), so the bot applies `risktier:low` and auto-approves.
- **Low → high:** The complete current PR is now high-risk, so the bot dismisses its old auto-approval and requests human reviewers.
- **Size-based high is dynamic:** The PR size check (≥50 files or ≥1000 lines) evaluates the full PR diff and can move the aggregate tier in either direction.

**Approval management:** The org ruleset has "dismiss stale reviews on push" **disabled** — approvals persist across pushes by default. Per-PR workflow runs are serialized (`cancel-in-progress: false`), with newer pending events allowed to coalesce. Each run resolves the live PR revision and revalidates it before label and review mutations; stale queued runs exit without touching approvals. The workflow paginates all reviews, uses only each account's latest effective review, and reconciles approvals from their own reviewed commit. Approval-delta file and insertion counts are filtered to files still present in the current PR, so base-branch merge-in churn is excluded; binary low-safe assets count as zero text insertions. Required dismissal errors fail the workflow, and the workflow verifies no invalid approval remains before succeeding with a high tier. Reviewers are requested only when no valid human approval exists, and users already requested are not requested again. Review-request failures remain warnings because the review gate still blocks merging.

**Atomic policy checkout:** The central policy checkout is pinned to `github.workflow_sha`, the exact commit that defines the running required workflow. Scripts, deterministic rules, and the workflow therefore roll out as one revision; never change this back to an unpinned `main` checkout.

**Merge blocking:** The `org-level-risk-tier` ruleset requires 1 PR review. The workflow auto-approves `risktier:low` PRs via bot review. `risktier:high` PRs auto-request reviews from collaborators with write access and require human review.

**Review requests:** On high-risk PRs, the workflow calls `repos.listCollaborators` with `permission: push` to find eligible reviewers (excluding the PR author). Team-based review requests (`team_reviewers`) don't work because the `GITHUB_TOKEN` can't resolve org team slugs (403/422).

## Org Ruleset Setup

Configured at: `github.com/organizations/phishfort/settings/rules/13230835`

- Ruleset name: `org-level-risk-tier`
- Enforcement: active
- Targets: specific repos by ID, branch target set includes `Default`, `main`, and `master`
- Required workflow: `.github/workflows/risk-tier-required.yml` from this repo at `refs/heads/main`
- Required pull request reviews: 1 approval, dismiss stale reviews **disabled** (workflow manages bot approval explicitly)
- Bypass: org admins

To add a repo: edit the ruleset and add the repo to the target list.

Branch targeting is intentionally broad to avoid coverage gaps in mixed branch-strategy repos:
- `Default` catches each repo's current default branch
- `main` and `master` catch explicit release-target PRs (for example `develop -> main`)

**Consumer repos do NOT need any workflow file.** The org ruleset injects `risk-tier-required.yml` automatically on PRs.

## Key Decisions & Gotchas

- **Reusable workflows don't work cross-repo** for private caller repos (even calling public reusable workflows). All steps are inlined in `risk-tier-required.yml`.
- **This repo must stay public** — `actions/checkout` in the required workflow checks out this repo; private repos can't checkout other private repos without a PAT.
- **Fork repos** (like `partner-sharing-service`) can't use `secrets: inherit` with cross-repo reusable workflows. Use explicit secret passing if ever re-adding the reusable workflow.
- Secret name is `CLAUDE_CODE_OAUTH_TOKEN` (org-level secret, visibility: private repos).
- `claude-code-action@v1` requires `id-token: write` permission for OIDC exchange.
- `claude-code-action@v1` input is `claude_code_oauth_token` (not `claude_access_token`).
- `max-turns: 15` — 5 was insufficient for Claude to read files + classify + label + comment.

## Branding

All PR comments use the `🏰 **PhishFort Risk Tier Profiler**` prefix and include links to the policy conditions and rule definitions in this repo. The Claude prompt also instructs the LLM to use this format.

## Rolling Out to a New Repo

1. Get the repo ID: `gh api repos/phishfort/REPO_NAME --jq '.id'`
2. Edit the org ruleset (see Org Ruleset Setup above)
3. Add the repo ID to the target list
4. Enable Actions PR-approval on the repo (else auto-approve fails with 422):
   ```
   gh api -X PUT repos/phishfort/REPO_NAME/actions/permissions/workflow \
     -f default_workflow_permissions=write \
     -F can_approve_pull_request_reviews=true
   ```
   Or via UI: Settings → Actions → General → Workflow permissions → tick "Allow GitHub Actions to create and approve pull requests".
5. That's it — no workflow file needed in the target repo

## Testing

To test on a repo:
1. Add repo to the org ruleset (see above)
2. Open a PR on that repo
3. The `🏰 PhishFort Risk Tier Profiler (Required)` / `classify` check should appear automatically
4. Verify label (`risktier:high` or `risktier:low`) and PR comment with PhishFort branding

## Modifying Policy

- **Deterministic rules:** edit `config/risk-rules.json` — file globs that auto-force `risktier:high`
- **LLM classification policy:** edit `risk-tier-conditions.md` — Claude reads this to decide tier
- New runs use the required workflow revision selected by the org ruleset; each run pins all co-located policy files to that workflow's exact commit.
