# Risk Tier Policy Gate

**WARNING: This is a PUBLIC repository. Never commit internal repo names, secrets, internal URLs, or any confidential org information.**

Central policy repo that auto-classifies PRs as `risktier:high` or `risktier:low` across the phishfort org.

## Architecture

```
risk-tier-required.yml  ← org-level required workflow (the main entrypoint)
config/risk-rules.json  ← deterministic pattern rules (high-risk file globs)
scripts/risk-rules.mjs  ← evaluates changed files against risk-rules.json
risk-tier-conditions.md ← policy doc Claude reads for non-deterministic classification

endpoint-auth-required.yml ← separate endpoint auth check (see "Endpoint Auth Check" below)
security/endpoint-auth/    ← its rules, fixtures, AI review guide, e2e test
```

**Flow:** deterministic rules run first → if forced_high, label immediately → otherwise Claude classifies → if no Claude token, fallback to high → finally, auto-approve low-risk PRs or dismiss bot approvals and request reviews from write-access collaborators for high-risk PRs.

**Incremental evaluation:** On `synchronize` (new push) events, the workflow evaluates the incremental diff (`before`→`sha`) for pattern/LLM classification, while the PR size check always uses the full PR diff. On `opened`/`reopened` events (or when no previous tier label exists), the full PR diff is evaluated for everything.

- **Pattern-based high → low follow-up (no downgrade):** If a PR was classified `risktier:high` due to file patterns and a follow-up push only touches low-risk files, the high label is maintained. The bot takes no approval action; existing human approval persists.
- **Low → high (escalation):** If a PR was `risktier:low` (bot auto-approved) and a follow-up push contains high-risk changes, the bot dismisses its own auto-approval, escalates to `risktier:high`, and requests human reviewers.
- **Size-based high is dynamic:** The PR size check (≥50 files or ≥1000 lines) always evaluates the full PR diff and can go in either direction. If a follow-up commit reduces the PR below the size threshold and there are no pattern-based high-risk files, the PR can downgrade to low.
- **Large PR + small follow-up:** If a large PR receives a small follow-up commit, the bot takes no action — existing human approval persists. If the follow-up itself exceeds size thresholds, the bot dismisses its own approval and requests reviewers.

**Approval management:** The org ruleset has "dismiss stale reviews on push" **disabled** — approvals persist across pushes by default. When new commits are high-risk, the workflow selectively dismisses approvals: for each existing approval, it diffs the reviewer's `commit_id` against the current HEAD and only dismisses if that diff contains high-risk file patterns. Approvals given after the high-risk changes (at the current HEAD) are preserved. When new commits are low-risk, all approvals are left untouched.

**Merge blocking:** The `org-level-risk-tier` ruleset requires 1 PR review. The workflow auto-approves `risktier:low` PRs via bot review. `risktier:high` PRs auto-request reviews from collaborators with write access and require human review.

**Review requests:** On high-risk PRs, the workflow calls `repos.listCollaborators` with `permission: push` to find eligible reviewers (excluding the PR author). Team-based review requests (`team_reviewers`) don't work because the `GITHUB_TOKEN` can't resolve org team slugs (403/422).

## Endpoint Auth Check (separate workflow)

`.github/workflows/endpoint-auth-required.yml` is a **second** org-injected required workflow, deliberately separate from the risk tier workflow so its failures are easy to spot. It never touches `risktier:*` labels or approvals.

**How it runs:**
- The job **always passes** (every step is `continue-on-error`), so it never blocks merges.
- Results go to a separate check run, `Endpoint auth findings`, created with `checks.create` against the PR head SHA:
  - ❌ failure: findings, a newly added `nosemgrep`, or the rules could not run
  - ⚪ neutral: the AI review failed
  - ✅ success: nothing to report
- The check run carries inline annotations. Findings also produce a PR comment (marker `<!-- endpoint-auth-gate -->`, which carries the previous AI findings in base64) and the label `security:unauth-endpoint`.

**Workspace layout:**
- The PR **head** is checked out at the workspace root.
- `rm -rf .endpoint-auth-gate` runs first, so a PR can't plant a same-named dir; then this repo is checked out into `.endpoint-auth-gate/`.
- All working files go in `.endpoint-auth-gate/run/`.
- The scan diffs **merge-base → working tree**, so line numbers match the PR head. That is required for annotations.

**AI step (`claude-code-action`):**
- Runs only when this push touches route or handler files.
- Tools are read-only (`Read,Glob,Grep`), with Bash/Write disallowed, so a prompt-injected PR can't alter the gate scripts in the workspace.
- It must return a JSON object in its final message; the report module parses it from `steps.ai.outputs.execution_file`.

**Other details:**
- Semgrep runs with `--disable-nosem`. Suppressions are tracked, never silent.
- Permissions: `checks: write`, `pull-requests: write`, `issues: write`, `id-token: write`.
- Enrolment: add this workflow as a required workflow in the org ruleset (same repo targets as risk tier).
- Tests: `semgrep --test security/endpoint-auth/rules` and `security/endpoint-auth/tests/e2e.sh`; CI is `endpoint-auth-tests.yml`.

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
- Changes take effect on next PR (workflow always pulls `@main`)
