# Risk Tier Policy Gate

**WARNING: This is a PUBLIC repository. Never commit internal repo names, secrets, internal URLs, or any confidential org information.**

Central policy repo that auto-classifies PRs as `risktier:high` or `risktier:low` across the phishfort org.

## Architecture

```
risk-tier-required.yml  ← org-level required workflow (the main entrypoint)
config/risk-rules.json  ← deterministic pattern rules (high-risk file globs)
scripts/risk-rules.mjs  ← evaluates changed files against risk-rules.json
risk-tier-conditions.md ← policy doc Claude reads for non-deterministic classification
```

**Flow:** deterministic rules run first → if forced_high, label immediately → otherwise Claude classifies → if no Claude token, fallback to high → finally, auto-approve low-risk PRs or dismiss bot approvals and request reviews from write-access collaborators for high-risk PRs.

**Merge blocking:** The `org-level-risk-tier` ruleset also requires 1 PR review (dismiss stale reviews on push). The workflow auto-approves `risktier:low` PRs via bot review. `risktier:high` PRs auto-request reviews from collaborators with write access and require human review. New pushes dismiss stale reviews, triggering re-classification.

**Review requests:** On high-risk PRs, the workflow calls `repos.listCollaborators` with `permission: push` to find eligible reviewers (excluding the PR author). Team-based review requests (`team_reviewers`) don't work because the `GITHUB_TOKEN` can't resolve org team slugs (403/422).

## Org Ruleset Setup

Configured at: `github.com/organizations/phishfort/settings/rules/13230835`

- Ruleset name: `org-level-risk-tier`
- Enforcement: active
- Targets: specific repos by ID, branch target set includes `Default`, `main`, and `master`
- Required workflow: `.github/workflows/risk-tier-required.yml` from this repo at `refs/heads/main`
- Required pull request reviews: 1 approval, dismiss stale reviews on new commits
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
4. That's it — no workflow file needed in the target repo

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
