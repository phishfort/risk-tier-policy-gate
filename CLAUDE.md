# Risk Tier Policy Gate

Central policy repo that auto-classifies PRs as `risktier:high` or `risktier:low` across the phishfort org.

## Architecture

```
risk-tier-required.yml  ← org-level required workflow (the main entrypoint)
config/risk-rules.json  ← deterministic pattern rules (high-risk file globs)
scripts/risk-rules.mjs  ← evaluates changed files against risk-rules.json
risk-tier-conditions.md ← policy doc Claude reads for non-deterministic classification
```

**Flow:** deterministic rules run first → if forced_high, label immediately → otherwise Claude classifies → if no Claude token, fallback to high.

## Org Ruleset Setup

Configured at: `github.com/organizations/phishfort/settings/rules/13230835`

- Ruleset name: `org-level-risk-tier`
- Enforcement: active
- Targets: specific repos by ID, default branch
- Required workflow: `.github/workflows/risk-tier-required.yml` from this repo at `refs/heads/main`
- Bypass: org admins

To add a repo: edit the ruleset and add the repo to the target list.

**Consumer repos do NOT need any workflow file.** The org ruleset injects `risk-tier-required.yml` automatically on PRs.

## Key Decisions & Gotchas

- **Reusable workflows don't work cross-repo** for private caller repos (even calling public reusable workflows). All steps are inlined in `risk-tier-required.yml`.
- **This repo must stay public** — `actions/checkout` in the required workflow checks out this repo; private repos can't checkout other private repos without a PAT.
- **Fork repos** (like `partner-sharing-service`) can't use `secrets: inherit` with cross-repo reusable workflows. Use explicit secret passing if ever re-adding the reusable workflow.
- Secret name is `CLAUDE_CODE_OAUTH_TOKEN` (org-level secret, visibility: private repos).
- `claude-code-action@v1` requires `id-token: write` permission for OIDC exchange.
- `claude-code-action@v1` input is `claude_code_oauth_token` (not `claude_access_token`).
- `max-turns: 15` — 5 was insufficient for Claude to read files + classify + label + comment.

## Testing

To test on a repo:
1. Add repo ID to the org ruleset target list
2. Open a PR on that repo
3. The `Risk Tier (Required)` / `classify` check should appear automatically
4. Verify label (`risktier:high` or `risktier:low`) and PR comment

## Modifying Policy

- **Deterministic rules:** edit `config/risk-rules.json` — file globs that auto-force `risktier:high`
- **LLM classification policy:** edit `risk-tier-conditions.md` — Claude reads this to decide tier
- Changes take effect on next PR (workflow always pulls `@main`)
