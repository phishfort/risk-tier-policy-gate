# Reusable Risk Tier Workflow

This repo exposes a reusable GitHub Actions workflow:

- `.github/workflows/risk-tier-reusable.yml`

## Usage in another repo

Create `.github/workflows/risk-tier.yml` in the target repo:

```yaml
name: Risk Tier

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  risk-tier:
    uses: phishfort/risk-tier-policy-gate/.github/workflows/risk-tier-reusable.yml@main
    secrets:
      CLAUDE_ACCESS_TOKEN: ${{ secrets.CLAUDE_ACCESS_TOKEN }}
```

> **Security note:** Do not use `secrets: inherit` with external reusable workflows. It exposes _all_ org and repo secrets to the called workflow. Always pass only the secrets the workflow actually needs.

### Optional overrides

If a repo needs custom paths or model, you can still pass inputs/secrets explicitly:

```yaml
jobs:
  risk-tier:
    uses: phishfort/risk-tier-policy-gate/.github/workflows/risk-tier-reusable.yml@main
    with:
      claude_model: sonnet
      repo_conditions_path: risk-tier-conditions.md
      repo_rules_path: .github/risk-rules.json
    secrets:
      CLAUDE_ACCESS_TOKEN: ${{ secrets.CLAUDE_ACCESS_TOKEN }}
```

## Required setup

1. Create labels in the target repo:
   - `risktier:high`
   - `risktier:low`
2. Provide `CLAUDE_ACCESS_TOKEN` (repo secret or org secret).

## Behavior

- Deterministic rules run first.
- If deterministic rules match high-risk patterns, label is forced to `risktier:high`.
- Otherwise Claude classifies (`sonnet` by default).
- If Claude token is unavailable, fallback is `risktier:high` (fail-safe).
