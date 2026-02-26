# Risk Tier Policy Gate

Automatically classifies pull requests as **high risk** or **low risk** across the PhishFort org — and blocks merges on high-risk PRs until a human reviews them.

## How it works

When you open a PR on an enrolled repo:

1. **Deterministic rules** check your changed files against known high-risk patterns (workflows, auth files, dependencies, etc.) defined in [`config/risk-rules.json`](config/risk-rules.json)
2. If no deterministic match, **Claude (LLM)** reads the diff and classifies using the policy in [`risk-tier-conditions.md`](risk-tier-conditions.md)
3. The PR gets labeled `risktier:high` or `risktier:low`
4. **Low-risk** PRs are auto-approved by the bot — merge away
5. **High-risk** PRs are blocked until a human approves

```
PR opened → deterministic rules → (if unclear) LLM classifies → label → auto-approve or block
```

## What makes a PR high risk?

Anything touching security-sensitive areas: auth, secrets, CI/CD, dependencies, database migrations, new API surfaces, etc. See the full policy in [`risk-tier-conditions.md`](risk-tier-conditions.md).

**Low-risk** examples: docs, tests, styling, UI components (no auth logic), static assets.

## For developers

**You don't need to do anything.** If your repo is enrolled, the check runs automatically on every PR. No workflow files needed in your repo.

- `risktier:low` → bot approves, you can merge
- `risktier:high` → get a teammate to review, then merge

## Repo structure

```
.github/workflows/risk-tier-required.yml  ← the workflow (injected by org ruleset)
config/risk-rules.json                    ← file patterns that auto-flag high risk
scripts/risk-rules.mjs                    ← evaluates files against the patterns
risk-tier-conditions.md                   ← full policy Claude reads for classification
```

## Enrolling a new repo

1. Get the repo ID: `gh api repos/phishfort/REPO_NAME --jq '.id'`
2. Add it to the [org ruleset](https://github.com/organizations/phishfort/settings/rules/13230835) target list
3. Done — next PR on that repo will be classified automatically

## Modifying the policy

- **Deterministic rules** (file patterns): edit [`config/risk-rules.json`](config/risk-rules.json)
- **LLM classification policy**: edit [`risk-tier-conditions.md`](risk-tier-conditions.md)
- Changes take effect on the next PR (workflow always pulls from `main`)
