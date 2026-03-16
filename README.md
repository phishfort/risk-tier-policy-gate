# Risk Tier Policy Gate

Automatically classifies pull requests as **high risk** or **low risk** across the PhishFort org — and blocks merges on high-risk PRs until a human reviews them.

## How it works

When you open a PR on an enrolled repo:

1. **Deterministic rules** check your changed files against known high-risk patterns (workflows, auth files, dependencies, etc.) defined in [`config/risk-rules.json`](config/risk-rules.json)
2. If no deterministic match, **Claude (LLM)** reads the diff and classifies using the policy in [`risk-tier-conditions.md`](risk-tier-conditions.md)
3. The PR gets labeled `risktier:high` or `risktier:low`
4. **Low-risk** PRs are auto-approved by the bot — merge away
5. **High-risk** PRs auto-request reviews from collaborators with write access and are blocked until a human approves

```
PR opened → deterministic rules → (if unclear) LLM classifies → label → auto-approve or block
```

## What makes a PR high risk?

Anything touching security-sensitive areas: auth, secrets, CI/CD, dependencies, database migrations, new API surfaces, etc. See the full policy in [`risk-tier-conditions.md`](risk-tier-conditions.md).

**Low-risk** examples: docs, tests, styling, UI components (no auth logic), static assets.

## For developers

**You don't need to do anything.** If your repo is enrolled, the check runs automatically on every PR. No workflow files needed in your repo.

- `risktier:low` → bot approves, you can merge
- `risktier:high` → reviews auto-requested from repo collaborators with write access, then merge after approval

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
3. Ensure ruleset branch targeting includes `Default`, `main`, and `master` (for mixed repos where `develop` may be default)
4. Done — next PR on that repo will be classified automatically

### Branch targeting note (important)

To ensure release PRs like `develop -> main` are covered org-wide, target these branches in the ruleset:

- `Default`
- `main`
- `master`

This avoids gaps in repos where `develop`/`development` is the default branch.

## Modifying the policy

- **Deterministic rules** (file patterns): edit [`config/risk-rules.json`](config/risk-rules.json)
- **LLM classification policy**: edit [`risk-tier-conditions.md`](risk-tier-conditions.md)
- Changes take effect on the next PR (workflow always pulls from `main`)

**Per-repo overrides:** Consumer repos can add their own `risk-tier-conditions.md` or `risk-rules.json` at the repo root. If present, they take precedence over the central defaults.
