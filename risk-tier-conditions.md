# Risk Tier Conditions (Org-Level)

Generic, framework-agnostic patterns for classifying PR changes. Repos should extend this with repo-specific file mappings in their own `risk-tier-conditions.md`.

---

## High Risk — requires human review

### Authentication & Authorization
- Auth flows (login, logout, session, token handling, MFA, SSO, OAuth)
- Permission/role checks, access control middleware, privilege escalation guards
- Session management (cookies, JWT, refresh tokens, expiry)

### Security Utilities
- Encryption/decryption, hashing, signing
- Input sanitization (XSS, SQLi, CSRF prevention)
- Redirect validation, CORS config, security headers
- Rate limiting, brute-force protection

### Middleware & Request Pipeline
- Route protection, auth middleware, request interceptors
- API gateway config, proxy rules

### CI/CD & Infrastructure
- GitHub Actions / CI pipeline definitions
- Dockerfile, docker-compose, container configs
- Terraform / IaC, deploy scripts
- Firewall rules, network policies

### Environment & Secrets
- Env var schemas, `.env` files, secret references
- Key/credential management, vault config

### Dependencies & Lockfiles
- `package.json`, `requirements.txt`, `Gemfile`, `go.mod` (and equivalents)
- Lockfile changes (`yarn.lock`, `package-lock.json`, `poetry.lock`, etc.)
- Especially: additions/upgrades of security-critical deps (auth, crypto, HTTP clients)

### File Uploads & User Content
- Upload endpoints, file processing, storage
- Content sanitization (SVG, HTML, PDF)
- MIME type validation

### API Core Infrastructure
- API router/handler registration (adding/removing endpoints changes attack surface)
- API framework setup (context creation, middleware chains, procedure definitions)
- Webhook handlers, callback endpoints

### Database & Migrations
- Schema migrations (column adds/drops/renames, index changes)
- Data migrations, seed scripts
- ORM config, connection pooling, query builders
- Direct SQL changes

### New Product Surfaces
- Entirely new top-level features/pages/services (new attack surface, permissions, data exposure)
- New API routers/controllers introduced for new product areas
- Distinguish from low-risk additive features on *existing* surfaces

### Data Validation Schemas (security-sensitive)
- User/account schemas, role enums, permission models
- Input validation for auth/payment/PII fields

### Audit & Compliance
- Audit logging, compliance-critical event tracking
- Data retention, GDPR/privacy logic

---

## Low Risk — auto-approvable

### Documentation
- READMEs, changelogs, ADRs, doc comments
- `.md` files, wiki pages, API docs

### Tests
- Unit, integration, e2e test files
- Test fixtures, mocks, factories
- Test config (`jest.config`, `playwright.config`, `pytest.ini`, etc.)

### UI Components (non-auth)
- Presentational components (buttons, modals, cards, layouts)
- Icons, illustrations
- Page-specific display components with no auth/data-mutation logic

### Styling
- CSS/SCSS/Tailwind/PostCSS files
- Theme config, design tokens
- Static assets (images, fonts, SVGs in public/)

### Linting & Formatting
- ESLint, Prettier, Stylelint, Rubocop configs
- Editor configs (`.editorconfig`, `.vscode/settings.json`)
- Git hooks (`.husky/`, pre-commit config)
- Commit lint config

### Type Definitions (non-schema)
- TypeScript type/interface files with no runtime effect
- API response type definitions (read-only shapes)

### Static Assets
- Images, fonts, favicons
- Locale/translation files (unless they expose unreleased features)

### Analytics & Monitoring (client-side)
- Analytics event tracking (PostHog, GA, Segment)
- Error monitoring config (Sentry, Datadog RUM)
- Cookie consent, banner config

### Read-Only Data Endpoints
- Display-only API routes (stats, charts, lists with no mutations)
- GraphQL/tRPC queries that only read data

### Client-Side State
- State management stores (Redux, Zustand, Pinia, etc.) with no auth logic
- React hooks, composables (non-security)

### Additive Features (within existing surfaces)
- New components added to existing pages (dropdowns, filters, cards)
- New client-side stores for existing features
- New data schemas that don't touch auth/user/payment models

### Non-Security Constants & Helpers
- Formatting utils, date helpers, string manipulation
- Feature-flag values (non-security), display constants
- Non-sensitive config (pagination sizes, sort orders)
