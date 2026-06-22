# safe-build

Drop-in security scaffolding for apps built quickly with AI.

`safe-build` adds a practical security gate to a Next.js / Supabase-style app:
request validation, ownership checks before admin database access, secret
scanning, static code checks, dependency audit, and a live preview scan.

It is not a certification, audit, or promise that an app is secure. It is a
starter kit that catches common mistakes before a fast-built app goes live.

## Install

```bash
npx safe-build init --target .
```

Until the npm package is published, run from GitHub:

```bash
npx github:daringly-hq/safe-build init --target .
```

Use the stricter profile for apps that handle customer data, payments, admin
actions, or production traffic:

```bash
npx safe-build init --profile strict --target .
```

Use the static profile for simple sites without app routes or databases:

```bash
npx safe-build init --profile static --target .
```

The CLI does not overwrite existing files unless you pass `--force`.

```bash
npx safe-build init --profile strict --target . --force
```

## Profiles

- `generic` — broad Next.js / Supabase guardrails for fast-built apps.
- `strict` — the same base files plus stricter docs and CI notes for production
  apps.
- `static` — secret scanning, static analysis, and preview scanning for static
  sites without Next.js routes or Supabase tables.

## What It Adds

- `lib/security/safe-route.ts` — request parsing, Zod validation, sign-in hooks,
  safe public errors, and request IDs.
- `lib/security/tenant.ts` — ownership proof before admin database access.
- `.github/workflows/security-gate.yml` — secret scanning, Semgrep checks,
  dependency audit, and optional OWASP ZAP preview scan.
- `docs/security/safe-build-gate.md` — what the gate covers and how to use it.
- `tests/security/tenant-isolation.example.ts` — starter tests for cross-user
  data isolation.

The `static` profile adds only the workflow and docs, because route wrappers and
tenant helpers do not apply to static sites.

## Coverage Summary

`safe-build` is meant to cover the security checks that can be added
generically to many AI-built apps:

- Secrets: scan for leaked API keys and tokens before merge.
- Dependencies: audit package risk before launch.
- Static app security: scan for common TypeScript and web app mistakes.
- Input validation: validate JSON bodies before route logic runs.
- Safe errors: return plain public errors instead of raw stack traces.
- Tenant isolation: prove ownership before using privileged database access.
- Abuse resistance: provide a clear place to add auth, rate limits, and bot
  checks.
- Preview testing: optionally scan a live preview URL before production.
- Static sites: run secret/static/deploy checks without adding irrelevant app
  route files.
- AI app handoff: document what the coding agent must review when a generic
  scaffold cannot know the app's rules.

## Screenshot Checklist Coverage

The screenshots list a full production-readiness checklist. `safe-build` covers
the generic parts directly and turns the app-specific parts into agent tasks.

| Item | Status in `safe-build` |
| --- | --- |
| Input sanitization and injection prevention | Scaffolded with Zod request validation and Semgrep; agent must use parameterized queries or safe ORM patterns in real data code. |
| Authentication on the server only | Agent task; `safeRoute` includes a `getUser` hook, but the app's real auth provider must decide who is signed in. |
| Authorization on every action | Scaffolded with ownership-gated admin access; agent must add the real ownership checks for each table/action. |
| Roles and permissions | Agent task; depends on the app's user model and business rules. |
| Session management and token expiry | Agent task; depends on Supabase/Auth0/JWT/session provider settings. |
| Secrets never in client/git | Covered with Gitleaks and Semgrep secret rules; agent must move real secrets to environment or secret storage. |
| HTTPS, TLS, and certificate rotation | Agent/host task; `safe-build` documents it and preview scans the deployed URL. |
| Rate limiting and abuse prevention | Agent task; generated docs call it out for public routes, signup, login, forms, and email/contact endpoints. |
| Dependency scanning and vulnerability patching | Covered with package audit in CI. |
| Multi-tenancy and data isolation | Scaffolded with ownership helper and tenant-isolation starter tests. |
| PII handling, retention, and deletion | Agent task; depends on what data the app stores. |
| Regulatory compliance like GDPR or HIPAA | Not feasible generically; agent must avoid making compliance claims without legal/security review. |
| Audit trails and tamper-evident logging | Agent task; depends on infrastructure and retention needs. |
| Unit, integration, end-to-end, and regression tests | Agent task; `safe-build` adds starter security tests only. |
| Load, stress, chaos, and resilience testing | Agent task; depends on hosting and expected traffic. |
| Test coverage thresholds in CI | Agent task; depends on the app's test suite and risk level. |
| Code review process and standards | Agent/team process; `safe-build` adds CI checks but cannot enforce review culture alone. |
| Error handling and graceful degradation | Partly scaffolded with safe API errors; app-specific fallback behavior is an agent task. |
| Retry logic, backoff, and idempotency | Agent task; depends on payment, email, queue, and webhook providers. |
| Circuit breakers and fallback behavior | Agent task; depends on critical external services. |
| Concurrency and race-condition prevention | Agent task; depends on database constraints and workflows. |
| Caching strategy and invalidation | Agent task; depends on framework, CDN, and data freshness needs. |
| RTO, RPO, and disaster recovery | Agent/operator task; depends on hosting, database, backups, and business needs. |
| Accessibility | Agent task; needs UI review and automated checks. |
| Architecture diagrams and ADRs | Agent task; `safe-build` recommends documenting decisions when the app becomes production-critical. |
| Email verification after signup | Agent task; depends on auth provider and signup flow. |
| API keys exposed in the frontend | Covered by secret scanning where possible; agent must move server-only keys behind backend routes. |
| Suspicious activity logging without logging passwords/tokens | Agent task; generated docs call out safe logging and redaction. |

## What The Agent Must Handle

Some work cannot be handled safely by a generic installer because it depends on
the app's business rules, data model, vendors, or production setup. The generated
README tells the coding agent to handle these items:

- Auth provider wiring and session lookup.
- The real ownership query for each user-owned table.
- Supabase RLS policies and migration review.
- Payment, webhook, OAuth, and email-provider signature checks.
- Rate limits and bot protection for public routes.
- CORS, CSRF, cookie, and security-header settings.
- File upload limits, malware scanning, and private storage rules.
- LLM prompt-injection tests for apps that call models or agents.
- PII handling, retention, export, and delete flows.
- Environment variables, key rotation, and production secret storage.
- Rollback, logging, alerting, and incident response.
- Legal or compliance claims such as SOC 2, HIPAA, PCI, GDPR, or "safe/secure"
  marketing copy.
- Email verification after signup.
- Server-only API key usage for model, payment, email, database, and analytics
  providers.
- Load testing, stress testing, coverage thresholds, accessibility checks,
  architecture diagrams, and ADRs.

## Agent Resource Pack

When `safe-build` says "agent task," the agent should use these as starting
points:

- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) for a full application-security checklist.
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) for practical implementation guidance.
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) for untrusted inputs.
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) for server-side auth decisions.
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) for session lifetime and token handling.
- [OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) for HTTPS, API behavior, and transport safety.
- [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x11-t10/) for API authentication, authorization, and abuse risks.
- [NIST SSDF](https://csrc.nist.gov/projects/ssdf) for secure software development process guidance.

## Local Development

```bash
npm install
npm run typecheck
npm test
node bin/safe-build.mjs init --profile generic --target /tmp/safe-build-demo --dry-run
```
