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

## Local Development

```bash
npm install
npm run typecheck
npm test
node bin/safe-build.mjs init --profile generic --target /tmp/safe-build-demo --dry-run
```
