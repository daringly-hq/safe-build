# Daringly Safe Build Kit

Drop-in security scaffolding for apps built quickly with AI.

This is a security gate, not a certification. It gives an app practical checks
that map to OWASP and NIST ideas: validate requests, check ownership before
using admin access, scan secrets, scan code, audit dependencies, and test a live
preview before launch.

## Profiles

- `generic` — for Next.js / Supabase-style apps that are not part of Daringly.
- `daringly` — for Daringly-owned apps. Adds stricter tenant and founder-facing
  guardrails, including Daringly lint hooks.

## Usage

Run from GitHub:

```bash
npx github:daringly-hq/daringly-safe-build init --target .
npx github:daringly-hq/daringly-safe-build init --profile daringly --target .
```

After the package is published to npm, the command becomes:

```bash
npx daringly-safe-build init --target .
npx daringly-safe-build init --profile daringly --target .
```

The CLI will not overwrite existing files unless you pass `--force`.

```bash
npx github:daringly-hq/daringly-safe-build init --profile generic --target .
npx github:daringly-hq/daringly-safe-build init --profile daringly --target . --force
```

## What It Adds

- `lib/security/safe-route.ts` — request parsing, schema validation, and safe
  error responses.
- `lib/security/tenant.ts` — ownership proof before admin access.
- `.github/workflows/security-gate.yml` — secret scanning, static checks,
  dependency audit, and optional preview scanning.
- `docs/security/*` — how to run and explain the gate.

The `daringly` profile also adds Daringly-specific lint commands and copy rules.

## Local Development

```bash
npm install
npm run typecheck
npm test
node bin/daringly-safe-build.mjs init --profile generic --target /tmp/safe-build-demo --dry-run
```

## Publishing

This repo is ready for npm publishing under the `daringly-safe-build` package
name. Publishing is a separate release step:

```bash
npm publish --access public
```

Until that is done, use the GitHub `npx` command shown above.
