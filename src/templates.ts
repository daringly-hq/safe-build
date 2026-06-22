import type { TemplateFile } from "./profiles";

const githubPreviewUrl = "${{ vars.PREVIEW_URL }}";

const safeRoute = String.raw`import { NextResponse, type NextRequest } from "next/server";
import { z, type ZodType } from "zod";

type AuthContext = {
  userId: string | null;
  user?: unknown;
};

type SafeRouteContext<TBody, TParams> = {
  req: NextRequest;
  body: TBody;
  params: TParams;
  auth: AuthContext;
  requestId: string;
};

type SafeRouteOptions<TBody, TResult, TParams> = {
  schema?: ZodType<TBody>;
  requireUser?: boolean;
  getUser?: (req: NextRequest) => Promise<AuthContext>;
  handler: (ctx: SafeRouteContext<TBody, TParams>) => Promise<TResult> | TResult;
};

export class PublicError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "PublicError";
  }
}

export function safeRoute<TBody = unknown, TResult = unknown, TParams = Record<string, string>>(
  options: SafeRouteOptions<TBody, TResult, TParams>,
) {
  return async (req: NextRequest, routeContext?: { params?: Promise<TParams> | TParams }) => {
    const requestId = newRequestId();
    try {
      const params = routeContext?.params ? await routeContext.params : ({} as TParams);
      const auth = options.getUser ? await options.getUser(req) : { userId: null };
      if (options.requireUser && !auth.userId) {
        throw new PublicError(401, "not_signed_in", "Sign in to keep going.");
      }

      const raw = await readJson(req);
      const body = options.schema ? options.schema.parse(raw) : (raw as TBody);
      const result = await options.handler({ req, body, params, auth, requestId });
      return NextResponse.json(result);
    } catch (err) {
      return safeErrorResponse(err, requestId);
    }
  };
}

export const EmptyBodySchema = z.object({}).strict();

async function readJson(req: NextRequest): Promise<unknown> {
  const text = await req.text();
  if (text.trim() === "") {
    return {};
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new PublicError(400, "invalid_json", "Check the request and try again.");
  }
}

function safeErrorResponse(err: unknown, requestId: string) {
  if (err instanceof PublicError) {
    return NextResponse.json(
      { error: err.code, message: err.message, requestId },
      { status: err.status },
    );
  }
  if (err instanceof z.ZodError) {
    return NextResponse.json(
      { error: "invalid_request", message: "Check the request and try again.", requestId },
      { status: 400 },
    );
  }

  console.error("safe_route_error", { requestId, err });
  return NextResponse.json(
    { error: "server_error", message: "Something went wrong. Try again in a minute.", requestId },
    { status: 500 },
  );
}

function newRequestId(): string {
  return globalThis.crypto?.randomUUID?.() ?? Math.random().toString(36).slice(2);
}
`;

const tenant = String.raw`export class OwnershipError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "OwnershipError";
  }
}

type QueryResult = {
  data: { id: string } | null;
  error: { message?: string } | null;
};

type BusinessOwnershipClient = {
  from(table: "businesses"): {
    select(columns: string): {
      eq(column: string, value: string): {
        eq(column: string, value: string): {
          maybeSingle(): Promise<QueryResult>;
        };
      };
    };
  };
};

const ownerVerified: unique symbol = Symbol("ownerVerified");

export type OwnedBusiness<TAdmin> = {
  id: string;
  userId: string;
  admin: TAdmin;
  readonly [ownerVerified]: true;
};

export async function requireBusinessOwnership<TAdmin>(args: {
  supabase: BusinessOwnershipClient;
  businessId: string;
  userId: string | null | undefined;
  getAdmin: () => TAdmin;
}): Promise<OwnedBusiness<TAdmin>> {
  if (!args.userId) {
    throw new OwnershipError(401, "not_signed_in", "Sign in to keep going.");
  }

  const { data, error } = await args.supabase
    .from("businesses")
    .select("id")
    .eq("id", args.businessId)
    .eq("user_id", args.userId)
    .maybeSingle();

  if (error) {
    console.error("business_ownership_check_failed", { businessId: args.businessId, error });
    throw new OwnershipError(500, "ownership_check_failed", "Something went wrong. Try again.");
  }
  if (!data) {
    throw new OwnershipError(404, "not_found", "We could not find that business.");
  }

  return {
    id: args.businessId,
    userId: args.userId,
    admin: args.getAdmin(),
    [ownerVerified]: true,
  };
}

export function ownedAdmin<TAdmin>(owned: OwnedBusiness<TAdmin>): TAdmin {
  return owned.admin;
}
`;

const workflow = String.raw`name: Safe Build Gate

on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  secrets:
    name: Secret scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: gitleaks/gitleaks-action@v2

  static-analysis:
    name: Static security scan
    runs-on: ubuntu-latest
    container:
      image: semgrep/semgrep:latest
    steps:
      - uses: actions/checkout@v4
      - run: semgrep scan --config p/owasp-top-ten --config p/typescript --error

  dependencies:
    name: Dependency audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: corepack enable
      - run: pnpm install --frozen-lockfile
      - run: pnpm audit --audit-level moderate

  preview-scan:
    name: Live preview scan
    runs-on: ubuntu-latest
    if: vars.PREVIEW_URL != ''
    steps:
      - uses: zaproxy/action-baseline@v0.14.0
        with:
          target: ${githubPreviewUrl}
          fail_action: true
          cmd_options: "-a"
`;

const strictWorkflow = String.raw`name: Safe Build Gate

on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  secrets:
    name: Secret scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: gitleaks/gitleaks-action@v2

  static-analysis:
    name: Static security scan
    runs-on: ubuntu-latest
    container:
      image: semgrep/semgrep:latest
    steps:
      - uses: actions/checkout@v4
      - run: semgrep scan --config p/owasp-top-ten --config p/typescript --config p/secrets --error

  dependencies:
    name: Dependency audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: corepack enable
      - run: pnpm install --frozen-lockfile
      - run: pnpm audit --audit-level moderate

  preview-scan:
    name: Live preview scan
    runs-on: ubuntu-latest
    if: vars.PREVIEW_URL != ''
    steps:
      - uses: zaproxy/action-baseline@v0.14.0
        with:
          target: ${githubPreviewUrl}
          fail_action: true
          cmd_options: "-a"
`;

const staticWorkflow = String.raw`name: Safe Build Gate

on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  secrets:
    name: Secret scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: gitleaks/gitleaks-action@v2

  static-analysis:
    name: Static content scan
    runs-on: ubuntu-latest
    container:
      image: semgrep/semgrep:latest
    steps:
      - uses: actions/checkout@v4
      - run: semgrep scan --config p/secrets --config p/javascript --error

  preview-scan:
    name: Live preview scan
    runs-on: ubuntu-latest
    if: vars.PREVIEW_URL != ''
    steps:
      - uses: zaproxy/action-baseline@v0.14.0
        with:
          target: ${githubPreviewUrl}
          fail_action: true
          cmd_options: "-a"
`;

const checklistCoverage = [
  "## Checklist Coverage",
  "",
  "- Covered directly: secret scanning, dependency audit, static code scan, safe public errors, preview scan wiring.",
  "- Scaffolded for the agent: server-side auth, authorization on every sensitive action, input validation, tenant isolation, safe logging.",
  "- Agent must implement: rate limits, email verification, session expiry, roles, CORS/CSRF, PII retention/deletion, audit logs, retries, idempotency, circuit breakers, cache invalidation, accessibility, disaster recovery, and compliance review.",
  "",
];

const staticChecklistCoverage = [
  "## Checklist Coverage",
  "",
  "- Covered directly: secret scanning, static content scan, preview scan wiring.",
  "- Agent must implement: hosting security headers, HTTPS/TLS settings, third-party script review, form abuse limits, accessibility, disaster recovery, and compliance review.",
  "",
];

const agentOperatingRules = [
  "## Agent Operating Rules",
  "",
  "When an agent installs this package, it should treat this document as the security handoff for the app.",
  "",
  "- Do not claim the app is secure, compliant, HIPAA-ready, SOC 2-ready, PCI-ready, or production-safe just because this gate exists.",
  "- Treat every form field, URL parameter, route parameter, webhook body, file, cookie, AI output, and third-party payload as untrusted until validated.",
  "- Server code must decide who is signed in. Client-side checks are only UX hints.",
  "- Every sensitive action needs an authorization check for this exact user, this exact record, and this exact action.",
  "- Never use a service-role, admin, or root client in a user-driven route until ownership has been proven.",
  "- Prefer deny-by-default behavior. If the app cannot prove access is allowed, return a safe error.",
  "- Never log passwords, tokens, cookies, authorization headers, API keys, raw payment data, or sensitive personal data.",
  "- Move server-only keys behind backend routes. Public browser keys must be designed for public use and protected with provider-side rules.",
  "- Keep security checks in CI and make failed scans block deploys for production apps.",
  "",
];

const bestPracticeMatrix = [
  "## Best Practices Matrix",
  "",
  "| Area | What `safe-build` adds | What the agent must do | Resources |",
  "| --- | --- | --- | --- |",
  "| App risk level | A baseline gate and profile choice. | Classify the app as static, generic, or strict. Use strict for customer data, payments, admin actions, private files, write access, AI agents, or production traffic. | OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/ |",
  "| Input validation and injection prevention | Zod request schemas and Semgrep checks. | Add schemas for every body, query string, route parameter, webhook payload, and AI/tool output. Use parameterized queries or safe ORM calls. Add max lengths and allowlists where practical. | OWASP Input Validation: https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html; OWASP SQL Injection Prevention: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html |",
  "| Authentication | `safeRoute` has a `getUser` hook. | Wire the hook to the real server-side auth provider. Require email verification for accounts that can create data, spend money, send email, or access private content. Add MFA for admin or high-risk accounts. | OWASP Authentication: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html; Supabase password auth: https://supabase.com/docs/guides/auth/passwords |",
  "| Email verification and account creation | Agent handoff notes. | Verify email ownership before enabling account use, sending email, creating billable resources, or showing private data. Rate-limit signup by IP, device/session where appropriate, and account identifiers. | OWASP Email Validation and Verification: https://cheatsheetseries.owasp.org/cheatsheets/Email_Validation_and_Verification_Cheat_Sheet.html; Supabase auth rate limits: https://supabase.com/docs/guides/auth/rate-limits |",
  "| Multifactor authentication | Agent handoff notes. | Require or strongly encourage MFA for admins, staff, high-risk users, billing settings, destructive actions, and apps with sensitive data. | OWASP MFA: https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html |",
  "| Authorization | Ownership helper and tenant-isolation starter tests. | Check authorization on every sensitive action. Cover both horizontal access, such as user A reading user B data, and vertical access, such as normal users using admin actions. | OWASP Authorization: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html; OWASP IDOR: https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html |",
  "| Roles and permissions | A place to centralize server checks. | Define roles in code, document who can do each action, and test every role boundary. Do not rely only on hidden buttons or client-side route guards. | OWASP Authorization: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html |",
  "| Session management | Agent handoff notes. | Set secure cookies, short session lifetimes for risky apps, refresh-token rotation where supported, sign-out handling, and server-side session lookup. | OWASP Session Management: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html |",
  "| Secrets management | Gitleaks and Semgrep secret checks. | Rotate any leaked secret, remove it from history where needed, keep `.env` files out of git, use hosting secrets, and separate public browser keys from server-only keys. | OWASP Secrets Management: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html; GitHub secret scanning: https://docs.github.com/en/code-security/concepts/secret-security/secret-scanning |",
  "| Frontend API keys | Secret scanning where possible. | Review every `NEXT_PUBLIC_`, Vite public env var, Firebase key, Supabase anon key, analytics key, and model key. Anything that grants paid, private, admin, or write access must move server-side. | OWASP API Security Top 10: https://owasp.org/API-Security/editions/2023/en/0x11-t10/ |",
  "| Rate limiting and abuse prevention | CI/docs callouts. | Add IP and user-based limits to signup, login, password reset, contact forms, email sending, file upload, AI calls, payment starts, and expensive reads. Do not rate-limit contact forms only by email address. | Arcjet: https://docs.arcjet.com/; OWASP Denial of Service: https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html |",
  "| Bot and automation protection | Agent handoff notes. | Add bot checks or CAPTCHA only where abuse risk justifies friction. Log and alert on spikes, repeated failures, throwaway domains, and high-cost paths. | OWASP Bot Management: https://cheatsheetseries.owasp.org/cheatsheets/Bot_Management_and_Anti-Automation_Cheat_Sheet.html |",
  "| HTTPS, TLS, and certificates | Preview scan against deployed URL. | Enforce HTTPS at the host, set HSTS after verifying subdomains, redirect HTTP to HTTPS, and confirm certificate renewal is owned by the host or ops process. | MDN HSTS: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security; OWASP Transport Layer Protection: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html |",
  "| Security headers | Agent handoff notes. | Add CSP, HSTS, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and frame protections. Test CSP in report-only mode before enforcing if the app has many scripts. | Next.js headers: https://nextjs.org/docs/app/api-reference/config/next-config-js/headers; Next.js CSP: https://nextjs.org/docs/app/guides/content-security-policy; MDN CSP: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP |",
  "| CORS and CSRF | Agent handoff notes. | Keep CORS allowlists narrow. Add CSRF protection to cookie-authenticated state-changing routes. Do not use wildcard origins with credentials. | OWASP CSRF: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html; OWASP REST Security: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html |",
  "| Database isolation | Tenant helper and starter tests. | Enable and review Supabase RLS on user-owned tables. Add policy tests that prove user A cannot read, write, update, or delete user B data. | Supabase RLS: https://supabase.com/docs/guides/database/postgres/row-level-security |",
  "| Admin/service-role clients | Ownership proof pattern. | Keep service-role clients out of browser code and unauthenticated routes. Wrap every privileged operation in a proof step and keep the proof close to the admin call. | OWASP Authorization: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html |",
  "| PII and privacy | Agent handoff notes. | Inventory personal data, minimize collection, document purpose, add export/delete flows where required, define retention, and redact PII in logs. | OWASP User Privacy Protection: https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html; NIST Privacy Framework: https://www.nist.gov/privacy-framework |",
  "| Compliance claims | Explicit non-certification language. | Do not claim GDPR, HIPAA, SOC 2, PCI, or other compliance without legal and security review. Map controls to requirements before making claims. | NIST SSDF: https://csrc.nist.gov/projects/ssdf; OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/ |",
  "| Logging and audit trails | Safe public errors and request IDs. | Log important security events, failed auth, permission denials, webhook failures, high-risk writes, and admin actions. Redact sensitive fields. Use append-only or tamper-resistant logs for high-risk apps. | OWASP Logging: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html |",
  "| Error handling | `PublicError` and safe error responses. | Return useful public messages without stack traces, SQL errors, raw provider errors, secrets, IDs that reveal access, or internal route details. Alert on repeated server errors. | OWASP Error Handling: https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html |",
  "| File uploads and storage | Agent handoff notes. | Enforce file size, type, extension, content sniffing, storage path ownership, private bucket rules, malware scanning for risky apps, and signed URLs with expiry. | OWASP File Upload: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html |",
  "| Webhooks and callbacks | Agent handoff notes. | Verify signatures before parsing business logic. Add replay protection, timestamp tolerance, idempotent processing, and safe retries. | Stripe webhooks: https://docs.stripe.com/webhooks; OWASP API Security Top 10: https://owasp.org/API-Security/editions/2023/en/0x11-t10/ |",
  "| Payments and billing | Agent handoff notes. | Use provider-hosted checkout where possible, verify webhook signatures, avoid trusting client-reported prices, and use idempotency for charge/order creation. | Stripe idempotent requests: https://docs.stripe.com/api/idempotent_requests; Stripe webhooks: https://docs.stripe.com/webhooks |",
  "| Retries and idempotency | Agent handoff notes. | Use stable idempotency keys for non-idempotent POST/PATCH actions such as payments, email sending, account creation, provisioning, and webhooks. Add backoff with jitter and avoid double side effects. | MDN Idempotency-Key: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Idempotency-Key; Stripe idempotent requests: https://docs.stripe.com/api/idempotent_requests |",
  "| Circuit breakers and fallback behavior | Agent handoff notes. | Add timeouts, provider failure handling, fallback states, and clear user-facing errors for critical services. Avoid endless retries. | Microsoft Circuit Breaker pattern: https://learn.microsoft.com/en-us/azure/architecture/patterns/circuit-breaker; Microsoft Retry pattern: https://learn.microsoft.com/en-us/azure/architecture/patterns/retry |",
  "| Concurrency and race conditions | Agent handoff notes. | Use database constraints, transactions, unique indexes, row locks where needed, and tests for duplicate submissions or concurrent webhook delivery. | PostgreSQL constraints: https://www.postgresql.org/docs/current/ddl-constraints.html; PostgreSQL transactions: https://www.postgresql.org/docs/current/tutorial-transactions.html |",
  "| Caching and invalidation | Agent handoff notes. | Do not cache private data publicly. Include user/tenant in cache keys. Define revalidation after writes and purge paths for deleted private content. | Next.js caching: https://nextjs.org/docs/app/building-your-application/caching |",
  "| Dependency risk | `pnpm audit` in CI. | Keep lockfiles committed, remove unused packages, enable Dependabot or Renovate, review install scripts, and add OSV/Snyk-style scanning for higher-risk apps. | GitHub dependency graph: https://docs.github.com/en/code-security/concepts/supply-chain-security/dependency-graph; OSV-Scanner: https://github.com/google/osv-scanner |",
  "| Software supply chain | Agent handoff notes. | Review package provenance, transitive dependencies, GitHub Actions, install scripts, generated lockfile churn, and release artifacts. Pin or review high-risk automation. | OWASP Software Supply Chain Security: https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html; OWASP Vulnerable Dependency Management: https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html |",
  "| CI and code scanning | Security workflow. | Make scans required for production branches. Add CodeQL or GitHub code scanning for mature repos. Do not let failing security checks deploy to production. | GitHub code scanning: https://docs.github.com/en/code-security/concepts/code-scanning/code-scanning; Semgrep: https://docs.semgrep.dev/getting-started/quickstart |",
  "| Code review process and standards | Agent handoff notes. | Require review for auth, permissions, data access, payments, webhooks, AI tools, secrets, migrations, and generated code. Review tests and failure modes, not just style. | OWASP Secure Code Review: https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html |",
  "| GitHub Actions security | A least-permission workflow start. | Pin actions for high-risk repos, minimize tokens, avoid running untrusted PR code with write tokens, and protect secrets from forked PRs. | GitHub Actions secure use: https://docs.github.com/en/actions/reference/security/secure-use |",
  "| Live preview scanning | Optional OWASP ZAP baseline scan. | Set `PREVIEW_URL` and review ZAP findings before production. Add authenticated scans only with care and test accounts. | OWASP ZAP baseline action: https://github.com/zaproxy/action-baseline; OWASP WSTG: https://owasp.org/www-project-web-security-testing-guide/ |",
  "| Unit, integration, E2E, and regression tests | Tenant-isolation starter tests. | Add tests for auth, authorization, validation, payment/webhook idempotency, PII deletion, file access, and important user flows. Keep regression tests for every fixed security bug. | OWASP WSTG: https://owasp.org/www-project-web-security-testing-guide/ |",
  "| Coverage thresholds | Agent handoff notes. | Add coverage thresholds only after useful tests exist. Prefer security-critical path tests over high percentages with shallow tests. | GitHub Code Quality PR thresholds: https://docs.github.com/en/code-security/how-tos/maintain-quality-code/set-pr-thresholds |",
  "| Load, stress, and resilience testing | Agent handoff notes. | Test expected peak traffic, expensive routes, signup/contact abuse, AI cost spikes, and webhook bursts. Define failure modes before launch. | k6 docs: https://grafana.com/docs/k6/latest/; OWASP DoS: https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html |",
  "| AI and LLM features | Agent handoff notes. | Add prompt-injection tests, data exfiltration tests, tool permission checks, output validation, PII controls, human approval for risky actions, and cost limits. | OWASP LLM Top 10: https://owasp.org/www-project-top-10-for-large-language-model-applications/; OWASP LLM Prompt Injection: https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html; Promptfoo red team: https://www.promptfoo.dev/docs/red-team/ |",
  "| Accessibility | Agent handoff notes. | Run automated checks and keyboard/screen-reader review on core flows. Do not block forms, modals, auth, checkout, or support flows for assistive tech users. | WCAG: https://www.w3.org/WAI/standards-guidelines/wcag/; Playwright accessibility testing: https://playwright.dev/docs/accessibility-testing; MDN accessibility: https://developer.mozilla.org/en-US/docs/Web/Accessibility |",
  "| Backups, RTO, RPO, and disaster recovery | Agent handoff notes. | Define backup schedule, restore test, owner, RTO, RPO, rollback process, secret rotation process, and incident contacts. Test restores before relying on backups. | NIST Cybersecurity Framework: https://www.nist.gov/cyberframework |",
  "| Architecture diagrams and ADRs | Agent handoff notes. | Document trust boundaries, data flow, privileged services, third-party systems, background jobs, storage, and key decisions when the app becomes business-critical. | OWASP Threat Modeling: https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html; ADR guide: https://adr.github.io/ |",
  "| Static sites | Static profile workflow and docs. | Review forms, CMS integrations, analytics tags, third-party scripts, redirects, cache rules, security headers, and any API that the static site calls. | OWASP Third Party JavaScript: https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html; MDN Web Security: https://developer.mozilla.org/en-US/docs/Web/Security |",
  "",
];

const agentChecklist = [
  "## Agent Checklist Before Shipping",
  "",
  "- Run the app test suite and add tests for any security-sensitive behavior changed by this work.",
  "- Run the generated security workflow locally where practical: secret scan, static scan, dependency audit, and preview scan.",
  "- Search for public env vars and frontend API calls that expose server-only credentials or paid provider keys.",
  "- Check every public mutation route for auth, authorization, input validation, rate limits, and safe errors.",
  "- Check every data read route for tenant isolation and private-data cache leaks.",
  "- Check every webhook for signature verification, replay protection, and idempotency.",
  "- Check every file upload or download path for size/type limits, private storage rules, signed URL expiry, and ownership.",
  "- Check every AI feature for prompt injection, tool misuse, data exfiltration, PII leaks, and cost abuse.",
  "- Confirm production hosting has HTTPS, security headers, environment secrets, logs, alerts, backups, and rollback.",
  "- Record anything not fixed yet as a clear follow-up with owner, risk, and launch impact.",
  "",
];

const agentResourcePack = [
  "## Agent Resource Pack",
  "",
  "Use these references when a task above says the agent must implement or review something app-specific.",
  "",
  "### Standards and testing",
  "",
  "- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/",
  "- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/",
  "- OWASP API Security Top 10: https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
  "- OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/",
  "- NIST SSDF: https://csrc.nist.gov/projects/ssdf",
  "- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework",
  "- NIST AI Risk Management Framework: https://www.nist.gov/itl/ai-risk-management-framework",
  "",
  "### Implementation references",
  "",
  "- Input Validation: https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
  "- SQL Injection Prevention: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
  "- Authentication: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
  "- Email Validation and Verification: https://cheatsheetseries.owasp.org/cheatsheets/Email_Validation_and_Verification_Cheat_Sheet.html",
  "- Multifactor Authentication: https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html",
  "- Authorization: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
  "- Session Management: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
  "- CSRF Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
  "- Bot Management and Anti-Automation: https://cheatsheetseries.owasp.org/cheatsheets/Bot_Management_and_Anti-Automation_Cheat_Sheet.html",
  "- Denial of Service: https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html",
  "- Secrets Management: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
  "- Logging: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
  "- Error Handling: https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html",
  "- File Upload: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
  "- REST Security: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html",
  "- User Privacy Protection: https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html",
  "- Software Supply Chain Security: https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html",
  "- Vulnerable Dependency Management: https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html",
  "- Secure Code Review: https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html",
  "- GitHub Actions Security: https://cheatsheetseries.owasp.org/cheatsheets/GitHub_Actions_Security_Cheat_Sheet.html",
  "- Third Party JavaScript Management: https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html",
  "- Threat Modeling: https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html",
  "- LLM Prompt Injection Prevention: https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html",
  "- OWASP LLM Top 10: https://owasp.org/www-project-top-10-for-large-language-model-applications/",
  "- Supabase RLS: https://supabase.com/docs/guides/database/postgres/row-level-security",
  "- Supabase password auth: https://supabase.com/docs/guides/auth/passwords",
  "- Supabase auth rate limits: https://supabase.com/docs/guides/auth/rate-limits",
  "- Next.js headers: https://nextjs.org/docs/app/api-reference/config/next-config-js/headers",
  "- Next.js CSP: https://nextjs.org/docs/app/guides/content-security-policy",
  "- Next.js caching: https://nextjs.org/docs/app/building-your-application/caching",
  "- MDN CSP: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
  "- MDN HSTS: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
  "- MDN Idempotency-Key: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Idempotency-Key",
  "- MDN Web Security: https://developer.mozilla.org/en-US/docs/Web/Security",
  "- PostgreSQL constraints: https://www.postgresql.org/docs/current/ddl-constraints.html",
  "- PostgreSQL transactions: https://www.postgresql.org/docs/current/tutorial-transactions.html",
  "- Microsoft Circuit Breaker pattern: https://learn.microsoft.com/en-us/azure/architecture/patterns/circuit-breaker",
  "- Microsoft Retry pattern: https://learn.microsoft.com/en-us/azure/architecture/patterns/retry",
  "- WCAG: https://www.w3.org/WAI/standards-guidelines/wcag/",
  "- ADR guide: https://adr.github.io/",
  "",
  "### Tooling references",
  "",
  "- Gitleaks action: https://github.com/gitleaks/gitleaks-action",
  "- Semgrep quickstart: https://docs.semgrep.dev/getting-started/quickstart",
  "- OWASP ZAP baseline action: https://github.com/zaproxy/action-baseline",
  "- GitHub code scanning: https://docs.github.com/en/code-security/concepts/code-scanning/code-scanning",
  "- GitHub secret scanning: https://docs.github.com/en/code-security/concepts/secret-security/secret-scanning",
  "- GitHub dependency graph: https://docs.github.com/en/code-security/concepts/supply-chain-security/dependency-graph",
  "- GitHub Actions secure use: https://docs.github.com/en/actions/reference/security/secure-use",
  "- OSV-Scanner: https://github.com/google/osv-scanner",
  "- Playwright accessibility testing: https://playwright.dev/docs/accessibility-testing",
  "- Arcjet: https://docs.arcjet.com/",
  "- Stripe webhooks: https://docs.stripe.com/webhooks",
  "- Stripe idempotent requests: https://docs.stripe.com/api/idempotent_requests",
  "- Promptfoo red teaming: https://www.promptfoo.dev/docs/red-team/",
  "",
];

const genericDoc = [
  "# Safe Build Gate",
  "",
  "This app uses the `safe-build` generic profile.",
  "",
  "This is not a security certification. It is a practical gate for fast-built apps.",
  "",
  "## What The Gate Covers",
  "",
  "- Secrets are scanned before merge.",
  "- Dependencies are audited before launch.",
  "- Code is scanned for common web app security mistakes.",
  "- API routes can validate JSON input before doing work.",
  "- Public errors avoid raw stack traces and internal details.",
  "- Admin database access is gated by an ownership helper.",
  "- A live preview can be scanned before production.",
  "",
  "## What The Agent Must Handle",
  "",
  "- Wire `getUser` to the app's real auth provider.",
  "- Replace the example business ownership query with the app's real data model.",
  "- Review Supabase RLS policies and migrations.",
  "- Add rate limits and bot checks to public routes.",
  "- Verify webhooks, OAuth callbacks, payment flows, and email signatures.",
  "- Add LLM prompt-injection tests if the app calls models or agents.",
  "- Set production security headers, cookies, CORS, CSRF, logging, and rollback.",
  "",
  ...checklistCoverage,
  ...agentOperatingRules,
  ...bestPracticeMatrix,
  ...agentChecklist,
  ...agentResourcePack,
].join("\n");

const strictDoc = [
  "# Safe Build Gate",
  "",
  "This app uses the `safe-build` strict profile.",
  "",
  "This profile is for apps that handle customer data, payments, admin actions,",
  "or production traffic. It still is not a security certification.",
  "",
  "## What The Gate Covers",
  "",
  "- Secret scanning with Gitleaks.",
  "- Static security scans with Semgrep OWASP, TypeScript, and secrets rules.",
  "- Dependency audit before launch.",
  "- Safe route wrapper for JSON parsing, validation, and safe public errors.",
  "- Ownership-gated admin access helper.",
  "- Optional OWASP ZAP scan against a preview URL.",
  "- Tenant-isolation starter tests.",
  "",
  "## What The Agent Must Handle",
  "",
  "- Auth provider wiring and session lookup.",
  "- Real ownership checks for every user-owned table.",
  "- Supabase RLS policies, migration review, and service-role boundaries.",
  "- Payment, webhook, OAuth, and email-provider signature checks.",
  "- Rate limits and bot protection for public routes.",
  "- CORS, CSRF, cookie, and security-header settings.",
  "- File upload limits, malware scanning, and private storage rules.",
  "- LLM prompt-injection tests for model or agent features.",
  "- PII handling, retention, export, and delete flows.",
  "- Environment variables, key rotation, and production secret storage.",
  "- Rollback, logging, alerting, and incident response.",
  "- Legal or compliance claims such as SOC 2, HIPAA, PCI, GDPR, or safe/secure marketing copy.",
  "",
  ...checklistCoverage,
  ...agentOperatingRules,
  ...bestPracticeMatrix,
  ...agentChecklist,
  ...agentResourcePack,
].join("\n");

const staticDoc = [
  "# Safe Build Gate",
  "",
  "This site uses the `safe-build` static profile.",
  "",
  "This profile is for static sites and simple render pipelines. It does not add",
  "Next.js route wrappers or Supabase tenant helpers.",
  "",
  "## What The Gate Covers",
  "",
  "- Secret scanning with Gitleaks.",
  "- Static content and JavaScript scans with Semgrep.",
  "- Optional OWASP ZAP scan against a preview URL.",
  "- A clear handoff list for checks that need project context.",
  "",
  "## What The Agent Must Handle",
  "",
  "- Add a dependency audit if this site later gains dependencies and a lockfile.",
  "- Verify forms, embeds, analytics, and third-party scripts.",
  "- Set production security headers, redirects, and cache rules with the host.",
  "- Keep `.env`, local build output, and generated artifacts out of git.",
  "- Review any CMS, form backend, or API endpoint connected to the static site.",
  "- Run a preview scan after deploy by setting `PREVIEW_URL` in GitHub Actions.",
  "",
  ...staticChecklistCoverage,
  ...agentOperatingRules,
  ...bestPracticeMatrix,
  ...agentChecklist,
  ...agentResourcePack,
].join("\n");

const tenantExample = String.raw`import { describe, expect, test } from "vitest";
import { ownedAdmin, requireBusinessOwnership } from "../../lib/security/tenant";

describe("tenant isolation", () => {
  test("a user cannot reach another user's business through admin access", async () => {
    const supabase = fakeSupabase({ owned: false });

    await expect(
      requireBusinessOwnership({
        supabase,
        businessId: "biz_other",
        userId: "user_a",
        getAdmin: () => ({ serviceRole: true }),
      }),
    ).rejects.toMatchObject({ status: 404 });
  });

  test("admin client is only returned after ownership is proven", async () => {
    const admin = { serviceRole: true };
    const owned = await requireBusinessOwnership({
      supabase: fakeSupabase({ owned: true }),
      businessId: "biz_a",
      userId: "user_a",
      getAdmin: () => admin,
    });

    expect(ownedAdmin(owned)).toBe(admin);
  });
});

function fakeSupabase({ owned }: { owned: boolean }) {
  return {
    from: () => ({
      select: () => ({
        eq: () => ({
          eq: () => ({
            maybeSingle: async () => ({
              data: owned ? { id: "biz_a" } : null,
              error: null,
            }),
          }),
        }),
      }),
    }),
  } as any;
}
`;

export const templates: TemplateFile[] = [
  {
    path: "lib/security/safe-route.ts",
    content: safeRoute,
    profiles: ["generic", "strict"],
  },
  {
    path: "lib/security/tenant.ts",
    content: tenant,
    profiles: ["generic", "strict"],
  },
  {
    path: ".github/workflows/security-gate.yml",
    content: workflow,
    profiles: ["generic"],
  },
  {
    path: ".github/workflows/security-gate.yml",
    content: strictWorkflow,
    profiles: ["strict"],
  },
  {
    path: ".github/workflows/security-gate.yml",
    content: staticWorkflow,
    profiles: ["static"],
  },
  {
    path: "docs/security/safe-build-gate.md",
    content: genericDoc,
    profiles: ["generic"],
  },
  {
    path: "docs/security/safe-build-gate.md",
    content: strictDoc,
    profiles: ["strict"],
  },
  {
    path: "docs/security/safe-build-gate.md",
    content: staticDoc,
    profiles: ["static"],
  },
  {
    path: "tests/security/tenant-isolation.example.ts",
    content: tenantExample,
    profiles: ["generic", "strict"],
  },
];
