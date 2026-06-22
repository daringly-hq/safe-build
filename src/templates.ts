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

const agentResourcePack = [
  "## Agent Resource Pack",
  "",
  "- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/",
  "- OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/",
  "- OWASP Input Validation: https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
  "- OWASP Authentication: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
  "- OWASP Session Management: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
  "- OWASP REST Security: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html",
  "- OWASP API Security Top 10: https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
  "- NIST SSDF: https://csrc.nist.gov/projects/ssdf",
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
