import type { TemplateFile } from "./profiles";

const githubPreviewUrl = "${{ vars.PREVIEW_URL }}";

const genericSafeRoute = String.raw`import { NextResponse, type NextRequest } from "next/server";
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

const genericTenant = String.raw`export class OwnershipError extends Error {
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

const genericWorkflow = String.raw`name: Safe Build Gate

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

const genericDoc = [
  "# Safe Build Gate",
  "",
  "This app uses the Daringly Safe Build Kit generic profile.",
  "",
  "It is not a security certification. It is a practical gate for fast-built apps.",
  "",
  "## What The Gate Checks",
  "",
  "- Secrets are not committed to the repo.",
  "- Code is scanned for common web app security mistakes.",
  "- Dependencies are audited before launch.",
  "- API routes validate input before doing work.",
  "- Admin database access is used only after ownership is checked.",
  "- A live preview can be scanned before production.",
  "",
  "## Commands",
  "",
  "Run the local checks your app already has, then run the security gate:",
  "",
  "```bash",
  "pnpm test",
  "pnpm audit --audit-level moderate",
  "```",
  "",
  "Set `PREVIEW_URL` as a GitHub Actions repository variable to enable the live",
  "OWASP ZAP baseline scan.",
  "",
  "## Safe Route Pattern",
  "",
  "Use `lib/security/safe-route.ts` for new API routes. It gives every route:",
  "",
  "- JSON parsing",
  "- Zod validation",
  "- sign-in checks when needed",
  "- plain error messages",
  "- request IDs for logs",
  "",
  "## Tenant Pattern",
  "",
  "Use `lib/security/tenant.ts` before any admin database call that touches a",
  "business or user-owned resource. Check ownership first, then call `ownedAdmin`.",
  "",
].join("\n");

const genericTenantExample = String.raw`import { describe, expect, test } from "vitest";
import { ownedAdmin, requireBusinessOwnership } from "../../lib/security/tenant";

describe("tenant isolation", () => {
  test("user A cannot use admin access for user B's business", async () => {
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

  test("admin access is only available after ownership is proven", async () => {
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

const daringlySafeRoute = String.raw`import { NextResponse, type NextRequest } from "next/server";
import { z, type ZodType } from "zod";

type AuthContext = {
  userId: string | null;
  user?: unknown;
};

type DaringlyRouteContext<TBody, TParams> = {
  req: NextRequest;
  body: TBody;
  params: TParams;
  auth: AuthContext;
  requestId: string;
};

type DaringlyRouteOptions<TBody, TResult, TParams> = {
  schema?: ZodType<TBody>;
  requireUser?: boolean;
  getUser?: (req: NextRequest) => Promise<AuthContext>;
  handler: (ctx: DaringlyRouteContext<TBody, TParams>) => Promise<TResult> | TResult;
};

export class FounderSafeError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "FounderSafeError";
  }
}

export function daringlyRoute<TBody = unknown, TResult = unknown, TParams = Record<string, string>>(
  options: DaringlyRouteOptions<TBody, TResult, TParams>,
) {
  return async (req: NextRequest, routeContext?: { params?: Promise<TParams> | TParams }) => {
    const requestId = newRequestId();
    try {
      const params = routeContext?.params ? await routeContext.params : ({} as TParams);
      const auth = options.getUser ? await options.getUser(req) : { userId: null };
      if (options.requireUser && !auth.userId) {
        throw new FounderSafeError(401, "not_signed_in", "Sign in to keep going.");
      }

      const raw = await readJson(req);
      const body = options.schema ? options.schema.parse(raw) : (raw as TBody);
      const result = await options.handler({ req, body, params, auth, requestId });
      return NextResponse.json(result);
    } catch (err) {
      return founderSafeErrorResponse(err, requestId);
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
    throw new FounderSafeError(400, "invalid_json", "Check the request and try again.");
  }
}

function founderSafeErrorResponse(err: unknown, requestId: string) {
  if (err instanceof FounderSafeError) {
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

  console.error("daringly_route_error", { requestId, err });
  return NextResponse.json(
    { error: "server_error", message: "Something went wrong on our end. Try again in a minute.", requestId },
    { status: 500 },
  );
}

function newRequestId(): string {
  return globalThis.crypto?.randomUUID?.() ?? Math.random().toString(36).slice(2);
}
`;

const daringlyTenant = String.raw`export class OwnershipError extends Error {
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
    throw new OwnershipError(500, "ownership_check_failed", "Something went wrong on our end. Try again.");
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

const daringlyWorkflow = String.raw`name: Daringly Safe Build Gate

on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  daringly-checks:
    name: Daringly guardrails
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: corepack enable
      - run: pnpm install --frozen-lockfile
      - run: pnpm lint:ownership
      - run: pnpm lint:idempotency
      - run: pnpm lint:plain-language
      - run: pnpm lint:no-founder-paperclip

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

const daringlyDoc = [
  "# Daringly Safe Build Gate",
  "",
  "This app uses the Daringly profile of the Safe Build Kit.",
  "",
  "It is not a security certification. It is a repeatable gate that keeps fast AI",
  "builds from skipping basic safety checks.",
  "",
  "## Extra Daringly Rules",
  "",
  "- Founder-facing copy must be plain language.",
  "- Founder-facing surfaces must never mention Paperclip.",
  "- User routes that take a business id must prove ownership before admin access.",
  "- Idempotency keys for external services must be stable, not random.",
  "- External-service failures must be shaped before they reach the founder.",
  "",
  "## Generated Files",
  "",
  "- `lib/security/safe-route.ts` wraps API routes with request validation and safe",
  "  error messages.",
  "- `lib/security/tenant.ts` gives a typed ownership proof before admin access.",
  "- `.github/workflows/security-gate.yml` runs Daringly lint gates plus secret,",
  "  static, dependency, and preview scans.",
  "",
  "## Required Local Checks",
  "",
  "```bash",
  "pnpm lint:ownership",
  "pnpm lint:idempotency",
  "pnpm lint:plain-language",
  "pnpm lint:no-founder-paperclip",
  "pnpm test",
  "```",
  "",
  "Set `PREVIEW_URL` as a GitHub Actions repository variable to enable the live",
  "OWASP ZAP baseline scan.",
  "",
].join("\n");

const daringlyTenantExample = String.raw`import { describe, expect, test } from "vitest";
import { ownedAdmin, requireBusinessOwnership } from "../../lib/security/tenant";

describe("Daringly tenant isolation", () => {
  test("a user cannot reach another business through admin access", async () => {
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
    content: genericSafeRoute,
    profiles: ["generic"],
  },
  {
    path: "lib/security/tenant.ts",
    content: genericTenant,
    profiles: ["generic"],
  },
  {
    path: ".github/workflows/security-gate.yml",
    content: genericWorkflow,
    profiles: ["generic"],
  },
  {
    path: "docs/security/safe-build-gate.md",
    content: genericDoc,
    profiles: ["generic"],
  },
  {
    path: "tests/security/tenant-isolation.example.ts",
    content: genericTenantExample,
    profiles: ["generic"],
  },
  {
    path: "lib/security/safe-route.ts",
    content: daringlySafeRoute,
    profiles: ["daringly"],
  },
  {
    path: "lib/security/tenant.ts",
    content: daringlyTenant,
    profiles: ["daringly"],
  },
  {
    path: ".github/workflows/security-gate.yml",
    content: daringlyWorkflow,
    profiles: ["daringly"],
  },
  {
    path: "docs/security/safe-build-gate.md",
    content: daringlyDoc,
    profiles: ["daringly"],
  },
  {
    path: "tests/security/tenant-isolation.example.ts",
    content: daringlyTenantExample,
    profiles: ["daringly"],
  },
];
