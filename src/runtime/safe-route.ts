export interface Parser<T> {
  parse(input: unknown): T;
}

export interface JsonResponseInit {
  status?: number;
  headers?: HeadersInit;
}

export class SafeRouteError extends Error {
  readonly status: number;
  readonly code: string;
  readonly safeMessage: string;

  constructor(status: number, code: string, safeMessage: string) {
    super(safeMessage);
    this.name = "SafeRouteError";
    this.status = status;
    this.code = code;
    this.safeMessage = safeMessage;
  }
}

export interface SafeJsonRouteOptions<TBody, TResult> {
  request: Request;
  schema?: Parser<TBody>;
  handler: (body: TBody, request: Request) => Promise<TResult> | TResult;
  parseEmptyBodyAs?: unknown;
  onError?: (error: unknown) => void;
}

export function json(body: unknown, init: JsonResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  if (!headers.has("content-type")) {
    headers.set("content-type", "application/json; charset=utf-8");
  }
  return new Response(JSON.stringify(body), { status: init.status ?? 200, headers });
}

export async function safeJsonRoute<TBody = unknown, TResult = unknown>({
  request,
  schema,
  handler,
  parseEmptyBodyAs,
  onError,
}: SafeJsonRouteOptions<TBody, TResult>): Promise<Response> {
  try {
    const raw = await parseJsonBody(request, parseEmptyBodyAs);
    const body = schema ? schema.parse(raw) : (raw as TBody);
    const result = await handler(body, request);
    return json(result);
  } catch (error) {
    onError?.(error);
    if (error instanceof SafeRouteError) {
      return json({ error: error.code, message: error.safeMessage }, { status: error.status });
    }
    if (isParserError(error)) {
      return json(
        { error: "invalid_request", message: "Check the request and try again." },
        { status: 400 },
      );
    }
    return json(
      { error: "server_error", message: "Something went wrong. Try again in a minute." },
      { status: 500 },
    );
  }
}

async function parseJsonBody(request: Request, emptyValue: unknown): Promise<unknown> {
  const text = await request.text();
  if (text.trim() === "") {
    return emptyValue ?? {};
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new SafeRouteError(400, "invalid_json", "Check the request and try again.");
  }
}

function isParserError(error: unknown): boolean {
  if (!error || typeof error !== "object") {
    return false;
  }
  if ("issues" in error && Array.isArray((error as { issues?: unknown }).issues)) {
    return true;
  }
  return error instanceof TypeError || error instanceof RangeError;
}
