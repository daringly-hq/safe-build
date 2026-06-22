import { describe, expect, it, vi } from "vitest";
import { type Parser, SafeRouteError, safeJsonRoute } from "./safe-route";

const NameSchema: Parser<{ name: string }> = {
  parse(input: unknown) {
    if (
      !input ||
      typeof input !== "object" ||
      !("name" in input) ||
      typeof input.name !== "string"
    ) {
      throw { issues: [{ path: ["name"], message: "Required" }] };
    }
    return { name: input.name };
  },
};

describe("safeJsonRoute", () => {
  it("validates JSON and returns the handler result", async () => {
    const response = await safeJsonRoute({
      request: jsonRequest({ name: "Ada" }),
      schema: NameSchema,
      handler: async (body) => ({ ok: true, greeting: `Hi ${body.name}` }),
    });

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ ok: true, greeting: "Hi Ada" });
  });

  it("returns a 400 for invalid JSON", async () => {
    const response = await safeJsonRoute({
      request: new Request("https://app.test/api", { method: "POST", body: "{" }),
      schema: NameSchema,
      handler: async () => ({ ok: true }),
    });

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({ error: "invalid_json" });
  });

  it("returns a 400 when schema parsing fails", async () => {
    const response = await safeJsonRoute({
      request: jsonRequest({ nope: true }),
      schema: NameSchema,
      handler: async () => ({ ok: true }),
    });

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({ error: "invalid_request" });
  });

  it("passes through safe public errors", async () => {
    const response = await safeJsonRoute({
      request: jsonRequest({ name: "Ada" }),
      schema: NameSchema,
      handler: async () => {
        throw new SafeRouteError(409, "already_done", "That has already been handled.");
      },
    });

    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toEqual({
      error: "already_done",
      message: "That has already been handled.",
    });
  });

  it("hides unexpected errors but still exposes them to logs", async () => {
    const onError = vi.fn();
    const response = await safeJsonRoute({
      request: jsonRequest({ name: "Ada" }),
      schema: NameSchema,
      onError,
      handler: async () => {
        throw new Error("database password is wrong");
      },
    });

    expect(response.status).toBe(500);
    expect(onError).toHaveBeenCalledOnce();
    await expect(response.json()).resolves.toEqual({
      error: "server_error",
      message: "Something went wrong. Try again in a minute.",
    });
  });
});

function jsonRequest(body: unknown): Request {
  return new Request("https://app.test/api", {
    method: "POST",
    body: JSON.stringify(body),
    headers: { "content-type": "application/json" },
  });
}
