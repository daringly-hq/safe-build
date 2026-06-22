import { describe, expect, it, vi } from "vitest";
import { OwnershipError, ownedAdmin, requireOwnedResource } from "./tenant";

describe("tenant ownership helpers", () => {
  it("rejects missing users before running the ownership check", async () => {
    const check = vi.fn();

    await expect(
      requireOwnedResource({
        resourceId: "biz_1",
        userId: null,
        admin: {},
        check,
      }),
    ).rejects.toEqual(new OwnershipError(401, "not_signed_in", "Sign in to keep going."));

    expect(check).not.toHaveBeenCalled();
  });

  it("returns a not-found response for resources the user does not own", async () => {
    await expect(
      requireOwnedResource({
        resourceId: "biz_2",
        userId: "user_1",
        admin: {},
        check: async () => false,
      }),
    ).rejects.toMatchObject({ status: 404, code: "not_found" });
  });

  it("brands owned resources and returns the admin handle only after proof", async () => {
    const admin = { serviceRole: true };
    const owned = await requireOwnedResource({
      resourceId: "biz_1",
      userId: "user_1",
      admin,
      check: async ({ resourceId, userId }) => resourceId === "biz_1" && userId === "user_1",
    });

    expect(owned.resourceId).toBe("biz_1");
    expect(owned.userId).toBe("user_1");
    expect(ownedAdmin(owned)).toBe(admin);
  });
});
