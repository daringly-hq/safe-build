export class OwnershipError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "OwnershipError";
    this.status = status;
    this.code = code;
  }
}

export type OwnershipCheck = (args: {
  resourceId: string;
  userId: string;
}) => Promise<boolean> | boolean;

export interface OwnedResource<TAdmin> {
  readonly admin: TAdmin;
  readonly resourceId: string;
  readonly userId: string;
  readonly __ownerVerified: "safe-build-kit";
}

export interface RequireOwnedResourceOptions<TAdmin> {
  resourceId: string;
  userId: string | null | undefined;
  admin: TAdmin;
  check: OwnershipCheck;
}

export async function requireOwnedResource<TAdmin>({
  resourceId,
  userId,
  admin,
  check,
}: RequireOwnedResourceOptions<TAdmin>): Promise<OwnedResource<TAdmin>> {
  if (!userId) {
    throw new OwnershipError(401, "not_signed_in", "Sign in to keep going.");
  }
  const owned = await check({ resourceId, userId });
  if (!owned) {
    throw new OwnershipError(404, "not_found", "We could not find that item.");
  }
  return {
    admin,
    resourceId,
    userId,
    __ownerVerified: "safe-build-kit",
  };
}

export function ownedAdmin<TAdmin>(owned: OwnedResource<TAdmin>): TAdmin {
  return owned.admin;
}
