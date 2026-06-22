import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { scaffoldSafeBuildKit } from "./scaffold";

const tempDirs: string[] = [];

afterEach(async () => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) {
      await rm(dir, { recursive: true, force: true });
    }
  }
});

describe("scaffoldSafeBuildKit", () => {
  it("scaffolds the generic profile without Daringly-specific lint hooks", async () => {
    const targetDir = await tempDir();
    const result = await scaffoldSafeBuildKit({ targetDir, profile: "generic" });

    expect(result.profile).toBe("generic");
    expect(result.files.map((file) => file.action)).toEqual([
      "created",
      "created",
      "created",
      "created",
      "created",
    ]);

    const workflow = await readFile(
      path.join(targetDir, ".github/workflows/security-gate.yml"),
      "utf8",
    );
    const route = await readFile(path.join(targetDir, "lib/security/safe-route.ts"), "utf8");
    expect(workflow).toContain("gitleaks/gitleaks-action");
    expect(workflow).not.toContain("lint:ownership");
    expect(route).toContain("safeRoute");
    expect(route).not.toContain("daringlyRoute");
  });

  it("scaffolds the Daringly profile with stricter repo guardrails", async () => {
    const targetDir = await tempDir();
    await scaffoldSafeBuildKit({ targetDir, profile: "daringly" });

    const workflow = await readFile(
      path.join(targetDir, ".github/workflows/security-gate.yml"),
      "utf8",
    );
    const doc = await readFile(path.join(targetDir, "docs/security/safe-build-gate.md"), "utf8");
    expect(workflow).toContain("pnpm lint:ownership");
    expect(workflow).toContain("pnpm lint:no-founder-paperclip");
    expect(doc).toContain("Founder-facing copy must be plain language.");
  });

  it("does not overwrite existing files unless forced", async () => {
    const targetDir = await tempDir();
    const routePath = path.join(targetDir, "lib/security/safe-route.ts");
    await scaffoldSafeBuildKit({ targetDir, profile: "generic" });
    await writeFile(routePath, "custom", "utf8");

    const skipped = await scaffoldSafeBuildKit({ targetDir, profile: "generic" });
    expect(skipped.files.find((file) => file.path === "lib/security/safe-route.ts")?.action).toBe(
      "skipped",
    );
    await expect(readFile(routePath, "utf8")).resolves.toBe("custom");

    const forced = await scaffoldSafeBuildKit({ targetDir, profile: "generic", force: true });
    expect(forced.files.find((file) => file.path === "lib/security/safe-route.ts")?.action).toBe(
      "overwritten",
    );
    await expect(readFile(routePath, "utf8")).resolves.toContain("safeRoute");
  });

  it("supports dry runs without writing files", async () => {
    const targetDir = await tempDir();
    const result = await scaffoldSafeBuildKit({ targetDir, profile: "daringly", dryRun: true });

    expect(result.files.every((file) => file.action === "would-create")).toBe(true);
    await expect(
      readFile(path.join(targetDir, "lib/security/safe-route.ts"), "utf8"),
    ).rejects.toThrow(/ENOENT/);
  });
});

async function tempDir(): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), "safe-build-kit-"));
  tempDirs.push(dir);
  return dir;
}
