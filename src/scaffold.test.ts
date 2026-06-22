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
  it("scaffolds the generic profile with the base security gate", async () => {
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
    expect(workflow).toContain("semgrep scan --config p/owasp-top-ten --config p/typescript");
    expect(route).toContain("safeRoute");
    expect(route).toContain("PublicError");
  });

  it("scaffolds the strict profile with stricter docs and scan config", async () => {
    const targetDir = await tempDir();
    await scaffoldSafeBuildKit({ targetDir, profile: "strict" });

    const workflow = await readFile(
      path.join(targetDir, ".github/workflows/security-gate.yml"),
      "utf8",
    );
    const doc = await readFile(path.join(targetDir, "docs/security/safe-build-gate.md"), "utf8");
    expect(workflow).toContain("--config p/secrets");
    expect(doc).toContain("This app uses the `safe-build` strict profile.");
    expect(doc).toContain("What The Agent Must Handle");
  });

  it("scaffolds the static profile without app-route files", async () => {
    const targetDir = await tempDir();
    const result = await scaffoldSafeBuildKit({ targetDir, profile: "static" });

    expect(result.profile).toBe("static");
    expect(result.files.map((file) => file.path)).toEqual([
      ".github/workflows/security-gate.yml",
      "docs/security/safe-build-gate.md",
    ]);

    const workflow = await readFile(
      path.join(targetDir, ".github/workflows/security-gate.yml"),
      "utf8",
    );
    const doc = await readFile(path.join(targetDir, "docs/security/safe-build-gate.md"), "utf8");
    expect(workflow).toContain("Static content scan");
    expect(doc).toContain("This site uses the `safe-build` static profile.");
    await expect(readFile(path.join(targetDir, "lib/security/safe-route.ts"), "utf8")).rejects.toThrow(
      /ENOENT/,
    );
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
    const result = await scaffoldSafeBuildKit({ targetDir, profile: "strict", dryRun: true });

    expect(result.files.every((file) => file.action === "would-create")).toBe(true);
    await expect(
      readFile(path.join(targetDir, "lib/security/safe-route.ts"), "utf8"),
    ).rejects.toThrow(/ENOENT/);
  });
});

async function tempDir(): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), "safe-build-"));
  tempDirs.push(dir);
  return dir;
}
