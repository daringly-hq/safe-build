import { mkdir, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { type SafeBuildProfile, parseProfile, templatesForProfile } from "./profiles";

export type ScaffoldAction =
  | "created"
  | "overwritten"
  | "skipped"
  | "would-create"
  | "would-overwrite";

export interface ScaffoldOptions {
  targetDir: string;
  profile?: SafeBuildProfile | string;
  force?: boolean;
  dryRun?: boolean;
}

export interface ScaffoldFileResult {
  path: string;
  action: ScaffoldAction;
}

export interface ScaffoldResult {
  profile: SafeBuildProfile;
  targetDir: string;
  files: ScaffoldFileResult[];
}

export async function scaffoldSafeBuildKit(options: ScaffoldOptions): Promise<ScaffoldResult> {
  const profile =
    typeof options.profile === "string"
      ? parseProfile(options.profile)
      : (options.profile ?? "generic");
  const targetDir = path.resolve(options.targetDir);
  const files: ScaffoldFileResult[] = [];

  for (const template of templatesForProfile(profile)) {
    const destination = path.join(targetDir, template.path);
    const exists = await fileExists(destination);
    const relativePath = path.relative(targetDir, destination);

    if (options.dryRun) {
      files.push({ path: relativePath, action: exists ? "would-overwrite" : "would-create" });
      continue;
    }

    if (exists && !options.force) {
      files.push({ path: relativePath, action: "skipped" });
      continue;
    }

    await mkdir(path.dirname(destination), { recursive: true });
    await writeFile(destination, template.content, "utf8");
    files.push({ path: relativePath, action: exists ? "overwritten" : "created" });
  }

  return { profile, targetDir, files };
}

async function fileExists(filePath: string): Promise<boolean> {
  try {
    const info = await stat(filePath);
    return info.isFile();
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
      return false;
    }
    throw error;
  }
}
