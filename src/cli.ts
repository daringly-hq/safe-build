#!/usr/bin/env node
import { scaffoldSafeBuildKit } from "./scaffold";

interface CliArgs {
  command: "init" | "help";
  profile: string;
  targetDir: string;
  force: boolean;
  dryRun: boolean;
}

async function main(argv: string[]): Promise<void> {
  const args = parseArgs(argv);
  if (args.command === "help") {
    printHelp();
    return;
  }

  const result = await scaffoldSafeBuildKit({
    targetDir: args.targetDir,
    profile: args.profile,
    force: args.force,
    dryRun: args.dryRun,
  });

  console.log(`safe-build (${result.profile}) -> ${result.targetDir}`);
  for (const file of result.files) {
    console.log(`${file.action.padEnd(15)} ${file.path}`);
  }
}

function parseArgs(argv: string[]): CliArgs {
  const [command = "help", ...rest] = argv;
  if (command === "help" || command === "--help" || command === "-h") {
    return {
      command: "help",
      profile: "generic",
      targetDir: process.cwd(),
      force: false,
      dryRun: false,
    };
  }
  if (command !== "init") {
    throw new Error(`Unknown command "${command}".`);
  }

  const args: CliArgs = {
    command,
    profile: "generic",
    targetDir: process.cwd(),
    force: false,
    dryRun: false,
  };

  for (let index = 0; index < rest.length; index += 1) {
    const arg = rest[index];
    if (arg === "--profile") {
      index += 1;
      args.profile = requireValue(rest, index, "--profile");
    } else if (arg?.startsWith("--profile=")) {
      args.profile = arg.slice("--profile=".length);
    } else if (arg === "--target") {
      index += 1;
      args.targetDir = requireValue(rest, index, "--target");
    } else if (arg?.startsWith("--target=")) {
      args.targetDir = arg.slice("--target=".length);
    } else if (arg === "--force") {
      args.force = true;
    } else if (arg === "--dry-run") {
      args.dryRun = true;
    } else {
      throw new Error(`Unknown option "${arg}".`);
    }
  }

  return args;
}

function requireValue(values: string[], index: number, flag: string): string {
  const value = values[index];
  if (!value || value.startsWith("--")) {
    throw new Error(`${flag} needs a value.`);
  }
  return value;
}

function printHelp(): void {
  console.log(`Usage:
  safe-build init [--profile generic|strict|static] [--target .] [--force] [--dry-run]

Profiles:
  generic   Broad Next.js/Supabase guardrails for fast-built apps
  strict    More production-focused checks and a bigger handoff list
  static    Secret/static/deploy checks for static sites without app routes`);
}

main(process.argv.slice(2)).catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
