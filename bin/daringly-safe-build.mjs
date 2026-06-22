#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const tsxPackageJson = require.resolve("tsx/package.json");
const tsxCli = path.join(path.dirname(tsxPackageJson), "dist/cli.mjs");
const cli = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
const result = spawnSync(process.execPath, [tsxCli, cli, ...process.argv.slice(2)], {
  stdio: "inherit",
});

if (result.error) {
  throw result.error;
}

process.exitCode = typeof result.status === "number" ? result.status : 1;
