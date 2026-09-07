#!/usr/bin/env node
// Runs Wrangler with an optional deployment profile:
//
//   node scripts/wrangler.mjs [--profile <name>] [--cwd <dir>] <wrangler arguments>
//
// `--profile` merges `wrangler.<name>.overlay.jsonc` over `wrangler.jsonc` (see
// scripts/wrangler-config.mjs) and passes the result with `--config`. `--cwd`
// selects another directory, which this repository does not currently need.
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import {
  projectRoot,
  resolveWranglerConfig,
  takeProfileArgument,
  wranglerBin,
} from "./wrangler-config.mjs";

function takeOption(args, name) {
  const index = args.indexOf(name);
  if (index === -1) return { value: undefined, rest: args };
  return { value: args[index + 1], rest: [...args.slice(0, index), ...args.slice(index + 2)] };
}

try {
  const { profile, rest: withoutProfile } = takeProfileArgument(process.argv.slice(2));
  const { value: cwd, rest } = takeOption(withoutProfile, "--cwd");
  const dir = cwd ? resolve(projectRoot, cwd) : projectRoot;
  const { configArgs } = resolveWranglerConfig(profile, dir);

  const result = spawnSync(wranglerBin, [...rest, ...configArgs], { cwd: dir, stdio: "inherit" });
  if (result.error) throw result.error;
  process.exitCode = result.status ?? 1;
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
