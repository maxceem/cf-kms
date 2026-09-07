// Deployment profiles.
//
// `wrangler.jsonc` is the complete, ready-to-deploy configuration and the only
// one the repository tracks. A profile is a gitignored
// `wrangler.<profile>.overlay.jsonc` next to it that holds just the keys a
// particular deployment changes: its name, a custom domain, its caller
// allowlist. The overlay is merged over the tracked file on every run, so
// shared sections such as the observability block are never copied and cannot
// drift.
//
// The merged result is written to `wrangler.<profile>.generated.jsonc` beside
// the sources (Wrangler resolves `main` and asset paths relative to the config
// file) and passed to Wrangler with `--config`.
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parse, printParseErrorCode } from "jsonc-parser";

export const projectRoot = fileURLToPath(new URL("..", import.meta.url));
export const wranglerBin =
  process.env.CF_KMS_WRANGLER_BIN ?? join(projectRoot, "node_modules", ".bin", "wrangler");

const BASE_FILE = "wrangler.jsonc";
const OVERLAY_SUFFIX = ".overlay.jsonc";
const PROFILE_PATTERN = /^[a-z0-9][a-z0-9-]*$/iu;

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Objects merge recursively, arrays in the overlay replace the base array
 * wholesale, and `null` deletes a key. Small enough to reason about by eye.
 */
export function mergeWranglerConfig(base, overlay) {
  if (!isPlainObject(base) || !isPlainObject(overlay)) return overlay;
  const result = { ...base };
  for (const [key, value] of Object.entries(overlay)) {
    if (value === null) {
      delete result[key];
    } else if (isPlainObject(value) && isPlainObject(result[key])) {
      result[key] = mergeWranglerConfig(result[key], value);
    } else {
      result[key] = value;
    }
  }
  return result;
}

export function readJsonc(path) {
  const errors = [];
  const value = parse(readFileSync(path, "utf8"), errors, { allowTrailingComma: true });
  if (errors.length > 0) {
    const [first] = errors;
    throw new Error(`${path}: ${printParseErrorCode(first.error)} at offset ${first.offset}`);
  }
  return value;
}

export function overlayFileName(profile) {
  return `wrangler.${profile}${OVERLAY_SUFFIX}`;
}

export function listProfiles(dir = projectRoot) {
  return readdirSync(dir)
    .filter((name) => name.startsWith("wrangler.") && name.endsWith(OVERLAY_SUFFIX))
    .map((name) => name.slice("wrangler.".length, -OVERLAY_SUFFIX.length))
    .sort();
}

/**
 * Resolves the Wrangler configuration for a profile. Without a profile the
 * tracked file is used as is and no extra CLI arguments are needed.
 */
export function resolveWranglerConfig(profile, dir = projectRoot) {
  const basePath = join(dir, BASE_FILE);
  const base = readJsonc(basePath);
  if (!profile) return { config: base, configPath: basePath, configArgs: [] };

  if (!PROFILE_PATTERN.test(profile)) {
    throw new Error(`Invalid deployment profile name "${profile}"`);
  }
  const overlayPath = join(dir, overlayFileName(profile));
  if (!existsSync(overlayPath)) {
    const available = listProfiles(dir);
    throw new Error(
      [
        `Deployment profile "${profile}" not found: expected ${overlayPath}`,
        available.length > 0
          ? `Available profiles: ${available.join(", ")}`
          : "No profiles exist yet; see the Deployment profiles section of the README.",
      ].join("\n"),
    );
  }

  const config = mergeWranglerConfig(base, readJsonc(overlayPath));
  const configPath = join(dir, `wrangler.${profile}.generated.jsonc`);
  writeFileSync(
    configPath,
    [
      `// Generated from ${BASE_FILE} and ${basename(overlayPath)}. Do not edit;`,
      "// change the overlay instead. This file is ignored by git.",
      JSON.stringify(config, null, 2),
      "",
    ].join("\n"),
  );
  return { config, configPath, configArgs: ["--config", configPath] };
}

/**
 * Removes `--profile <name>` (or `--profile=<name>`) from an argument list.
 */
export function takeProfileArgument(args) {
  const rest = [];
  let profile;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--profile") {
      profile = args[index + 1];
      index += 1;
    } else if (arg.startsWith("--profile=")) {
      profile = arg.slice("--profile=".length);
    } else {
      rest.push(arg);
    }
  }
  if (profile === "" || profile === undefined && args.includes("--profile")) {
    throw new Error("--profile requires a name");
  }
  return { profile, rest };
}
