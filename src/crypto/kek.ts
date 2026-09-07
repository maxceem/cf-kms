/**
 * KEK registry.
 *
 * SECURITY INVARIANT: this is the only file allowed to read `KEK_*` off the
 * environment, and the only place raw KEK material is ever touched. Nothing
 * here returns key bytes — callers only ever get a non-extractable `CryptoKey`.
 * `test/invariants.test.ts` enforces the grep-level part of this.
 */
const KEK_SECRET_PREFIX = "KEK_V";
const KEK_SECRET_PATTERN = /^KEK_V([1-9][0-9]{0,3})$/;
const KEK_CURRENT_VERSION_BINDING = "KEK_CURRENT_VERSION";
const KEK_BYTE_LENGTH = 32;

export interface KekRegistry {
  /** Version used for new wraps. Always present in {@link KekRegistry.versions}. */
  readonly currentVersion: number;
  /** Every version accepted for unwrap, ascending. */
  readonly versions: readonly number[];
  has(version: number): boolean;
  /** Non-extractable AES-256-GCM key. Rejects for unknown versions. */
  key(version: number): Promise<CryptoKey>;
}

/**
 * Imported keys, cached for the lifetime of the isolate. Keyed by the raw
 * material so that two envs (e.g. across tests, or a rotated secret) can never
 * collide on a version number. The material is already resident in `env`; the
 * cache adds no new exposure, and the imported key is non-extractable.
 */
const importedKeks = new Map<string, Promise<CryptoKey>>();

const decodeBase64 = (value: string): Uint8Array => {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes;
};

/**
 * Validates one `KEK_V<n>` secret and returns it unchanged (still base64).
 * The decoded bytes are dropped immediately — only `importKek` materializes
 * them, and only to hand them straight to a non-extractable `CryptoKey`.
 */
const validateKekMaterial = (value: unknown, binding: string): string => {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`cf-kms: ${binding} must be a non-empty base64 string`);
  }

  const material = value.trim();
  let byteLength: number;

  try {
    byteLength = decodeBase64(material).length;
  } catch {
    throw new Error(`cf-kms: ${binding} is not valid base64`);
  }

  if (byteLength !== KEK_BYTE_LENGTH) {
    throw new Error(`cf-kms: ${binding} must decode to ${KEK_BYTE_LENGTH} bytes`);
  }

  return material;
};

const importKek = (material: string): Promise<CryptoKey> => {
  const cached = importedKeks.get(material);

  if (cached) {
    return cached;
  }

  const imported = crypto.subtle
    .importKey("raw", decodeBase64(material), { name: "AES-GCM" }, false, ["encrypt", "decrypt"])
    .catch((error: unknown) => {
      importedKeks.delete(material);
      throw error;
    });

  importedKeks.set(material, imported);

  return imported;
};

const parseCurrentVersion = (value: unknown): number => {
  if (typeof value !== "string" || !/^[1-9][0-9]{0,3}$/.test(value.trim())) {
    throw new Error(`cf-kms: ${KEK_CURRENT_VERSION_BINDING} must be a positive integer string`);
  }

  return Number(value.trim());
};

/**
 * Validates the KEK configuration and returns the registry. Throws (fails the
 * request, loudly) on a missing or malformed secret — there is no degraded mode.
 */
export const createKekRegistry = (env: unknown): KekRegistry => {
  if (typeof env !== "object" || env === null) {
    throw new Error("cf-kms: env must be an object");
  }

  const materials = new Map<number, string>();

  for (const [binding, value] of Object.entries(env as Record<string, unknown>)) {
    if (!binding.startsWith(KEK_SECRET_PREFIX)) {
      continue;
    }

    const match = KEK_SECRET_PATTERN.exec(binding);

    // A binding that looks like a KEK but is not one (KEK_V0, KEK_Vold, a typo)
    // must not be silently ignored — that would be a KEK nobody notices missing.
    if (!match?.[1]) {
      throw new Error(`cf-kms: ${binding} is not a valid KEK secret name`);
    }

    materials.set(Number(match[1]), validateKekMaterial(value, binding));
  }

  if (materials.size === 0) {
    throw new Error("cf-kms: at least one KEK_V<n> secret is required");
  }

  const currentVersion = parseCurrentVersion(
    (env as Record<string, unknown>)[KEK_CURRENT_VERSION_BINDING],
  );

  if (!materials.has(currentVersion)) {
    throw new Error(
      `cf-kms: ${KEK_CURRENT_VERSION_BINDING} is ${currentVersion} but KEK_V${currentVersion} is not set`,
    );
  }

  const versions = [...materials.keys()].sort((left, right) => left - right);

  return {
    currentVersion,
    versions,
    has: (version) => materials.has(version),
    key: async (version) => {
      const material = materials.get(version);

      if (material === undefined) {
        throw new Error("cf-kms: unknown KEK version");
      }

      return importKek(material);
    },
  };
};
