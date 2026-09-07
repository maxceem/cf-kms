import { z } from "zod";
import { contextSatisfies, type EncryptionContext } from "./crypto/context";
import { unauthorized } from "./errors";

/**
 * Caller authentication.
 *
 * Tokens look like `ckms_<name>_<random>`. cf-kms only ever stores the SHA-256
 * hash of the whole token, so a dump of its `CALLERS` var yields nothing usable.
 */
const TOKEN_PREFIX = "ckms_";
const MIN_TOKEN_SECRET_LENGTH = 16;
const MAX_TOKEN_LENGTH = 256;
const MAX_CALLERS = 64;

const callerNameSchema = z
  .string()
  .min(1)
  .max(64)
  // No `_`: the name is delimited from the random part by the first underscore.
  .regex(/^[a-z0-9][a-z0-9-]*$/);

export const callerSchema = z.object({
  name: callerNameSchema,
  /** Lowercase SHA-256 hex of the full bearer token. */
  tokenHash: z.string().regex(/^[0-9a-f]{64}$/),
  /**
   * Keys that must be present, with exactly these values, in the
   * `encryptionContext` of every request from this caller.
   */
  requiredContext: z.record(z.string().min(1).max(64), z.string().max(256)).default({}),
});

export type Caller = z.infer<typeof callerSchema>;

export const callersSchema = z
  .array(callerSchema)
  .max(MAX_CALLERS)
  .refine((callers) => new Set(callers.map((caller) => caller.name)).size === callers.length, {
    message: "caller names must be unique",
  })
  .refine(
    (callers) => new Set(callers.map((caller) => caller.tokenHash)).size === callers.length,
    { message: "caller token hashes must be unique" },
  );

/** Parses the `CALLERS` var (a JSON string, or an already-parsed array). */
export const parseCallers = (raw: unknown): Caller[] => {
  let value: unknown = raw;

  if (typeof raw === "string") {
    try {
      value = JSON.parse(raw);
    } catch {
      throw new Error("cf-kms: CALLERS must be valid JSON");
    }
  }

  const parsed = callersSchema.safeParse(value);

  if (!parsed.success) {
    throw new Error("cf-kms: CALLERS is not a valid caller list");
  }

  return parsed.data;
};

export const sha256Hex = async (value: string): Promise<string> => {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));

  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
};

/**
 * Constant-time string comparison. Only ever used on fixed-length hex digests,
 * so the length check leaks nothing.
 */
export const timingSafeEqual = (left: string, right: string): boolean => {
  if (left.length !== right.length) {
    return false;
  }

  let difference = 0;

  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }

  return difference === 0;
};

export const readBearerToken = (header: string | null | undefined): string | null => {
  if (typeof header !== "string") {
    return null;
  }

  const separator = header.indexOf(" ");

  if (separator < 0 || header.slice(0, separator).toLowerCase() !== "bearer") {
    return null;
  }

  const token = header.slice(separator + 1).trim();

  return token.length > 0 && token.length <= MAX_TOKEN_LENGTH ? token : null;
};

/** `ckms_<name>_<random>` → `<name>`, or `null` if the shape is wrong. */
export const callerNameOfToken = (token: string): string | null => {
  if (!token.startsWith(TOKEN_PREFIX)) {
    return null;
  }

  const rest = token.slice(TOKEN_PREFIX.length);
  const separator = rest.indexOf("_");

  if (separator <= 0 || rest.length - separator - 1 < MIN_TOKEN_SECRET_LENGTH) {
    return null;
  }

  const name = rest.slice(0, separator);

  return callerNameSchema.safeParse(name).success ? name : null;
};

/**
 * Resolves the caller behind an `Authorization` header, or throws
 * `unauthorized`. Every configured caller is compared on every request — there
 * is no early exit — so the work done does not depend on which entry matched.
 */
export const authenticateCaller = async (
  callers: readonly Caller[],
  authorization: string | null | undefined,
): Promise<Caller> => {
  const token = readBearerToken(authorization);

  if (token === null) {
    throw unauthorized();
  }

  const presented = await sha256Hex(token);
  let matched: Caller | null = null;

  for (const caller of callers) {
    if (timingSafeEqual(caller.tokenHash, presented)) {
      matched = caller;
    }
  }

  if (matched === null || callerNameOfToken(token) !== matched.name) {
    throw unauthorized();
  }

  return matched;
};

/**
 * Caller scoping. Deployments are per-service already; this is defence in depth
 * against a config mistake pointing two services at one deployment.
 */
export const assertCallerContext = (caller: Caller, context: EncryptionContext): void => {
  if (!contextSatisfies(context, caller.requiredContext)) {
    throw unauthorized();
  }
};
