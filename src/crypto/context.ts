import { z } from "zod";

/**
 * Encryption context — the AAD every wrap is bound to.
 *
 * The canonical form is part of the wire contract: a ciphertext produced with
 * one canonicalization can only ever be opened with the same one. Changing
 * anything in this file breaks every stored `wrappedKey`.
 */
export const MAX_CONTEXT_ENTRIES = 8;
export const MAX_CONTEXT_KEY_LENGTH = 64;
export const MAX_CONTEXT_VALUE_LENGTH = 256;

const contextKeySchema = z
  .string()
  .min(1)
  .max(MAX_CONTEXT_KEY_LENGTH)
  // Conservative alphabet: keeps keys JSON-plain and rules out `__proto__`.
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/);

const contextValueSchema = z.string().max(MAX_CONTEXT_VALUE_LENGTH);

export const encryptionContextSchema = z
  .record(contextKeySchema, contextValueSchema)
  .refine((context) => Object.keys(context).length <= MAX_CONTEXT_ENTRIES);

export type EncryptionContext = Record<string, string>;

/**
 * Canonical serialization: keys sorted lexicographically by UTF-16 code unit
 * (the default `Array#sort` order), then `JSON.stringify`d. `JSON.stringify`
 * of a string→string object is fully specified — quoting, escaping and
 * lone-surrogate handling included — so this is stable across runtimes.
 *
 * Golden vectors live in `test/crypto.test.ts`.
 */
export const canonicalizeContext = (context: EncryptionContext): string => {
  const sorted = Object.entries(context).sort(([left], [right]) =>
    left < right ? -1 : left > right ? 1 : 0,
  );

  return JSON.stringify(Object.fromEntries(sorted));
};

/** UTF-8 bytes of {@link canonicalizeContext}, used as AES-GCM `additionalData`. */
export const encodeContextAad = (context: EncryptionContext): Uint8Array =>
  new TextEncoder().encode(canonicalizeContext(context));

/** True when every entry of `required` is present in `context` with the same value. */
export const contextSatisfies = (
  context: EncryptionContext,
  required: EncryptionContext,
): boolean => Object.entries(required).every(([key, value]) => context[key] === value);
