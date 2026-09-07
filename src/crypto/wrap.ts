import { decryptFailed } from "../errors";
import { decodeBase64Url, encodeBase64Url } from "./base64url";
import { encodeContextAad, type EncryptionContext } from "./context";
import type { KekRegistry } from "./kek";

/**
 * DEK wrapping.
 *
 * AES-256-GCM with the canonical encryption context as AAD. AES-KW is not used
 * because it cannot bind additional authenticated data, and the context binding
 * is the whole point.
 */

/** Wire-format version of the token itself, independent of the KEK version. */
export const TOKEN_PREFIX = "cfkms1";
export const DEK_BYTE_LENGTH = 32;
export const IV_BYTE_LENGTH = 12;
const GCM_TAG_BYTE_LENGTH = 16;
const WRAPPED_CIPHERTEXT_BYTE_LENGTH = DEK_BYTE_LENGTH + GCM_TAG_BYTE_LENGTH;

/** Generous upper bound on `cfkms1.<v>.<b64url 12B>.<b64url 48B>`. */
export const MAX_WRAPPED_KEY_LENGTH = 256;

export const generateDek = (): Uint8Array =>
  crypto.getRandomValues(new Uint8Array(DEK_BYTE_LENGTH));

export interface WrappedKey {
  wrappedKey: string;
  kekVersion: number;
}

export const wrapDek = async (
  keks: KekRegistry,
  dek: Uint8Array,
  context: EncryptionContext,
): Promise<WrappedKey> => {
  const kekVersion = keks.currentVersion;
  const key = await keks.key(kekVersion);
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTE_LENGTH));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: encodeContextAad(context) },
      key,
      dek,
    ),
  );

  return {
    wrappedKey: `${TOKEN_PREFIX}.${kekVersion}.${encodeBase64Url(iv)}.${encodeBase64Url(ciphertext)}`,
    kekVersion,
  };
};

interface DecodedToken {
  kekVersion: number;
  iv: Uint8Array;
  ciphertext: Uint8Array;
}

/** Every rejection path throws the same opaque error as a failed GCM open. */
const decodeToken = (wrappedKey: string): DecodedToken => {
  if (wrappedKey.length > MAX_WRAPPED_KEY_LENGTH) {
    throw decryptFailed();
  }

  const parts = wrappedKey.split(".");

  if (parts.length !== 4 || parts[0] !== TOKEN_PREFIX) {
    throw decryptFailed();
  }

  const [, version, ivPart, ciphertextPart] = parts;

  if (
    version === undefined ||
    ivPart === undefined ||
    ciphertextPart === undefined ||
    !/^[1-9][0-9]{0,3}$/.test(version)
  ) {
    throw decryptFailed();
  }

  let iv: Uint8Array;
  let ciphertext: Uint8Array;

  try {
    iv = decodeBase64Url(ivPart);
    ciphertext = decodeBase64Url(ciphertextPart);
  } catch {
    throw decryptFailed();
  }

  if (iv.length !== IV_BYTE_LENGTH || ciphertext.length !== WRAPPED_CIPHERTEXT_BYTE_LENGTH) {
    throw decryptFailed();
  }

  return { kekVersion: Number(version), iv, ciphertext };
};

export interface UnwrappedDek {
  dek: Uint8Array;
  kekVersion: number;
}

/**
 * Unwraps a token. Malformed token, tampered ciphertext, mismatched context and
 * unknown/retired KEK version all fail the same way — the context is AAD, so a
 * context mismatch *is* a GCM authentication failure.
 */
export const unwrapDek = async (
  keks: KekRegistry,
  wrappedKey: string,
  context: EncryptionContext,
): Promise<UnwrappedDek> => {
  const token = decodeToken(wrappedKey);

  if (!keks.has(token.kekVersion)) {
    throw decryptFailed();
  }

  const key = await keks.key(token.kekVersion);
  let plaintext: ArrayBuffer;

  try {
    plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: token.iv, additionalData: encodeContextAad(context) },
      key,
      token.ciphertext,
    );
  } catch {
    throw decryptFailed();
  }

  if (plaintext.byteLength !== DEK_BYTE_LENGTH) {
    throw decryptFailed();
  }

  return { dek: new Uint8Array(plaintext), kekVersion: token.kekVersion };
};

/** Reads the KEK version off a token without unwrapping it. */
export const kekVersionOf = (wrappedKey: string): number => decodeToken(wrappedKey).kekVersion;
