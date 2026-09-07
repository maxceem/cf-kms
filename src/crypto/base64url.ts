/**
 * Unpadded base64url, the only binary encoding used on the wire.
 *
 * Kept dependency-free and mirrored (deliberately duplicated) in
 * `src/client/index.ts`, which must stay dependency-free too.
 */
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]*$/;

export const encodeBase64Url = (bytes: Uint8Array): string => {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
};

/** Throws on any character outside the base64url alphabet. */
export const decodeBase64Url = (value: string): Uint8Array => {
  if (!BASE64URL_PATTERN.test(value)) {
    throw new Error("not base64url");
  }

  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(
    value.length + ((4 - (value.length % 4)) % 4),
    "=",
  );
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes;
};
