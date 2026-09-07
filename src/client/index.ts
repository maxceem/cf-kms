/**
 * `@maxceem/cf-kms/client` — typed client for a cf-kms deployment.
 *
 * Zero runtime dependencies; needs only `fetch` and WebCrypto, so it runs
 * unchanged on Cloudflare Workers and Node >= 20.
 *
 * The high-level helpers implement the envelope pattern so consumers never
 * hand-roll it: `encryptSecret` asks cf-kms for a fresh data key, encrypts the
 * payload locally with it, and returns one storable string. The plaintext data
 * key exists only in the consumer's isolate memory, never at rest.
 */

/** String → string metadata bound into both crypto layers as AAD. */
export interface EncryptionContext {
  readonly [key: string]: string;
}

export type KmsFetch = (input: string, init?: RequestInit) => Promise<Response>;

export interface KmsClientOptions {
  /**
   * Base URL of the deployment, e.g. `https://kms-acme.example.com`.
   * Must be `https://`; plain `http://` is refused except on loopback.
   */
  url: string;
  /** The caller's bearer token (`ckms_<name>_<random>`). */
  token: string;
  /**
   * How long an unwrapped data key may be reused from isolate memory, keyed by
   * `wrappedKey` + encryption context. `0` (the default) disables the cache, so
   * every `decryptSecret` is one audited cf-kms call.
   */
  cacheTtlMs?: number;
  /** Injection point for tests and service bindings. Defaults to global fetch. */
  fetch?: KmsFetch;
  /** Injection point for tests. Defaults to `Date.now`. */
  now?: () => number;
}

export interface GenerateDataKeyResult {
  /** base64url, 32 bytes. Use once, then drop it. */
  plaintextKey: string;
  wrappedKey: string;
  kekVersion: number;
}

export interface DecryptResult {
  plaintextKey: string;
  kekVersion: number;
}

export interface ReWrapResult {
  wrappedKey: string;
  kekVersion: number;
}

export interface KmsClient {
  generateDataKey(input: { encryptionContext: EncryptionContext }): Promise<GenerateDataKeyResult>;
  decrypt(input: {
    wrappedKey: string;
    encryptionContext: EncryptionContext;
  }): Promise<DecryptResult>;
  reWrap(input: { wrappedKey: string; encryptionContext: EncryptionContext }): Promise<ReWrapResult>;
  /** Envelope-encrypts `plaintext` into a single storable string. */
  encryptSecret(plaintext: string, encryptionContext: EncryptionContext): Promise<string>;
  /** Inverse of {@link KmsClient.encryptSecret}. */
  decryptSecret(blob: string, encryptionContext: EncryptionContext): Promise<string>;
  /** Drops every cached data key. Call on caller-token rotation. */
  clearCache(): void;
}

export class KmsClientError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(code: string, status: number) {
    super(`cf-kms: ${code}`);
    this.name = `KmsClientError:${code}`;
    this.code = code;
    this.status = status;
  }
}

/** Envelope wire format: `cfkms-env1.<wrappedKey>.<b64url iv>.<b64url ct+tag>`. */
export const ENVELOPE_PREFIX = "cfkms-env1";

const IV_BYTE_LENGTH = 12;
const MAX_CACHE_ENTRIES = 512;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]*$/;

const encodeBase64Url = (bytes: Uint8Array): string => {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

const decodeBase64Url = (value: string): Uint8Array => {
  if (!BASE64URL_PATTERN.test(value)) {
    throw new KmsClientError("invalid_envelope", 0);
  }

  const padded = value
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(value.length + ((4 - (value.length % 4)) % 4), "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes;
};

/**
 * Must match `src/crypto/context.ts` byte for byte: keys sorted by UTF-16 code
 * unit, then `JSON.stringify`. Duplicated rather than imported to keep this
 * module dependency-free; `test/client.test.ts` pins the two together.
 */
export const canonicalizeContext = (context: EncryptionContext): string => {
  const entries = Object.entries(context).sort(([left], [right]) =>
    left < right ? -1 : left > right ? 1 : 0,
  );

  return JSON.stringify(Object.fromEntries(entries));
};

const contextAad = (context: EncryptionContext): Uint8Array =>
  new TextEncoder().encode(canonicalizeContext(context));

const importDataKey = (bytes: Uint8Array): Promise<CryptoKey> =>
  crypto.subtle.importKey("raw", bytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);

/**
 * The bearer token goes out on every call, so plaintext HTTP is refused: a typo
 * in `KMS_URL` must not silently become a credential leak. Loopback is allowed
 * so `wrangler dev` against a local cf-kms still works.
 */
const assertSecureUrl = (url: string): void => {
  if (/^https:\/\//i.test(url)) {
    return;
  }

  if (/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?(\/|$)/i.test(url)) {
    return;
  }

  throw new KmsClientError("insecure_url", 0);
};

interface CacheEntry {
  key: CryptoKey;
  expiresAt: number;
}

export const createKmsClient = (options: KmsClientOptions): KmsClient => {
  assertSecureUrl(options.url);

  const baseUrl = options.url.replace(/\/+$/, "");
  const cacheTtlMs = options.cacheTtlMs ?? 0;
  const doFetch: KmsFetch = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
  const now = options.now ?? (() => Date.now());
  const cache = new Map<string, CacheEntry>();

  const call = async <T>(path: string, body: unknown, expected: readonly string[]): Promise<T> => {
    const response = await doFetch(`${baseUrl}${path}`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${options.token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(body),
    });

    let payload: unknown;

    try {
      payload = await response.json();
    } catch {
      throw new KmsClientError("invalid_response", response.status);
    }

    if (!response.ok) {
      const code = (payload as { error?: { code?: unknown } } | null)?.error?.code;

      throw new KmsClientError(typeof code === "string" ? code : "request_failed", response.status);
    }

    const record = payload as Record<string, unknown> | null;

    if (
      record === null ||
      typeof record !== "object" ||
      expected.some((field) => typeof record[field] !== "string") ||
      typeof record.kekVersion !== "number"
    ) {
      throw new KmsClientError("invalid_response", response.status);
    }

    return record as T;
  };

  const cacheKeyFor = (wrappedKey: string, context: EncryptionContext): string =>
    `${wrappedKey}\x00${canonicalizeContext(context)}`;

  const readCache = (cacheKey: string): CryptoKey | null => {
    if (cacheTtlMs <= 0) {
      return null;
    }

    const entry = cache.get(cacheKey);

    if (!entry) {
      return null;
    }

    if (entry.expiresAt <= now()) {
      cache.delete(cacheKey);

      return null;
    }

    return entry.key;
  };

  const writeCache = (cacheKey: string, key: CryptoKey): void => {
    if (cacheTtlMs <= 0) {
      return;
    }

    if (cache.size >= MAX_CACHE_ENTRIES) {
      const oldest = cache.keys().next();

      if (!oldest.done) {
        cache.delete(oldest.value);
      }
    }

    cache.set(cacheKey, { key, expiresAt: now() + cacheTtlMs });
  };

  const generateDataKey: KmsClient["generateDataKey"] = (input) =>
    call<GenerateDataKeyResult>("/v1/generate-data-key", input, ["plaintextKey", "wrappedKey"]);

  const decrypt: KmsClient["decrypt"] = (input) =>
    call<DecryptResult>("/v1/decrypt", input, ["plaintextKey"]);

  const reWrap: KmsClient["reWrap"] = (input) =>
    call<ReWrapResult>("/v1/re-wrap", input, ["wrappedKey"]);

  const dataKeyFor = async (
    wrappedKey: string,
    encryptionContext: EncryptionContext,
  ): Promise<CryptoKey> => {
    const cacheKey = cacheKeyFor(wrappedKey, encryptionContext);
    const cached = readCache(cacheKey);

    if (cached) {
      return cached;
    }

    const { plaintextKey } = await decrypt({ wrappedKey, encryptionContext });
    const key = await importDataKey(decodeBase64Url(plaintextKey));
    writeCache(cacheKey, key);

    return key;
  };

  const encryptSecret: KmsClient["encryptSecret"] = async (plaintext, encryptionContext) => {
    const { plaintextKey, wrappedKey } = await generateDataKey({ encryptionContext });
    const key = await importDataKey(decodeBase64Url(plaintextKey));
    const iv = crypto.getRandomValues(new Uint8Array(IV_BYTE_LENGTH));
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: contextAad(encryptionContext) },
        key,
        new TextEncoder().encode(plaintext),
      ),
    );

    writeCache(cacheKeyFor(wrappedKey, encryptionContext), key);

    return `${ENVELOPE_PREFIX}.${wrappedKey}.${encodeBase64Url(iv)}.${encodeBase64Url(ciphertext)}`;
  };

  const decryptSecret: KmsClient["decryptSecret"] = async (blob, encryptionContext) => {
    const parts = blob.split(".");

    // The wrapped key contains dots of its own, so it is everything between the
    // envelope prefix and the trailing iv / ciphertext pair.
    if (parts.length < 4 || parts[0] !== ENVELOPE_PREFIX) {
      throw new KmsClientError("invalid_envelope", 0);
    }

    const ciphertextPart = parts[parts.length - 1];
    const ivPart = parts[parts.length - 2];
    const wrappedKey = parts.slice(1, parts.length - 2).join(".");

    if (ivPart === undefined || ciphertextPart === undefined || wrappedKey === "") {
      throw new KmsClientError("invalid_envelope", 0);
    }

    const iv = decodeBase64Url(ivPart);
    const ciphertext = decodeBase64Url(ciphertextPart);

    if (iv.length !== IV_BYTE_LENGTH) {
      throw new KmsClientError("invalid_envelope", 0);
    }

    const key = await dataKeyFor(wrappedKey, encryptionContext);
    let payload: ArrayBuffer;

    try {
      payload = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv, additionalData: contextAad(encryptionContext) },
        key,
        ciphertext,
      );
    } catch {
      throw new KmsClientError("decrypt_failed", 0);
    }

    return new TextDecoder().decode(payload);
  };

  return {
    generateDataKey,
    decrypt,
    reWrap,
    encryptSecret,
    decryptSecret,
    clearCache: () => cache.clear(),
  };
};
