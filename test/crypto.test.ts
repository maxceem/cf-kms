import { describe, expect, it } from "vitest";
import { decodeBase64Url, encodeBase64Url } from "../src/crypto/base64url";
import {
  canonicalizeContext,
  encodeContextAad,
  encryptionContextSchema,
  MAX_CONTEXT_ENTRIES,
  MAX_CONTEXT_VALUE_LENGTH,
} from "../src/crypto/context";
import { createKekRegistry } from "../src/crypto/kek";
import {
  DEK_BYTE_LENGTH,
  generateDek,
  kekVersionOf,
  TOKEN_PREFIX,
  unwrapDek,
  wrapDek,
} from "../src/crypto/wrap";
import { isKmsError } from "../src/errors";
import { testKeks } from "./constants";
import { tamper } from "./helpers";

const registry = (keks: Record<string, string>, current: string) =>
  createKekRegistry({ ...keks, KEK_CURRENT_VERSION: current });

const bothKeks = { KEK_V1: testKeks.v1, KEK_V2: testKeks.v2 };

const context = { service: "acme", tenantId: "org_123" };

const expectDecryptFailed = async (promise: Promise<unknown>) => {
  await expect(promise).rejects.toSatisfy(
    (error: unknown) => isKmsError(error) && error.code === "decrypt_failed",
  );
};

describe("canonicalizeContext", () => {
  // Golden vectors. These are wire format: changing any of them invalidates
  // every wrapped key that has ever been issued.
  it.each([
    [{}, "{}"],
    [{ a: "1" }, '{"a":"1"}'],
    [{ b: "2", a: "1" }, '{"a":"1","b":"2"}'],
    [{ a: "1", b: "2" }, '{"a":"1","b":"2"}'],
    // Sorted by UTF-16 code unit, so uppercase sorts before lowercase.
    [{ a: "1", A: "2" }, '{"A":"2","a":"1"}'],
    // "-" (0x2D) sorts before "." (0x2E) and ":" (0x3A).
    [{ "a.b": "1", "a-b": "2", "a:b": "3" }, '{"a-b":"2","a.b":"1","a:b":"3"}'],
    [{ k: "ü€" }, '{"k":"ü€"}'],
    [{ k: 'a"b\\c\nd' }, '{"k":"a\\"b\\\\c\\nd"}'],
    [{ k: "" }, '{"k":""}'],
  ])("canonicalizes %j", (input, expected) => {
    expect(canonicalizeContext(input)).toBe(expected);
  });

  it("is insensitive to key insertion order", () => {
    const forwards = { service: "acme", tenantId: "org_1", purpose: "provider-key" };
    const backwards = { purpose: "provider-key", tenantId: "org_1", service: "acme" };

    expect(canonicalizeContext(forwards)).toBe(canonicalizeContext(backwards));
  });

  it("encodes the AAD as UTF-8 of the canonical form", () => {
    const aad = encodeContextAad({ k: "ü" });

    expect(new TextDecoder().decode(aad)).toBe('{"k":"ü"}');
    // "ü" is two bytes in UTF-8.
    expect(aad.length).toBe('{"k":"u"}'.length + 1);
  });
});

describe("encryptionContextSchema", () => {
  it("accepts a plain string map", () => {
    expect(encryptionContextSchema.safeParse(context).success).toBe(true);
    expect(encryptionContextSchema.safeParse({}).success).toBe(true);
  });

  it("rejects non-string values", () => {
    expect(encryptionContextSchema.safeParse({ a: 1 }).success).toBe(false);
    expect(encryptionContextSchema.safeParse({ a: null }).success).toBe(false);
    expect(encryptionContextSchema.safeParse({ a: { b: "c" } }).success).toBe(false);
    expect(encryptionContextSchema.safeParse({ a: ["b"] }).success).toBe(false);
  });

  it("rejects too many keys", () => {
    const tooMany = Object.fromEntries(
      Array.from({ length: MAX_CONTEXT_ENTRIES + 1 }, (_, index) => [`k${index}`, "v"]),
    );

    expect(encryptionContextSchema.safeParse(tooMany).success).toBe(false);
  });

  it("rejects oversized values", () => {
    expect(
      encryptionContextSchema.safeParse({ a: "x".repeat(MAX_CONTEXT_VALUE_LENGTH) }).success,
    ).toBe(true);
    expect(
      encryptionContextSchema.safeParse({ a: "x".repeat(MAX_CONTEXT_VALUE_LENGTH + 1) }).success,
    ).toBe(false);
  });

  it("rejects exotic keys", () => {
    expect(encryptionContextSchema.safeParse({ "": "v" }).success).toBe(false);
    // zod strips `__proto__` rather than rejecting it; either way it must never
    // reach the canonicalizer.
    const polluted = encryptionContextSchema.safeParse(Object.fromEntries([["__proto__", "v"]]));

    expect(polluted.success && Object.hasOwn(polluted.data, "__proto__")).toBe(false);
    expect(encryptionContextSchema.safeParse({ "a b": "v" }).success).toBe(false);
    expect(encryptionContextSchema.safeParse({ ["x".repeat(65)]: "v" }).success).toBe(false);
  });
});

describe("base64url", () => {
  it("round-trips arbitrary bytes without padding", () => {
    for (let length = 0; length < 40; length += 1) {
      const bytes = crypto.getRandomValues(new Uint8Array(length));
      const encoded = encodeBase64Url(bytes);

      expect(encoded).not.toContain("=");
      expect(encoded).not.toContain("+");
      expect(encoded).not.toContain("/");
      expect([...decodeBase64Url(encoded)]).toStrictEqual([...bytes]);
    }
  });

  it("rejects characters outside the alphabet", () => {
    expect(() => decodeBase64Url("aa=a")).toThrow();
    expect(() => decodeBase64Url("aa+a")).toThrow();
    expect(() => decodeBase64Url("aa/a")).toThrow();
  });
});

describe("KEK registry", () => {
  it("exposes every configured version and the current one", () => {
    const keks = registry(bothKeks, "1");

    expect(keks.currentVersion).toBe(1);
    expect(keks.versions).toStrictEqual([1, 2]);
    expect(keks.has(1)).toBe(true);
    expect(keks.has(3)).toBe(false);
  });

  it("imports keys as non-extractable AES-GCM keys", async () => {
    const key = await registry(bothKeks, "1").key(1);

    expect(key.extractable).toBe(false);
    expect(key.algorithm).toMatchObject({ name: "AES-GCM", length: 256 });
    await expect(crypto.subtle.exportKey("raw", key)).rejects.toThrow();
  });

  it("caches the imported key per isolate", async () => {
    const first = await registry(bothKeks, "1").key(1);
    const second = await registry(bothKeks, "2").key(1);

    expect(second).toBe(first);
  });

  it("fails fast on a missing KEK secret", () => {
    expect(() => registry({}, "1")).toThrow(/KEK_V<n>/);
  });

  it("fails fast when KEK_CURRENT_VERSION has no secret", () => {
    expect(() => registry({ KEK_V1: testKeks.v1 }, "2")).toThrow(/KEK_V2 is not set/);
  });

  it("fails fast on a malformed KEK_CURRENT_VERSION", () => {
    expect(() => registry(bothKeks, "0")).toThrow(/positive integer/);
    expect(() => registry(bothKeks, "one")).toThrow(/positive integer/);
    expect(() => createKekRegistry(bothKeks)).toThrow(/positive integer/);
  });

  it("fails fast on malformed KEK material", () => {
    expect(() => registry({ KEK_V1: "" }, "1")).toThrow(/non-empty base64/);
    expect(() => registry({ KEK_V1: "not base64!!" }, "1")).toThrow(/base64/);
    // 16 bytes, not 32.
    expect(() => registry({ KEK_V1: "AAAAAAAAAAAAAAAAAAAAAA==" }, "1")).toThrow(/32 bytes/);
    expect(() => createKekRegistry({ KEK_V1: 1, KEK_CURRENT_VERSION: "1" })).toThrow(/base64/);
  });

  it("rejects a non-object env", () => {
    expect(() => createKekRegistry(null)).toThrow(/env must be an object/);
  });

  it("refuses to silently ignore a misnamed KEK binding", () => {
    expect(() => registry({ KEK_V1: testKeks.v1, KEK_V0: testKeks.v2 }, "1")).toThrow(
      /KEK_V0 is not a valid KEK secret name/,
    );
    expect(() => registry({ KEK_V1: testKeks.v1, KEK_Vold: testKeks.v2 }, "1")).toThrow(
      /not a valid KEK secret name/,
    );
  });
});

describe("wrap / unwrap", () => {
  it("generates 32-byte data keys that differ every call", () => {
    const first = generateDek();
    const second = generateDek();

    expect(first.length).toBe(DEK_BYTE_LENGTH);
    expect(encodeBase64Url(first)).not.toBe(encodeBase64Url(second));
  });

  it("round-trips a data key under the current KEK", async () => {
    const keks = registry(bothKeks, "2");
    const dek = generateDek();
    const { wrappedKey, kekVersion } = await wrapDek(keks, dek, context);

    expect(kekVersion).toBe(2);
    expect(wrappedKey.split(".")[0]).toBe(TOKEN_PREFIX);
    expect(wrappedKey.split(".")[1]).toBe("2");
    expect(wrappedKey.split(".").length).toBe(4);

    const unwrapped = await unwrapDek(keks, wrappedKey, context);

    expect([...unwrapped.dek]).toStrictEqual([...dek]);
    expect(unwrapped.kekVersion).toBe(2);
  });

  it("uses a fresh IV per wrap", async () => {
    const keks = registry(bothKeks, "1");
    const dek = generateDek();
    const first = await wrapDek(keks, dek, context);
    const second = await wrapDek(keks, dek, context);

    expect(first.wrappedKey).not.toBe(second.wrappedKey);
    expect(first.wrappedKey.split(".")[2]).not.toBe(second.wrappedKey.split(".")[2]);
  });

  it("is insensitive to encryption-context key order", async () => {
    const keks = registry(bothKeks, "1");
    const dek = generateDek();
    const { wrappedKey } = await wrapDek(keks, dek, { a: "1", b: "2" });

    await expect(unwrapDek(keks, wrappedKey, { b: "2", a: "1" })).resolves.toMatchObject({
      kekVersion: 1,
    });
  });

  it("fails on a mismatched encryption context", async () => {
    const keks = registry(bothKeks, "1");
    const { wrappedKey } = await wrapDek(keks, generateDek(), context);

    await expectDecryptFailed(unwrapDek(keks, wrappedKey, { ...context, tenantId: "org_999" }));
    await expectDecryptFailed(unwrapDek(keks, wrappedKey, {}));
    await expectDecryptFailed(unwrapDek(keks, wrappedKey, { ...context, extra: "x" }));
  });

  it("fails on a tampered token", async () => {
    const keks = registry(bothKeks, "1");
    const { wrappedKey } = await wrapDek(keks, generateDek(), context);
    const parts = wrappedKey.split(".");

    await expectDecryptFailed(unwrapDek(keks, tamper(wrappedKey), context));
    // Tampered IV.
    await expectDecryptFailed(
      unwrapDek(keks, [parts[0], parts[1], tamper(parts[2] ?? ""), parts[3]].join("."), context),
    );
  });

  it("fails on a malformed token", async () => {
    const keks = registry(bothKeks, "1");
    const { wrappedKey } = await wrapDek(keks, generateDek(), context);
    const parts = wrappedKey.split(".");

    for (const malformed of [
      "",
      "nonsense",
      wrappedKey.replace(TOKEN_PREFIX, "cfkms2"),
      parts.slice(0, 3).join("."),
      `${wrappedKey}.extra`,
      [parts[0], "0", parts[2], parts[3]].join("."),
      [parts[0], "x", parts[2], parts[3]].join("."),
      // IV too short, ciphertext padded with "=".
      [parts[0], parts[1], "AAAA", parts[3]].join("."),
      [parts[0], parts[1], parts[2], `${parts[3]}==`].join("."),
      `${TOKEN_PREFIX}.1.${"A".repeat(400)}.${"A".repeat(400)}`,
    ]) {
      await expectDecryptFailed(unwrapDek(keks, malformed, context));
    }
  });

  it("fails on an unknown or retired KEK version", async () => {
    const full = registry(bothKeks, "2");
    const { wrappedKey } = await wrapDek(full, generateDek(), context);

    expect(kekVersionOf(wrappedKey)).toBe(2);

    // v2 secret has been deleted: the old wrap is now undecryptable.
    const retired = registry({ KEK_V1: testKeks.v1 }, "1");

    await expectDecryptFailed(unwrapDek(retired, wrappedKey, context));
    await expectDecryptFailed(
      unwrapDek(full, wrappedKey.replace(`${TOKEN_PREFIX}.2.`, `${TOKEN_PREFIX}.9.`), context),
    );
  });

  it("fails when the KEK material is different", async () => {
    const mine = registry({ KEK_V1: testKeks.v1 }, "1");
    const theirs = registry({ KEK_V1: testKeks.v3 }, "1");
    const { wrappedKey } = await wrapDek(mine, generateDek(), context);

    await expectDecryptFailed(unwrapDek(theirs, wrappedKey, context));
  });
});
