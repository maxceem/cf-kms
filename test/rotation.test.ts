import { describe, expect, it } from "vitest";
import { acmeCaller, acmeContext, testKeks } from "./constants";
import { createTestEnv, jsonOf, request, type TestEnv } from "./helpers";

/**
 * The rotation runbook, executed: add `KEK_V2` → bump `KEK_CURRENT_VERSION` →
 * consumers re-wrap → delete `KEK_V1`.
 */
interface DataKeyResponse {
  plaintextKey: string;
  wrappedKey: string;
  kekVersion: number;
}

const token = acmeCaller.token;

const beforeRotation = () =>
  createTestEnv({ keks: { KEK_V1: testKeks.v1 }, currentVersion: "1" });

const duringRotation = () =>
  createTestEnv({ keks: { KEK_V1: testKeks.v1, KEK_V2: testKeks.v2 }, currentVersion: "2" });

const afterRotation = () =>
  createTestEnv({ keks: { KEK_V2: testKeks.v2 }, currentVersion: "2" });

const generate = (env: TestEnv) =>
  request(env, "/v1/generate-data-key", {
    token,
    body: { encryptionContext: acmeContext },
  }).then(jsonOf<DataKeyResponse>);

const decrypt = (env: TestEnv, wrappedKey: string) =>
  request(env, "/v1/decrypt", {
    token,
    body: { wrappedKey, encryptionContext: acmeContext },
  });

const reWrap = (env: TestEnv, wrappedKey: string) =>
  request(env, "/v1/re-wrap", {
    token,
    body: { wrappedKey, encryptionContext: acmeContext },
  });

describe("KEK rotation", () => {
  it("wraps with the current version and unwraps with any present version", async () => {
    const old = await generate(await beforeRotation());

    expect(old.kekVersion).toBe(1);

    const rotating = await duringRotation();
    const fresh = await generate(rotating);

    expect(fresh.kekVersion).toBe(2);

    // Both windows still decrypt while both secrets are present.
    const stillWorks = await decrypt(rotating, old.wrappedKey);

    expect(stillWorks.status).toBe(200);
    await expect(jsonOf<DataKeyResponse>(stillWorks)).resolves.toMatchObject({
      plaintextKey: old.plaintextKey,
      kekVersion: 1,
    });
  });

  it("re-wraps an old token onto the current version without changing the data key", async () => {
    const old = await generate(await beforeRotation());
    const rotating = await duringRotation();

    const response = await reWrap(rotating, old.wrappedKey);
    const rewrapped = await jsonOf<DataKeyResponse>(response);

    expect(response.status).toBe(200);
    expect(rewrapped.kekVersion).toBe(2);
    expect(rewrapped.wrappedKey.startsWith("cfkms1.2.")).toBe(true);

    await expect(
      decrypt(rotating, rewrapped.wrappedKey).then(jsonOf<DataKeyResponse>),
    ).resolves.toMatchObject({ plaintextKey: old.plaintextKey, kekVersion: 2 });

    // And it survives retiring the old secret, which the original token does not.
    const retired = await afterRotation();

    await expect(
      decrypt(retired, rewrapped.wrappedKey).then(jsonOf<DataKeyResponse>),
    ).resolves.toMatchObject({ plaintextKey: old.plaintextKey });

    const orphaned = await decrypt(retired, old.wrappedKey);

    expect(orphaned.status).toBe(400);
    await expect(jsonOf(orphaned)).resolves.toStrictEqual({
      error: { code: "decrypt_failed" },
    });
  });

  it("re-wraps a token that is already current onto a new ciphertext", async () => {
    const rotating = await duringRotation();
    const issued = await generate(rotating);
    const rewrapped = await reWrap(rotating, issued.wrappedKey).then(jsonOf<DataKeyResponse>);

    expect(rewrapped.kekVersion).toBe(2);
    expect(rewrapped.wrappedKey).not.toBe(issued.wrappedKey);

    await expect(
      decrypt(rotating, rewrapped.wrappedKey).then(jsonOf<DataKeyResponse>),
    ).resolves.toMatchObject({ plaintextKey: issued.plaintextKey });
  });

  it("refuses to re-wrap a token whose KEK version has been retired", async () => {
    const old = await generate(await beforeRotation());
    const retired = await afterRotation();
    const response = await reWrap(retired, old.wrappedKey);

    expect(response.status).toBe(400);
    await expect(jsonOf(response)).resolves.toStrictEqual({
      error: { code: "decrypt_failed" },
    });
  });

  it("keeps the encryption context binding across a re-wrap", async () => {
    const rotating = await duringRotation();
    const issued = await generate(rotating);
    const rewrapped = await reWrap(rotating, issued.wrappedKey).then(jsonOf<DataKeyResponse>);

    const wrongContext = await request(rotating, "/v1/decrypt", {
      token,
      body: {
        wrappedKey: rewrapped.wrappedKey,
        encryptionContext: { ...acmeContext, tenantId: "org_999" },
      },
    });

    expect(wrongContext.status).toBe(400);
  });
});
