import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import {
  canonicalizeContext as clientCanonicalizeContext,
  createKmsClient,
  ENVELOPE_PREFIX,
  KmsClientError,
  type KmsClientOptions,
  type KmsFetch,
} from "../src/client";
import { canonicalizeContext as workerCanonicalizeContext } from "../src/crypto/context";
import { acmeCaller, acmeContext, unknownCallerToken } from "./constants";
import { tamper, testOrigin } from "./helpers";

/**
 * Integration tests: the client talks to the real worker over HTTP through
 * `SELF`, with the bindings declared in `vitest.config.ts`.
 */
const counted = (): { fetch: KmsFetch; calls: () => number } => {
  let calls = 0;

  return {
    fetch: (input, init) => {
      calls += 1;

      return SELF.fetch(input, init);
    },
    calls: () => calls,
  };
};

const client = (options?: Partial<KmsClientOptions>) => {
  const transport = counted();
  const kms = createKmsClient({
    url: testOrigin,
    token: acmeCaller.token,
    fetch: transport.fetch,
    ...options,
  });

  return { kms, calls: transport.calls };
};

describe("transport safety", () => {
  it("refuses a plaintext-HTTP base URL", () => {
    for (const url of [
      "http://kms-acme.example.com",
      "http://localhost.example.com",
      "http://127.0.0.1.example.com/v1",
      "ws://kms.example.com",
      "kms-acme.example.com",
      "",
    ]) {
      expect(() => createKmsClient({ url, token: acmeCaller.token })).toThrow(KmsClientError);
      expect(() => createKmsClient({ url, token: acmeCaller.token })).toThrow(
        /insecure_url/,
      );
    }
  });

  it("allows https and loopback development URLs", () => {
    for (const url of [
      "https://kms-acme.example.com",
      "HTTPS://kms-acme.example.com/",
      "http://localhost:8787",
      "http://localhost",
      "http://127.0.0.1:8787/",
    ]) {
      expect(() => createKmsClient({ url, token: acmeCaller.token })).not.toThrow();
    }
  });
});

describe("canonicalization parity", () => {
  it.each([
    {},
    { a: "1" },
    { b: "2", a: "1" },
    { a: "1", A: "2" },
    { k: 'ü"€\n' },
    { service: "acme", tenantId: "org_1", purpose: "provider-key" },
  ])("matches the worker for %j", (context) => {
    expect(clientCanonicalizeContext(context)).toBe(workerCanonicalizeContext(context));
  });
});

describe("low-level API", () => {
  it("generates, decrypts and re-wraps", async () => {
    const { kms } = client();
    const issued = await kms.generateDataKey({ encryptionContext: acmeContext });

    expect(issued.kekVersion).toBe(2);
    expect(issued.wrappedKey.startsWith("cfkms1.2.")).toBe(true);

    await expect(
      kms.decrypt({ wrappedKey: issued.wrappedKey, encryptionContext: acmeContext }),
    ).resolves.toMatchObject({ plaintextKey: issued.plaintextKey, kekVersion: 2 });

    const rewrapped = await kms.reWrap({
      wrappedKey: issued.wrappedKey,
      encryptionContext: acmeContext,
    });

    expect(rewrapped.wrappedKey).not.toBe(issued.wrappedKey);
    await expect(
      kms.decrypt({ wrappedKey: rewrapped.wrappedKey, encryptionContext: acmeContext }),
    ).resolves.toMatchObject({ plaintextKey: issued.plaintextKey });
  });

  it("surfaces server error codes", async () => {
    const { kms } = client({ token: unknownCallerToken });

    await expect(
      kms.generateDataKey({ encryptionContext: acmeContext }),
    ).rejects.toMatchObject({ code: "unauthorized", status: 401 });

    const authorized = client().kms;

    await expect(
      authorized.decrypt({ wrappedKey: "nonsense", encryptionContext: acmeContext }),
    ).rejects.toMatchObject({ code: "decrypt_failed", status: 400 });

    await expect(
      authorized.generateDataKey({ encryptionContext: { service: "widgets" } }),
    ).rejects.toBeInstanceOf(KmsClientError);
  });
});

describe("envelope helpers", () => {
  it("round-trips a secret", async () => {
    const { kms } = client();
    const plaintext = "sk-live-üñïçôdé-🔐-0123456789";
    const blob = await kms.encryptSecret(plaintext, acmeContext);

    expect(blob.startsWith(`${ENVELOPE_PREFIX}.`)).toBe(true);
    // prefix + 4 wrapped-key segments + iv + ciphertext.
    expect(blob.split(".")).toHaveLength(7);
    expect(blob).not.toContain(plaintext);

    await expect(kms.decryptSecret(blob, acmeContext)).resolves.toBe(plaintext);
  });

  it("produces a different blob every time", async () => {
    const { kms } = client();
    const first = await kms.encryptSecret("same", acmeContext);
    const second = await kms.encryptSecret("same", acmeContext);

    expect(first).not.toBe(second);
    await expect(kms.decryptSecret(second, acmeContext)).resolves.toBe("same");
  });

  it("fails when the context does not match", async () => {
    const { kms } = client();
    const blob = await kms.encryptSecret("secret", acmeContext);

    await expect(
      kms.decryptSecret(blob, { ...acmeContext, tenantId: "org_999" }),
    ).rejects.toMatchObject({ code: "decrypt_failed" });
  });

  it("fails when the payload has been tampered with", async () => {
    const { kms } = client();
    const blob = await kms.encryptSecret("secret", acmeContext);

    await expect(kms.decryptSecret(tamper(blob), acmeContext)).rejects.toMatchObject({
      code: "decrypt_failed",
    });
  });

  it("rejects a malformed envelope without calling the server", async () => {
    const { kms, calls } = client();

    for (const blob of ["", "nope", "cfkms-env1.a.b", "cfkms-env2.cfkms1.2.aa.bb.cc.dd"]) {
      await expect(kms.decryptSecret(blob, acmeContext)).rejects.toBeInstanceOf(
        KmsClientError,
      );
    }

    expect(calls()).toBe(0);
  });

  it("survives a re-wrap of the envelope's data key", async () => {
    const { kms } = client();
    const blob = await kms.encryptSecret("rotate me", acmeContext);
    const parts = blob.split(".");
    const wrappedKey = parts.slice(1, parts.length - 2).join(".");

    const rewrapped = await kms.reWrap({ wrappedKey, encryptionContext: acmeContext });
    const rotated = [
      ENVELOPE_PREFIX,
      rewrapped.wrappedKey,
      parts[parts.length - 2],
      parts[parts.length - 1],
    ].join(".");

    await expect(kms.decryptSecret(rotated, acmeContext)).resolves.toBe("rotate me");
  });
});

describe("data key cache", () => {
  it("is off by default", async () => {
    const { kms, calls } = client();
    const blob = await kms.encryptSecret("secret", acmeContext);
    const before = calls();

    await kms.decryptSecret(blob, acmeContext);
    await kms.decryptSecret(blob, acmeContext);

    expect(calls() - before).toBe(2);
  });

  it("reuses a data key within the ttl", async () => {
    let clock = 1_000;
    const { kms, calls } = client({ cacheTtlMs: 60_000, now: () => clock });
    const blob = await kms.encryptSecret("secret", acmeContext);
    const before = calls();

    // encryptSecret primed the cache, so neither read hits the network.
    await expect(kms.decryptSecret(blob, acmeContext)).resolves.toBe("secret");
    await expect(kms.decryptSecret(blob, acmeContext)).resolves.toBe("secret");
    expect(calls() - before).toBe(0);

    clock += 60_001;
    await expect(kms.decryptSecret(blob, acmeContext)).resolves.toBe("secret");
    expect(calls() - before).toBe(1);
  });

  it("does not share entries across encryption contexts", async () => {
    const { kms } = client({ cacheTtlMs: 60_000 });
    const blob = await kms.encryptSecret("secret", acmeContext);

    await expect(
      kms.decryptSecret(blob, { ...acmeContext, tenantId: "org_999" }),
    ).rejects.toMatchObject({ code: "decrypt_failed" });
  });

  it("can be cleared", async () => {
    const { kms, calls } = client({ cacheTtlMs: 60_000 });
    const blob = await kms.encryptSecret("secret", acmeContext);
    const before = calls();

    kms.clearCache();
    await kms.decryptSecret(blob, acmeContext);

    expect(calls() - before).toBe(1);
  });
});
