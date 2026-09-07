import { beforeAll, describe, expect, it } from "vitest";
import { decodeBase64Url } from "../src/crypto/base64url";
import { DEK_BYTE_LENGTH } from "../src/crypto/wrap";
import { acmeCaller, acmeContext, widgetsCaller, testKeks } from "./constants";
import { createTestEnv, jsonOf, request, tamper, type TestEnv } from "./helpers";

interface DataKeyResponse {
  plaintextKey: string;
  wrappedKey: string;
  kekVersion: number;
}

let env: TestEnv;

const token = acmeCaller.token;

const generate = async (context: Record<string, string> = acmeContext) => {
  const response = await request(env, "/v1/generate-data-key", {
    token,
    body: { encryptionContext: context },
  });

  expect(response.status).toBe(200);

  return jsonOf<DataKeyResponse>(response);
};

beforeAll(async () => {
  env = await createTestEnv();
});

describe("GET /v1/health", () => {
  it("answers unauthenticated with nothing but ok", async () => {
    const response = await request(env, "/v1/health");
    const body = await jsonOf<Record<string, unknown>>(response);

    expect(response.status).toBe(200);
    expect(body).toStrictEqual({ ok: true });
    expect(Object.keys(body)).toStrictEqual(["ok"]);
  });

  it("leaks no configuration even when the deployment is misconfigured", async () => {
    const broken = await request({ CALLERS: "[]" }, "/v1/health");

    expect(broken.status).toBe(200);
    await expect(jsonOf(broken)).resolves.toStrictEqual({ ok: true });
  });
});

describe("POST /v1/generate-data-key", () => {
  it("returns a fresh 32-byte data key and its wrapped form", async () => {
    const body = await generate();

    expect(decodeBase64Url(body.plaintextKey).length).toBe(DEK_BYTE_LENGTH);
    expect(body.kekVersion).toBe(2);
    expect(body.wrappedKey).toMatch(/^cfkms1\.2\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    expect(Object.keys(body).sort()).toStrictEqual([
      "kekVersion",
      "plaintextKey",
      "wrappedKey",
    ]);

    const second = await generate();

    expect(second.plaintextKey).not.toBe(body.plaintextKey);
  });

  it("accepts an empty encryption context from an unscoped caller", async () => {
    const response = await request(env, "/v1/generate-data-key", {
      token: widgetsCaller.token,
      body: { encryptionContext: {} },
    });

    expect(response.status).toBe(200);
  });
});

describe("POST /v1/decrypt", () => {
  it("returns the same data key for the same context", async () => {
    const issued = await generate();
    const response = await request(env, "/v1/decrypt", {
      token,
      body: { wrappedKey: issued.wrappedKey, encryptionContext: acmeContext },
    });
    const body = await jsonOf<DataKeyResponse>(response);

    expect(response.status).toBe(200);
    expect(body.plaintextKey).toBe(issued.plaintextKey);
    expect(body.kekVersion).toBe(2);
    expect(Object.keys(body).sort()).toStrictEqual(["kekVersion", "plaintextKey"]);
  });

  it("ignores encryption-context key order", async () => {
    const issued = await generate({ service: "acme", tenantId: "org_1" });
    const response = await request(env, "/v1/decrypt", {
      token,
      body: {
        wrappedKey: issued.wrappedKey,
        encryptionContext: { tenantId: "org_1", service: "acme" },
      },
    });

    await expect(jsonOf<DataKeyResponse>(response)).resolves.toMatchObject({
      plaintextKey: issued.plaintextKey,
    });
  });

  it("fails identically for every kind of bad token", async () => {
    const issued = await generate();
    const foreign = await createTestEnv({ keks: { KEK_V2: testKeks.v3 } });
    const foreignIssued = await request(foreign, "/v1/generate-data-key", {
      token,
      body: { encryptionContext: acmeContext },
    }).then(jsonOf<DataKeyResponse>);

    const attempts = [
      // Tampered ciphertext.
      { wrappedKey: tamper(issued.wrappedKey), encryptionContext: acmeContext },
      // Mismatched encryption context.
      {
        wrappedKey: issued.wrappedKey,
        encryptionContext: { ...acmeContext, tenantId: "org_999" },
      },
      // Unknown / retired KEK version.
      {
        wrappedKey: issued.wrappedKey.replace("cfkms1.2.", "cfkms1.9."),
        encryptionContext: acmeContext,
      },
      // Right shape, wrong KEK material.
      { wrappedKey: foreignIssued.wrappedKey, encryptionContext: acmeContext },
      // Not a token at all.
      { wrappedKey: "nonsense", encryptionContext: acmeContext },
      { wrappedKey: "cfkms1.2.AAAA.AAAA", encryptionContext: acmeContext },
    ];

    const results = await Promise.all(
      attempts.map(async (body) => {
        const response = await request(env, "/v1/decrypt", { token, body });

        return { status: response.status, body: await response.text() };
      }),
    );

    for (const result of results) {
      expect(result).toStrictEqual({
        status: 400,
        body: JSON.stringify({ error: { code: "decrypt_failed" } }),
      });
    }
  });

  it("never echoes caller input", async () => {
    const marker = "canary-value-9f3a";
    const response = await request(env, "/v1/decrypt", {
      token,
      body: {
        wrappedKey: `cfkms1.2.${marker}`,
        encryptionContext: { service: "acme", tenantId: marker },
      },
    });
    const text = await response.text();

    expect(text).not.toContain(marker);
    expect(text).toBe(JSON.stringify({ error: { code: "decrypt_failed" } }));
  });
});

describe("POST /v1/re-wrap", () => {
  it("re-wraps under the current KEK version", async () => {
    const issued = await generate();
    const response = await request(env, "/v1/re-wrap", {
      token,
      body: { wrappedKey: issued.wrappedKey, encryptionContext: acmeContext },
    });
    const body = await jsonOf<DataKeyResponse>(response);

    expect(response.status).toBe(200);
    expect(Object.keys(body).sort()).toStrictEqual(["kekVersion", "wrappedKey"]);
    expect(body.kekVersion).toBe(2);
    expect(body.wrappedKey).not.toBe(issued.wrappedKey);

    const decrypted = await request(env, "/v1/decrypt", {
      token,
      body: { wrappedKey: body.wrappedKey, encryptionContext: acmeContext },
    }).then(jsonOf<DataKeyResponse>);

    expect(decrypted.plaintextKey).toBe(issued.plaintextKey);
  });

  it("never returns plaintext key material", async () => {
    const issued = await generate();
    const text = await request(env, "/v1/re-wrap", {
      token,
      body: { wrappedKey: issued.wrappedKey, encryptionContext: acmeContext },
    }).then((response) => response.text());

    expect(text).not.toContain("plaintextKey");
    expect(text).not.toContain(issued.plaintextKey);
  });

  it("fails closed on a bad token", async () => {
    const issued = await generate();
    const response = await request(env, "/v1/re-wrap", {
      token,
      body: { wrappedKey: tamper(issued.wrappedKey), encryptionContext: acmeContext },
    });

    expect(response.status).toBe(400);
    await expect(jsonOf(response)).resolves.toStrictEqual({
      error: { code: "decrypt_failed" },
    });
  });
});

describe("request validation", () => {
  it.each([
    ["missing body", {}],
    ["missing encryptionContext", { wrappedKey: "cfkms1.2.aa.bb" }],
    ["null context", { encryptionContext: null }],
    ["array context", { encryptionContext: [] }],
    ["non-string context value", { encryptionContext: { service: 1 } }],
    ["unknown field", { encryptionContext: { service: "acme" }, extra: true }],
  ])("rejects %s with invalid_request", async (_label, body) => {
    const response = await request(env, "/v1/generate-data-key", { token, body });

    expect(response.status).toBe(400);
    await expect(jsonOf(response)).resolves.toStrictEqual({
      error: { code: "invalid_request" },
    });
  });

  it("rejects a body that is not JSON", async () => {
    const response = await request(env, "/v1/generate-data-key", {
      token,
      rawBody: "{not json",
      method: "POST",
    });

    expect(response.status).toBe(400);
    await expect(jsonOf(response)).resolves.toStrictEqual({
      error: { code: "invalid_request" },
    });
  });

  it("rejects a missing wrappedKey on decrypt and re-wrap", async () => {
    for (const path of ["/v1/decrypt", "/v1/re-wrap"]) {
      const response = await request(env, path, {
        token,
        body: { encryptionContext: acmeContext },
      });

      expect(response.status).toBe(400);
      await expect(jsonOf(response)).resolves.toStrictEqual({
        error: { code: "invalid_request" },
      });
    }
  });

  it("rejects an oversized wrappedKey before touching crypto", async () => {
    const response = await request(env, "/v1/decrypt", {
      token,
      body: { wrappedKey: "x".repeat(10_000), encryptionContext: acmeContext },
    });

    expect(response.status).toBe(400);
    await expect(jsonOf(response)).resolves.toStrictEqual({
      error: { code: "invalid_request" },
    });
  });
});

describe("routing", () => {
  it("404s unknown paths and methods", async () => {
    for (const [path, init] of [
      ["/", {}],
      ["/v1/unknown", {}],
      ["/v1/decrypt", { method: "GET" }],
      ["/v1/health", { method: "POST", body: {} }],
    ] as const) {
      const response = await request(env, path, { token, ...init });

      expect(response.status).toBe(404);
      await expect(jsonOf(response)).resolves.toStrictEqual({ error: { code: "not_found" } });
    }
  });
});

describe("environment validation", () => {
  it("fails closed when the KEK configuration is broken", async () => {
    const cases: TestEnv[] = [
      { KEK_CURRENT_VERSION: "1", CALLERS: "[]" },
      { KEK_V1: "nonsense", KEK_CURRENT_VERSION: "1", CALLERS: "[]" },
      { KEK_V1: testKeks.v1, KEK_CURRENT_VERSION: "3", CALLERS: "[]" },
      { KEK_V1: testKeks.v1, KEK_CURRENT_VERSION: "1", CALLERS: "not json" },
    ];

    for (const broken of cases) {
      const response = await request(broken, "/v1/generate-data-key", {
        token,
        body: { encryptionContext: acmeContext },
      });

      expect(response.status).toBe(500);
      await expect(jsonOf(response)).resolves.toStrictEqual({
        error: { code: "internal_error" },
      });
    }
  });
});
