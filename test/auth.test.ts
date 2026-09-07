import { beforeAll, describe, expect, it } from "vitest";
import {
  assertCallerContext,
  authenticateCaller,
  callerNameOfToken,
  parseCallers,
  readBearerToken,
  sha256Hex,
  timingSafeEqual,
  type Caller,
} from "../src/auth";
import { isKmsError } from "../src/errors";
import {
  acmeCaller,
  acmeContext,
  widgetsCaller,
  unknownCallerToken,
} from "./constants";
import { buildCallers, createTestEnv, jsonOf, request, type TestEnv } from "./helpers";

const expectUnauthorized = async (promise: Promise<unknown>) => {
  await expect(promise).rejects.toSatisfy(
    (error: unknown) => isKmsError(error) && error.code === "unauthorized" && error.status === 401,
  );
};

let callers: Caller[];
let env: TestEnv;

beforeAll(async () => {
  callers = (await buildCallers([acmeCaller, widgetsCaller])) as Caller[];
  env = await createTestEnv();
});

describe("readBearerToken", () => {
  it("reads a bearer token case-insensitively", () => {
    expect(readBearerToken("Bearer abc")).toBe("abc");
    expect(readBearerToken("bearer abc")).toBe("abc");
    expect(readBearerToken("BEARER   abc  ")).toBe("abc");
  });

  it("rejects anything else", () => {
    expect(readBearerToken(null)).toBeNull();
    expect(readBearerToken(undefined)).toBeNull();
    expect(readBearerToken("")).toBeNull();
    expect(readBearerToken("abc")).toBeNull();
    expect(readBearerToken("Basic abc")).toBeNull();
    expect(readBearerToken("Bearer ")).toBeNull();
    expect(readBearerToken(`Bearer ${"x".repeat(257)}`)).toBeNull();
  });
});

describe("callerNameOfToken", () => {
  it("reads the name segment", () => {
    expect(callerNameOfToken(acmeCaller.token)).toBe("acme");
    expect(callerNameOfToken(widgetsCaller.token)).toBe("widgets");
  });

  it("rejects malformed tokens", () => {
    expect(callerNameOfToken("nope")).toBeNull();
    expect(callerNameOfToken("ckms_acme")).toBeNull();
    expect(callerNameOfToken("ckms__abcdefghijklmnopqrst")).toBeNull();
    // Random part too short to be a credential.
    expect(callerNameOfToken("ckms_acme_short")).toBeNull();
    expect(callerNameOfToken("ckms_Acme_abcdefghijklmnopqrst")).toBeNull();
  });
});

describe("timingSafeEqual", () => {
  it("compares equal-length strings", () => {
    expect(timingSafeEqual("abcd", "abcd")).toBe(true);
    expect(timingSafeEqual("abcd", "abce")).toBe(false);
    expect(timingSafeEqual("abcd", "abc")).toBe(false);
    expect(timingSafeEqual("", "")).toBe(true);
  });
});

describe("parseCallers", () => {
  it("parses the JSON var", () => {
    const parsed = parseCallers(JSON.stringify(callers));

    expect(parsed).toHaveLength(2);
    expect(parsed[0]?.requiredContext).toStrictEqual({ service: "acme" });
    expect(parseCallers("[]")).toStrictEqual([]);
  });

  it("defaults requiredContext to an empty object", () => {
    const parsed = parseCallers([{ name: "x", tokenHash: "a".repeat(64) }]);

    expect(parsed[0]?.requiredContext).toStrictEqual({});
  });

  it("rejects malformed configuration", () => {
    expect(() => parseCallers("not json")).toThrow(/valid JSON/);
    expect(() => parseCallers("{}")).toThrow(/valid caller list/);
    expect(() => parseCallers([{ name: "x", tokenHash: "short" }])).toThrow(/valid caller list/);
    expect(() => parseCallers([{ name: "Bad_Name", tokenHash: "a".repeat(64) }])).toThrow();
    // Uppercase hex is not the format `sha256sum` prints.
    expect(() => parseCallers([{ name: "x", tokenHash: "A".repeat(64) }])).toThrow();
    expect(() =>
      parseCallers([
        { name: "x", tokenHash: "a".repeat(64) },
        { name: "x", tokenHash: "b".repeat(64) },
      ]),
    ).toThrow();
    expect(() =>
      parseCallers([
        { name: "x", tokenHash: "a".repeat(64) },
        { name: "y", tokenHash: "a".repeat(64) },
      ]),
    ).toThrow();
  });
});

describe("authenticateCaller", () => {
  it("resolves the caller behind a valid token", async () => {
    await expect(
      authenticateCaller(callers, `Bearer ${acmeCaller.token}`),
    ).resolves.toMatchObject({ name: "acme" });
  });

  it("rejects a missing, malformed or unknown token", async () => {
    await expectUnauthorized(authenticateCaller(callers, null));
    await expectUnauthorized(authenticateCaller(callers, "Bearer "));
    await expectUnauthorized(authenticateCaller(callers, acmeCaller.token));
    await expectUnauthorized(authenticateCaller(callers, `Bearer ${unknownCallerToken}`));
    await expectUnauthorized(
      authenticateCaller(callers, `Bearer ${acmeCaller.token}x`),
    );
    await expectUnauthorized(authenticateCaller([], `Bearer ${acmeCaller.token}`));
  });

  it("rejects a token whose name segment does not match its entry", async () => {
    const mislabelled = [
      { ...(callers[0] as Caller), name: "widgets", requiredContext: {} },
    ];

    await expectUnauthorized(
      authenticateCaller(mislabelled, `Bearer ${acmeCaller.token}`),
    );
  });

  it("stores only the hash of the token", async () => {
    const serialized = JSON.stringify(callers);

    expect(serialized).not.toContain(acmeCaller.token);
    expect(serialized).toContain(await sha256Hex(acmeCaller.token));
  });
});

describe("assertCallerContext", () => {
  it("requires every scoped key to match exactly", () => {
    const caller = callers[0] as Caller;

    expect(() => assertCallerContext(caller, acmeContext)).not.toThrow();
    expect(() => assertCallerContext(caller, { service: "acme" })).not.toThrow();
    expect(() => assertCallerContext(caller, { service: "widgets" })).toThrow();
    expect(() => assertCallerContext(caller, { tenantId: "org_1" })).toThrow();
    expect(() => assertCallerContext(callers[1] as Caller, {})).not.toThrow();
  });
});

describe("route authentication", () => {
  const paths = ["/v1/generate-data-key", "/v1/decrypt", "/v1/re-wrap"] as const;

  it("rejects unauthenticated calls to every operation", async () => {
    for (const path of paths) {
      const response = await request(env, path, { body: { encryptionContext: acmeContext } });

      expect(response.status).toBe(401);
      await expect(jsonOf(response)).resolves.toStrictEqual({
        error: { code: "unauthorized" },
      });
    }
  });

  it("rejects an unknown caller token", async () => {
    for (const path of paths) {
      const response = await request(env, path, {
        token: unknownCallerToken,
        body: { encryptionContext: acmeContext },
      });

      expect(response.status).toBe(401);
    }
  });

  it("does not authenticate on the health endpoint", async () => {
    const response = await request(env, "/v1/health");

    expect(response.status).toBe(200);
  });

  it("enforces caller scoping", async () => {
    const scoped = await request(env, "/v1/generate-data-key", {
      token: acmeCaller.token,
      body: { encryptionContext: { service: "widgets", tenantId: "org_1" } },
    });

    expect(scoped.status).toBe(401);
    await expect(jsonOf(scoped)).resolves.toStrictEqual({ error: { code: "unauthorized" } });

    const allowed = await request(env, "/v1/generate-data-key", {
      token: acmeCaller.token,
      body: { encryptionContext: acmeContext },
    });

    expect(allowed.status).toBe(200);
  });

  it("lets an unscoped caller use any context", async () => {
    const response = await request(env, "/v1/generate-data-key", {
      token: widgetsCaller.token,
      body: { encryptionContext: { service: "whatever" } },
    });

    expect(response.status).toBe(200);
  });

  it("rejects a caller whose token is no longer configured", async () => {
    const revoked = await createTestEnv({ callers: [widgetsCaller] });
    const response = await request(revoked, "/v1/generate-data-key", {
      token: acmeCaller.token,
      body: { encryptionContext: acmeContext },
    });

    expect(response.status).toBe(401);
  });
});
