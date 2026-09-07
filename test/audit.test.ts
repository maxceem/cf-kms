import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { acmeCaller, acmeContext, unknownCallerToken } from "./constants";
import { createTestEnv, jsonOf, request, tamper, type TestEnv } from "./helpers";

interface AuditLine {
  audit: true;
  caller: string | null;
  op: string;
  kekVersion: number | null;
  context: Record<string, string> | null;
  success: boolean;
}

interface DataKeyResponse {
  plaintextKey: string;
  wrappedKey: string;
  kekVersion: number;
}

const token = acmeCaller.token;

let env: TestEnv;
let logged: string[];

beforeEach(async () => {
  env = await createTestEnv();
  logged = [];
  vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
    logged.push(args.map(String).join(" "));
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

const auditLines = (): AuditLine[] =>
  logged
    .map((line) => {
      try {
        return JSON.parse(line) as AuditLine;
      } catch {
        return null;
      }
    })
    .filter((line): line is AuditLine => line?.audit === true);

const generate = async (context: Record<string, string> = acmeContext) =>
  jsonOf<DataKeyResponse>(
    await request(env, "/v1/generate-data-key", { token, body: { encryptionContext: context } }),
  );

describe("audit log", () => {
  it("writes exactly one line per successful operation", async () => {
    const issued = await generate();

    expect(auditLines()).toStrictEqual([
      {
        audit: true,
        caller: "acme",
        op: "generate-data-key",
        kekVersion: 2,
        context: acmeContext,
        success: true,
      },
    ]);

    logged = [];
    await request(env, "/v1/decrypt", {
      token,
      body: { wrappedKey: issued.wrappedKey, encryptionContext: acmeContext },
    });

    expect(auditLines()).toStrictEqual([
      {
        audit: true,
        caller: "acme",
        op: "decrypt",
        kekVersion: 2,
        context: acmeContext,
        success: true,
      },
    ]);

    logged = [];
    await request(env, "/v1/re-wrap", {
      token,
      body: { wrappedKey: issued.wrappedKey, encryptionContext: acmeContext },
    });

    expect(auditLines()).toStrictEqual([
      {
        audit: true,
        caller: "acme",
        op: "re-wrap",
        kekVersion: 2,
        context: acmeContext,
        success: true,
      },
    ]);
  });

  it("logs failed decrypts", async () => {
    const issued = await generate();
    logged = [];

    await request(env, "/v1/decrypt", {
      token,
      body: { wrappedKey: tamper(issued.wrappedKey), encryptionContext: acmeContext },
    });

    expect(auditLines()).toStrictEqual([
      {
        audit: true,
        caller: "acme",
        op: "decrypt",
        kekVersion: null,
        context: acmeContext,
        success: false,
      },
    ]);
  });

  it("logs failed authentication with no caller", async () => {
    await request(env, "/v1/decrypt", {
      token: unknownCallerToken,
      body: { wrappedKey: "cfkms1.2.aa.bb", encryptionContext: acmeContext },
    });

    expect(auditLines()).toStrictEqual([
      { audit: true, caller: null, op: "decrypt", kekVersion: null, context: null, success: false },
    ]);
  });

  it("logs caller-scoping violations", async () => {
    await request(env, "/v1/generate-data-key", {
      token,
      body: { encryptionContext: { service: "widgets" } },
    });

    expect(auditLines()).toStrictEqual([
      {
        audit: true,
        caller: "acme",
        op: "generate-data-key",
        kekVersion: null,
        context: { service: "widgets" },
        success: false,
      },
    ]);
  });

  it("logs invalid requests without echoing the body", async () => {
    await request(env, "/v1/generate-data-key", {
      token,
      rawBody: JSON.stringify({ encryptionContext: { service: "x".repeat(400) } }),
      method: "POST",
    });

    expect(auditLines()).toStrictEqual([
      {
        audit: true,
        caller: "acme",
        op: "generate-data-key",
        kekVersion: null,
        context: null,
        success: false,
      },
    ]);
    expect(logged.join("\n")).not.toContain("x".repeat(400));
  });

  it("never logs key material, tokens or bearer credentials", async () => {
    const issued = await generate();

    await request(env, "/v1/decrypt", {
      token,
      body: { wrappedKey: issued.wrappedKey, encryptionContext: acmeContext },
    });
    await request(env, "/v1/re-wrap", {
      token,
      body: { wrappedKey: issued.wrappedKey, encryptionContext: acmeContext },
    });

    const everything = logged.join("\n");

    expect(everything).not.toContain(issued.plaintextKey);
    expect(everything).not.toContain(issued.wrappedKey);
    expect(everything).not.toContain(token);
    expect(everything).not.toContain("ckms_");
    expect(everything).not.toContain("cfkms1.");
    expect(everything).not.toContain("Bearer");

    for (const line of auditLines()) {
      expect(Object.keys(line).sort()).toStrictEqual([
        "audit",
        "caller",
        "context",
        "kekVersion",
        "op",
        "success",
      ]);
    }
  });

  it("does not log health checks", async () => {
    await request(env, "/v1/health");

    expect(auditLines()).toStrictEqual([]);
  });
});
