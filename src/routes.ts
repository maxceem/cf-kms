import { Hono } from "hono";
import type { Context } from "hono";
import { z } from "zod";
import { audited, writeAuditLog, type AuditOperation } from "./audit";
import { assertCallerContext, authenticateCaller, type Caller } from "./auth";
import { encodeBase64Url } from "./crypto/base64url";
import { encryptionContextSchema } from "./crypto/context";
import {
  generateDek,
  MAX_WRAPPED_KEY_LENGTH,
  unwrapDek,
  wrapDek,
} from "./crypto/wrap";
import { assertEnvironment, type KmsRuntime } from "./env";
import { invalidRequest, notFound, toErrorResponse } from "./errors";

export const healthPath = "/v1/health";
export const generateDataKeyPath = "/v1/generate-data-key";
export const decryptPath = "/v1/decrypt";
export const reWrapPath = "/v1/re-wrap";

/** The worker reads nothing off `env` directly; everything goes through zod. */
type Bindings = Record<string, unknown>;

type KmsContext = Context<{ Bindings: Bindings }>;

const generateDataKeyRequestSchema = z
  .object({ encryptionContext: encryptionContextSchema })
  .strict();

/**
 * `wrappedKey` is deliberately only length-checked here: a malformed token must
 * fail as `decrypt_failed`, not `invalid_request`, or the shape of the error
 * would tell an attacker which part they got wrong.
 */
const wrappedKeyRequestSchema = z
  .object({
    wrappedKey: z.string().min(1).max(MAX_WRAPPED_KEY_LENGTH),
    encryptionContext: encryptionContextSchema,
  })
  .strict();

const authenticateRequest = async (
  c: KmsContext,
  op: AuditOperation,
): Promise<{ runtime: KmsRuntime; caller: Caller }> => {
  const runtime = assertEnvironment(c.env);

  try {
    const caller = await authenticateCaller(runtime.callers, c.req.header("authorization"));

    return { runtime, caller };
  } catch (error) {
    writeAuditLog({ caller: null, op, kekVersion: null, context: null, success: false });

    throw error;
  }
};

const readBody = async <T extends z.ZodType>(c: KmsContext, schema: T): Promise<z.infer<T>> => {
  let raw: unknown;

  try {
    raw = await c.req.json();
  } catch {
    throw invalidRequest();
  }

  const parsed = schema.safeParse(raw);

  if (!parsed.success) {
    // The zod issues are dropped on purpose — they would echo caller input.
    throw invalidRequest();
  }

  return parsed.data;
};

export const createApp = () => {
  const app = new Hono<{ Bindings: Bindings }>();

  // Unauthenticated liveness probe. Says nothing about configuration, KEK
  // versions or version numbers.
  app.get(healthPath, (c) => c.json({ ok: true }));

  app.post(generateDataKeyPath, async (c) => {
    const { runtime, caller } = await authenticateRequest(c, "generate-data-key");

    return audited(caller.name, "generate-data-key", async (draft) => {
      const { encryptionContext } = await readBody(c, generateDataKeyRequestSchema);
      draft.context = encryptionContext;
      assertCallerContext(caller, encryptionContext);

      const dek = generateDek();
      const { wrappedKey, kekVersion } = await wrapDek(runtime.keks, dek, encryptionContext);
      draft.kekVersion = kekVersion;

      return c.json({ plaintextKey: encodeBase64Url(dek), wrappedKey, kekVersion });
    });
  });

  app.post(decryptPath, async (c) => {
    const { runtime, caller } = await authenticateRequest(c, "decrypt");

    return audited(caller.name, "decrypt", async (draft) => {
      const { wrappedKey, encryptionContext } = await readBody(c, wrappedKeyRequestSchema);
      draft.context = encryptionContext;
      assertCallerContext(caller, encryptionContext);

      const { dek, kekVersion } = await unwrapDek(runtime.keks, wrappedKey, encryptionContext);
      draft.kekVersion = kekVersion;

      return c.json({ plaintextKey: encodeBase64Url(dek), kekVersion });
    });
  });

  // Rotation helper: unwrap with whichever KEK version the token names, re-wrap
  // with the current one. The plaintext DEK never leaves the worker.
  app.post(reWrapPath, async (c) => {
    const { runtime, caller } = await authenticateRequest(c, "re-wrap");

    return audited(caller.name, "re-wrap", async (draft) => {
      const body = await readBody(c, wrappedKeyRequestSchema);
      draft.context = body.encryptionContext;
      assertCallerContext(caller, body.encryptionContext);

      const { dek } = await unwrapDek(runtime.keks, body.wrappedKey, body.encryptionContext);
      const { wrappedKey, kekVersion } = await wrapDek(runtime.keks, dek, body.encryptionContext);
      draft.kekVersion = kekVersion;

      return c.json({ wrappedKey, kekVersion });
    });
  });

  app.notFound(() => toErrorResponse(notFound()));
  app.onError((error) => toErrorResponse(error));

  return app;
};

export type KmsApp = ReturnType<typeof createApp>;
