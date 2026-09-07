import { sha256Hex } from "../src/auth";
import { createApp } from "../src/routes";
import { testCallers, testKeks, type TestCaller } from "./constants";

/**
 * Tests drive the Hono app directly with a hand-built env, which is what lets
 * one test file exercise several KEK configurations (rotation windows, retired
 * versions) without redeploying anything. `client.test.ts` goes through `SELF`
 * instead, against the bindings in `vitest.config.ts`.
 */
export const app = createApp();

export const testOrigin = "https://kms.test";

export type TestEnv = Record<string, unknown>;

export const buildCallers = async (callers: readonly TestCaller[]) =>
  Promise.all(
    callers.map(async (caller) => ({
      name: caller.name,
      tokenHash: await sha256Hex(caller.token),
      requiredContext: caller.requiredContext,
    })),
  );

export const createTestEnv = async (options?: {
  keks?: Record<string, string>;
  currentVersion?: string;
  callers?: readonly TestCaller[];
}): Promise<TestEnv> => ({
  ...(options?.keks ?? { KEK_V1: testKeks.v1, KEK_V2: testKeks.v2 }),
  KEK_CURRENT_VERSION: options?.currentVersion ?? "2",
  CALLERS: JSON.stringify(await buildCallers(options?.callers ?? testCallers)),
});

export const request = async (
  env: TestEnv,
  path: string,
  init?: { token?: string | null; body?: unknown; method?: string; rawBody?: string },
): Promise<Response> => {
  const headers = new Headers();

  if (init?.token) {
    headers.set("authorization", `Bearer ${init.token}`);
  }

  const body = init?.rawBody ?? (init?.body === undefined ? undefined : JSON.stringify(init.body));

  if (body !== undefined) {
    headers.set("content-type", "application/json");
  }

  return app.fetch(
    new Request(`${testOrigin}${path}`, {
      method: init?.method ?? (body === undefined ? "GET" : "POST"),
      headers,
      ...(body === undefined ? {} : { body }),
    }),
    env,
  );
};

export const jsonOf = async <T>(response: Response): Promise<T> => (await response.json()) as T;

/** Flips one base64url character of the last segment of a token. */
export const tamper = (token: string): string => {
  const parts = token.split(".");
  const last = parts[parts.length - 1] ?? "";
  const first = last.charAt(0);
  parts[parts.length - 1] = (first === "A" ? "B" : "A") + last.slice(1);

  return parts.join(".");
};
