import { parseCallers, type Caller } from "./auth";
import { createKekRegistry, type KekRegistry } from "./crypto/kek";

/**
 * Validated runtime configuration.
 *
 * A Worker has no startup hook that can see its bindings, so "fail fast" means
 * "fail on the first request that needs the config, every time". The result is
 * memoised per env object for the lifetime of the isolate; a broken config is
 * never memoised, so it keeps throwing until it is fixed.
 */
export interface KmsRuntime {
  readonly keks: KekRegistry;
  readonly callers: readonly Caller[];
}

const runtimeByEnv = new WeakMap<object, KmsRuntime>();

export const assertEnvironment = (env: unknown): KmsRuntime => {
  if (typeof env !== "object" || env === null) {
    throw new Error("cf-kms: env must be an object");
  }

  const cached = runtimeByEnv.get(env);

  if (cached) {
    return cached;
  }

  const runtime: KmsRuntime = {
    keks: createKekRegistry(env),
    callers: parseCallers((env as Record<string, unknown>).CALLERS),
  };

  runtimeByEnv.set(env, runtime);

  return runtime;
};
