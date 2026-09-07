import { createHash } from "node:crypto";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";
import { testCallers, testKeks } from "./test/constants";

// The `CALLERS` var holds only hashes, so the host computes them here from the
// throwaway tokens in `test/constants.ts` — exactly what the onboarding runbook
// tells an operator to do with `sha256sum`.
const callers = testCallers.map((caller) => ({
  name: caller.name,
  tokenHash: createHash("sha256").update(caller.token).digest("hex"),
  requiredContext: caller.requiredContext,
}));

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        bindings: {
          // Two KEK versions so `SELF`-driven tests exercise a rotation window.
          KEK_V1: testKeks.v1,
          KEK_V2: testKeks.v2,
          KEK_CURRENT_VERSION: "2",
          CALLERS: JSON.stringify(callers),
        },
      },
    }),
  ],
  test: {
    include: ["test/**/*.test.ts"],
  },
});
