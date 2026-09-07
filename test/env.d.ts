// Bindings injected by vitest.config.ts on top of the ones wrangler.jsonc
// declares. Kept in a .d.ts so `wrangler types` can keep owning
// worker-configuration.d.ts.
declare global {
  namespace Cloudflare {
    interface Env {
      KEK_V1: string;
      KEK_V2: string;
    }
  }
}

export {};
