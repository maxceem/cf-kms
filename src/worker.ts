import { createApp } from "./routes";

export {
  decryptPath,
  generateDataKeyPath,
  healthPath,
  reWrapPath,
} from "./routes";

/**
 * cf-kms — a wrap/unwrap-only KMS-shaped Worker.
 *
 * Deployed once per consuming service into a dedicated security Cloudflare
 * account, reachable only through its custom domain route. It holds the root
 * KEK as a Worker secret and exposes no code path that returns it: callers get
 * data keys wrapped under an encryption context, and can trade a wrapped key
 * back for its plaintext only by presenting the exact same context.
 *
 * Configuration (`wrangler.jsonc`) is validated with zod on the first request
 * that needs it; a missing or malformed `KEK_V*` / `CALLERS` /
 * `KEK_CURRENT_VERSION` fails the request outright rather than degrading.
 */
const app = createApp();

export default app;
