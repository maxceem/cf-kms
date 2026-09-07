# cf-kms documentation

A small Cloudflare Worker that wraps and unwraps encryption keys, so your other
services can encrypt secrets without holding the root key.

- [What you get, and what you do not](#what-you-get-and-what-you-do-not)
- [How it works](#how-it-works)
- [HTTP API](#http-api)
- [The client](#the-client)
- [Picking an encryption context](#picking-an-encryption-context)
- [Deploying](#deploying)
- [Adding a caller](#adding-a-caller)
- [Changing the root key](#changing-the-root-key)
- [Turning off a token](#turning-off-a-token)
- [What is logged](#what-is-logged)
- [Local development](#local-development)

---

## What you get, and what you do not

**What you get** is a wall between your services and the root key. The key never
leaves the Worker, and there is no code path that returns it. Every wrap ties
the secret to a *context* you choose, so a value encrypted for one customer
cannot be reused for another. Changing the key is versioned and does not break
anything already stored. The whole thing is a few hundred lines you can read in
one sitting — being small **is** the security argument.

**What you do not get is hardware.** The root key is a Worker secret. Anyone who
can deploy to, or read secrets from, the security account can read it. What you
gain over "encrypt in the app with a secret kept in the app's own account" is
*separation*: if one service is broken into, the root key is not in that
account. What you do not gain is hardware key storage, key attestation, or
protection from Cloudflare itself. If you need those, keep this API and put a
real KMS behind it.

It also stores nothing. There is no database. Your services keep their own
encrypted values and wrapped keys.

## How it works

1. Your service asks for a key. cf-kms makes 32 random bytes, wraps them with
   the root key and your context, and returns both the plain key and the wrapped
   one.
2. Your service encrypts its data with the plain key, stores the result next to
   the wrapped key, and throws the plain key away.
3. To read it back, your service sends the wrapped key **and the same context**.
   Any other context fails, because the context is part of what the encryption
   checks.

Formats you may see stored:

| Thing | Looks like |
| --- | --- |
| Wrapped key | `cfkms1.<key version>.<iv>.<ciphertext>` |
| Whole encrypted secret from the client | `cfkms-env1.<wrapped key>.<iv>.<ciphertext>` |
| Caller token | `ckms_<name>_<random>` |

`cfkms1` is the *format* version and is not the same as the root key version.
Both layers are AES-256-GCM with a fresh random IV every time.

A context is a flat map of strings to strings: at most 8 entries, keys up to 64
characters matching `[A-Za-z0-9][A-Za-z0-9._:-]*`, values up to 256 characters.
The order you write the keys in does not matter. Every other byte does.

## HTTP API

Everything is `POST`, JSON in and JSON out, with
`Authorization: Bearer <caller token>`.

### `POST /v1/generate-data-key`

```jsonc
// request
{ "encryptionContext": { "service": "acme", "tenantId": "org_123" } }
// response 200
{ "plaintextKey": "<32 bytes>", "wrappedKey": "cfkms1.2.…", "kekVersion": 2 }
```

### `POST /v1/decrypt`

```jsonc
// request
{ "wrappedKey": "cfkms1.2.…", "encryptionContext": { /* must match exactly */ } }
// response 200
{ "plaintextKey": "<32 bytes>", "kekVersion": 2 }
```

### `POST /v1/re-wrap`

```jsonc
// request
{ "wrappedKey": "cfkms1.1.…", "encryptionContext": { /* must match exactly */ } }
// response 200
{ "wrappedKey": "cfkms1.2.…", "kekVersion": 2 }
```

Unwraps with whichever key version the wrapped key names and wraps it again with
the current one. The plain key never leaves the Worker here. This is what a
rotation job calls.

### `GET /v1/health`

No token needed. Returns `{"ok":true}` and nothing else — no version, no key
versions, no settings.

### Errors

```jsonc
{ "error": { "code": "decrypt_failed" } }
```

| Code | Status | Meaning |
| --- | --- | --- |
| `invalid_request` | 400 | The body is not JSON, or does not match the schema. |
| `decrypt_failed` | 400 | Unwrapping did not work. See below. |
| `unauthorized` | 401 | Missing or unknown token, or the caller may not use this context. |
| `not_found` | 404 | Unknown path or method. |
| `internal_error` | 500 | A bug or broken settings. Logged, never explained. |

Error replies never repeat what you sent and never carry a message or a stack
trace.

**`decrypt_failed` looks the same on purpose** whether the wrapped key was
malformed, tampered with, sent with the wrong context, or made with a key
version that was never set up or has since been removed. The endpoint must not
tell an attacker which of those it was.

## The client

```ts
import { createKmsClient } from "@maxceem/cf-kms/client";

const kms = createKmsClient({
  url: env.KMS_URL,     // https://kms-acme.example.com
  token: env.KMS_TOKEN, // ckms_acme_…
  cacheTtlMs: 60_000,   // optional, off by default
});

// Straight copies of the API.
await kms.generateDataKey({ encryptionContext });
await kms.decrypt({ wrappedKey, encryptionContext });
await kms.reWrap({ wrappedKey, encryptionContext });

// What you will use most of the time.
const blob = await kms.encryptSecret(plaintext, encryptionContext);
const plaintext = await kms.decryptSecret(blob, encryptionContext);
```

`encryptSecret` and `decryptSecret` encrypt your data on your side, tie the same
context to it, and give you one string to store.

Failures throw `KmsClientError` with the server's `code` and `status`, or a
local `invalid_envelope`, `decrypt_failed` or `insecure_url` with status `0`.

`url` must start with `https://`. The token goes out on every call, so a typo
like `http://kms-acme.example.com` is refused when you build the client rather
than leaking the token. `http://localhost` and `http://127.0.0.1` on any port
are allowed, for working on your own machine.

### Caching keys

`cacheTtlMs` keeps unwrapped keys in memory, matched on both the wrapped key and
the context. It is off by default. It trades detail in the log for speed: a
cached read is not a call to cf-kms, so it does not show up in the audit log.
60–300 seconds is reasonable on a busy path. Leave it off if every decrypt has
to be individually traceable. `kms.clearCache()` empties it.

## Picking an encryption context

The context is what a stored value is tied to, so **make it as specific as the
row it lives in**. Two values encrypted with the same context can be swapped for
each other: someone who can write to your database could move one row's blob
into another row, and it would decrypt fine. Putting `tenantId` in the context
already stops that across customers — but two keys belonging to the *same*
customer and provider would still be swappable.

Add something unique to the row, so every value is tied to its own:

```ts
const context = {
  service: "acme",
  tenantId: "org_123",
  provider: "openai",
  recordId: row.id, // ← makes this value usable only in this row
};
```

Store the context, or the columns you build it from, next to the value, and
build it the same way when you read. Context values are labels, not secrets:
they appear in the audit log, so keep customer data out of them.

## Deploying

### The security account

cf-kms is only worth deploying if it sits somewhere your other services cannot
reach:

- A **separate Cloudflare account** used for nothing else.
- Hardware-key two-factor on every member, and as few members as possible.
- No API tokens that can edit Workers except the one you deploy with.
- No CI deploys. Deploy by hand from a machine you trust. The Worker changes
  about once a year.
- A zone in that account for the custom domain.

### One deployment per service

Each service gets its own deployment **and its own root key**, so a stolen token
can never read another service's data:

```
cf-kms-<service> → kms-<service>.<your-domain>
```

A deployment is described by a **profile**: a gitignored
`wrangler.<profile>.overlay.jsonc` that lists only what is different from the
tracked `wrangler.jsonc`. It is merged over that file every time you run a
command. Objects merge into each other, an array replaces the whole array, and
`null` removes a key.

```jsonc title="wrangler.acme.overlay.jsonc"
{
  "name": "cf-kms-acme",
  "routes": [{ "pattern": "kms-acme.example.com", "custom_domain": true }],
}
```

Every command takes `--profile <name>`:

```bash
pnpm run deploy --profile acme
pnpm run deploy:dry-run --profile acme
pnpm run cf-typegen --profile acme
```

The merged result is written to `wrangler.<profile>.generated.jsonc`, also
gitignored. Commands with no profile flag of their own — `wrangler secret`,
`wrangler tail` — take that file directly.

`workers_dev` and `preview_urls` stay `false`, so the decrypt endpoint is not
reachable on the shared `*.workers.dev` names. Calls from another account are
plain HTTPS, because service bindings cannot cross accounts. Putting Cloudflare
Access or mTLS in front of the route is a fine extra step but not required — the
token is the real check.

### Making the root key

```bash
openssl rand -base64 32 | pnpm exec wrangler secret put KEK_V1 \
  --config wrangler.acme.generated.jsonc
```

Do this once per deployment, and keep no copy except an offline backup if you
want one. **There is no way to recover it**: lose the key and everything wrapped
with it is gone for good.

Leave `KEK_CURRENT_VERSION` at `"1"` until you change it.

Secret commands take a config file rather than a profile, so run
`pnpm run deploy:dry-run --profile acme` once first. That writes
`wrangler.acme.generated.jsonc` for every `wrangler secret` call to point at.

### Adding callers and deploying

Fill in `CALLERS` (see below), then:

```bash
pnpm run deploy --profile acme
curl -s https://kms-acme.example.com/v1/health   # {"ok":true}
```

## Adding a caller

1. Make a token. The `<name>` part must match the caller entry and must not
   contain underscores:

   ```bash
   TOKEN="ckms_acme_$(openssl rand -base64 24 | tr '+/' '-_' | tr -d '=' | cut -c1-32)"
   printf '%s' "$TOKEN" | shasum -a 256
   ```

2. Put the **hash** in `CALLERS` in that deployment's overlay. It is a plain
   variable, not a secret, because it cannot be used to call anything:

   ```jsonc title="wrangler.acme.overlay.jsonc"
   "vars": {
     "CALLERS": "[{\"name\":\"acme\",\"tokenHash\":\"<sha256 hex>\",\"requiredContext\":{\"service\":\"acme\"}}]",
   }
   ```

3. Give the **token** to the service, as a secret on its own Worker:

   ```bash
   npx wrangler secret put KMS_TOKEN   # in that service's account
   ```

`requiredContext` limits what a caller may do: every key listed must be present,
with exactly that value, in the context of every request. Deployments are
already one per service, so this is a second line of defence against a settings
mistake — for example two services pointed at one deployment by accident. A
caller with `"requiredContext": {}` may use any context.

cf-kms stores only the hash of the token, and compares it in a way that takes
the same time whether or not it matches, so a copy of the Worker's settings is
worth nothing.

## Changing the root key

You do not have to re-encrypt anything your services store — only re-wrap the
small wrapped keys. Every `KEK_V*` secret that is present can still unwrap, so
old and new live side by side for as long as you need.

1. **Add the new version.**

   ```bash
   openssl rand -base64 32 | pnpm exec wrangler secret put KEK_V2 \
     --config wrangler.acme.generated.jsonc
   pnpm run deploy --profile acme
   ```

   Nothing changes yet. `KEK_CURRENT_VERSION` still points at `KEK_V1`.

2. **Switch new wraps over.** Set `"KEK_CURRENT_VERSION": "2"` in the overlay
   and deploy. New keys are wrapped with v2; everything already stored still
   opens with v1.

3. **Re-wrap what is stored.** The service goes through its rows and calls
   `POST /v1/re-wrap` with each wrapped key and its original context, then saves
   what comes back. Its own data is untouched — the key did not change, only the
   key protecting it.

   ```ts
   const { wrappedKey } = await kms.reWrap({ wrappedKey: row.wrappedKey, encryptionContext });
   ```

   Check nothing is left on v1. Wrapped keys carry their version, so looking for
   `cfkms1.1.%` is enough.

4. **Remove the old version.**

   ```bash
   pnpm exec wrangler secret delete KEK_V1 --config wrangler.acme.generated.jsonc
   pnpm run deploy --profile acme
   ```

   > **This cannot be undone.** Anything still wrapped with v1 becomes
   > unreadable the moment `KEK_V1` is gone. That is also how you destroy data on
   > purpose, in one step.

Removing a version early is what you do if you think the key has leaked: add v2,
re-wrap, delete v1.

## Turning off a token

This is one variable change and one deploy. The service does not need
redeploying, beyond giving it a new token.

1. Remove the caller from `CALLERS` in the overlay, or replace its `tokenHash`
   with the hash of a new token.
2. `pnpm run deploy --profile <name>`. The old token stops working on the next
   request.
3. If you are replacing rather than removing, put the new token on the service
   with `wrangler secret put KMS_TOKEN` and restart it.

Nothing needs re-encrypting. Caller tokens are not key material.

## What is logged

Every request with a token writes exactly one line to Workers Logs:

```json
{"audit":true,"caller":"acme","op":"decrypt","kekVersion":2,"context":{"service":"acme","tenantId":"org_123"},"success":true}
```

Both successes and failures. A failed sign-in is logged with `"caller":null`.
The line is built field by field, so plain keys, wrapped keys and tokens cannot
end up in it.

**Workers Logs are kept for days, not months.** Looking into an incident older
than that is not possible today. If you need longer, add a Logpush job on the
security account.

To watch decrypts as they happen:

```bash
npx wrangler tail cf-kms-acme --format json \
  | jq -c '.logs[]?.message[]? | select(type == "string") | fromjson? | select(.audit == true)'
```

For anything older, use the dashboard: **Workers & Pages → cf-kms-… → Logs**,
filter on `audit`, `op`, `caller` and `success`, and group by `caller`. A sudden
jump in `op = decrypt` for one caller, especially with many different
`context.tenantId` values, is the sign that a token has leaked.

## Local development

```bash
pnpm install
cp .dev.vars.example .dev.vars   # then put `openssl rand -base64 32` into KEK_V1
pnpm dev
pnpm check                       # types + tests + build
```

Tests run in the Workers runtime. Test keys and tokens live in
`test/constants.ts` and are hashed into the `CALLERS` variable by
`vitest.config.ts` — the same thing the caller runbook tells you to do by hand.

Run `pnpm cf-typegen` after editing `wrangler.jsonc`.
