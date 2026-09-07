# cf-kms

A tiny Cloudflare Worker that wraps and unwraps encryption keys, so your other
services can encrypt secrets — customer API keys, webhook secrets, tokens —
without ever holding the root key themselves.

The root key lives only in this Worker's secrets, in a **separate Cloudflare
account** from the services that use it. Someone who dumps a service's database,
or even gets full deploy access to that service's account, still cannot read the
root key. The most they get is the ability to *call* decrypt while that
service's token is valid — and every call is logged and the token can be turned
off.

The API copies AWS KMS on purpose, so you can put a real KMS behind it later
without changing anything that uses it.

## Install

The client is the only thing you import. The Worker itself is deployed.

```sh
pnpm add @maxceem/cf-kms
```

## Use it

```ts
import { createKmsClient } from "@maxceem/cf-kms/client";

const kms = createKmsClient({ url: env.KMS_URL, token: env.KMS_TOKEN });

// Say what this secret belongs to. You must pass the same thing to read it back.
const context = { service: "acme", tenantId: "org_123", provider: "openai" };

const blob = await kms.encryptSecret("sk-live-…", context); // store this string
const secret = await kms.decryptSecret(blob, context);      // and get it back
```

The client has no dependencies. It needs only `fetch` and WebCrypto, so it runs
on Workers and on Node 20 and above.

## Documentation

[`docs/index.md`](docs/index.md) covers how it works, the HTTP API, the client,
picking a good encryption context, deploying, adding callers, and the key and
token runbooks.

## License

This project is licensed under the [Apache License 2.0](LICENSE).
