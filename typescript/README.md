# @algovoi/key-credential-binding

TypeScript reference verifier for binding an RFC 9421 HTTP Message Signature
key to an issued agent credential. Behavioral parity with the Python
[`algovoi-key-credential-binding`](https://pypi.org/project/algovoi-key-credential-binding/),
over the same conformance vectors.

RFC 9421 proves a request was signed by the holder of a key. It does not prove
which credential that key belongs to, nor that the request is within the
credential's scope. This package adds that layer on top of
[`@algovoi/rfc9421-verifier`](https://www.npmjs.com/package/@algovoi/rfc9421-verifier)
and evaluates four independent checks: `key_anchored`, `signature_valid`,
`scope_valid`, `credential_valid`. The public key is resolved from the
credential (keyed by `keyid`), never from the request artifact.

See the
[repository](https://github.com/chopmob-cloud/algovoi-key-credential-binding)
for `SPEC.md` and the language-neutral vector set.

## Install

```
npm install @algovoi/key-credential-binding
```

## Usage

```ts
import { verifyBoundRequest, type Credential } from "@algovoi/key-credential-binding";

const credential: Credential = {
  credential_id: "cred_001",
  enrolled_keys: [
    { keyid: "did:web:api.example#key-1", alg: "ed25519", public_key_hex: "700e2ce7..." },
  ],
  scope: { methods: ["POST"], path_prefixes: ["/v1/binding-receipts"] },
  not_before: 1740000000,
  not_after: 1760000000,
  status: "active",
};

const request = {
  method: "POST",
  authority: "api.example",
  path: "/v1/binding-receipts",
  headers: {
    "content-digest": "sha-256=:...:",
    "signature-input": 'sig=(...);created=...;keyid="did:web:api.example#key-1";alg="ed25519"',
    "signature": "sig=:...:",
  },
  body: Buffer.from("..."),
};

const result = await verifyBoundRequest(request, credential);
// result.valid, result.key_anchored, result.signature_valid,
// result.scope_valid, result.credential_valid, result.errors
```

Node >= 18. On Node 18 a small WebCrypto shim supplies `globalThis.crypto`
(provided natively on Node 20+).

## License

Apache-2.0.
