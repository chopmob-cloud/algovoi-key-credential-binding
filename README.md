# algovoi-key-credential-binding


[![PyPI](https://img.shields.io/pypi/v/algovoi-key-credential-binding)](https://pypi.org/project/algovoi-key-credential-binding/) [![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![npm](https://img.shields.io/npm/v/@algovoi/key-credential-binding)](https://www.npmjs.com/package/@algovoi/key-credential-binding)

Conformance vectors and a reference verifier for **binding an RFC 9421 HTTP
Message Signature to an issued agent credential**.

RFC 9421 proves that a request was signed by the holder of *a* key. It does not
prove which credential that key belongs to, nor that the request is within the
credential's authorized scope. The RFC 9421 `keyid` is an integrity-protected
label; mapping it to an issued credential, and enforcing that credential's
scope and validity, is left to each implementation. Today every issuer and
verifier does that mapping differently, or not at all.

This package pins the missing layer as testable vectors on top of the raw
signature check, so implementations can converge on one behavior instead of
each inventing (or skipping) it.

## The four checks

A bound request is verified along four independent dimensions:

| Check | Meaning |
| --- | --- |
| `key_anchored` | The signature-input `keyid` resolves to a key **enrolled in the presented credential**, through a verifier-controlled registry. The public key is taken from the credential, never from the request artifact. |
| `signature_valid` | The raw RFC 9421 + RFC 9530 signature verifies against the **credential-resolved** public key. |
| `scope_valid` | The request method and path fall within the credential's declared scope. |
| `credential_valid` | The credential is active (not revoked) and the signed `created` falls within the credential validity window. |
| `valid` | All four checks hold. |

The dimensions are deliberately separable so a failure in one is observable
without collapsing into another. The one intentional coupling: an unenrolled
key leaves no verifier-trusted key to check a signature against, so
`key_anchored=false` necessarily carries `signature_valid=false`.

## Why key material comes from the credential, not the artifact

The core rule is that `keyid` is a **lookup hint into verifier-held material,
not a trust-root selector**. A verifier resolves the public key from its own
credential registry keyed by `keyid`. It never fetches or reads key material
nominated by the signer (an embedded key, a `jku`, or an `x5u`). This is the
same boundary that prevents a signed artifact from nominating its own trust
root: a card that carries its own key source can be fabricated wholesale and
still verify cleanly against the key it supplies.

Vector `kcb-v1-004` (keyid-substitution) proves the point concretely: an
adversary signs a request and spoofs the enrolled `keyid`. Because the verifier
resolves the public key from the credential, it checks the adversary signature
against the enrolled key and rejects it. A naive verifier that trusted a key
carried in the artifact would accept the forgery. The generator asserts both
outcomes.

## Vectors

`vectors/key-credential-binding-v1.json`, nine cases, each isolating one
dimension:

| id | case | key_anchored | signature_valid | scope_valid | credential_valid | valid |
| --- | --- | --- | --- | --- | --- | --- |
| 001 | valid | true | true | true | true | **true** |
| 002 | signature-fail (corrupted bytes) | true | false | true | true | false |
| 003 | unanchored-key (keyid not enrolled) | false | false | true | true | false |
| 004 | keyid-substitution (spoofed enrolled keyid) | true | false | true | true | false |
| 005 | scope-violation (out-of-scope path) | true | true | false | true | false |
| 006 | credential-expired (created after not_after) | true | true | true | false | false |
| 007 | credential-revoked (status revoked) | true | true | true | false | false |
| 008 | credential-not-yet-valid (created before not_before) | true | true | true | false | false |
| 009 | method-scope-violation (method not permitted) | true | true | false | true | false |

Each vector carries the exact signed request (`method`, `authority`, `path`,
the three signature headers, `body_hex`, and `body_json`), a `credential_ref`
into the `credentials` map, and an `expect` block with the five outcomes.

## Keys

Two fixed Ed25519 test keypairs. Public keys are derived from the seeds, never
hardcoded, and cross-checked by both PyNaCl and the `cryptography` library.

- **Enrolled key** (`did:web:api.algovoi.co.uk#key-1`): public key
  `700e2ce7c4b674427eab27ba820bcf6f0faebe68e09fe8564292114e41dc6a41`. Reused
  from the AlgoVoi RFC 9421 conformance sets so this set composes with them.
- **Adversary key** (`did:web:attacker.example#key-1`, not enrolled): public
  key `361e5bee54dacf0078c4be8585c345716ff7a7015c933ed7e0abb73587bdff90`.

These are throwaway test keys with published seeds. They protect nothing and
must never be used outside conformance testing.

## Layout

```
vectors/key-credential-binding-v1.json                    frozen vector set (language-neutral)
python/algovoi_key_credential_binding/binding_verifier.py  Python reference verifier (pip package)
python/generate.py                                        deterministic vector generator (self-verifying)
python/run_conformance.py                                 Python GREEN/RED runner, exit 0 on all-pass
python/tests/test_vectors.py                              pytest: re-verify every vector + independence
typescript/src/binding-verifier.ts                        TypeScript reference verifier (npm package)
typescript/test/vectors.test.ts                           node:test over the same vectors
typescript/run-conformance.ts                             TypeScript GREEN/RED runner
SPEC.md                                                   normative binding rules
```

The vector file is the single source of truth; the Python and TypeScript
verifiers both consume it and produce identical results.

## Run

```
cd python
pip install -e .[dev]        # the package + generation/test dependencies
python generate.py           # regenerate + self-verify the vectors
python run_conformance.py     # GREEN/RED table, exit 0 iff all pass
python -m pytest tests/ -q   # vector-driven tests
```

The generator signs with the real `algovoi-rfc9421-signer` and verifies every
vector through the reference `binding_verifier` before writing the file, so the
vectors cannot drift from the code that consumes them.

TypeScript (in `typescript/`):

```
cd typescript
npm install                 # pulls @algovoi/rfc9421-verifier from npm
npm run conformance         # build + GREEN/RED table, exit 0 iff all pass
npm test                    # build + node:test over the same vectors
```

The TypeScript verifier depends on the published `@algovoi/rfc9421-verifier`
and reads the same `vectors/key-credential-binding-v1.json`. Node >= 18 is
supported; on Node 18 a small WebCrypto shim in `binding-verifier.ts` supplies
`globalThis.crypto`, which Node 20+ provides natively.

## Relationship to RFC 9421

This set is strictly additive. `signature_valid` delegates unchanged to a raw
RFC 9421 verifier; the other three checks are the credential layer above it. It
introduces no new signature format and no new algorithm. Signatures are Ed25519
over the RFC 9421 Section 2.5 signing base with an RFC 9530 `Content-Digest`.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.
