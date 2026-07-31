# Key-to-credential binding for RFC 9421 signed requests

Status: draft, reference. Normative language uses RFC 2119 / RFC 8174 terms.

## 1. Scope

RFC 9421 (HTTP Message Signatures) establishes that a request was signed by the
holder of a key selected by the verifier. It does not define how that key is
bound to an issued credential, nor how a credential's authorization scope is
enforced. This document specifies that binding as a set of checks a verifier
applies after a successful RFC 9421 signature verification, and pins the
behavior with the `key_credential_binding_v1` vectors.

It introduces no new signature format and no new algorithm. It constrains how a
verifier selects the key it verifies against, and what it does with the result.

## 2. Terms

- **Credential**: a verifier-trusted record that enrolls one or more keys for a
  subject (an agent), together with an authorization scope and a validity
  window. Held by the verifier and obtained through a path the verifier
  controls, out of band from any request under verification.
- **Enrolled key**: a `(keyid, algorithm, public key)` entry inside a
  credential.
- **Artifact**: the request under verification, including its signature headers
  and body. Untrusted input from the signer.

## 3. Key anchoring

3.1. `keyid` carried in a request's signature parameters is an
integrity-protected label. A verifier MUST treat it as a lookup hint into a
verifier-controlled credential registry, and MUST NOT treat it as an
instruction to fetch or locate key material.

3.2. A verifier MUST resolve the public key used for signature verification
from an enrolled key inside the credential the request claims to act under. A
verifier MUST NOT use key material carried in, or nominated by, the artifact.
This includes an embedded public key, a signer-supplied `jku` (JWK Set URL), or
a signer-supplied `x5u` (X.509 URL). The same constraint applies to any future
parameter that would let the signer select where key material is fetched from.

3.3. If the `keyid` does not resolve to an enrolled key in the referenced
credential, the request MUST fail with `key_anchored=false`. It MUST NOT fall
through to a signature check against any key supplied by the artifact.

Rationale. A valid signature only proves possession of the private key
corresponding to the key the verifier selected. It does not prove the verifier
selected that key through a verifier-controlled trust path. If the artifact can
choose its own key source, it can nominate its own trust root, and a fabricated
request verifies cleanly. Resolving the key from the credential keeps the trust
root under verifier control.

## 4. Signature

4.1. The signature MUST verify, per RFC 9421 and RFC 9530, against the
credential-resolved public key from Section 3, and against no other key.

4.2. `key_anchored=true` with `signature_valid=false` is the correct outcome
when a request presents an enrolled `keyid` but is signed by a different key
(key substitution). The verifier MUST reject it. It MUST NOT accept the request
on the basis of any key the artifact supplies.

## 5. Scope

5.1. A credential declares an authorization scope. This document models scope as
a set of permitted methods and a set of permitted path prefixes. A verifier
MUST confirm the request method and path fall within the credential scope
before treating the request as authorized (`scope_valid`).

5.2. Scope is a property of the credential, evaluated by the verifier. It MUST
NOT be derived from any field the artifact supplies.

## 6. Credential validity

6.1. A verifier MUST confirm the credential is active (not revoked) at the time
the request is evaluated (`credential_valid`).

6.2. A verifier MUST confirm the request's signed `created` falls within the
credential validity window (`not_before <= created <= not_after`). Binding
freshness to the integrity-protected `created` keeps the check independent of
unsynchronized clocks for conformance purposes; a deployment MAY additionally
enforce wall-clock freshness.

6.3. Revocation and expiry are the same dimension: both produce
`credential_valid=false`. A standardized, offline-checkable revocation
reference (a status list, or an OCSP-style responder) lets a policy enforcement
point evaluate 6.1 without a bespoke per-issuer format.

## 7. Verdict

7.1. A request is bound and authorized (`valid=true`) only if all four checks
hold: `key_anchored`, `signature_valid`, `scope_valid`, and `credential_valid`.

7.2. A verifier SHOULD expose the four dimensions individually, not only the
combined verdict, so a relying party can distinguish an unenrolled key from a
scope violation from an expired credential.

## 8. Conformance

An implementation conforms if, for every vector in
`key-credential-binding-v1.json`, it reproduces the vector's `expect` block for
all five fields when the request is evaluated against the referenced
credential. The reference verifier in `reference/binding_verifier.py` is one
such implementation.
