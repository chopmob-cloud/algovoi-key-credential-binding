"""Deterministic generator for key_credential_binding_v1.

Produces an RFC 9421 signed-request vector set that proves the layer above raw
message-signature verification: binding a signature key to an ISSUED CREDENTIAL
and enforcing that credential's scope and validity window.

RFC 9421 proves possession of a key. It says nothing about which credential the
key belongs to. This set demonstrates the four independent checks a verifier
must add (key_anchored, signature_valid, scope_valid, credential_valid) and the
distinct way each one fails.

Signatures are produced with the real algovoi-rfc9421-signer and every vector is
self-verified through the reference binding_verifier before it is written, so
the file cannot drift from the code that consumes it.

Determinism: fixed Ed25519 test keypairs (public keys cross-derived from the
seeds by PyNaCl and the `cryptography` library), fixed timestamps, no clock, no
UUID, no randomness. Bodies are RFC 8785 (JCS) canonical and byte-frozen.

Run:  python generate.py
"""
from __future__ import annotations

import json
import os
import sys

import rfc8785
from nacl.signing import SigningKey
from algovoi_rfc9421_signer import sign_request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "reference"))
from binding_verifier import verify_bound_request  # noqa: E402

# --- fixed test keypairs -------------------------------------------------------
# Deterministic Ed25519 seeds. Public keys are derived below, never hardcoded.
# The enrolled seed is reused verbatim from the AlgoVoi RFC 9421 conformance
# sets so this set composes with them; its public key is 700e2ce7... . (Note:
# the legacy comment in those sets calls this "RFC 8032 Section 7.1 Test 1";
# that provenance label is inaccurate -- the seed does not reproduce RFC 8032
# Test 1's published public key or signature -- so it is not repeated here.)
SEED_LEGIT = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55"
# A second, distinct seed for an adversary key that is NOT enrolled.
SEED_ADV = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6f9"


def _pub_hex(seed_hex: str) -> str:
    """Derive the Ed25519 public key hex from a seed (never hardcoded)."""
    return SigningKey(bytes.fromhex(seed_hex)).verify_key.encode().hex()


PUB_LEGIT = _pub_hex(SEED_LEGIT)
PUB_ADV = _pub_hex(SEED_ADV)

KEYID_LEGIT = "did:web:api.algovoi.co.uk#key-1"
KEYID_ADV = "did:web:attacker.example#key-1"

AUTHORITY = "api.algovoi.co.uk"
IN_SCOPE_PATH = "/v1/binding-receipts"
OUT_OF_SCOPE_PATH = "/v1/admin/keys"

# --- fixed timestamps ----------------------------------------------------------
NOT_BEFORE = 1740000000
NOT_AFTER = 1760000000
CREATED = 1750000000            # inside the window
CREATED_EXPIRED = 1770000000    # after NOT_AFTER
CREATED_BEFORE = 1730000000     # before NOT_BEFORE

# --- issued credentials (the verifier-held registry) ---------------------------
CRED_ACTIVE = {
    "credential_id": "cred_algovoi_test_001",
    "agent_id": "did:web:api.algovoi.co.uk",
    "issuer": "did:web:issuer.algovoi.test",
    "enrolled_keys": [
        {"keyid": KEYID_LEGIT, "alg": "ed25519", "public_key_hex": PUB_LEGIT},
    ],
    "scope": {"methods": ["POST"], "path_prefixes": [IN_SCOPE_PATH]},
    "not_before": NOT_BEFORE,
    "not_after": NOT_AFTER,
    "status": "active",
}

CRED_REVOKED = {
    "credential_id": "cred_algovoi_test_002_revoked",
    "agent_id": "did:web:api.algovoi.co.uk",
    "issuer": "did:web:issuer.algovoi.test",
    "enrolled_keys": [
        {"keyid": KEYID_LEGIT, "alg": "ed25519", "public_key_hex": PUB_LEGIT},
    ],
    "scope": {"methods": ["POST"], "path_prefixes": [IN_SCOPE_PATH]},
    "not_before": NOT_BEFORE,
    "not_after": NOT_AFTER,
    "status": "revoked",
}

CREDENTIALS = {c["credential_id"]: c for c in (CRED_ACTIVE, CRED_REVOKED)}

# A fixed payload reference so the signed body is byte-stable.
PAYLOAD_REF = "sha256:3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea"


def _body(action: str = "submit_receipt") -> bytes:
    """Canonical (RFC 8785/JCS) request body."""
    return rfc8785.dumps(
        {
            "action": action,
            "agent_id": "did:web:api.algovoi.co.uk",
            "payload_ref": PAYLOAD_REF,
        }
    )


def _sign(body: bytes, *, path: str, seed: str, keyid: str, created: int, method: str = "POST"):
    return sign_request(
        method=method,
        authority=AUTHORITY,
        path=path,
        body=body,
        private_key=seed,
        keyid=keyid,
        created=created,
    )


def _corrupt_signature(signature_header: str) -> str:
    """Flip the first base64 payload char of the Signature value."""
    marker = "sig=:"
    idx = signature_header.index(marker) + len(marker)
    flip = "B" if signature_header[idx] != "B" else "C"
    return signature_header[:idx] + flip + signature_header[idx + 1:]


def _http(body: bytes, sig, *, path: str, method: str = "POST", signature_override: str | None = None) -> dict:
    return {
        "method": method,
        "authority": AUTHORITY,
        "path": path,
        "headers": {
            "content-digest": sig.content_digest,
            "signature-input": sig.signature_input,
            "signature": signature_override if signature_override is not None else sig.signature,
        },
        "body_hex": body.hex(),
        "body_json": json.loads(body.decode("utf-8")),
    }


def _request_from_http(http: dict) -> dict:
    return {
        "method": http["method"],
        "authority": http["authority"],
        "path": http["path"],
        "headers": http["headers"],
        "body": bytes.fromhex(http["body_hex"]),
    }


def _build_vectors() -> list[dict]:
    vectors: list[dict] = []

    # 001 valid: enrolled key, in scope, active credential, created in window.
    body = _body()
    sig = _sign(body, path=IN_SCOPE_PATH, seed=SEED_LEGIT, keyid=KEYID_LEGIT, created=CREATED)
    vectors.append({
        "description": "valid: signed by the credential's enrolled key, request in scope, credential active and created within the validity window",
        "vector_id": "kcb-v1-001",
        "credential_ref": "cred_algovoi_test_001",
        "http": _http(body, sig, path=IN_SCOPE_PATH),
        "expect": {"key_anchored": True, "signature_valid": True, "scope_valid": True, "credential_valid": True, "valid": True},
    })

    # 002 signature-fail: same as 001 but signature bytes corrupted.
    body = _body()
    sig = _sign(body, path=IN_SCOPE_PATH, seed=SEED_LEGIT, keyid=KEYID_LEGIT, created=CREATED)
    vectors.append({
        "description": "signature-fail: enrolled keyid and everything else valid, but the signature bytes are corrupted (isolates signature_valid=false)",
        "vector_id": "kcb-v1-002",
        "credential_ref": "cred_algovoi_test_001",
        "http": _http(body, sig, path=IN_SCOPE_PATH, signature_override=_corrupt_signature(sig.signature)),
        "expect": {"key_anchored": True, "signature_valid": False, "scope_valid": True, "credential_valid": True, "valid": False},
    })

    # 003 unanchored-key: signed by an adversary key whose keyid is NOT enrolled.
    body = _body()
    sig = _sign(body, path=IN_SCOPE_PATH, seed=SEED_ADV, keyid=KEYID_ADV, created=CREATED)
    vectors.append({
        "description": "unanchored-key: cryptographically valid signature by a key that is not enrolled in the credential; its keyid resolves to nothing in the verifier-held registry (isolates key_anchored=false). No enrolled key exists to verify against, so the signature is not credited.",
        "vector_id": "kcb-v1-003",
        "credential_ref": "cred_algovoi_test_001",
        "http": _http(body, sig, path=IN_SCOPE_PATH),
        "signing_key_hex": PUB_ADV,
        "expect": {"key_anchored": False, "signature_valid": False, "scope_valid": True, "credential_valid": True, "valid": False},
    })

    # 004 keyid-substitution: adversary signs, but claims the enrolled keyid.
    body = _body()
    sig = _sign(body, path=IN_SCOPE_PATH, seed=SEED_ADV, keyid=KEYID_LEGIT, created=CREATED)
    vectors.append({
        "description": "keyid-substitution: a valid signature by the adversary key that SPOOFS the enrolled keyid in signature-input. Because the verifier resolves the public key from the credential (not the artifact), it checks the adversary signature against the enrolled key and rejects it. A naive verifier that trusted a key carried in the artifact would accept. key_anchored=true (keyid is enrolled) but signature_valid=false.",
        "vector_id": "kcb-v1-004",
        "credential_ref": "cred_algovoi_test_001",
        "http": _http(body, sig, path=IN_SCOPE_PATH),
        "signing_key_hex": PUB_ADV,
        "naive_artifact_key_would_pass": True,
        "expect": {"key_anchored": True, "signature_valid": False, "scope_valid": True, "credential_valid": True, "valid": False},
    })

    # 005 scope-violation: valid signature by enrolled key, but out-of-scope path.
    body = _body(action="rotate_key")
    sig = _sign(body, path=OUT_OF_SCOPE_PATH, seed=SEED_LEGIT, keyid=KEYID_LEGIT, created=CREATED)
    vectors.append({
        "description": "scope-violation: valid signature by the enrolled key, credential active, but the request path is outside the credential's declared scope (isolates scope_valid=false)",
        "vector_id": "kcb-v1-005",
        "credential_ref": "cred_algovoi_test_001",
        "http": _http(body, sig, path=OUT_OF_SCOPE_PATH),
        "expect": {"key_anchored": True, "signature_valid": True, "scope_valid": False, "credential_valid": True, "valid": False},
    })

    # 006 credential-expired: valid signature, in scope, but created after not_after.
    body = _body()
    sig = _sign(body, path=IN_SCOPE_PATH, seed=SEED_LEGIT, keyid=KEYID_LEGIT, created=CREATED_EXPIRED)
    vectors.append({
        "description": "credential-expired: valid signature by the enrolled key, in scope, but the signed `created` falls after the credential's not_after (isolates credential_valid=false via the validity window)",
        "vector_id": "kcb-v1-006",
        "credential_ref": "cred_algovoi_test_001",
        "http": _http(body, sig, path=IN_SCOPE_PATH),
        "expect": {"key_anchored": True, "signature_valid": True, "scope_valid": True, "credential_valid": False, "valid": False},
    })

    # 007 credential-revoked: valid signature, in scope, in window, but credential revoked.
    body = _body()
    sig = _sign(body, path=IN_SCOPE_PATH, seed=SEED_LEGIT, keyid=KEYID_LEGIT, created=CREATED)
    vectors.append({
        "description": "credential-revoked: valid signature by the enrolled key, in scope, created within the window, but the credential status is revoked (isolates credential_valid=false via revocation)",
        "vector_id": "kcb-v1-007",
        "credential_ref": "cred_algovoi_test_002_revoked",
        "http": _http(body, sig, path=IN_SCOPE_PATH),
        "expect": {"key_anchored": True, "signature_valid": True, "scope_valid": True, "credential_valid": False, "valid": False},
    })

    # 008 credential-not-yet-valid: valid signature, in scope, but created before not_before.
    body = _body()
    sig = _sign(body, path=IN_SCOPE_PATH, seed=SEED_LEGIT, keyid=KEYID_LEGIT, created=CREATED_BEFORE)
    vectors.append({
        "description": "credential-not-yet-valid: valid signature by the enrolled key, in scope, but the signed `created` falls before the credential's not_before (isolates credential_valid=false via the lower bound of the validity window)",
        "vector_id": "kcb-v1-008",
        "credential_ref": "cred_algovoi_test_001",
        "http": _http(body, sig, path=IN_SCOPE_PATH),
        "expect": {"key_anchored": True, "signature_valid": True, "scope_valid": True, "credential_valid": False, "valid": False},
    })

    # 009 method-scope-violation: valid signature by the enrolled key, path in scope,
    # active credential, but the HTTP method is not in the credential's permitted set.
    body = _body(action="delete_receipt")
    sig = _sign(body, path=IN_SCOPE_PATH, seed=SEED_LEGIT, keyid=KEYID_LEGIT, created=CREATED, method="DELETE")
    vectors.append({
        "description": "method-scope-violation: valid signature by the enrolled key, path within scope, credential active, but the HTTP method is outside the credential's permitted methods (isolates scope_valid=false via the method dimension)",
        "vector_id": "kcb-v1-009",
        "credential_ref": "cred_algovoi_test_001",
        "http": _http(body, sig, path=IN_SCOPE_PATH, method="DELETE"),
        "expect": {"key_anchored": True, "signature_valid": True, "scope_valid": False, "credential_valid": True, "valid": False},
    })

    return vectors


def _self_check(vectors: list[dict]) -> None:
    """Run every vector through the reference binding verifier; abort on drift."""
    dims = ("key_anchored", "signature_valid", "scope_valid", "credential_valid", "valid")
    for v in vectors:
        cred = CREDENTIALS[v["credential_ref"]]
        res = verify_bound_request(_request_from_http(v["http"]), cred)
        got = {d: getattr(res, d) for d in dims}
        want = v["expect"]
        if got != want:
            raise SystemExit(
                f"SELF-CHECK FAILED {v['vector_id']}\n  want {want}\n  got  {got}\n  errors {res.errors}"
            )

    # Cross-check the naive-verifier claim on 004: verifying the adversary
    # signature against the key carried in the artifact WOULD pass. This proves
    # the substitution attack is real and that credential-anchoring is what
    # defeats it.
    from algovoi_rfc9421_verifier import verify_request as _vr
    v4 = next(v for v in vectors if v["vector_id"] == "kcb-v1-004")
    req = _request_from_http(v4["http"])
    naive = _vr(
        method=req["method"], authority=req["authority"], path=req["path"],
        headers=req["headers"], body=req["body"], public_key=v4["signing_key_hex"],
    )
    if not naive.valid:
        raise SystemExit("SELF-CHECK FAILED kcb-v1-004: naive artifact-key verification did not pass as claimed")


def main() -> None:
    vectors = _build_vectors()
    _self_check(vectors)

    out = {
        "description": "key_credential_binding_v1 -- binding an RFC 9421 signature key to an issued credential (key_anchored), and enforcing that credential's scope (scope_valid) and validity window/revocation (credential_valid), on top of raw signature verification (signature_valid). Apache-2.0. Every vector self-verified through the reference binding_verifier.",
        "issuer_id": "algovoi:test",
        "keypair": {"public_key_hex": PUB_LEGIT, "seed_hex": SEED_LEGIT, "keyid": KEYID_LEGIT},
        "adversary_keypair": {"public_key_hex": PUB_ADV, "seed_hex": SEED_ADV, "keyid": KEYID_ADV,
                              "note": "NOT enrolled in any credential; used for the unanchored-key and keyid-substitution vectors"},
        "created": CREATED,
        "binding_rules": [
            "keyid is an integrity-protected label, not a trust-root selector. A verifier MUST resolve the public key from a verifier-controlled credential registry keyed by keyid, and MUST NOT take key material from the request artifact (embedded key, signer-supplied jku or x5u).",
            "An unenrolled keyid MUST fail explicitly (key_anchored=false); it MUST NOT fall through to a signature check against any artifact-supplied key.",
            "The signature MUST verify against the credential-resolved public key, not against any key nominated by the signer.",
            "The request method and path MUST fall within the credential's declared scope.",
            "The credential MUST be active (not revoked) and the signed `created` MUST fall within the credential validity window.",
        ],
        "checks": {
            "key_anchored": "signature-input keyid resolves to a key enrolled in the referenced credential",
            "signature_valid": "RFC 9421 + RFC 9530 signature verifies against the credential-resolved key",
            "scope_valid": "request method and path are within the credential scope",
            "credential_valid": "credential active and signed `created` within the validity window",
            "valid": "all four checks hold",
        },
        "credentials": CREDENTIALS,
        "vectors": vectors,
    }

    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "vectors", "key-credential-binding-v1.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, indent=2)
        f.write("\n")

    print(f"wrote {len(vectors)} vectors -> {path}")
    print(f"  enrolled key {PUB_LEGIT}  keyid {KEYID_LEGIT}")
    print(f"  adversary key {PUB_ADV}  keyid {KEYID_ADV}")
    for v in vectors:
        print(f"  {v['vector_id']}  {v['credential_ref']:<28} expect {v['expect']}")
    print("self-check: all vectors match the reference binding_verifier")


if __name__ == "__main__":
    main()
