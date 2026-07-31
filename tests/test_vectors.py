"""Vector-driven tests for key_credential_binding_v1.

Reads the frozen vector file and re-verifies every case through the reference
binding verifier, asserting each of the five dimensions against the vector's
`expect` block. This proves the published vectors match the code that consumes
them; it does not re-sign anything.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "reference"))
from binding_verifier import verify_bound_request  # noqa: E402

VECTOR_FILE = os.path.join(_ROOT, "vectors", "key-credential-binding-v1.json")
DIMS = ("key_anchored", "signature_valid", "scope_valid", "credential_valid", "valid")


def _load():
    with open(VECTOR_FILE, encoding="utf-8") as f:
        return json.load(f)


_DATA = _load()
_CREDS = _DATA["credentials"]


def _request(http: dict) -> dict:
    return {
        "method": http["method"],
        "authority": http["authority"],
        "path": http["path"],
        "headers": http["headers"],
        "body": bytes.fromhex(http["body_hex"]),
    }


@pytest.mark.parametrize("vector", _DATA["vectors"], ids=[v["vector_id"] for v in _DATA["vectors"]])
def test_vector(vector):
    cred = _CREDS[vector["credential_ref"]]
    result = verify_bound_request(_request(vector["http"]), cred)
    got = {d: getattr(result, d) for d in DIMS}
    assert got == vector["expect"], f"{vector['vector_id']}: {got} != {vector['expect']} ({result.errors})"


def test_body_hex_matches_content_digest():
    """The body_hex in each vector is the exact bytes covered by Content-Digest."""
    import base64
    import hashlib
    for v in _DATA["vectors"]:
        body = bytes.fromhex(v["http"]["body_hex"])
        cd = v["http"]["headers"]["content-digest"]
        b64 = cd.split("sha-256=:", 1)[1].rstrip(":")
        assert hashlib.sha256(body).digest() == base64.b64decode(b64), v["vector_id"]


def test_independence():
    """Independence of the check dimensions.

    key_anchored and signature_valid are coupled in one direction only: an
    unanchored key leaves no verifier-trusted key to check a signature against,
    so key_anchored=false necessarily carries signature_valid=false. The
    meaningful independence claims are therefore:

      * signature_valid fails while every other check passes (002, 004),
      * scope_valid fails while every other check passes (005),
      * credential_valid fails while every other check passes (006, 007),
      * key_anchored is demonstrated false in at least one vector (003).
    """
    def sole_failure(dim):
        return any(
            not v["expect"][dim]
            and all(v["expect"][d] for d in DIMS if d not in (dim, "valid"))
            for v in _DATA["vectors"]
        )

    assert sole_failure("signature_valid"), "no vector isolates signature_valid"
    assert sole_failure("scope_valid"), "no vector isolates scope_valid"
    assert sole_failure("credential_valid"), "no vector isolates credential_valid"
    assert any(not v["expect"]["key_anchored"] for v in _DATA["vectors"]), "no vector exercises key_anchored=false"
