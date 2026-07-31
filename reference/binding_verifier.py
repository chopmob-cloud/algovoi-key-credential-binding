"""
Reference key-to-credential binding verifier for RFC 9421 signed requests.

RFC 9421 (HTTP Message Signatures) proves that a request was signed by the
holder of *a* key. It does not prove that the key belongs to any particular
issued credential, nor that the request falls within that credential's
authorized scope. RFC 9421 `keyid` is an integrity-protected label; mapping it
to an issued credential and enforcing scope is left to each implementation.

This module adds that missing layer on top of the raw
algovoi-rfc9421-verifier. It evaluates four independent checks:

  key_anchored     The signature-input `keyid` resolves to a key ENROLLED in
                   the presented credential, through a verifier-controlled
                   registry. The public key used for signature verification is
                   taken from the credential, never from the request artifact.
                   `keyid` is a lookup hint into verifier-held material, not a
                   trust-root selector. `jku` / `x5u` / `x5c` are never
                   followed; an unenrolled keyid fails explicitly.

  signature_valid  The raw RFC 9421 + RFC 9530 signature verifies against the
                   credential-resolved public key (delegated to
                   algovoi_rfc9421_verifier.verify_request).

  scope_valid      The request method and path fall within the credential's
                   declared scope.

  credential_valid The credential is active (not revoked) and the request's
                   signed `created` timestamp falls within the credential
                   validity window.

  valid            True only if all four checks hold.

The four checks are deliberately independent so a failure in one is
observable without collapsing into another. See the accompanying vector set
key_credential_binding_v1 for the proving cases.

Apache-2.0. Reference implementation; pairs with algovoi-rfc9421-verifier.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

from algovoi_rfc9421_verifier import verify_request
from algovoi_rfc9421_verifier.parse import parse_signature_input


@dataclass
class BindingResult:
    """Outcome of verify_bound_request.

    `valid` is True only if every check ran and passed. The individual
    dimensions are exposed so a caller can see exactly which invariant a
    request violates.
    """

    valid: bool = False
    key_anchored: bool = False
    signature_valid: bool = False
    scope_valid: bool = False
    credential_valid: bool = False
    resolved_keyid: str = ""
    errors: list[str] = field(default_factory=list)


def _resolve_enrolled_key(
    credential: Mapping[str, Any], keyid: Optional[str]
) -> Optional[Mapping[str, Any]]:
    """Return the enrolled key entry whose keyid matches, or None.

    Resolution is a lookup into the verifier-held credential only. Nothing
    from the request artifact is consulted to locate or fetch key material.
    """
    if keyid is None:
        return None
    for entry in credential.get("enrolled_keys", []):
        if entry.get("keyid") == keyid:
            return entry
    return None


def verify_bound_request(
    request: Mapping[str, Any],
    credential: Mapping[str, Any],
) -> BindingResult:
    """Verify an RFC 9421 request against an issued credential.

    Args:
        request: dict with keys method, authority, path, headers (dict), and
                 body (bytes). Same shape the raw verifier consumes.
        credential: the issued credential the request claims to act under.
                    Shape:
                      {
                        "credential_id": str,
                        "enrolled_keys": [
                          {"keyid": str, "alg": "ed25519", "public_key_hex": str}
                        ],
                        "scope": {"methods": [str], "path_prefixes": [str]},
                        "not_before": int, "not_after": int,
                        "status": "active" | "revoked",
                      }

    Returns:
        BindingResult with the four dimensions and the overall verdict.
    """
    result = BindingResult()

    headers = {k.lower(): v for k, v in request["headers"].items()}
    si_value = headers.get("signature-input")
    if not si_value:
        result.errors.append("signature-input header missing")
        return result

    try:
        parsed = parse_signature_input(si_value)
    except Exception as exc:  # SignatureInputParseError and any malformed input
        result.errors.append(f"signature-input parse error: {exc}")
        return result

    keyid = parsed.parameters.get("keyid")
    created_raw = parsed.parameters.get("created")

    # 1. Key anchoring: keyid MUST resolve to a key enrolled in the credential.
    #    The resolved public key is verifier-controlled material.
    enrolled = _resolve_enrolled_key(credential, keyid)
    if enrolled is None:
        result.errors.append(
            f"keyid {keyid!r} is not enrolled in credential "
            f"{credential.get('credential_id')!r}"
        )
    else:
        result.key_anchored = True
        result.resolved_keyid = keyid

    # 2. Signature: verify against the CREDENTIAL-resolved key, not the artifact.
    #    Only meaningful when a key was anchored; an unanchored request has no
    #    verifier-trusted key to check against and cannot pass.
    if result.key_anchored and enrolled is not None:
        vr = verify_request(
            method=request["method"],
            authority=request["authority"],
            path=request["path"],
            headers=request["headers"],
            body=request["body"],
            public_key=enrolled["public_key_hex"],
        )
        result.signature_valid = vr.valid
        if not vr.valid:
            result.errors.extend(vr.errors)

    # 3. Scope: request method and path must fall within the credential scope.
    scope = credential.get("scope", {})
    methods = scope.get("methods", [])
    prefixes = scope.get("path_prefixes", [])
    result.scope_valid = request["method"] in methods and any(
        request["path"].startswith(p) for p in prefixes
    )
    if not result.scope_valid:
        result.errors.append(
            f"request {request['method']} {request['path']} is outside "
            f"credential scope"
        )

    # 4. Credential validity: active, and the signed `created` is within the
    #    credential validity window. Freshness is bound to the integrity-
    #    protected `created`, not wall-clock, so the check is deterministic.
    active = credential.get("status") == "active"
    in_window = False
    try:
        created = int(created_raw)
        in_window = (
            credential.get("not_before", 0)
            <= created
            <= credential.get("not_after", 1 << 62)
        )
    except (TypeError, ValueError):
        result.errors.append("signature-input `created` missing or non-integer")
    result.credential_valid = active and in_window
    if not active:
        result.errors.append(
            f"credential {credential.get('credential_id')!r} status is "
            f"{credential.get('status')!r}, not active"
        )
    elif not in_window:
        result.errors.append("signed `created` is outside credential validity window")

    result.valid = (
        result.key_anchored
        and result.signature_valid
        and result.scope_valid
        and result.credential_valid
    )
    return result
