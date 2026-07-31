"""algovoi-key-credential-binding: bind an RFC 9421 signature key to a credential.

Reference verifier that layers key-to-credential anchoring, scope, and
credential-validity checks on top of the raw signature verification provided by
algovoi-rfc9421-verifier. See the repository README and SPEC.md for the
normative binding rules and the accompanying conformance vector set.

Apache-2.0.
"""
from algovoi_key_credential_binding.binding_verifier import (
    BindingResult,
    verify_bound_request,
)

__version__ = "0.1.0"

__all__ = ["BindingResult", "verify_bound_request"]
