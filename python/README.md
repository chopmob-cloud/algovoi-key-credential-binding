# algovoi-key-credential-binding (Python)

Reference verifier for binding an RFC 9421 HTTP Message Signature key to an
issued agent credential. Layered on
[algovoi-rfc9421-verifier](https://pypi.org/project/algovoi-rfc9421-verifier/).

RFC 9421 proves a request was signed by the holder of a key. It does not prove
which credential that key belongs to, nor that the request is within the
credential's scope. This package adds that layer and evaluates four independent
checks: `key_anchored`, `signature_valid`, `scope_valid`, `credential_valid`.

The public key is resolved from the credential (keyed by `keyid`), never from
the request artifact. See the
[repository](https://github.com/chopmob-cloud/algovoi-key-credential-binding)
for `SPEC.md` (normative rules) and the language-neutral conformance vector set.

## Install

```
pip install algovoi-key-credential-binding
```

## Usage

```python
from algovoi_key_credential_binding import verify_bound_request

credential = {
    "credential_id": "cred_001",
    "enrolled_keys": [
        {"keyid": "did:web:api.example#key-1", "alg": "ed25519",
         "public_key_hex": "700e2ce7..."},
    ],
    "scope": {"methods": ["POST"], "path_prefixes": ["/v1/binding-receipts"]},
    "not_before": 1740000000,
    "not_after": 1760000000,
    "status": "active",
}

request = {
    "method": "POST",
    "authority": "api.example",
    "path": "/v1/binding-receipts",
    "headers": {  # content-digest, signature-input, signature
        "content-digest": "sha-256=:...:",
        "signature-input": 'sig=(...);created=...;keyid="did:web:api.example#key-1";alg="ed25519"',
        "signature": "sig=:...:",
    },
    "body": b"...",
}

result = verify_bound_request(request, credential)
# result.valid, result.key_anchored, result.signature_valid,
# result.scope_valid, result.credential_valid, result.errors
```

## Develop

```
pip install -e .[dev]
python generate.py          # regenerate + self-verify the vectors
python run_conformance.py    # GREEN/RED table, exit 0 iff all pass
python -m pytest tests/ -q
```

## License

Apache-2.0.
