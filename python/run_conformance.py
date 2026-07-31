"""Standalone conformance runner for key_credential_binding_v1.

Prints a per-vector GREEN/RED table and exits 0 only if every vector's five
dimensions match its `expect` block. No pytest dependency; suitable for CI or a
quick local check.

Run:  python run_conformance.py
"""
from __future__ import annotations

import json
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
from algovoi_key_credential_binding.binding_verifier import verify_bound_request  # noqa: E402

VECTOR_FILE = os.path.join(_HERE, "..", "vectors", "key-credential-binding-v1.json")
DIMS = ("key_anchored", "signature_valid", "scope_valid", "credential_valid", "valid")

GREEN = "\033[32m"
RED = "\033[31m"
RESET = "\033[0m"


def _request(http: dict) -> dict:
    return {
        "method": http["method"],
        "authority": http["authority"],
        "path": http["path"],
        "headers": http["headers"],
        "body": bytes.fromhex(http["body_hex"]),
    }


def main() -> int:
    with open(VECTOR_FILE, encoding="utf-8") as f:
        data = json.load(f)
    creds = data["credentials"]

    all_ok = True
    print(f"key_credential_binding_v1  ({len(data['vectors'])} vectors)\n")
    for v in data["vectors"]:
        cred = creds[v["credential_ref"]]
        res = verify_bound_request(_request(v["http"]), cred)
        got = {d: getattr(res, d) for d in DIMS}
        ok = got == v["expect"]
        all_ok = all_ok and ok
        tag = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
        print(f"  {tag}  {v['vector_id']}  valid={str(got['valid']):<5}  {v['vector_id']} {v['description'][:60]}")
        if not ok:
            print(f"        want {v['expect']}")
            print(f"        got  {got}")
            print(f"        errors {res.errors}")

    print()
    if all_ok:
        print(f"{GREEN}ALL GREEN{RESET}  {len(data['vectors'])}/{len(data['vectors'])} vectors match")
        return 0
    print(f"{RED}FAILURES present{RESET}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
