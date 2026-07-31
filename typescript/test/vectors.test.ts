/**
 * Vector-driven tests (node:test) for key_credential_binding_v1.
 *
 * Reads the same frozen vector file the Python side consumes and re-verifies
 * every case through the TypeScript reference binding verifier, asserting each
 * of the five dimensions against the vector's `expect` block. This proves the
 * TypeScript verifier and the Python verifier agree on the same vectors.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { verifyBoundRequest, type Credential } from "../src/binding-verifier.js";
import { verifyRequest } from "@algovoi/rfc9421-verifier";

const here = dirname(fileURLToPath(import.meta.url)); // dist/test
const VECTOR_FILE = join(here, "..", "..", "..", "vectors", "key-credential-binding-v1.json");

interface Vector {
  vector_id: string;
  credential_ref: string;
  http: {
    method: string;
    authority: string;
    path: string;
    headers: Record<string, string>;
    body_hex: string;
  };
  signing_key_hex?: string;
  expect: Record<string, boolean>;
}

const data = JSON.parse(readFileSync(VECTOR_FILE, "utf-8")) as {
  vectors: Vector[];
  credentials: Record<string, Credential>;
};
const DIMS = [
  "key_anchored",
  "signature_valid",
  "scope_valid",
  "credential_valid",
  "valid",
] as const;

function request(http: Vector["http"]) {
  return {
    method: http.method,
    authority: http.authority,
    path: http.path,
    headers: http.headers,
    body: Buffer.from(http.body_hex, "hex"),
  };
}

for (const v of data.vectors) {
  test(v.vector_id, async () => {
    const res = await verifyBoundRequest(request(v.http), data.credentials[v.credential_ref]);
    const got: Record<string, boolean> = {};
    for (const d of DIMS) got[d] = res[d];
    assert.deepEqual(
      got,
      v.expect,
      `${v.vector_id}: ${JSON.stringify(got)} != ${JSON.stringify(v.expect)} (${res.errors.join("; ")})`,
    );
  });
}

test("kcb-v1-004 naive artifact-key verification would pass", async () => {
  // The substitution attack is real: verifying the adversary signature against
  // the key carried in the artifact (naive behavior) passes. Credential
  // anchoring is what defeats it.
  const v = data.vectors.find((x) => x.vector_id === "kcb-v1-004");
  assert.ok(v && v.signing_key_hex, "vector 004 must carry signing_key_hex");
  const r = request(v.http);
  const vr = await verifyRequest({
    method: r.method,
    authority: r.authority,
    path: r.path,
    headers: r.headers,
    body: r.body,
    publicKey: v.signing_key_hex,
  });
  assert.equal(vr.valid, true, "naive artifact-key verification should pass as claimed");
});
