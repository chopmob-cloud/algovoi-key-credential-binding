/**
 * Standalone conformance runner (TypeScript) for key_credential_binding_v1.
 *
 * Prints a per-vector PASS/FAIL table and exits 0 only if every vector's five
 * dimensions match its `expect` block. Parity with the Python run_conformance.py.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { verifyBoundRequest, type Credential } from "./src/binding-verifier.js";

const here = dirname(fileURLToPath(import.meta.url)); // dist
const VECTOR_FILE = join(here, "..", "..", "vectors", "key-credential-binding-v1.json");

const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const RESET = "\x1b[0m";

const DIMS = [
  "key_anchored",
  "signature_valid",
  "scope_valid",
  "credential_valid",
  "valid",
] as const;

interface Vector {
  vector_id: string;
  credential_ref: string;
  description: string;
  http: {
    method: string;
    authority: string;
    path: string;
    headers: Record<string, string>;
    body_hex: string;
  };
  expect: Record<string, boolean>;
}

async function main(): Promise<number> {
  const data = JSON.parse(readFileSync(VECTOR_FILE, "utf-8")) as {
    vectors: Vector[];
    credentials: Record<string, Credential>;
  };

  let allOk = true;
  process.stdout.write(`key_credential_binding_v1  (${data.vectors.length} vectors)\n\n`);
  for (const v of data.vectors) {
    const res = await verifyBoundRequest(
      {
        method: v.http.method,
        authority: v.http.authority,
        path: v.http.path,
        headers: v.http.headers,
        body: Buffer.from(v.http.body_hex, "hex"),
      },
      data.credentials[v.credential_ref],
    );
    const got: Record<string, boolean> = {};
    for (const d of DIMS) got[d] = res[d];
    const ok = DIMS.every((d) => got[d] === v.expect[d]);
    allOk = allOk && ok;
    const tag = ok ? `${GREEN}PASS${RESET}` : `${RED}FAIL${RESET}`;
    process.stdout.write(`  ${tag}  ${v.vector_id}  valid=${String(got["valid"])}  ${v.description.slice(0, 60)}\n`);
    if (!ok) {
      process.stdout.write(`        want ${JSON.stringify(v.expect)}\n`);
      process.stdout.write(`        got  ${JSON.stringify(got)}\n`);
      process.stdout.write(`        errors ${res.errors.join("; ")}\n`);
    }
  }

  process.stdout.write("\n");
  if (allOk) {
    process.stdout.write(`${GREEN}ALL GREEN${RESET}  ${data.vectors.length}/${data.vectors.length} vectors match\n`);
    return 0;
  }
  process.stdout.write(`${RED}FAILURES present${RESET}\n`);
  return 1;
}

main().then((code) => process.exit(code));
