/**
 * Reference key-to-credential binding verifier for RFC 9421 signed requests
 * (TypeScript). Behavioral parity with the Python reference implementation
 * reference/binding_verifier.py.
 *
 * RFC 9421 proves a request was signed by the holder of a key. It does not
 * prove which credential that key belongs to, nor that the request is within
 * the credential's authorized scope. This module adds that layer on top of the
 * raw @algovoi/rfc9421-verifier and evaluates four independent checks:
 *
 *   key_anchored      signature-input keyid resolves to a key ENROLLED in the
 *                     presented credential, via a verifier-controlled registry;
 *                     the public key is taken from the credential, never from
 *                     the request artifact. keyid is a lookup hint, not a
 *                     trust-root selector; jku / x5u / x5c are never followed.
 *   signature_valid   raw RFC 9421 + RFC 9530 signature verifies against the
 *                     credential-resolved key.
 *   scope_valid       request method and path are within the credential scope.
 *   credential_valid  credential is active and the signed `created` is within
 *                     the credential validity window.
 *   valid             all four hold.
 *
 * Apache-2.0.
 */

import { webcrypto } from "node:crypto";
import { verifyRequest, parseSignatureInput } from "@algovoi/rfc9421-verifier";

// Node-version compatibility shim. @noble/ed25519 v2 (used transitively by
// @algovoi/rfc9421-verifier) reaches for crypto.subtle during async hashing.
// Node >= 20 exposes globalThis.crypto by default; Node 18 does not, and the
// verifier swallows the resulting throw as a false verification. Providing the
// WebCrypto global on Node 18 makes signature verification behave identically
// across Node 18, 20, and 22. No-op where globalThis.crypto already exists.
if (typeof (globalThis as { crypto?: unknown }).crypto === "undefined") {
  (globalThis as { crypto?: unknown }).crypto = webcrypto;
}

export interface EnrolledKey {
  keyid: string;
  alg: string;
  public_key_hex: string;
}

export interface Credential {
  credential_id: string;
  enrolled_keys: EnrolledKey[];
  scope: { methods: string[]; path_prefixes: string[] };
  not_before: number;
  not_after: number;
  status: string;
  [key: string]: unknown;
}

export interface BoundRequest {
  method: string;
  authority: string;
  path: string;
  headers: Record<string, string>;
  body: Uint8Array | Buffer;
}

export interface BindingResult {
  valid: boolean;
  key_anchored: boolean;
  signature_valid: boolean;
  scope_valid: boolean;
  credential_valid: boolean;
  resolved_keyid: string;
  errors: string[];
}

function resolveEnrolledKey(
  credential: Credential,
  keyid: string | undefined,
): EnrolledKey | undefined {
  if (keyid === undefined) return undefined;
  return credential.enrolled_keys.find((k) => k.keyid === keyid);
}

export async function verifyBoundRequest(
  request: BoundRequest,
  credential: Credential,
): Promise<BindingResult> {
  const result: BindingResult = {
    valid: false,
    key_anchored: false,
    signature_valid: false,
    scope_valid: false,
    credential_valid: false,
    resolved_keyid: "",
    errors: [],
  };

  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(request.headers)) {
    headers[k.toLowerCase()] = v;
  }
  const siValue = headers["signature-input"];
  if (!siValue) {
    result.errors.push("signature-input header missing");
    return result;
  }

  let parsed;
  try {
    parsed = parseSignatureInput(siValue);
  } catch (e) {
    result.errors.push(`signature-input parse error: ${(e as Error).message}`);
    return result;
  }

  const keyidRaw = parsed.parameters["keyid"];
  const keyid = typeof keyidRaw === "string" ? keyidRaw : undefined;
  const createdRaw = parsed.parameters["created"];

  // 1. Key anchoring: keyid MUST resolve to a key enrolled in the credential.
  //    The resolved public key is verifier-controlled material.
  const enrolled = resolveEnrolledKey(credential, keyid);
  if (enrolled === undefined) {
    result.errors.push(
      `keyid ${JSON.stringify(keyidRaw)} is not enrolled in credential ` +
        `${JSON.stringify(credential.credential_id)}`,
    );
  } else {
    result.key_anchored = true;
    result.resolved_keyid = enrolled.keyid;
  }

  // 2. Signature: verify against the CREDENTIAL-resolved key, not the artifact.
  if (result.key_anchored && enrolled !== undefined) {
    const vr = await verifyRequest({
      method: request.method,
      authority: request.authority,
      path: request.path,
      headers: request.headers,
      body: request.body,
      publicKey: enrolled.public_key_hex,
    });
    result.signature_valid = vr.valid;
    if (!vr.valid) result.errors.push(...vr.errors);
  }

  // 3. Scope: request method and path must fall within the credential scope.
  const scope = credential.scope ?? { methods: [], path_prefixes: [] };
  result.scope_valid =
    scope.methods.includes(request.method) &&
    scope.path_prefixes.some((p) => request.path.startsWith(p));
  if (!result.scope_valid) {
    result.errors.push(
      `request ${request.method} ${request.path} is outside credential scope`,
    );
  }

  // 4. Credential validity: active, and signed `created` within the window.
  const active = credential.status === "active";
  let inWindow = false;
  const created =
    typeof createdRaw === "number" ? createdRaw : Number(createdRaw);
  if (Number.isInteger(created)) {
    inWindow =
      (credential.not_before ?? 0) <= created &&
      created <= (credential.not_after ?? Number.MAX_SAFE_INTEGER);
  } else {
    result.errors.push("signature-input `created` missing or non-integer");
  }
  result.credential_valid = active && inWindow;
  if (!active) {
    result.errors.push(
      `credential ${JSON.stringify(credential.credential_id)} status is ` +
        `${JSON.stringify(credential.status)}, not active`,
    );
  } else if (!inWindow) {
    result.errors.push("signed `created` is outside credential validity window");
  }

  result.valid =
    result.key_anchored &&
    result.signature_valid &&
    result.scope_valid &&
    result.credential_valid;
  return result;
}
