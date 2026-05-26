/**
 * Audit chain — canonicalization + HMAC primitives.
 *
 * MUST produce byte-identical output to `warlog_spec.audit_chain`
 * in the Python package. Cross-language equivalence is what makes
 * a `SignedAuditRow` verifiable regardless of which implementation
 * signed it.
 *
 * Canonicalization v1 :
 *   - sorted-keys JSON
 *   - compact separators ("," and ":")
 *   - UTF-8 encoded
 *   - no whitespace, no ensure_ascii (allow Unicode through verbatim)
 *
 * Equivalent Python : `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`.
 */

import { createHmac } from "node:crypto";

export const CANONICALIZATION_FORMAT_V1 = "v1";

const GENESIS_SALT = Buffer.from("warlog-spec/v1.0/audit-chain/genesis", "utf-8");

/**
 * Recursively sort dict keys lexicographically before JSON-stringify.
 *
 * Critical : `JSON.stringify(obj)` in Node uses insertion order on
 * objects, which does NOT match Python's `sort_keys=True`. We must
 * walk the tree and sort manually.
 *
 * Arrays preserve order (ordered semantically), only objects sort.
 */
function sortKeysDeep(value: unknown): unknown {
  if (value === null || typeof value !== "object") {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(sortKeysDeep);
  }
  // Plain object — sort keys lexicographically.
  const sorted: Record<string, unknown> = {};
  const keys = Object.keys(value as Record<string, unknown>).sort();
  for (const k of keys) {
    sorted[k] = sortKeysDeep((value as Record<string, unknown>)[k]);
  }
  return sorted;
}

/**
 * v1 canonicalization : sorted-keys JSON, compact, UTF-8 bytes.
 *
 * Input is the camelCase-serialized form of an AuditRow (or any
 * canonical artifact). Output is the exact bytes that get
 * HMAC-signed.
 *
 * Equivalent to Python's :
 *     json.dumps(row.model_dump(mode="json", by_alias=True),
 *                sort_keys=True,
 *                separators=(",", ":"),
 *                ensure_ascii=False).encode("utf-8")
 */
export function canonicalizeV1(value: unknown): Buffer {
  const sorted = sortKeysDeep(value);
  // JSON.stringify with no spaces matches Python's compact separators.
  const jsonStr = JSON.stringify(sorted);
  return Buffer.from(jsonStr, "utf-8");
}

/**
 * Per-tenant genesis hash — what the first row's `prev_row_hash`
 * points at. Equivalent to Python's :
 *     hmac.new(secret, GENESIS_SALT + tenant_id.encode("utf-8"), hashlib.sha256).hexdigest()
 */
export function computeGenesis(tenantId: string, secret: Buffer): string {
  const h = createHmac("sha256", secret);
  h.update(GENESIS_SALT);
  h.update(Buffer.from(tenantId, "utf-8"));
  return h.digest("hex");
}

/**
 * HMAC-SHA256 over (prev_hash || "|" || canonical_bytes).
 *
 * Equivalent to Python's :
 *     hmac.new(secret, (prev_hash + "|").encode("utf-8") + canonical_bytes,
 *              hashlib.sha256).hexdigest()
 *
 * Note the `|` separator between prev_hash and canonical_bytes —
 * matches the Python implementation's wire-format.
 */
export function computeSignature(
  prevHash: string,
  canonicalBytes: Buffer,
  secret: Buffer,
): string {
  const h = createHmac("sha256", secret);
  h.update(Buffer.from(prevHash + "|", "utf-8"));
  h.update(canonicalBytes);
  return h.digest("hex");
}

/**
 * Verify a signed row given its predecessor.
 *
 * Returns true when the recomputed HMAC matches `signature` ; false
 * otherwise. The canonical bytes are recomputed from `payload`
 * (matching the Python verifier's behaviour) — to verify against
 * stored canonical bytes instead, callers MUST pass the stored
 * bytes to `computeSignature` directly.
 */
export function verifySignature(
  payload: unknown,
  prevHash: string,
  signature: string,
  secret: Buffer,
): boolean {
  const canonical = canonicalizeV1(payload);
  const recomputed = computeSignature(prevHash, canonical, secret);
  return recomputed === signature;
}

/**
 * Pure sha256 hex digest. Useful for content_hash of decision /
 * trigger artifacts that an AuditRow points at — same recipe as
 * the Python store : sha256 of the canonical-bytes serialization.
 */
export function sha256Hex(canonicalBytes: Buffer): string {
  const { createHash } = require("node:crypto") as typeof import("node:crypto");
  return createHash("sha256").update(canonicalBytes).digest("hex");
}
