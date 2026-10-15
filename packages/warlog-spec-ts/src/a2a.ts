/**
 * A2A (Agent2Agent) agent attestation — verifiable agent identity in transport metadata.
 *
 * TypeScript mirror of `warlog_spec.a2a` (Python). Same wire format
 * (camelCase JSON), same domain-separated canonicalization, so a py-signed
 * attestation verifies in TS and vice versa.
 *
 * An attestation is a signed claim carried in JSON-RPC `_meta`
 * (`params._meta["org.warlog.a2a-attestation/v1"]`) or A2A `Message.metadata`,
 * proving WHICH agent (and its delegation chain) issued a request. A gateway
 * VERIFIES it cryptographically instead of trusting a caller-asserted header.
 *
 * Design (RFC-0005):
 *  - Reuses {@link AiAgentRef} verbatim as the identity payload (already carries
 *    the delegation tree: subAgents, compositionKind, toolsManifestHash).
 *  - {@link A2ASignature} mirrors `AuditAttestation` MINUS `prevRowHash` — an
 *    attestation is standalone, not chained.
 *  - Signed bytes are DOMAIN-SEPARATED: `"warlog-spec/v1/a2a-attestation|" +
 *    canonicalizeV1(payload)`.
 *  - Ed25519 (RFC-0004 keyId semantics), via Node's built-in `crypto`.
 *
 * Anti-replay (nonce) is intentionally NOT done here — it needs shared state
 * (a Redis seen-cache) which is the gateway's concern. The `nonce` is signed,
 * so trustworthy once the signature verifies.
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
} from "node:crypto";

import { z } from "zod";

import { canonicalizeV1 } from "./audit-chain.js";
import { AiAgentRef } from "./provider-abi.js";

export const A2A_ATTESTATION_VERSION = "1.0";

/** Namespaced key the attestation rides under in `params._meta` / A2A `Message.metadata`. */
export const A2A_META_KEY = "org.warlog.a2a-attestation/v1";

/** Extension URI an A2A producer declares in `Message.extensions`. */
export const A2A_EXTENSION_URI = "https://warlog-spec.org/ext/a2a-attestation/v1";

/** Domain-separation prefix (ends with `|`; canonical JSON object follows). */
const A2A_DOMAIN = Buffer.from("warlog-spec/v1/a2a-attestation|", "utf-8");

const HEX64_RE = /^[0-9a-f]{64}$/;
const HEX128_RE = /^[0-9a-f]{128}$/;

export class A2AVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "A2AVerificationError";
  }
}

// ============================================================================
// Wire types (Zod) — strict() to reject smuggled fields (anti-confusion)
// ============================================================================

export const A2ASignature = z
  .object({
    algorithm: z.literal("Ed25519").default("Ed25519"),
    signatureValue: z
      .string()
      .regex(HEX128_RE, "must be 128 lowercase hex chars (Ed25519, 64 bytes)"),
    keyId: z.string().min(1),
    canonicalizationFormat: z.literal("v1").default("v1"),
  })
  .strict();
export type A2ASignature = z.infer<typeof A2ASignature>;

export const A2AAttestationPayload = z
  .object({
    agent: AiAgentRef,
    agentId: z.string().min(1),
    audience: z.string().min(1),
    issuedAt: z.string().datetime({ offset: true }),
    nonce: z.string().min(1),
    requestBinding: z
      .string()
      .regex(HEX64_RE, "must be 64 lowercase hex chars (sha256)"),
  })
  .strict();
export type A2AAttestationPayload = z.infer<typeof A2AAttestationPayload>;

export const A2AAttestation = z
  .object({
    specVersion: z.literal("1.0").default("1.0"),
    payload: A2AAttestationPayload,
    signature: A2ASignature,
  })
  .strict();
export type A2AAttestation = z.infer<typeof A2AAttestation>;

// ============================================================================
// Canonicalization + request binding (shared by signer and verifier)
// ============================================================================

/**
 * Shallow-copy `params` without the top-level `_meta` key. Single source of
 * truth for the request binding; the whole `_meta` key is dropped so no
 * attestation/extension residue leaks into the signed bytes.
 */
export function stripMeta(
  params: Record<string, unknown> | null | undefined,
): Record<string, unknown> {
  if (!params) return {};
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(params)) {
    if (k !== "_meta") out[k] = v;
  }
  return out;
}

/** sha256 hex of `method + "|" + canonicalizeV1(stripMeta(params))`. */
export function computeRequestBinding(
  method: string,
  params: Record<string, unknown> | null | undefined,
): string {
  const canonical = canonicalizeV1(stripMeta(params));
  const buf = Buffer.concat([Buffer.from(method + "|", "utf-8"), canonical]);
  return createHash("sha256").update(buf).digest("hex");
}

/** Domain-separated canonical bytes the Ed25519 signature covers. */
export function canonicalizeA2aV1(payload: A2AAttestationPayload): Buffer {
  return Buffer.concat([A2A_DOMAIN, canonicalizeV1(payload)]);
}

// ============================================================================
// Ed25519 sign / verify (Node built-in crypto)
// ============================================================================

/** Reference/test helper: a fresh Ed25519 keypair as PKCS8 / SPKI PEM. */
export function generateEd25519KeypairPem(): {
  privatePem: string;
  publicPem: string;
} {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" }) as string,
    publicPem: publicKey.export({ type: "spki", format: "pem" }) as string,
  };
}

/** Sign a payload with an Ed25519 private key (PEM) and return the envelope. */
export function signA2aAttestation(
  payload: A2AAttestationPayload,
  opts: { privateKeyPem: string; keyId: string },
): A2AAttestation {
  const parsed = A2AAttestationPayload.parse(payload);
  const key = createPrivateKey(opts.privateKeyPem);
  const signatureValue = cryptoSign(null, canonicalizeA2aV1(parsed), key).toString("hex");
  return A2AAttestation.parse({
    payload: parsed,
    signature: { signatureValue, keyId: opts.keyId },
  });
}

export interface VerifyOptions {
  publicKeyPem: string;
  expectedAudience: string;
  method: string;
  params: Record<string, unknown> | null | undefined;
  now: Date;
  maxAgeSeconds?: number;
}

/**
 * Verify an attestation end-to-end and return the proven {@link AiAgentRef}.
 * Throws {@link A2AVerificationError} on any failed check. Does NOT check the
 * nonce (stateless — the gateway enforces single-use against its own cache).
 */
export function verifyA2aAttestation(
  attestation: A2AAttestation,
  opts: VerifyOptions,
): AiAgentRef {
  const att = A2AAttestation.parse(attestation);
  const maxAge = opts.maxAgeSeconds ?? 300;

  // 1. Signature over the domain-separated canonical bytes.
  const key = createPublicKey(opts.publicKeyPem);
  let ok = false;
  try {
    ok = cryptoVerify(
      null,
      canonicalizeA2aV1(att.payload),
      key,
      Buffer.from(att.signature.signatureValue, "hex"),
    );
  } catch {
    throw new A2AVerificationError("malformed signature encoding");
  }
  if (!ok) {
    throw new A2AVerificationError("Ed25519 signature verification failed");
  }

  // 2. Audience binding.
  if (att.payload.audience !== opts.expectedAudience) {
    throw new A2AVerificationError(
      `audience mismatch: attestation is for '${att.payload.audience}', ` +
        `this verifier is '${opts.expectedAudience}'`,
    );
  }

  // 3. Freshness (both directions to bound clock skew).
  const ageSeconds = (opts.now.getTime() - Date.parse(att.payload.issuedAt)) / 1000;
  if (ageSeconds > maxAge) {
    throw new A2AVerificationError(
      `attestation too old (${ageSeconds.toFixed(0)}s > ${maxAge}s window)`,
    );
  }
  if (ageSeconds < -maxAge) {
    throw new A2AVerificationError(
      `attestation issued_at is in the future beyond tolerance (${(-ageSeconds).toFixed(0)}s)`,
    );
  }

  // 4. Request binding (anti-splice).
  const expectedBinding = computeRequestBinding(opts.method, opts.params);
  if (expectedBinding !== att.payload.requestBinding) {
    throw new A2AVerificationError(
      "request_binding mismatch: attestation is not bound to this request",
    );
  }

  return att.payload.agent;
}
