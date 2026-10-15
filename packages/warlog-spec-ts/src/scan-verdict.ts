/**
 * Content scan verdict — a portable, signed record of what a guardrail saw.
 *
 * TypeScript mirror of `warlog_spec.scan_verdict` (Python). Same wire format
 * (camelCase JSON), same domain-separated canonicalization, so a py-signed
 * verdict verifies in TS and vice versa.
 *
 * A verdict is the artifact an operator hands to an auditor, a regulator or an
 * insurer to answer "you say your guardrail runs — show me", without handing
 * over the traffic itself.
 *
 * Design (RFC-0006):
 *  - A sibling of {@link A2AAttestation}, NOT an AuditRow: an audit row requires
 *    an actionId from a closed enum, a subject, a phase, a connector and an
 *    idempotencyKey, none of which a verdict has.
 *  - The content is BOUND, never carried: `contentBinding` is a
 *    domain-separated sha256 of the scanned bytes. A record that quoted the
 *    matched bytes would leak exactly the secret it flagged.
 *  - The GATEWAY signs; the detector is named. A detector reports a finding, it
 *    does not choose an outcome, so a detector signature could not legitimately
 *    cover `disposition`.
 *  - The verdict joins the attestation on the same `requestBinding`, so two
 *    independent signatures provably describe one call.
 *
 * NO FLOATS in the canonical bytes. `JSON.stringify(1.0)` is `"1"` here and
 * `json.dumps(1.0)` is `"1.0"` in Python: a score of exactly 1.0 or 0.0 would
 * break byte-equivalence and the signature would fail in a way that looks like
 * tampering. Scores and thresholds are integer thousandths.
 *
 * Unlike A2A there is no freshness window and no audience: a verdict is a
 * record, not a capability. Age does not weaken it, and presenting it elsewhere
 * gains an attacker nothing.
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
} from "node:crypto";

import { z } from "zod";

import { canonicalizeV1 } from "./audit-chain.js";

export const SCAN_VERDICT_VERSION = "1.0";

/** Domain-separation prefix for the signed bytes (ends with `|`). */
const SCAN_VERDICT_DOMAIN = Buffer.from("warlog-spec/v1/scan-verdict|", "utf-8");

/** Domain-separation prefix for {@link computeContentBinding}. Separate from the
 *  signing domain so a crafted payload cannot be presented as a content binding. */
const SCAN_CONTENT_DOMAIN = Buffer.from("warlog-spec/v1/scan-content|", "utf-8");

const HEX64_RE = /^[0-9a-f]{64}$/;
const HEX128_RE = /^[0-9a-f]{128}$/;

/**
 * Where in the agent's traffic the scanned bytes came from.
 *
 * `mcp_tool_manifest` is the one entry that is not a message in a conversation:
 * it is the server's advertised capability, the tool descriptions a model reads
 * as trusted context, and it is where Tool Poisoning lives because the payload
 * is metadata rather than traffic. Its `content` for {@link computeContentBinding}
 * is specified in RFC-0006 — the CANONICAL tool-list bytes, not the raw frame,
 * because MCP fixes neither the order of the `tools` array nor the serialisation
 * of each entry, and two proxies must not produce two bindings for one manifest.
 */
export const SCAN_SURFACES = [
  "llm_request",
  "llm_response",
  "mcp_tool_args",
  "mcp_tool_result",
  "mcp_resource_result",
  "mcp_tool_manifest",
] as const;

export class ScanVerdictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ScanVerdictError";
  }
}

// ============================================================================
// Wire types (Zod) — strict() to reject smuggled fields (anti-confusion)
// ============================================================================

export const ScanVerdictSignature = z
  .object({
    algorithm: z.literal("Ed25519").default("Ed25519"),
    signatureValue: z
      .string()
      .regex(HEX128_RE, "must be 128 lowercase hex chars (Ed25519, 64 bytes)"),
    /** The GATEWAY's key, not the detector's. */
    keyId: z.string().min(1),
    canonicalizationFormat: z.literal("v1").default("v1"),
  })
  .strict();
export type ScanVerdictSignature = z.infer<typeof ScanVerdictSignature>;

export const ScanVerdictPayload = z
  .object({
    verdictId: z.string().min(1),
    tenantRef: z.string().min(1),
    /** null = the caller was unattested, which is a fact, not a missing field. */
    agentId: z.string().min(1).nullable().default(null),
    requestBinding: z.string().regex(HEX64_RE).nullable().default(null),
    surface: z.enum(SCAN_SURFACES),
    direction: z.enum(["egress", "ingress"]),
    detector: z.string().min(1),
    detectorVersion: z.string().min(1),
    detectorKind: z.enum(["deterministic", "model"]),
    /** Category only. NEVER the matched bytes, offsets, or any excerpt. */
    finding: z.string().min(1).nullable().default(null),
    /** Thousandths (873 = 0.873). Integer: see the module note on floats. */
    scoreMilli: z.number().int().min(0).max(1000).nullable().default(null),
    thresholdMilli: z.number().int().min(0).max(1000).nullable().default(null),
    contentBinding: z.string().regex(HEX64_RE, "must be 64 lowercase hex chars (sha256)"),
    disposition: z.enum(["observed", "refused"]),
    scannedAt: z.string().datetime({ offset: true }),
  })
  .strict()
  .superRefine((v, ctx) => {
    // The combinations a reader could reasonably misinterpret. Enforced at the
    // wire format because it is the last place able to refuse them.
    if (v.detectorKind === "deterministic" && (v.scoreMilli !== null || v.thresholdMilli !== null)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          "a deterministic detector cannot report a score or a threshold: a rule either matched or it did not",
      });
    }
    if (v.detectorKind === "model" && (v.scoreMilli === null || v.thresholdMilli === null)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          "a model detector must report both its score and the threshold it was compared against, or its verdict cannot be re-derived",
      });
    }
    if (v.disposition === "refused" && v.finding === null) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "a call cannot be refused on a clean verdict",
      });
    }
  });
export type ScanVerdictPayload = z.infer<typeof ScanVerdictPayload>;

export const ScanVerdict = z
  .object({
    specVersion: z.literal("1.0").default("1.0"),
    payload: ScanVerdictPayload,
    signature: ScanVerdictSignature,
  })
  .strict();
export type ScanVerdict = z.infer<typeof ScanVerdict>;

// ============================================================================
// Content binding + canonicalization (shared by signer and verifier)
// ============================================================================

/**
 * sha256 hex of `domain + surface + "|" + content`.
 *
 * Binds a verdict to the exact bytes examined WITHOUT carrying them. The
 * surface is mixed in so a binding over a tool result cannot be presented as
 * one over a request body. Deliberately independent of the detector: two
 * detectors over the same bytes produce the same binding, which is what lets
 * their verdicts be correlated by a third party holding neither.
 */
export function computeContentBinding(surface: string, content: string): string {
  const buf = Buffer.concat([
    SCAN_CONTENT_DOMAIN,
    Buffer.from(surface + "|", "utf-8"),
    Buffer.from(content, "utf-8"),
  ]);
  return createHash("sha256").update(buf).digest("hex");
}

/** Domain-separated canonical bytes the Ed25519 signature covers. */
export function canonicalizeScanVerdictV1(payload: ScanVerdictPayload): Buffer {
  return Buffer.concat([SCAN_VERDICT_DOMAIN, canonicalizeV1(payload)]);
}

// ============================================================================
// Ed25519 sign / verify (Node built-in crypto)
// ============================================================================

/** Sign a payload with the GATEWAY's Ed25519 private key (PEM). */
export function signScanVerdict(
  payload: ScanVerdictPayload,
  opts: { privateKeyPem: string; keyId: string },
): ScanVerdict {
  const parsed = ScanVerdictPayload.parse(payload);
  const key = createPrivateKey(opts.privateKeyPem);
  const signatureValue = cryptoSign(null, canonicalizeScanVerdictV1(parsed), key).toString("hex");
  return ScanVerdict.parse({
    payload: parsed,
    signature: { signatureValue, keyId: opts.keyId },
  });
}

/**
 * Verify a verdict and return its payload. Throws {@link ScanVerdictError}.
 *
 * `expectedContent` is optional because the interesting case is the verifier
 * who does NOT hold the traffic: an auditor can establish that a gateway signed
 * this statement without ever being shown what was scanned. Supplying the
 * content upgrades that to proof the statement is about it.
 */
export function verifyScanVerdict(
  verdict: ScanVerdict,
  opts: { publicKeyPem: string; expectedContent?: string },
): ScanVerdictPayload {
  const parsed = ScanVerdict.parse(verdict);

  const key = createPublicKey(opts.publicKeyPem);
  let ok = false;
  try {
    ok = cryptoVerify(
      null,
      canonicalizeScanVerdictV1(parsed.payload),
      key,
      Buffer.from(parsed.signature.signatureValue, "hex"),
    );
  } catch {
    throw new ScanVerdictError("malformed signature encoding");
  }
  if (!ok) {
    throw new ScanVerdictError("Ed25519 signature verification failed");
  }

  if (opts.expectedContent !== undefined) {
    const expected = computeContentBinding(parsed.payload.surface, opts.expectedContent);
    if (expected !== parsed.payload.contentBinding) {
      throw new ScanVerdictError(
        "contentBinding mismatch: this verdict is not about the content supplied " +
          "(different bytes, or a different surface)",
      );
    }
  }

  return parsed.payload;
}
