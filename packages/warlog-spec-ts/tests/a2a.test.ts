/**
 * A2A agent attestation (RFC-0005) — cross-language byte equivalence + verify.
 *
 * The golden values below are produced by the Python reference
 * (`warlog_spec.a2a`). The TypeScript impl MUST produce byte-identical
 * canonical bytes and the identical request binding, otherwise a py-signed
 * attestation would not verify in a TS gateway (and vice versa). A
 * transcription guard checks the embedded golden string against the Python
 * sha256 so a copy error is distinguishable from a real canonicalization drift.
 */

import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  A2AAttestation,
  A2AAttestationPayload,
  A2AVerificationError,
  canonicalizeA2aV1,
  computeRequestBinding,
  generateEd25519KeypairPem,
  signA2aAttestation,
  verifyA2aAttestation,
} from "../src/a2a.js";

const PINNED_METHOD = "tools/call";
const PINNED_PARAMS = {
  name: "search_alerts",
  arguments: { q: "lateral movement", limit: 50 },
  _meta: { x: 1 },
};

// --- Golden values from the Python reference --------------------------------
const PY_BINDING =
  "a4cf63634d9502bc2439f745ee97d854ba8cba3c5d703251af07273bd780800b";
const PY_GOLDEN =
  `warlog-spec/v1/a2a-attestation|{"agent":{"agentRunId":"run-root-1",` +
  `"compositionKind":"delegated","model":"claude-opus-4-8",` +
  `"modelVersion":"2026-01-01","reasoningArtifactRef":null,` +
  `"retrievalContextRef":null,"subAgents":[{"agentRunId":"run-sub-7",` +
  `"compositionKind":null,"model":"claude-haiku-4-5","modelVersion":"2026-01-01",` +
  `"reasoningArtifactRef":null,"retrievalContextRef":null,"subAgents":[],` +
  `"systemPromptHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",` +
  `"toolsManifestHash":null}],` +
  `"systemPromptHash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",` +
  `"toolsManifestHash":null},"agentId":"did:web:acme.example#agent-triage-1",` +
  `"audience":"warlog-mcp://tenant-acme","issuedAt":"2026-01-01T12:00:00Z",` +
  `"nonce":"nonce-0001",` +
  `"requestBinding":"a4cf63634d9502bc2439f745ee97d854ba8cba3c5d703251af07273bd780800b"}`;
const PY_GOLDEN_SHA256 =
  "9cd985169edee720e8870c0d9c3884a8280fbaba8e1039f195ad2e75ab4b3df1";

const PINNED_PAYLOAD = A2AAttestationPayload.parse({
  agent: {
    model: "claude-opus-4-8",
    modelVersion: "2026-01-01",
    systemPromptHash: "b".repeat(64),
    agentRunId: "run-root-1",
    compositionKind: "delegated",
    subAgents: [
      {
        model: "claude-haiku-4-5",
        modelVersion: "2026-01-01",
        systemPromptHash: "a".repeat(64),
        agentRunId: "run-sub-7",
      },
    ],
  },
  agentId: "did:web:acme.example#agent-triage-1",
  audience: "warlog-mcp://tenant-acme",
  issuedAt: "2026-01-01T12:00:00Z",
  nonce: "nonce-0001",
  requestBinding: PY_BINDING,
});

describe("A2A cross-language byte equivalence", () => {
  it("the embedded golden matches the Python sha256 (transcription guard)", () => {
    const sha = createHash("sha256")
      .update(Buffer.from(PY_GOLDEN, "utf-8"))
      .digest("hex");
    expect(sha).toEqual(PY_GOLDEN_SHA256);
  });

  it("computeRequestBinding matches the Python golden", () => {
    expect(computeRequestBinding(PINNED_METHOD, PINNED_PARAMS)).toEqual(PY_BINDING);
  });

  it("canonicalizeA2aV1 matches the Python golden bytes", () => {
    expect(canonicalizeA2aV1(PINNED_PAYLOAD).toString("utf-8")).toEqual(PY_GOLDEN);
  });
});

describe("A2A sign / verify round-trip", () => {
  const { privatePem, publicPem } = generateEd25519KeypairPem();
  const now = new Date("2026-01-01T12:00:00Z");
  const att = signA2aAttestation(PINNED_PAYLOAD, {
    privateKeyPem: privatePem,
    keyId: "did:web:acme.example#key-ed25519-1",
  });
  const base = {
    publicKeyPem: publicPem,
    expectedAudience: "warlog-mcp://tenant-acme",
    method: PINNED_METHOD,
    params: PINNED_PARAMS,
    now,
  };

  it("verifies and returns the agent with its delegation chain", () => {
    const agent = verifyA2aAttestation(att, base);
    expect(agent.model).toEqual("claude-opus-4-8");
    expect(agent.compositionKind).toEqual("delegated");
    expect(agent.subAgents?.[0]?.agentRunId).toEqual("run-sub-7");
  });

  it("rejects a forged signature", () => {
    const forged = A2AAttestation.parse({
      ...att,
      signature: { ...att.signature, signatureValue: "0".repeat(128) },
    });
    expect(() => verifyA2aAttestation(forged, base)).toThrow(A2AVerificationError);
  });

  it("rejects an audience mismatch", () => {
    expect(() =>
      verifyA2aAttestation(att, { ...base, expectedAudience: "warlog-mcp://other" }),
    ).toThrow(/audience/);
  });

  it("rejects a request spliced onto a different call", () => {
    expect(() =>
      verifyA2aAttestation(att, { ...base, params: { name: "delete_everything" } }),
    ).toThrow(/request_binding/);
  });

  it("rejects a stale attestation", () => {
    expect(() =>
      verifyA2aAttestation(att, { ...base, now: new Date("2026-01-01T12:10:00Z") }),
    ).toThrow(/too old/);
  });
});

describe("stripMeta / request binding", () => {
  it("the binding is identical regardless of _meta content", () => {
    const a = computeRequestBinding("m", { x: 1, _meta: { a: 1 } });
    const b = computeRequestBinding("m", { x: 1, _meta: { b: 2 } });
    const c = computeRequestBinding("m", { x: 1 });
    expect(a).toEqual(b);
    expect(b).toEqual(c);
  });
});
