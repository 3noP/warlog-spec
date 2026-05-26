/**
 * Cross-language byte equivalence : canonicalize_v1 in TypeScript MUST
 * produce the same bytes as in Python for the same input.
 *
 * The pinned audit row below mirrors
 * `packages/warlog-spec-py/tests/test_canonical_row_bytes.py`.
 * Its `_GOLDEN` value is the Python output ; we compare byte-for-byte.
 * Run `pytest` on the Python side and `npm test` here — both pin the
 * same 900-byte output (sha256
 * 75f5a2f740a505d0f68f10b456470f9be9d5e431de08950eb1c48828bb4267f3).
 */

import { describe, expect, it } from "vitest";

import {
  CANONICALIZATION_FORMAT_V1,
  canonicalizeV1,
  computeGenesis,
  computeSignature,
} from "../src/audit-chain.js";

// Pinned, byte-identical to the Python test fixture.
const PINNED_ROW = {
  actionId: "host.isolate",
  actor: { id: "alice", kind: "human" },
  auditId: "audit-pinned-001",
  completedAt: "2026-01-01T12:00:00Z",
  complianceScope: ["nis2"],
  connector: { id: "demo-edr", version: "0.1.0" },
  decisionRef: {
    artifactId: "proposal-pinned-001",
    artifactType: "next_step_proposal",
    contentHash:
      "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  },
  durationMs: 1000,
  error: null,
  executionId: "exec-pinned-001",
  idempotencyKey: "idem-pinned-key",
  outcome: "success",
  phase: "apply",
  priorAuditId: null,
  specVersion: "1.0",
  startedAt: "2026-01-01T12:00:00Z",
  subject: {
    kind: "endpoint",
    selectorKeyId: null,
    selectorRepresentation: "raw",
    selectorType: "agent_id",
    selectorValue: "agent-pinned-007",
  },
  tenantId: "tenant-pinned",
  triggerSignalRef: {
    contentHash:
      "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    kind: "alert",
    sourceId: "alert-pinned-001",
  },
};

const PYTHON_GOLDEN =
  `{"actionId":"host.isolate","actor":{"id":"alice","kind":"human"},` +
  `"auditId":"audit-pinned-001","completedAt":"2026-01-01T12:00:00Z",` +
  `"complianceScope":["nis2"],"connector":{"id":"demo-edr","version":"0.1.0"},` +
  `"decisionRef":{"artifactId":"proposal-pinned-001","artifactType":"next_step_proposal",` +
  `"contentHash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},` +
  `"durationMs":1000,"error":null,"executionId":"exec-pinned-001",` +
  `"idempotencyKey":"idem-pinned-key","outcome":"success","phase":"apply",` +
  `"priorAuditId":null,` +
  `"specVersion":"1.0","startedAt":"2026-01-01T12:00:00Z",` +
  `"subject":{"kind":"endpoint","selectorKeyId":null,` +
  `"selectorRepresentation":"raw","selectorType":"agent_id",` +
  `"selectorValue":"agent-pinned-007"},"tenantId":"tenant-pinned",` +
  `"triggerSignalRef":{"contentHash":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",` +
  `"kind":"alert","sourceId":"alert-pinned-001"}}`;

describe("canonicalizeV1 — cross-language byte equivalence", () => {
  it("produces the same bytes as the Python golden", () => {
    const actual = canonicalizeV1(PINNED_ROW).toString("utf-8");
    expect(actual).toEqual(PYTHON_GOLDEN);
  });

  it("is deterministic across calls", () => {
    const a = canonicalizeV1(PINNED_ROW);
    const b = canonicalizeV1(PINNED_ROW);
    expect(a.equals(b)).toBe(true);
  });

  it("format identifier matches the spec", () => {
    expect(CANONICALIZATION_FORMAT_V1).toEqual("v1");
  });
});

describe("HMAC primitives", () => {
  const SECRET = Buffer.from("test-secret-do-not-ship", "utf-8");
  const TENANT = "tenant-x";

  it("computeGenesis is deterministic", () => {
    const a = computeGenesis(TENANT, SECRET);
    const b = computeGenesis(TENANT, SECRET);
    expect(a).toEqual(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });

  it("computeGenesis matches the Python golden", () => {
    expect(computeGenesis(TENANT, SECRET)).toEqual(
      "0ac2cc007f8b5a972d042824b56555eccde8b1e87893b4ed43bc9beedccd3a92",
    );
  });

  it("computeGenesis differs per tenant", () => {
    const a = computeGenesis("tenant-a", SECRET);
    const b = computeGenesis("tenant-b", SECRET);
    expect(a).not.toEqual(b);
  });

  it("computeSignature differs when prev_hash changes", () => {
    const bytes = canonicalizeV1(PINNED_ROW);
    const sigA = computeSignature("a".repeat(64), bytes, SECRET);
    const sigB = computeSignature("b".repeat(64), bytes, SECRET);
    expect(sigA).not.toEqual(sigB);
  });

  it("computeSignature differs when payload changes", () => {
    const prev = "a".repeat(64);
    const sigA = computeSignature(prev, canonicalizeV1(PINNED_ROW), SECRET);
    const sigB = computeSignature(
      prev,
      canonicalizeV1({ ...PINNED_ROW, outcome: "failure" }),
      SECRET,
    );
    expect(sigA).not.toEqual(sigB);
  });
});
