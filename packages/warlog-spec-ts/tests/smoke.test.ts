/**
 * Smoke tests — the package imports, Zod schemas accept their canonical
 * shape, the top-level constants match Python.
 */

import { describe, expect, it } from "vitest";

import {
  ABI_VERSION,
  AlertCategory,
  AutomationActor,
  ComplianceScope,
  DecisionRef,
  HumanActor,
  ResponseActionId,
  ResponseActionResult,
  ResponseSubject,
  SPEC_VERSION,
  SelectorRepresentation,
  SignedAuditRow,
  TriggerSignalRef,
} from "../src/index.js";

describe("Top-level constants", () => {
  it("ABI_VERSION matches Python", () => {
    expect(ABI_VERSION).toEqual("1.0");
  });

  it("SPEC_VERSION matches Python package version", () => {
    expect(SPEC_VERSION).toEqual("0.1.0");
  });
});

describe("Enums export both objects and values", () => {
  it("AlertCategory has 17 canonical values", () => {
    expect(Object.values(AlertCategory).length).toEqual(17);
    expect(AlertCategory.EXECUTION).toEqual("execution");
  });

  it("ComplianceScope has 9 canonical values", () => {
    expect(Object.values(ComplianceScope).length).toEqual(9);
    expect(ComplianceScope.NIS2).toEqual("nis2");
  });

  it("SelectorRepresentation is closed enum of 3", () => {
    expect(Object.values(SelectorRepresentation)).toEqual([
      "raw",
      "sha256",
      "sha256_salted",
    ]);
  });
});

describe("Zod schemas — discriminated AuditActor", () => {
  it("accepts a HumanActor", () => {
    const human = HumanActor.parse({ id: "alice" });
    expect(human.kind).toEqual("human");
    expect(human.id).toEqual("alice");
  });

  it("accepts an AutomationActor with AiAgentRef", () => {
    const auto = AutomationActor.parse({
      id: "agent-1",
      agent: {
        model: "claude-opus-4-7",
        modelVersion: "2026-04-15",
        systemPromptHash: "a".repeat(64),
        agentRunId: "run-1",
      },
    });
    expect(auto.kind).toEqual("automation");
    expect(auto.agent.model).toEqual("claude-opus-4-7");
  });

  it("rejects an AutomationActor missing the agent field", () => {
    expect(() =>
      AutomationActor.parse({ id: "agent-1" }),
    ).toThrowError();
  });
});

describe("ResponseActionId catalog", () => {
  it("includes the canonical 49 actions", () => {
    expect(ResponseActionId.options.length).toEqual(49);
  });

  it("includes host.isolate, user.revoke_tokens, key.rotate", () => {
    expect(ResponseActionId.options).toContain("host.isolate");
    expect(ResponseActionId.options).toContain("user.revoke_tokens");
    expect(ResponseActionId.options).toContain("key.rotate");
  });
});

describe("Selector representation gate", () => {
  it("accepts a raw selector without keyId", () => {
    const subject = {
      kind: "endpoint" as const,
      selectorType: "agent_id",
      selectorValue: "host-001",
    };
    // Allow Zod's default to fill in.
    expect(() =>
      ResponseSubject.parse(subject),
    ).not.toThrow();
  });

  it("rejects a pseudonymized selector without keyId", () => {
    expect(() =>
      ResponseSubject.parse({
        kind: "identity",
        selectorType: "user_principal_name",
        selectorValue: "c".repeat(64),
        selectorRepresentation: "sha256_salted",
        selectorKeyId: null,
      }),
    ).toThrowError();
  });

  it("rejects a pseudonymized selector with a non-sha256 value", () => {
    expect(() =>
      ResponseSubject.parse({
        kind: "identity",
        selectorType: "user_principal_name",
        selectorValue: "not-a-sha256",
        selectorRepresentation: "sha256_salted",
        selectorKeyId: "tenant:t:salt:v1",
      }),
    ).toThrowError();
  });
});

describe("Trust references", () => {
  it("rejects non-manual triggers without a sha256 contentHash", () => {
    expect(() =>
      TriggerSignalRef.parse({
        kind: "alert",
        sourceId: "alert-1",
        contentHash: "",
      }),
    ).toThrowError();
  });

  it("rejects non-hex decision content hashes", () => {
    expect(() =>
      DecisionRef.parse({
        artifactType: "next_step_proposal",
        artifactId: "proposal-1",
        contentHash: "z".repeat(64),
      }),
    ).toThrowError();
  });
});

describe("Execution outcome invariants", () => {
  const baseResult = {
    executionId: "exec-1",
    actionId: "host.isolate" as const,
    subject: {
      kind: "endpoint" as const,
      selectorType: "agent_id",
      selectorValue: "agent-1",
    },
  };

  it("requires an error for failed results", () => {
    expect(() =>
      ResponseActionResult.parse({
        ...baseResult,
        outcome: "failure",
      }),
    ).toThrowError();
  });

  it("rejects an error on successful results", () => {
    expect(() =>
      ResponseActionResult.parse({
        ...baseResult,
        outcome: "success",
        error: {
          category: "transient",
          message: "should not ride with success",
          retryable: true,
        },
      }),
    ).toThrowError();
  });
});

describe("SignedAuditRow envelope", () => {
  it("parses a payload + attestation pair", () => {
    const row = {
      auditId: "a-1",
      executionId: "e-1",
      tenantId: "t-1",
      actor: { kind: "human", id: "alice" },
      actionId: "alert.acknowledge",
      subject: {
        kind: "platform",
        selectorType: "alert_id",
        selectorValue: "alert-1",
      },
      phase: "apply",
      outcome: "success",
      startedAt: "2026-05-20T10:00:00Z",
      completedAt: "2026-05-20T10:00:01Z",
      durationMs: 100,
      connector: { id: "demo", version: "0.1.0" },
      idempotencyKey: "k-1",
      decisionRef: {
        artifactType: "next_step_proposal",
        artifactId: "p-1",
        contentHash: "a".repeat(64),
      },
      triggerSignalRef: {
        kind: "manual",
        sourceId: "",
        contentHash: "",
      },
      complianceScope: [],
    };
    const signed = SignedAuditRow.parse({
      payload: row,
      attestation: {
        prevRowHash: "0".repeat(64),
        signatureValue: "1".repeat(64),
        algorithm: "HMAC-SHA256",
        canonicalizationFormat: "v1",
        keyId: "tenant:test:hmac:v1",
      },
    });
    expect(signed.payload.auditId).toEqual("a-1");
    expect(signed.attestation.keyId).toEqual("tenant:test:hmac:v1");
  });
});

describe("RFC-0002 — AiAgentRef multi-agent extensions", () => {
  it("accepts a v1 single-agent (all RFC-0002 fields default-absent)", () => {
    const single = AutomationActor.parse({
      id: "agent-1",
      agent: {
        model: "claude-opus-4-7",
        modelVersion: "2026-04-15",
        systemPromptHash: "a".repeat(64),
        agentRunId: "run-1",
      },
    });
    expect(single.agent.subAgents).toEqual([]);
    expect(single.agent.toolsManifestHash).toBeNull();
    expect(single.agent.retrievalContextRef).toBeNull();
    expect(single.agent.compositionKind).toBeNull();
  });

  it("accepts an orchestrator with nested sub-agents", () => {
    const orchestrator = AutomationActor.parse({
      id: "executor-1",
      agent: {
        model: "claude-opus-4-7",
        modelVersion: "2026-04-15",
        systemPromptHash: "b".repeat(64),
        agentRunId: "run-executor",
        compositionKind: "delegated",
        toolsManifestHash: "c".repeat(64),
        retrievalContextRef: "kb://vector-snapshot-2026-05-20",
        subAgents: [
          {
            model: "claude-opus-4-7",
            modelVersion: "2026-04-15",
            systemPromptHash: "d".repeat(64),
            agentRunId: "run-planner",
            compositionKind: "orchestrator",
          },
        ],
      },
    });
    expect(orchestrator.agent.subAgents).toHaveLength(1);
    expect(orchestrator.agent.subAgents[0]!.compositionKind).toEqual(
      "orchestrator",
    );
    expect(orchestrator.agent.compositionKind).toEqual("delegated");
  });

  it("rejects an invalid tools_manifest_hash length", () => {
    expect(() =>
      AutomationActor.parse({
        id: "agent-1",
        agent: {
          model: "m",
          modelVersion: "v",
          systemPromptHash: "a".repeat(64),
          agentRunId: "r",
          toolsManifestHash: "tooshort",
        },
      }),
    ).toThrowError();
  });
});

// Bundle shape tests removed — TriageBundle and its siblings are now
// backend-internal (Warlog product-specific UI projection), not part of
// the open spec. See packages/warlog-spec-py/CHANGELOG.md > "Out of scope".
