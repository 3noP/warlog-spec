/**
 * Tests for the Auditor — the heart of the proxy. We exercise :
 * - PII subject pseudonymization
 * - non-PII subject pass-through
 * - chain linkage across multiple audits
 * - strict-mode refusal of unmapped tools
 * - loose-mode forwarding of unmapped tools
 */

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { beforeEach, describe, expect, it } from "vitest";

import { Auditor } from "../src/auditor.js";
import { JsonlAuditPersister } from "../src/persister.js";
import type { ApprovalGate, AuditorContext } from "../src/auditor.js";
import type { MappingFile } from "../src/mapping.js";

const SECRET = Buffer.from("test-hmac-secret-do-not-ship", "utf-8");
const SALT = Buffer.from("test-pii-salt-do-not-ship", "utf-8");

function buildMapping(): MappingFile {
  return {
    tenantId: "acme-test",
    connectorId: "mcp.test",
    connectorVersion: "0.1.0",
    selectorKeyId: "tenant:acme-test:salt:v1",
    toolMappings: new Map([
      [
        "okta_revoke",
        {
          actionId: "user.revoke_tokens",
          subjectParam: "user_id",
          complianceScope: ["gdpr", "nis2"],
          approval: null,
        },
      ],
      [
        "falcon_isolate",
        {
          actionId: "host.isolate",
          subjectParam: "agent_id",
          complianceScope: ["nis2"],
          approval: null,
        },
      ],
      [
        "okta_revoke_requires_approval",
        {
          actionId: "user.revoke_tokens",
          subjectParam: "user_id",
          complianceScope: ["gdpr", "nis2"],
          approval: {
            state: "pending",
            level: "senior",
            rationale: "senior approval required for token revocation",
          },
        },
      ],
      [
        "okta_revoke_denied_by_policy",
        {
          actionId: "user.revoke_tokens",
          subjectParam: "user_id",
          complianceScope: ["gdpr", "nis2"],
          approval: {
            state: "denied",
            level: "manager",
            rationale: "policy denies token revocation from this MCP surface",
          },
        },
      ],
      [
        "okta_revoke_auto_approved",
        {
          actionId: "user.revoke_tokens",
          subjectParam: "user_id",
          complianceScope: ["gdpr", "nis2"],
          approval: {
            state: "approved",
            level: "senior",
            rationale: "pre-approved emergency playbook",
          },
        },
      ],
    ]),
  };
}

function buildContext(): AuditorContext {
  return {
    agent: {
      model: "test",
      modelVersion: "test",
      systemPromptHash: "a".repeat(64),
      agentRunId: "test-run-001",
      reasoningArtifactRef: null,
      subAgents: [],
      toolsManifestHash: null,
      retrievalContextRef: null,
      compositionKind: null,
    },
    trigger: {
      kind: "alert",
      sourceId: "alert-001",
      contentHash: "b".repeat(64),
    },
    actorId: "playbook.test",
  };
}

let tmp: string;

beforeEach(() => {
  tmp = join(tmpdir(), `warlog-auditor-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tmp, { recursive: true });
});

describe("Auditor", () => {
  it("pseudonymizes a PII subject (identity family)", () => {
    const path = join(tmp, "audit.jsonl");
    const persister = new JsonlAuditPersister(path);
    const auditor = new Auditor({
      mapping: buildMapping(),
      persister,
      hmacSecret: SECRET,
      piiSalt: SALT,
      context: buildContext(),
    });

    const decision = auditor.audit("okta_revoke", { user_id: "alice@acme.example" }, false);
    expect(decision.outcome).toBe("authorize");

    const expectedHash = createHash("sha256")
      .update(SALT)
      .update("alice@acme.example", "utf-8")
      .digest("hex");

    const line = readFileSync(path, "utf-8").trim().split("\n").pop()!;
    const entry = JSON.parse(line);
    expect(entry.row.subject.selectorRepresentation).toBe("sha256_salted");
    expect(entry.row.subject.selectorValue).toBe(expectedHash);
    expect(entry.row.subject.selectorKeyId).toBe("tenant:acme-test:salt:v1");
  });

  it("leaves a non-PII subject in raw form", () => {
    const path = join(tmp, "audit.jsonl");
    const persister = new JsonlAuditPersister(path);
    const auditor = new Auditor({
      mapping: buildMapping(),
      persister,
      hmacSecret: SECRET,
      piiSalt: SALT,
      context: buildContext(),
    });

    auditor.audit("falcon_isolate", { agent_id: "agent-007" }, false);

    const line = readFileSync(path, "utf-8").trim().split("\n").pop()!;
    const entry = JSON.parse(line);
    expect(entry.row.subject.selectorRepresentation).toBe("raw");
    expect(entry.row.subject.selectorValue).toBe("agent-007");
  });

  it("links successive audits via HMAC", () => {
    const path = join(tmp, "audit.jsonl");
    const persister = new JsonlAuditPersister(path);
    const auditor = new Auditor({
      mapping: buildMapping(),
      persister,
      hmacSecret: SECRET,
      piiSalt: SALT,
      context: buildContext(),
    });

    auditor.audit("okta_revoke", { user_id: "alice@acme.example" }, false);
    auditor.audit("okta_revoke", { user_id: "bob@acme.example" }, false);

    const lines = readFileSync(path, "utf-8").trim().split("\n");
    expect(lines.length).toBe(2);
    const first = JSON.parse(lines[0]!);
    const second = JSON.parse(lines[1]!);
    // Row 2's prevHash MUST equal row 1's signature : the chain links.
    expect(second.prevHash).toBe(first.signature);
  });

  it("refuses an unmapped tool in strict mode", () => {
    const path = join(tmp, "audit.jsonl");
    const persister = new JsonlAuditPersister(path);
    const auditor = new Auditor({
      mapping: buildMapping(),
      persister,
      hmacSecret: SECRET,
      piiSalt: SALT,
      context: buildContext(),
    });

    const decision = auditor.audit("totally_unmapped_tool", { foo: "bar" }, true);
    expect(decision.outcome).toBe("refuse_unmapped");
    expect(decision.reason).toContain("strict mode");
  });

  it("forwards unmapped tools without audit in loose mode", () => {
    const path = join(tmp, "audit.jsonl");
    const persister = new JsonlAuditPersister(path);
    const auditor = new Auditor({
      mapping: buildMapping(),
      persister,
      hmacSecret: SECRET,
      piiSalt: SALT,
      context: buildContext(),
    });

    const decision = auditor.audit("totally_unmapped_tool", { foo: "bar" }, false);
    expect(decision.outcome).toBe("authorize");
    // No JSONL line was written because no row was signed.
    let content = "";
    try {
      content = readFileSync(path, "utf-8");
    } catch {
      content = "";
    }
    expect(content.trim()).toBe("");
  });

  it("rejects an empty subject on a PII action", () => {
    const path = join(tmp, "audit.jsonl");
    const persister = new JsonlAuditPersister(path);
    const auditor = new Auditor({
      mapping: buildMapping(),
      persister,
      hmacSecret: SECRET,
      piiSalt: SALT,
      context: buildContext(),
    });

    expect(() => auditor.audit("okta_revoke", {}, false)).toThrow(/PII family/);
  });

  it("emits PENDING_APPROVAL and refuses forwarding when approval is pending", () => {
    const path = join(tmp, "audit.jsonl");
    const persister = new JsonlAuditPersister(path);
    const auditor = new Auditor({
      mapping: buildMapping(),
      persister,
      hmacSecret: SECRET,
      piiSalt: SALT,
      context: buildContext(),
    });

    const decision = auditor.audit(
      "okta_revoke_requires_approval",
      { user_id: "alice@acme.example" },
      false,
    );
    expect(decision.outcome).toBe("approval_required");
    expect(decision.auditId).toBeTruthy();
    expect(decision.requestId).toMatch(/^warlog-mcp-/);

    const line = readFileSync(path, "utf-8").trim().split("\n").pop()!;
    const entry = JSON.parse(line);
    expect(entry.row.phase).toBe("approval");
    expect(entry.row.outcome).toBe("pending_approval");
    expect(entry.row.auditId).toBe(decision.auditId);
  });

  it("emits DENIED and refuses forwarding when approval is denied", () => {
    const path = join(tmp, "audit.jsonl");
    const persister = new JsonlAuditPersister(path);
    const auditor = new Auditor({
      mapping: buildMapping(),
      persister,
      hmacSecret: SECRET,
      piiSalt: SALT,
      context: buildContext(),
    });

    const decision = auditor.audit(
      "okta_revoke_denied_by_policy",
      { user_id: "alice@acme.example" },
      false,
    );
    expect(decision.outcome).toBe("approval_denied");
    expect(decision.reason).toContain("policy denies");

    const line = readFileSync(path, "utf-8").trim().split("\n").pop()!;
    const entry = JSON.parse(line);
    expect(entry.row.phase).toBe("approval");
    expect(entry.row.outcome).toBe("denied");
  });

  it("emits APPROVAL success then APPLY success when approval is pre-approved", () => {
    const path = join(tmp, "audit.jsonl");
    const persister = new JsonlAuditPersister(path);
    const auditor = new Auditor({
      mapping: buildMapping(),
      persister,
      hmacSecret: SECRET,
      piiSalt: SALT,
      context: buildContext(),
    });

    const decision = auditor.audit(
      "okta_revoke_auto_approved",
      { user_id: "alice@acme.example" },
      false,
    );
    expect(decision.outcome).toBe("authorize");

    const lines = readFileSync(path, "utf-8").trim().split("\n");
    expect(lines.length).toBe(2);
    const approval = JSON.parse(lines[0]!);
    const apply = JSON.parse(lines[1]!);
    expect(approval.row.phase).toBe("approval");
    expect(approval.row.outcome).toBe("success");
    expect(apply.row.phase).toBe("apply");
    expect(apply.row.outcome).toBe("success");
    expect(apply.prevHash).toBe(approval.signature);
  });

  it.each([
    {
      gateState: "approved" as const,
      expectedDecision: "authorize" as const,
      expectedRows: ["success", "success"],
      requestId: null,
    },
    {
      gateState: "pending" as const,
      expectedDecision: "approval_required" as const,
      expectedRows: ["pending_approval"],
      requestId: "approval-queue-123",
    },
    {
      gateState: "denied" as const,
      expectedDecision: "approval_denied" as const,
      expectedRows: ["denied"],
      requestId: null,
    },
  ])("delegates $gateState decisions to a custom synchronous gate", (scenario) => {
    const path = join(tmp, "audit.jsonl");
    const persister = new JsonlAuditPersister(path);
    const gate: ApprovalGate = {
      request: (req) => ({
        state: scenario.gateState,
        rationale: `gate saw ${req.toolName}`,
        requestId: scenario.requestId,
      }),
    };
    const auditor = new Auditor({
      mapping: buildMapping(),
      persister,
      hmacSecret: SECRET,
      piiSalt: SALT,
      context: buildContext(),
      approvalGate: gate,
    });

    const decision = auditor.audit(
      "okta_revoke_requires_approval",
      { user_id: "alice@acme.example" },
      false,
    );
    expect(decision.outcome).toBe(scenario.expectedDecision);
    if (scenario.expectedDecision !== "authorize") {
      expect(decision.reason).toBe("gate saw okta_revoke_requires_approval");
    }
    if (scenario.expectedDecision === "approval_required") {
      expect(decision.requestId).toBe(scenario.requestId);
    }

    const lines = readFileSync(path, "utf-8").trim().split("\n");
    expect(lines.length).toBe(scenario.expectedRows.length);
    const approval = JSON.parse(lines[0]!);
    expect(approval.row.phase).toBe("approval");
    expect(approval.row.outcome).toBe(scenario.expectedRows[0]);
    if (scenario.gateState === "approved") {
      const apply = JSON.parse(lines[1]!);
      expect(apply.row.phase).toBe("apply");
      expect(apply.row.outcome).toBe(scenario.expectedRows[1]);
      expect(apply.prevHash).toBe(approval.signature);
    }
  });

  it("resumes the chain across persister restarts", () => {
    const path = join(tmp, "audit.jsonl");

    // First persister + audit
    const persister1 = new JsonlAuditPersister(path);
    const auditor1 = new Auditor({
      mapping: buildMapping(),
      persister: persister1,
      hmacSecret: SECRET,
      piiSalt: SALT,
      context: buildContext(),
    });
    auditor1.audit("okta_revoke", { user_id: "alice@acme.example" }, false);
    const headAfterFirst = persister1.headSignature();
    expect(headAfterFirst).not.toBeNull();

    // Second persister reads the same file — recovers head
    const persister2 = new JsonlAuditPersister(path);
    expect(persister2.headSignature()).toBe(headAfterFirst);

    const auditor2 = new Auditor({
      mapping: buildMapping(),
      persister: persister2,
      hmacSecret: SECRET,
      piiSalt: SALT,
      context: buildContext(),
    });
    auditor2.audit("okta_revoke", { user_id: "bob@acme.example" }, false);

    const lines = readFileSync(path, "utf-8").trim().split("\n");
    expect(lines.length).toBe(2);
    const second = JSON.parse(lines[1]!);
    expect(second.prevHash).toBe(headAfterFirst);
  });
});
