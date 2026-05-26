/**
 * Audit pipeline — turns an intercepted MCP ``tools/call`` into a signed
 * AuditRow on the local chain.
 */

import { createHash } from "node:crypto";
import { randomUUID } from "node:crypto";

import {
  CANONICALIZATION_FORMAT_V1,
  SelectorRepresentation,
  canonicalizeV1,
  computeGenesis,
  computeSignature,
} from "@warlog/spec";
import type {
  AiAgentRef,
  ApprovalLevelValue,
  AuditConnectorRef,
  AuditRow,
  AutomationActor,
  ConnectorError,
  DecisionRef,
  ExecutionOutcomeValue,
  ExecutionPhaseValue,
  ResponseActionIdValue,
  ResponseSubject,
  TriggerSignalRef,
} from "@warlog/spec";

import type { MappingFile, ToolMapping } from "./mapping.js";
import type { JsonlAuditPersister } from "./persister.js";

// Action families whose subject is PII-bearing — selector MUST be
// pseudonymized before signing.
const PII_FAMILIES = new Set(["identity", "email", "iam"]);

// Family → ResponseActionScope kind mapping (mirrors the Python integrate module).
const FAMILY_TO_SCOPE: Record<string, string> = {
  device: "endpoint",
  identity: "identity",
  iam: "identity",
  network: "network",
  email: "mail",
  key: "pki",
  storage: "platform",
  workflow: "platform",
};

// Action catalog families needed to drive the GDPR gate. Hardcoded subset
// — keeps the proxy free of a runtime dependency on warlog-spec-py's
// catalog. The action IDs that need pseudonymization are listed by
// family below ; everything else stays RAW.
const ACTION_FAMILY: Record<string, string> = {
  // identity
  "user.disable": "identity",
  "user.force_logout": "identity",
  "user.reset_mfa": "identity",
  "user.revoke_tokens": "identity",
  "user.reset_password": "identity",
  "user.expire_password": "identity",
  "user.unlock": "identity",
  "user.group_remove": "identity",
  "user.delete": "identity",
  // email
  "email.quarantine": "email",
  "email.recall": "email",
  "email.release": "email",
  "email.block_sender": "email",
  "email.unblock_sender": "email",
  // iam
  "iam.role_detach": "iam",
  "iam.role_attach": "iam",
  "iam.credentials_disable": "iam",
  "iam.credentials_enable": "iam",
  "iam.credentials_rotate": "iam",
  // others fall through to "workflow" / unknown — RAW selectors.
};

export interface AuditorContext {
  /** AI agent identity to bind to every emitted row. */
  agent: AiAgentRef;
  /** Upstream trigger signal that motivated this proxy session. */
  trigger: TriggerSignalRef;
  /** Stable id for the originating playbook / automation. */
  actorId: string;
}

export interface AuditorConfig {
  mapping: MappingFile;
  persister: JsonlAuditPersister;
  hmacSecret: Buffer;
  piiSalt: Buffer;
  context: AuditorContext;
  /** Optional synchronous gate. When absent, mapping.approval is used directly. */
  approvalGate?: ApprovalGate | null;
}

export interface ApprovalRequest {
  actionId: ResponseActionIdValue;
  subject: ResponseSubject;
  defaultApprovalLevel: ApprovalLevelValue;
  toolName: string;
  argsSummary: Record<string, string>;
  agentRunId: string | null;
  actorId: string;
  idempotencyKey: string;
}

export interface ApprovalDecisionResult {
  state: "approved" | "denied" | "pending";
  rationale?: string | null;
  requestId?: string | null;
}

export interface ApprovalGate {
  /** Decide synchronously whether this mapped MCP tool call may reach the backend. */
  request(req: ApprovalRequest): ApprovalDecisionResult;
}

/** Result of auditing a tools/call : either authorize-and-forward or refuse. */
export interface AuditDecision {
  outcome: "authorize" | "refuse_unmapped" | "approval_required" | "approval_denied";
  reason?: string;
  auditId?: string;
  requestId?: string;
}

export class Auditor {
  private cfg: AuditorConfig;

  constructor(cfg: AuditorConfig) {
    this.cfg = cfg;
  }

  /**
   * Audit one intercepted tools/call. If the mapping declares a static
   * approval policy, the proxy emits an APPROVAL row first. Pending or
   * denied decisions are terminal and the backend is never called.
   * Approved decisions continue and emit an APPLY/SUCCESS intent row
   * before forwarding. Mappings without approval preserve the v0.1
   * audit-only behavior : one APPLY/SUCCESS intent row before forwarding.
   *
   * Returns a decision : authorize-and-forward, or refuse-unmapped if
   * strict mode is enabled and the tool is not in the mapping.
   *
   * **Load-bearing : this method is intentionally synchronous.** The
   * proxy's correctness against HMAC-chain race conditions depends on
   * the read-compute-append sequence being atomic. Node.js's
   * single-threaded event loop makes synchronous code atomic by
   * construction : even when N parallel ``tools/call`` requests arrive
   * in the same I/O burst, ``readline`` fires sequentially and each
   * ``audit()`` runs to completion before the next starts.
   *
   * If a future contributor adds ``await`` anywhere in this method
   * (e.g. an async approval gate that talks HTTP), they MUST also
   * introduce a mutex around the (``headSignature → computeSignature
   * → append``) critical section — otherwise two concurrent audits
   * will read the same prev_hash, compute conflicting signatures, and
   * corrupt the chain. See the user-visible doctrine note in
   * README.md > "HMAC chain integrity".
   */
  audit(toolName: string, args: Record<string, unknown>, strict: boolean): AuditDecision {
    const mapping = this.cfg.mapping.toolMappings.get(toolName);
    if (!mapping) {
      if (strict) {
        return {
          outcome: "refuse_unmapped",
          reason: `tool '${toolName}' is not in the warlog mapping (strict mode)`,
        };
      }
      // Loose mode : forward without audit. The proxy operator should
      // add the mapping if the tool is sensitive.
      process.stderr.write(
        `[warlog-mcp] WARN: tool '${toolName}' is not in the mapping ; forwarding without audit\n`,
      );
      return { outcome: "authorize" };
    }

    const rawSubject = String(args[mapping.subjectParam] ?? "");
    const subject = this.buildSubject(mapping, rawSubject);
    const decisionRef = this.synthesizeDecisionRef(mapping, args);

    const executionId = randomUUID();
    const idempotencyKey = this.deterministicIdempotencyKey(
      mapping.actionId,
      subject.selectorValue,
      args,
    );

    const now = new Date().toISOString();
    const connectorRef: AuditConnectorRef = {
      id: this.cfg.mapping.connectorId,
      version: this.cfg.mapping.connectorVersion,
    };

    const actor: AutomationActor = {
      kind: "automation",
      id: this.cfg.context.actorId,
      agent: this.cfg.context.agent,
    };

    if (mapping.approval) {
      const approvalDecision = this.requestApproval(
        mapping,
        toolName,
        subject,
        args,
        idempotencyKey,
      );
      const approvalOutcome: ExecutionOutcomeValue =
        approvalDecision.state === "approved"
          ? "success"
          : approvalDecision.state === "denied"
            ? "denied"
            : "pending_approval";
      const approvalRow = this.signAndAppend(
        this.buildRow({
          executionId,
          actor,
          mapping,
          subject,
          phase: "approval",
          outcome: approvalOutcome,
          error: null,
          connectorRef,
          idempotencyKey,
          decisionRef,
          now,
        }),
      );

      if (approvalDecision.state === "pending") {
        return {
          outcome: "approval_required",
          auditId: approvalRow.row.auditId,
          requestId: approvalDecision.requestId ?? idempotencyKey,
          reason: approvalDecision.rationale ?? mapping.approval.rationale,
        };
      }
      if (approvalDecision.state === "denied") {
        return {
          outcome: "approval_denied",
          auditId: approvalRow.row.auditId,
          reason: approvalDecision.rationale ?? mapping.approval.rationale,
        };
      }
    }

    this.signAndAppend(
      this.buildRow({
        executionId,
        actor,
        mapping,
        subject,
        phase: "apply",
        outcome: "success",
        error: null,
        connectorRef,
        idempotencyKey,
        decisionRef,
        now,
      }),
    );

    return { outcome: "authorize" };
  }

  private requestApproval(
    mapping: ToolMapping,
    toolName: string,
    subject: ResponseSubject,
    args: Record<string, unknown>,
    idempotencyKey: string,
  ): ApprovalDecisionResult {
    const staticPolicy = mapping.approval;
    if (!staticPolicy) {
      return { state: "approved", rationale: "no approval policy" };
    }

    if (!this.cfg.approvalGate) {
      return {
        state: staticPolicy.state,
        rationale: staticPolicy.rationale,
        requestId: staticPolicy.state === "pending" ? idempotencyKey : null,
      };
    }

    const decision = this.cfg.approvalGate.request({
      actionId: mapping.actionId,
      subject,
      defaultApprovalLevel: staticPolicy.level,
      toolName,
      argsSummary: summarizeArgs(args),
      agentRunId: this.cfg.context.agent.agentRunId,
      actorId: this.cfg.context.actorId,
      idempotencyKey,
    });
    if (
      decision.state !== "approved" &&
      decision.state !== "denied" &&
      decision.state !== "pending"
    ) {
      throw new Error(
        `ApprovalGate.request() returned state '${String(
          decision.state,
        )}' ; expected approved, denied, or pending`,
      );
    }
    return decision;
  }

  private buildRow(args: {
    executionId: string;
    actor: AutomationActor;
    mapping: ToolMapping;
    subject: ResponseSubject;
    phase: ExecutionPhaseValue;
    outcome: ExecutionOutcomeValue;
    error: ConnectorError | null;
    connectorRef: AuditConnectorRef;
    idempotencyKey: string;
    decisionRef: DecisionRef;
    now: string;
  }): AuditRow {
    return {
      specVersion: "1.0",
      auditId: randomUUID(),
      executionId: args.executionId,
      tenantId: this.cfg.mapping.tenantId,
      actor: args.actor,
      actionId: args.mapping.actionId,
      subject: args.subject,
      phase: args.phase,
      outcome: args.outcome,
      startedAt: args.now,
      completedAt: args.now,
      durationMs: 0,
      error: args.error,
      connector: args.connectorRef,
      idempotencyKey: args.idempotencyKey,
      decisionRef: args.decisionRef,
      triggerSignalRef: this.cfg.context.trigger,
      complianceScope: args.mapping.complianceScope,
      priorAuditId: null,
    };
  }

  private signAndAppend(row: AuditRow) {
    const prev =
      this.cfg.persister.headSignature() ??
      computeGenesis(this.cfg.mapping.tenantId, this.cfg.hmacSecret);
    const canonical = canonicalizeV1(row);
    const signature = computeSignature(prev, canonical, this.cfg.hmacSecret);
    const entry = {
      row,
      prevHash: prev,
      signature,
      canonicalBytes: canonical,
      canonicalizationFormat: CANONICALIZATION_FORMAT_V1,
    };
    this.cfg.persister.append(entry);
    return entry;
  }

  private buildSubject(mapping: ToolMapping, rawValue: string): ResponseSubject {
    const family = ACTION_FAMILY[mapping.actionId] ?? "workflow";
    const scope = FAMILY_TO_SCOPE[family] ?? "platform";

    if (PII_FAMILIES.has(family)) {
      if (!rawValue) {
        throw new Error(
          `Action '${mapping.actionId}' is in PII family '${family}' but received an empty subject ; ` +
            `check that the MCP tool's '${mapping.subjectParam}' argument is populated.`,
        );
      }
      const hash = createHash("sha256")
        .update(this.cfg.piiSalt)
        .update(rawValue, "utf-8")
        .digest("hex");
      return {
        kind: scope as ResponseSubject["kind"],
        selectorType: "user_principal_name",
        selectorValue: hash,
        selectorRepresentation: SelectorRepresentation.SHA256_SALTED,
        selectorKeyId: this.cfg.mapping.selectorKeyId,
      };
    }

    return {
      kind: scope as ResponseSubject["kind"],
      selectorType: family,
      selectorValue: rawValue,
      selectorRepresentation: SelectorRepresentation.RAW,
      selectorKeyId: null,
    };
  }

  private synthesizeDecisionRef(
    mapping: ToolMapping,
    args: Record<string, unknown>,
  ): DecisionRef {
    const payload = JSON.stringify(
      { action_id: mapping.actionId, args },
      Object.keys({ action_id: mapping.actionId, args }).sort(),
    );
    const contentHash = createHash("sha256").update(payload, "utf-8").digest("hex");
    return {
      artifactType: "next_step_proposal",
      artifactId: `synthetic-mcp-${contentHash.slice(0, 16)}`,
      contentHash,
    };
  }

  private deterministicIdempotencyKey(
    actionId: ResponseActionIdValue,
    subjectValue: string,
    args: Record<string, unknown>,
  ): string {
    const payload = JSON.stringify(
      { action_id: actionId, subject: subjectValue, args },
      Object.keys({ action_id: actionId, subject: subjectValue, args }).sort(),
    );
    const hash = createHash("sha256").update(payload, "utf-8").digest("hex");
    return `warlog-mcp-${hash.slice(0, 32)}`;
  }
}

function summarizeArgs(args: Record<string, unknown>): Record<string, string> {
  const summary: Record<string, string> = {};
  for (const [key, value] of Object.entries(args)) {
    summary[key] = String(value).slice(0, 200);
  }
  return summary;
}
