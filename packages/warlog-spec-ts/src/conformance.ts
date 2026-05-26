/**
 * Conformance Level 2 (Write) — canonical example factories for the
 * TypeScript implementation.
 *
 * Mirrors `warlog_spec.conformance` in the Python package. Each
 * factory returns the camelCase wire-format dict for one productible
 * type. `produceAll()` returns the 18-type registry that the
 * conformance runner validates.
 *
 * Bundles (TriageBundle / InvestigationBundle / ResponseBundle /
 * IncidentBundle) are intentionally NOT in this registry — they are
 * product-specific UI projections that live in the Warlog backend,
 * not in the open spec.
 *
 * Determinism : all timestamps are pinned to the same value the
 * Python factories use, so the TS and Python outputs are
 * byte-comparable.
 */

import {
  canonicalizeV1,
  computeGenesis,
  computeSignature,
} from "./audit-chain.js";
import {
  AcceptedRisk,
  ApprovalDecision,
  ApprovalDecisionPayload,
  ArbitrationAuthority,
  ArbitrationScope,
  ArtifactCitation,
  ArtifactConfidence,
  ArtifactEnvelope,
  ArtifactProducer,
  CaseReturnSummary,
  ClassificationAssessment,
  ClassificationDecision,
  ClosureSummary,
  EnrichmentAssessment,
  EnrichmentAssessmentPayload,
  ExtractedIOC,
  MitreAssessment,
  MitreMapping,
  PolicyRef,
  ResponseActionRequestRef,
  RiskArbitration,
  RiskArbitrationPayload,
} from "./artifacts.js";
import { PackManifest } from "./pack-manifest.js";
import {
  AiAgentRef,
  AuditAttestation,
  AuditConnectorRef,
  AuditRow,
  AutomationActor,
  ConnectorCapability,
  ConnectorError,
  HumanActor,
  ResponseActionResult,
  ResponseActionSpec,
  ResponseSubject,
  SignedAuditRow,
} from "./provider-abi.js";
import {
  InvestigationSummaryProposal,
  InvestigationSummaryProposalPayload,
  NextStep,
  NextStepProposal,
  NextStepProposalPayload,
  PlaybookCandidate,
  PlaybookCandidateProposal,
  PlaybookCandidateProposalPayload,
  ProposalEnvelope,
  TriageProposal,
  TriageProposalPayload,
} from "./proposals.js";

// ----------------------------------------------------------------------------
// Pinned constants — match the Python factories byte-for-byte
// ----------------------------------------------------------------------------

const TS = "2026-05-20T10:00:00Z";
const ALERT_ID = "01HK7Z8M9XQYR4VTBN2WJC5CON";
const CASE_ID = "CASE-2026-CONFORMANCE-001";

const PII_SALT_KEY = "tenant:warlog-conformance:salt:v1";
const PII_SHA256_ALICE =
  "55a4d4a7e6f7d6e6e4e7c0a7d2d5c8b7f1a9e3d6c5b8a7e6d4c3b2a190817263";

const DEMO_HMAC_SECRET = Buffer.from(
  "warlog-conformance-demo-secret-do-not-use-in-prod",
  "utf-8",
);
const DEMO_HMAC_KEY_ID = "tenant:warlog-conformance:hmac:v1";

const dump = <T>(schema: { parse: (v: unknown) => T }, value: unknown): T =>
  schema.parse(value);

// ----------------------------------------------------------------------------
// Helpers reused by multiple factories
// ----------------------------------------------------------------------------

function classificationEnvelope() {
  return ArtifactEnvelope.parse({
    artifactType: "classification_assessment",
    subjectType: "alert",
    subjectId: ALERT_ID,
    producer: { kind: "ml", name: "alert_classifier", model: "ref-v1" },
    generatedAt: TS,
    confidence: { score: 0.85, band: "high" },
  });
}

function proposalEnv(
  proposalType: string,
  subjectId: string,
  subjectType: "alert" | "case" = "alert",
) {
  return ProposalEnvelope.parse({
    proposalType,
    proposalVersion: "v1",
    proposalId: `${proposalType}:${subjectId}:conformance`,
    subjectType,
    subjectId,
    requiresApproval: true,
    canMutate: false,
    confidence: { score: 0.85, band: "high" },
    citations: [],
    rationale: "Conformance reference example.",
  });
}

// ----------------------------------------------------------------------------
// Artifact factories (7)
// ----------------------------------------------------------------------------

export function produceClassificationAssessment(): ClassificationAssessment {
  return dump(ClassificationAssessment, {
    envelope: classificationEnvelope(),
    classification: dump(ClassificationDecision, {
      category: "execution",
      severity: "high",
      verdict: "suspicious",
      shouldEscalate: true,
      escalationRisk: "high",
    }),
    reasoning: "Encoded PowerShell + C2 callout matches T1059.001 patterns.",
    evidenceSummary: [
      "Parent process is winword.exe",
      "Base64-encoded command line",
    ],
    missingEvidence: ["No memory dump available"],
  });
}

export function produceMitreAssessment(): MitreAssessment {
  return dump(MitreAssessment, {
    envelope: ArtifactEnvelope.parse({
      artifactType: "mitre_assessment",
      subjectType: "alert",
      subjectId: ALERT_ID,
      producer: { kind: "rule", name: "mitre_mapper" },
      generatedAt: TS,
      confidence: { score: 0.78, band: "high" },
    }),
    mitre: { tactics: ["TA0002"], techniques: ["T1059.001"] },
    reasoning: "Encoded PowerShell from Office parent matches T1059.001 pattern.",
  });
}

export function produceEnrichmentAssessment(): EnrichmentAssessment {
  return dump(EnrichmentAssessment, {
    envelope: ArtifactEnvelope.parse({
      artifactType: "enrichment.ioc_reputation",
      subjectType: "alert",
      subjectId: ALERT_ID,
      producer: { kind: "system", name: "virustotal_enricher" },
      generatedAt: TS,
      confidence: { score: 0.92, band: "high" },
      citations: [
        {
          sourceId: "vt-report-abc123",
          sourceKind: "threat_intel_feed",
          score: 0.92,
        },
      ],
    }),
    payload: {
      matchedIocs: [
        {
          iocType: "hash_sha256",
          value:
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          maliciousness: "true_positive",
        },
      ],
      threatIntelHits: ["malware/cobalt-strike-beacon"],
    },
  });
}

export function produceClosureSummary(): ClosureSummary {
  return dump(ClosureSummary, {
    subjectType: "alert",
    subjectId: ALERT_ID,
    generatedAt: TS,
    closedBy: "user-analyst-jdoe",
    verdict: "true_positive",
    category: "execution",
    resolutionSummary: "Contained host, revoked tokens, deployed YARA rule.",
    evidenceReferences: [`s3://warlog-evidence/${ALERT_ID}/forensics.tar.gz`],
  });
}

export function produceCaseReturnSummary(): CaseReturnSummary {
  return dump(CaseReturnSummary, {
    caseId: CASE_ID,
    caseNumber: "CASE-2026-042",
    generatedAt: TS,
    finalVerdict: "true_positive",
    finalCategory: "execution",
    finalSeverity: "high",
    outcomeSummary: "Confirmed compromise. Host contained. Credentials rotated.",
    rootCause: "Successful spear-phishing against user.alice@warlog.demo.",
    lessonsLearned:
      "Disable macros for external Office documents. Tighten egress to known C2 ASNs.",
    linkedAlertIds: [ALERT_ID],
    confidence: { score: 0.95, band: "high" },
  });
}

export function produceRiskArbitration(): RiskArbitration {
  return dump(RiskArbitration, {
    envelope: ArtifactEnvelope.parse({
      artifactType: "risk_arbitration",
      subjectType: "case",
      subjectId: CASE_ID,
      producer: { kind: "human", name: "rssi_signing_console" },
      generatedAt: TS,
    }),
    payload: {
      authority: {
        role: "ciso",
        signerId: "user-rssi-mdupont",
        signerName: "Marie Dupont",
      },
      scope: [
        { scopeKind: "asset_group", selectorValue: "billing-prod-cluster" },
      ],
      acceptedRisks: [
        {
          name: "lsass_memory_dump_during_maintenance",
          description: "Authorized admin tool dumps LSASS for integrity checks.",
        },
      ],
      policyRef: {
        policyKind: "playbook",
        policyId: "playbook:lsass-maintenance-window",
        version: "2026.04",
      },
      validFrom: TS,
      validUntil: "2026-08-01T04:00:00Z",
      justification: "Monthly integrity check signed off by CISO and DRO.",
    },
  });
}

export function produceApprovalDecision(): ApprovalDecision {
  return dump(ApprovalDecision, {
    envelope: ArtifactEnvelope.parse({
      artifactType: "approval_decision",
      subjectType: "case",
      subjectId: CASE_ID,
      producer: { kind: "human", name: "approval_console" },
      generatedAt: TS,
      reviewState: "accepted",
    }),
    payload: {
      requestRef: {
        actionId: "user.revoke_tokens",
        subjectKind: "identity",
        subjectValue: PII_SHA256_ALICE,
        idempotencyKey: `case:${CASE_ID}:user.revoke_tokens:${PII_SHA256_ALICE.slice(0, 16)}`,
      },
      decisionMakerKind: "human",
      decisionMakerId: "user-senior-bclaudel",
      decision: "approved",
      decidedAt: TS,
      basisRef: {
        policyKind: "playbook",
        policyId: "playbook:token-revocation-on-confirmed-takeover",
        version: "2026.03",
      },
      rationale: "Confirmed account takeover. Tier-2 containment per playbook.",
    },
  });
}

// ----------------------------------------------------------------------------
// Proposal factories (4)
// ----------------------------------------------------------------------------

export function produceTriageProposal(): TriageProposal {
  return dump(TriageProposal, {
    envelope: proposalEnv("triage_proposal", ALERT_ID),
    payload: {
      recommendedStatus: "escalated",
      recommendedSeverity: "high",
      recommendedVerdict: "suspicious",
      recommendedCategory: "execution",
      shouldCreateCase: true,
      priorityHint: "p2",
      summary: "Suspicious encoded PowerShell + C2 callout. Escalate to L2.",
    },
  });
}

export function produceNextStepProposal(): NextStepProposal {
  return dump(NextStepProposal, {
    envelope: proposalEnv("next_step_proposal", ALERT_ID),
    payload: {
      steps: [
        {
          title: "Isolate host",
          kind: "containment",
          priority: 1,
          expectedOutcome:
            "Host network traffic blocked, in-memory process still observable.",
        },
        {
          title: "Collect memory dump",
          kind: "investigation",
          priority: 2,
          expectedOutcome: "LSASS region available for offline forensics.",
        },
      ],
    },
  });
}

export function producePlaybookCandidateProposal(): PlaybookCandidateProposal {
  return dump(PlaybookCandidateProposal, {
    envelope: proposalEnv("playbook_candidate_proposal", ALERT_ID),
    payload: {
      candidatePlaybooks: [
        {
          playbookId: "pb-edr-containment-001",
          playbookName: "EDR containment + token revocation",
          whyRecommended:
            "Matches confirmed-compromise pattern with identity blast radius.",
          preconditions: [
            "host.isolate available",
            "user.revoke_tokens available",
          ],
          approvalLevel: "senior",
          requiredCapabilityKeys: [
            "edr.endpoint.isolate",
            "iam.user.revoke_tokens",
          ],
        },
      ],
      whyRecommended:
        "Single playbook covers both containment and identity perimeters.",
      preconditions: [
        "EDR connector authenticated",
        "IAM connector authenticated",
      ],
    },
  });
}

export function produceInvestigationSummaryProposal(): InvestigationSummaryProposal {
  return dump(InvestigationSummaryProposal, {
    envelope: proposalEnv("investigation_summary_proposal", CASE_ID, "case"),
    payload: {
      summary: "Confirmed spear-phishing → execution → token theft chain.",
      hypothesis:
        "Adversary used MFA fatigue after initial spear-phish foothold.",
      findings: [
        "T1566.001 spear-phishing attachment delivered",
        "T1059.001 PowerShell execution observed",
        "T1078.004 cloud account abuse from previously-unseen IP",
      ],
      impactAssessment:
        "One user identity compromised. No data exfiltration confirmed.",
      nextSteps: [
        "Force password rotation + MFA re-enrollment for the user",
        "Deploy YARA rule to detect the dropped binary fleet-wide",
      ],
      unresolvedQuestions: ["Initial delivery vector pre-spear-phish"],
      confidence: { score: 0.9, band: "high" },
    },
  });
}

// ----------------------------------------------------------------------------
// Provider ABI factories (6 — connector cap, action spec, result, audit row,
// signed audit row, connector error)
// ----------------------------------------------------------------------------

export function produceConnectorCapability(): ConnectorCapability {
  return dump(ConnectorCapability, {
    connectorId: "reference-edr",
    connectorVersion: "0.1.0",
    vendor: "Conformance Reference Inc.",
    kind: "edr",
    auth: {
      model: "oauth2_client_credentials",
      scopes: ["read", "respond"],
      discoveryUrl: null,
    },
    ingress: {
      produces: ["ocsf.detection_finding.v1.4"],
      delivery: "polling",
      pollingMinIntervalS: 30,
    },
    egress: {
      supportsResponseActions: ["host.isolate", "host.unisolate"],
    },
    enrichment: {
      producesArtifactTypes: ["enrichment.context"],
      supportsEntityTypes: ["host", "user"],
      supportsIocTypes: [],
      freshness: "near_realtime",
      bulkLookup: false,
    },
    dryRun: { supported: true, scope: "egress" },
    lifecycle: {
      supportsHealthCheck: true,
      supportsCredentialRotation: true,
      supportsPausedState: false,
    },
    compat: { warlogSpecMin: "1.0.0", warlogSpecMax: "1.x" },
  });
}

export function produceResponseActionSpec(): ResponseActionSpec {
  return dump(ResponseActionSpec, {
    actionId: "user.revoke_tokens",
    subject: {
      kind: "identity",
      selectorType: "user_principal_name",
      selectorValue: PII_SHA256_ALICE,
      selectorRepresentation: "sha256_salted",
      selectorKeyId: PII_SALT_KEY,
    },
    params: { reason: "Confirmed account takeover" },
    approval: {
      required: true,
      level: "senior",
      rationale: "Token revocation on confirmed account takeover per playbook.",
    },
    idempotencyKey: `case:${CASE_ID}:user.revoke_tokens:${PII_SHA256_ALICE.slice(0, 16)}`,
    expiresAt: "2026-05-20T11:00:00Z",
  });
}

export function produceResponseActionResult(): ResponseActionResult {
  return dump(ResponseActionResult, {
    executionId: "exec-conformance-001",
    actionId: "user.revoke_tokens",
    outcome: "success",
    subject: {
      kind: "identity",
      selectorType: "user_principal_name",
      selectorValue: PII_SHA256_ALICE,
      selectorRepresentation: "sha256_salted",
      selectorKeyId: PII_SALT_KEY,
    },
    details: { vendor_task_id: "task-conformance-abc" },
  });
}

function buildPinnedAuditRow(): AuditRow {
  return dump(AuditRow, {
    auditId: "audit-conformance-001",
    executionId: "exec-conformance-001",
    tenantId: "tenant-conformance",
    actor: {
      kind: "automation",
      id: "agent:autonomous-soc:identity-containment-loop",
      agent: {
        model: "claude-opus-4-7",
        modelVersion: "2026-04-15-build-c7d2e1",
        systemPromptHash:
          "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        agentRunId: "run-conformance-001",
        reasoningArtifactRef: null,
      },
    },
    actionId: "user.revoke_tokens",
    subject: {
      kind: "identity",
      selectorType: "user_principal_name",
      selectorValue: PII_SHA256_ALICE,
      selectorRepresentation: "sha256_salted",
      selectorKeyId: PII_SALT_KEY,
    },
    phase: "apply",
    outcome: "success",
    startedAt: TS,
    completedAt: TS,
    durationMs: 712,
    connector: { id: "okta", version: "0.3.1" },
    idempotencyKey: `case:${CASE_ID}:user.revoke_tokens:${PII_SHA256_ALICE.slice(0, 16)}`,
    decisionRef: {
      artifactType: "approval_decision",
      artifactId: `approval:${CASE_ID}:user.revoke_tokens`,
      contentHash:
        "2c624232cdd221771294dfbb310aca000a0df6ac8b66b696d90ef06fdefb64a3",
    },
    triggerSignalRef: {
      kind: "ocsf_event",
      sourceId: "ocsf-event-conformance-001",
      contentHash:
        "7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730",
    },
    complianceScope: ["nis2", "gdpr"],
    priorAuditId: "audit-conformance-approval-pending",
  });
}

export function produceAuditRow(): AuditRow {
  return buildPinnedAuditRow();
}

export function produceSignedAuditRow(): SignedAuditRow {
  const row = buildPinnedAuditRow();
  const canonical = canonicalizeV1(row);
  const prev = computeGenesis(row.tenantId, DEMO_HMAC_SECRET);
  const sig = computeSignature(prev, canonical, DEMO_HMAC_SECRET);
  return dump(SignedAuditRow, {
    payload: row,
    attestation: {
      prevRowHash: prev,
      signatureValue: sig,
      algorithm: "HMAC-SHA256",
      canonicalizationFormat: "v1",
      keyId: DEMO_HMAC_KEY_ID,
    },
  });
}

export function produceConnectorError(): ConnectorError {
  return dump(ConnectorError, {
    category: "auth",
    message: "Upstream rejected credentials (HTTP 401).",
    retryable: false,
    vendorCode: "okta.401.unauthorized",
    vendorMessage: "Invalid API token",
  });
}

// ----------------------------------------------------------------------------
// Registry factory (1)
// ----------------------------------------------------------------------------

export function producePackManifest(): PackManifest {
  return dump(PackManifest, {
    packId: "warlog-conformance-reference",
    packVersion: "0.1.0",
    kind: "playbook",
    publisher: {
      id: "warlog-conformance",
      trustLevel: "community",
      signature: "ed25519:reference-signature-placeholder",
    },
    title: "Conformance reference pack",
    description:
      "Reference pack used by Level 2 conformance to exercise the manifest shape.",
    compat: {
      warlogSpecMin: "1.0.0",
      warlogSpecMax: "1.x",
      dependsOnPacks: [],
    },
    license: "Apache-2.0",
    contents: {
      detectionRules: [],
      playbooks: ["playbooks/reference.yaml"],
      kbArticles: [],
      connectorSpecs: [],
      actionMappings: [],
      examples: [],
      tests: [],
    },
    provenance: {
      sourceRepo: "https://example.invalid/pack",
      sourceCommit: "0".repeat(40),
      buildAt: TS,
      sbom: null,
      builderIdentity: null,
    },
  });
}

// ----------------------------------------------------------------------------
// Registry mapping schema_relpath -> factory  (18 productible types)
// ----------------------------------------------------------------------------

export const PRODUCERS: Record<string, () => unknown> = {
  // Artifacts (7)
  "artifacts/classification-assessment.json": produceClassificationAssessment,
  "artifacts/mitre-assessment.json": produceMitreAssessment,
  "artifacts/enrichment-assessment.json": produceEnrichmentAssessment,
  "artifacts/closure-summary.json": produceClosureSummary,
  "artifacts/case-return-summary.json": produceCaseReturnSummary,
  "artifacts/risk-arbitration.json": produceRiskArbitration,
  "artifacts/approval-decision.json": produceApprovalDecision,
  // Proposals (4)
  "proposals/triage-proposal.json": produceTriageProposal,
  "proposals/next-step-proposal.json": produceNextStepProposal,
  "proposals/playbook-candidate-proposal.json": producePlaybookCandidateProposal,
  "proposals/investigation-summary-proposal.json":
    produceInvestigationSummaryProposal,
  // Provider ABI (6 with signed-audit-row)
  "provider-abi/connector-capability.json": produceConnectorCapability,
  "provider-abi/response-action-spec.json": produceResponseActionSpec,
  "provider-abi/response-action-result.json": produceResponseActionResult,
  "provider-abi/audit-row.json": produceAuditRow,
  "provider-abi/signed-audit-row.json": produceSignedAuditRow,
  "provider-abi/connector-error.json": produceConnectorError,
  // Registry (1)
  "registry/pack-manifest.json": producePackManifest,
  // Bundles are intentionally NOT producers — they are product-specific
  // UI projections that live in the Warlog backend, not in the open spec.
};

/**
 * Produce one canonical example for each of the 18 productible types.
 */
export function produceAll(): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [relpath, factory] of Object.entries(PRODUCERS)) {
    out[relpath] = factory();
  }
  return out;
}
