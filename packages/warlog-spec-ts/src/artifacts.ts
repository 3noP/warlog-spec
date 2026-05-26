/**
 * Canonical read-side artifact types.
 *
 * Mirrors `warlog_spec.artifacts` in the Python package. Where the
 * Provider ABI defines write-side verbs (response actions), this
 * module defines read-side shapes — what enricher / classifier /
 * arbitration / approval-emitting connectors produce.
 */

import { z } from "zod";

import {
  AlertCategory,
  AlertSeverity,
  AlertVerdict,
  ConfidenceBand,
  ArtifactReviewState,
  EntityRole,
  EntityType,
  IOCType,
} from "./enums.js";

const ConfidenceBandEnum = z.enum([
  ConfidenceBand.LOW,
  ConfidenceBand.MEDIUM,
  ConfidenceBand.HIGH,
  ConfidenceBand.UNKNOWN,
]);

const ArtifactReviewStateEnum = z.enum([
  ArtifactReviewState.PENDING,
  ArtifactReviewState.ACCEPTED,
  ArtifactReviewState.REJECTED,
  ArtifactReviewState.SUPERSEDED,
]);

const AlertCategoryEnum = z.enum([
  AlertCategory.MALWARE,
  AlertCategory.PHISHING,
  AlertCategory.CREDENTIAL_ACCESS,
  AlertCategory.UNAUTHORIZED_ACCESS,
  AlertCategory.LATERAL_MOVEMENT,
  AlertCategory.EXECUTION,
  AlertCategory.PERSISTENCE,
  AlertCategory.EXFILTRATION,
  AlertCategory.DATA_BREACH,
  AlertCategory.INSIDER_THREAT,
  AlertCategory.POLICY_VIOLATION,
  AlertCategory.DENIAL_OF_SERVICE,
  AlertCategory.RECONNAISSANCE,
  AlertCategory.IMPACT,
  AlertCategory.OTHER,
  AlertCategory.UNKNOWN,
  AlertCategory.NEEDS_REVIEW,
]);

const AlertSeverityEnum = z.enum([
  AlertSeverity.CRITICAL,
  AlertSeverity.HIGH,
  AlertSeverity.MEDIUM,
  AlertSeverity.LOW,
  AlertSeverity.INFO,
  AlertSeverity.UNKNOWN,
]);

const AlertVerdictEnum = z.enum([
  AlertVerdict.UNDETERMINED,
  AlertVerdict.TRUE_POSITIVE,
  AlertVerdict.FALSE_POSITIVE,
  AlertVerdict.BENIGN,
  AlertVerdict.SUSPICIOUS,
  AlertVerdict.MIXED,
  AlertVerdict.NEEDS_REVIEW,
]);

const EntityTypeEnum = z.enum([
  EntityType.HOST,
  EntityType.USER,
  EntityType.IP,
  EntityType.DOMAIN,
  EntityType.URL,
  EntityType.HASH,
  EntityType.FILE,
  EntityType.PROCESS,
  EntityType.EMAIL,
  EntityType.ASSET_GROUP,
  EntityType.ORGANIZATION,
  EntityType.OTHER,
]);

const EntityRoleEnum = z.enum([
  EntityRole.SUBJECT,
  EntityRole.TARGET,
  EntityRole.RELATED,
  EntityRole.CONTEXT,
  EntityRole.UNKNOWN,
]);

const IOCTypeEnum = z.enum([
  IOCType.IP,
  IOCType.IPV6,
  IOCType.DOMAIN,
  IOCType.URL,
  IOCType.HASH_MD5,
  IOCType.HASH_SHA1,
  IOCType.HASH_SHA256,
  IOCType.EMAIL,
  IOCType.USER,
  IOCType.PROCESS,
  IOCType.REGISTRY_KEY,
  IOCType.FILE_PATH,
  IOCType.CERTIFICATE,
  IOCType.CVE,
  IOCType.OTHER,
]);

// ============================================================================
// Provenance + confidence + citation primitives
// ============================================================================

export const ArtifactProducer = z.object({
  kind: z.enum(["llm", "rule", "ml", "human", "system"]),
  name: z.string(),
  model: z.string().nullable().default(null),
});
export type ArtifactProducer = z.infer<typeof ArtifactProducer>;

export const ArtifactConfidence = z.object({
  score: z.number().min(0).max(1).nullable().default(null),
  band: ConfidenceBandEnum.default("unknown"),
});
export type ArtifactConfidence = z.infer<typeof ArtifactConfidence>;

export const ArtifactCitation = z.object({
  sourceId: z.string(),
  sourceKind: z.string(),
  section: z.string().nullable().default(null),
  score: z.number().min(0).max(1).nullable().default(null),
});
export type ArtifactCitation = z.infer<typeof ArtifactCitation>;

// ============================================================================
// Subjects : entities + IOCs
// ============================================================================

export const NormalizedEntity = z.object({
  entityType: EntityTypeEnum,
  value: z.string(),
  role: EntityRoleEnum.default("unknown"),
  confidence: ArtifactConfidence.default({ score: null, band: "unknown" }),
  sourceFields: z.array(z.string()).default([]),
});
export type NormalizedEntity = z.infer<typeof NormalizedEntity>;

export const ExtractedIOC = z.object({
  iocType: IOCTypeEnum,
  value: z.string(),
  confidence: ArtifactConfidence.default({ score: null, band: "unknown" }),
  maliciousness: AlertVerdictEnum.default("undetermined"),
  sourceFields: z.array(z.string()).default([]),
  firstSeen: z.string().datetime({ offset: true }).nullable().default(null),
  lastSeen: z.string().datetime({ offset: true }).nullable().default(null),
  feedId: z.string().nullable().default(null),
  feedFreshnessAt: z.string().datetime({ offset: true }).nullable().default(null),
});
export type ExtractedIOC = z.infer<typeof ExtractedIOC>;

// ============================================================================
// ArtifactEnvelope — unified read-side wrapper
// ============================================================================

export const ArtifactEnvelope = z.object({
  artifactType: z.string(),
  artifactVersion: z.string().default("v1"),
  subjectType: z.enum(["alert", "case"]),
  subjectId: z.string(),
  producer: ArtifactProducer,
  generatedAt: z.string().datetime({ offset: true }),
  confidence: ArtifactConfidence.default({ score: null, band: "unknown" }),
  reviewState: ArtifactReviewStateEnum.default("pending"),
  citations: z.array(ArtifactCitation).default([]),
});
export type ArtifactEnvelope = z.infer<typeof ArtifactEnvelope>;

// ============================================================================
// MITRE assessment
// ============================================================================

export const AlternativeTechnique = z.object({
  technique: z.string(),
  why: z.string(),
});
export type AlternativeTechnique = z.infer<typeof AlternativeTechnique>;

export const MitreMapping = z.object({
  tactics: z.array(z.string()).default([]),
  techniques: z.array(z.string()).default([]),
});
export type MitreMapping = z.infer<typeof MitreMapping>;

export const MitreAssessment = z.object({
  envelope: ArtifactEnvelope,
  mitre: MitreMapping,
  reasoning: z.string(),
  alternatives: z.array(AlternativeTechnique).default([]),
});
export type MitreAssessment = z.infer<typeof MitreAssessment>;

// ============================================================================
// Enrichment assessment
// ============================================================================

export const EnrichmentAssessmentPayload = z.object({
  relatedEntities: z.array(NormalizedEntity).default([]),
  matchedIocs: z.array(ExtractedIOC).default([]),
  prevalenceSummary: z.string().nullable().default(null),
  assetCriticality: ConfidenceBandEnum.default("unknown"),
  userContext: z.string().nullable().default(null),
  threatIntelHits: z.array(z.string()).default([]),
  anomalies: z.array(z.string()).default([]),
});
export type EnrichmentAssessmentPayload = z.infer<typeof EnrichmentAssessmentPayload>;

export const EnrichmentAssessment = z.object({
  envelope: ArtifactEnvelope,
  payload: EnrichmentAssessmentPayload,
});
export type EnrichmentAssessment = z.infer<typeof EnrichmentAssessment>;

// ============================================================================
// Classification assessment
// ============================================================================

export const ClassificationDecision = z.object({
  category: AlertCategoryEnum.default("unknown"),
  severity: AlertSeverityEnum.default("unknown"),
  verdict: AlertVerdictEnum.default("undetermined"),
  shouldEscalate: z.boolean().default(false),
  escalationRisk: ConfidenceBandEnum.default("unknown"),
});
export type ClassificationDecision = z.infer<typeof ClassificationDecision>;

export const ClassificationAssessment = z.object({
  envelope: ArtifactEnvelope,
  classification: ClassificationDecision,
  reasoning: z.string(),
  evidenceSummary: z.array(z.string()).default([]),
  missingEvidence: z.array(z.string()).default([]),
});
export type ClassificationAssessment = z.infer<typeof ClassificationAssessment>;

// ============================================================================
// Closure + case-return summary
// ============================================================================

export const ClosureSummary = z.object({
  schemaVersion: z.literal("closure_summary.v1").default("closure_summary.v1"),
  subjectType: z.enum(["alert", "case"]),
  subjectId: z.string(),
  generatedAt: z.string().datetime({ offset: true }),
  closedBy: z.string(),
  verdict: AlertVerdictEnum,
  category: AlertCategoryEnum,
  resolutionSummary: z.string(),
  falsePositiveRationale: z.string().nullable().default(null),
  suppressionRationale: z.string().nullable().default(null),
  evidenceReferences: z.array(z.string()).default([]),
});
export type ClosureSummary = z.infer<typeof ClosureSummary>;

export const CaseReturnSummary = z.object({
  schemaVersion: z
    .literal("case_return_summary.v1")
    .default("case_return_summary.v1"),
  caseId: z.string(),
  caseNumber: z.string(),
  generatedAt: z.string().datetime({ offset: true }),
  finalVerdict: AlertVerdictEnum,
  finalCategory: AlertCategoryEnum,
  finalSeverity: AlertSeverityEnum,
  outcomeSummary: z.string(),
  rootCause: z.string().nullable().default(null),
  lessonsLearned: z.string().nullable().default(null),
  linkedAlertIds: z.array(z.string()).default([]),
  confidence: ArtifactConfidence.default({ score: null, band: "unknown" }),
});
export type CaseReturnSummary = z.infer<typeof CaseReturnSummary>;

// ============================================================================
// Trust-layer artifacts : PolicyRef, RiskArbitration, ApprovalDecision
// ============================================================================

export const PolicyRef = z.object({
  policyKind: z.string().min(1),
  policyId: z.string().min(1),
  version: z.string().nullable().default(null),
});
export type PolicyRef = z.infer<typeof PolicyRef>;

export const ArbitrationAuthority = z.object({
  role: z.enum([
    "ciso",
    "dro",
    "dpo",
    "manager",
    "senior_analyst",
    "service_owner",
    "other",
  ]),
  signerId: z.string().min(1),
  signerName: z.string().min(1),
});
export type ArbitrationAuthority = z.infer<typeof ArbitrationAuthority>;

export const ArbitrationScope = z.object({
  scopeKind: z.string().min(1),
  selectorValue: z.string().min(1),
});
export type ArbitrationScope = z.infer<typeof ArbitrationScope>;

export const AcceptedRisk = z.object({
  name: z.string().min(1),
  description: z.string().min(1),
});
export type AcceptedRisk = z.infer<typeof AcceptedRisk>;

export const RiskArbitrationPayload = z.object({
  authority: ArbitrationAuthority,
  scope: z.array(ArbitrationScope).min(1),
  acceptedRisks: z.array(AcceptedRisk).min(1),
  policyRef: PolicyRef.nullable().default(null),
  validFrom: z.string().datetime({ offset: true }),
  validUntil: z.string().datetime({ offset: true }),
  justification: z.string().min(1),
});
export type RiskArbitrationPayload = z.infer<typeof RiskArbitrationPayload>;

export const RiskArbitration = z.object({
  envelope: ArtifactEnvelope,
  payload: RiskArbitrationPayload,
});
export type RiskArbitration = z.infer<typeof RiskArbitration>;

export const ResponseActionRequestRef = z.object({
  actionId: z.string().min(1),
  subjectKind: z.string().min(1),
  subjectValue: z.string().min(1),
  idempotencyKey: z.string().min(1),
});
export type ResponseActionRequestRef = z.infer<typeof ResponseActionRequestRef>;

export const ApprovalDecisionPayload = z.object({
  requestRef: ResponseActionRequestRef,
  decisionMakerKind: z.enum(["human", "automation"]),
  decisionMakerId: z.string().min(1),
  decision: z.enum(["approved", "denied"]),
  decidedAt: z.string().datetime({ offset: true }),
  basisRef: PolicyRef.nullable().default(null),
  rationale: z.string().min(1),
  expirationOverride: z.string().datetime({ offset: true }).nullable().default(null),
});
export type ApprovalDecisionPayload = z.infer<typeof ApprovalDecisionPayload>;

export const ApprovalDecision = z.object({
  envelope: ArtifactEnvelope,
  payload: ApprovalDecisionPayload,
});
export type ApprovalDecision = z.infer<typeof ApprovalDecision>;
