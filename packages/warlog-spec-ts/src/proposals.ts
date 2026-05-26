/**
 * Canonical proposal types. Mirrors `warlog_spec.proposals`.
 *
 * Where artifacts describe what was observed, proposals are
 * recommendations a human MAY accept. The envelope marks
 * ``requiresApproval`` explicitly.
 */

import { z } from "zod";

import {
  AlertCategory,
  AlertSeverity,
  AlertStatus,
  AlertVerdict,
  CasePriority,
  ProposalStepKind,
} from "./enums.js";
import { ArtifactCitation, ArtifactConfidence } from "./artifacts.js";

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

const AlertStatusEnum = z.enum([
  AlertStatus.NEW,
  AlertStatus.TRIAGING,
  AlertStatus.INVESTIGATING,
  AlertStatus.ESCALATED,
  AlertStatus.PENDING,
  AlertStatus.RESOLVED,
  AlertStatus.CLOSED,
  AlertStatus.SUPPRESSED,
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

const CasePriorityEnum = z.enum([
  CasePriority.P1,
  CasePriority.P2,
  CasePriority.P3,
  CasePriority.P4,
  CasePriority.UNKNOWN,
]);

const ProposalStepKindEnum = z.enum([
  ProposalStepKind.INVESTIGATION,
  ProposalStepKind.ENRICHMENT,
  ProposalStepKind.CONTAINMENT,
  ProposalStepKind.COMMUNICATION,
  ProposalStepKind.ESCALATION,
  ProposalStepKind.CLOSURE_PREPARATION,
]);

// ============================================================================
// Envelope shared by all proposal shapes
// ============================================================================

export const ProposalEnvelope = z.object({
  proposalType: z.string(),
  proposalVersion: z.string().default("v1"),
  proposalId: z.string(),
  subjectType: z.enum(["alert", "case"]),
  subjectId: z.string(),
  requiresApproval: z.boolean().default(true),
  canMutate: z.boolean().default(false),
  confidence: ArtifactConfidence.default({ score: null, band: "unknown" }),
  citations: z.array(ArtifactCitation).default([]),
  rationale: z.string(),
});
export type ProposalEnvelope = z.infer<typeof ProposalEnvelope>;

// ============================================================================
// TriageProposal
// ============================================================================

export const TriageProposalPayload = z.object({
  recommendedStatus: AlertStatusEnum,
  recommendedSeverity: AlertSeverityEnum,
  recommendedVerdict: AlertVerdictEnum,
  recommendedCategory: AlertCategoryEnum,
  shouldCreateCase: z.boolean().default(false),
  priorityHint: CasePriorityEnum.default("unknown"),
  summary: z.string(),
});
export type TriageProposalPayload = z.infer<typeof TriageProposalPayload>;

export const TriageProposal = z.object({
  envelope: ProposalEnvelope,
  payload: TriageProposalPayload,
});
export type TriageProposal = z.infer<typeof TriageProposal>;

// ============================================================================
// NextStepProposal
// ============================================================================

export const NextStep = z.object({
  title: z.string(),
  kind: ProposalStepKindEnum,
  priority: z.number().int().min(1),
  expectedOutcome: z.string(),
});
export type NextStep = z.infer<typeof NextStep>;

export const NextStepProposalPayload = z.object({
  steps: z.array(NextStep).default([]),
});
export type NextStepProposalPayload = z.infer<typeof NextStepProposalPayload>;

export const NextStepProposal = z.object({
  envelope: ProposalEnvelope,
  payload: NextStepProposalPayload,
});
export type NextStepProposal = z.infer<typeof NextStepProposal>;

// ============================================================================
// PlaybookCandidateProposal
// ============================================================================

export const PlaybookCandidate = z.object({
  playbookId: z.string(),
  playbookName: z.string(),
  whyRecommended: z.string(),
  preconditions: z.array(z.string()).default([]),
  approvalLevel: z.enum(["none", "analyst", "senior", "manager"]).default("analyst"),
  requiredCapabilityKeys: z.array(z.string()).default([]),
});
export type PlaybookCandidate = z.infer<typeof PlaybookCandidate>;

export const PlaybookCandidateProposalPayload = z.object({
  candidatePlaybooks: z.array(PlaybookCandidate).default([]),
  whyRecommended: z.string(),
  preconditions: z.array(z.string()).default([]),
});
export type PlaybookCandidateProposalPayload = z.infer<
  typeof PlaybookCandidateProposalPayload
>;

export const PlaybookCandidateProposal = z.object({
  envelope: ProposalEnvelope,
  payload: PlaybookCandidateProposalPayload,
});
export type PlaybookCandidateProposal = z.infer<typeof PlaybookCandidateProposal>;

// ============================================================================
// InvestigationSummaryProposal
// ============================================================================

export const InvestigationSummaryProposalPayload = z.object({
  summary: z.string(),
  hypothesis: z.string().nullable().default(null),
  findings: z.array(z.string()).default([]),
  impactAssessment: z.string().nullable().default(null),
  nextSteps: z.array(z.string()).default([]),
  unresolvedQuestions: z.array(z.string()).default([]),
  confidence: ArtifactConfidence.default({ score: null, band: "unknown" }),
});
export type InvestigationSummaryProposalPayload = z.infer<
  typeof InvestigationSummaryProposalPayload
>;

export const InvestigationSummaryProposal = z.object({
  envelope: ProposalEnvelope,
  payload: InvestigationSummaryProposalPayload,
});
export type InvestigationSummaryProposal = z.infer<typeof InvestigationSummaryProposal>;
