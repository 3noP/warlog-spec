/**
 * Canonical workflow enums — single source of truth, mirrors
 * `warlog_spec.enums` in the Python package.
 *
 * Each enum is exposed both as a frozen object (`AlertSeverity.HIGH`)
 * for ergonomic constant access AND as a string-literal union type
 * (`AlertSeverityValue`) for type-narrowing in function signatures.
 * This matches the Python `StrEnum` pattern : the value IS the
 * string, and the type system enforces the closed set.
 */

const freeze = <T extends object>(o: T): Readonly<T> => Object.freeze(o);

// ----------------------------------------------------------------------------
// Alert / Case workflow enums
// ----------------------------------------------------------------------------

export const AlertSeverity = freeze({
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  INFO: "info",
  UNKNOWN: "unknown",
} as const);
export type AlertSeverityValue = (typeof AlertSeverity)[keyof typeof AlertSeverity];

export const AlertStatus = freeze({
  NEW: "new",
  TRIAGING: "triaging",
  INVESTIGATING: "investigating",
  ESCALATED: "escalated",
  PENDING: "pending",
  RESOLVED: "resolved",
  CLOSED: "closed",
  SUPPRESSED: "suppressed",
} as const);
export type AlertStatusValue = (typeof AlertStatus)[keyof typeof AlertStatus];

export const AlertVerdict = freeze({
  UNDETERMINED: "undetermined",
  TRUE_POSITIVE: "true_positive",
  FALSE_POSITIVE: "false_positive",
  BENIGN: "benign",
  SUSPICIOUS: "suspicious",
  MIXED: "mixed",
  NEEDS_REVIEW: "needs_review",
} as const);
export type AlertVerdictValue = (typeof AlertVerdict)[keyof typeof AlertVerdict];

export const AlertCategory = freeze({
  MALWARE: "malware",
  PHISHING: "phishing",
  CREDENTIAL_ACCESS: "credential_access",
  UNAUTHORIZED_ACCESS: "unauthorized_access",
  LATERAL_MOVEMENT: "lateral_movement",
  EXECUTION: "execution",
  PERSISTENCE: "persistence",
  EXFILTRATION: "exfiltration",
  DATA_BREACH: "data_breach",
  INSIDER_THREAT: "insider_threat",
  POLICY_VIOLATION: "policy_violation",
  DENIAL_OF_SERVICE: "denial_of_service",
  RECONNAISSANCE: "reconnaissance",
  IMPACT: "impact",
  OTHER: "other",
  UNKNOWN: "unknown",
  NEEDS_REVIEW: "needs_review",
} as const);
export type AlertCategoryValue = (typeof AlertCategory)[keyof typeof AlertCategory];

export const AlertSource = freeze({
  EDR: "edr",
  SIEM: "siem",
  EMAIL_SECURITY: "email_security",
  IAM: "iam",
  NETWORK: "network",
  CLOUD: "cloud",
  THREAT_INTEL: "threat_intel",
  MANUAL: "manual",
  CORRELATION: "correlation",
  UNKNOWN: "unknown",
} as const);
export type AlertSourceValue = (typeof AlertSource)[keyof typeof AlertSource];

export const CaseStatus = freeze({
  NEW: "new",
  INVESTIGATING: "investigating",
  CONTAINMENT: "containment",
  ERADICATION: "eradication",
  RECOVERY: "recovery",
  CLOSED: "closed",
  PENDING_L1_INFO: "pending_l1_info",
} as const);
export type CaseStatusValue = (typeof CaseStatus)[keyof typeof CaseStatus];

export const CasePriority = freeze({
  P1: "p1",
  P2: "p2",
  P3: "p3",
  P4: "p4",
  UNKNOWN: "unknown",
} as const);
export type CasePriorityValue = (typeof CasePriority)[keyof typeof CasePriority];

export const CaseSeverity = freeze({
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  INFO: "info",
  UNKNOWN: "unknown",
} as const);
export type CaseSeverityValue = (typeof CaseSeverity)[keyof typeof CaseSeverity];

export const CaseCategory = AlertCategory;
export type CaseCategoryValue = AlertCategoryValue;

// ----------------------------------------------------------------------------
// Entity / IOC enums
// ----------------------------------------------------------------------------

export const EntityType = freeze({
  HOST: "host",
  USER: "user",
  IP: "ip",
  DOMAIN: "domain",
  URL: "url",
  HASH: "hash",
  FILE: "file",
  PROCESS: "process",
  EMAIL: "email",
  ASSET_GROUP: "asset_group",
  ORGANIZATION: "organization",
  OTHER: "other",
} as const);
export type EntityTypeValue = (typeof EntityType)[keyof typeof EntityType];

export const EntityRole = freeze({
  SUBJECT: "subject",
  TARGET: "target",
  RELATED: "related",
  CONTEXT: "context",
  UNKNOWN: "unknown",
} as const);
export type EntityRoleValue = (typeof EntityRole)[keyof typeof EntityRole];

export const IOCType = freeze({
  IP: "ip",
  IPV6: "ipv6",
  DOMAIN: "domain",
  URL: "url",
  HASH_MD5: "hash_md5",
  HASH_SHA1: "hash_sha1",
  HASH_SHA256: "hash_sha256",
  EMAIL: "email",
  USER: "user",
  PROCESS: "process",
  REGISTRY_KEY: "registry_key",
  FILE_PATH: "file_path",
  CERTIFICATE: "certificate",
  CVE: "cve",
  OTHER: "other",
} as const);
export type IOCTypeValue = (typeof IOCType)[keyof typeof IOCType];

// ----------------------------------------------------------------------------
// Provider ABI enums (trust-layer)
// ----------------------------------------------------------------------------

export const ComplianceScope = freeze({
  NIS2: "nis2",
  DORA: "dora",
  PCI_DSS_V4: "pci_dss_v4",
  SOX: "sox",
  HDS: "hds",
  SECNUMCLOUD: "secnumcloud",
  HIPAA: "hipaa",
  GDPR: "gdpr",
  ISO_27001: "iso_27001",
} as const);
export type ComplianceScopeValue = (typeof ComplianceScope)[keyof typeof ComplianceScope];

export const SelectorRepresentation = freeze({
  RAW: "raw",
  SHA256: "sha256",
  SHA256_SALTED: "sha256_salted",
} as const);
export type SelectorRepresentationValue =
  (typeof SelectorRepresentation)[keyof typeof SelectorRepresentation];

// ----------------------------------------------------------------------------
// Workflow / proposal enums
// ----------------------------------------------------------------------------

export const ProposalStepKind = freeze({
  INVESTIGATION: "investigation",
  ENRICHMENT: "enrichment",
  CONTAINMENT: "containment",
  COMMUNICATION: "communication",
  ESCALATION: "escalation",
  CLOSURE_PREPARATION: "closure_preparation",
} as const);
export type ProposalStepKindValue =
  (typeof ProposalStepKind)[keyof typeof ProposalStepKind];

export const IncidentPhase = freeze({
  IDENTIFICATION: "identification",
  CONTAINMENT: "containment",
  ERADICATION: "eradication",
  RECOVERY: "recovery",
  LESSONS_LEARNED: "lessons_learned",
} as const);
export type IncidentPhaseValue = (typeof IncidentPhase)[keyof typeof IncidentPhase];

// ----------------------------------------------------------------------------
// Confidence + review-state (canon-only, no DB persistence)
// ----------------------------------------------------------------------------

export const ConfidenceBand = freeze({
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  UNKNOWN: "unknown",
} as const);
export type ConfidenceBandValue = (typeof ConfidenceBand)[keyof typeof ConfidenceBand];

export const ArtifactReviewState = freeze({
  PENDING: "pending",
  ACCEPTED: "accepted",
  REJECTED: "rejected",
  SUPERSEDED: "superseded",
} as const);
export type ArtifactReviewStateValue =
  (typeof ArtifactReviewState)[keyof typeof ArtifactReviewState];
