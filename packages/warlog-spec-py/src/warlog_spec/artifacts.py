"""Canonical read-side artifact types — public data contract.

Where the Provider ABI (``warlog_spec.provider_abi``) defines the
**write-side** vendor contract (what an analyst can ASK a vendor to
do — host.isolate, user.disable, key.rotate, ...), this module
defines the **read-side** vendor contract : what a connector PRODUCES
canonically when an entity is enriched, an IOC is looked up, an
alert is classified, or MITRE coverage is assessed.

The two surfaces are deliberately asymmetric :

- Write side : verbs (``ResponseActionId``) with lifecycle hooks
  (auth → dry_run → approval → apply → verify), audit chain, params
  validation. The contract is "how to issue the action".
- Read side : data shapes (``ArtifactEnvelope`` and friends) with
  provenance, confidence, and citations. The contract is "what the
  result looks like, regardless of which vendor produced it".

A connector that wraps VirusTotal, AbuseIPDB, Shodan, or an internal
ML model returns the same ``ArtifactEnvelope`` shape with the same
``ArtifactProducer`` / ``ArtifactConfidence`` / ``ArtifactCitation``
metadata. Downstream bundle assemblers, UI surfaces, and audit
tooling never depend on which specific enricher produced an artifact
— only on the canonical shape.

Doctrine note : these types are PROMOTED here from
``backend/app/schemas/canonical.py`` exactly as they were in the
Warlog product. Same fields, same defaults, same camelCase wire
format. The backend re-exports from here ; there is no duplication.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import Field

from warlog_spec._base import SpecModel
from warlog_spec.enums import (
    AlertCategory,
    AlertSeverity,
    AlertVerdict,
    EntityRole,
    EntityType,
    IOCType,
)


# =============================================================================
# Canon-only enums (no DB persistence, no business-state semantics)
# =============================================================================


class ConfidenceBand(StrEnum):
    """Coarse-grained confidence band used when a numeric score is not the
    right surface (e.g. for human-readable summaries or UI badges)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    UNKNOWN = "unknown"


class ArtifactReviewState(StrEnum):
    """Lifecycle state of a produced artifact through human review.

    A connector emits artifacts in ``PENDING`` ; analysts move them
    through ``ACCEPTED`` / ``REJECTED``. ``SUPERSEDED`` covers the
    case where a fresher artifact about the same subject replaces an
    older one (e.g. a re-enrichment after the IOC verdict flipped).
    """

    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    SUPERSEDED = "superseded"


# =============================================================================
# Provenance / confidence / citation primitives
# =============================================================================


class ArtifactProducer(SpecModel):
    """Who or what generated an artifact.

    The five kinds map cleanly to the provenance categories that
    matter for downstream review : human-authored, rule-based,
    ML-model-output, LLM-output, or system-internal (e.g. an
    auto-correlator).
    """

    kind: Literal["llm", "rule", "ml", "human", "system"]
    name: str
    model: str | None = None


class ArtifactConfidence(SpecModel):
    """A numeric confidence score paired with a coarse-grained band.

    Both fields are optional so that producers without a probabilistic
    model can still emit confidence (band only) and probabilistic
    producers can emit both. Consumers read whichever is present.
    """

    score: float | None = Field(default=None, ge=0.0, le=1.0)
    band: ConfidenceBand = ConfidenceBand.UNKNOWN


class ArtifactCitation(SpecModel):
    """A pointer to evidence that supports an artifact.

    Citations are how downstream review can audit a producer's
    reasoning : "this MITRE T1078 mapping was supported by event X
    section Y at score 0.83". The exact ``source_kind`` vocabulary is
    open (``alert``, ``log_event``, ``threat_intel_feed``, etc.) ;
    consumers MUST tolerate kinds they don't recognize.
    """

    source_id: str = Field(description="Identifier of the supporting source")
    source_kind: str = Field(description="Type of supporting source")
    section: str | None = Field(default=None, description="Optional section or path")
    score: float | None = Field(default=None, ge=0.0, le=1.0)


# =============================================================================
# Subjects : entities and IOCs
# =============================================================================


class NormalizedEntity(SpecModel):
    """A canonical entity reference (host, user, IP, hash, ...).

    The vendor-side identifier is normalized at extraction time into
    ``(entity_type, value)`` ; ``role`` distinguishes the entity's
    semantic role in the alert/case (subject, target, related, ...).
    Connectors producing context artifacts about an entity reference
    it via this shape ; downstream consumers route by ``entity_type``.
    """

    entity_type: EntityType
    value: str
    role: EntityRole = EntityRole.UNKNOWN
    confidence: ArtifactConfidence = Field(default_factory=ArtifactConfidence)
    source_fields: list[str] = Field(default_factory=list)


class ExtractedIOC(SpecModel):
    """A canonical indicator-of-compromise reference.

    Distinct from :class:`NormalizedEntity` because IOCs carry
    threat-intel-specific metadata (``maliciousness``, feed
    provenance, first/last-seen) that doesn't apply to e.g. an
    internal user or host entity.
    """

    ioc_type: IOCType
    value: str
    confidence: ArtifactConfidence = Field(default_factory=ArtifactConfidence)
    maliciousness: AlertVerdict = AlertVerdict.UNDETERMINED
    source_fields: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    # Threat-intel feed provenance — set when this IOC was tagged from
    # a ThreatIntelFeed snapshot. Both stay NULL when extraction came
    # from raw event data without an intel hit.
    feed_id: str | None = None
    feed_freshness_at: datetime | None = None


# =============================================================================
# ArtifactEnvelope : the unified read-side wrapper
# =============================================================================


class ArtifactEnvelope(SpecModel):
    """Canonical envelope every read-side artifact rides in.

    The ``artifact_type`` string identifies WHAT was produced (an
    enrichment, a classification, a MITRE assessment, ...). The
    ``subject_*`` fields identify what it's ABOUT (an alert or a
    case). Producer / confidence / citations carry HOW it was made.
    The actual payload of the artifact lives outside the envelope —
    typed assessment classes (``ClassificationAssessment``,
    ``MitreAssessment``, ``EnrichmentAssessment``) compose the
    envelope with their specific payload.

    This is the read-side analogue of :class:`warlog_spec.provider_abi.AuditRow`
    on the write side : a uniform envelope shape that audit, review,
    and surface tooling can consume without knowing the producer.
    """

    artifact_type: str
    artifact_version: str = "v1"
    subject_type: Literal["alert", "case"]
    subject_id: str
    producer: ArtifactProducer
    generated_at: datetime
    confidence: ArtifactConfidence = Field(default_factory=ArtifactConfidence)
    review_state: ArtifactReviewState = ArtifactReviewState.PENDING
    citations: list[ArtifactCitation] = Field(default_factory=list)


# =============================================================================
# CanonicalArtifact : the base every envelope-bearing artifact inherits from
# =============================================================================


class CanonicalArtifact(SpecModel):
    """Base class for every envelope-bearing canonical artifact.

    Any read-side artifact shape that an :class:`~warlog_spec.abi.AbiEnricher`
    is allowed to return inherits from this. The shared ``envelope``
    field carries the provenance / confidence / citation metadata
    plus the ``artifact_type`` string the connector's
    :class:`~warlog_spec.provider_abi.EnrichmentDescriptor` declared.

    Subclasses (:class:`EnrichmentAssessment`, :class:`MitreAssessment`,
    …) add their typed payload alongside the envelope. The runtime /
    orchestrator routes by ``envelope.artifact_type`` ; consumers
    type-narrow to the specific subclass when they care about the
    payload shape.

    This base exists so the public ABC return type
    (``AbiEnricher.enrich() -> CanonicalArtifact | None``) is honest :
    a connector advertising ``produces_artifact_types =
    ["mitre.assessment"]`` returns a :class:`MitreAssessment`, one
    advertising ``["enrichment.ioc_reputation"]`` returns an
    :class:`EnrichmentAssessment` — both are valid inhabitants of
    the return type. Without this base, the descriptor could declare
    artifact types the ABC return type forbade.
    """

    envelope: ArtifactEnvelope


# =============================================================================
# Read-side request : carries subject + target so the enricher
# does not depend on implicit runtime stamping
# =============================================================================


class EnrichmentRequest(SpecModel):
    """Input to :meth:`~warlog_spec.abi.AbiEnricher.enrich`.

    The request carries TWO pieces the enricher needs to produce a
    self-attributed artifact :

    - ``subject_type`` / ``subject_id`` — the alert or case the
      resulting artifact will be ATTRIBUTED to. The enricher copies
      these into ``ArtifactEnvelope.subject_type`` / ``subject_id``
      so the produced artifact is self-attributing without any
      implicit runtime post-processing. (Earlier drafts had the
      enricher emit ``subject_id=""`` and rely on the runtime to
      stamp it ; that was a contract hole the request shape closes.)
    - ``target`` — the entity or IOC the enricher should resolve.
      The vendor lookup is keyed on this.

    Connectors that don't need ``subject_id`` for any vendor-side
    behaviour (most of them) just thread it through to the envelope.
    """

    subject_type: Literal["alert", "case"]
    subject_id: str = Field(min_length=1)
    target: NormalizedEntity | ExtractedIOC


# =============================================================================
# MITRE assessment artifacts
# =============================================================================


class AlternativeTechnique(SpecModel):
    """A non-primary technique the assessment considered."""

    technique: str
    why: str


class MitreMapping(SpecModel):
    """ATT&CK tactics + techniques an artifact maps to."""

    tactics: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)


class MitreAssessment(CanonicalArtifact):
    """Envelope-wrapped MITRE mapping with reasoning. Inherits the
    canonical ``envelope`` field from :class:`CanonicalArtifact`."""

    mitre: MitreMapping
    reasoning: str
    alternatives: list[AlternativeTechnique] = Field(default_factory=list)


# =============================================================================
# Enrichment assessment artifacts
# =============================================================================


class EnrichmentAssessmentPayload(SpecModel):
    """The actual enrichment payload — what context the lookup added.

    Each field is optional so different enrichers can fill different
    slices : a host enricher fills ``asset_criticality`` and
    ``user_context`` ; a hash reputation enricher fills
    ``threat_intel_hits`` and ``matched_iocs`` ; a behavior enricher
    fills ``anomalies``. The same payload shape carries all of them.
    """

    related_entities: list[NormalizedEntity] = Field(default_factory=list)
    matched_iocs: list[ExtractedIOC] = Field(default_factory=list)
    prevalence_summary: str | None = None
    asset_criticality: ConfidenceBand = ConfidenceBand.UNKNOWN
    user_context: str | None = None
    threat_intel_hits: list[str] = Field(default_factory=list)
    anomalies: list[str] = Field(default_factory=list)


class EnrichmentAssessment(CanonicalArtifact):
    """Envelope-wrapped enrichment payload — the canonical read-side
    output of an enricher connector. Inherits the canonical
    ``envelope`` field from :class:`CanonicalArtifact`.

    A connector wrapping VirusTotal, AbuseIPDB, Shodan, GreyNoise, or
    an internal ML model produces this exact shape. The orchestrator
    (or bundle assembler) merges multiple ``EnrichmentAssessment``
    instances about the same subject without caring which connector
    produced each.
    """

    payload: EnrichmentAssessmentPayload


# =============================================================================
# Classification assessment artifacts
# =============================================================================


class ClassificationDecision(SpecModel):
    """Triage-time classification : category / severity / verdict /
    escalation recommendation.

    Produced by classifier models or rule-based scorers ; consumed by
    the triage proposal layer + the alert surface. ``escalation_risk``
    is a coarse-grained band rather than a numeric score because it
    drives a UI badge, not a routing decision.
    """

    category: AlertCategory = AlertCategory.UNKNOWN
    severity: AlertSeverity = AlertSeverity.UNKNOWN
    verdict: AlertVerdict = AlertVerdict.UNDETERMINED
    should_escalate: bool = False
    escalation_risk: ConfidenceBand = ConfidenceBand.UNKNOWN


class ClassificationAssessment(CanonicalArtifact):
    """Envelope-wrapped triage classification.

    Produced by a classifier (rule, ML, or LLM) at triage time and
    surfaced to the analyst alongside the alert. ``evidence_summary``
    is the short rationale ; ``missing_evidence`` declares what the
    classifier would need to raise its confidence (used by an
    orchestrator to decide whether to schedule an enrichment).
    """

    classification: ClassificationDecision
    reasoning: str
    evidence_summary: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)


# =============================================================================
# Closure + case-return summary (decision-class artifacts)
# =============================================================================


class ClosureSummary(SpecModel):
    """Explicit closure artifact produced when an alert or case is closed.

    Auditable record of what was concluded and why. NOT a
    :class:`CanonicalArtifact` because it predates the envelope-based
    artifact pattern in the spec — instead it carries ``schema_version``,
    ``subject_type``, and ``subject_id`` directly on the body. Surfaces
    on the closed alert / case so future triage of related entities
    inherits the closure context.
    """

    schema_version: Literal["closure_summary.v1"] = "closure_summary.v1"
    subject_type: Literal["alert", "case"]
    subject_id: str
    generated_at: datetime
    closed_by: str
    verdict: AlertVerdict
    category: AlertCategory
    resolution_summary: str
    false_positive_rationale: str | None = None
    suppression_rationale: str | None = None
    evidence_references: list[str] = Field(default_factory=list)


class CaseReturnSummary(SpecModel):
    """Typed projection from a closed case back to linked alerts.

    Produced when a case closes and propagated to its linked alerts as
    context for future triage. Distinct from :class:`ClosureSummary` :
    closure is per-subject (one alert OR one case), case-return is the
    case → alerts fan-out summary so a future alert on the same entity
    has historical context without reading the case's full timeline.
    """

    schema_version: Literal["case_return_summary.v1"] = "case_return_summary.v1"
    case_id: str
    case_number: str
    generated_at: datetime
    final_verdict: AlertVerdict
    final_category: AlertCategory
    final_severity: AlertSeverity
    outcome_summary: str
    root_cause: str | None = None
    lessons_learned: str | None = None
    linked_alert_ids: list[str] = Field(default_factory=list)
    confidence: ArtifactConfidence = Field(default_factory=ArtifactConfidence)


# =============================================================================
# Trust-layer artifacts (ABI v2.0) : risk arbitration + approval decision
#
# These two artifacts make the "substrate" (the human, doctrinal layer of
# the SOC) a first-class citizen of the contract. They are produced by
# humans (or human-signed policy engines), referenced by AuditRow via
# DecisionRef, and survive the resilience of the audit chain itself.
# =============================================================================


class PolicyRef(SpecModel):
    """Pointer to a policy, playbook, or doctrine document.

    Open ``policy_kind`` vocabulary so the spec doesn't lock the
    substrate into a single doctrine-repository format. Common
    values today : ``"playbook"``, ``"policy_document"``,
    ``"doctrine_kb"``, ``"derogation"``, ``"runbook"``. Consumers
    MUST tolerate kinds they don't recognize.
    """

    policy_kind: str = Field(min_length=1)
    policy_id: str = Field(min_length=1)
    version: str | None = None


class ArbitrationAuthority(SpecModel):
    """Who signed a :class:`RiskArbitration`.

    The role is structured (CISO, DRO, manager, …) so audit queries
    can filter by signing authority. ``signer_id`` is the SSO sub /
    employee id ; ``signer_name`` is the displayable form persisted
    at signing time (so the row stays auditable even if the user
    object is later updated or deleted).
    """

    role: Literal["ciso", "dro", "dpo", "manager", "senior_analyst", "service_owner", "other"]
    signer_id: str = Field(min_length=1)
    signer_name: str = Field(min_length=1)


class ArbitrationScope(SpecModel):
    """A scope an arbitration applies to.

    Multiple scopes per arbitration are allowed — a single dérogation
    may cover several hosts, a whole business unit, or a regulated
    perimeter. ``scope_kind`` is open so the substrate is not locked
    to a fixed taxonomy (cloud accounts, business units, asset
    groups, etc.).
    """

    scope_kind: str = Field(
        min_length=1,
        description="Open vocabulary: 'host', 'business_unit', 'asset_group', 'compliance_perimeter', 'tenant', …",
    )
    selector_value: str = Field(min_length=1)


class AcceptedRisk(SpecModel):
    """A specific risk the arbitration explicitly accepts.

    Forces the substrate to name what it accepts rather than carry
    a generic free-form rationale. Auditors can map accepted risks
    to a risk register independent of the prose justification.
    """

    name: str = Field(min_length=1)
    description: str = Field(min_length=1)


class RiskArbitrationPayload(SpecModel):
    """Body of a :class:`RiskArbitration` artifact.

    Captures the human, doctrinal layer the v1 ABI was missing :
    who has signed off, what scope is covered, what risks are
    explicitly accepted, until when. Referenced by
    :class:`~warlog_spec.provider_abi.AuditRow.decision_ref` when an
    arbitration legitimizes an action.
    """

    authority: ArbitrationAuthority
    scope: list[ArbitrationScope] = Field(min_length=1)
    accepted_risks: list[AcceptedRisk] = Field(min_length=1)
    policy_ref: PolicyRef | None = None
    valid_from: datetime
    valid_until: datetime
    justification: str = Field(min_length=1)


class RiskArbitration(CanonicalArtifact):
    """Signed human arbitration that legitimizes a class of actions.

    Where :class:`~warlog_spec.provider_abi.ApprovalDescriptor` is a
    request-time gate ("does this specific apply need a senior to
    click"), :class:`RiskArbitration` is the durable, signed doctrinal
    decision that pre-authorizes a class of actions on a scope until
    expiration. It is the "Bob's tribal knowledge" of the SOC made
    into a contract artifact : auditable, versioned, expirable.

    Rides inside :class:`ArtifactEnvelope`. Produced by a human
    (``envelope.producer.kind = "human"``) or a policy engine that
    is itself signed by a human authority.
    """

    payload: RiskArbitrationPayload


class ResponseActionRequestRef(SpecModel):
    """Pointer back at the request an :class:`ApprovalDecision` resolves.

    Mirrors the :class:`~warlog_spec.provider_abi.ResponseActionSpec`
    triple (action_id, subject, idempotency_key) so a runtime can
    correlate the approval back to the originating request without
    holding the full spec.
    """

    action_id: str = Field(min_length=1)
    subject_kind: str = Field(min_length=1)
    subject_value: str = Field(min_length=1)
    idempotency_key: str = Field(min_length=1)


class ApprovalDecisionPayload(SpecModel):
    """Body of an :class:`ApprovalDecision` artifact.

    Distinct from :class:`~warlog_spec.provider_abi.ApprovalDescriptor`
    (which lives on the request side and declares what level is
    required) : this artifact records the EFFECTIVE decision that
    was made out-of-band by an authorized human (or signed-policy
    engine), so the audit chain has a typed object to point at via
    ``DecisionRef`` rather than relying on a row in the runtime's
    ``pending_approvals`` table.
    """

    request_ref: ResponseActionRequestRef
    decision_maker_kind: Literal["human", "automation"]
    decision_maker_id: str = Field(min_length=1)
    decision: Literal["approved", "denied"]
    decided_at: datetime
    basis_ref: PolicyRef | None = Field(
        default=None,
        description="Policy / playbook / arbitration this decision was based on.",
    )
    rationale: str = Field(min_length=1)
    expiration_override: datetime | None = Field(
        default=None,
        description="Override the request's expires_at when the approver wants a shorter window.",
    )


class ApprovalDecision(CanonicalArtifact):
    """Typed, signed record of an approval decision.

    Rides inside :class:`ArtifactEnvelope`. An audit row in the
    ``apply`` phase whose request required ``ApprovalLevel.SENIOR``
    or higher points at this artifact via ``decision_ref`` so the
    full chain (signal → arbitration → approval → apply) is
    traversable from any link.
    """

    payload: ApprovalDecisionPayload


__all__ = [
    "AcceptedRisk",
    "AlternativeTechnique",
    "ApprovalDecision",
    "ApprovalDecisionPayload",
    "ArbitrationAuthority",
    "ArbitrationScope",
    "ArtifactCitation",
    "ArtifactConfidence",
    "ArtifactEnvelope",
    "ArtifactProducer",
    "ArtifactReviewState",
    "CanonicalArtifact",
    "CaseReturnSummary",
    "ClassificationAssessment",
    "ClassificationDecision",
    "ClosureSummary",
    "ConfidenceBand",
    "EnrichmentAssessment",
    "EnrichmentAssessmentPayload",
    "EnrichmentRequest",
    "ExtractedIOC",
    "MitreAssessment",
    "MitreMapping",
    "NormalizedEntity",
    "PolicyRef",
    "ResponseActionRequestRef",
    "RiskArbitration",
    "RiskArbitrationPayload",
]
