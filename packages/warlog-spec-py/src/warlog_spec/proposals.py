"""Canonical proposal types — recommended-but-not-yet-applied workflow steps.

Where :mod:`warlog_spec.artifacts` defines **assessments** (what we
observe : MITRE mapping, enrichment payload, closure summary),
proposals are **recommendations** : a producer (typically an ML
classifier, a rule engine, or an LLM playbook agent) suggests
a transition the human MAY accept. The envelope marks ``requires_approval``
explicitly ; the runtime gates execution behind the approval workflow.

The four canonical proposal shapes :

- :class:`TriageProposal` — recommended status / severity / verdict /
  category for an alert during triage.
- :class:`NextStepProposal` — ordered list of suggested follow-up
  actions (investigate, contain, communicate, escalate, …).
- :class:`PlaybookCandidateProposal` — ranked playbooks to apply,
  with preconditions + required capabilities.
- :class:`InvestigationSummaryProposal` — synthesized investigation
  narrative (findings, hypothesis, impact, unresolved questions) for
  L1→L2 handoff or case closure.

Promoted from the backend (``app.schemas.canonical``) so adopters can
build proposers + reviewers against the same typed contract.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from warlog_spec._base import SpecModel
from warlog_spec.artifacts import (
    ArtifactCitation,
    ArtifactConfidence,
)
from warlog_spec.enums import (
    AlertCategory,
    AlertSeverity,
    AlertStatus,
    AlertVerdict,
    CasePriority,
)

from enum import StrEnum


# =============================================================================
# Envelope + step-kind enum shared by all proposal shapes
# =============================================================================


class ProposalStepKind(StrEnum):
    """Kind of next-step a :class:`NextStepProposal` recommends.

    Mirrors the operational categories analysts use to bucket
    follow-up actions. ``closure_preparation`` covers steps that
    don't act but assemble closure evidence (e.g. drafting the
    closure summary).
    """

    INVESTIGATION = "investigation"
    ENRICHMENT = "enrichment"
    CONTAINMENT = "containment"
    COMMUNICATION = "communication"
    ESCALATION = "escalation"
    CLOSURE_PREPARATION = "closure_preparation"


class ProposalEnvelope(SpecModel):
    """Provenance + approval metadata around any proposal payload.

    Distinct from :class:`~warlog_spec.artifacts.ArtifactEnvelope` :
    where artifacts describe what was observed (and are passively
    consumed), proposals carry an explicit approval contract :
    ``requires_approval`` MUST be true unless a tenant policy
    auto-approves the class. ``can_mutate`` declares whether
    accepting the proposal triggers a state change (set ``False``
    for review-only suggestions).
    """

    proposal_type: str
    proposal_version: str = "v1"
    proposal_id: str
    subject_type: Literal["alert", "case"]
    subject_id: str
    requires_approval: bool = True
    can_mutate: bool = False
    confidence: ArtifactConfidence = Field(default_factory=ArtifactConfidence)
    citations: list[ArtifactCitation] = Field(default_factory=list)
    rationale: str


# =============================================================================
# TriageProposal — recommended triage state for an alert
# =============================================================================


class TriageProposalPayload(SpecModel):
    """Body of a :class:`TriageProposal` : recommended status, severity,
    verdict, and category for an alert + optional priority hint.

    ``should_create_case`` is the explicit escalation signal — when
    True the orchestrator opens (or routes into) a case. ``summary``
    is the one-line rationale surfaced on the triage queue.
    """

    recommended_status: AlertStatus
    recommended_severity: AlertSeverity
    recommended_verdict: AlertVerdict
    recommended_category: AlertCategory
    should_create_case: bool = False
    priority_hint: CasePriority = CasePriority.UNKNOWN
    summary: str


class TriageProposal(SpecModel):
    """Envelope-wrapped triage recommendation for an alert."""

    envelope: ProposalEnvelope
    payload: TriageProposalPayload


# =============================================================================
# NextStepProposal — ordered list of follow-up actions
# =============================================================================


class NextStep(SpecModel):
    """One suggested follow-up step inside a :class:`NextStepProposal`."""

    title: str
    kind: ProposalStepKind
    priority: int = Field(ge=1)
    expected_outcome: str


class NextStepProposalPayload(SpecModel):
    steps: list[NextStep] = Field(default_factory=list)


class NextStepProposal(SpecModel):
    """Envelope-wrapped recommended follow-up actions."""

    envelope: ProposalEnvelope
    payload: NextStepProposalPayload


# =============================================================================
# PlaybookCandidateProposal — ranked playbooks to apply
# =============================================================================


class PlaybookCandidate(SpecModel):
    """A single playbook the proposer recommends as a candidate.

    ``required_capability_keys`` lets the orchestrator pre-resolve
    whether the candidate is executable given the tenant's current
    connector bindings, without an extra round-trip per candidate.
    """

    playbook_id: str
    playbook_name: str
    why_recommended: str
    preconditions: list[str] = Field(default_factory=list)
    approval_level: Literal["none", "analyst", "senior", "manager"] = "analyst"
    required_capability_keys: list[str] = Field(default_factory=list)


class PlaybookCandidateProposalPayload(SpecModel):
    candidate_playbooks: list[PlaybookCandidate] = Field(default_factory=list)
    why_recommended: str
    preconditions: list[str] = Field(default_factory=list)


class PlaybookCandidateProposal(SpecModel):
    """Envelope-wrapped ranked list of candidate playbooks."""

    envelope: ProposalEnvelope
    payload: PlaybookCandidateProposalPayload


# =============================================================================
# InvestigationSummaryProposal — handoff or closure narrative
# =============================================================================


class InvestigationSummaryProposalPayload(SpecModel):
    """Synthesized investigation summary : findings, hypothesis,
    impact, recommended next steps, unresolved questions.

    Produced at L1→L2 handoff (case escalation) or at case closure
    (becomes part of the :class:`~warlog_spec.artifacts.CaseReturnSummary`).
    """

    summary: str
    hypothesis: str | None = None
    findings: list[str] = Field(default_factory=list)
    impact_assessment: str | None = None
    next_steps: list[str] = Field(default_factory=list)
    unresolved_questions: list[str] = Field(default_factory=list)
    confidence: ArtifactConfidence = Field(default_factory=ArtifactConfidence)


class InvestigationSummaryProposal(SpecModel):
    """Envelope-wrapped synthesized investigation summary."""

    envelope: ProposalEnvelope
    payload: InvestigationSummaryProposalPayload


__all__ = [
    "InvestigationSummaryProposal",
    "InvestigationSummaryProposalPayload",
    "NextStep",
    "NextStepProposal",
    "NextStepProposalPayload",
    "PlaybookCandidate",
    "PlaybookCandidateProposal",
    "PlaybookCandidateProposalPayload",
    "ProposalEnvelope",
    "ProposalStepKind",
    "TriageProposal",
    "TriageProposalPayload",
]
