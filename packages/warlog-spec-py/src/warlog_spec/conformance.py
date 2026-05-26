"""Conformance Level 2 (Write) — canonical example factories.

An implementation claims **Level 2** by producing one valid example
artifact for each of the 18 productible canonical types in the spec. This module
is the reference producer that ships with the Python implementation :
:func:`produce_all` returns a ``{schema_relpath: example_dict}``
mapping covering all 18 types.

The runner (``warlog-spec/tests/conformance/runner.py --level 2``)
consumes this output (or fixtures emitted by any other impl) and
validates each example against its schema. Pass = conformant.

Type coverage (18 productible shapes) :

- 7 read-side artifacts : ClassificationAssessment, MitreAssessment,
  EnrichmentAssessment, ClosureSummary, CaseReturnSummary,
  RiskArbitration, ApprovalDecision
- 4 proposals : TriageProposal, NextStepProposal,
  PlaybookCandidateProposal, InvestigationSummaryProposal
- 6 provider-ABI types : ConnectorCapability, ResponseActionSpec,
  ResponseActionResult, AuditRow, SignedAuditRow, ConnectorError
- 1 registry type : PackManifest

Doctrine — bundles are NOT in this list. The four bundle types
(``TriageBundle``, ``InvestigationBundle``, ``ResponseBundle``,
``IncidentBundle``) are product-specific UI projections that live
in the Warlog backend, not in the open spec. The open contract
stops at the hashable artifacts that ``DecisionRef`` references ;
bundle shapes are an operator's UI concern. See the doctrine note
in ``app/schemas/bundles.py`` in the Warlog backend repo.

All timestamps are pinned to a deterministic value so producing the
same example twice yields byte-identical output. Run
``python -m warlog_spec.conformance`` to dump every example to
stdout (one JSON object per type, newline-separated).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from warlog_spec.artifacts import (
    AcceptedRisk,
    ApprovalDecision,
    ApprovalDecisionPayload,
    ArbitrationAuthority,
    ArbitrationScope,
    ArtifactCitation,
    ArtifactConfidence,
    ArtifactEnvelope,
    ArtifactProducer,
    ArtifactReviewState,
    CaseReturnSummary,
    ClassificationAssessment,
    ClassificationDecision,
    ClosureSummary,
    ConfidenceBand,
    EnrichmentAssessment,
    EnrichmentAssessmentPayload,
    ExtractedIOC,
    MitreAssessment,
    MitreMapping,
    NormalizedEntity,
    PolicyRef,
    ResponseActionRequestRef,
    RiskArbitration,
    RiskArbitrationPayload,
)
from warlog_spec.enums import (
    AlertCategory,
    AlertSeverity,
    AlertStatus,
    AlertVerdict,
    CasePriority,
    CaseStatus,
    EntityRole,
    EntityType,
    IOCType,
)
from warlog_spec.pack_manifest import (
    PACK_MANIFEST_VERSION,
    PackCompat,
    PackContents,
    PackKind,
    PackManifest,
    PackProvenance,
    PackPublisher,
    TrustLevel,
)
from warlog_spec.audit_chain import canonicalize_v1, compute_genesis, compute_signature
from warlog_spec.proposals import (
    InvestigationSummaryProposal,
    InvestigationSummaryProposalPayload,
    NextStep,
    NextStepProposal,
    NextStepProposalPayload,
    PlaybookCandidate,
    PlaybookCandidateProposal,
    PlaybookCandidateProposalPayload,
    ProposalEnvelope,
    ProposalStepKind,
    TriageProposal,
    TriageProposalPayload,
)
from warlog_spec.provider_abi import (
    ABI_VERSION,
    AiAgentRef,
    ApprovalDescriptor,
    ApprovalLevel,
    AuditAttestation,
    AuditConnectorRef,
    AuditRow,
    AuthDescriptor,
    AutomationActor,
    ComplianceScope,
    ConnectorAuthModel,
    ConnectorCapability,
    ConnectorCompat,
    ConnectorError,
    ConnectorKind,
    DecisionArtifactType,
    DecisionRef,
    DryRunDescriptor,
    DryRunScope,
    EgressDescriptor,
    EnrichmentDescriptor,
    ExecutionOutcome,
    ExecutionPhase,
    FailureCategory,
    FreshnessHint,
    HumanActor,
    IngressDelivery,
    IngressDescriptor,
    LifecycleDescriptor,
    ResponseActionId,
    ResponseActionResult,
    ResponseActionScope,
    ResponseActionSpec,
    ResponseSubject,
    SelectorRepresentation,
    SignedAuditRow,
    TriggerSignalKind,
    TriggerSignalRef,
)

# Pinned timestamp so produce_all() is deterministic across calls and
# across processes — auditors comparing two outputs see byte-identical
# diffs unless the canonical shape itself changed.
_TS_DT = datetime(2026, 5, 20, 10, 0, 0, tzinfo=UTC)
_TS = "2026-05-20T10:00:00Z"

_ALERT_ID = "01HK7Z8M9XQYR4VTBN2WJC5CON"
_CASE_ID = "CASE-2026-CONFORMANCE-001"

# Salt-key reference used by the PII-sensitive selectors in the
# conformance examples. Operator-defined format ; in production this
# would identify a specific rotation epoch in a tenant-side secret
# store.
_PII_SALT_KEY = "tenant:warlog-conformance:salt:v1"

# Pre-computed lowercase-hex sha256 of "saltbytes|alice@warlog.demo" for
# the conformance example. Deterministic so produce_all() round-trips.
# Recipients verify by retrieving the salt by ``selectorKeyId``,
# concatenating with the cleartext, and re-hashing.
_PII_SHA256_ALICE = "55a4d4a7e6f7d6e6e4e7c0a7d2d5c8b7f1a9e3d6c5b8a7e6d4c3b2a190817263"

# HMAC secret used by the SignedAuditRow factory. Conformance-only ;
# real producers MUST keep the secret in Vault and reference it by
# ``key_id``.
_DEMO_HMAC_SECRET = b"warlog-conformance-demo-secret-do-not-use-in-prod"
_DEMO_HMAC_KEY_ID = "tenant:warlog-conformance:hmac:v1"


def _dump(model) -> dict[str, Any]:
    """Pydantic → dict with camelCase aliases, JSON-mode values."""
    return model.model_dump(mode="json", by_alias=True)


# =============================================================================
# Pydantic-backed factories (8 types)
# =============================================================================


def produce_mitre_assessment() -> dict[str, Any]:
    return _dump(
        MitreAssessment(
            envelope=ArtifactEnvelope(
                artifact_type="mitre_assessment",
                subject_type="alert",
                subject_id=_ALERT_ID,
                producer=ArtifactProducer(kind="rule", name="mitre_mapper"),
                generated_at=_TS_DT,
                confidence=ArtifactConfidence(score=0.78, band=ConfidenceBand.HIGH),
            ),
            mitre=MitreMapping(tactics=["TA0002"], techniques=["T1059.001"]),
            reasoning="Encoded PowerShell from Office parent matches T1059.001 pattern.",
        )
    )


def produce_enrichment_assessment() -> dict[str, Any]:
    return _dump(
        EnrichmentAssessment(
            envelope=ArtifactEnvelope(
                artifact_type="enrichment.ioc_reputation",
                subject_type="alert",
                subject_id=_ALERT_ID,
                producer=ArtifactProducer(kind="system", name="virustotal_enricher"),
                generated_at=_TS_DT,
                confidence=ArtifactConfidence(score=0.92, band=ConfidenceBand.HIGH),
                citations=[
                    ArtifactCitation(
                        source_id="vt-report-abc123",
                        source_kind="threat_intel_feed",
                        score=0.92,
                    )
                ],
            ),
            payload=EnrichmentAssessmentPayload(
                matched_iocs=[
                    ExtractedIOC(
                        ioc_type=IOCType.HASH_SHA256,
                        value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                        maliciousness=AlertVerdict.TRUE_POSITIVE,
                    )
                ],
                threat_intel_hits=["malware/cobalt-strike-beacon"],
            ),
        )
    )


def produce_risk_arbitration() -> dict[str, Any]:
    return _dump(
        RiskArbitration(
            envelope=ArtifactEnvelope(
                artifact_type="risk_arbitration",
                subject_type="case",
                subject_id=_CASE_ID,
                producer=ArtifactProducer(kind="human", name="rssi_signing_console"),
                generated_at=_TS_DT,
            ),
            payload=RiskArbitrationPayload(
                authority=ArbitrationAuthority(
                    role="ciso",
                    signer_id="user-rssi-mdupont",
                    signer_name="Marie Dupont",
                ),
                scope=[
                    ArbitrationScope(
                        scope_kind="asset_group",
                        selector_value="billing-prod-cluster",
                    )
                ],
                accepted_risks=[
                    AcceptedRisk(
                        name="lsass_memory_dump_during_maintenance",
                        description="Authorized admin tool dumps LSASS for integrity checks.",
                    )
                ],
                policy_ref=PolicyRef(
                    policy_kind="playbook",
                    policy_id="playbook:lsass-maintenance-window",
                    version="2026.04",
                ),
                valid_from=_TS_DT,
                valid_until=datetime(2026, 8, 1, 4, 0, 0, tzinfo=UTC),
                justification="Monthly integrity check signed off by CISO and DRO.",
            ),
        )
    )


def produce_approval_decision() -> dict[str, Any]:
    return _dump(
        ApprovalDecision(
            envelope=ArtifactEnvelope(
                artifact_type="approval_decision",
                subject_type="case",
                subject_id=_CASE_ID,
                producer=ArtifactProducer(kind="human", name="approval_console"),
                generated_at=_TS_DT,
            ),
            payload=ApprovalDecisionPayload(
                request_ref=ResponseActionRequestRef(
                    action_id="user.revoke_tokens",
                    # The reference into an AuditRow uses the SAME pseudonymized
                    # value the AuditRow carries — same salt-key epoch, same hash.
                    # See produce_audit_row() and produce_response_action_spec().
                    subject_kind="identity",
                    subject_value=_PII_SHA256_ALICE,
                    idempotency_key=f"case:{_CASE_ID}:user.revoke_tokens:{_PII_SHA256_ALICE[:16]}",
                ),
                decision_maker_kind="human",
                decision_maker_id="user-senior-bclaudel",
                decision="approved",
                decided_at=_TS_DT,
                basis_ref=PolicyRef(
                    policy_kind="playbook",
                    policy_id="playbook:token-revocation-on-confirmed-takeover",
                    version="2026.03",
                ),
                rationale="Confirmed account takeover. Tier-2 containment per playbook.",
            ),
        )
    )


def produce_connector_capability() -> dict[str, Any]:
    return _dump(
        ConnectorCapability(
            connector_id="reference-edr",
            connector_version="0.1.0",
            vendor="Conformance Reference Inc.",
            kind=ConnectorKind.EDR,
            auth=AuthDescriptor(
                model=ConnectorAuthModel.OAUTH2_CLIENT_CREDENTIALS,
                scopes=["read", "respond"],
            ),
            ingress=IngressDescriptor(
                produces=["ocsf.detection_finding.v1.4"],
                delivery=IngressDelivery.POLLING,
                polling_min_interval_s=30,
            ),
            egress=EgressDescriptor(
                supports_response_actions=[
                    ResponseActionId.HOST_ISOLATE,
                    ResponseActionId.HOST_UNISOLATE,
                ]
            ),
            enrichment=EnrichmentDescriptor(
                produces_artifact_types=["enrichment.context"],
                supports_entity_types=["host", "user"],
                freshness=FreshnessHint.NEAR_REALTIME,
            ),
            dry_run=DryRunDescriptor(supported=True, scope=DryRunScope.EGRESS),
            lifecycle=LifecycleDescriptor(
                supports_health_check=True, supports_credential_rotation=True
            ),
            compat=ConnectorCompat(warlog_spec_min="1.0.0", warlog_spec_max="1.x"),
        )
    )


def produce_response_action_spec() -> dict[str, Any]:
    """Reference :class:`ResponseActionSpec` for an identity-family action.

    Uses ``sha256_salted`` for the user principal — actions targeting
    identity / email / iam families MUST pseudonymize their selector
    per the GDPR doctrine. The runner enforces this gate before
    signing any audit row.
    """
    return _dump(
        ResponseActionSpec(
            action_id=ResponseActionId.USER_REVOKE_TOKENS,
            subject=ResponseSubject(
                kind=ResponseActionScope.IDENTITY,
                selector_type="user_principal_name",
                selector_value=_PII_SHA256_ALICE,
                selector_representation=SelectorRepresentation.SHA256_SALTED,
                selector_key_id=_PII_SALT_KEY,
            ),
            params={"reason": "Confirmed account takeover"},
            approval=ApprovalDescriptor(
                required=True,
                level=ApprovalLevel.SENIOR,
                rationale="Token revocation on confirmed account takeover per playbook.",
            ),
            idempotency_key=f"case:{_CASE_ID}:user.revoke_tokens:{_PII_SHA256_ALICE[:16]}",
            expires_at=datetime(2026, 5, 20, 11, 0, 0, tzinfo=UTC),
        )
    )


def produce_response_action_result() -> dict[str, Any]:
    return _dump(
        ResponseActionResult(
            execution_id="exec-conformance-001",
            action_id=ResponseActionId.USER_REVOKE_TOKENS,
            outcome=ExecutionOutcome.SUCCESS,
            subject=ResponseSubject(
                kind=ResponseActionScope.IDENTITY,
                selector_type="user_principal_name",
                selector_value=_PII_SHA256_ALICE,
                selector_representation=SelectorRepresentation.SHA256_SALTED,
                selector_key_id=_PII_SALT_KEY,
            ),
            details={"vendor_task_id": "task-conformance-abc"},
        )
    )


def produce_audit_row() -> dict[str, Any]:
    return _dump(_build_pinned_audit_row())


def _build_pinned_audit_row() -> AuditRow:
    """Shared between produce_audit_row and produce_signed_audit_row.

    Identity-family action → selector_representation=sha256_salted with
    a key_id pointing at the rotatable salt epoch. ``prior_audit_id``
    references the pending_approval row this resolution supersedes
    (typical approve-then-apply doctrine).
    """
    return AuditRow(
        audit_id="audit-conformance-001",
        execution_id="exec-conformance-001",
        tenant_id="tenant-conformance",
        actor=AutomationActor(
            id="agent:autonomous-soc:identity-containment-loop",
            agent=AiAgentRef(
                model="claude-opus-4-7",
                model_version="2026-04-15-build-c7d2e1",
                system_prompt_hash="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
                agent_run_id="run-conformance-001",
            ),
        ),
        action_id=ResponseActionId.USER_REVOKE_TOKENS,
        subject=ResponseSubject(
            kind=ResponseActionScope.IDENTITY,
            selector_type="user_principal_name",
            selector_value=_PII_SHA256_ALICE,
            selector_representation=SelectorRepresentation.SHA256_SALTED,
            selector_key_id=_PII_SALT_KEY,
        ),
        phase=ExecutionPhase.APPLY,
        outcome=ExecutionOutcome.SUCCESS,
        started_at=_TS_DT,
        completed_at=_TS_DT,
        duration_ms=712,
        connector=AuditConnectorRef(id="okta", version="0.3.1"),
        idempotency_key=f"case:{_CASE_ID}:user.revoke_tokens:{_PII_SHA256_ALICE[:16]}",
        decision_ref=DecisionRef(
            artifact_type=DecisionArtifactType.APPROVAL_DECISION,
            artifact_id=f"approval:{_CASE_ID}:user.revoke_tokens",
            content_hash="2c624232cdd221771294dfbb310aca000a0df6ac8b66b696d90ef06fdefb64a3",
        ),
        trigger_signal_ref=TriggerSignalRef(
            kind=TriggerSignalKind.OCSF_EVENT,
            source_id="ocsf-event-conformance-001",
            content_hash="7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730",
        ),
        compliance_scope=[ComplianceScope.NIS2, ComplianceScope.GDPR],
        # Resolution of an earlier pending_approval row in the same execution.
        prior_audit_id="audit-conformance-approval-pending",
    )


def produce_signed_audit_row() -> dict[str, Any]:
    """Reference :class:`SignedAuditRow` — the exportable, verifiable envelope.

    The conformance secret is published in this module so a third party
    can re-run verification and inspect the contract. Production
    deployments MUST use a Vault-stored tenant secret keyed by
    ``attestation.key_id`` ; the conformance secret is for documentation
    only.
    """
    row = _build_pinned_audit_row()
    canonical = canonicalize_v1(row)
    prev = compute_genesis(row.tenant_id, _DEMO_HMAC_SECRET)
    sig = compute_signature(prev, canonical, _DEMO_HMAC_SECRET)
    return _dump(
        SignedAuditRow(
            payload=row,
            attestation=AuditAttestation(
                prev_row_hash=prev,
                signature_value=sig,
                key_id=_DEMO_HMAC_KEY_ID,
            ),
        )
    )


def produce_connector_error() -> dict[str, Any]:
    return _dump(
        ConnectorError(
            category=FailureCategory.AUTH,
            message="Upstream rejected credentials (HTTP 401).",
            retryable=False,
            vendor_code="okta.401.unauthorized",
            vendor_message="Invalid API token",
        )
    )


def produce_pack_manifest() -> dict[str, Any]:
    return _dump(
        PackManifest(
            pack_id="warlog-conformance-reference",
            pack_version="0.1.0",
            kind=PackKind.PLAYBOOK,
            publisher=PackPublisher(
                id="warlog-conformance",
                trust_level=TrustLevel.COMMUNITY,
                signature="ed25519:reference-signature-placeholder",
            ),
            title="Conformance reference pack",
            description="Reference pack used by Level 2 conformance to exercise the manifest shape.",
            compat=PackCompat(
                warlog_spec_min="1.0.0",
                warlog_spec_max="1.x",
            ),
            license="Apache-2.0",
            contents=PackContents(
                playbooks=["playbooks/reference.yaml"],
            ),
            provenance=PackProvenance(
                source_repo="https://example.invalid/pack",
                source_commit="0" * 40,
                build_at=_TS_DT,
            ),
        )
    )


# =============================================================================
# Hardcoded canonical dicts (13 backend-only types)
# =============================================================================


def _artifact_envelope(artifact_type: str, subject_id: str, subject_type: str = "alert") -> dict[str, Any]:
    return _dump(
        ArtifactEnvelope(
            artifact_type=artifact_type,
            subject_type=subject_type,  # type: ignore[arg-type]
            subject_id=subject_id,
            producer=ArtifactProducer(kind="ml", name="conformance_producer", model="ref-v1"),
            generated_at=_TS_DT,
            confidence=ArtifactConfidence(score=0.85, band=ConfidenceBand.HIGH),
        )
    )


def _proposal_envelope(
    proposal_type: str, subject_id: str, subject_type: str = "alert"
) -> dict[str, Any]:
    return {
        "proposalType": proposal_type,
        "proposalVersion": "v1",
        "proposalId": f"{proposal_type}:{subject_id}:conformance",
        "subjectType": subject_type,
        "subjectId": subject_id,
        "requiresApproval": True,
        "canMutate": False,
        "confidence": {"score": 0.85, "band": "high"},
        "citations": [],
        "rationale": "Conformance reference example.",
    }


def _classification_envelope() -> ArtifactEnvelope:
    return ArtifactEnvelope(
        artifact_type="classification_assessment",
        subject_type="alert",
        subject_id=_ALERT_ID,
        producer=ArtifactProducer(kind="ml", name="alert_classifier", model="ref-v1"),
        generated_at=_TS_DT,
        confidence=ArtifactConfidence(score=0.85, band=ConfidenceBand.HIGH),
    )


def _proposal_env(
    proposal_type: str, subject_id: str, subject_type: str = "alert"
) -> ProposalEnvelope:
    return ProposalEnvelope(
        proposal_type=proposal_type,
        proposal_version="v1",
        proposal_id=f"{proposal_type}:{subject_id}:conformance",
        subject_type=subject_type,  # type: ignore[arg-type]
        subject_id=subject_id,
        requires_approval=True,
        can_mutate=False,
        confidence=ArtifactConfidence(score=0.85, band=ConfidenceBand.HIGH),
        citations=[],
        rationale="Conformance reference example.",
    )


def produce_classification_assessment() -> dict[str, Any]:
    return _dump(
        ClassificationAssessment(
            envelope=_classification_envelope(),
            classification=ClassificationDecision(
                category=AlertCategory.EXECUTION,
                severity=AlertSeverity.HIGH,
                verdict=AlertVerdict.SUSPICIOUS,
                should_escalate=True,
                escalation_risk=ConfidenceBand.HIGH,
            ),
            reasoning="Encoded PowerShell + C2 callout matches T1059.001 patterns.",
            evidence_summary=[
                "Parent process is winword.exe",
                "Base64-encoded command line",
            ],
            missing_evidence=["No memory dump available"],
        )
    )


def produce_closure_summary() -> dict[str, Any]:
    return _dump(
        ClosureSummary(
            subject_type="alert",
            subject_id=_ALERT_ID,
            generated_at=_TS_DT,
            closed_by="user-analyst-jdoe",
            verdict=AlertVerdict.TRUE_POSITIVE,
            category=AlertCategory.EXECUTION,
            resolution_summary="Contained host, revoked tokens, deployed YARA rule.",
            evidence_references=[f"s3://warlog-evidence/{_ALERT_ID}/forensics.tar.gz"],
        )
    )


def produce_case_return_summary() -> dict[str, Any]:
    return _dump(
        CaseReturnSummary(
            case_id=_CASE_ID,
            case_number="CASE-2026-042",
            generated_at=_TS_DT,
            final_verdict=AlertVerdict.TRUE_POSITIVE,
            final_category=AlertCategory.EXECUTION,
            final_severity=AlertSeverity.HIGH,
            outcome_summary="Confirmed compromise. Host contained. Credentials rotated.",
            root_cause="Successful spear-phishing against user.alice@warlog.demo.",
            lessons_learned=(
                "Disable macros for external Office documents. "
                "Tighten egress to known C2 ASNs."
            ),
            linked_alert_ids=[_ALERT_ID],
            confidence=ArtifactConfidence(score=0.95, band=ConfidenceBand.HIGH),
        )
    )


def produce_triage_proposal() -> dict[str, Any]:
    return _dump(
        TriageProposal(
            envelope=_proposal_env("triage_proposal", _ALERT_ID),
            payload=TriageProposalPayload(
                recommended_status=AlertStatus.ESCALATED,
                recommended_severity=AlertSeverity.HIGH,
                recommended_verdict=AlertVerdict.SUSPICIOUS,
                recommended_category=AlertCategory.EXECUTION,
                should_create_case=True,
                priority_hint=CasePriority.P2,
                summary="Suspicious encoded PowerShell + C2 callout. Escalate to L2.",
            ),
        )
    )


def produce_next_step_proposal() -> dict[str, Any]:
    return _dump(
        NextStepProposal(
            envelope=_proposal_env("next_step_proposal", _ALERT_ID),
            payload=NextStepProposalPayload(
                steps=[
                    NextStep(
                        title="Isolate host",
                        kind=ProposalStepKind.CONTAINMENT,
                        priority=1,
                        expected_outcome="Host network traffic blocked, in-memory process still observable.",
                    ),
                    NextStep(
                        title="Collect memory dump",
                        kind=ProposalStepKind.INVESTIGATION,
                        priority=2,
                        expected_outcome="LSASS region available for offline forensics.",
                    ),
                ]
            ),
        )
    )


def produce_playbook_candidate_proposal() -> dict[str, Any]:
    return _dump(
        PlaybookCandidateProposal(
            envelope=_proposal_env("playbook_candidate_proposal", _ALERT_ID),
            payload=PlaybookCandidateProposalPayload(
                candidate_playbooks=[
                    PlaybookCandidate(
                        playbook_id="pb-edr-containment-001",
                        playbook_name="EDR containment + token revocation",
                        why_recommended=(
                            "Matches confirmed-compromise pattern with identity blast radius."
                        ),
                        preconditions=[
                            "host.isolate available",
                            "user.revoke_tokens available",
                        ],
                        approval_level="senior",
                        required_capability_keys=[
                            "edr.endpoint.isolate",
                            "iam.user.revoke_tokens",
                        ],
                    )
                ],
                why_recommended=(
                    "Single playbook covers both containment and identity perimeters."
                ),
                preconditions=[
                    "EDR connector authenticated",
                    "IAM connector authenticated",
                ],
            ),
        )
    )


def produce_investigation_summary_proposal() -> dict[str, Any]:
    return _dump(
        InvestigationSummaryProposal(
            envelope=_proposal_env(
                "investigation_summary_proposal", _CASE_ID, subject_type="case"
            ),
            payload=InvestigationSummaryProposalPayload(
                summary="Confirmed spear-phishing → execution → token theft chain.",
                hypothesis="Adversary used MFA fatigue after initial spear-phish foothold.",
                findings=[
                    "T1566.001 spear-phishing attachment delivered",
                    "T1059.001 PowerShell execution observed",
                    "T1078.004 cloud account abuse from previously-unseen IP",
                ],
                impact_assessment="One user identity compromised. No data exfiltration confirmed.",
                next_steps=[
                    "Force password rotation + MFA re-enrollment for the user",
                    "Deploy YARA rule to detect the dropped binary fleet-wide",
                ],
                unresolved_questions=["Initial delivery vector pre-spear-phish"],
                confidence=ArtifactConfidence(score=0.9, band=ConfidenceBand.HIGH),
            ),
        )
    )


# =============================================================================
# Registry mapping schema_relpath -> factory
# =============================================================================


PRODUCERS: dict[str, Any] = {
    # Artifacts (7)
    "artifacts/classification-assessment.json": produce_classification_assessment,
    "artifacts/mitre-assessment.json": produce_mitre_assessment,
    "artifacts/enrichment-assessment.json": produce_enrichment_assessment,
    "artifacts/closure-summary.json": produce_closure_summary,
    "artifacts/case-return-summary.json": produce_case_return_summary,
    "artifacts/risk-arbitration.json": produce_risk_arbitration,
    "artifacts/approval-decision.json": produce_approval_decision,
    # Proposals (4)
    "proposals/triage-proposal.json": produce_triage_proposal,
    "proposals/next-step-proposal.json": produce_next_step_proposal,
    "proposals/playbook-candidate-proposal.json": produce_playbook_candidate_proposal,
    "proposals/investigation-summary-proposal.json": produce_investigation_summary_proposal,
    # Provider ABI (6)
    "provider-abi/connector-capability.json": produce_connector_capability,
    "provider-abi/response-action-spec.json": produce_response_action_spec,
    "provider-abi/response-action-result.json": produce_response_action_result,
    "provider-abi/audit-row.json": produce_audit_row,
    "provider-abi/signed-audit-row.json": produce_signed_audit_row,
    "provider-abi/connector-error.json": produce_connector_error,
    # Registry (1)
    "registry/pack-manifest.json": produce_pack_manifest,
    # Bundles (TriageBundle / InvestigationBundle / ResponseBundle /
    # IncidentBundle) are intentionally NOT producers — they are product-
    # specific UI projections that live in the Warlog backend, not in the
    # open spec. See module docstring.
}


def produce_all() -> dict[str, dict[str, Any]]:
    """Produce one canonical example for each of the 18 productible types.

    Returns ``{schema_relpath: example_dict}`` where ``schema_relpath``
    is the path under ``warlog-spec/schemas/`` and ``example_dict`` is
    the canonical wire-format dict.
    """
    return {relpath: factory() for relpath, factory in PRODUCERS.items()}


__all__ = [
    "PRODUCERS",
    "produce_all",
    # Individual factories — exported for selective use.
    "produce_approval_decision",
    "produce_audit_row",
    "produce_case_return_summary",
    "produce_classification_assessment",
    "produce_closure_summary",
    "produce_connector_capability",
    "produce_connector_error",
    "produce_enrichment_assessment",
    "produce_investigation_summary_proposal",
    "produce_mitre_assessment",
    "produce_next_step_proposal",
    "produce_pack_manifest",
    "produce_playbook_candidate_proposal",
    "produce_response_action_result",
    "produce_response_action_spec",
    "produce_risk_arbitration",
    "produce_signed_audit_row",
    "produce_triage_proposal",
]


def _cli() -> int:
    """``python -m warlog_spec.conformance dump --out DIR``.

    Writes one fixture per productible type into the layout the
    conformance runner expects, named
    ``<DIR>/<schema-subdir>/<schema-stem>.warlog-spec-py.json``.

    Example :

        python -m warlog_spec.conformance dump --out ./fixtures
        python warlog-spec/tests/conformance/runner.py \\
            --level 2 --fixtures-dir ./fixtures

        python -m warlog_spec.conformance provider-check --out ./provider-report.json
        python warlog-spec/tests/conformance/runner.py \
            --level 4 --provider-report ./provider-report.json
    """
    import argparse
    import asyncio
    import json
    import sys
    from pathlib import Path

    from warlog_spec.provider_conformance import run_mock_provider_level_4

    parser = argparse.ArgumentParser(
        description="warlog-spec-py conformance helpers"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    dump = sub.add_parser("dump", help="Write fixtures to a directory")
    dump.add_argument("--out", type=Path, required=True, help="Output directory")

    provider = sub.add_parser(
        "provider-check",
        help="Run the Level 4 mock-provider contract and write an evidence report",
    )
    provider.add_argument("--out", type=Path, required=True, help="Output JSON report")

    args = parser.parse_args()

    if args.cmd == "dump":
        out: Path = args.out
        out.mkdir(parents=True, exist_ok=True)
        for schema_relpath, factory in PRODUCERS.items():
            example = factory()
            subdir, schema_file = schema_relpath.rsplit("/", 1)
            schema_stem = schema_file.removesuffix(".json")
            fixture_path = out / subdir / f"{schema_stem}.warlog-spec-py.json"
            fixture_path.parent.mkdir(parents=True, exist_ok=True)
            with fixture_path.open("w", encoding="utf-8") as fh:
                json.dump(example, fh, indent=2, sort_keys=True)
                fh.write("\n")
            print(f"wrote {fixture_path}", file=sys.stderr)
        print(
            f"\nDumped {len(PRODUCERS)} fixtures to {out}",
            file=sys.stderr,
        )
        return 0

    if args.cmd == "provider-check":
        out: Path = args.out
        out.parent.mkdir(parents=True, exist_ok=True)
        report = asyncio.run(run_mock_provider_level_4())
        with out.open("w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, sort_keys=True)
            fh.write("\n")
        print(f"wrote {out}", file=sys.stderr)
        return 0

    return 1


if __name__ == "__main__":
    import sys

    sys.exit(_cli())
