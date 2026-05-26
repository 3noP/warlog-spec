"""Smoke tests — proves the package imports cleanly and round-trips.

Runs without any Warlog backend. Just ``pip install warlog-spec`` (or
``pip install -e .`` from this directory) and ``pytest``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from warlog_spec import (
    ABI_VERSION,
    ACTION_CATALOG,
    CANONICALIZATION_FORMAT_V1,
    AbiConnector,
    ActionMeta,
    AlertSeverity,
    ApprovalLevel,
    AuditChainBroken,
    AuditConnectorRef,
    AuditRow,
    AuthDescriptor,
    ComplianceScope,
    ConnectorAbiError,
    ConnectorAuthModel,
    ConnectorCapability,
    ConnectorCompat,
    ConnectorKind,
    DecisionArtifactType,
    DecisionRef,
    EgressDescriptor,
    ExecutionOutcome,
    ExecutionPhase,
    FailureCategory,
    HumanActor,
    ResponseActionId,
    ResponseActionResult,
    ResponseActionReversibility,
    ResponseActionScope,
    ResponseActionSpec,
    ResponseSubject,
    TriggerSignalKind,
    TriggerSignalRef,
    actions_by_family,
    actions_by_reversibility,
    canonicalize_v1,
    compute_genesis,
    compute_signature,
    default_approval_for,
)


_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent.parent.parent


def _canonical_schemas_dir() -> Path | None:
    candidates = (
        _REPO_ROOT / "warlog-spec" / "schemas",
        _REPO_ROOT / "schemas",
    )
    return next(
        (
            candidate
            for candidate in candidates
            if (candidate / "action-catalog.json").is_file()
        ),
        None,
    )


def test_top_level_constants_present() -> None:
    assert ABI_VERSION == "1.0"
    assert CANONICALIZATION_FORMAT_V1 == "v1"


def test_response_action_id_catalog_size() -> None:
    """Catalog of canonical actions — adding one is additive within MAJOR.

    Extensions (2026-05-07):
    - Identity (Okta-driven): revoke_tokens, reset_password, expire_password,
      unlock, group_remove, delete (see 08-identity-gap-audit.md)
    - Device (Falcon-driven): restart, collect_artifacts, hash.block (see
      09-device-gap-audit.md)
    - Network (PAN-OS-driven): ip/domain/url.unblock, hash.unblock,
      session.terminate (see 11-network-gap-audit.md)
    - Email (Proofpoint-driven): block_sender, unblock_sender, release
      (see 12-email-gap-audit.md)
    - Cloud (AWS/Azure/GCP-driven): host.stop, host.delete, iam.role_detach,
      iam.credentials_disable, iam.credentials_rotate, key.disable, key.rotate,
      key.schedule_deletion, bucket.lockdown — 9 actions across new families
      iam/key/storage + device extension (see 15-cloud-gap-audit.md)
    - Inverse symmetry (post-review, audit 16): host.start, iam.role_attach,
      iam.credentials_enable, key.enable, bucket.unlock. Doctrine refinement
      clarifies DISRUPTIVE = vendor-side reversal exists, regardless of
      whether canon ships the inverse — but shipping inverses where they
      are real IR primitives keeps the catalog symmetric.
    """
    assert len(list(ResponseActionId)) == 49


def test_action_catalog_is_complete() -> None:
    """Every ResponseActionId has a catalog entry — the catalog IS the
    contract that drives runtime approval defaults, so missing entries
    are spec drift, not a stylistic gap."""
    assert set(ACTION_CATALOG) == set(ResponseActionId), (
        f"catalog drift: {set(ResponseActionId) - set(ACTION_CATALOG)}"
    )


def test_action_catalog_entries_are_well_formed() -> None:
    """Each ActionMeta entry has the expected shape and consistent values."""
    valid_families = {
        "identity",
        "device",
        "network",
        "email",
        "workflow",
        "iam",
        "key",
        "storage",
    }
    for action_id, meta in ACTION_CATALOG.items():
        assert isinstance(meta, ActionMeta)
        assert meta.action_id is action_id
        assert meta.family in valid_families, f"unknown family for {action_id.value}"
        assert isinstance(meta.reversibility, ResponseActionReversibility)
        assert isinstance(meta.default_approval, ApprovalLevel)
        assert meta.default_reviewers >= 0
        # Auto-execute discipline : NONE level ↔ 0 reviewers.
        if meta.default_approval is ApprovalLevel.NONE:
            assert meta.default_reviewers == 0, (
                f"{action_id.value} has NONE level but {meta.default_reviewers} reviewers"
            )
        # Manager-level actions land on destructive/irreversible primitives :
        # require two reviewers (four-eyes).
        if meta.default_approval is ApprovalLevel.MANAGER:
            assert meta.default_reviewers >= 2, (
                f"{action_id.value} at MANAGER level needs ≥2 reviewers"
            )


def test_action_catalog_reversibility_drives_approval() -> None:
    """Reversibility doctrine in audit 14 maps to approval defaults :
    REVERSIBLE → analyst (or NONE for auto-exec workflow), DISRUPTIVE →
    senior, DESTRUCTIVE → senior or manager. Drift here is doctrine drift."""
    for action_id, meta in ACTION_CATALOG.items():
        if meta.reversibility is ResponseActionReversibility.REVERSIBLE:
            assert meta.default_approval in {ApprovalLevel.NONE, ApprovalLevel.ANALYST, ApprovalLevel.SENIOR}, (
                f"{action_id.value} reversible but default_approval={meta.default_approval.value}"
            )
        elif meta.reversibility is ResponseActionReversibility.DISRUPTIVE:
            assert meta.default_approval in {ApprovalLevel.SENIOR, ApprovalLevel.MANAGER}, (
                f"{action_id.value} disruptive but default_approval={meta.default_approval.value}"
            )
        elif meta.reversibility is ResponseActionReversibility.DESTRUCTIVE:
            assert meta.default_approval in {ApprovalLevel.SENIOR, ApprovalLevel.MANAGER}, (
                f"{action_id.value} destructive but default_approval={meta.default_approval.value}"
            )


def test_action_catalog_json_in_sync_with_python_registry() -> None:
    """The published JSON manifest MUST match the Python registry.

    The Python registry is the authoring side ; the JSON is a
    derivation other-language SDKs (Go, TS) consume. Drift between
    the two would let cross-language SDKs apply different approval
    defaults than the Python runtime — exactly the gap the catalog
    refactor was meant to close.

    To regenerate the JSON after a registry edit :

        python -m warlog_spec.action_catalog \\
            > warlog-spec/schemas/action-catalog.json
    """
    import json
    from warlog_spec.action_catalog import to_json_manifest

    schemas_dir = _canonical_schemas_dir()
    json_path = schemas_dir / "action-catalog.json" if schemas_dir else None
    if json_path is None or not json_path.exists():
        pytest.skip(f"action-catalog.json not present at {json_path}")

    on_disk = json.loads(json_path.read_text(encoding="utf-8"))
    generated = to_json_manifest()

    # Core invariants : every action_id known to the registry has the
    # same operational metadata in the JSON, and vice versa. The
    # human-readable ``description`` field is allowed to drift (it's
    # prose) ; everything operational must match exactly.
    assert set(on_disk["actions"]) == set(generated["actions"]), (
        "action_id set drift between JSON manifest and Python registry: "
        f"json-only={set(on_disk['actions']) - set(generated['actions'])}, "
        f"py-only={set(generated['actions']) - set(on_disk['actions'])}"
    )
    for action_id, gen_meta in generated["actions"].items():
        disk_meta = on_disk["actions"][action_id]
        for field in (
            "family",
            "reversibility",
            "default_approval",
            "default_reviewers",
        ):
            assert disk_meta.get(field) == gen_meta[field], (
                f"{action_id}.{field} drift: json={disk_meta.get(field)} "
                f"vs python={gen_meta[field]}"
            )
        # params_schema_ref is optional — assert presence + value match.
        assert disk_meta.get("params_schema_ref") == gen_meta.get(
            "params_schema_ref"
        ), f"{action_id}.params_schema_ref drift"


def test_params_schema_loads_for_actions_that_declare_one() -> None:
    """Every action with a non-null ``params_schema_ref`` MUST load."""
    from warlog_spec import load_params_schema

    expected_to_have_schema = {
        ResponseActionId.HOST_COLLECT_ARTIFACTS,
        ResponseActionId.USER_GROUP_REMOVE,
        ResponseActionId.SESSION_TERMINATE,
        ResponseActionId.IAM_ROLE_DETACH,
        ResponseActionId.IAM_ROLE_ATTACH,
        ResponseActionId.IAM_CREDENTIALS_DISABLE,
        ResponseActionId.IAM_CREDENTIALS_ENABLE,
        ResponseActionId.IAM_CREDENTIALS_ROTATE,
        ResponseActionId.KEY_SCHEDULE_DELETION,
    }
    for action in ResponseActionId:
        meta = ACTION_CATALOG[action]
        schema = load_params_schema(action)
        if action in expected_to_have_schema:
            assert schema is not None, f"{action.value} should load a schema"
            assert "type" in schema or "$schema" in schema
            assert meta.params_schema_ref is not None
        else:
            assert schema is None, f"{action.value} should not have a schema"
            assert meta.params_schema_ref is None


def test_validate_params_rejects_invalid_payload() -> None:
    """Schema-violating ``params`` raise ParamsValidationError with
    pointed messages."""
    from warlog_spec import ParamsValidationError, validate_params

    # host.collect_artifacts requires artifact_type ∈ {file, memory}
    with pytest.raises(ParamsValidationError) as excinfo:
        validate_params(
            ResponseActionId.HOST_COLLECT_ARTIFACTS,
            {"artifact_type": "screenshot"},  # not in enum
        )
    assert "artifact_type" in excinfo.value.errors[0]

    # artifact_type='file' requires path
    with pytest.raises(ParamsValidationError):
        validate_params(
            ResponseActionId.HOST_COLLECT_ARTIFACTS,
            {"artifact_type": "file"},  # missing path
        )

    # user.group_remove requires group_id
    with pytest.raises(ParamsValidationError):
        validate_params(ResponseActionId.USER_GROUP_REMOVE, {})


def test_validate_params_accepts_valid_payload() -> None:
    """Happy paths and vendor-specific extension keys both pass."""
    from warlog_spec import validate_params

    # Memory dump — no path required.
    validate_params(
        ResponseActionId.HOST_COLLECT_ARTIFACTS,
        {"artifact_type": "memory"},
    )
    # File dump with path.
    validate_params(
        ResponseActionId.HOST_COLLECT_ARTIFACTS,
        {"artifact_type": "file", "path": "C:/temp/sample.exe"},
    )
    # Vendor-specific extension key (additionalProperties=true).
    validate_params(
        ResponseActionId.HOST_COLLECT_ARTIFACTS,
        {"artifact_type": "memory", "vendor_priority": "urgent"},
    )
    # session.terminate has no required fields, defaults to flow.
    validate_params(ResponseActionId.SESSION_TERMINATE, {})
    validate_params(
        ResponseActionId.SESSION_TERMINATE,
        {"session_type": "vpn", "gateway": "GP-EU-1"},
    )


def test_validate_params_noop_for_actions_without_schema() -> None:
    """Actions with no ``params_schema_ref`` accept any params."""
    from warlog_spec import validate_params

    # HOST_ISOLATE has no schema — anything goes.
    validate_params(
        ResponseActionId.HOST_ISOLATE,
        {"random_key": [1, 2, 3], "another": {"nested": True}},
    )
    validate_params(ResponseActionId.IP_BLOCK, {})


def test_bundled_schemas_match_canonical_artifacts() -> None:
    """Schemas shipped inside the package MUST match the canonical
    files at ``warlog-spec/schemas/action-params/``. Drift between the
    two would let the package and cross-language SDKs apply different
    validation rules to the same action.
    """
    import json
    schemas_dir = _canonical_schemas_dir()
    canonical_dir = schemas_dir / "action-params" if schemas_dir else None
    bundled_dir = (
        _REPO_ROOT
        / "packages"
        / "warlog-spec-py"
        / "src"
        / "warlog_spec"
        / "_schemas"
        / "action-params"
    )
    if canonical_dir is None or not canonical_dir.exists() or not bundled_dir.exists():
        pytest.skip("monorepo layout not present (installed-only mode)")

    canonical_files = {p.name for p in canonical_dir.glob("*.json")}
    bundled_files = {p.name for p in bundled_dir.glob("*.json")}
    assert canonical_files == bundled_files, (
        f"schema set drift: canonical-only={canonical_files - bundled_files}, "
        f"bundled-only={bundled_files - canonical_files}"
    )
    for name in canonical_files:
        canonical = json.loads((canonical_dir / name).read_text(encoding="utf-8"))
        bundled = json.loads((bundled_dir / name).read_text(encoding="utf-8"))
        assert canonical == bundled, f"{name} drift between canonical and bundled copies"


def test_artifact_envelope_round_trips_with_camel_case_wire() -> None:
    """The read-side data canon : an ``ArtifactEnvelope`` round-trips
    via its camelCase wire format and reloads identically. This proves
    the read-side public contract behaves the same way the write-side
    contract does (Pydantic + camelCase aliases + populate_by_name)."""
    from datetime import UTC, datetime as dt

    from warlog_spec import (
        ArtifactCitation,
        ArtifactConfidence,
        ArtifactEnvelope,
        ArtifactProducer,
        ArtifactReviewState,
        ConfidenceBand,
    )

    env = ArtifactEnvelope(
        artifact_type="enrichment.ioc_reputation",
        subject_type="alert",
        subject_id="alert-001",
        producer=ArtifactProducer(kind="ml", name="vt-wrapper", model="vt-v3"),
        generated_at=dt(2026, 5, 7, 12, 0, tzinfo=UTC),
        confidence=ArtifactConfidence(score=0.92, band=ConfidenceBand.HIGH),
        citations=[
            ArtifactCitation(
                source_id="vt-id-1",
                source_kind="threat_intel_feed",
                score=0.92,
            )
        ],
    )
    dumped = env.model_dump(by_alias=True)
    assert dumped["artifactType"] == "enrichment.ioc_reputation"
    assert dumped["subjectType"] == "alert"
    assert dumped["reviewState"] == "pending"
    assert dumped["citations"][0]["sourceKind"] == "threat_intel_feed"

    reloaded = ArtifactEnvelope.model_validate(dumped)
    assert reloaded.subject_id == "alert-001"
    assert reloaded.producer.kind == "ml"
    assert reloaded.confidence.band is ConfidenceBand.HIGH
    assert reloaded.review_state is ArtifactReviewState.PENDING


def test_enrichment_assessment_carries_typed_payload() -> None:
    """An ``EnrichmentAssessment`` composes envelope + typed payload —
    it is the canonical output shape that any enricher (VirusTotal,
    AbuseIPDB, internal ML) produces, regardless of vendor."""
    from datetime import UTC, datetime as dt

    from warlog_spec import (
        ArtifactConfidence,
        ArtifactEnvelope,
        ArtifactProducer,
        ConfidenceBand,
        EnrichmentAssessment,
        EnrichmentAssessmentPayload,
        EntityType,
        ExtractedIOC,
        IOCType,
        NormalizedEntity,
    )
    from warlog_spec import AlertVerdict

    assessment = EnrichmentAssessment(
        envelope=ArtifactEnvelope(
            artifact_type="enrichment.context",
            subject_type="alert",
            subject_id="alert-002",
            producer=ArtifactProducer(kind="rule", name="abuseipdb-wrapper"),
            generated_at=dt(2026, 5, 7, 12, 0, tzinfo=UTC),
        ),
        payload=EnrichmentAssessmentPayload(
            matched_iocs=[
                ExtractedIOC(
                    ioc_type=IOCType.HASH_SHA256,
                    value="abc" * 21,
                    maliciousness=AlertVerdict.SUSPICIOUS,
                ),
            ],
            related_entities=[
                NormalizedEntity(entity_type=EntityType.IP, value="1.2.3.4"),
            ],
            asset_criticality=ConfidenceBand.HIGH,
            threat_intel_hits=["Mirai"],
        ),
    )
    dumped = assessment.model_dump(by_alias=True)
    assert dumped["envelope"]["producer"]["kind"] == "rule"
    assert dumped["payload"]["matchedIocs"][0]["iocType"] == "hash_sha256"
    assert dumped["payload"]["relatedEntities"][0]["entityType"] == "ip"
    assert dumped["payload"]["assetCriticality"] == "high"

    reloaded = EnrichmentAssessment.model_validate(dumped)
    assert reloaded.payload.threat_intel_hits == ["Mirai"]


def test_backend_canonical_re_exports_share_class_identity() -> None:
    """The backend re-export pattern preserves class identity (not a
    copy) — same as how provider_abi types are shared. This means
    ``isinstance(x, app.schemas.canonical.ArtifactEnvelope)`` and
    ``isinstance(x, warlog_spec.ArtifactEnvelope)`` agree."""
    import importlib

    spec_artifacts = importlib.import_module("warlog_spec.artifacts")
    try:
        backend_canonical = importlib.import_module("app.schemas.canonical")
    except ImportError:
        pytest.skip("backend not on sys.path (running outside monorepo)")
    for name in (
        "ArtifactEnvelope",
        "ArtifactProducer",
        "ArtifactConfidence",
        "ArtifactCitation",
        "NormalizedEntity",
        "ExtractedIOC",
        "MitreMapping",
        "MitreAssessment",
        "EnrichmentAssessment",
        "EnrichmentAssessmentPayload",
        "ConfidenceBand",
        "ArtifactReviewState",
    ):
        backend_cls = getattr(backend_canonical, name)
        spec_cls = getattr(spec_artifacts, name)
        assert backend_cls is spec_cls, (
            f"{name} : backend re-export is not the same class as warlog_spec.artifacts ; "
            "duplication detected"
        )


def test_enrichment_descriptor_round_trips_camel_case() -> None:
    """``EnrichmentDescriptor`` is the read-side analogue of
    ``EgressDescriptor`` and rides on ``ConnectorCapability``. Test
    that it round-trips via camelCase wire and that an empty default
    means "this connector does no read-side enrichment"."""
    from warlog_spec import (
        AuthDescriptor,
        ConnectorAuthModel,
        ConnectorCapability,
        ConnectorCompat,
        ConnectorKind,
        EnrichmentDescriptor,
        FreshnessHint,
    )

    cap = ConnectorCapability(
        connector_id="enricher-x",
        connector_version="0.1.0",
        vendor="X",
        kind=ConnectorKind.THREAT_INTEL,
        auth=AuthDescriptor(model=ConnectorAuthModel.API_KEY),
        enrichment=EnrichmentDescriptor(
            produces_artifact_types=["enrichment.ioc_reputation"],
            supports_ioc_types=["ip", "hash_sha256"],
            freshness=FreshnessHint.NEAR_REALTIME,
            bulk_lookup=True,
        ),
        compat=ConnectorCompat(warlog_spec_min="1.0.0", warlog_spec_max="1.x"),
    )
    dumped = cap.model_dump(by_alias=True)
    assert dumped["enrichment"]["producesArtifactTypes"] == ["enrichment.ioc_reputation"]
    assert dumped["enrichment"]["supportsIocTypes"] == ["ip", "hash_sha256"]
    assert dumped["enrichment"]["bulkLookup"] is True
    assert dumped["enrichment"]["freshness"] == "near_realtime"

    reloaded = ConnectorCapability.model_validate(dumped)
    assert reloaded.enrichment.bulk_lookup is True

    # Default is empty (write-only connectors don't declare enrichment).
    write_only = ConnectorCapability(
        connector_id="writer-x",
        connector_version="0.1.0",
        vendor="X",
        kind=ConnectorKind.EDR,
        auth=AuthDescriptor(model=ConnectorAuthModel.API_KEY),
        compat=ConnectorCompat(warlog_spec_min="1.0.0", warlog_spec_max="1.x"),
    )
    assert write_only.enrichment.produces_artifact_types == []
    assert write_only.enrichment.bulk_lookup is False


def test_abi_enricher_is_abstract_and_subclassable() -> None:
    """``AbiEnricher`` enforces ``authenticate`` and ``enrich``
    as abstract ; subclasses with both methods instantiate cleanly.
    The ``enrich`` return type is ``CanonicalArtifact | None`` —
    any envelope-bearing canonical type is admissible."""
    from warlog_spec import (
        AbiEnricher,
        AuthDescriptor,
        CanonicalArtifact,
        ConnectorAuthModel,
        ConnectorCapability,
        ConnectorCompat,
        ConnectorKind,
        EnrichmentDescriptor,
        EnrichmentRequest,
    )

    assert AbiEnricher.__abstractmethods__ == frozenset({"authenticate", "enrich"})

    class _Concrete(AbiEnricher):
        capability = ConnectorCapability(
            connector_id="x",
            connector_version="0.1.0",
            vendor="X",
            kind=ConnectorKind.THREAT_INTEL,
            auth=AuthDescriptor(model=ConnectorAuthModel.API_KEY),
            enrichment=EnrichmentDescriptor(
                produces_artifact_types=["enrichment.ioc_reputation"],
                supports_ioc_types=["ip"],
            ),
            compat=ConnectorCompat(warlog_spec_min="1.0.0", warlog_spec_max="1.x"),
        )

        async def authenticate(self) -> None:
            return

        async def enrich(
            self,
            request: EnrichmentRequest,
        ) -> CanonicalArtifact | None:
            return None

    instance = _Concrete({"api_key": "k"})
    assert isinstance(instance, AbiEnricher)


def test_canonical_artifact_is_base_for_envelope_bearing_types() -> None:
    """``CanonicalArtifact`` is the type-level glue between the
    ``EnrichmentDescriptor.produces_artifact_types`` declaration and
    the ``AbiEnricher.enrich`` return type. ``EnrichmentAssessment``
    and ``MitreAssessment`` both inherit from it, so a single ABC
    return type covers every artifact shape a connector can declare
    it produces."""
    from warlog_spec import (
        CanonicalArtifact,
        EnrichmentAssessment,
        MitreAssessment,
    )

    assert issubclass(EnrichmentAssessment, CanonicalArtifact)
    assert issubclass(MitreAssessment, CanonicalArtifact)


def test_enrichment_request_requires_subject_attribution() -> None:
    """The ``EnrichmentRequest`` shape forces the caller to provide
    the alert/case attribution. The enricher copies these into the
    envelope ; no runtime post-processing required.

    A request without ``subject_id`` is rejected at validation time —
    the contract is self-sufficient."""
    import pytest as _pytest

    from warlog_spec import (
        EnrichmentRequest,
        EntityType,
        ExtractedIOC,
        IOCType,
        NormalizedEntity,
    )

    request = EnrichmentRequest(
        subject_type="alert",
        subject_id="alert-001",
        target=ExtractedIOC(ioc_type=IOCType.HASH_SHA256, value="a" * 64),
    )
    assert request.subject_id == "alert-001"
    assert isinstance(request.target, ExtractedIOC)

    # Entity target also accepted by the discriminated union.
    request_entity = EnrichmentRequest(
        subject_type="case",
        subject_id="case-002",
        target=NormalizedEntity(entity_type=EntityType.IP, value="1.2.3.4"),
    )
    assert isinstance(request_entity.target, NormalizedEntity)

    # Empty subject_id is rejected — closes the previous "runtime
    # stamps it" contract hole.
    with _pytest.raises(Exception):  # pydantic ValidationError
        EnrichmentRequest(
            subject_type="alert",
            subject_id="",
            target=ExtractedIOC(ioc_type=IOCType.IP, value="1.2.3.4"),
        )


def test_virustotal_enricher_capability() -> None:
    module = _load_example("virustotal_enricher")
    cls = module.VirusTotalEnricher
    from warlog_spec import AbiEnricher, IOCType

    assert issubclass(cls, AbiEnricher)
    cap = cls.capability
    assert cap.connector_id == "virustotal-enricher"
    assert cap.kind is ConnectorKind.THREAT_INTEL
    assert cap.enrichment.produces_artifact_types == ["enrichment.ioc_reputation"]
    assert IOCType.HASH_SHA256.value in cap.enrichment.supports_ioc_types
    assert IOCType.IP.value in cap.enrichment.supports_ioc_types
    # Read-only connector — no write actions advertised.
    assert cap.egress.supports_response_actions == []

    # Constructor enforces api_key — proves the contract is checked
    # before any VT API call.
    with pytest.raises(ConnectorAbiError) as excinfo:
        cls({})
    assert excinfo.value.category is FailureCategory.AUTH


def test_virustotal_response_maps_to_canonical_assessment() -> None:
    """Mapping VT's vendor-shape response → canonical
    EnrichmentAssessment is the central read-side promise. Lock it
    down with a synthetic VT payload — and verify the envelope's
    subject attribution is populated from the request, not stamped
    by the runtime."""
    module = _load_example("virustotal_enricher")
    from warlog_spec import (
        AlertVerdict,
        ConfidenceBand,
        EnrichmentRequest,
        ExtractedIOC,
        IOCType,
    )

    fake_vt_response = {
        "data": {
            "id": "abc1234567",
            "type": "file",
            "attributes": {
                "last_analysis_stats": {
                    "harmless": 50,
                    "malicious": 12,
                    "suspicious": 3,
                    "undetected": 5,
                    "timeout": 0,
                },
                "last_analysis_date": 1715000000,
                "popular_threat_classification": {
                    "suggested_threat_label": "trojan.emotet/win32",
                },
            },
        }
    }
    request = EnrichmentRequest(
        subject_type="alert",
        subject_id="alert-XYZ",
        target=ExtractedIOC(
            ioc_type=IOCType.HASH_SHA256,
            value="a" * 64,
        ),
    )
    assessment = module._vt_response_to_assessment(fake_vt_response, request)

    # Envelope is self-attributing : subject identity comes from the
    # request, not from runtime post-processing.
    assert assessment.envelope.subject_type == "alert"
    assert assessment.envelope.subject_id == "alert-XYZ"
    assert assessment.envelope.artifact_type == "enrichment.ioc_reputation"
    assert assessment.envelope.producer.name == "virustotal-v3"
    # 12 malicious + 3 suspicious of 70 total ≈ 0.214
    assert 0.20 < (assessment.envelope.confidence.score or 0) < 0.25
    assert assessment.envelope.confidence.band is ConfidenceBand.HIGH

    # Citations carry the VT report id
    assert assessment.envelope.citations[0].source_id == "abc1234567"
    assert assessment.envelope.citations[0].source_kind == "threat_intel_feed"

    # Payload : enriched IOC with verdict, threat label
    assert len(assessment.payload.matched_iocs) == 1
    enriched = assessment.payload.matched_iocs[0]
    assert enriched.maliciousness is AlertVerdict.TRUE_POSITIVE  # 12 malicious >= 5 threshold
    assert enriched.last_seen is not None  # timestamp populated
    assert "trojan.emotet/win32" in assessment.payload.threat_intel_hits


def test_action_catalog_has_no_duplicate_entries() -> None:
    """Importing the module already raises on duplicates ; this test
    documents the invariant and guards against an accidental relaxation
    of the assertion.
    """
    from warlog_spec.action_catalog import _ENTRIES  # noqa: PLC0415

    seen = [e.action_id for e in _ENTRIES]
    assert len(seen) == len(set(seen)), (
        f"_ENTRIES contains duplicates: {sorted(a.value for a in seen if seen.count(a) > 1)}"
    )


def test_action_catalog_helpers_round_trip() -> None:
    """The convenience helpers return non-empty, consistent slices."""
    device_actions = actions_by_family("device")
    assert ResponseActionId.HOST_ISOLATE in device_actions
    assert ResponseActionId.PROCESS_KILL in device_actions
    assert ResponseActionId.IP_BLOCK not in device_actions

    destructive = actions_by_reversibility(ResponseActionReversibility.DESTRUCTIVE)
    assert ResponseActionId.PROCESS_KILL in destructive
    assert ResponseActionId.USER_FORCE_LOGOUT in destructive
    assert ResponseActionId.HOST_UNISOLATE not in destructive

    level, reviewers = default_approval_for(ResponseActionId.USER_DELETE)
    assert level is ApprovalLevel.MANAGER
    assert reviewers >= 2


def test_failure_categories_are_five() -> None:
    assert {c.value for c in FailureCategory} == {
        "auth",
        "not_found",
        "state_conflict",
        "transient",
        "policy",
    }


def test_construct_connector_capability_round_trips() -> None:
    cap = ConnectorCapability(
        connector_id="example",
        connector_version="0.1.0",
        vendor="Example",
        kind=ConnectorKind.OTHER,
        auth=AuthDescriptor(model=ConnectorAuthModel.API_KEY),
        egress=EgressDescriptor(
            supports_response_actions=[ResponseActionId.ALERT_ACKNOWLEDGE]
        ),
        compat=ConnectorCompat(warlog_spec_min="1.0.0", warlog_spec_max="1.x"),
    )
    # Round-trip via JSON dict to confirm the camelCase wire format.
    dumped = cap.model_dump(by_alias=True)
    assert dumped["connectorId"] == "example"
    assert dumped["egress"]["supportsResponseActions"] == ["alert.acknowledge"]
    assert dumped["compat"]["warlogSpecMin"] == "1.0.0"
    # Re-load via aliases.
    reloaded = ConnectorCapability.model_validate(dumped)
    assert reloaded.connector_id == "example"


def test_pending_approval_is_in_outcomes() -> None:
    """Non-terminal outcome — the runtime must NOT cache pending."""
    assert ExecutionOutcome.PENDING_APPROVAL.value == "pending_approval"


def test_provider_abi_rejects_invalid_pseudonymized_subject() -> None:
    with pytest.raises(Exception):
        ResponseSubject(
            kind=ResponseActionScope.IDENTITY,
            selector_type="user_principal_name",
            selector_value="not-a-sha256",
            selector_representation="sha256_salted",
            selector_key_id="tenant:t:salt:v1",
        )

    with pytest.raises(Exception):
        ResponseSubject(
            kind=ResponseActionScope.IDENTITY,
            selector_type="user_principal_name",
            selector_value="a" * 64,
            selector_representation="sha256_salted",
        )


def test_provider_abi_rejects_invalid_signal_and_hash_refs() -> None:
    with pytest.raises(Exception):
        TriggerSignalRef(kind=TriggerSignalKind.ALERT, source_id="alert-1", content_hash="")

    with pytest.raises(Exception):
        DecisionRef(
            artifact_type=DecisionArtifactType.NEXT_STEP_PROPOSAL,
            artifact_id="proposal-1",
            content_hash="z" * 64,
        )


def test_provider_abi_requires_error_for_failed_result() -> None:
    subject = ResponseSubject(
        kind=ResponseActionScope.ENDPOINT,
        selector_type="agent_id",
        selector_value="agent-1",
    )

    with pytest.raises(Exception):
        ResponseActionResult(
            execution_id="exec-1",
            action_id=ResponseActionId.HOST_ISOLATE,
            outcome=ExecutionOutcome.FAILURE,
            subject=subject,
        )

    with pytest.raises(Exception):
        ResponseActionResult(
            execution_id="exec-1",
            action_id=ResponseActionId.HOST_ISOLATE,
            outcome=ExecutionOutcome.SUCCESS,
            subject=subject,
            error=ConnectorError(
                category=FailureCategory.TRANSIENT,
                message="should not ride with success",
                retryable=True,
            ),
        )


def test_audit_chain_genesis_and_signature_round_trip() -> None:
    secret = b"unit-test-secret"
    tenant = "tenant-x"
    row = AuditRow(
        audit_id="a-001",
        execution_id="e-001",
        tenant_id=tenant,
        actor=HumanActor(id="alice"),
        action_id=ResponseActionId.ALERT_ACKNOWLEDGE,
        subject=ResponseSubject(
            kind=ResponseActionScope.PLATFORM,
            selector_type="alert_id",
            selector_value="alert-001",
        ),
        phase=ExecutionPhase.APPLY,
        outcome=ExecutionOutcome.SUCCESS,
        started_at=datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC),
        completed_at=datetime(2026, 1, 1, 12, 0, 1, tzinfo=UTC),
        connector=AuditConnectorRef(id="example", version="0.1.0"),
        idempotency_key="key-001",
        decision_ref=DecisionRef(
            artifact_type=DecisionArtifactType.NEXT_STEP_PROPOSAL,
            artifact_id="proposal-001",
            content_hash="a" * 64,
        ),
        trigger_signal_ref=TriggerSignalRef(
            kind=TriggerSignalKind.ALERT,
            source_id="alert-001",
            content_hash="b" * 64,
        ),
        compliance_scope=[ComplianceScope.NIS2],
    )
    canonical = canonicalize_v1(row)
    prev = compute_genesis(tenant, secret)
    sig = compute_signature(prev, canonical, secret)

    # Recompute matches.
    assert compute_signature(prev, canonical, secret) == sig

    # Different secret → different signature.
    assert compute_signature(prev, canonical, b"different") != sig

    # Tampering canonical bytes → different signature.
    tampered = bytearray(canonical)
    tampered[5] = (tampered[5] + 1) % 256
    assert compute_signature(prev, bytes(tampered), secret) != sig


def test_connector_abi_error_carries_category() -> None:
    err = ConnectorAbiError(
        FailureCategory.NOT_FOUND,
        "host not in inventory",
        vendor_code="404",
    )
    assert err.category is FailureCategory.NOT_FOUND
    assert err.retryable is False  # default for non-transient
    converted = err.to_connector_error()
    assert converted.category is FailureCategory.NOT_FOUND
    assert converted.vendor_code == "404"


def test_audit_chain_broken_is_exception() -> None:
    with pytest.raises(AuditChainBroken):
        raise AuditChainBroken("integrity violated")


def test_alert_severity_enum_complete() -> None:
    assert {s.value for s in AlertSeverity} == {
        "critical",
        "high",
        "medium",
        "low",
        "info",
        "unknown",
    }


@pytest.mark.asyncio
async def test_example_connector_runs_lifecycle_in_memory() -> None:
    """The ``examples/echo_connector.py`` module must run without a runtime."""
    import importlib.util
    import pathlib

    here = pathlib.Path(__file__).resolve().parent.parent
    example_path = here / "examples" / "echo_connector.py"
    spec = importlib.util.spec_from_file_location("echo_connector", example_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    EchoConnector = module.EchoConnector  # noqa: N806
    assert issubclass(EchoConnector, AbiConnector)

    connector = EchoConnector({"api_key": "test"})
    sample = ResponseActionSpec(
        action_id=ResponseActionId.ALERT_ACKNOWLEDGE,
        subject=ResponseSubject(
            kind=ResponseActionScope.PLATFORM,
            selector_type="alert_id",
            selector_value="alert-test",
        ),
        idempotency_key="test-key",
    )
    await connector.authenticate()
    await connector.dry_run(sample)
    result = await connector.apply(sample)
    assert result.outcome is ExecutionOutcome.SUCCESS
    assert await connector.verify(sample, result) is True

    # Idempotency : repeat apply with same key returns dedup hit.
    second = await connector.apply(sample)
    assert second.details.get("vendor_dedup") is True
    assert second.details["vendor_task_id"] == result.details["vendor_task_id"]


# ---------------------------------------------------------------------------
# Vendor reference connectors — capability + construction smoke only.
# These cannot be exercised end-to-end without live tenants; the test
# locks down that the manifests parse and the action mappings are
# self-consistent so they don't drift.
# ---------------------------------------------------------------------------


def _load_example(name: str):
    import importlib.util
    import pathlib

    here = pathlib.Path(__file__).resolve().parent.parent
    example_path = here / "examples" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, example_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_okta_user_response_connector_capability() -> None:
    module = _load_example("okta_user_response_connector")
    cls = module.OktaUserResponseConnector
    assert issubclass(cls, AbiConnector)

    cap = cls.capability
    assert cap.connector_id == "okta-user-response"
    assert cap.kind is ConnectorKind.IAM
    assert cap.auth.model is ConnectorAuthModel.API_KEY
    assert set(cap.egress.supports_response_actions) == {
        ResponseActionId.USER_DISABLE,
        ResponseActionId.USER_RESET_MFA,
        ResponseActionId.USER_FORCE_LOGOUT,
        ResponseActionId.USER_REVOKE_TOKENS,
        ResponseActionId.USER_RESET_PASSWORD,
        ResponseActionId.USER_EXPIRE_PASSWORD,
        ResponseActionId.USER_UNLOCK,
        ResponseActionId.USER_GROUP_REMOVE,
        ResponseActionId.USER_DELETE,
    }

    # Constructor validates required config — proves the contract is
    # enforced before the runtime ever calls authenticate().
    with pytest.raises(ConnectorAbiError) as excinfo:
        cls({})
    assert excinfo.value.category in {FailureCategory.AUTH, FailureCategory.POLICY}


def test_zscaler_zia_connector_capability() -> None:
    module = _load_example("zscaler_zia_connector")
    cls = module.ZscalerZiaConnector
    assert issubclass(cls, AbiConnector)

    cap = cls.capability
    assert cap.connector_id == "zscaler-zia"
    assert cap.kind is ConnectorKind.NETWORK
    assert set(cap.egress.supports_response_actions) == {
        ResponseActionId.URL_BLOCK,
        ResponseActionId.URL_UNBLOCK,
        ResponseActionId.DOMAIN_BLOCK,
        ResponseActionId.DOMAIN_UNBLOCK,
        ResponseActionId.HASH_BLOCK,
        ResponseActionId.HASH_UNBLOCK,
        ResponseActionId.SESSION_TERMINATE,
    }

    with pytest.raises(ConnectorAbiError) as excinfo:
        cls({})
    assert excinfo.value.category in {FailureCategory.AUTH, FailureCategory.POLICY}


def test_proofpoint_connector_capability() -> None:
    module = _load_example("proofpoint_connector")
    cls = module.ProofpointConnector
    assert issubclass(cls, AbiConnector)

    cap = cls.capability
    assert cap.connector_id == "proofpoint-tap-trap"
    assert cap.kind is ConnectorKind.EMAIL
    assert set(cap.egress.supports_response_actions) == {
        ResponseActionId.EMAIL_QUARANTINE,
        ResponseActionId.EMAIL_RECALL,
        ResponseActionId.EMAIL_RELEASE,
        ResponseActionId.EMAIL_BLOCK_SENDER,
        ResponseActionId.EMAIL_UNBLOCK_SENDER,
    }

    with pytest.raises(ConnectorAbiError) as excinfo:
        cls({})
    assert excinfo.value.category in {FailureCategory.AUTH, FailureCategory.POLICY}


def test_aws_response_connector_capability() -> None:
    module = _load_example("aws_response_connector")
    cls = module.AwsResponseConnector
    assert issubclass(cls, AbiConnector)

    cap = cls.capability
    assert cap.connector_id == "aws-multi-service"
    assert cap.kind is ConnectorKind.OTHER
    assert set(cap.egress.supports_response_actions) == {
        ResponseActionId.HOST_STOP,
        ResponseActionId.HOST_START,
        ResponseActionId.HOST_DELETE,
        ResponseActionId.IAM_ROLE_DETACH,
        ResponseActionId.IAM_ROLE_ATTACH,
        ResponseActionId.IAM_CREDENTIALS_DISABLE,
        ResponseActionId.IAM_CREDENTIALS_ENABLE,
        ResponseActionId.IAM_CREDENTIALS_ROTATE,
        ResponseActionId.KEY_DISABLE,
        ResponseActionId.KEY_ENABLE,
        ResponseActionId.KEY_ROTATE,
        ResponseActionId.KEY_SCHEDULE_DELETION,
        ResponseActionId.BUCKET_LOCKDOWN,
        ResponseActionId.BUCKET_UNLOCK,
    }

    # Constructor enforces required region — proves the contract is
    # checked before any AWS API call.
    with pytest.raises(ConnectorAbiError) as excinfo:
        cls({})
    assert excinfo.value.category in {FailureCategory.AUTH, FailureCategory.POLICY}


def test_paloalto_panos_connector_capability() -> None:
    module = _load_example("palo_alto_panos_connector")
    cls = module.PaloAltoPanosConnector
    assert issubclass(cls, AbiConnector)

    cap = cls.capability
    assert cap.connector_id == "paloalto-panos"
    assert cap.kind is ConnectorKind.NETWORK
    assert cap.auth.model is ConnectorAuthModel.API_KEY
    assert set(cap.egress.supports_response_actions) == {
        ResponseActionId.IP_BLOCK,
        ResponseActionId.IP_UNBLOCK,
        ResponseActionId.DOMAIN_BLOCK,
        ResponseActionId.DOMAIN_UNBLOCK,
        ResponseActionId.URL_BLOCK,
        ResponseActionId.URL_UNBLOCK,
        ResponseActionId.SESSION_TERMINATE,
    }

    with pytest.raises(ConnectorAbiError) as excinfo:
        cls({})
    assert excinfo.value.category in {FailureCategory.AUTH, FailureCategory.POLICY}


def test_crowdstrike_falcon_connector_capability() -> None:
    module = _load_example("crowdstrike_falcon_connector")
    cls = module.CrowdstrikeFalconConnector
    assert issubclass(cls, AbiConnector)

    cap = cls.capability
    assert cap.connector_id == "crowdstrike-falcon"
    assert cap.kind is ConnectorKind.EDR
    assert cap.auth.model is ConnectorAuthModel.OAUTH2_CLIENT_CREDENTIALS
    assert set(cap.egress.supports_response_actions) == {
        ResponseActionId.HOST_ISOLATE,
        ResponseActionId.HOST_UNISOLATE,
        ResponseActionId.HOST_RESTART,
        ResponseActionId.HOST_COLLECT_ARTIFACTS,
        ResponseActionId.IP_BLOCK,
        ResponseActionId.IP_UNBLOCK,
        ResponseActionId.DOMAIN_BLOCK,
        ResponseActionId.DOMAIN_UNBLOCK,
        ResponseActionId.URL_BLOCK,
        ResponseActionId.URL_UNBLOCK,
        ResponseActionId.HASH_BLOCK,
        ResponseActionId.HASH_UNBLOCK,
    }

    with pytest.raises(ConnectorAbiError) as excinfo:
        cls({})
    assert excinfo.value.category in {FailureCategory.AUTH, FailureCategory.POLICY}
