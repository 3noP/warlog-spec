"""OCSF inbound mapping helpers.

Warlog Spec consumes OCSF telemetry as an upstream signal. This module
implements the first deliberately small projection: OCSF Detection
Finding -> Warlog read-side artifacts plus a ``TriggerSignalRef``.

The mapper is conservative. It preserves the original event by hashing
its canonical JSON bytes, emits only existing Warlog artifact shapes,
and leaves the raw OCSF payload outside the public contract.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
import hashlib
import json
import re
from typing import Any, Literal

from pydantic import Field

from warlog_spec._base import SpecModel
from warlog_spec.artifacts import (
    ArtifactCitation,
    ArtifactConfidence,
    ArtifactEnvelope,
    ArtifactProducer,
    ClassificationAssessment,
    ClassificationDecision,
    ConfidenceBand,
    EnrichmentAssessment,
    EnrichmentAssessmentPayload,
    ExtractedIOC,
    MitreAssessment,
    MitreMapping,
    NormalizedEntity,
)
from warlog_spec.enums import AlertCategory, AlertSeverity, AlertVerdict, EntityRole, EntityType, IOCType
from warlog_spec.provider_abi import TriggerSignalKind, TriggerSignalRef

_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_HEX40_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_HEX32_RE = re.compile(r"^[0-9a-fA-F]{32}$")


class OcsfDetectionFindingMapping(SpecModel):
    """Warlog projection of one OCSF Detection Finding event."""

    source_event_id: str = Field(min_length=1)
    source_content_hash: str = Field(min_length=64, max_length=64)
    trigger_signal: TriggerSignalRef
    classification: ClassificationAssessment
    enrichment: EnrichmentAssessment
    mitre: MitreAssessment | None = None


def canonicalize_ocsf_event(event: Mapping[str, Any]) -> bytes:
    """Return stable JSON bytes for an OCSF payload.

    This mirrors the audit-chain stance: sign/hash bytes from a stable
    serialization rather than a lossy projection. The original payload
    remains outside Warlog Spec; only the hash enters downstream audit refs.
    """

    return json.dumps(
        event,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def hash_ocsf_event(event: Mapping[str, Any]) -> str:
    """sha256 of :func:`canonicalize_ocsf_event`."""

    return hashlib.sha256(canonicalize_ocsf_event(event)).hexdigest()


def map_ocsf_detection_finding(
    event: Mapping[str, Any],
    *,
    subject_type: Literal["alert", "case"] = "alert",
    producer_name: str = "ocsf.detection_finding.mapper",
) -> OcsfDetectionFindingMapping:
    """Map one OCSF Detection Finding event to Warlog artifacts.

    Supported input is intentionally broad enough for common OCSF-shaped
    dictionaries while staying honest: unknown fields are preserved only
    through the content hash, not guessed into canonical truth.
    """

    event_id = _event_id(event)
    content_hash = hash_ocsf_event(event)
    generated_at = _event_time(event)
    confidence = _confidence(event)
    citation = ArtifactCitation(
        source_id=event_id,
        source_kind="ocsf_detection_finding",
        section="$",
        score=confidence.score,
    )
    producer = ArtifactProducer(kind="system", name=producer_name)

    category = _category(event)
    severity = _severity(event)
    verdict = _verdict(event)
    classification_confidence = confidence
    classification = ClassificationAssessment(
        envelope=ArtifactEnvelope(
            artifact_type="classification_assessment",
            subject_type=subject_type,
            subject_id=event_id,
            producer=producer,
            generated_at=generated_at,
            confidence=classification_confidence,
            citations=[citation],
        ),
        classification=ClassificationDecision(
            category=category,
            severity=severity,
            verdict=verdict,
            should_escalate=severity in {AlertSeverity.CRITICAL, AlertSeverity.HIGH}
            or verdict is AlertVerdict.TRUE_POSITIVE,
            escalation_risk=_band_for_severity(severity),
        ),
        reasoning=_reasoning(event, category=category, severity=severity, verdict=verdict),
        evidence_summary=_evidence_summary(event),
        missing_evidence=[] if _attacks(event) else ["No OCSF attacks[] mapping present"],
    )

    entities = _entities(event, confidence=confidence)
    iocs = _iocs(event, verdict=verdict, confidence=confidence)
    enrichment = EnrichmentAssessment(
        envelope=ArtifactEnvelope(
            artifact_type="enrichment.ocsf_context",
            subject_type=subject_type,
            subject_id=event_id,
            producer=producer,
            generated_at=generated_at,
            confidence=confidence,
            citations=[citation],
        ),
        payload=EnrichmentAssessmentPayload(
            related_entities=entities,
            matched_iocs=iocs,
            prevalence_summary=_string_from_paths(
                event,
                ("finding", "desc"),
                ("finding", "description"),
                ("message",),
            ),
        ),
    )

    mitre = _mitre(event, event_id=event_id, generated_at=generated_at, producer=producer, confidence=confidence, citation=citation, subject_type=subject_type)
    trigger_signal = TriggerSignalRef(
        kind=TriggerSignalKind.OCSF_EVENT,
        source_id=event_id,
        content_hash=content_hash,
    )
    return OcsfDetectionFindingMapping(
        source_event_id=event_id,
        source_content_hash=content_hash,
        trigger_signal=trigger_signal,
        classification=classification,
        enrichment=enrichment,
        mitre=mitre,
    )


def _event_id(event: Mapping[str, Any]) -> str:
    value = _string_from_paths(
        event,
        ("uid",),
        ("finding", "uid"),
        ("finding", "id"),
        ("metadata", "uid"),
        ("metadata", "event_id"),
        ("metadata", "correlation_uid"),
    )
    if value:
        return value
    return f"ocsf:{hash_ocsf_event(event)[:16]}"


def _event_time(event: Mapping[str, Any]) -> datetime:
    text = _string_from_paths(event, ("time_dt",), ("metadata", "logged_time_dt"))
    if text:
        parsed = _parse_datetime(text)
        if parsed is not None:
            return parsed

    raw = _path(event, ("time",))
    if isinstance(raw, int | float):
        value = raw / 1000 if raw > 10_000_000_000 else raw
        try:
            return datetime.fromtimestamp(value, tz=UTC)
        except (OSError, OverflowError, ValueError):
            return _default_time()
    return _default_time()


def _default_time() -> datetime:
    return datetime(1970, 1, 1, tzinfo=UTC)


def _parse_datetime(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def _confidence(event: Mapping[str, Any]) -> ArtifactConfidence:
    raw_score = _path(event, ("confidence_score",))
    if isinstance(raw_score, int | float):
        score = raw_score / 100 if raw_score > 1 else raw_score
        score = max(0.0, min(1.0, float(score)))
        return ArtifactConfidence(score=score, band=_band_for_score(score))

    raw = _string_from_paths(event, ("confidence",), ("confidence_name",))
    band = _band_for_text(raw or "")
    return ArtifactConfidence(score=None, band=band)


def _severity(event: Mapping[str, Any]) -> AlertSeverity:
    raw = _string_from_paths(event, ("severity",), ("severity_name",))
    if raw:
        text = raw.lower().replace(" ", "_")
        if text in {item.value for item in AlertSeverity}:
            return AlertSeverity(text)

    raw_id = _path(event, ("severity_id",))
    if isinstance(raw_id, int):
        return {
            1: AlertSeverity.INFO,
            2: AlertSeverity.LOW,
            3: AlertSeverity.MEDIUM,
            4: AlertSeverity.HIGH,
            5: AlertSeverity.CRITICAL,
            6: AlertSeverity.CRITICAL,
        }.get(raw_id, AlertSeverity.UNKNOWN)
    return AlertSeverity.UNKNOWN


def _category(event: Mapping[str, Any]) -> AlertCategory:
    text = _search_text(event)
    keyword_map: list[tuple[tuple[str, ...], AlertCategory]] = [
        (("phish",), AlertCategory.PHISHING),
        (("credential", "password", "token", "mfa"), AlertCategory.CREDENTIAL_ACCESS),
        (("unauthorized", "login", "authentication"), AlertCategory.UNAUTHORIZED_ACCESS),
        (("lateral",), AlertCategory.LATERAL_MOVEMENT),
        (("powershell", "script", "execution", "process"), AlertCategory.EXECUTION),
        (("persist",), AlertCategory.PERSISTENCE),
        (("exfil",), AlertCategory.EXFILTRATION),
        (("malware", "ransom", "trojan", "beacon"), AlertCategory.MALWARE),
        (("recon", "scan"), AlertCategory.RECONNAISSANCE),
        (("impact", "destruct", "wipe"), AlertCategory.IMPACT),
        (("policy",), AlertCategory.POLICY_VIOLATION),
        (("denial", "dos", "ddos"), AlertCategory.DENIAL_OF_SERVICE),
    ]
    for keywords, category in keyword_map:
        if any(keyword in text for keyword in keywords):
            return category
    return AlertCategory.UNKNOWN


def _verdict(event: Mapping[str, Any]) -> AlertVerdict:
    text = _search_text(event)
    if "false positive" in text or "false_positive" in text:
        return AlertVerdict.FALSE_POSITIVE
    if "benign" in text:
        return AlertVerdict.BENIGN
    if "true positive" in text or "true_positive" in text or "confirmed" in text:
        return AlertVerdict.TRUE_POSITIVE
    if "suspicious" in text or "malicious" in text or "threat" in text:
        return AlertVerdict.SUSPICIOUS
    return AlertVerdict.UNDETERMINED


def _mitre(
    event: Mapping[str, Any],
    *,
    event_id: str,
    generated_at: datetime,
    producer: ArtifactProducer,
    confidence: ArtifactConfidence,
    citation: ArtifactCitation,
    subject_type: Literal["alert", "case"],
) -> MitreAssessment | None:
    tactics: list[str] = []
    techniques: list[str] = []
    for attack in _attacks(event):
        tactic = _string_from_paths(attack, ("tactic_id",), ("tactic", "uid"), ("tactic", "id"))
        technique = _string_from_paths(
            attack,
            ("technique_id",),
            ("technique", "uid"),
            ("technique", "id"),
            ("technique_uid",),
        )
        if tactic and tactic not in tactics:
            tactics.append(tactic)
        if technique and technique not in techniques:
            techniques.append(technique)
    if not tactics and not techniques:
        return None
    return MitreAssessment(
        envelope=ArtifactEnvelope(
            artifact_type="mitre_assessment",
            subject_type=subject_type,
            subject_id=event_id,
            producer=producer,
            generated_at=generated_at,
            confidence=confidence,
            citations=[citation],
        ),
        mitre=MitreMapping(tactics=tactics, techniques=techniques),
        reasoning="Mapped from OCSF attacks[] references.",
    )


def _entities(event: Mapping[str, Any], *, confidence: ArtifactConfidence) -> list[NormalizedEntity]:
    entities: list[NormalizedEntity] = []
    add_entity(entities, EntityType.HOST, _string_from_paths(event, ("device", "hostname"), ("device", "name"), ("device", "uid")), EntityRole.TARGET, confidence, ["device"])
    add_entity(entities, EntityType.HOST, _string_from_paths(event, ("endpoint", "hostname"), ("endpoint", "name"), ("endpoint", "uid")), EntityRole.TARGET, confidence, ["endpoint"])
    add_entity(entities, EntityType.USER, _string_from_paths(event, ("actor", "user", "name"), ("actor", "user", "uid"), ("user", "name"), ("user", "uid")), EntityRole.RELATED, confidence, ["actor.user", "user"])
    add_entity(entities, EntityType.PROCESS, _string_from_paths(event, ("process", "name"), ("process", "cmd_line")), EntityRole.RELATED, confidence, ["process"])
    add_entity(entities, EntityType.FILE, _string_from_paths(event, ("file", "path"), ("file", "name")), EntityRole.RELATED, confidence, ["file"])
    add_entity(entities, EntityType.IP, _string_from_paths(event, ("src_endpoint", "ip"), ("src_ip",)), EntityRole.RELATED, confidence, ["src_endpoint.ip", "src_ip"])
    add_entity(entities, EntityType.IP, _string_from_paths(event, ("dst_endpoint", "ip"), ("dst_ip",)), EntityRole.TARGET, confidence, ["dst_endpoint.ip", "dst_ip"])

    for observable in _observables(event):
        value = _observable_value(observable)
        kind_text = _observable_kind_text(observable)
        if not value:
            continue
        if "domain" in kind_text:
            add_entity(entities, EntityType.DOMAIN, value, EntityRole.RELATED, confidence, ["observables"])
        elif "url" in kind_text or "uri" in kind_text:
            add_entity(entities, EntityType.URL, value, EntityRole.RELATED, confidence, ["observables"])
        elif "email" in kind_text:
            add_entity(entities, EntityType.EMAIL, value, EntityRole.RELATED, confidence, ["observables"])
    return entities


def add_entity(
    entities: list[NormalizedEntity],
    entity_type: EntityType,
    value: str | None,
    role: EntityRole,
    confidence: ArtifactConfidence,
    source_fields: list[str],
) -> None:
    if not value:
        return
    key = (entity_type.value, value, role.value)
    existing = {(item.entity_type.value, item.value, item.role.value) for item in entities}
    if key in existing:
        return
    entities.append(
        NormalizedEntity(
            entity_type=entity_type,
            value=value,
            role=role,
            confidence=confidence,
            source_fields=source_fields,
        )
    )


def _iocs(
    event: Mapping[str, Any],
    *,
    verdict: AlertVerdict,
    confidence: ArtifactConfidence,
) -> list[ExtractedIOC]:
    iocs: list[ExtractedIOC] = []
    for value, source_field in (
        (_string_from_paths(event, ("src_endpoint", "ip"), ("src_ip",)), "src_endpoint.ip"),
        (_string_from_paths(event, ("dst_endpoint", "ip"), ("dst_ip",)), "dst_endpoint.ip"),
        (_string_from_paths(event, ("url", "url_string"), ("url", "full"), ("url",)), "url"),
    ):
        _add_ioc(iocs, value, _guess_ioc_type(value or ""), verdict, confidence, [source_field])

    for observable in _observables(event):
        value = _observable_value(observable)
        if not value:
            continue
        _add_ioc(
            iocs,
            value,
            _guess_ioc_type(value, hint=_observable_kind_text(observable)),
            verdict,
            confidence,
            ["observables"],
        )
    return iocs


def _add_ioc(
    iocs: list[ExtractedIOC],
    value: str | None,
    ioc_type: IOCType,
    verdict: AlertVerdict,
    confidence: ArtifactConfidence,
    source_fields: list[str],
) -> None:
    if not value:
        return
    key = (ioc_type.value, value)
    existing = {(item.ioc_type.value, item.value) for item in iocs}
    if key in existing:
        return
    iocs.append(
        ExtractedIOC(
            ioc_type=ioc_type,
            value=value,
            maliciousness=verdict,
            confidence=confidence,
            source_fields=source_fields,
        )
    )


def _guess_ioc_type(value: str, *, hint: str = "") -> IOCType:
    text = f"{hint} {value}".lower()
    if "sha256" in text or _HEX64_RE.fullmatch(value):
        return IOCType.HASH_SHA256
    if "sha1" in text or _HEX40_RE.fullmatch(value):
        return IOCType.HASH_SHA1
    if "md5" in text or _HEX32_RE.fullmatch(value):
        return IOCType.HASH_MD5
    if "url" in text or value.startswith(("http://", "https://")):
        return IOCType.URL
    if "email" in text or "@" in value:
        return IOCType.EMAIL
    if "domain" in text:
        return IOCType.DOMAIN
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value):
        return IOCType.IP
    return IOCType.OTHER


def _attacks(event: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    attacks = _path(event, ("attacks",))
    if isinstance(attacks, list):
        return [item for item in attacks if isinstance(item, Mapping)]
    return []


def _observables(event: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    observables = _path(event, ("observables",))
    if isinstance(observables, list):
        return [item for item in observables if isinstance(item, Mapping)]
    return []


def _observable_value(observable: Mapping[str, Any]) -> str | None:
    return _string_from_paths(observable, ("value",), ("name",), ("data",))


def _observable_kind_text(observable: Mapping[str, Any]) -> str:
    return " ".join(
        item
        for item in (
            _string_from_paths(observable, ("type",)),
            _string_from_paths(observable, ("type_name",)),
            _string_from_paths(observable, ("name",)),
        )
        if item
    ).lower()


def _reasoning(
    event: Mapping[str, Any],
    *,
    category: AlertCategory,
    severity: AlertSeverity,
    verdict: AlertVerdict,
) -> str:
    title = _string_from_paths(event, ("finding", "title"), ("type_name",), ("activity_name",), ("message",))
    if title:
        return f"OCSF Detection Finding mapped from {title!r}: category={category.value}, severity={severity.value}, verdict={verdict.value}."
    return f"OCSF Detection Finding mapped to category={category.value}, severity={severity.value}, verdict={verdict.value}."


def _evidence_summary(event: Mapping[str, Any]) -> list[str]:
    evidence = []
    for path in (("finding", "title"), ("message",), ("type_name",), ("activity_name",), ("class_name",)):
        value = _string_from_paths(event, path)
        if value and value not in evidence:
            evidence.append(value)
    return evidence


def _search_text(event: Mapping[str, Any]) -> str:
    fields = [
        _string_from_paths(event, ("category_name",)),
        _string_from_paths(event, ("class_name",)),
        _string_from_paths(event, ("type_name",)),
        _string_from_paths(event, ("activity_name",)),
        _string_from_paths(event, ("message",)),
        _string_from_paths(event, ("finding", "title")),
        _string_from_paths(event, ("finding", "desc"), ("finding", "description")),
        _string_from_paths(event, ("disposition",)),
        _string_from_paths(event, ("status",)),
    ]
    return " ".join(field for field in fields if field).lower()


def _band_for_text(text: str) -> ConfidenceBand:
    lowered = text.lower()
    if "high" in lowered:
        return ConfidenceBand.HIGH
    if "medium" in lowered or "moderate" in lowered:
        return ConfidenceBand.MEDIUM
    if "low" in lowered:
        return ConfidenceBand.LOW
    return ConfidenceBand.UNKNOWN


def _band_for_score(score: float) -> ConfidenceBand:
    if score >= 0.75:
        return ConfidenceBand.HIGH
    if score >= 0.4:
        return ConfidenceBand.MEDIUM
    return ConfidenceBand.LOW


def _band_for_severity(severity: AlertSeverity) -> ConfidenceBand:
    if severity in {AlertSeverity.CRITICAL, AlertSeverity.HIGH}:
        return ConfidenceBand.HIGH
    if severity is AlertSeverity.MEDIUM:
        return ConfidenceBand.MEDIUM
    if severity in {AlertSeverity.LOW, AlertSeverity.INFO}:
        return ConfidenceBand.LOW
    return ConfidenceBand.UNKNOWN


def _string_from_paths(event: Mapping[str, Any], *paths: tuple[str, ...]) -> str | None:
    for path in paths:
        value = _path(event, path)
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, int | float):
            return str(value)
    return None


def _path(event: Mapping[str, Any], path: Iterable[str]) -> Any:
    current: Any = event
    for segment in path:
        if not isinstance(current, Mapping):
            return None
        current = current.get(segment)
    return current


__all__ = [
    "OcsfDetectionFindingMapping",
    "canonicalize_ocsf_event",
    "hash_ocsf_event",
    "map_ocsf_detection_finding",
]