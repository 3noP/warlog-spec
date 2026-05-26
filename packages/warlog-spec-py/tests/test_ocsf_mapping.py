from __future__ import annotations

import hashlib
import json

from warlog_spec.ocsf import canonicalize_ocsf_event, hash_ocsf_event, map_ocsf_detection_finding
from warlog_spec.provider_abi import TriggerSignalRef


SAMPLE_DETECTION_FINDING = {
    "class_name": "Detection Finding",
    "class_uid": 2004,
    "uid": "ocsf-event-001",
    "time_dt": "2026-05-25T12:00:00Z",
    "severity": "High",
    "confidence_score": 87,
    "type_name": "Process Activity: Malicious PowerShell",
    "message": "Suspicious encoded PowerShell execution from Office parent.",
    "finding": {
        "title": "Encoded PowerShell from Office",
        "desc": "Suspicious execution chain with external payload URL.",
    },
    "attacks": [{"tactic_id": "TA0002", "technique_id": "T1059.001"}],
    "device": {"hostname": "WIN-001", "uid": "agent-001"},
    "actor": {"user": {"name": "alice@warlog.demo"}},
    "process": {"name": "powershell.exe", "cmd_line": "powershell -enc ..."},
    "src_endpoint": {"ip": "10.0.0.5"},
    "observables": [
        {"type_name": "URL", "value": "https://evil.example/payload"},
        {
            "type_name": "SHA256 Hash",
            "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        },
    ],
}


def test_hash_ocsf_event_is_stable_canonical_json() -> None:
    expected = hashlib.sha256(
        json.dumps(
            SAMPLE_DETECTION_FINDING,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()

    assert hashlib.sha256(canonicalize_ocsf_event(SAMPLE_DETECTION_FINDING)).hexdigest() == expected


def test_detection_finding_maps_to_warlog_artifacts() -> None:
    mapped = map_ocsf_detection_finding(SAMPLE_DETECTION_FINDING)

    TriggerSignalRef.model_validate(mapped.trigger_signal)
    assert mapped.trigger_signal.kind == "ocsf_event"
    assert mapped.trigger_signal.source_id == "ocsf-event-001"
    assert mapped.trigger_signal.content_hash == mapped.source_content_hash

    decision = mapped.classification.classification
    assert decision.category == "execution"
    assert decision.severity == "high"
    assert decision.verdict == "suspicious"
    assert decision.should_escalate is True

    assert mapped.mitre is not None
    assert mapped.mitre.mitre.tactics == ["TA0002"]
    assert mapped.mitre.mitre.techniques == ["T1059.001"]

    entities = {(entity.entity_type.value, entity.value) for entity in mapped.enrichment.payload.related_entities}
    assert ("host", "WIN-001") in entities
    assert ("user", "alice@warlog.demo") in entities
    assert ("process", "powershell.exe") in entities

    iocs = {(ioc.ioc_type.value, ioc.value) for ioc in mapped.enrichment.payload.matched_iocs}
    assert ("url", "https://evil.example/payload") in iocs
    assert (
        "hash_sha256",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ) in iocs


def test_invalid_time_falls_back_without_losing_source_hash() -> None:
    event = {"uid": "bad-time", "time_dt": "not-a-date", "severity": "Low"}

    mapped = map_ocsf_detection_finding(event)

    assert mapped.classification.envelope.generated_at.year == 1970
    assert mapped.trigger_signal.content_hash == hash_ocsf_event(event)