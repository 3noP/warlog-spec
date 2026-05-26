"""RFC-0003 — outbound STIX 2.1 projection tests.

Validates the shape against the STIX 2.1 Note SDO contract :

- required fields present
- ``id`` matches the pattern ``note--<uuid>``
- ``object_refs`` derived deterministically from linked alert ids
- ``confidence`` lies in [0, 100]
- two projections of the same input yield the same Note id
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

import pytest

from warlog_spec.artifacts import (
    ArtifactConfidence,
    CaseReturnSummary,
    ConfidenceBand,
    ExtractedIOC,
)
from warlog_spec.enums import (
    AlertCategory,
    AlertSeverity,
    AlertVerdict,
    IOCType,
)
from warlog_spec.stix_projection import (
    case_return_to_stix_note,
    ioc_to_stix_indicator,
)


_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
)


def _sample_case_return() -> CaseReturnSummary:
    return CaseReturnSummary(
        case_id="CASE-2026-0042",
        case_number="CASE-2026-0042",
        generated_at=datetime(2026, 5, 20, 10, 0, 0, tzinfo=UTC),
        final_verdict=AlertVerdict.TRUE_POSITIVE,
        final_category=AlertCategory.EXECUTION,
        final_severity=AlertSeverity.HIGH,
        outcome_summary="Contained host, revoked tokens, deployed YARA rule.",
        root_cause="Successful spear-phishing against alice@warlog.demo.",
        lessons_learned="Disable macros on external Office docs.",
        linked_alert_ids=["alert-001", "alert-002"],
        confidence=ArtifactConfidence(score=0.95, band=ConfidenceBand.HIGH),
    )


def test_projection_shape_matches_stix_2_1_note_sdo() -> None:
    note = case_return_to_stix_note(
        _sample_case_return(),
        tenant_id="tenant-1",
        case_url="https://soc.example.org/cases/CASE-2026-0042",
    )

    # Type + spec version
    assert note["type"] == "note"
    assert note["spec_version"] == "2.1"

    # id : note--<uuid>
    assert note["id"].startswith("note--")
    assert _UUID_RE.match(note["id"].split("--", 1)[1])

    # Timestamps in Z form
    assert note["created"].endswith("Z")
    assert note["modified"].endswith("Z")
    assert note["created"] == note["modified"]  # Notes are immutable in our projection

    # Abstract + content
    assert len(note["abstract"]) <= 200
    assert "CASE-2026-0042" in note["abstract"]
    assert "TRUE_POSITIVE" in note["abstract"]
    assert "## Outcome summary" in note["content"]
    assert "## Root cause" in note["content"]
    assert "## Lessons learned" in note["content"]
    assert len(note["content"]) <= 65535

    # object_refs : one incident per linked alert
    assert len(note["object_refs"]) == 2
    assert all(ref.startswith("incident--") for ref in note["object_refs"])

    # external_references
    ext = note["external_references"][0]
    assert ext["source_name"] == "warlog-spec"
    assert ext["external_id"] == "CASE-2026-0042"
    assert ext["url"] == "https://soc.example.org/cases/CASE-2026-0042"

    # labels
    assert "closure" in note["labels"]
    assert "execution" in note["labels"]

    # confidence in [0, 100]
    assert 0 <= note["confidence"] <= 100
    assert note["confidence"] == 95  # score=0.95 → 95


def test_projection_is_deterministic() -> None:
    """Same input → same ids. Lets consumers dedup across MSSPs."""
    note_a = case_return_to_stix_note(_sample_case_return(), tenant_id="t-1")
    note_b = case_return_to_stix_note(_sample_case_return(), tenant_id="t-1")
    assert note_a["id"] == note_b["id"]
    assert note_a["object_refs"] == note_b["object_refs"]
    # Different tenant → different created_by_ref but same Note id
    # (Note id depends only on case_id, not tenant — by design).
    note_c = case_return_to_stix_note(_sample_case_return(), tenant_id="t-2")
    assert note_c["id"] == note_a["id"]
    assert note_c["created_by_ref"] != note_a["created_by_ref"]


def test_projection_without_optional_fields() -> None:
    case_return = _sample_case_return().model_copy(
        update={"root_cause": None, "lessons_learned": None}
    )
    note = case_return_to_stix_note(case_return, tenant_id="t-1")
    assert "## Root cause" not in note["content"]
    assert "## Lessons learned" not in note["content"]
    assert "## Outcome summary" in note["content"]


def test_confidence_band_mapping() -> None:
    case_return = _sample_case_return().model_copy(
        update={"confidence": ArtifactConfidence(score=None, band=ConfidenceBand.LOW)}
    )
    note = case_return_to_stix_note(case_return, tenant_id="t-1")
    assert note["confidence"] == 25

    case_return = _sample_case_return().model_copy(
        update={"confidence": ArtifactConfidence(score=None, band=ConfidenceBand.MEDIUM)}
    )
    note = case_return_to_stix_note(case_return, tenant_id="t-1")
    assert note["confidence"] == 60

    case_return = _sample_case_return().model_copy(
        update={"confidence": ArtifactConfidence(score=None, band=ConfidenceBand.HIGH)}
    )
    note = case_return_to_stix_note(case_return, tenant_id="t-1")
    assert note["confidence"] == 85

    case_return = _sample_case_return().model_copy(
        update={"confidence": ArtifactConfidence(score=None, band=ConfidenceBand.UNKNOWN)}
    )
    note = case_return_to_stix_note(case_return, tenant_id="t-1")
    assert note["confidence"] == 0


def test_ioc_indicator_projection_for_sha256() -> None:
    ioc = ExtractedIOC(
        ioc_type=IOCType.HASH_SHA256,
        value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        confidence=ArtifactConfidence(score=0.92, band=ConfidenceBand.HIGH),
        maliciousness=AlertVerdict.TRUE_POSITIVE,
        first_seen=datetime(2026, 5, 1, 0, 0, 0, tzinfo=UTC),
    )
    indicator = ioc_to_stix_indicator(ioc, tenant_id="t-1")
    assert indicator is not None
    assert indicator["type"] == "indicator"
    assert indicator["spec_version"] == "2.1"
    assert indicator["pattern_type"] == "stix"
    assert "SHA-256" in indicator["pattern"]
    assert ioc.value in indicator["pattern"]
    assert "malicious-activity" in indicator["labels"]


def test_ioc_indicator_projection_for_ip() -> None:
    ioc = ExtractedIOC(
        ioc_type=IOCType.IP,
        value="192.0.2.50",
        confidence=ArtifactConfidence(score=None, band=ConfidenceBand.MEDIUM),
        maliciousness=AlertVerdict.SUSPICIOUS,
        first_seen=datetime(2026, 5, 1, 0, 0, 0, tzinfo=UTC),
    )
    indicator = ioc_to_stix_indicator(ioc, tenant_id="t-1")
    assert indicator is not None
    assert "ipv4-addr" in indicator["pattern"]
    assert "192.0.2.50" in indicator["pattern"]
    # Not "malicious-activity" because maliciousness != true_positive
    assert "anomalous-activity" in indicator["labels"]


def test_ioc_indicator_projection_returns_none_for_unsupported_type() -> None:
    ioc = ExtractedIOC(
        ioc_type=IOCType.USER,
        value="alice@warlog.demo",
        confidence=ArtifactConfidence(band=ConfidenceBand.HIGH),
        maliciousness=AlertVerdict.SUSPICIOUS,
    )
    assert ioc_to_stix_indicator(ioc, tenant_id="t-1") is None


def test_abstract_caps_at_200_chars() -> None:
    long_case = _sample_case_return().model_copy(
        update={"case_number": "X" * 300}
    )
    note = case_return_to_stix_note(long_case, tenant_id="t-1")
    assert len(note["abstract"]) <= 200
    assert note["abstract"].endswith("...")
