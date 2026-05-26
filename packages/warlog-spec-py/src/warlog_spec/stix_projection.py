"""Outbound STIX 2.1 projection — RFC-0003.

Translate a :class:`~warlog_spec.artifacts.CaseReturnSummary` into a
STIX 2.1 :term:`Note` object so a tenant can share closure context
with a threat-intel partner without re-implementing the shape per
consumer.

The projection is **deterministic** (same input → same STIX ids via
``uuid5``) and **opinionated** (fixed field mapping ; consumers
that want a different shape MUST implement their own).

See ``warlog-spec/rfcs/0003-stix-projection.md`` for the design
rationale and the field-by-field mapping.
"""

from __future__ import annotations

from typing import Any
from uuid import NAMESPACE_OID, uuid5

from warlog_spec.artifacts import (
    ArtifactConfidence,
    CaseReturnSummary,
    ConfidenceBand,
    ExtractedIOC,
)
from warlog_spec.enums import IOCType

# Fixed namespace string for deterministic uuid5 derivation. Two
# tenants projecting the same source object produce the same STIX
# ids — useful for cross-tenant deduplication on the consumer side.
_NS = "warlog-spec:stix:"


def _id(stix_type: str, name: str) -> str:
    """Build a deterministic STIX id of the form ``<type>--<uuid5>``."""
    return f"{stix_type}--{uuid5(NAMESPACE_OID, _NS + name)}"


def _confidence_to_int(confidence: ArtifactConfidence) -> int:
    """Map ``ArtifactConfidence.band`` to the STIX 0-100 integer scale.

    STIX 2.1's ``confidence`` is an optional integer between 0 and
    100. Our band mapping :

    - ``unknown`` → 0
    - ``low``     → 25
    - ``medium``  → 60
    - ``high``    → 85

    A numeric score on ``confidence.score`` (0.0-1.0) takes
    precedence when present : ``round(score * 100)``.
    """
    if confidence.score is not None:
        return max(0, min(100, round(confidence.score * 100)))
    return {
        ConfidenceBand.UNKNOWN: 0,
        ConfidenceBand.LOW: 25,
        ConfidenceBand.MEDIUM: 60,
        ConfidenceBand.HIGH: 85,
    }[confidence.band]


def _abstract(case_return: CaseReturnSummary) -> str:
    """STIX 2.1 caps ``abstract`` at 200 chars ; build a short summary."""
    text = (
        f"Closure of {case_return.case_number} — "
        f"verdict={case_return.final_verdict.value.upper()}"
    )
    if len(text) > 200:
        text = text[:197] + "..."
    return text


def _content(case_return: CaseReturnSummary) -> str:
    """Render the closure summary as Markdown for the STIX ``content`` field.

    STIX 2.1 caps ``content`` at 65535 chars ; we never approach
    that with a normal closure summary, but we truncate defensively
    just in case.
    """
    lines: list[str] = []
    lines.append(f"# Closure : {case_return.case_number}")
    lines.append("")
    lines.append(f"**Verdict** : {case_return.final_verdict.value}")
    lines.append(f"**Category** : {case_return.final_category.value}")
    lines.append(f"**Severity** : {case_return.final_severity.value}")
    lines.append("")
    lines.append("## Outcome summary")
    lines.append(case_return.outcome_summary)
    if case_return.root_cause:
        lines.append("")
        lines.append("## Root cause")
        lines.append(case_return.root_cause)
    if case_return.lessons_learned:
        lines.append("")
        lines.append("## Lessons learned")
        lines.append(case_return.lessons_learned)
    body = "\n".join(lines)
    return body if len(body) <= 65535 else body[:65532] + "..."


def case_return_to_stix_note(
    case_return: CaseReturnSummary,
    *,
    tenant_id: str,
    case_url: str | None = None,
    author_display_name: str = "warlog-spec",
) -> dict[str, Any]:
    """Project a :class:`CaseReturnSummary` to a STIX 2.1 Note dict.

    Returns a dict ready for JSON serialization. The shape conforms
    to STIX 2.1 §4.10 (Note SDO).

    Parameters
    ----------
    case_return:
        The source warlog artifact.
    tenant_id:
        Tenant identifier — used to derive the ``created_by_ref``
        STIX Identity id deterministically. Operator-supplied so
        the projection doesn't have to know about the runtime
        user model.
    case_url:
        Optional URL to the case in the producer's UI. Embedded in
        ``external_references[0].url`` when provided.
    author_display_name:
        Display name for the producer ; lands in ``authors[0]``.

    Examples
    --------
    >>> note = case_return_to_stix_note(
    ...     summary,
    ...     tenant_id="tenant-soc-1",
    ...     case_url="https://soc.example.org/cases/CASE-2026-0042",
    ... )
    >>> note["type"]
    'note'
    >>> note["spec_version"]
    '2.1'
    """
    created_by_ref = _id("identity", f"tenant:{tenant_id}")
    object_refs = [_id("incident", f"alert:{aid}") for aid in case_return.linked_alert_ids]

    external_ref: dict[str, Any] = {
        "source_name": "warlog-spec",
        "external_id": case_return.case_id,
    }
    if case_url:
        external_ref["url"] = case_url

    return {
        "type": "note",
        "spec_version": "2.1",
        "id": _id("note", f"case-return:{case_return.case_id}"),
        "created": case_return.generated_at.isoformat().replace("+00:00", "Z"),
        "modified": case_return.generated_at.isoformat().replace("+00:00", "Z"),
        "created_by_ref": created_by_ref,
        "abstract": _abstract(case_return),
        "content": _content(case_return),
        "authors": [author_display_name],
        "object_refs": object_refs,
        "external_references": [external_ref],
        "labels": ["closure", case_return.final_category.value],
        "confidence": _confidence_to_int(case_return.confidence),
    }


def _ioc_to_stix_pattern(ioc: ExtractedIOC) -> str | None:
    """Map an ``ExtractedIOC`` to a STIX 2.1 pattern expression.

    Returns ``None`` for IOC types without a clean STIX 2.1 pattern
    (e.g. internal ``user`` references) — the caller skips the
    indicator emission.
    """
    v = ioc.value.replace("'", r"\'")
    if ioc.ioc_type is IOCType.IP:
        return f"[ipv4-addr:value = '{v}']"
    if ioc.ioc_type is IOCType.IPV6:
        return f"[ipv6-addr:value = '{v}']"
    if ioc.ioc_type is IOCType.DOMAIN:
        return f"[domain-name:value = '{v}']"
    if ioc.ioc_type is IOCType.URL:
        return f"[url:value = '{v}']"
    if ioc.ioc_type is IOCType.HASH_MD5:
        return f"[file:hashes.MD5 = '{v}']"
    if ioc.ioc_type is IOCType.HASH_SHA1:
        return f"[file:hashes.'SHA-1' = '{v}']"
    if ioc.ioc_type is IOCType.HASH_SHA256:
        return f"[file:hashes.'SHA-256' = '{v}']"
    if ioc.ioc_type is IOCType.EMAIL:
        return f"[email-addr:value = '{v}']"
    if ioc.ioc_type is IOCType.FILE_PATH:
        return f"[file:name = '{v}']"
    # No clean STIX pattern : skip (returns None).
    return None


def ioc_to_stix_indicator(
    ioc: ExtractedIOC,
    *,
    tenant_id: str,
) -> dict[str, Any] | None:
    """Project an :class:`ExtractedIOC` to a STIX 2.1 Indicator dict.

    Returns ``None`` when the IOC type has no clean STIX 2.1 pattern
    expression (e.g. internal user references). Skip them on the
    caller side.
    """
    pattern = _ioc_to_stix_pattern(ioc)
    if pattern is None:
        return None
    created_by_ref = _id("identity", f"tenant:{tenant_id}")
    indicator: dict[str, Any] = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": _id("indicator", f"ioc:{ioc.ioc_type.value}:{ioc.value}"),
        "created": (ioc.first_seen or ioc.last_seen).isoformat().replace("+00:00", "Z")
        if (ioc.first_seen or ioc.last_seen)
        else "1970-01-01T00:00:00Z",
        "modified": (ioc.last_seen or ioc.first_seen).isoformat().replace("+00:00", "Z")
        if (ioc.last_seen or ioc.first_seen)
        else "1970-01-01T00:00:00Z",
        "created_by_ref": created_by_ref,
        "pattern_type": "stix",
        "pattern": pattern,
        "valid_from": (ioc.first_seen or ioc.last_seen)
        .isoformat()
        .replace("+00:00", "Z")
        if (ioc.first_seen or ioc.last_seen)
        else "1970-01-01T00:00:00Z",
        "confidence": _confidence_to_int(ioc.confidence),
        "labels": ["malicious-activity"] if ioc.maliciousness.value == "true_positive" else ["anomalous-activity"],
    }
    return indicator


__all__ = [
    "case_return_to_stix_note",
    "ioc_to_stix_indicator",
]
