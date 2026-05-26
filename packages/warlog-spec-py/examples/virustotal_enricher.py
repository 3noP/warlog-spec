"""VirusTotal enricher — reference read-side connector.

Wraps the public VirusTotal API v3 (https://docs.virustotal.com/) to
implement the canonical SOC enrichment surface : given an
``ExtractedIOC`` (file hash, IP, domain, URL), return a typed
``EnrichmentAssessment`` with reputation context.

This is the **read-side** dual of the write-side reference
connectors (Okta, Falcon, PAN-OS, Zscaler, Proofpoint, AWS). Where
those map vendor APIs to ``ResponseActionResult`` outputs, this
maps a vendor API to an ``ArtifactEnvelope``-bearing
``EnrichmentAssessment`` output. The surface a third-party
integrator implements is :class:`AbiEnricher`, not
:class:`AbiConnector`.

What this file proves :

- The read-side ABI supports a real, production-shape vendor (VT
  v3) without inventing verb taxonomies. The connector declares
  ``produces_artifact_types`` and ``supports_ioc_types`` ; the
  runtime routes IOC subjects to it ; the connector returns a
  typed canonical envelope.
- The contract is the **shape**, not the API. VT-specific JSON
  (last_analysis_stats, attributes nested two layers deep, etc.) is
  mapped at the connector boundary. Downstream bundle assemblers,
  UI surfaces, and audit tooling see uniform
  ``EnrichmentAssessmentPayload`` shape regardless of whether the
  enricher was VT, AbuseIPDB, Shodan, or an internal model.
- Vendor-specific raw JSON does NOT leak into the canonical
  envelope. The contract escape hatch is provenance
  (``ArtifactCitation`` with the VT report id) and confidence
  (the malicious-vote ratio mapped to a 0..1 score).

**Auth model :** VirusTotal uses a static API key in the
``x-apikey`` header. Free tier is rate-limited (4 lookups / minute,
500 / day) ; the connector surfaces a TRANSIENT error on 429 so
the runtime applies bounded backoff.

Configuration shape::

    {
        "base_url": "https://www.virustotal.com/api/v3",  # default
        "api_key": "redacted",
    }

**Runtime-test status :** spec-conformant, written against VT API v3
public docs. PRs from anyone running it against a live VT account
are welcomed.

Requires ``httpx``.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any, ClassVar

import httpx

from warlog_spec import (
    AbiEnricher,
    AlertVerdict,
    ArtifactCitation,
    ArtifactConfidence,
    ArtifactEnvelope,
    ArtifactProducer,
    AuthDescriptor,
    CanonicalArtifact,
    ConfidenceBand,
    ConnectorAbiError,
    ConnectorAuthModel,
    ConnectorCapability,
    ConnectorCompat,
    ConnectorKind,
    EnrichmentAssessment,
    EnrichmentAssessmentPayload,
    EnrichmentDescriptor,
    EnrichmentRequest,
    ExtractedIOC,
    FailureCategory,
    FreshnessHint,
    IOCType,
    LifecycleDescriptor,
)


_VT_PRODUCER_NAME = "virustotal-v3"


class VirusTotalEnricher(AbiEnricher):
    """Reference enricher wrapping VirusTotal v3."""

    capability: ClassVar[ConnectorCapability] = ConnectorCapability(
        connector_id="virustotal-enricher",
        connector_version="0.1.0",
        vendor="VirusTotal",
        kind=ConnectorKind.THREAT_INTEL,
        auth=AuthDescriptor(
            model=ConnectorAuthModel.API_KEY,
            scopes=["vt.public"],
        ),
        enrichment=EnrichmentDescriptor(
            produces_artifact_types=["enrichment.ioc_reputation"],
            supports_ioc_types=[
                IOCType.IP.value,
                IOCType.DOMAIN.value,
                IOCType.URL.value,
                IOCType.HASH_MD5.value,
                IOCType.HASH_SHA1.value,
                IOCType.HASH_SHA256.value,
            ],
            freshness=FreshnessHint.NEAR_REALTIME,
            bulk_lookup=False,  # VT v3 has separate batch endpoints ; out of scope here
        ),
        lifecycle=LifecycleDescriptor(supports_health_check=True),
        compat=ConnectorCompat(warlog_spec_min="1.0.0", warlog_spec_max="1.x"),
    )

    def __init__(self, config: dict[str, object]) -> None:
        super().__init__(config)
        api_key = config.get("api_key")
        if not isinstance(api_key, str) or not api_key:
            raise ConnectorAbiError(
                FailureCategory.AUTH,
                "virustotal: config['api_key'] is required",
            )
        base_url = str(config.get("base_url") or "https://www.virustotal.com/api/v3")
        self._api_key = api_key
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=httpx.Timeout(15.0, connect=5.0),
            headers={
                "x-apikey": api_key,
                "Accept": "application/json",
            },
        )

    # -- Lifecycle hooks --------------------------------------------------

    async def authenticate(self) -> None:
        """Smoke the API key with a no-op call.

        VT v3 doesn't have a dedicated auth endpoint ; we hit the
        users/me route which works on any non-expired key. A 401 is
        the unambiguous bad-key signal.
        """
        try:
            resp = await self._client.get("/users/me")
        except httpx.HTTPError as exc:
            raise ConnectorAbiError(
                FailureCategory.TRANSIENT,
                f"virustotal: auth network error: {exc}",
            ) from exc
        if resp.status_code == 401:
            raise ConnectorAbiError(
                FailureCategory.AUTH,
                "virustotal: API key invalid or revoked",
                vendor_code="401",
            )
        # Free-tier keys may not have access to /users/me ; treat 403
        # as "key works but lacks scope" — auth itself is fine.
        if resp.status_code not in (200, 403):
            raise _map_vt_error(resp, op="authenticate")

    async def enrich(
        self,
        request: EnrichmentRequest,
    ) -> CanonicalArtifact | None:
        """Resolve the canonical IOC target against VT v3.

        The resulting envelope's ``subject_type`` / ``subject_id``
        are copied from ``request`` — the artifact is fully
        self-attributing without runtime post-processing.
        """
        target = request.target
        if not isinstance(target, ExtractedIOC):
            # Capability declares supports_ioc_types only. Entity
            # enrichment is out of scope for this enricher — defer
            # to the runtime to route entities elsewhere.
            raise ConnectorAbiError(
                FailureCategory.POLICY,
                f"virustotal: target kind not supported "
                f"(got {type(target).__name__}, expected ExtractedIOC)",
            )

        path = _vt_path_for_ioc(target)
        if path is None:
            raise ConnectorAbiError(
                FailureCategory.POLICY,
                f"virustotal: ioc_type {target.ioc_type.value!r} not supported",
            )

        try:
            resp = await self._client.get(path)
        except httpx.HTTPError as exc:
            raise ConnectorAbiError(
                FailureCategory.TRANSIENT,
                f"virustotal: lookup network error: {exc}",
            ) from exc

        if resp.status_code == 404:
            # VT explicitly says "we don't know about this IOC". This
            # is a clean miss, not an error — return None so the
            # orchestrator records "looked up, no data" rather than
            # propagating a failure.
            return None
        if resp.status_code != 200:
            raise _map_vt_error(resp, op=f"lookup:{target.ioc_type.value}")

        return _vt_response_to_assessment(resp.json(), request)

    async def aclose(self) -> None:
        await self._client.aclose()


# ---------------------------------------------------------------------------
# Vendor-shape → canonical-shape mapping
# ---------------------------------------------------------------------------


def _vt_path_for_ioc(ioc: ExtractedIOC) -> str | None:
    """Map our canonical IOC type → VT v3 endpoint path."""
    value = ioc.value.strip()
    if ioc.ioc_type is IOCType.IP:
        return f"/ip_addresses/{value}"
    if ioc.ioc_type is IOCType.DOMAIN:
        return f"/domains/{value}"
    if ioc.ioc_type is IOCType.URL:
        # VT URL lookups use a base64-without-padding identifier.
        import base64

        url_id = base64.urlsafe_b64encode(value.encode()).rstrip(b"=").decode()
        return f"/urls/{url_id}"
    if ioc.ioc_type in {
        IOCType.HASH_MD5,
        IOCType.HASH_SHA1,
        IOCType.HASH_SHA256,
    }:
        return f"/files/{value}"
    return None


def _vt_response_to_assessment(
    body: dict[str, Any],
    request: EnrichmentRequest,
) -> EnrichmentAssessment:
    """Map a VT v3 response envelope to a canonical EnrichmentAssessment.

    VT's response shape is :

        {"data": {
            "id": "<vendor id>",
            "type": "ip_address|domain|url|file",
            "attributes": {
                "last_analysis_stats": {
                    "harmless": int, "malicious": int,
                    "suspicious": int, "undetected": int,
                    "timeout": int
                },
                "last_analysis_date": int,  # unix timestamp
                "reputation": int,           # -100..100
                ...
            }
        }}

    We pull the malicious / suspicious counts to derive a 0..1
    confidence score and map it to a coarse band, attribute the
    artifact to the VT producer with the report id as the citation,
    and surface the IOC verdict back into the canonical
    ``maliciousness`` field on a fresh ``ExtractedIOC``.
    """
    data = body.get("data") or {}
    attrs = data.get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}

    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    harmless = int(stats.get("harmless") or 0)
    undetected = int(stats.get("undetected") or 0)
    total_engines = malicious + suspicious + harmless + undetected
    detection_ratio = (malicious + suspicious) / total_engines if total_engines else 0.0

    if malicious >= 5:
        verdict = AlertVerdict.TRUE_POSITIVE
        band = ConfidenceBand.HIGH
    elif malicious >= 1 or suspicious >= 3:
        verdict = AlertVerdict.SUSPICIOUS
        band = ConfidenceBand.MEDIUM
    elif total_engines > 0 and harmless / total_engines > 0.95:
        verdict = AlertVerdict.BENIGN
        band = ConfidenceBand.HIGH
    else:
        verdict = AlertVerdict.UNDETERMINED
        band = ConfidenceBand.LOW

    last_analysis_at: datetime | None = None
    last_analysis_unix = attrs.get("last_analysis_date")
    if isinstance(last_analysis_unix, int) and last_analysis_unix > 0:
        last_analysis_at = datetime.fromtimestamp(last_analysis_unix, tz=UTC)

    target = request.target
    assert isinstance(target, ExtractedIOC)  # validated upstream
    enriched_ioc = ExtractedIOC(
        ioc_type=target.ioc_type,
        value=target.value,
        confidence=ArtifactConfidence(score=detection_ratio, band=band),
        maliciousness=verdict,
        last_seen=last_analysis_at,
    )

    envelope = ArtifactEnvelope(
        artifact_type="enrichment.ioc_reputation",
        # subject_type / subject_id come from the request — the
        # connector is responsible for self-attributing the artifact
        # to the alert/case the enrichment was requested for. No
        # runtime post-processing required.
        subject_type=request.subject_type,
        subject_id=request.subject_id,
        producer=ArtifactProducer(
            kind="rule",
            name=_VT_PRODUCER_NAME,
            model=str(attrs.get("last_analysis_engine_version") or "v3"),
        ),
        generated_at=datetime.now(UTC),
        confidence=ArtifactConfidence(score=detection_ratio, band=band),
        citations=[
            ArtifactCitation(
                source_id=str(data.get("id") or target.value),
                source_kind="threat_intel_feed",
                section="last_analysis_stats",
                score=detection_ratio,
            )
        ],
    )
    payload = EnrichmentAssessmentPayload(
        matched_iocs=[enriched_ioc],
        prevalence_summary=(
            f"{malicious} malicious / {suspicious} suspicious / "
            f"{harmless} harmless / {undetected} undetected "
            f"across {total_engines} engines"
        ),
        threat_intel_hits=_extract_threat_categories(attrs),
    )
    return EnrichmentAssessment(envelope=envelope, payload=payload)


def _extract_threat_categories(attrs: dict[str, Any]) -> list[str]:
    """Surface VT-reported categories into our canonical
    ``threat_intel_hits`` field.

    VT exposes ``categories`` (domain) or ``popular_threat_classification``
    (file) — different schemas. Pull whichever is present.
    """
    out: list[str] = []
    categories = attrs.get("categories")
    if isinstance(categories, dict):
        out.extend(str(v) for v in categories.values())
    threat_class = attrs.get("popular_threat_classification") or {}
    label = threat_class.get("suggested_threat_label")
    if isinstance(label, str) and label:
        out.append(label)
    return out[:10]


_VT_HTTP_TO_CATEGORY: dict[int, tuple[FailureCategory, bool]] = {
    400: (FailureCategory.POLICY, False),
    401: (FailureCategory.AUTH, False),
    403: (FailureCategory.POLICY, False),
    404: (FailureCategory.NOT_FOUND, False),
    429: (FailureCategory.TRANSIENT, True),
}


def _map_vt_error(resp: httpx.Response, *, op: str) -> ConnectorAbiError:
    """Map a VT non-2xx response to a categorized ABI error."""
    status = resp.status_code
    if status in _VT_HTTP_TO_CATEGORY:
        category, retryable = _VT_HTTP_TO_CATEGORY[status]
    elif 500 <= status < 600:
        category, retryable = FailureCategory.TRANSIENT, True
    else:
        category, retryable = FailureCategory.POLICY, False
    try:
        body: dict[str, Any] = resp.json()
    except ValueError:
        body = {}
    error = body.get("error") or {}
    return ConnectorAbiError(
        category,
        f"virustotal {op} failed: HTTP {status}",
        retryable=retryable,
        vendor_code=str(error.get("code") or status),
        vendor_message=str(error.get("message") or "")[:200] or None,
    )


# ---------------------------------------------------------------------------
# CLI walkthrough — capability inspection only.
# ---------------------------------------------------------------------------


async def _main() -> None:
    cap = VirusTotalEnricher.capability
    print(f"connector_id     = {cap.connector_id}")
    print(f"vendor           = {cap.vendor}")
    print(f"kind             = {cap.kind.value}")
    print(f"auth_model       = {cap.auth.model.value}")
    print(f"egress.actions   = {[a.value for a in cap.egress.supports_response_actions] or '(read-only enricher)'}")
    print(f"enrichment       = {cap.enrichment.produces_artifact_types}")
    print(f"  ioc_types      = {cap.enrichment.supports_ioc_types}")
    print(f"  freshness      = {cap.enrichment.freshness.value}")
    print(f"  bulk_lookup    = {cap.enrichment.bulk_lookup}")
    print()
    print("To exercise against a live VirusTotal account :")
    print("  pip install httpx")
    print("  export VT_API_KEY=...")
    print("  python -m examples.virustotal_enricher --live <ioc-value>")


if __name__ == "__main__":
    asyncio.run(_main())
