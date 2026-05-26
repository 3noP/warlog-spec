"""ABI — abstract base classes a connector implements.

Two ABCs are exposed :

- :class:`AbiConnector` — write-side. Lifecycle hooks
  ``authenticate → dry_run → apply → verify``. Used by connectors
  that issue response actions against a vendor (host.isolate,
  user.disable, key.rotate, …).
- :class:`AbiEnricher` — read-side. Simpler lifecycle :
  ``authenticate → enrich``. Returns a canonical
  :class:`~warlog_spec.artifacts.EnrichmentAssessment` (or another
  envelope-bearing canonical shape). Used by connectors that PRODUCE
  context about an entity / IOC (VirusTotal, AbuseIPDB, Shodan, …).

A vendor that does both can implement both bases on a single class
via multiple inheritance, or ship two separate connector classes
sharing config. The runtime routes by the populated descriptors on
:class:`~warlog_spec.provider_abi.ConnectorCapability` —
``egress`` for writes, ``enrichment`` for reads.

Catches exceptions and maps them to :class:`ConnectorError` via the
failure model in :mod:`warlog_spec.provider_abi`. To shortcut
categorization, raise :class:`ConnectorAbiError` from connector code.

This module is the **public** integration surface : a third party
writes its connector by subclassing :class:`AbiConnector` or
:class:`AbiEnricher` from this package. The runtime that orchestrates
lifecycle, audit chain, approval gate, idempotency cache lives in
the Warlog backend and is NOT part of this package. Conformance only
requires you to implement the abstract methods correctly.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from warlog_spec.artifacts import (
    CanonicalArtifact,
    EnrichmentRequest,
)
from warlog_spec.provider_abi import (
    ConnectorCapability,
    ConnectorError,
    FailureCategory,
    ResponseActionResult,
    ResponseActionSpec,
)


class ConnectorAbiError(Exception):
    """Categorized error a connector raises to short-circuit failure mapping.

    Use this when the connector knows the failure category at the
    call site (e.g. catching a vendor 401 → ``AUTH``). For unknown
    exceptions the runtime defaults to ``FailureCategory.TRANSIENT``
    (retryable).
    """

    def __init__(
        self,
        category: FailureCategory,
        message: str,
        *,
        retryable: bool | None = None,
        vendor_code: str | None = None,
        vendor_message: str | None = None,
    ) -> None:
        super().__init__(message)
        self.category = category
        self.message = message
        self.retryable = (
            retryable
            if retryable is not None
            else (category in {FailureCategory.TRANSIENT})
        )
        self.vendor_code = vendor_code
        self.vendor_message = vendor_message

    def to_connector_error(self) -> ConnectorError:
        return ConnectorError(
            category=self.category,
            message=self.message,
            retryable=self.retryable,
            vendor_code=self.vendor_code,
            vendor_message=self.vendor_message,
        )


class AbiConnector(ABC):
    """ABI-conformant connector base class.

    Subclasses must declare a class-level ``capability`` attribute
    and implement the four lifecycle hooks. The runtime calls them in
    order ``authenticate → dry_run → apply → verify``.

    ``apply`` MAY return a partial result if the upstream operation
    is asynchronous; ``verify`` is then expected to confirm the final
    state by polling the upstream vendor.
    """

    capability: ClassVar[ConnectorCapability]

    def __init__(self, config: dict[str, object]) -> None:
        self.config = config

    # -- Lifecycle hooks --------------------------------------------------

    @abstractmethod
    async def authenticate(self) -> None:
        """Acquire/refresh credentials.

        Raise :class:`ConnectorAbiError` with category ``AUTH`` on
        failure. Called once per execution by the runtime before
        ``dry_run``.
        """

    @abstractmethod
    async def dry_run(self, spec: ResponseActionSpec) -> None:
        """Validate the action without executing it.

        Connectors with ``capability.dry_run.supported = False`` MAY
        return immediately. Validation failures should raise
        :class:`ConnectorAbiError` (typically ``NOT_FOUND`` for missing
        subjects, ``STATE_CONFLICT`` for invalid current state,
        ``POLICY`` for vendor-side denials).
        """

    @abstractmethod
    async def apply(self, spec: ResponseActionSpec) -> ResponseActionResult:
        """Execute the action against the upstream vendor.

        .. important:: **Connector-side idempotency is REQUIRED.** The
           runtime's idempotency cache only protects against repeat
           calls within one process and one terminal outcome.
           Cross-process re-invokes after a ``PENDING_APPROVAL`` (a
           parallel approval landing during a re-poll) can both reach
           ``apply``. To prevent vendor-side double-execution, the
           connector MUST forward ``spec.idempotency_key`` to the
           upstream API as the vendor's idempotency token. Connectors
           that ignore the key are responsible for any duplicate side
           effects.

          Connector implementations should return ``SUCCESS``, ``FAILURE``,
          or ``EXPIRED``. ``PENDING_APPROVAL`` and ``DENIED`` are runner / approval
          gate outcomes used when execution stops before vendor mutation.
        """

    @abstractmethod
    async def verify(
        self,
        spec: ResponseActionSpec,
        result: ResponseActionResult,
    ) -> bool:
        """Poll the upstream vendor to confirm the action took effect.

        Return ``True`` once the target state is observed. The runtime
        retries on ``False`` with bounded backoff. Raise
        :class:`ConnectorAbiError` for hard failures.
        """


class AbiEnricher(ABC):
    """ABI-conformant enrichment connector base class.

    The read-side dual of :class:`AbiConnector`. Where a write-side
    connector mutates vendor state through a four-stage lifecycle,
    an enrichment connector PRODUCES a canonical artifact about a
    subject :

        ``authenticate → enrich(request) → CanonicalArtifact | None``

    No ``dry_run`` (reads are naturally non-destructive), no
    ``approval`` (the catalog defaults read-side actions to
    auto-execute), no ``verify`` (the assessment IS the result), no
    cross-process idempotency_key requirement (reads are naturally
    idempotent).

    Subclasses MUST :

    1. Declare a class-level :attr:`capability` whose
       ``enrichment`` :class:`~warlog_spec.provider_abi.EnrichmentDescriptor`
       declares what artifact types they produce (e.g.
       ``"enrichment.ioc_reputation"``, ``"mitre.assessment"``) and
       on what subjects (entity / IOC types).
    2. Implement :meth:`authenticate` (idempotent ; called once per
       runtime session).
    3. Implement :meth:`enrich` to return a
       :class:`~warlog_spec.artifacts.CanonicalArtifact` subclass
       (``EnrichmentAssessment``, ``MitreAssessment``, …) on a
       successful lookup, or ``None`` when the vendor has no data
       about the subject (clean miss, distinguished from an error).
       The connector's actual return type MUST be one of the shapes
       it advertised in ``capability.enrichment.produces_artifact_types``.

    Idiomatic shape : connector inspects the request's
    ``target`` type, queries the vendor API, maps the response into
    a typed payload, wraps it in an
    :class:`~warlog_spec.artifacts.ArtifactEnvelope` (copying
    ``subject_type`` / ``subject_id`` from the request so the
    artifact is self-attributing), and returns the composed
    :class:`~warlog_spec.artifacts.CanonicalArtifact`. Vendor-specific
    raw data is NOT returned ; the canonical envelope IS the contract.
    """

    capability: ClassVar[ConnectorCapability]

    def __init__(self, config: dict[str, object]) -> None:
        self.config = config

    @abstractmethod
    async def authenticate(self) -> None:
        """Acquire / refresh credentials.

        Raise :class:`ConnectorAbiError` with category ``AUTH`` on
        failure. Called once per session.
        """

    @abstractmethod
    async def enrich(
        self,
        request: EnrichmentRequest,
    ) -> CanonicalArtifact | None:
        """Produce a canonical artifact for ``request.target``.

        The returned artifact's envelope MUST carry
        ``subject_type`` / ``subject_id`` copied from the request —
        the connector is responsible for this attribution, not the
        runtime.

        Return ``None`` when the vendor has no data about the target
        (clean miss). Raise :class:`ConnectorAbiError` for hard
        failures :

        - ``AUTH`` for credential errors,
        - ``NOT_FOUND`` if the vendor explicitly says the target
          does not exist (distinct from a clean miss — only raise
          this when the vendor's API confirms non-existence rather
          than absence-of-data),
        - ``POLICY`` if the connector cannot enrich this target
          type (it should not have been routed here in the first
          place — the capability declares supports_*),
        - ``TRANSIENT`` for retryable failures (rate limits, network).
        """


__all__ = [
    "AbiConnector",
    "AbiEnricher",
    "ConnectorAbiError",
]
