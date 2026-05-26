"""Pattern A — ambient-context audit decorator for AI agent tools.

This module is the **integration ergonomics layer** of ``warlog-spec``.
It lets a developer turn any function into an audited tool with a
single decorator, while preserving the trust-layer invariants the
spec promises (EU AI Act traceability, GDPR pseudonymization gate,
HMAC chain integrity, decision-pointer hashes).

Quickstart::

    from warlog_spec import AiAgentRef, ComplianceScope, ResponseActionId, TriggerSignalKind
    from warlog_spec.integrate import WarlogClient, audited, agent_run

    client = WarlogClient.from_env()

    @audited(
        client=client,
        action_id=ResponseActionId.USER_REVOKE_TOKENS,
        subject_arg="user_email",
        compliance_scope=[ComplianceScope.GDPR, ComplianceScope.NIS2],
    )
    async def revoke_user_tokens(user_email: str) -> dict:
        return await okta_client.users.sessions.delete(user_email)

    # In your agent loop :
    agent = AiAgentRef(
        model="gpt-4o", model_version="2026-04-01",
        system_prompt_hash=SYSTEM_PROMPT_HASH,
        agent_run_id=str(uuid.uuid4()),
        tools_manifest_hash=TOOLS_HASH,
    )
    async with agent_run(client, agent=agent, alert_id="alert-123",
                         alert_payload=alert_bytes,
                         compliance_scope=[ComplianceScope.GDPR]):
        await revoke_user_tokens("alice@acme.example")

Design doctrine
---------------

- **Strict env defaults.** ``WarlogClient.from_env()`` fails loudly on
  missing ``WARLOG_HMAC_SECRET``, ``WARLOG_TENANT_ID``, ``WARLOG_PII_SALT``.
  No silent defaults — a missing secret means anyone with the (well-known)
  fallback could forge audit rows.
- **Strict context by default.** Calling an ``@audited`` function outside
  an active ``agent_run`` raises :class:`TraceabilityError` — EU AI Act
  traceability is mandatory in production. Set
  ``WarlogClient(require_agent_run=False)`` for local tests.
- **Optional approval gate.** By default the decorator does pure audit +
    signing. If your use case needs an active shield before destructive
    actions reach the vendor, pass an ``ApprovalGate`` to ``WarlogClient`` ;
    pending or denied decisions emit signed approval rows and block ``apply``.
- **Chain state lives in the persister.** On process restart, the next
  signed row's ``prev_hash`` comes from the persister's last row, not
  from in-memory state. No phantom chain breaks across restarts.
- **Synthetic decision_ref.** The decorator builds a minimal
  ``NextStepProposal`` from ``(action_id, function.__doc__, args)``,
  canonicalizes it, and hashes it for the ``DecisionRef.content_hash``.
  This makes the AuditRow's required ``decision_ref`` field always
  populated without forcing the caller to materialize a proposal per
  call.
"""

from __future__ import annotations

import contextvars
import functools
import hashlib
import inspect
import json
import os
import threading
import time
import uuid
import warnings
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Callable, Literal, Protocol, Union

from warlog_spec.action_catalog import ACTION_CATALOG
from warlog_spec.audit_chain import (
    CANONICALIZATION_FORMAT_V1,
    canonicalize_v1,
    compute_genesis,
    compute_signature,
)
from warlog_spec.provider_abi import (
    AiAgentRef,
    ApprovalLevel,
    AuditConnectorRef,
    AuditRow,
    AutomationActor,
    ComplianceScope,
    ConnectorError,
    DecisionArtifactType,
    DecisionRef,
    ExecutionOutcome,
    ExecutionPhase,
    FailureCategory,
    ResponseActionId,
    ResponseActionScope,
    ResponseSubject,
    SelectorRepresentation,
    TriggerSignalKind,
    TriggerSignalRef,
)

# ---------------------------------------------------------------------------
# Public exceptions
# ---------------------------------------------------------------------------


class TraceabilityError(RuntimeError):
    """An audited action was invoked outside an active ``agent_run`` context.

    Doctrine : EU AI Act traceability requires every automated action to
    carry the agent identity (``AiAgentRef``) and the upstream signal
    that triggered it (``TriggerSignalRef``). The decorator refuses to
    sign a row that would have to lie about those fields.

    To suppress this for tests : set ``WarlogClient(require_agent_run=False)``.
    """


class WarlogConfigError(RuntimeError):
    """A required ``WARLOG_*`` environment variable was not set or empty."""


# ---------------------------------------------------------------------------
# Approval gate — protocol + default + typed exceptions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ApprovalRequest:
    """Summary of a pending action handed to the :class:`ApprovalGate`.

    The gate inspects this object and returns an :class:`ApprovalDecision`.
    The gate is free to consult any side channel (a DB of pre-approvals,
    a Slack bot, a PagerDuty integration, a static policy table) to
    reach its decision. The :class:`ApprovalRequest` is intentionally
    immutable and JSON-serializable so the gate can persist it for
    out-of-band review.
    """

    action_id: ResponseActionId
    subject: ResponseSubject
    default_approval_level: ApprovalLevel
    function_name: str
    args_summary: dict[str, Any]
    agent_run_id: str | None
    actor_id: str | None
    idempotency_key: str


@dataclass(frozen=True)
class ApprovalDecision:
    """Outcome of an :meth:`ApprovalGate.request` call.

    ``state`` :

    - ``"approved"`` — the decorator proceeds to ``apply``.
    - ``"denied"`` — the decorator emits a ``DENIED`` audit row and
      raises :class:`ApprovalDenied`.
    - ``"pending"`` — the decorator emits a ``PENDING_APPROVAL`` audit
      row and raises :class:`ApprovalRequired` with ``request_id`` for
      out-of-band tracking.

    ``request_id`` is required when ``state == "pending"`` so the
    caller can poll, cancel, or correlate the durable approval row.
    """

    state: Literal["approved", "denied", "pending"]
    rationale: str | None = None
    request_id: str | None = None


class ApprovalGate(Protocol):
    """Synchronous approval gate consulted by :func:`audited` before ``apply``.

    Doctrine : the gate is on the critical path of every audited tool
    call. Production gates SHOULD complete in <10 ms — backed by an
    in-memory cache, SQLite, or a fast Redis lookup. HTTP gates with
    cloud round-trips are acceptable only if the operator accepts the
    extra per-call latency.

    When :attr:`WarlogClient.approval_gate` is ``None`` (default), the
    decorator skips the approval phase entirely — no ``APPROVAL`` audit
    row is emitted. Inject a gate to enable the bouclier-actif mode.
    """

    def request(self, req: ApprovalRequest) -> ApprovalDecision:
        """Decide whether to authorize, deny, or suspend the action."""


class AutoApproveGate:
    """Always-approves gate. Useful for tests and for opt-in audit-only mode.

    Note : configuring this gate IS opt-in to the approval phase — every
    audited call emits an ``APPROVAL/SUCCESS`` row in addition to
    ``DRY_RUN`` and ``APPLY``. If you want NO approval row at all,
    leave :attr:`WarlogClient.approval_gate` as ``None`` (the default).
    """

    def request(self, req: ApprovalRequest) -> ApprovalDecision:
        return ApprovalDecision(state="approved", rationale="auto-approved (no policy)")


class ApprovalRequired(Exception):
    """Raised when the gate returns ``"pending"`` — caller must suspend.

    The decorator has emitted a ``PENDING_APPROVAL`` audit row before
    raising ; the row's id is available as :attr:`audit_id`. The
    expected pattern is :

    .. code-block:: python

        try:
            await revoke_user_tokens(user_email)
        except ApprovalRequired as exc:
            await notify_human(exc.request_id, exc.audit_id)
            # ... wait for the human's out-of-band decision ...
            # On retry, the deterministic idempotency_key ensures the
            # gate sees the same request_id (most gate impls dedupe).
            await revoke_user_tokens(user_email)

    The wrapped function is NOT called when this is raised.
    """

    def __init__(self, request_id: str, audit_id: str, rationale: str = "") -> None:
        super().__init__(
            f"Approval required (request_id={request_id}, audit_id={audit_id}). {rationale}".strip()
        )
        self.request_id = request_id
        self.audit_id = audit_id
        self.rationale = rationale


class ApprovalDenied(Exception):
    """Raised when the gate returns ``"denied"`` — action permanently refused.

    The decorator has emitted a ``DENIED`` audit row before raising ;
    the row's id is available as :attr:`audit_id`. The wrapped function
    is NOT called. Retrying with the same idempotency_key will produce
    the same denial — gates are expected to cache decisions per
    (action_id, subject, idempotency_key).
    """

    def __init__(self, audit_id: str, rationale: str = "") -> None:
        super().__init__(
            f"Action denied by approval gate (audit_id={audit_id}). {rationale}".strip()
        )
        self.audit_id = audit_id
        self.rationale = rationale


# ---------------------------------------------------------------------------
# Family -> Scope mapping
# ---------------------------------------------------------------------------

# The action catalog uses string family names. ResponseSubject.kind uses
# the typed ResponseActionScope enum. This mapping is the source of truth
# the decorator uses to construct subjects when the caller did not pass
# an explicit kind.
_FAMILY_TO_SCOPE: dict[str, ResponseActionScope] = {
    "device": ResponseActionScope.ENDPOINT,
    "identity": ResponseActionScope.IDENTITY,
    "iam": ResponseActionScope.IDENTITY,
    "network": ResponseActionScope.NETWORK,
    "email": ResponseActionScope.MAIL,
    "key": ResponseActionScope.PKI,
    "storage": ResponseActionScope.PLATFORM,
    "workflow": ResponseActionScope.PLATFORM,
}

# Action families whose subject is PII-bearing — the decorator MUST
# pseudonymize the selector before signing. Mirrors the runtime gate
# in ``backend/app/services/connectors/abi_runner.py``.
_PII_FAMILIES: frozenset[str] = frozenset({"identity", "email", "iam"})


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SignedRow:
    """A row + its HMAC envelope, the unit the persister stores.

    ``canonical_bytes`` is the EXACT byte sequence that was signed.
    A verifier recomputes ``HMAC(secret, prev_hash || "|" || canonical_bytes)``
    and compares to ``signature`` — it never re-serializes ``row``. This
    is what makes Pydantic schema evolution safe for historical chains.
    """

    row: AuditRow
    prev_hash: str
    signature: str
    canonical_bytes: bytes
    canonicalization_format: str = CANONICALIZATION_FORMAT_V1


class AuditPersister(Protocol):
    """Append-only sink for signed audit rows.

    Implementations MUST be safe to call from multiple threads. The
    :class:`WarlogClient` adds its own lock around the compute-then-append
    sequence so the chain is consistent ; the persister only has to
    serialize concurrent ``append`` calls.
    """

    def head_signature(self) -> str | None:
        """Return the signature of the last row in the chain, or ``None`` if empty.

        Called once per ``append`` to resolve the next ``prev_hash``. A
        persister that survives process restarts MUST return the same
        head signature it returned before the restart — otherwise the
        chain develops a phantom break.
        """

    def append(self, signed: SignedRow) -> None:
        """Atomically append ``signed`` to the chain."""


class InMemoryPersister:
    """In-memory persister — for tests and short-lived processes."""

    def __init__(self) -> None:
        self._rows: list[SignedRow] = []
        self._lock = threading.Lock()

    def head_signature(self) -> str | None:
        with self._lock:
            return self._rows[-1].signature if self._rows else None

    def append(self, signed: SignedRow) -> None:
        with self._lock:
            self._rows.append(signed)

    def rows(self) -> list[SignedRow]:
        """Read-only snapshot of the chain (mostly for tests)."""
        with self._lock:
            return list(self._rows)


class JsonlFilePersister:
    """Append-only JSONL persister.

    Each line is one ``SignedRow`` rendered as a JSON object containing :

    - ``row`` — the canonical AuditRow as camelCase JSON
    - ``prevHash`` — hex predecessor signature
    - ``signature`` — hex HMAC of this row
    - ``canonicalBytes`` — base64 of the bytes that were actually signed
    - ``canonicalizationFormat`` — usually ``"v1"``

    On init, the file is scanned to recover the last signature (so the
    chain survives process restarts). Concurrent ``append`` calls from
    multiple threads serialize via an internal lock.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = os.fspath(path)
        self._lock = threading.Lock()
        self._head_signature: str | None = self._recover_head()

    def _recover_head(self) -> str | None:
        if not os.path.exists(self._path):
            return None
        last: str | None = None
        with open(self._path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                sig = entry.get("signature")
                if isinstance(sig, str):
                    last = sig
        return last

    def head_signature(self) -> str | None:
        with self._lock:
            return self._head_signature

    def append(self, signed: SignedRow) -> None:
        import base64

        entry = {
            "row": signed.row.model_dump(mode="json", by_alias=True),
            "prevHash": signed.prev_hash,
            "signature": signed.signature,
            "canonicalBytes": base64.b64encode(signed.canonical_bytes).decode("ascii"),
            "canonicalizationFormat": signed.canonicalization_format,
        }
        line = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        with self._lock:
            os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            self._head_signature = signed.signature


# ---------------------------------------------------------------------------
# Client + ambient context
# ---------------------------------------------------------------------------


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise WarlogConfigError(
            f"Required environment variable {name!r} is not set or is empty. "
            "warlog_spec.integrate refuses silent defaults for secrets — "
            "set the variable explicitly or build a WarlogClient(...) directly."
        )
    return value


class WarlogClient:
    """Configuration + persister handle for the audit decorator.

    Holds the tenant identity, HMAC secret, PII salt, and the persister
    that owns the chain state. Multiple ``WarlogClient`` instances per
    process are allowed (for multi-tenant agents) but each instance's
    ``persister`` must be distinct — sharing a persister across tenants
    interleaves chains.

    Construct directly when you want full control :

        client = WarlogClient(
            tenant_id="acme-eu",
            hmac_secret=hsm.get_secret("warlog-hmac-v3"),
            pii_salt=hsm.get_secret("warlog-salt-v3"),
            selector_key_id="tenant:acme-eu:salt:v3",
            persister=JsonlFilePersister("/var/log/warlog/audit.jsonl"),
        )

    Or use :meth:`from_env` to read from environment variables :

        client = WarlogClient.from_env()
    """

    def __init__(
        self,
        *,
        tenant_id: str,
        hmac_secret: Union[bytes, Callable[[], bytes]],
        pii_salt: bytes,
        persister: AuditPersister,
        selector_key_id: str | None = None,
        connector_id: str = "in_process.integrate",
        connector_version: str = "0.1.0",
        require_agent_run: bool = True,
        approval_gate: ApprovalGate | None = None,
        clock_drift_tolerance_s: float = 1.0,
    ) -> None:
        """Construct a client.

        ``hmac_secret`` can be either :

        - ``bytes`` — the secret held in process memory for the
          process lifetime. Simple, sufficient for development and
          self-managed deployments.
        - ``Callable[[], bytes]`` — a provider invoked once per signed
          row. For high-security environments (ANSSI / OIV / classified),
          configure this to fetch from an HSM, HashiCorp Vault, AWS KMS
          DataKey API, or any short-lived secret broker over a Unix
          socket. The secret bytes returned are used for the single
          signature operation and eligible for garbage collection
          immediately after. A successful RCE on the process can still
          dump memory mid-signing, but the attacker only catches one
          secret-bytes lifetime per attack window — making forging an
          entire historical chain materially harder.

        ``clock_drift_tolerance_s`` controls the time-drift detection
        threshold (default 1 second). Wall-clock vs monotonic-clock
        divergence beyond this triggers a ``RuntimeWarning``. Set
        higher if your environment legitimately experiences NTP steps.
        Detection only — the chain is not invalidated.
        """
        if not tenant_id:
            raise WarlogConfigError("tenant_id must be a non-empty string")
        if not pii_salt:
            raise WarlogConfigError("pii_salt must be non-empty bytes")

        # Normalize hmac_secret into a callable. A literal bytes value
        # is captured into a no-op provider so the rest of the code
        # path is uniform (call provider every time, garbage-collect
        # the result). The literal case keeps the secret in memory the
        # whole process lifetime ; the callable case can pull it
        # ephemerally from a vault.
        if callable(hmac_secret):
            initial = hmac_secret()
            if not initial:
                raise WarlogConfigError("hmac_secret provider returned empty bytes")
            self._hmac_secret_provider: Callable[[], bytes] = hmac_secret  # type: ignore[assignment]
        elif isinstance(hmac_secret, (bytes, bytearray)):
            if not hmac_secret:
                raise WarlogConfigError("hmac_secret must be non-empty bytes")
            _captured = bytes(hmac_secret)
            self._hmac_secret_provider = lambda: _captured
        else:
            raise WarlogConfigError(
                f"hmac_secret must be bytes or Callable[[], bytes], got {type(hmac_secret).__name__}"
            )

        self.tenant_id = tenant_id
        self.pii_salt = pii_salt
        self.persister = persister
        self.selector_key_id = selector_key_id or f"tenant:{tenant_id}:salt:default"
        self.connector_ref = AuditConnectorRef(id=connector_id, version=connector_version)
        self.require_agent_run = require_agent_run
        self.clock_drift_tolerance_s = clock_drift_tolerance_s

        # Clock-drift detection state. Compared on every emitted row :
        # if wall-clock and monotonic-clock diverge by more than
        # ``clock_drift_tolerance_s``, a RuntimeWarning fires (the
        # chain stays cryptographically valid, but timestamps become
        # forensically suspect). Detection-only — operators must run
        # a strict NTP daemon (chronyd, systemd-timesyncd) for
        # actual prevention.
        self._last_wall: datetime | None = None
        self._last_mono_ns: int | None = None

        # Multi-tenant safety check : a single persister is per-tenant
        # by construction (the HMAC chain links rows with the SAME secret,
        # and each tenant gets its own salt + secret). Two clients sharing
        # a persister but holding different tenant_ids would interleave
        # their chains in storage ; per-tenant verify() would then fail
        # because the chain crosses secret domains. Stamp ownership on the
        # persister so we can warn loudly on misuse.
        existing_owner = getattr(persister, "_warlog_owner_tenant", None)
        if existing_owner is None:
            persister._warlog_owner_tenant = tenant_id  # type: ignore[attr-defined]
        elif existing_owner != tenant_id:
            import warnings

            warnings.warn(
                f"WarlogClient(tenant_id={tenant_id!r}) is sharing a persister already "
                f"claimed by tenant {existing_owner!r}. Each tenant MUST own its own "
                f"persister — sharing interleaves HMAC chains in storage and per-tenant "
                f"verify() will fail because rows are signed with different secrets. "
                f"Construct one persister per tenant.",
                RuntimeWarning,
                stacklevel=2,
            )
        # ``approval_gate`` is None by default → decorator skips the
        # APPROVAL phase entirely (audit-only mode). Inject a real gate
        # to switch into bouclier-actif mode : every audited call emits
        # an APPROVAL row and ``pending`` / ``denied`` outcomes raise
        # typed exceptions that block ``apply``.
        self.approval_gate = approval_gate
        # Serializes the compute-then-append step across threads / tasks
        # sharing this client. Persisters add their own locking on top.
        self._chain_lock = threading.Lock()

    @property
    def hmac_secret(self) -> bytes:
        """Resolve the secret on each access via the configured provider.

        For literal-bytes construction this returns the captured bytes
        every time. For callable construction this invokes the provider —
        operators of high-security environments should ensure their
        provider hits an HSM / Vault rather than caching the secret in
        memory. The return value is used for one ``compute_signature``
        call and dropped.
        """
        return self._hmac_secret_provider()

    def _check_clock_drift(self, now: datetime) -> None:
        """Compare wall-clock progress against monotonic-clock progress.

        If they diverge by more than ``clock_drift_tolerance_s``, the
        wall clock has been adjusted (NTP step, VM clock skip,
        manual operator change). The HMAC chain stays valid — the
        signature is over canonical bytes that include the wall-clock
        timestamp regardless — but the timestamps are no longer
        trustworthy for forensic ordering. Surface the discrepancy
        as a RuntimeWarning so operators see it in logs.

        Implementation note : ``time.monotonic_ns()`` is immune to
        NTP adjustments and VM clock skips by construction. It only
        moves forward at the system tick rate.
        """
        mono_now = time.monotonic_ns()
        if self._last_wall is None or self._last_mono_ns is None:
            self._last_wall = now
            self._last_mono_ns = mono_now
            return

        wall_delta = (now - self._last_wall).total_seconds()
        mono_delta = (mono_now - self._last_mono_ns) / 1e9

        # Backward step is suspicious ONLY if it exceeds the tolerance.
        # Sub-tolerance backwards on Windows can be OS time-quantum noise
        # (datetime.now() resolution ≈ 16ms on default config) — we don't
        # want to spam warnings for normal clock jitter.
        if wall_delta < -self.clock_drift_tolerance_s:
            warnings.warn(
                f"Wall clock moved backwards by {-wall_delta:.3f}s between audit "
                f"rows (tolerance {self.clock_drift_tolerance_s:.3f}s). Possible NTP "
                f"step, manual clock change, or VM hypervisor freeze. The HMAC chain "
                f"is still cryptographically valid but audit timestamps no longer "
                f"order linearly — forensic reconstruction requires correlating "
                f"monotonic.",
                RuntimeWarning,
                stacklevel=3,
            )
        elif abs(wall_delta - mono_delta) > self.clock_drift_tolerance_s:
            warnings.warn(
                f"Wall-clock advanced {wall_delta:.3f}s while monotonic clock "
                f"advanced {mono_delta:.3f}s (drift {wall_delta - mono_delta:+.3f}s). "
                f"Possible NTP step or hypervisor pause. Subsequent audit rows "
                f"will reflect the new wall-clock baseline. Investigate the "
                f"host clock.",
                RuntimeWarning,
                stacklevel=3,
            )

        self._last_wall = now
        self._last_mono_ns = mono_now

    @classmethod
    def from_env(cls) -> WarlogClient:
        """Construct a client from ``WARLOG_*`` environment variables.

        Required :
            - ``WARLOG_TENANT_ID``
            - ``WARLOG_HMAC_SECRET``
            - ``WARLOG_PII_SALT``

        Optional :
            - ``WARLOG_AUDIT_LOG`` — JSONL persister path. Defaults to
              ``./warlog-audit.jsonl`` in the current working directory.
            - ``WARLOG_SELECTOR_KEY_ID`` — surfaced on every pseudonymized
              subject. Format ``tenant:<id>:salt:v<N>`` is the convention.
            - ``WARLOG_CONNECTOR_ID`` / ``WARLOG_CONNECTOR_VERSION`` —
              what to put in the AuditRow's ``connector`` field for
              decorator-emitted rows.
        """
        tenant_id = _require_env("WARLOG_TENANT_ID")
        hmac_secret = _require_env("WARLOG_HMAC_SECRET").encode("utf-8")
        pii_salt = _require_env("WARLOG_PII_SALT").encode("utf-8")
        log_path = os.environ.get("WARLOG_AUDIT_LOG", "./warlog-audit.jsonl")
        selector_key_id = os.environ.get("WARLOG_SELECTOR_KEY_ID")
        connector_id = os.environ.get("WARLOG_CONNECTOR_ID", "in_process.integrate")
        connector_version = os.environ.get("WARLOG_CONNECTOR_VERSION", "0.1.0")
        return cls(
            tenant_id=tenant_id,
            hmac_secret=hmac_secret,
            pii_salt=pii_salt,
            persister=JsonlFilePersister(log_path),
            selector_key_id=selector_key_id,
            connector_id=connector_id,
            connector_version=connector_version,
        )


@dataclass(frozen=True)
class AgentRunContext:
    """Ambient context bound for the duration of an ``agent_run``.

    Carries the EU AI Act traceability anchors (the agent identity, the
    upstream signal) plus the compliance scopes any action initiated in
    this context will inherit. The ``id`` field is the
    ``AutomationActor.id`` — typically the playbook / workflow id that
    invoked the agent.
    """

    actor_id: str
    agent_ref: AiAgentRef
    trigger_signal_ref: TriggerSignalRef
    compliance_scope: list[ComplianceScope] = field(default_factory=list)


_CURRENT_CONTEXT: ContextVar[AgentRunContext | None] = ContextVar(
    "warlog_current_run_context", default=None
)


class agent_run:
    """Bind an ``AgentRunContext`` for the duration of a block.

    Works as both a sync context manager (``with agent_run(...):``) and
    an async context manager (``async with agent_run(...):``). The
    binding is task-local thanks to :class:`contextvars.ContextVar`, so
    concurrent ``asyncio.gather`` tasks each see their own context.

    Two ways to bind a trigger signal :

    1. Pass a fully-built :class:`TriggerSignalRef` via ``trigger=``.
    2. Pass ``alert_id`` + ``alert_payload`` (raw bytes) and let the
       constructor synthesize a ``TriggerSignalRef`` of kind ``ALERT``
       with ``content_hash = sha256(alert_payload)``. Most agent code
       prefers (2) — passing the bytes you already have.

    Example::

        async with agent_run(
            client,
            actor_id="playbook.fraud_triage",
            agent=agent_ref,
            alert_id="alert-2026-05-20-7f3e",
            alert_payload=alert.json().encode(),
            compliance_scope=[ComplianceScope.GDPR, ComplianceScope.NIS2],
        ):
            await revoke_user_tokens("alice@acme.example")
    """

    def __init__(
        self,
        client: WarlogClient,
        *,
        agent: AiAgentRef,
        actor_id: str = "automation",
        trigger: TriggerSignalRef | None = None,
        alert_id: str | None = None,
        alert_payload: bytes | None = None,
        trigger_kind: TriggerSignalKind = TriggerSignalKind.ALERT,
        compliance_scope: list[ComplianceScope] | None = None,
    ) -> None:
        if trigger is None:
            if alert_id is not None or alert_payload is not None:
                trigger = TriggerSignalRef(
                    kind=trigger_kind,
                    source_id=alert_id or "",
                    content_hash=hashlib.sha256(alert_payload or b"").hexdigest(),
                )
            else:
                # Manual / walked-in click — explicit "no upstream signal".
                trigger = TriggerSignalRef(
                    kind=TriggerSignalKind.MANUAL,
                    source_id="",
                    content_hash="",
                )

        self._client = client
        self._context = AgentRunContext(
            actor_id=actor_id,
            agent_ref=agent,
            trigger_signal_ref=trigger,
            compliance_scope=list(compliance_scope or []),
        )
        self._token: Token[AgentRunContext | None] | None = None

    # -- Sync ---------------------------------------------------------

    def __enter__(self) -> AgentRunContext:
        self._token = _CURRENT_CONTEXT.set(self._context)
        return self._context

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        if self._token is not None:
            _CURRENT_CONTEXT.reset(self._token)
            self._token = None

    # -- Async --------------------------------------------------------

    async def __aenter__(self) -> AgentRunContext:
        return self.__enter__()

    async def __aexit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        self.__exit__(exc_type, exc_val, exc_tb)


# ---------------------------------------------------------------------------
# Thread propagation helper
# ---------------------------------------------------------------------------


def propagate_warlog_context(callable_: Callable[..., Any]) -> Callable[..., Any]:
    """Wrap a callable so the current ``agent_run`` context follows it into threads.

    Python's ``contextvars`` are async-safe and propagate naturally
    across ``asyncio.to_thread``, ``loop.run_in_executor``, and any
    helper that uses ``contextvars.copy_context()`` internally. **They
    do NOT propagate across a raw ``ThreadPoolExecutor.submit(fn)``** :
    the worker thread starts with a fresh context, the ``_CURRENT_CONTEXT``
    ContextVar reverts to its default ``None``, and any ``@audited``
    function that runs there raises :class:`TraceabilityError`.

    Some agent frameworks (older LangChain tool execution paths,
    certain custom dispatchers) use raw ThreadPoolExecutor under the
    hood. Wrap your tool callable with this helper to capture the
    caller's context at submission time and re-establish it in the
    worker thread :

    .. code-block:: python

        from concurrent.futures import ThreadPoolExecutor
        from warlog_spec.integrate import propagate_warlog_context

        with agent_run(client, agent=...):
            wrapped = propagate_warlog_context(my_audited_tool)
            future = pool.submit(wrapped, "alice@acme.example")
            result = future.result()

    Under the hood : :func:`contextvars.copy_context` snapshots the
    current context (incl. ``_CURRENT_CONTEXT``) and ``Context.run``
    replays it in the worker. The audited function sees the same
    actor / trigger / compliance_scope it would have seen in the
    caller's thread.

    No-op for already-async callables : if your agent uses
    ``asyncio.to_thread`` or ``loop.run_in_executor``, contextvars
    propagate automatically and this helper is unnecessary.

    Implementation note : the context is snapshotted at the moment
    you CALL ``propagate_warlog_context(fn)``, not at the moment the
    worker invokes the wrapped function. Call this helper INSIDE the
    ``agent_run`` block (right before submitting to the pool), not at
    module scope, otherwise you snapshot an empty context.
    """
    captured_ctx = contextvars.copy_context()

    @functools.wraps(callable_)
    def thread_safe(*args: Any, **kwargs: Any) -> Any:
        return captured_ctx.run(callable_, *args, **kwargs)

    return thread_safe


# ---------------------------------------------------------------------------
# Decision-ref synthesis + GDPR gate
# ---------------------------------------------------------------------------


def _canonical_args_hash(action_id: ResponseActionId, doc: str, args: dict[str, Any]) -> str:
    """sha256 of a deterministic JSON of ``(action_id, doc, args)``.

    Used as ``DecisionRef.content_hash`` for the synthetic NextStepProposal
    the decorator materializes. Same function + same args = same hash, so
    re-invoking is observable across audit rows.
    """
    safe_args: dict[str, Any] = {}
    for key, value in args.items():
        try:
            json.dumps(value)
            safe_args[key] = value
        except TypeError:
            safe_args[key] = repr(value)
    payload = json.dumps(
        {
            "action_id": action_id.value,
            "rationale": doc.strip() if doc else "",
            "args": safe_args,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _synthesize_decision_ref(
    action_id: ResponseActionId, function: Callable[..., Any], bound_args: dict[str, Any]
) -> DecisionRef:
    """Build a ``DecisionRef`` pointing at a synthetic NextStepProposal.

    The decorator never persists the proposal itself — it just hashes it
    so the AuditRow's required ``decision_ref`` is populated and the
    hash is reproducible from ``(action_id, function.__doc__, args)``.
    An operator who wants a verifiable proposal object can rebuild it
    server-side from the same inputs and confirm the hash matches.
    """
    doc = function.__doc__ or ""
    content_hash = _canonical_args_hash(action_id, doc, bound_args)
    return DecisionRef(
        artifact_type=DecisionArtifactType.NEXT_STEP_PROPOSAL,
        artifact_id=f"synthetic-{content_hash[:16]}",
        content_hash=content_hash,
    )


def _deterministic_idempotency_key(
    action_id: ResponseActionId, subject_value: str, bound_args: dict[str, Any]
) -> str:
    """Stable idempotency key derived from (action_id, subject, args).

    Same call twice = same key — the vendor side can dedupe by it.
    Different agent_run_id calls deliberately produce the SAME key when
    the action is the same on the same subject (which is the doctrine
    of vendor-side idempotency).
    """
    payload = json.dumps(
        {
            "action_id": action_id.value,
            "subject": subject_value,
            "args": {k: repr(v) for k, v in bound_args.items()},
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return f"warlog-{hashlib.sha256(payload).hexdigest()[:32]}"


def _build_subject(
    action_id: ResponseActionId,
    subject_value: Any,
    client: WarlogClient,
) -> ResponseSubject:
    """Build a ``ResponseSubject`` for the action, pseudonymizing if PII.

    For actions in the PII families (identity / email / iam), the raw
    subject is hashed with the tenant salt and the
    ``selector_representation`` is set to ``SHA256_SALTED``. For other
    families, the raw value passes through unchanged.

    Doctrine : pseudonymization is the caller's responsibility ; the
    decorator's job is to enforce that responsibility, not to bypass
    it. The salt lives on the client (which holds it as bytes) — the
    spec NEVER stores the salt in the audit row.
    """
    meta = ACTION_CATALOG.get(action_id)
    family = meta.family if meta else "workflow"
    scope = _FAMILY_TO_SCOPE.get(family, ResponseActionScope.PLATFORM)
    raw_str = str(subject_value) if subject_value is not None else ""

    if family in _PII_FAMILIES:
        if not raw_str:
            raise TraceabilityError(
                f"Action {action_id.value!r} is in PII family {family!r} but received an "
                f"empty subject. The decorator cannot pseudonymize an empty value ; "
                f"check the function's `subject_arg` parameter."
            )
        hashed = hashlib.sha256(client.pii_salt + raw_str.encode("utf-8")).hexdigest()
        return ResponseSubject(
            kind=scope,
            selector_type="user_principal_name",
            selector_value=hashed,
            selector_representation=SelectorRepresentation.SHA256_SALTED,
            selector_key_id=client.selector_key_id,
        )

    return ResponseSubject(
        kind=scope,
        selector_type=family,
        selector_value=raw_str,
        selector_representation=SelectorRepresentation.RAW,
    )


# ---------------------------------------------------------------------------
# Signing pipeline
# ---------------------------------------------------------------------------


def _resolve_context(client: WarlogClient) -> AgentRunContext | None:
    """Return the ambient ``AgentRunContext`` or raise / fallback per policy."""
    ctx = _CURRENT_CONTEXT.get()
    if ctx is None and client.require_agent_run:
        raise TraceabilityError(
            "Audited action invoked outside an active agent_run context. "
            "EU AI Act traceability requires an AiAgentRef + TriggerSignalRef "
            "on every automated action. Wrap your call in "
            "`with agent_run(client, agent=..., alert_id=..., alert_payload=...):`. "
            "For local tests, set WarlogClient(require_agent_run=False)."
        )
    return ctx


def _build_actor(
    ctx: AgentRunContext | None,
) -> AutomationActor:
    """Build the ``AutomationActor`` from the ambient context.

    When ``require_agent_run=False`` and there is no context, we use a
    synthetic ``manual`` AiAgentRef. This path exists ONLY for tests —
    it carries enough nulls that a downstream auditor immediately
    notices the row is non-production.
    """
    if ctx is not None:
        return AutomationActor(id=ctx.actor_id, agent=ctx.agent_ref)
    placeholder = AiAgentRef(
        model="test",
        model_version="test",
        system_prompt_hash="0" * 64,
        agent_run_id=str(uuid.uuid4()),
    )
    return AutomationActor(id="test.local", agent=placeholder)


def _build_trigger(ctx: AgentRunContext | None) -> TriggerSignalRef:
    if ctx is not None:
        return ctx.trigger_signal_ref
    return TriggerSignalRef(kind=TriggerSignalKind.MANUAL, source_id="", content_hash="")


def _sign_and_persist(
    client: WarlogClient,
    *,
    ctx: AgentRunContext | None,
    execution_id: str,
    action_id: ResponseActionId,
    subject: ResponseSubject,
    decision_ref: DecisionRef,
    phase: ExecutionPhase,
    outcome: ExecutionOutcome,
    idempotency_key: str,
    started_at: datetime,
    completed_at: datetime,
    error: ConnectorError | None = None,
) -> SignedRow:
    """Build, sign, persist one AuditRow. Returns the signed wrapper.

    Thread-safe : the (compute_prev → sign → append) sequence is held
    under ``client._chain_lock`` so concurrent decorator calls produce a
    well-ordered chain. The persister's own lock serializes the actual
    write.
    """
    actor = _build_actor(ctx)
    trigger = _build_trigger(ctx)
    compliance = list(ctx.compliance_scope) if ctx is not None else []

    duration_ms = max(0, int((completed_at - started_at).total_seconds() * 1000))
    row = AuditRow(
        audit_id=str(uuid.uuid4()),
        execution_id=execution_id,
        tenant_id=client.tenant_id,
        actor=actor,
        action_id=action_id,
        subject=subject,
        phase=phase,
        outcome=outcome,
        started_at=started_at,
        completed_at=completed_at,
        duration_ms=duration_ms,
        error=error,
        connector=client.connector_ref,
        idempotency_key=idempotency_key,
        decision_ref=decision_ref,
        trigger_signal_ref=trigger,
        compliance_scope=compliance,
    )

    with client._chain_lock:
        # Resolve the secret ONCE per signing op, scoped to this block.
        # When configured with a callable provider (KMS / Vault), this
        # fetches fresh bytes that get GC'd at the end of the block —
        # the secret bytes spend minimal time in process memory.
        secret = client.hmac_secret
        # Clock-drift detection runs on the row we just built (now-based
        # timestamps already on disk in `row.started_at` / `completed_at`).
        client._check_clock_drift(row.started_at)
        prev = client.persister.head_signature()
        if prev is None:
            prev = compute_genesis(client.tenant_id, secret)
        canonical = canonicalize_v1(row)
        signature = compute_signature(prev, canonical, secret)
        signed = SignedRow(
            row=row,
            prev_hash=prev,
            signature=signature,
            canonical_bytes=canonical,
        )
        client.persister.append(signed)
        # secret variable goes out of scope here ; the bytes are eligible
        # for garbage collection. For ANSSI-grade systems, the provider
        # SHOULD pull a fresh secret per call rather than cache.
    return signed


def _consult_gate(
    client: WarlogClient,
    *,
    ctx: AgentRunContext | None,
    execution_id: str,
    action_id: ResponseActionId,
    subject: ResponseSubject,
    decision_ref: DecisionRef,
    idempotency_key: str,
    function_name: str,
    bound_args: dict[str, Any],
) -> None:
    """Consult the approval gate, emit the APPROVAL row, route the outcome.

    No-op when ``client.approval_gate`` is ``None``. Otherwise :

    - builds the :class:`ApprovalRequest` from the call context
    - calls ``client.approval_gate.request(...)``
    - emits an ``APPROVAL`` audit row with the matching ``outcome``
    - raises :class:`ApprovalRequired` on ``pending``
    - raises :class:`ApprovalDenied` on ``denied``
    - returns silently on ``approved``
    """
    gate = client.approval_gate
    if gate is None:
        return

    meta = ACTION_CATALOG.get(action_id)
    default_level = meta.default_approval if meta else ApprovalLevel.MANAGER
    args_summary = {k: repr(v)[:200] for k, v in bound_args.items()}
    request = ApprovalRequest(
        action_id=action_id,
        subject=subject,
        default_approval_level=default_level,
        function_name=function_name,
        args_summary=args_summary,
        agent_run_id=ctx.agent_ref.agent_run_id if ctx else None,
        actor_id=ctx.actor_id if ctx else None,
        idempotency_key=idempotency_key,
    )

    decision = gate.request(request)

    # Defense against a common misuse — passing an async gate where a
    # sync one is expected. The decorator's gate hook is intentionally
    # synchronous (the design doctrine accepts <10ms blocking on the
    # critical path of a tool call ; production gates use in-memory /
    # SQLite / Redis backends). An ``async def request`` returns a
    # coroutine that this code path never awaits — without this guard
    # the user gets an obscure ``AttributeError: 'coroutine' object
    # has no attribute 'state'`` ; with it, the error names the bug.
    if inspect.iscoroutine(decision):
        decision.close()
        raise TypeError(
            f"ApprovalGate {type(gate).__name__}.request() returned a coroutine. "
            "The decorator's gate hook is synchronous by design (see ApprovalGate "
            "Protocol docstring). Either rewrite the gate as `def request` (sync), "
            "or block on the async logic inside a sync wrapper, or use a different "
            "approval mechanism outside the decorator."
        )

    # Defense against a malformed gate that returns an unknown state
    # value. Without this guard the next line raises a KeyError that
    # leaks our internal outcome_map ; with it, the error names the
    # actual contract violation.
    if not isinstance(decision, ApprovalDecision):
        raise TypeError(
            f"ApprovalGate {type(gate).__name__}.request() must return an "
            f"ApprovalDecision, got {type(decision).__name__}."
        )
    if decision.state not in {"approved", "denied", "pending"}:
        raise ValueError(
            f"ApprovalGate {type(gate).__name__}.request() returned "
            f"ApprovalDecision(state={decision.state!r}) but the only valid states "
            f"are 'approved', 'denied', 'pending'."
        )

    outcome_map = {
        "approved": ExecutionOutcome.SUCCESS,
        "denied": ExecutionOutcome.DENIED,
        "pending": ExecutionOutcome.PENDING_APPROVAL,
    }
    now = datetime.now(UTC)
    signed = _sign_and_persist(
        client,
        ctx=ctx,
        execution_id=execution_id,
        action_id=action_id,
        subject=subject,
        decision_ref=decision_ref,
        phase=ExecutionPhase.APPROVAL,
        outcome=outcome_map[decision.state],
        idempotency_key=idempotency_key,
        started_at=now,
        completed_at=now,
    )

    if decision.state == "denied":
        raise ApprovalDenied(
            audit_id=signed.row.audit_id,
            rationale=decision.rationale or "",
        )
    if decision.state == "pending":
        raise ApprovalRequired(
            request_id=decision.request_id or "unknown",
            audit_id=signed.row.audit_id,
            rationale=decision.rationale or "",
        )


def _categorize_exception(exc: BaseException) -> ConnectorError:
    """Map an unhandled exception to a typed ``ConnectorError``.

    Mirrors the ``AbiRunner._categorize_unknown`` policy : unknown
    exceptions are ``TRANSIENT`` (retryable) by default. A connector
    that wants finer categorization raises a ``ConnectorAbiError``
    explicitly.
    """
    return ConnectorError(
        category=FailureCategory.TRANSIENT,
        message=f"{exc.__class__.__name__}: {exc}",
        retryable=True,
    )


# ---------------------------------------------------------------------------
# The decorator
# ---------------------------------------------------------------------------


def audited(
    *,
    client: WarlogClient,
    action_id: ResponseActionId,
    subject_arg: str | None = None,
    compliance_scope: list[ComplianceScope] | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Wrap any function so each call emits two signed AuditRows.

    The decorator produces one row at the ``DRY_RUN`` phase (recording
    the intent — what the agent decided to do) and one row at the
    ``APPLY`` phase (recording the outcome — success or failure). Both
    rows share the same ``execution_id`` and ``decision_ref``, and the
    HMAC chain links them in order.

    Parameters
    ----------
    client : WarlogClient
        The client that owns the chain state and the secrets.
    action_id : ResponseActionId
        The canonical action this function performs. Must be in the
        49-action catalog. The decorator uses it to pick the action's
        family (which drives the GDPR gate) and the default scope.
    subject_arg : str, optional
        Name of the function parameter that carries the subject of the
        action (the email, host id, file path…). If omitted and the
        function has exactly one parameter, that parameter is used.
        Otherwise raises :class:`TypeError` at decoration time.
    compliance_scope : list[ComplianceScope], optional
        Compliance perimeters to override the ambient scope from
        ``agent_run``. Use this to tag tool-level scope when the
        ambient scope is broader.

    Returns
    -------
    decorator : Callable
        A decorator that preserves the wrapped function's signature
        and async-ness.

    Raises
    ------
    TraceabilityError
        If called outside an ``agent_run`` context and the client has
        ``require_agent_run=True``.
    """
    if not isinstance(action_id, ResponseActionId):
        raise TypeError(
            f"action_id must be a ResponseActionId enum member, got {type(action_id).__name__}"
        )

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        sig = inspect.signature(fn)
        params = list(sig.parameters)

        if subject_arg is not None:
            if subject_arg not in sig.parameters:
                raise TypeError(
                    f"@audited(subject_arg={subject_arg!r}) but {fn.__name__!r} has no "
                    f"such parameter. Available parameters: {params}."
                )
            chosen_subject_arg: str = subject_arg
        elif len(params) == 1:
            chosen_subject_arg = params[0]
        else:
            raise TypeError(
                f"@audited applied to {fn.__name__!r} with {len(params)} parameters but "
                f"no `subject_arg` specified. Pass subject_arg=<param_name> explicitly."
            )

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                ctx = _resolve_context(client)
                subject_value = bound.arguments.get(chosen_subject_arg)
                subject = _build_subject(action_id, subject_value, client)
                decision_ref = _synthesize_decision_ref(action_id, fn, dict(bound.arguments))
                execution_id = str(uuid.uuid4())
                idem = _deterministic_idempotency_key(
                    action_id, subject.selector_value, dict(bound.arguments)
                )

                if compliance_scope is not None and ctx is not None:
                    ctx = AgentRunContext(
                        actor_id=ctx.actor_id,
                        agent_ref=ctx.agent_ref,
                        trigger_signal_ref=ctx.trigger_signal_ref,
                        compliance_scope=list(compliance_scope),
                    )

                dry_run_started = datetime.now(UTC)
                _sign_and_persist(
                    client,
                    ctx=ctx,
                    execution_id=execution_id,
                    action_id=action_id,
                    subject=subject,
                    decision_ref=decision_ref,
                    phase=ExecutionPhase.DRY_RUN,
                    outcome=ExecutionOutcome.SUCCESS,
                    idempotency_key=idem,
                    started_at=dry_run_started,
                    completed_at=datetime.now(UTC),
                )

                # APPROVAL phase — only when a gate is configured.
                # _consult_gate raises ApprovalRequired/ApprovalDenied
                # if the action is blocked ; the wrapped fn never runs.
                _consult_gate(
                    client,
                    ctx=ctx,
                    execution_id=execution_id,
                    action_id=action_id,
                    subject=subject,
                    decision_ref=decision_ref,
                    idempotency_key=idem,
                    function_name=fn.__name__,
                    bound_args=dict(bound.arguments),
                )

                apply_started = datetime.now(UTC)
                try:
                    result = await fn(*args, **kwargs)
                except (ApprovalRequired, ApprovalDenied):
                    # Gate already emitted the APPROVAL row ; do not
                    # double-sign a FAILURE row for the same execution.
                    raise
                except BaseException as exc:
                    err = _categorize_exception(exc)
                    _sign_and_persist(
                        client,
                        ctx=ctx,
                        execution_id=execution_id,
                        action_id=action_id,
                        subject=subject,
                        decision_ref=decision_ref,
                        phase=ExecutionPhase.APPLY,
                        outcome=ExecutionOutcome.FAILURE,
                        idempotency_key=idem,
                        started_at=apply_started,
                        completed_at=datetime.now(UTC),
                        error=err,
                    )
                    raise

                _sign_and_persist(
                    client,
                    ctx=ctx,
                    execution_id=execution_id,
                    action_id=action_id,
                    subject=subject,
                    decision_ref=decision_ref,
                    phase=ExecutionPhase.APPLY,
                    outcome=ExecutionOutcome.SUCCESS,
                    idempotency_key=idem,
                    started_at=apply_started,
                    completed_at=datetime.now(UTC),
                )
                return result

            return async_wrapper

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            ctx = _resolve_context(client)
            subject_value = bound.arguments.get(chosen_subject_arg)
            subject = _build_subject(action_id, subject_value, client)
            decision_ref = _synthesize_decision_ref(action_id, fn, dict(bound.arguments))
            execution_id = str(uuid.uuid4())
            idem = _deterministic_idempotency_key(
                action_id, subject.selector_value, dict(bound.arguments)
            )

            if compliance_scope is not None and ctx is not None:
                ctx = AgentRunContext(
                    actor_id=ctx.actor_id,
                    agent_ref=ctx.agent_ref,
                    trigger_signal_ref=ctx.trigger_signal_ref,
                    compliance_scope=list(compliance_scope),
                )

            dry_run_started = datetime.now(UTC)
            _sign_and_persist(
                client,
                ctx=ctx,
                execution_id=execution_id,
                action_id=action_id,
                subject=subject,
                decision_ref=decision_ref,
                phase=ExecutionPhase.DRY_RUN,
                outcome=ExecutionOutcome.SUCCESS,
                idempotency_key=idem,
                started_at=dry_run_started,
                completed_at=datetime.now(UTC),
            )

            # APPROVAL phase — only when a gate is configured.
            # _consult_gate raises ApprovalRequired/ApprovalDenied if
            # the action is blocked ; the wrapped fn never runs.
            _consult_gate(
                client,
                ctx=ctx,
                execution_id=execution_id,
                action_id=action_id,
                subject=subject,
                decision_ref=decision_ref,
                idempotency_key=idem,
                function_name=fn.__name__,
                bound_args=dict(bound.arguments),
            )

            apply_started = datetime.now(UTC)
            try:
                result = fn(*args, **kwargs)
            except (ApprovalRequired, ApprovalDenied):
                # Gate already emitted the APPROVAL row ; do not
                # double-sign a FAILURE row for the same execution.
                raise
            except BaseException as exc:
                err = _categorize_exception(exc)
                _sign_and_persist(
                    client,
                    ctx=ctx,
                    execution_id=execution_id,
                    action_id=action_id,
                    subject=subject,
                    decision_ref=decision_ref,
                    phase=ExecutionPhase.APPLY,
                    outcome=ExecutionOutcome.FAILURE,
                    idempotency_key=idem,
                    started_at=apply_started,
                    completed_at=datetime.now(UTC),
                    error=err,
                )
                raise

            _sign_and_persist(
                client,
                ctx=ctx,
                execution_id=execution_id,
                action_id=action_id,
                subject=subject,
                decision_ref=decision_ref,
                phase=ExecutionPhase.APPLY,
                outcome=ExecutionOutcome.SUCCESS,
                idempotency_key=idem,
                started_at=apply_started,
                completed_at=datetime.now(UTC),
            )
            return result

        return sync_wrapper

    return decorator


# ---------------------------------------------------------------------------
# Verification helper
# ---------------------------------------------------------------------------


def verify_chain(client: WarlogClient, rows: list[SignedRow]) -> None:
    """Verify a chain of signed rows produced by this client.

    Raises :class:`~warlog_spec.audit_chain.AuditChainBroken` on the
    first row whose signature does not recompute. Useful for tests and
    for periodic background verification of a JSONL persister's
    contents.

    The secret is resolved ONCE at the start of verification (not
    per-row) so a callable provider that hits an HSM doesn't pay N
    round-trips for an N-row chain. For long-running verification of
    a rotating-secret deployment, walk rows in batches with the secret
    that was active during their write window.
    """
    from warlog_spec.audit_chain import AuditChainBroken

    secret = client.hmac_secret
    expected_prev = compute_genesis(client.tenant_id, secret)
    for signed in rows:
        if signed.prev_hash != expected_prev:
            raise AuditChainBroken(f"prev_hash mismatch at audit_id={signed.row.audit_id}")
        recomputed = compute_signature(signed.prev_hash, signed.canonical_bytes, secret)
        if recomputed != signed.signature:
            raise AuditChainBroken(f"signature mismatch at audit_id={signed.row.audit_id}")
        expected_prev = signed.signature


__all__ = [
    "AgentRunContext",
    "ApprovalDecision",
    "ApprovalDenied",
    "ApprovalGate",
    "ApprovalRequest",
    "ApprovalRequired",
    "AuditPersister",
    "AutoApproveGate",
    "InMemoryPersister",
    "JsonlFilePersister",
    "SignedRow",
    "TraceabilityError",
    "WarlogClient",
    "WarlogConfigError",
    "agent_run",
    "audited",
    "propagate_warlog_context",
    "verify_chain",
]
