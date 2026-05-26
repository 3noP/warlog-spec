"""Tests for ``warlog_spec.integrate`` — the Pattern A audit decorator."""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
import warnings
from datetime import UTC, datetime
from pathlib import Path

import pytest

from warlog_spec import (
    AiAgentRef,
    ComplianceScope,
    ExecutionOutcome,
    ExecutionPhase,
    FailureCategory,
    ResponseActionId,
    SelectorRepresentation,
)
from warlog_spec.audit_chain import AuditChainBroken
from warlog_spec.integrate import (
    ApprovalDecision,
    ApprovalDenied,
    ApprovalRequest,
    ApprovalRequired,
    AutoApproveGate,
    InMemoryPersister,
    JsonlFilePersister,
    TraceabilityError,
    WarlogClient,
    WarlogConfigError,
    agent_run,
    audited,
    verify_chain,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_AGENT = AiAgentRef(
    model="gpt-4o",
    model_version="2026-04-01",
    system_prompt_hash="a" * 64,
    agent_run_id="test-run-001",
)


def _make_client(*, require_agent_run: bool = True, persister=None, approval_gate=None) -> WarlogClient:
    return WarlogClient(
        tenant_id="acme-test",
        hmac_secret=b"test-hmac-secret-do-not-ship",
        pii_salt=b"test-pii-salt-do-not-ship",
        persister=persister or InMemoryPersister(),
        selector_key_id="tenant:acme-test:salt:v1",
        require_agent_run=require_agent_run,
        approval_gate=approval_gate,
    )


def _run_ctx(client: WarlogClient, **overrides) -> agent_run:
    return agent_run(
        client,
        agent=_AGENT,
        actor_id="playbook.test",
        alert_id="alert-test-001",
        alert_payload=b'{"alert":"test"}',
        compliance_scope=[ComplianceScope.GDPR],
        **overrides,
    )


# ---------------------------------------------------------------------------
# WarlogClient + env loading
# ---------------------------------------------------------------------------


def test_warlog_client_rejects_empty_tenant() -> None:
    with pytest.raises(WarlogConfigError, match="tenant_id"):
        WarlogClient(
            tenant_id="",
            hmac_secret=b"x",
            pii_salt=b"y",
            persister=InMemoryPersister(),
        )


def test_warlog_client_rejects_empty_secret() -> None:
    with pytest.raises(WarlogConfigError, match="hmac_secret"):
        WarlogClient(
            tenant_id="t",
            hmac_secret=b"",
            pii_salt=b"y",
            persister=InMemoryPersister(),
        )


def test_from_env_fails_loudly_on_missing_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WARLOG_HMAC_SECRET", raising=False)
    monkeypatch.setenv("WARLOG_TENANT_ID", "t")
    monkeypatch.setenv("WARLOG_PII_SALT", "s")
    with pytest.raises(WarlogConfigError, match="WARLOG_HMAC_SECRET"):
        WarlogClient.from_env()


def test_from_env_fails_loudly_on_empty_string(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WARLOG_TENANT_ID", "t")
    monkeypatch.setenv("WARLOG_HMAC_SECRET", "")
    monkeypatch.setenv("WARLOG_PII_SALT", "s")
    with pytest.raises(WarlogConfigError, match="WARLOG_HMAC_SECRET"):
        WarlogClient.from_env()


def test_from_env_constructs_when_all_set(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WARLOG_TENANT_ID", "acme")
    monkeypatch.setenv("WARLOG_HMAC_SECRET", "secret")
    monkeypatch.setenv("WARLOG_PII_SALT", "salt")
    monkeypatch.setenv("WARLOG_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    client = WarlogClient.from_env()
    assert client.tenant_id == "acme"
    assert isinstance(client.persister, JsonlFilePersister)


# ---------------------------------------------------------------------------
# agent_run binds and unbinds correctly
# ---------------------------------------------------------------------------


def test_agent_run_binds_and_unbinds_sync() -> None:
    from warlog_spec.integrate import _CURRENT_CONTEXT

    client = _make_client()
    assert _CURRENT_CONTEXT.get() is None
    with _run_ctx(client):
        ctx = _CURRENT_CONTEXT.get()
        assert ctx is not None
        assert ctx.agent_ref.agent_run_id == "test-run-001"
    assert _CURRENT_CONTEXT.get() is None


def test_agent_run_async_binds_and_unbinds() -> None:
    from warlog_spec.integrate import _CURRENT_CONTEXT

    async def inner() -> None:
        client = _make_client()
        async with _run_ctx(client):
            assert _CURRENT_CONTEXT.get() is not None
        assert _CURRENT_CONTEXT.get() is None

    asyncio.run(inner())


# ---------------------------------------------------------------------------
# Decorator basics — sync
# ---------------------------------------------------------------------------


def test_sync_audited_emits_two_rows() -> None:
    client = _make_client()

    @audited(
        client=client,
        action_id=ResponseActionId.USER_REVOKE_TOKENS,
        subject_arg="user_email",
        compliance_scope=[ComplianceScope.GDPR],
    )
    def revoke(user_email: str) -> dict:
        return {"revoked": True, "user": user_email}

    with _run_ctx(client):
        out = revoke("alice@acme.example")
    assert out == {"revoked": True, "user": "alice@acme.example"}

    rows = client.persister.rows()
    assert len(rows) == 2
    assert rows[0].row.phase is ExecutionPhase.DRY_RUN
    assert rows[0].row.outcome is ExecutionOutcome.SUCCESS
    assert rows[1].row.phase is ExecutionPhase.APPLY
    assert rows[1].row.outcome is ExecutionOutcome.SUCCESS
    # Same execution_id across both rows.
    assert rows[0].row.execution_id == rows[1].row.execution_id


def test_sync_audited_failure_emits_failure_row_and_reraises() -> None:
    client = _make_client()

    @audited(
        client=client,
        action_id=ResponseActionId.USER_REVOKE_TOKENS,
        subject_arg="user_email",
    )
    def broken(user_email: str) -> dict:
        raise RuntimeError("boom")

    with _run_ctx(client), pytest.raises(RuntimeError, match="boom"):
        broken("alice@acme.example")

    rows = client.persister.rows()
    assert len(rows) == 2
    assert rows[0].row.outcome is ExecutionOutcome.SUCCESS  # dry_run
    assert rows[1].row.outcome is ExecutionOutcome.FAILURE  # apply failed
    assert rows[1].row.error is not None
    assert rows[1].row.error.category is FailureCategory.TRANSIENT
    assert "boom" in rows[1].row.error.message


# ---------------------------------------------------------------------------
# Decorator basics — async
# ---------------------------------------------------------------------------


def test_async_audited_emits_two_rows() -> None:
    client = _make_client()

    @audited(
        client=client,
        action_id=ResponseActionId.USER_REVOKE_TOKENS,
        subject_arg="user_email",
    )
    async def revoke(user_email: str) -> dict:
        await asyncio.sleep(0)
        return {"revoked": True}

    async def run() -> dict:
        async with _run_ctx(client):
            return await revoke("alice@acme.example")

    out = asyncio.run(run())
    assert out["revoked"] is True
    rows = client.persister.rows()
    assert len(rows) == 2
    assert rows[1].row.outcome is ExecutionOutcome.SUCCESS


def test_async_audited_propagates_exception() -> None:
    client = _make_client()

    @audited(
        client=client,
        action_id=ResponseActionId.USER_REVOKE_TOKENS,
        subject_arg="user_email",
    )
    async def broken(user_email: str) -> dict:
        raise ValueError("nope")

    async def run() -> None:
        async with _run_ctx(client):
            await broken("a@b.com")

    with pytest.raises(ValueError, match="nope"):
        asyncio.run(run())

    rows = client.persister.rows()
    assert rows[-1].row.outcome is ExecutionOutcome.FAILURE


# ---------------------------------------------------------------------------
# GDPR pseudonymization gate
# ---------------------------------------------------------------------------


def test_pii_subject_is_pseudonymized() -> None:
    client = _make_client()

    @audited(
        client=client,
        action_id=ResponseActionId.USER_REVOKE_TOKENS,
        subject_arg="user_email",
    )
    def revoke(user_email: str) -> None:
        return None

    with _run_ctx(client):
        revoke("alice@acme.example")

    rows = client.persister.rows()
    subject = rows[0].row.subject
    assert subject.selector_representation is SelectorRepresentation.SHA256_SALTED
    # Recompute the expected hash and compare.
    expected = hashlib.sha256(b"test-pii-salt-do-not-ship" + b"alice@acme.example").hexdigest()
    assert subject.selector_value == expected
    assert subject.selector_key_id == "tenant:acme-test:salt:v1"


def test_non_pii_subject_stays_raw() -> None:
    client = _make_client()

    @audited(
        client=client,
        action_id=ResponseActionId.HOST_ISOLATE,
        subject_arg="agent_id",
    )
    def isolate(agent_id: str) -> None:
        return None

    with _run_ctx(client):
        isolate("agent-xyz-007")

    rows = client.persister.rows()
    subject = rows[0].row.subject
    assert subject.selector_representation is SelectorRepresentation.RAW
    assert subject.selector_value == "agent-xyz-007"


# ---------------------------------------------------------------------------
# Traceability invariant
# ---------------------------------------------------------------------------


def test_audited_without_agent_run_raises_strict() -> None:
    client = _make_client()  # require_agent_run=True by default

    @audited(
        client=client,
        action_id=ResponseActionId.USER_REVOKE_TOKENS,
        subject_arg="user_email",
    )
    def revoke(user_email: str) -> None:
        return None

    with pytest.raises(TraceabilityError, match="agent_run"):
        revoke("alice@acme.example")
    assert client.persister.rows() == []


def test_audited_without_agent_run_passes_when_lax() -> None:
    client = _make_client(require_agent_run=False)

    @audited(
        client=client,
        action_id=ResponseActionId.USER_REVOKE_TOKENS,
        subject_arg="user_email",
    )
    def revoke(user_email: str) -> None:
        return None

    revoke("alice@acme.example")
    rows = client.persister.rows()
    assert len(rows) == 2


# ---------------------------------------------------------------------------
# Subject inference (single-arg shortcut)
# ---------------------------------------------------------------------------


def test_single_arg_function_infers_subject() -> None:
    client = _make_client()

    @audited(client=client, action_id=ResponseActionId.HOST_ISOLATE)
    def isolate(agent_id: str) -> None:
        return None

    with _run_ctx(client):
        isolate("agent-007")
    rows = client.persister.rows()
    assert rows[0].row.subject.selector_value == "agent-007"


def test_multi_arg_function_requires_subject_arg() -> None:
    client = _make_client()

    with pytest.raises(TypeError, match="subject_arg"):
        @audited(client=client, action_id=ResponseActionId.HOST_ISOLATE)
        def isolate(agent_id: str, reason: str) -> None:  # noqa: F841
            return None


def test_bad_subject_arg_raises_typeerror() -> None:
    client = _make_client()

    with pytest.raises(TypeError, match="no such parameter"):
        @audited(
            client=client,
            action_id=ResponseActionId.HOST_ISOLATE,
            subject_arg="nonexistent",
        )
        def isolate(agent_id: str) -> None:  # noqa: F841
            return None


# ---------------------------------------------------------------------------
# Determinism — decision_ref + idempotency_key are reproducible
# ---------------------------------------------------------------------------


def test_decision_ref_content_hash_is_deterministic() -> None:
    client = _make_client()

    @audited(
        client=client,
        action_id=ResponseActionId.USER_REVOKE_TOKENS,
        subject_arg="user_email",
    )
    def revoke(user_email: str) -> None:
        """VPN anomaly detected — revoke tokens."""
        return None

    with _run_ctx(client):
        revoke("alice@acme.example")
        revoke("alice@acme.example")

    rows = client.persister.rows()
    # 4 rows : DRY_RUN+APPLY, DRY_RUN+APPLY
    assert len(rows) == 4
    # Same call args produce the same decision_ref content_hash.
    assert rows[0].row.decision_ref.content_hash == rows[2].row.decision_ref.content_hash
    # And the same idempotency_key (vendor-side dedup).
    assert rows[0].row.idempotency_key == rows[2].row.idempotency_key
    # But each call has its own execution_id (independent attempt).
    assert rows[0].row.execution_id != rows[2].row.execution_id


# ---------------------------------------------------------------------------
# Chain integrity
# ---------------------------------------------------------------------------


def test_chain_verifies_end_to_end() -> None:
    client = _make_client()

    @audited(
        client=client,
        action_id=ResponseActionId.USER_REVOKE_TOKENS,
        subject_arg="user_email",
    )
    def revoke(user_email: str) -> None:
        return None

    with _run_ctx(client):
        revoke("alice@acme.example")
        revoke("bob@acme.example")

    rows = client.persister.rows()
    assert len(rows) == 4
    # No exception means every HMAC checks out.
    verify_chain(client, rows)


def test_chain_break_detected_after_tamper() -> None:
    client = _make_client()

    @audited(
        client=client,
        action_id=ResponseActionId.USER_REVOKE_TOKENS,
        subject_arg="user_email",
    )
    def revoke(user_email: str) -> None:
        return None

    with _run_ctx(client):
        revoke("alice@acme.example")

    rows = client.persister.rows()
    # Tamper a byte in the second row's canonical_bytes.
    from warlog_spec.integrate import SignedRow

    target = rows[1]
    tampered = SignedRow(
        row=target.row,
        prev_hash=target.prev_hash,
        signature=target.signature,
        canonical_bytes=target.canonical_bytes[:-1] + bytes([target.canonical_bytes[-1] ^ 0x01]),
        canonicalization_format=target.canonicalization_format,
    )
    rows[1] = tampered

    with pytest.raises(AuditChainBroken):
        verify_chain(client, rows)


# ---------------------------------------------------------------------------
# JsonlFilePersister persists across "process restarts"
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Approval gate — opt-in shield mode
# ---------------------------------------------------------------------------


class _PendingGate:
    """Gate that always returns ``pending`` — exercises the suspension path."""

    def __init__(self, request_id: str = "appr-test-001") -> None:
        self._req_id = request_id
        self.calls: list[ApprovalRequest] = []

    def request(self, req: ApprovalRequest) -> ApprovalDecision:
        self.calls.append(req)
        return ApprovalDecision(
            state="pending",
            rationale="awaiting senior triage",
            request_id=self._req_id,
        )


class _DenyGate:
    """Gate that always returns ``denied``."""

    def __init__(self, rationale: str = "policy refusal") -> None:
        self._rationale = rationale
        self.calls: list[ApprovalRequest] = []

    def request(self, req: ApprovalRequest) -> ApprovalDecision:
        self.calls.append(req)
        return ApprovalDecision(state="denied", rationale=self._rationale)


def test_no_gate_skips_approval_phase_entirely() -> None:
    """Default config emits dry_run + apply, no APPROVAL row at all."""
    client = _make_client()  # approval_gate=None by default

    @audited(
        client=client,
        action_id=ResponseActionId.USER_REVOKE_TOKENS,
        subject_arg="user_email",
    )
    def revoke(user_email: str) -> dict:
        return {"ok": True}

    with _run_ctx(client):
        revoke("alice@acme.example")

    rows = client.persister.rows()
    phases = [r.row.phase for r in rows]
    assert phases == [ExecutionPhase.DRY_RUN, ExecutionPhase.APPLY]


def test_auto_approve_gate_emits_approval_row() -> None:
    """Configured gate that auto-approves → 3 rows : dry_run, approval, apply."""
    client = _make_client(approval_gate=AutoApproveGate())

    @audited(
        client=client,
        action_id=ResponseActionId.USER_REVOKE_TOKENS,
        subject_arg="user_email",
    )
    def revoke(user_email: str) -> dict:
        return {"ok": True}

    with _run_ctx(client):
        revoke("alice@acme.example")

    rows = client.persister.rows()
    phases = [(r.row.phase, r.row.outcome) for r in rows]
    assert phases == [
        (ExecutionPhase.DRY_RUN, ExecutionOutcome.SUCCESS),
        (ExecutionPhase.APPROVAL, ExecutionOutcome.SUCCESS),
        (ExecutionPhase.APPLY, ExecutionOutcome.SUCCESS),
    ]


def test_pending_gate_raises_and_blocks_apply() -> None:
    """``pending`` gate → ApprovalRequired raised, target NEVER called, no APPLY row."""
    gate = _PendingGate(request_id="appr-pending-007")
    client = _make_client(approval_gate=gate)
    called = {"n": 0}

    @audited(
        client=client,
        action_id=ResponseActionId.USER_REVOKE_TOKENS,
        subject_arg="user_email",
    )
    def revoke(user_email: str) -> dict:
        called["n"] += 1
        return {"ok": True}

    with _run_ctx(client), pytest.raises(ApprovalRequired) as exc_info:
        revoke("alice@acme.example")

    assert called["n"] == 0, "target function must NOT be called when approval is pending"
    assert exc_info.value.request_id == "appr-pending-007"
    assert "senior triage" in exc_info.value.rationale

    rows = client.persister.rows()
    phases = [(r.row.phase, r.row.outcome) for r in rows]
    assert phases == [
        (ExecutionPhase.DRY_RUN, ExecutionOutcome.SUCCESS),
        (ExecutionPhase.APPROVAL, ExecutionOutcome.PENDING_APPROVAL),
    ]
    # Exception carries the audit_id of the APPROVAL row.
    assert exc_info.value.audit_id == rows[1].row.audit_id
    # Gate received the expected request shape.
    assert len(gate.calls) == 1
    req = gate.calls[0]
    assert req.action_id == ResponseActionId.USER_REVOKE_TOKENS
    assert req.function_name == "revoke"
    assert req.actor_id == "playbook.test"


def test_denied_gate_raises_and_blocks_apply() -> None:
    """``denied`` gate → ApprovalDenied raised, target NEVER called."""
    gate = _DenyGate(rationale="agent reasoning under-supported")
    client = _make_client(approval_gate=gate)
    called = {"n": 0}

    @audited(
        client=client,
        action_id=ResponseActionId.USER_REVOKE_TOKENS,
        subject_arg="user_email",
    )
    def revoke(user_email: str) -> dict:
        called["n"] += 1
        return {"ok": True}

    with _run_ctx(client), pytest.raises(ApprovalDenied) as exc_info:
        revoke("alice@acme.example")

    assert called["n"] == 0
    assert "under-supported" in exc_info.value.rationale

    rows = client.persister.rows()
    phases = [(r.row.phase, r.row.outcome) for r in rows]
    assert phases == [
        (ExecutionPhase.DRY_RUN, ExecutionOutcome.SUCCESS),
        (ExecutionPhase.APPROVAL, ExecutionOutcome.DENIED),
    ]
    assert exc_info.value.audit_id == rows[1].row.audit_id


def test_async_pending_gate_blocks() -> None:
    """The async wrapper honors the gate path the same way the sync wrapper does."""
    gate = _PendingGate()
    client = _make_client(approval_gate=gate)
    called = {"n": 0}

    @audited(
        client=client,
        action_id=ResponseActionId.USER_REVOKE_TOKENS,
        subject_arg="user_email",
    )
    async def revoke(user_email: str) -> dict:
        called["n"] += 1
        return {"ok": True}

    async def run() -> None:
        async with _run_ctx(client):
            await revoke("alice@acme.example")

    with pytest.raises(ApprovalRequired):
        asyncio.run(run())

    assert called["n"] == 0
    rows = client.persister.rows()
    assert rows[-1].row.outcome is ExecutionOutcome.PENDING_APPROVAL


def test_chain_integrity_holds_across_approval_paths() -> None:
    """The chain links cleanly across dry_run + approval + apply rows."""
    client = _make_client(approval_gate=AutoApproveGate())

    @audited(
        client=client,
        action_id=ResponseActionId.USER_REVOKE_TOKENS,
        subject_arg="user_email",
    )
    def revoke(user_email: str) -> None:
        return None

    with _run_ctx(client):
        revoke("alice@acme.example")
        revoke("bob@acme.example")

    rows = client.persister.rows()
    assert len(rows) == 6  # 3 phases × 2 calls
    verify_chain(client, rows)


# ---------------------------------------------------------------------------
# Crash-test defenses — thread contextvars, non-serializable args, async gate
# ---------------------------------------------------------------------------


def test_raw_threadpool_loses_context_by_design() -> None:
    """Without propagate_warlog_context, a raw ThreadPoolExecutor breaks tracing.

    This is the symptom users hit when frameworks (LangChain, custom
    dispatchers) submit audited tools to a thread pool : the worker
    thread starts with a fresh ContextVar state, the agent_run binding
    is lost, and the decorator raises TraceabilityError.

    Pinning this behavior here so we notice if Python ever changes the
    contextvar propagation semantics.
    """
    from concurrent.futures import ThreadPoolExecutor

    client = _make_client()

    @audited(
        client=client,
        action_id=ResponseActionId.USER_REVOKE_TOKENS,
        subject_arg="user_email",
    )
    def revoke(user_email: str) -> None:
        return None

    with _run_ctx(client), ThreadPoolExecutor(max_workers=1) as pool, pytest.raises(
        TraceabilityError, match="agent_run"
    ):
        pool.submit(revoke, "alice@acme.example").result()


def test_propagate_warlog_context_restores_context_across_threads() -> None:
    """``propagate_warlog_context`` is the documented fix for raw thread pools."""
    from concurrent.futures import ThreadPoolExecutor

    from warlog_spec.integrate import propagate_warlog_context

    client = _make_client()

    @audited(
        client=client,
        action_id=ResponseActionId.USER_REVOKE_TOKENS,
        subject_arg="user_email",
    )
    def revoke(user_email: str) -> dict:
        return {"ok": True}

    with _run_ctx(client), ThreadPoolExecutor(max_workers=1) as pool:
        wrapped = propagate_warlog_context(revoke)
        result = pool.submit(wrapped, "alice@acme.example").result()

    assert result == {"ok": True}
    rows = client.persister.rows()
    assert len(rows) == 2  # dry_run + apply, both emitted from inside the worker thread
    assert rows[-1].row.outcome is ExecutionOutcome.SUCCESS


def test_asyncio_to_thread_propagates_context_automatically() -> None:
    """No helper needed when the agent uses ``asyncio.to_thread`` — Python
    already snapshots the context. Pinning this to avoid users adding
    superfluous wrappers."""

    client = _make_client()

    @audited(
        client=client,
        action_id=ResponseActionId.USER_REVOKE_TOKENS,
        subject_arg="user_email",
    )
    def revoke(user_email: str) -> dict:
        return {"ok": True}

    async def run() -> dict:
        async with _run_ctx(client):
            return await asyncio.to_thread(revoke, "alice@acme.example")

    result = asyncio.run(run())
    assert result == {"ok": True}
    assert len(client.persister.rows()) == 2


def test_non_serializable_args_do_not_crash_the_decorator() -> None:
    """Arbitrary objects (Path, dataframes, API clients, …) must NOT crash
    the synth decision_ref or the idempotency_key computation."""

    class WeirdObj:
        def __init__(self) -> None:
            self.x = 42

        def __repr__(self) -> str:
            return f"WeirdObj(x={self.x})"

    client = _make_client()

    @audited(
        client=client,
        action_id=ResponseActionId.USER_REVOKE_TOKENS,
        subject_arg="user_email",
    )
    def revoke(user_email: str, ctx_obj: object) -> dict:
        return {"ok": True}

    with _run_ctx(client):
        result = revoke("alice@acme.example", WeirdObj())

    assert result == {"ok": True}
    rows = client.persister.rows()
    assert len(rows) == 2
    # decision_ref content_hash must still be deterministic for the same
    # weird object (because repr() is stable for same-state instances).
    assert rows[0].row.decision_ref.content_hash == rows[1].row.decision_ref.content_hash


def test_async_gate_misuse_raises_typed_error() -> None:
    """Passing an async gate (``async def request``) to a sync gate slot
    is a misuse. The decorator detects the coroutine return and raises
    a clear TypeError instead of an obscure AttributeError downstream."""

    class AsyncGateMisuse:
        async def request(self, req: ApprovalRequest) -> ApprovalDecision:
            return ApprovalDecision(state="approved")

    client = _make_client(approval_gate=AsyncGateMisuse())  # type: ignore[arg-type]

    @audited(
        client=client,
        action_id=ResponseActionId.USER_REVOKE_TOKENS,
        subject_arg="user_email",
    )
    def revoke(user_email: str) -> None:
        return None

    with _run_ctx(client), pytest.raises(TypeError, match="returned a coroutine"):
        revoke("alice@acme.example")


def test_multi_tenant_persister_sharing_warns() -> None:
    """Two clients with different tenant_ids must not share a persister.

    Sharing a persister across tenants interleaves their HMAC chains in
    storage : per-tenant ``verify_chain`` will then fail because rows
    are signed with different secrets. We warn loudly on construction
    so operators notice during smoke tests, not in production.
    """
    import warnings

    shared = InMemoryPersister()

    # First tenant claims it silently.
    WarlogClient(
        tenant_id="acme",
        hmac_secret=b"sa",
        pii_salt=b"x",
        persister=shared,
    )

    # Second tenant should warn.
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        WarlogClient(
            tenant_id="beta",
            hmac_secret=b"sb",
            pii_salt=b"y",
            persister=shared,
        )
    assert len(caught) == 1
    assert issubclass(caught[0].category, RuntimeWarning)
    assert "tenant_id='beta'" in str(caught[0].message)
    assert "interleaves HMAC chains" in str(caught[0].message)


def test_same_tenant_sharing_persister_is_silent() -> None:
    """Same tenant re-using its own persister (e.g. on process reload) is OK."""
    import warnings

    shared = InMemoryPersister()
    WarlogClient(tenant_id="acme", hmac_secret=b"s", pii_salt=b"x", persister=shared)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        WarlogClient(tenant_id="acme", hmac_secret=b"s", pii_salt=b"x", persister=shared)
    assert not caught


def test_malformed_gate_decision_raises_clear_error() -> None:
    """A gate returning an ApprovalDecision with an unknown state value
    must surface a ValueError that names the bug, not a KeyError on
    our internal outcome_map."""

    class WrongStateGate:
        def request(self, req: ApprovalRequest) -> ApprovalDecision:
            return ApprovalDecision(state="maybe")  # type: ignore[arg-type]

    client = _make_client(approval_gate=WrongStateGate())

    @audited(
        client=client,
        action_id=ResponseActionId.USER_REVOKE_TOKENS,
        subject_arg="user_email",
    )
    def revoke(user_email: str) -> None:
        return None

    with _run_ctx(client), pytest.raises(ValueError, match="state='maybe'"):
        revoke("alice@acme.example")


def test_non_decision_gate_return_raises_typeerror() -> None:
    """A gate that doesn't even return an ApprovalDecision (e.g. returns
    a tuple, a None, a string) must raise TypeError that names the
    actual return type, not crash later on attribute access."""

    class WrongReturnGate:
        def request(self, req: ApprovalRequest) -> ApprovalDecision:
            return "approved"  # type: ignore[return-value]

    client = _make_client(approval_gate=WrongReturnGate())

    @audited(
        client=client,
        action_id=ResponseActionId.USER_REVOKE_TOKENS,
        subject_arg="user_email",
    )
    def revoke(user_email: str) -> None:
        return None

    with _run_ctx(client), pytest.raises(TypeError, match="must return an ApprovalDecision"):
        revoke("alice@acme.example")


def test_multi_thread_agent_run_isolation() -> None:
    """Two threads each in their own agent_run see DIFFERENT contexts.

    Pins the doctrine that contextvars isolate per-thread by default.
    Each thread's audited rows carry its own actor / trigger.
    """
    import threading

    client = _make_client()

    @audited(
        client=client,
        action_id=ResponseActionId.HOST_ISOLATE,
        subject_arg="agent_id",
    )
    def isolate(agent_id: str) -> None:
        return None

    barrier = threading.Barrier(2)

    def worker(actor_id: str, agent_id: str) -> None:
        agent = AiAgentRef(
            model="m",
            model_version="v",
            system_prompt_hash="a" * 64,
            agent_run_id=actor_id,
        )
        with agent_run(
            client,
            agent=agent,
            actor_id=actor_id,
            alert_id=actor_id,
            alert_payload=actor_id.encode(),
            compliance_scope=[ComplianceScope.GDPR],
        ):
            barrier.wait()  # ensure both threads are inside their context
            isolate(agent_id)

    t1 = threading.Thread(target=worker, args=("playbook.A", "host-a"))
    t2 = threading.Thread(target=worker, args=("playbook.B", "host-b"))
    t1.start(); t2.start()
    t1.join(); t2.join()

    rows = client.persister.rows()
    assert len(rows) == 4  # 2 phases × 2 threads
    # Each row's actor_id must match its thread's binding (no cross-contamination).
    actor_ids = {r.row.actor.id for r in rows}
    assert actor_ids == {"playbook.A", "playbook.B"}
    # Chain still verifies — _chain_lock serialized the writes.
    verify_chain(client, rows)


def test_nested_agent_run_restores_outer_context() -> None:
    """Nested agent_run blocks must restore the outer context on inner exit
    (Token-based ContextVar semantics). Without this, an audited tool
    called after a nested run-then-exit would lose its actor."""

    client = _make_client()

    @audited(
        client=client,
        action_id=ResponseActionId.HOST_ISOLATE,
        subject_arg="agent_id",
    )
    def isolate(agent_id: str) -> None:
        return None

    agent_outer = AiAgentRef(
        model="m",
        model_version="v",
        system_prompt_hash="a" * 64,
        agent_run_id="outer-run",
    )
    agent_inner = AiAgentRef(
        model="m",
        model_version="v",
        system_prompt_hash="b" * 64,
        agent_run_id="inner-run",
    )

    with agent_run(
        client, agent=agent_outer, actor_id="outer",
        alert_id="a-out", alert_payload=b"out",
    ):
        # In outer context — outer agent_run_id should be on the row.
        isolate("host-x")
        with agent_run(
            client, agent=agent_inner, actor_id="inner",
            alert_id="a-in", alert_payload=b"in",
        ):
            isolate("host-y")
        # Inner exited — outer context is back.
        isolate("host-z")

    rows = client.persister.rows()
    # 3 calls × 2 phases (dry_run + apply, no gate) = 6 rows
    assert len(rows) == 6
    # Group by execution_id to find which call each row belongs to.
    by_subject = {r.row.subject.selector_value: r for r in rows if r.row.phase is ExecutionPhase.APPLY}
    assert by_subject["host-x"].row.actor.agent.agent_run_id == "outer-run"
    assert by_subject["host-y"].row.actor.agent.agent_run_id == "inner-run"
    assert by_subject["host-z"].row.actor.agent.agent_run_id == "outer-run"


def test_recursive_audited_tool_keeps_context() -> None:
    """A tool that calls another @audited tool from inside its own body
    must see the same agent_run context (no isolation between
    nested decorator invocations)."""

    client = _make_client()

    @audited(client=client, action_id=ResponseActionId.HOST_COLLECT_ARTIFACTS, subject_arg="agent_id")
    def collect(agent_id: str) -> dict:
        return {"artifact": "memdump"}

    @audited(client=client, action_id=ResponseActionId.HOST_ISOLATE, subject_arg="agent_id")
    def isolate_then_collect(agent_id: str) -> dict:
        # Recursive audited call — must inherit the same context.
        return collect(agent_id)

    with _run_ctx(client):
        result = isolate_then_collect("host-007")

    assert result == {"artifact": "memdump"}
    rows = client.persister.rows()
    # 2 phases (dry_run + apply) for the outer isolate
    # + 2 phases for the inner collect = 4 rows
    assert len(rows) == 4
    action_ids = [r.row.action_id for r in rows]
    # Order : outer dry_run, inner dry_run, inner apply, outer apply
    # (the inner call runs entirely inside the outer's apply phase).
    assert ResponseActionId.HOST_ISOLATE in action_ids
    assert ResponseActionId.HOST_COLLECT_ARTIFACTS in action_ids


def test_hmac_secret_can_be_a_callable_provider() -> None:
    """A callable hmac_secret is invoked per signing op so a KMS-backed
    provider doesn't keep the secret pinned in process memory."""
    fetch_count = {"n": 0}

    def fetch_secret() -> bytes:
        fetch_count["n"] += 1
        return b"secret-from-vault"

    client = WarlogClient(
        tenant_id="acme-test",
        hmac_secret=fetch_secret,
        pii_salt=b"x",
        persister=InMemoryPersister(),
        selector_key_id="tenant:acme-test:salt:v1",
        require_agent_run=True,
    )
    # Construction fetches once to validate non-empty bytes.
    assert fetch_count["n"] == 1

    @audited(
        client=client,
        action_id=ResponseActionId.HOST_ISOLATE,
        subject_arg="agent_id",
    )
    def isolate(agent_id: str) -> None:
        return None

    with _run_ctx(client):
        isolate("host-a")
        isolate("host-b")

    rows = client.persister.rows()
    assert len(rows) == 4  # 2 calls × 2 phases
    # Each row signing fetches the secret once : 1 (construct) + 4 (signing).
    assert fetch_count["n"] == 5
    verify_chain(client, rows)


def test_hmac_secret_callable_returning_empty_bytes_fails_loud() -> None:
    """Provider must NEVER return empty bytes — a chain signed with the
    well-known fallback would be forgeable. Fail at construction."""
    def fetch_empty() -> bytes:
        return b""

    with pytest.raises(WarlogConfigError, match="empty"):
        WarlogClient(
            tenant_id="acme",
            hmac_secret=fetch_empty,
            pii_salt=b"x",
            persister=InMemoryPersister(),
        )


def test_hmac_secret_must_be_bytes_or_callable() -> None:
    """A string / int / None as the secret is a config error."""
    with pytest.raises(WarlogConfigError, match="bytes or Callable"):
        WarlogClient(
            tenant_id="acme",
            hmac_secret="not-bytes",  # type: ignore[arg-type]
            pii_salt=b"x",
            persister=InMemoryPersister(),
        )


def test_clock_drift_backwards_emits_warning() -> None:
    """Wall clock going backwards between rows fires a clear warning."""
    client = _make_client()

    @audited(
        client=client,
        action_id=ResponseActionId.HOST_ISOLATE,
        subject_arg="agent_id",
    )
    def isolate(agent_id: str) -> None:
        return None

    # First call sets the baseline. Then artificially rewind the
    # client's last-wall to the future so the next emit goes "backwards".
    with _run_ctx(client):
        isolate("host-a")
        # Force the comparison to think we're going backwards.
        client._last_wall = datetime.now(UTC).replace(year=2099)
        client._last_mono_ns = time.monotonic_ns()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            isolate("host-b")
        backward_warns = [w for w in caught if issubclass(w.category, RuntimeWarning)]
        assert backward_warns, "expected RuntimeWarning on backwards wall-clock"
        assert "moved backwards" in str(backward_warns[0].message)


def test_clock_drift_forward_jump_emits_warning() -> None:
    """Wall clock jumping forward (NTP step, hypervisor pause) without
    matching monotonic progress fires a divergence warning."""
    client = _make_client()

    @audited(
        client=client,
        action_id=ResponseActionId.HOST_ISOLATE,
        subject_arg="agent_id",
    )
    def isolate(agent_id: str) -> None:
        return None

    with _run_ctx(client):
        isolate("host-a")
        # Simulate a 60s NTP forward step : wall jumped, monotonic
        # only ticked ~ε. Inject the past state then call again.
        client._last_wall = datetime.now(UTC).replace(
            second=(datetime.now(UTC).second - 0) % 60,
        )
        # Push monotonic baseline backward to fake "monotonic didn't advance".
        # Easiest : set _last_mono_ns to "just now", and _last_wall to 60s ago.
        client._last_wall = datetime.fromtimestamp(time.time() - 60, tz=UTC)
        client._last_mono_ns = time.monotonic_ns()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            isolate("host-b")
        drift_warns = [
            w for w in caught
            if issubclass(w.category, RuntimeWarning) and "drift" in str(w.message)
        ]
        assert drift_warns, "expected drift RuntimeWarning on forward NTP step"


def test_clock_drift_within_tolerance_is_silent() -> None:
    """Sub-tolerance drift (the normal case under chronyd) doesn't spam warnings."""
    client = _make_client()

    @audited(
        client=client,
        action_id=ResponseActionId.HOST_ISOLATE,
        subject_arg="agent_id",
    )
    def isolate(agent_id: str) -> None:
        return None

    with _run_ctx(client), warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        # 4 calls back-to-back. wall vs monotonic should agree within
        # millisecond-level drift well below the default 1.0s tolerance.
        for h in ("a", "b", "c", "d"):
            isolate(f"host-{h}")
        drift_warns = [w for w in caught if issubclass(w.category, RuntimeWarning)]
        assert not drift_warns, f"unexpected drift warns under normal clock : {[str(w.message) for w in drift_warns]}"


def test_canonicalization_immune_to_delimiter_injection() -> None:
    """v1 canonicalization (sorted-keys JSON) is structurally immune to
    delimiter-injection attacks. An attacker can't make ``canonicalize_v1``
    produce a byte sequence that collides with another row by stuffing
    the HMAC separator ``b"|"`` into a string field.

    Why : JSON encodes strings as quote-delimited sequences. The HMAC
    boundary (``prev_hash || "|" || canonical_bytes``) is well-defined :
    ``prev_hash`` is 64 hex chars (restricted to [0-9a-f] — ``|`` cannot
    appear), the next byte is ALWAYS the literal ``|``, and the rest is
    a JSON object starting with ``{``. Two different rows produce
    canonical_bytes of different content AND no string field can
    collapse the structural quotes."""
    from datetime import UTC, datetime

    from warlog_spec import (
        AuditConnectorRef,
        AuditRow,
        ComplianceScope,
        DecisionArtifactType,
        DecisionRef,
        ExecutionPhase,
        HumanActor,
        ResponseActionScope,
        ResponseSubject,
        TriggerSignalKind,
        TriggerSignalRef,
    )
    from warlog_spec.audit_chain import canonicalize_v1

    pin = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)

    def row(selector_value: str) -> AuditRow:
        return AuditRow(
            audit_id="a",
            execution_id="e",
            tenant_id="t",
            actor=HumanActor(id="alice"),
            action_id=ResponseActionId.HOST_ISOLATE,
            subject=ResponseSubject(
                kind=ResponseActionScope.ENDPOINT,
                selector_type="agent_id",
                selector_value=selector_value,
            ),
            phase=ExecutionPhase.APPLY,
            outcome=ExecutionOutcome.SUCCESS,
            started_at=pin,
            completed_at=pin,
            duration_ms=0,
            error=None,
            connector=AuditConnectorRef(id="c", version="1"),
            idempotency_key="k",
            decision_ref=DecisionRef(
                artifact_type=DecisionArtifactType.NEXT_STEP_PROPOSAL,
                artifact_id="d",
                content_hash="c" * 64,
            ),
            trigger_signal_ref=TriggerSignalRef(
                kind=TriggerSignalKind.ALERT,
                source_id="a",
                content_hash="d" * 64,
            ),
            compliance_scope=[ComplianceScope.NIS2],
        )

    benign = canonicalize_v1(row("alice"))
    # Try to make poison's bytes structurally identical to a different
    # legitimate row by injecting the HMAC separator + fake JSON keys.
    poison_bytes = canonicalize_v1(row('alice"|"action_id":"user.admin'))

    # Different lengths = different bytes = different HMAC.
    assert len(benign) != len(poison_bytes)
    assert benign != poison_bytes

    # The injected `"` characters in the user input get JSON-escaped to
    # `\"` in the canonical output — preserving the structural quotes
    # of the OUTER selectorValue field. The poison string ends up
    # nested inside its own JSON quotes, not promoted to the row level.
    assert b'"selectorValue":"alice\\"' in poison_bytes


def test_spec_models_forbid_extra_fields_against_type_confusion() -> None:
    """Spec types must reject unknown fields to prevent type-confusion
    attacks on discriminated unions. With ``extra="ignore"``, an
    attacker could pass ``{kind: "human", id: "alice", agent: {...}}``,
    Pydantic would silently drop the ``agent`` and instantiate a
    HumanActor — masking the true automation executor in the chain.
    With ``extra="forbid"`` the attack surfaces as a ValidationError."""
    from pydantic import ValidationError

    from warlog_spec import AutomationActor, HumanActor

    # HumanActor must NOT silently accept an automation 'agent' field.
    with pytest.raises(ValidationError, match="agent"):
        HumanActor.model_validate(
            {
                "kind": "human",
                "id": "alice",
                "agent": {
                    "model": "gpt-4o",
                    "modelVersion": "v",
                    "systemPromptHash": "a" * 64,
                    "agentRunId": "r",
                },
            }
        )

    # AutomationActor must NOT silently accept arbitrary garbage.
    with pytest.raises(ValidationError, match="evil"):
        AutomationActor.model_validate(
            {
                "kind": "automation",
                "id": "bot",
                "agent": {
                    "model": "gpt-4o",
                    "modelVersion": "v",
                    "systemPromptHash": "a" * 64,
                    "agentRunId": "r",
                },
                "evil": "payload",
            }
        )


def test_audit_actor_discriminated_union_rejects_mixed_keys() -> None:
    """The discriminated union AuditActor routes by ``kind``. A payload
    that claims kind=human but carries automation-only fields must be
    rejected, not silently coerced into a HumanActor with the extra
    fields dropped."""
    from pydantic import TypeAdapter, ValidationError

    from warlog_spec.provider_abi import AuditActor

    actor_validator = TypeAdapter(AuditActor)

    with pytest.raises(ValidationError):
        actor_validator.validate_python(
            {
                "kind": "human",
                "id": "alice",
                "agent": {
                    "model": "gpt-4o",
                    "modelVersion": "v",
                    "systemPromptHash": "a" * 64,
                    "agentRunId": "r",
                },
            }
        )

    # Sanity : valid HumanActor still parses.
    valid = actor_validator.validate_python({"kind": "human", "id": "alice"})
    assert valid.kind == "human"
    assert valid.id == "alice"


def test_jsonl_persister_resumes_chain_after_restart(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"

    # First "process"
    persister1 = JsonlFilePersister(log_path)
    client1 = _make_client(persister=persister1)

    @audited(
        client=client1,
        action_id=ResponseActionId.USER_REVOKE_TOKENS,
        subject_arg="user_email",
    )
    def revoke1(user_email: str) -> None:
        return None

    with _run_ctx(client1):
        revoke1("alice@acme.example")
    head_after_first = persister1.head_signature()
    assert head_after_first is not None

    # Second "process" — new persister reading the same file.
    persister2 = JsonlFilePersister(log_path)
    assert persister2.head_signature() == head_after_first

    client2 = _make_client(persister=persister2)

    @audited(
        client=client2,
        action_id=ResponseActionId.USER_REVOKE_TOKENS,
        subject_arg="user_email",
    )
    def revoke2(user_email: str) -> None:
        return None

    with _run_ctx(client2):
        revoke2("bob@acme.example")

    # File now contains 4 lines (2 from process 1, 2 from process 2).
    with open(log_path, encoding="utf-8") as f:
        lines = [json.loads(line) for line in f if line.strip()]
    assert len(lines) == 4
    # Chain links across the restart : line[2].prevHash == line[1].signature
    assert lines[2]["prevHash"] == lines[1]["signature"]
