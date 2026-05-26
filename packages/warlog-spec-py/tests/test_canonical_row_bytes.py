"""Writer-stability tripwire for the v1 canonicalization.

The bytes produced by :func:`canonicalize_v1` are what get HMAC-signed
at write time. **Historical chains are NOT at risk** from changes to
this function : if you persist the signed canonical bytes alongside
the signature, verification reads them back rather than re-serializing
the current Pydantic model. This test catches drift in the **current
writer** — change ``canonicalize_v1`` and future rows will diverge
from past ones at the byte level. The correct response is to introduce
``canonicalize_v2`` and bump ``CURRENT_CANONICALIZATION_FORMAT``, not
to mutate v1.

This test is the **Python side** of the cross-language byte-equivalence
guarantee. The TypeScript side lives at
``packages/warlog-spec-ts/tests/audit-chain.test.ts``. Both pin the
same ``AuditRow`` payload and the same ``_GOLDEN`` byte string ;
running ``pytest`` here and ``npm test`` there must both pass against
the same 900-byte output.
"""

from __future__ import annotations

from datetime import UTC, datetime

from warlog_spec import (
    AuditConnectorRef,
    AuditRow,
    ComplianceScope,
    DecisionArtifactType,
    DecisionRef,
    ExecutionOutcome,
    ExecutionPhase,
    HumanActor,
    ResponseActionId,
    ResponseActionScope,
    ResponseSubject,
    TriggerSignalKind,
    TriggerSignalRef,
    canonicalize_v1,
)

# Pinned UTC instant — never change. The whole point of the golden is
# byte stability across the codebase's lifetime.
_PIN = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def _pinned_row() -> AuditRow:
    return AuditRow(
        audit_id="audit-pinned-001",
        execution_id="exec-pinned-001",
        tenant_id="tenant-pinned",
        actor=HumanActor(id="alice"),
        action_id=ResponseActionId.HOST_ISOLATE,
        subject=ResponseSubject(
            kind=ResponseActionScope.ENDPOINT,
            selector_type="agent_id",
            selector_value="agent-pinned-007",
        ),
        phase=ExecutionPhase.APPLY,
        outcome=ExecutionOutcome.SUCCESS,
        started_at=_PIN,
        completed_at=_PIN,
        duration_ms=1000,
        error=None,
        connector=AuditConnectorRef(id="demo-edr", version="0.1.0"),
        idempotency_key="idem-pinned-key",
        decision_ref=DecisionRef(
            artifact_type=DecisionArtifactType.NEXT_STEP_PROPOSAL,
            artifact_id="proposal-pinned-001",
            content_hash="c" * 64,
        ),
        trigger_signal_ref=TriggerSignalRef(
            kind=TriggerSignalKind.ALERT,
            source_id="alert-pinned-001",
            content_hash="d" * 64,
        ),
        compliance_scope=[ComplianceScope.NIS2],
    )


# Golden bytes — produced by running ``canonicalize_v1(_pinned_row())``
# at the time this test was authored. Changing this value means you've
# changed the canonicalization. See the module docstring for the
# playbook. Byte-identical to the ``PYTHON_GOLDEN`` constant in the
# TypeScript test ``packages/warlog-spec-ts/tests/audit-chain.test.ts``
# — sha256 of this string is
# ``75f5a2f740a505d0f68f10b456470f9be9d5e431de08950eb1c48828bb4267f3``.
_GOLDEN = (
    b'{"actionId":"host.isolate","actor":{"id":"alice","kind":"human"},'
    b'"auditId":"audit-pinned-001","completedAt":"2026-01-01T12:00:00Z",'
    b'"complianceScope":["nis2"],"connector":{"id":"demo-edr","version":"0.1.0"},'
    b'"decisionRef":{"artifactId":"proposal-pinned-001",'
    b'"artifactType":"next_step_proposal",'
    b'"contentHash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},'
    b'"durationMs":1000,"error":null,"executionId":"exec-pinned-001",'
    b'"idempotencyKey":"idem-pinned-key","outcome":"success","phase":"apply",'
    b'"priorAuditId":null,'
    b'"specVersion":"1.0","startedAt":"2026-01-01T12:00:00Z",'
    b'"subject":{"kind":"endpoint","selectorKeyId":null,'
    b'"selectorRepresentation":"raw","selectorType":"agent_id",'
    b'"selectorValue":"agent-pinned-007"},"tenantId":"tenant-pinned",'
    b'"triggerSignalRef":{"contentHash":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",'
    b'"kind":"alert","sourceId":"alert-pinned-001"}}'
)


def test_canonicalize_v1_is_stable_for_pinned_payload() -> None:
    """If this fails, the audit chain canonicalization has changed.

    Either restore the original behavior, or follow the schema-evolution
    playbook : add ``canonicalize_v2`` alongside ``canonicalize_v1`` and
    update writers to emit the new format identifier.
    """
    actual = canonicalize_v1(_pinned_row())
    assert actual == _GOLDEN, (
        "Canonical bytes drifted from the golden. "
        "If intentional, see schema-evolution playbook in audit_chain.py "
        "and update _GOLDEN deliberately.\n"
        f"Expected:\n  {_GOLDEN!r}\n"
        f"Got:\n  {actual!r}"
    )


def test_canonicalize_v1_is_deterministic_across_calls() -> None:
    """Same input -> same bytes, every call. No clock or randomness leak."""
    row = _pinned_row()
    a = canonicalize_v1(row)
    b = canonicalize_v1(row)
    c = canonicalize_v1(row)
    assert a == b == c


def test_golden_length_is_pinned() -> None:
    """The 900-byte length is what we cite in public documentation. Pin it."""
    assert len(_GOLDEN) == 900
