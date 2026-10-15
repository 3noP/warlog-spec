"""A2A canonical bytes — the Python half of the cross-language pin (RFC-0005).

``test_a2a_attestation.py`` has pointed at this file since RFC-0005 shipped,
and it did not exist: the A2A golden was pinned **only** in
``packages/warlog-spec-ts/tests/a2a.test.ts``, which transcribes a value it
attributes to Python and checks it against a Python sha256 that nothing on this
side ever recomputed. That is a one-sided pin. If the Python canonicalization
drifted, the TypeScript suite would keep passing against its frozen copy and
the divergence would surface as a signature failure in production, on the one
code path where a failure reads as tampering.

The payload and the goldens here are byte-identical to the ones in that TS
file **on purpose**. Both suites must pin the same bytes or neither pins
anything.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from warlog_spec import AgentCompositionKind, AiAgentRef
from warlog_spec.a2a import (
    A2AAttestationPayload,
    canonicalize_a2a_v1,
    compute_request_binding,
)

_PINNED_METHOD = "tools/call"
_PINNED_PARAMS = {
    "name": "search_alerts",
    "arguments": {"q": "lateral movement", "limit": 50},
    "_meta": {"x": 1},
}

#: Shared with ``a2a.test.ts``.
_PY_BINDING = "a4cf63634d9502bc2439f745ee97d854ba8cba3c5d703251af07273bd780800b"
_PY_GOLDEN_SHA256 = "9cd985169edee720e8870c0d9c3884a8280fbaba8e1039f195ad2e75ab4b3df1"


def _pinned_payload() -> A2AAttestationPayload:
    sub = AiAgentRef(
        model="claude-haiku-4-5",
        model_version="2026-01-01",
        system_prompt_hash="a" * 64,
        agent_run_id="run-sub-7",
    )
    agent = AiAgentRef(
        model="claude-opus-4-8",
        model_version="2026-01-01",
        system_prompt_hash="b" * 64,
        agent_run_id="run-root-1",
        composition_kind=AgentCompositionKind.DELEGATED,
        sub_agents=[sub],
    )
    return A2AAttestationPayload(
        agent=agent,
        agent_id="did:web:acme.example#agent-triage-1",
        audience="warlog-mcp://tenant-acme",
        issued_at=datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC),
        nonce="nonce-0001",
        request_binding=_PY_BINDING,
    )


def test_request_binding_is_pinned() -> None:
    """The anti-splice binding must be reproducible byte-for-byte."""
    assert compute_request_binding(_PINNED_METHOD, _PINNED_PARAMS) == _PY_BINDING


def test_canonical_bytes_hash_is_pinned() -> None:
    """If this fails, a py-signed attestation stopped verifying in a TS gateway.

    Either restore the canonicalization, or change BOTH goldens deliberately
    (here and in ``a2a.test.ts``) and bump the canonicalization format.
    """
    actual = canonicalize_a2a_v1(_pinned_payload())
    assert hashlib.sha256(actual).hexdigest() == _PY_GOLDEN_SHA256, (
        "A2A canonical bytes drifted from the golden shared with the TypeScript "
        f"suite.\nGot:\n  {actual!r}"
    )


def test_canonical_bytes_are_domain_separated() -> None:
    """The prefix is at a fixed position, so no payload string can forge it."""
    assert canonicalize_a2a_v1(_pinned_payload()).startswith(
        b"warlog-spec/v1/a2a-attestation|{"
    )


def test_canonicalization_is_deterministic_across_calls() -> None:
    payload = _pinned_payload()
    assert canonicalize_a2a_v1(payload) == canonicalize_a2a_v1(payload)
