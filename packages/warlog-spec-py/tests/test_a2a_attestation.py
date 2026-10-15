"""A2A agent attestation — sign/verify behaviour and failure modes (RFC-0005).

Functional tests for :mod:`warlog_spec.a2a`. The cross-language byte-equivalence
pin (Python golden == TypeScript golden) lives in
``test_a2a_canonical_bytes.py`` / the TS ``a2a.test.ts``; this file exercises the
verification logic and every refusal path.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from warlog_spec import (
    AgentCompositionKind,
    AiAgentRef,
)
from warlog_spec.a2a import (
    A2AAttestation,
    A2AAttestationPayload,
    A2ASignature,
    A2AVerificationError,
    compute_request_binding,
    generate_ed25519_keypair_pem,
    sign_a2a_attestation,
    strip_meta,
    verify_a2a_attestation,
)

_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
_AUDIENCE = "warlog-mcp://tenant-acme"
_METHOD = "tools/call"
_PARAMS = {
    "name": "search_alerts",
    "arguments": {"q": "lateral movement", "limit": 50},
    "_meta": {"org.warlog.a2a-attestation/v1": {"opaque": "attestation goes here"}},
}


def _delegating_agent() -> AiAgentRef:
    """An orchestrator that delegated to one sub-agent (2-deep chain)."""
    sub = AiAgentRef(
        model="claude-haiku-4-5",
        model_version="2026-01-01",
        system_prompt_hash="a" * 64,
        agent_run_id="run-sub-7",
    )
    return AiAgentRef(
        model="claude-opus-4-8",
        model_version="2026-01-01",
        system_prompt_hash="b" * 64,
        agent_run_id="run-root-1",
        sub_agents=[sub],
        composition_kind=AgentCompositionKind.DELEGATED,
    )


def _make_payload(**overrides: object) -> A2AAttestationPayload:
    base: dict[str, object] = {
        "agent": _delegating_agent(),
        "agent_id": "did:web:acme.example#agent-triage-1",
        "audience": _AUDIENCE,
        "issued_at": _NOW,
        "nonce": "nonce-0001",
        "request_binding": compute_request_binding(_METHOD, _PARAMS),
    }
    base.update(overrides)
    return A2AAttestationPayload(**base)  # type: ignore[arg-type]


@pytest.fixture
def keypair() -> tuple[bytes, bytes]:
    return generate_ed25519_keypair_pem()


@pytest.fixture
def attestation(keypair: tuple[bytes, bytes]) -> A2AAttestation:
    priv, _pub = keypair
    return sign_a2a_attestation(
        _make_payload(), private_key_pem=priv, key_id="did:web:acme.example#key-ed25519-1"
    )


def _verify(att: A2AAttestation, pub: bytes, **overrides: object) -> AiAgentRef:
    kwargs: dict[str, object] = {
        "public_key_pem": pub,
        "expected_audience": _AUDIENCE,
        "method": _METHOD,
        "params": _PARAMS,
        "now": _NOW,
    }
    kwargs.update(overrides)
    return verify_a2a_attestation(att, **kwargs)  # type: ignore[arg-type]


# --- Happy path -------------------------------------------------------------


def test_valid_attestation_returns_agent_with_delegation(
    attestation: A2AAttestation, keypair: tuple[bytes, bytes]
) -> None:
    _priv, pub = keypair
    agent = _verify(attestation, pub)
    assert agent.model == "claude-opus-4-8"
    assert agent.composition_kind is AgentCompositionKind.DELEGATED
    assert len(agent.sub_agents) == 1
    assert agent.sub_agents[0].agent_run_id == "run-sub-7"


def test_wire_round_trip_then_verifies(
    attestation: A2AAttestation, keypair: tuple[bytes, bytes]
) -> None:
    """The gateway receives the attestation as a plain dict from ``_meta``.

    Serialize -> dict -> re-parse must preserve verifiability byte-for-byte.
    """
    _priv, pub = keypair
    wire = attestation.model_dump(mode="json", by_alias=True)
    parsed = A2AAttestation.model_validate(wire)
    agent = _verify(parsed, pub)
    assert agent.sub_agents[0].agent_run_id == "run-sub-7"


# --- Signature integrity ----------------------------------------------------


def test_bad_signature_is_rejected(
    attestation: A2AAttestation, keypair: tuple[bytes, bytes]
) -> None:
    _priv, pub = keypair
    forged = attestation.model_copy(deep=True)
    forged.signature.signature_value = "0" * 128
    with pytest.raises(A2AVerificationError, match="signature"):
        _verify(forged, pub)


def test_tampered_payload_is_rejected(
    attestation: A2AAttestation, keypair: tuple[bytes, bytes]
) -> None:
    """Swap the signed payload for a different agent, keep the old signature."""
    _priv, pub = keypair
    swapped = A2AAttestation(
        payload=_make_payload(agent_id="did:web:evil.example#agent-x"),
        signature=attestation.signature,
    )
    with pytest.raises(A2AVerificationError):
        _verify(swapped, pub)


def test_verify_with_wrong_public_key_is_rejected(
    attestation: A2AAttestation,
) -> None:
    _other_priv, other_pub = generate_ed25519_keypair_pem()
    with pytest.raises(A2AVerificationError, match="signature"):
        _verify(attestation, other_pub)


# --- Audience / freshness / binding ----------------------------------------


def test_audience_mismatch_is_rejected(
    attestation: A2AAttestation, keypair: tuple[bytes, bytes]
) -> None:
    _priv, pub = keypair
    with pytest.raises(A2AVerificationError, match="audience"):
        _verify(attestation, pub, expected_audience="warlog-mcp://tenant-other")


def test_stale_attestation_is_rejected(
    attestation: A2AAttestation, keypair: tuple[bytes, bytes]
) -> None:
    _priv, pub = keypair
    with pytest.raises(A2AVerificationError, match="too old"):
        _verify(attestation, pub, now=_NOW + timedelta(seconds=301))


def test_future_attestation_beyond_tolerance_is_rejected(
    attestation: A2AAttestation, keypair: tuple[bytes, bytes]
) -> None:
    _priv, pub = keypair
    with pytest.raises(A2AVerificationError, match="future"):
        _verify(attestation, pub, now=_NOW - timedelta(seconds=301))


def test_within_window_is_accepted(
    attestation: A2AAttestation, keypair: tuple[bytes, bytes]
) -> None:
    _priv, pub = keypair
    # 299s old is inside the default 300s window.
    _verify(attestation, pub, now=_NOW + timedelta(seconds=299))


def test_splice_onto_different_request_is_rejected(
    attestation: A2AAttestation, keypair: tuple[bytes, bytes]
) -> None:
    _priv, pub = keypair
    with pytest.raises(A2AVerificationError, match="request_binding"):
        _verify(attestation, pub, params={"name": "delete_everything"})


# --- strip_meta / request binding -------------------------------------------


def test_request_binding_ignores_meta_content() -> None:
    """The binding must be identical regardless of what rides in ``_meta``."""
    without = compute_request_binding(_METHOD, {"name": "x", "arguments": {}})
    with_meta = compute_request_binding(
        _METHOD, {"name": "x", "arguments": {}, "_meta": {"anything": [1, 2, 3]}}
    )
    other_meta = compute_request_binding(
        _METHOD, {"name": "x", "arguments": {}, "_meta": {"different": True}}
    )
    assert without == with_meta == other_meta


def test_request_binding_is_key_order_insensitive() -> None:
    """Canonicalization sorts keys, so param insertion order cannot change it."""
    a = compute_request_binding(_METHOD, {"name": "x", "arguments": {"b": 1, "a": 2}})
    b = compute_request_binding(_METHOD, {"arguments": {"a": 2, "b": 1}, "name": "x"})
    assert a == b


def test_request_binding_changes_with_method() -> None:
    p = {"name": "x", "arguments": {}}
    assert compute_request_binding("tools/call", p) != compute_request_binding("tools/list", p)


def test_strip_meta_removes_only_top_level_meta() -> None:
    params = {"name": "x", "_meta": {"k": 1}, "arguments": {"_meta": "kept-nested"}}
    stripped = strip_meta(params)
    assert "_meta" not in stripped
    # A nested key literally named _meta is NOT stripped (only the top-level one).
    assert stripped["arguments"]["_meta"] == "kept-nested"


def test_strip_meta_handles_none_and_empty() -> None:
    assert strip_meta(None) == {}
    assert strip_meta({}) == {}


# --- Schema hardening -------------------------------------------------------


def test_unknown_field_in_attestation_is_forbidden() -> None:
    """SpecModel extra='forbid' rejects injected fields (anti-confusion)."""
    from pydantic import ValidationError

    wire = A2AAttestation(
        payload=_make_payload(),
        signature=A2ASignature(signature_value="0" * 128, key_id="k"),
    ).model_dump(mode="json", by_alias=True)
    wire["payload"]["smuggled"] = "evil"
    with pytest.raises(ValidationError):
        A2AAttestation.model_validate(wire)


def test_signature_value_must_be_128_hex() -> None:
    from pydantic import ValidationError

    # 64 hex chars (HMAC length) is too short for Ed25519.
    with pytest.raises(ValidationError):
        A2ASignature(signature_value="a" * 64, key_id="k")
    # non-hex
    with pytest.raises(ValidationError):
        A2ASignature(signature_value="z" * 128, key_id="k")
