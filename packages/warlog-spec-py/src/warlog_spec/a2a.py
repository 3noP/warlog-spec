"""A2A (Agent2Agent) agent attestation — verifiable agent identity in transport metadata.

An **A2A attestation** is a signed claim, carried in JSON-RPC ``_meta``
(MCP: ``params._meta["org.warlog.a2a-attestation/v1"]``) or A2A
``Message.metadata``, that proves *which* agent — and its delegation chain,
under which mandate — issued a request. A gateway **verifies** it
cryptographically instead of trusting a caller-asserted identity header
(the trust gap of ratelock's ``X-User-ID`` and a per-tenant Bearer key).

This module is the **open-source verification primitive** of the Warlog agent
gateway: the schema + the pure ``sign`` / ``verify`` functions are Apache-2.0.
The stateful policy / enforcement layer (anti-replay nonce cache, per-agent
budgets, rate limits) lives in the commercial backend, NOT here.

Design (RFC-0005), built entirely on the existing trust layer :

- The identity payload **reuses** :class:`~warlog_spec.provider_abi.AiAgentRef`
  verbatim — it already carries the multi-agent delegation tree
  (``sub_agents``, ``composition_kind``, ``tools_manifest_hash``), so an A2A
  delegation chain (client agent -> remote agent -> ...) maps directly.
- :class:`A2ASignature` mirrors
  :class:`~warlog_spec.provider_abi.AuditAttestation` **minus** ``prev_row_hash``
  — an attestation is standalone, not chained — so the audit-chain type is
  not contaminated with a meaningless field.
- The signed bytes are **domain-separated** :
  ``b"warlog-spec/v1/a2a-attestation|" + canonical_json_bytes(payload)``. An
  A2A attestation signature can therefore never be mistaken for (or replayed
  as) an audit-chain signature, and vice versa.
- Signatures are **Ed25519** (RFC-0004 ``keyId`` semantics — a ``did:web`` /
  JWKS / file reference resolving to the public key, signer != verifier custody).
  The crypto dependency is **optional** (``pip install warlog-spec[crypto]``)
  so ``import warlog_spec`` stays dependency-light for type-only consumers.

Verification rules — see :func:`verify_a2a_attestation` :

1. Ed25519 signature over the domain-separated canonical bytes.
2. ``audience`` matches the expected gateway / tenant.
3. ``issued_at`` is within the freshness window (default 300 s, both directions
   to bound clock skew).
4. ``request_binding`` equals ``sha256(method || "|" || canonical(params sans _meta))``
   recomputed from the actual request — anti-splice.

**Anti-replay (nonce) is intentionally NOT done here.** It requires shared,
mutable state (a Redis seen-cache) which is the operator's concern. This
primitive stays pure and side-effect-free; the gateway combines it with a
``SET a2a:nonce:{tenant}:{nonce} 1 NX EX {window}`` check. The ``nonce`` field
is signed so the gateway can trust it once the signature verifies.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from warlog_spec._base import SpecModel
from warlog_spec.audit_chain import canonical_json_bytes
from warlog_spec.provider_abi import HEX64_PATTERN, HEX_PATTERN, AiAgentRef

A2A_ATTESTATION_VERSION = "1.0"

#: The canonical, namespaced key under which the attestation rides in the
#: JSON-RPC ``params._meta`` map (MCP) or the A2A ``Message.metadata`` map.
A2A_META_KEY = "org.warlog.a2a-attestation/v1"

#: The extension URI an A2A producer declares in ``Message.extensions`` to
#: announce it is carrying a Warlog attestation under :data:`A2A_META_KEY`.
A2A_EXTENSION_URI = "https://warlog-spec.org/ext/a2a-attestation/v1"

#: Domain-separation prefix mixed into the signed bytes. Ends with ``"|"``;
#: the canonical payload bytes (a JSON object starting with ``{``) follow. The
#: boundary is fixed-position, so no string field inside the payload can forge
#: the prefix — same anti-injection discipline as the audit chain's
#: ``prev_hash || "|" || canonical`` construction.
_A2A_DOMAIN = b"warlog-spec/v1/a2a-attestation|"


class A2AVerificationError(Exception):
    """Raised when an A2A attestation fails verification.

    Covers a bad signature, an audience mismatch, a stale / future
    ``issued_at``, or a ``request_binding`` mismatch (anti-splice). The
    message states which check failed; callers SHOULD surface it as a refusal,
    never as a silent pass.
    """


class A2ACryptoUnavailable(RuntimeError):
    """Raised when an Ed25519 operation is attempted without the optional extra.

    The core package stays dependency-light. Ed25519 sign / verify need the
    ``cryptography`` package : ``pip install warlog-spec[crypto]``.
    """


# =============================================================================
# Wire types
# =============================================================================


class A2ASignature(SpecModel):
    """Detached signature envelope for an :class:`A2AAttestationPayload`.

    Mirrors :class:`~warlog_spec.provider_abi.AuditAttestation` but omits
    ``prev_row_hash`` : an attestation is a standalone claim, not a link in an
    append-only chain. ``key_id`` follows RFC-0004 semantics (a URI / DID
    resolving to the Ed25519 **public** key; the verifier fetches it out of
    band — for warlog-mcp, from the tenant ``AgentKey`` registry).
    """

    algorithm: Literal["Ed25519"] = Field(
        default="Ed25519",
        description="Signature algorithm. Ed25519 only in v1 (RFC-0004 asymmetric path).",
    )
    signature_value: str = Field(
        min_length=128,
        max_length=128,
        pattern=HEX_PATTERN,
        description="Hex-encoded Ed25519 signature over the domain-separated canonical payload bytes (64 bytes -> 128 hex).",
    )
    key_id: str = Field(
        min_length=1,
        description=(
            "Reference resolving to the Ed25519 public key (RFC-0004). Common "
            "patterns: 'did:web:acme.example#key-ed25519-1', "
            "'https://keys.example.org/ed25519/v3.pem'. The gateway resolves it "
            "against its tenant agent-key registry."
        ),
    )
    canonicalization_format: Literal["v1"] = Field(
        default="v1",
        description="Canonical-bytes format identifier, decoupled from the payload's spec_version.",
    )


class A2AAttestationPayload(SpecModel):
    """The signed claim: which agent, for whom, bound to which request.

    ``agent`` reuses :class:`~warlog_spec.provider_abi.AiAgentRef` so the full
    delegation tree (``sub_agents`` recursive, ``composition_kind``,
    ``tools_manifest_hash``) travels verbatim and projects 1:1 onto an
    :class:`~warlog_spec.provider_abi.AutomationActor` on the audit chain.
    """

    agent: AiAgentRef = Field(
        description="Verifiable identity of the calling agent (and its delegation chain).",
    )
    agent_id: str = Field(
        min_length=1,
        description=(
            "Stable A2A identity of the agent (a did:web or URL). The subject "
            "the key_id is expected to belong to; the gateway binds the resolved "
            "public key to this id in its registry."
        ),
    )
    audience: str = Field(
        min_length=1,
        description=(
            "Target the attestation is minted for (gateway / tenant URI). The "
            "verifier rejects a mismatch so an attestation captured by one "
            "recipient cannot be presented to another."
        ),
    )
    issued_at: datetime = Field(
        description="When the attestation was minted (aware UTC). Checked against the freshness window.",
    )
    nonce: str = Field(
        min_length=1,
        description=(
            "Single-use value for anti-replay. Signed here so the gateway can "
            "trust it after signature verification, then enforce uniqueness in "
            "its own (Redis) seen-cache within the freshness window."
        ),
    )
    request_binding: str = Field(
        min_length=64,
        max_length=64,
        pattern=HEX64_PATTERN,
        description=(
            "sha256 hex of (method || '|' || canonical_json_bytes(strip_meta(params))). "
            "Binds the attestation to THIS exact JSON-RPC call so it cannot be "
            "spliced onto a different request. Compute via compute_request_binding()."
        ),
    )


class A2AAttestation(SpecModel):
    """The full attestation envelope carried in transport ``_meta``."""

    spec_version: Literal["1.0"] = Field(default=A2A_ATTESTATION_VERSION)
    payload: A2AAttestationPayload
    signature: A2ASignature


# =============================================================================
# Canonicalization + request binding (shared by signer and verifier)
# =============================================================================


def strip_meta(params: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return a shallow copy of JSON-RPC ``params`` with the ``_meta`` key removed.

    The **single source of truth** used by BOTH the signer and the verifier to
    compute :func:`compute_request_binding`. The whole top-level ``_meta`` key
    is dropped (not just the attestation sub-key) so no attestation or other
    extension residue can leak into the signed bytes. Any divergence between
    the two sides here would break signatures intermittently in production.
    """
    if not params:
        return {}
    return {k: v for k, v in params.items() if k != "_meta"}


def compute_request_binding(method: str, params: Mapping[str, Any] | None) -> str:
    """sha256 hex of ``method || "|" || canonical_json_bytes(strip_meta(params))``.

    ``params`` must be JSON-native (the parsed JSON-RPC params). The ``"|"``
    separator is safe: ``method`` is a bare JSON-RPC method string and the
    canonical params bytes are a JSON object beginning with ``{``.
    """
    stripped = strip_meta(params)
    binding_bytes = method.encode("utf-8") + b"|" + canonical_json_bytes(stripped)
    return hashlib.sha256(binding_bytes).hexdigest()


def canonicalize_a2a_v1(payload: A2AAttestationPayload) -> bytes:
    """Domain-separated canonical bytes that the Ed25519 signature covers.

    ``_A2A_DOMAIN`` + ``canonical_json_bytes(payload as camelCase JSON)``. This
    is byte-identical to the TypeScript ``canonicalizeA2aV1`` — the shared
    discipline is what makes a py-signed attestation verifiable by a ts gateway
    and vice versa.
    """
    return _A2A_DOMAIN + canonical_json_bytes(
        payload.model_dump(mode="json", by_alias=True)
    )


# =============================================================================
# Ed25519 sign / verify (optional 'crypto' extra)
# =============================================================================


def _load_crypto() -> tuple[Any, Any, Any, Any]:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as exc:  # pragma: no cover - only without the extra installed
        raise A2ACryptoUnavailable(
            "A2A attestation Ed25519 signing/verification requires the optional "
            "'cryptography' dependency. Install with: pip install warlog-spec[crypto]"
        ) from exc
    return InvalidSignature, serialization, Ed25519PrivateKey, Ed25519PublicKey


def generate_ed25519_keypair_pem() -> tuple[bytes, bytes]:
    """Reference/test helper: return ``(private_pem, public_pem)`` for a fresh key."""
    _inv, serialization, Ed25519PrivateKey, _pub = _load_crypto()
    priv = Ed25519PrivateKey.generate()
    private_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def sign_a2a_attestation(
    payload: A2AAttestationPayload,
    *,
    private_key_pem: bytes,
    key_id: str,
) -> A2AAttestation:
    """Sign ``payload`` with an Ed25519 private key (PEM) and return the envelope.

    Reference signer — the client side (an A2A-speaking agent or an SDK) uses
    this to mint the attestation it injects into ``_meta``. The gateway only
    ever calls :func:`verify_a2a_attestation`.
    """
    _inv, _serialization, Ed25519PrivateKey, _pub = _load_crypto()
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise A2AVerificationError("provided private key is not an Ed25519 key")

    signature_hex = key.sign(canonicalize_a2a_v1(payload)).hex()
    return A2AAttestation(
        payload=payload,
        signature=A2ASignature(signature_value=signature_hex, key_id=key_id),
    )


def verify_a2a_attestation(
    attestation: A2AAttestation,
    *,
    public_key_pem: bytes,
    expected_audience: str,
    method: str,
    params: Mapping[str, Any] | None,
    now: datetime,
    max_age_seconds: int = 300,
) -> AiAgentRef:
    """Verify an attestation end-to-end and return the proven :class:`AiAgentRef`.

    Raises :class:`A2AVerificationError` on any failed check. Does NOT check the
    nonce (stateless primitive — the caller enforces single-use against its own
    seen-cache; the ``nonce`` is signed, so it is trustworthy once the signature
    verifies).

    Args:
        attestation: the parsed envelope from ``params._meta``.
        public_key_pem: Ed25519 public key (PEM) resolved from ``signature.key_id``.
        expected_audience: this gateway / tenant URI.
        method: the JSON-RPC method of the request carrying the attestation.
        params: the JSON-RPC params of that request (``_meta`` is stripped internally).
        now: current aware-UTC time (injected for testability).
        max_age_seconds: freshness window, applied in both directions (clock skew).
    """
    # 1. Signature over the domain-separated canonical bytes.
    InvalidSignature, _serialization, _priv, Ed25519PublicKey = _load_crypto()
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_public_key(public_key_pem)
    if not isinstance(key, Ed25519PublicKey):
        raise A2AVerificationError("resolved public key is not an Ed25519 key")
    try:
        key.verify(
            bytes.fromhex(attestation.signature.signature_value),
            canonicalize_a2a_v1(attestation.payload),
        )
    except InvalidSignature as exc:
        raise A2AVerificationError("Ed25519 signature verification failed") from exc
    except ValueError as exc:
        raise A2AVerificationError("malformed signature encoding") from exc

    # 2. Audience binding.
    if attestation.payload.audience != expected_audience:
        raise A2AVerificationError(
            f"audience mismatch: attestation is for {attestation.payload.audience!r}, "
            f"this verifier is {expected_audience!r}"
        )

    # 3. Freshness (both directions to bound clock skew).
    age_seconds = (now - attestation.payload.issued_at).total_seconds()
    if age_seconds > max_age_seconds:
        raise A2AVerificationError(
            f"attestation too old ({age_seconds:.0f}s > {max_age_seconds}s window)"
        )
    if age_seconds < -max_age_seconds:
        raise A2AVerificationError(
            f"attestation issued_at is in the future beyond tolerance ({-age_seconds:.0f}s)"
        )

    # 4. Request binding (anti-splice).
    expected_binding = compute_request_binding(method, params)
    if expected_binding != attestation.payload.request_binding:
        raise A2AVerificationError(
            "request_binding mismatch: attestation is not bound to this request "
            "(spliced from a different call, or params were tampered)"
        )

    return attestation.payload.agent


__all__ = [
    "A2A_ATTESTATION_VERSION",
    "A2A_EXTENSION_URI",
    "A2A_META_KEY",
    "A2AAttestation",
    "A2AAttestationPayload",
    "A2ACryptoUnavailable",
    "A2ASignature",
    "A2AVerificationError",
    "canonicalize_a2a_v1",
    "compute_request_binding",
    "generate_ed25519_keypair_pem",
    "sign_a2a_attestation",
    "strip_meta",
    "verify_a2a_attestation",
]
